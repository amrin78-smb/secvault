'use strict';

// lib/engines/fleetConformanceData.js
//
// THE PLUMBING HALF of "which firewall is configured unlike its peers". It
// fetches the active fleet and each firewall's latest parsed configuration,
// hands them to the pure lib/engines/fleetConformance.js, and returns what a
// page renders. NOTHING HERE DECIDES ANYTHING — the cohorting, the minority
// rule, the identity-path exclusions, the wording of every statement and the
// one claim the feature makes all live in that file and are mutation-verified
// there. This file fetches, shapes, and reports what it could not read.
//
// ⛔ THE SPLIT IS DELIBERATE — the same one coverageRegister /
// coverageRegisterData, segmentation / segmentationData and applicationView /
// applicationViewData already use. The engine is pure (devices in, cohorts
// out), which is what lets a test drive every branch with literal data.
//
// ⛔ READ TIME. NO TABLE, NO CRON JOB, NO CACHE. A stored answer goes stale
// against the very configurations it compares — a firewall brought into line
// with its peers last night would still be listed as differing — and a stale
// answer is then read as fact. Same rule /segmentation and /applications
// follow.
//
// ── ⛔ MAJORITY IS NOT CORRECTNESS, AND THIS FILE INHERITS THAT ──────────────
//
// Live on the reference fleet, `global.admin-ssh-port` is 22 on four FortiGates
// and 5022 on the fifth. The fifth is the MINORITY and it is the only firewall
// not on the default SSH port — the hardened one. A layer that described the
// minority as misconfigured, or as the wrong value, would have told an operator
// to undo the only piece of hardening in the cohort. So this file emits no
// prose about a deviation at all: every sentence a reader sees comes from the
// engine, and `claim` travels back with the data so a view cannot drop it.
//
// ── ⛔ WHAT THIS FILE HAS TO GET RIGHT ──────────────────────────────────────
//
// AN EMPTY BOARD READS AS "EVERY FIREWALL AGREES WITH ITS PEERS". That is the
// strongest false statement available here, and a query that throws produces
// exactly that shape unless it is labelled. So a failed read returns EMPTY
// COHORTS WITH A POPULATED `failures`, never a clean-looking empty board, and
// every caller is required to refuse a verdict, a count and an all-clear while
// `failures` is non-empty. The same `{source, error}` isolation convention
// coverageRegisterData.js and workQueueData.js use, for the same reason.
//
// ⛔ AND A FAILED CONFIG READ HANDS THE ENGINE NOTHING, NOT SIXTEEN NULLS. The
// engine has a documented exclusion for a firewall with no parsed
// configuration, and it counts it. If the configuration statement throws and
// this file still passed the device rows through, every firewall on the fleet
// would be excluded for `no_parsed_config` and the board would report, with
// counts and named firewalls, that SecVault has collected nothing from any of
// them. That is a failed read recorded as a fact, dressed as a measurement.
//
// CommonJS, dependency-free: services/engine-worker.js loads this half of the
// repo under plain node, which cannot load ESM.

const {
  buildCohorts,
  findDeviations,
  summariseConformance,
  CONFORMANCE_CLAIM,
} = require('./fleetConformance');

/**
 * ⛔ `deviceIds` DISTINGUISHES "NO FILTER" FROM "NO DEVICES", and the two are
 * opposite instructions — the same asymmetry coverageRegisterData.js and
 * upgradePlanData.js already draw for this exact parameter.
 *
 *   undefined / null  the whole active fleet (the ordinary call)
 *   []                NO devices — a scoped account granted nothing
 *   [id, …]           exactly those
 *
 * Returned as a parameter for `= ANY($1::uuid[])`, never interpolated.
 */
function normaliseDeviceIds(deviceIds) {
  if (deviceIds === null || deviceIds === undefined) return null;
  if (!Array.isArray(deviceIds)) return null;
  return deviceIds.filter((id) => typeof id === 'string' && id.length > 0);
}

/** A thrown non-Error still has to read as something. */
function errorText(err) {
  return (err && err.message) ? err.message : String(err);
}

// ─────────────────────────────────────────────────────────────────────────
// The statements
// ─────────────────────────────────────────────────────────────────────────
//
// ⛔ TWO, AND THE FIRST ONE IS DRIVEN FROM `devices`. A firewall that has never
// been collected from has no `device_configs` row at all, so a board built from
// the configuration table alone would not merely omit it — it would omit it
// SILENTLY, and a firewall SecVault cannot read is the one most likely to be
// configured unlike its peers. Driving the roster from `devices` is what lets
// the engine see it, exclude it, and COUNT it. Same trap coverageRegisterData.js
// documents for its own register.
const FLEET_SQL = `
  SELECT d.id,
         d.name,
         d.vendor,
         d.mgmt_method
    FROM devices d
   WHERE d.active
     AND ($1::uuid[] IS NULL OR d.id = ANY($1::uuid[]))
   ORDER BY d.name
`;

// ⛔ ONE ROW PER DEVICE, THE NEWEST PARSED CONFIGURATION, AND `config_parsed`
// SELECTED EXACTLY ONCE. `DISTINCT ON (c.device_id)` with a matching leading
// `ORDER BY c.device_id` is what makes the row per device the newest one; the
// shape is verified against the live fleet.
//
// ⛔ THE PAYLOAD IS THE COST HERE AND IT IS BOUNDED BY THE PREDICATES, NOT BY A
// LIMIT. Measured 2026-09-25: the largest single configuration is ~1,160 kB and
// the whole active fleet is ~5 MB, which is affordable for a read-time page and
// would not be if this selected every historical snapshot. `d.active` and the
// device-id filter are therefore part of the statement rather than applied
// afterwards — a config row for a firewall this call will not compare is a row
// that has no reason to leave the database.
//
// ⛔ `config_parsed IS NOT NULL` BELONGS HERE, not in JavaScript. A device whose
// only snapshots carry a raw text config and no parsed structure has nothing to
// compare, and this predicate makes it arrive as a device with no configuration
// — which the engine excludes and counts — rather than as a row whose payload is
// null and whose meaning has to be re-derived downstream.
const LATEST_CONFIG_SQL = `
  SELECT DISTINCT ON (c.device_id)
         c.device_id,
         c.collected_at,
         c.config_parsed
    FROM device_configs c
    JOIN devices d ON d.id = c.device_id
   WHERE d.active
     AND c.config_parsed IS NOT NULL
     AND ($1::uuid[] IS NULL OR d.id = ANY($1::uuid[]))
   ORDER BY c.device_id, c.collected_at DESC
`;

/**
 * Which firewall is configured unlike its peers, computed at read time.
 *
 * @param {object} pool  ⛔ A PARAMETER, never imported and never instantiated —
 *   CLAUDE.md's Database rule. Removing it breaks DB access silently: builds
 *   clean, fails at runtime.
 * @param {object} [opts]
 * @param {string[]|null} [opts.deviceIds] restrict to these devices; see
 *   normaliseDeviceIds for why `[]` and `undefined` are opposite instructions.
 * @param {Date|string} [opts.now] injectable clock, so `generatedAt` is
 *   pinnable by a test rather than being whatever the suite ran at.
 * @returns {Promise<{cohorts:Array, summary:object, failures:Array,
 *   generatedAt:string, claim:string}>}
 *
 * ⛔ `failures` IS NOT A LOG LINE — IT IS PART OF THE ANSWER. `cohorts: []`
 * with a populated `failures` means THE BOARD COULD NOT BE BUILT, which is the
 * opposite of "every firewall agrees with its cohort". No caller may render a
 * verdict, a count or an all-clear while it is non-empty.
 *
 * ⛔ THERE IS NO `maxDepth` OPTION, DELIBERATELY. The engine's depth is a
 * measurement rather than a preference — raising it does not surface more
 * disagreements, it surfaces more features one firewall has configured and the
 * others have not. Exposing it here would let a page pick its own policy and
 * then disagree with the tests that pin the engine's.
 */
async function getFleetConformance(pool, opts = {}) {
  const ids = normaliseDeviceIds(opts.deviceIds);
  const failures = [];

  // ⛔ TWO ISOLATED READS, SO THE FAILURE CAN BE NAMED. Both are structural: the
  // roster says which firewalls exist and the payload says what they are set
  // to, and neither can stand in for the other. They are isolated so the answer
  // says WHICH one failed, not so that half an answer can be rendered.
  let deviceRows = [];
  let fleetOk = true;
  try {
    const res = await pool.query(FLEET_SQL, [ids]);
    deviceRows = (res && Array.isArray(res.rows)) ? res.rows : [];
  } catch (err) {
    fleetOk = false;
    failures.push({ source: 'conformance_fleet', error: errorText(err) });
  }

  let configRows = [];
  let configsOk = true;
  try {
    const res = await pool.query(LATEST_CONFIG_SQL, [ids]);
    configRows = (res && Array.isArray(res.rows)) ? res.rows : [];
  } catch (err) {
    configsOk = false;
    failures.push({ source: 'conformance_configs', error: errorText(err) });
  }

  const configByDevice = new Map();
  for (const row of configRows) {
    if (!row || row.device_id === undefined || row.device_id === null) continue;
    // ⛔ FIRST ROW PER DEVICE WINS AND LATER ONES ARE IGNORED. `DISTINCT ON`
    // already guarantees one, so a second row for the same device means the
    // statement was changed underneath this loop; keeping the first keeps the
    // newest, because the ORDER BY puts it first.
    if (!configByDevice.has(row.device_id)) configByDevice.set(row.device_id, row);
  }

  // ⛔ THE ONE PLACE A FAILED READ COULD BECOME A FACT. With the configuration
  // statement broken, every device would carry `config_parsed: null` and the
  // engine would faithfully report the whole fleet as having no collected
  // configuration — a named, counted, entirely fabricated finding. So the
  // engine is handed nothing at all, and `failures` is what says why.
  const devices = (fleetOk && configsOk)
    ? deviceRows.map((row) => {
      const config = configByDevice.get(row.id);
      return {
        id: row.id,
        name: row.name,
        vendor: row.vendor,
        mgmt_method: row.mgmt_method,
        // ⛔ `null` FOR A DEVICE WITH NO ROW, which the engine excludes as
        // `no_parsed_config` and counts. It is not defaulted to `{}`: an empty
        // object is a REAL shape an adapter can return on meeting an unexpected
        // response, and the engine tells the two apart.
        config_parsed: config ? config.config_parsed : null,
      };
    })
    : [];

  // ⛔ EVERY JUDGEMENT BELONGS TO THE ENGINE. There is no filter, no sort and no
  // re-count in this file: the cohort order, the minority rule and the device
  // ranking are pinned by tests/fleetConformance.test.js, and a second opinion
  // here would eventually disagree with the one those tests hold.
  const cohorts = buildCohorts(devices).map(findDeviations);

  return {
    cohorts,
    // ⛔ Computed from whatever survived, and honest about it: on a failure this
    // summarises an EMPTY list, so every total is 0 — which is exactly why
    // `failures` has to be read first. `devicesCompared: 0` beside a live fleet
    // is the signal, and the caller is the one that has to refuse to print it.
    summary: summariseConformance(cohorts),
    failures,
    generatedAt: (opts.now ? new Date(opts.now) : new Date()).toISOString(),
    // ⛔ CARRIED BACK VERBATIM FROM THE ENGINE so a view renders it rather than
    // writing its own. A second wording of this sentence would be a second
    // claim, and this feature makes exactly one.
    claim: CONFORMANCE_CLAIM,
  };
}

module.exports = { getFleetConformance };
