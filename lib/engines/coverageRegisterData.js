'use strict';

// lib/engines/coverageRegisterData.js
//
// The blind-spot register's PLUMBING. Counts, per active firewall, how much of
// each evidence source SecVault actually holds, hands those counts to the pure
// `coverageRegister.js`, and returns what a page or a route renders.
//
// ⛔ SPLIT FROM coverageRegister.js DELIBERATELY — the same split
// upgradePlan.js / upgradePlanData.js, segmentation.js / segmentationData.js
// and applicationView.js / applicationViewData.js already use. That file is
// pure (counts in, a register out), which is what lets a test drive every
// branch with literal data. Nothing in here decides anything: it counts,
// shapes, and reports what it could not read.
//
// ⛔ READ TIME. NO TABLE, NO CRON JOB, NO CACHE. A stored coverage register
// goes stale against the very collection it indexes — a firewall collected
// successfully last night would still be listed as a blind spot — and a stale
// register is then read as fact. Same rule /segmentation, /applications and
// the upgrade plan follow.
//
// ── ⛔ THE THING THIS FILE MUST GET RIGHT ─────────────────────────────────
//
// AN EMPTY REGISTER READS AS "WE CAN SEE EVERYTHING". This is the page whose
// entire job is to name what SecVault cannot measure, so a failed read here
// does not merely lose information — it asserts the exact opposite of the
// truth, on the one page a reader consults to find out how much to trust the
// rest of the product.
//
// So a query that throws returns `entries: []` WITH a populated `failures`,
// never a clean-looking empty register, and every caller must refuse to render
// a verdict while `failures.length > 0`. The same `{source, error}` isolation
// convention `workQueueData.js` uses, and for the same reason.
//
// ⛔ AND A DERIVED VALUE THAT COULD NOT BE READ IS `null`, NEVER 0. The engine's
// own `num()` treats null as "we did not measure the measurement" and marks the
// cell `certain: false` ("we could not even check"), which is a different fact
// from a measured zero ("we checked; there is nothing there"). `countOrNull()`
// below is the only thing standing between those two, because `Number(null)`
// is 0 and 0 is finite.

const {
  assessDevice,
  rankRegister,
  summariseRegister,
} = require('./coverageRegister');

/**
 * ⛔ COUNTS COME BACK FROM `pg` AS STRINGS. `count(*)` is `bigint`, which node-
 * postgres hands over as a STRING to avoid silently truncating past 2^53; the
 * `::int` age expressions come back as real numbers. Both shapes go through
 * here so the engine is handed one consistent type, and so that the ONE value
 * that must never be coerced — SQL NULL — stays null.
 *
 * `null` here means the count could not be read AT ALL. It is not zero, and
 * turning it into zero is this codebase's signature bug pointed at the register
 * that exists to surface that bug.
 */
function countOrNull(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/**
 * ⛔ `deviceIds` DISTINGUISHES "NO FILTER" FROM "NO DEVICES", and the two are
 * opposite instructions — the same asymmetry `ldapRoles.js` draws between no
 * mappings configured and no mapping matched, and the one `upgradePlanData.js`
 * already draws for this exact parameter.
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

// ─────────────────────────────────────────────────────────────────────────
// The statement
// ─────────────────────────────────────────────────────────────────────────
//
// ⛔ ONE ROW PER ACTIVE DEVICE, DRIVEN FROM `devices`. Every count is a
// correlated subquery, so a firewall with no rules, no interfaces, no syslog
// and no config still gets a row — with zeroes and nulls that say so. Driving
// this from any evidence table instead would DROP exactly the devices the
// register exists to name, which is the upgrade plan's documented trap wearing
// a different hat.
//
// ⛔ `syslog_rollup_hourly` IS COUNTED; THE RAW EVENT TABLE IS FORBIDDEN HERE.
// `syslog_events` carries ~28M rows/day in daily partitions with no index that
// would serve this, and a count over it would land its cost on a page render
// while the collector is inserting at ~1,000 rows/sec. The rollup answers the
// only question this register asks — "does this firewall send us anything at
// all" — at low cardinality. `tests/coverageRegisterData.test.js` scans this
// file (with comments stripped, so this paragraph cannot satisfy the scan) and
// fails the build if the raw table is ever named in the code.
//
// ⛔ `analyzed_at`, NOT `created_at`. `rule_analysis_results` has no
// `created_at` column — verified against lib/schema.sql, which declares
// `analyzed_at TIMESTAMPTZ NOT NULL DEFAULT now()`. The wrong name here would
// not degrade gracefully: the statement throws, and the whole register comes
// back empty.
//
// ⛔ AGES ARE WHOLE DAYS AND `NULL` WHEN THERE IS NO ROW AT ALL. `max()` over an
// empty set is NULL and `EXTRACT` of NULL is NULL, so "never collected" arrives
// as null rather than as a very large age or a zero. Both sides of the
// subtraction come from the SAME server clock (`collected_at`/`analyzed_at` are
// written with that server's `now()`), so a negative age is not reachable and
// is deliberately not guarded against with a clamp that would invent a value.
//
// ⛔ THE OBJECT-REFERENCE CTE IS SCOPED BY THE SAME PARAMETER. It flattens every
// rule's src/dst address arrays, which is the most expensive part of this
// statement; leaving it fleet-wide while the outer query is scoped would make a
// single-device call pay for the whole fleet. The `jsonb_typeof` guards are what
// keep a rule whose address field is NULL or an object (not every vendor emits
// an array) from aborting the flatten.
const REGISTER_SQL = `
  WITH refd AS (
    SELECT fr.device_id, v AS name
    FROM firewall_rules fr,
    LATERAL (
      SELECT jsonb_array_elements_text(
           CASE WHEN jsonb_typeof(fr.src_addresses) = 'array' THEN fr.src_addresses ELSE '[]'::jsonb END
        || CASE WHEN jsonb_typeof(fr.dst_addresses) = 'array' THEN fr.dst_addresses ELSE '[]'::jsonb END
      ) AS v
    ) x
    WHERE ($1::uuid[] IS NULL OR fr.device_id = ANY($1::uuid[]))
  )
  SELECT d.id,
         d.name,
         d.vendor,
         d.last_rules_collected_at,
         (SELECT count(*) FROM device_versions v WHERE v.device_id = d.id)      AS version_rows,
         (SELECT count(*) FROM device_interfaces i WHERE i.device_id = d.id)    AS interfaces,
         (SELECT count(*) FROM firewall_rules f WHERE f.device_id = d.id)       AS rules,
         (SELECT count(*) FROM firewall_rules f WHERE f.device_id = d.id
            AND f.hit_count IS NULL)                                            AS rules_unmeasured,
         (SELECT count(*) FROM syslog_rollup_hourly s WHERE s.device_id = d.id) AS log_buckets,
         (SELECT count(DISTINCT r.name) FROM refd r WHERE r.device_id = d.id)   AS obj_refs,
         (SELECT count(DISTINCT r.name) FROM refd r WHERE r.device_id = d.id
            AND NOT EXISTS (
              SELECT 1 FROM network_objects o
              WHERE o.device_id = r.device_id AND o.name = r.name
            ))                                                                  AS obj_unresolvable,
         (SELECT EXTRACT(day FROM now() - max(c.collected_at))::int
            FROM device_configs c WHERE c.device_id = d.id)                     AS config_age_days,
         (SELECT EXTRACT(day FROM now() - max(rr.analyzed_at))::int
            FROM rule_analysis_results rr WHERE rr.device_id = d.id)            AS analysis_age_days,
         (SELECT count(*) FROM rule_analysis_results rr WHERE rr.device_id = d.id)
                                                                                AS rule_findings
  FROM devices d
  WHERE d.active
    AND ($1::uuid[] IS NULL OR d.id = ANY($1::uuid[]))
  ORDER BY d.name
`;

/**
 * One database row → the engine's documented per-device input.
 *
 * ⛔ EXACTLY THE KEYS `assessDevice()` READS, and every one of them either a
 * number or `null`. A key this function forgets does not fail loudly — the
 * engine reads `undefined`, `num()` returns null, and the cell renders as "we
 * could not check" on a firewall we measured perfectly well. So the mapping is
 * spelled out one key per line rather than spread or renamed in bulk.
 *
 * `rulesCollectedAt` is passed through as whatever the driver returned (a Date,
 * a string, or null): the engine only ever tests it for truthiness, and
 * converting it here would invent a format nothing asked for.
 */
function toEngineInput(row) {
  return {
    deviceId: row.id,
    deviceName: row.name,
    vendor: row.vendor,
    rules: countOrNull(row.rules),
    rulesUnmeasured: countOrNull(row.rules_unmeasured),
    logBuckets: countOrNull(row.log_buckets),
    interfaces: countOrNull(row.interfaces),
    objectRefs: countOrNull(row.obj_refs),
    objectUnresolvable: countOrNull(row.obj_unresolvable),
    configAgeDays: countOrNull(row.config_age_days),
    versionRows: countOrNull(row.version_rows),
    analysisAgeDays: countOrNull(row.analysis_age_days),
    ruleFindings: countOrNull(row.rule_findings),
    rulesCollectedAt: row.last_rules_collected_at || null,
  };
}

/**
 * The fleet's blind-spot register, computed at read time.
 *
 * @param {object} pool  ⛔ A PARAMETER, never imported — CLAUDE.md's Database
 *   rule. Removing it breaks DB access and credential decryption silently:
 *   builds clean, fails at runtime.
 * @param {object} [opts]
 * @param {string[]|null} [opts.deviceIds] restrict to these devices; see
 *   normaliseDeviceIds for why `[]` and `undefined` are opposite instructions.
 * @param {Date|string} [opts.now] injectable clock, so `generatedAt` is
 *   pinnable by a test rather than being whatever the suite ran at.
 * @returns {Promise<{entries:Array, summary:object, failures:Array, generatedAt:string}>}
 *
 * ⛔ `failures` IS NOT A LOG LINE — IT IS PART OF THE ANSWER. `entries: []`
 * with a populated `failures` means THE REGISTER COULD NOT BE BUILT, which is
 * the opposite of "this fleet has no blind spots". No caller may render a
 * verdict, a count or an all-clear while it is non-empty.
 */
async function getCoverageRegister(pool, opts = {}) {
  const ids = normaliseDeviceIds(opts.deviceIds);
  const failures = [];
  let rows = [];

  // ⛔ ONE SOURCE, ISOLATED ANYWAY. There is a single statement here today, so
  // this try/catch cannot produce a PARTIAL register — and that is the point:
  // it produces an EMPTY one that is explicitly labelled as broken, rather
  // than an empty one that looks complete. A second source added later gets
  // its own try/catch and its own `failures` entry; it must never be folded
  // into this one, because then one dead source would blank the other.
  try {
    const res = await pool.query(REGISTER_SQL, [ids]);
    rows = (res && Array.isArray(res.rows)) ? res.rows : [];
  } catch (err) {
    failures.push({
      source: 'coverage_counts',
      error: (err && err.message) ? err.message : String(err),
    });
  }

  // ⛔ Ranked by the engine, never re-sorted here. `rankRegister` puts stale
  // findings above pure gaps and then orders by answers withheld — a
  // consequence ordering, not a gap count — and a second sort in this file
  // would eventually disagree with the one the tests pin.
  const entries = rankRegister(rows.map((row) => assessDevice(toEngineInput(row))));

  return {
    entries,
    // ⛔ Computed from whatever survived, and honest about it: on a failure
    // this summarises an EMPTY list, so every total is 0 — which is exactly
    // why `failures` has to be read first. `devices: 0` beside a live fleet is
    // the signal, and the caller is the one that must refuse to print it.
    summary: summariseRegister(entries),
    failures,
    generatedAt: (opts.now ? new Date(opts.now) : new Date()).toISOString(),
  };
}

module.exports = { getCoverageRegister };
