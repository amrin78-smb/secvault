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
// ── ⛔ AND THE REGISTER CAN OVERSTATE A GAP TOO (A3, 2026-09-25) ──────────
//
// `hit_count IS NULL` alone was the `ruleUsage` gap, and that is now WRONG BY
// 84 RULES. A device that cannot report hit counts is not necessarily a device
// whose rule usage is unknown: its own logs may answer instead. Measured on the
// live fleet, of 235 rules the DEVICE cannot measure, 84 have a log-derived
// answer — 54 matched by the vendor's rule ID, 30 by NAME only.
//
// ⛔ AN OVERSTATED GAP IS STILL A LIE, and it is the one this page is least
// able to afford: the register's whole authority rests on its numbers being
// exactly what SecVault can and cannot see. A blind-spot list that names
// firewalls it CAN see teaches an operator to discount the ones it cannot.
//
// ⛔ BUT THE CORRECTION MAY ONLY EVER SHRINK THE GAP TO `partial`, NEVER TO
// `measured`. A log-derived answer is a bounded-window observation, not the
// device's own lifetime counter, and a NAME-grade one is weaker still — see
// the `ruleUsage` cell in coverageRegister.js.
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

// ⛔ THE GRADING IS NOT RE-IMPLEMENTED HERE, AND MUST NEVER BE. `usageGrade` /
// `deletionEvidence` are decided in ONE place — ruleHitCorrelation.js — because
// two files deciding "is this rule in use" would eventually disagree, and the
// wrong one would be recommending that rules be deleted from a firewall. This
// file fetches the same three inputs that engine's other callers fetch
// (segmentationData.js, ruleHygiene.js, ruleChangeRequestReport.js), hands them
// to `enrichRulesWithLogEvidence` unchanged, and COUNTS the grades it returns.
// Nothing here decides what a grade means; the SQL below selects rules and
// never grades them.
const {
  getDeviceLogCoverage,
  getLoggedRuleHits,
  enrichRulesWithLogEvidence,
} = require('./ruleHitCorrelation');

// The log-evidence window. 30 days is the product-wide convention
// (`EVIDENCE_WINDOW_DAYS` in ruleChangeRequestReport.js, ruleAnalysis.js's
// `logEvidenceDays`, ruleHygiene.js) and the register must agree with the pages
// it indexes: a register that graded usage over a different window from
// /analysis would report a gap the rule-hygiene page does not show, or hide one
// it does. Overridable per call only so a test can pin it.
const LOG_EVIDENCE_WINDOW_DAYS = 30;

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

// ⛔ THE RULES THE DEVICE COULD NOT MEASURE, FLEET-WIDE IN ONE STATEMENT, and
// scoped to the devices that actually have any. Live that is 235 rows across a
// handful of firewalls, so the whole-fleet fetch is cheaper than one query per
// device and keeps the per-device work to the hit lookup alone.
//
// ⛔ IT SELECTS, IT DOES NOT GRADE. Every column here is an INPUT to
// `enrichRulesWithLogEvidence`; there is deliberately no CASE, no join to the
// rollup and no count of "answered" in this SQL. Grading in SQL would be a
// second implementation of the thing ruleHitCorrelation.js exists to own.
const UNMEASURED_RULES_SQL = `
  SELECT device_id, rule_id_vendor, rule_name, log_enabled, hit_count
    FROM firewall_rules
   WHERE hit_count IS NULL
     AND device_id = ANY($1::uuid[])
   ORDER BY device_id, sequence_number ASC NULLS LAST
`;

/**
 * Per-device counts of how many device-unmeasurable rules the LOGS can answer.
 *
 * ⛔ A SECOND SOURCE, ISOLATED FROM THE FIRST. Its failure must not blank the
 * register — the counts above are still true and still worth showing — so it
 * pushes its own `failures` entry and leaves the affected devices' counts
 * ABSENT FROM THE MAP, which `toEngineInput` turns into `null`. The engine then
 * holds the `ruleUsage` cell at its existing, WORSE state with `certain: false`.
 * ⛔ Never 0: a zero here would assert "the logs answer none of them", which is
 * precisely the claim a failed read cannot make.
 *
 * ⛔ AN N+1, ON PURPOSE AND BOUNDED — the same shape segmentationData.js,
 * ruleHygiene.js and ruleRiskByTraffic.js already use, because
 * `getLoggedRuleHits` is scoped per device and reproducing it fleet-wide here
 * would be a fourth copy of a query this codebase deliberately keeps in one
 * place. The bound is what makes it affordable: only devices with at least one
 * `hit_count IS NULL` rule are visited, and a fleet whose every device reports
 * hit counts issues NO extra queries at all. Live: 2 shared statements plus one
 * per affected firewall.
 *
 * @returns {Promise<Map<string, {answered:number, idGrade:number}>>}
 */
async function gatherLogEvidence(pool, rows, opts, failures) {
  const out = new Map();
  const needy = [];

  for (const row of rows) {
    const unmeasured = countOrNull(row.rules_unmeasured);
    // ⛔ An unreadable rule count cannot be improved by anything. Leaving it out
    // of the map keeps it null all the way through, rather than pairing an
    // unknown gap with a confident "and none of it is log-answered".
    if (unmeasured === null) continue;
    if (unmeasured === 0) { out.set(row.id, { answered: 0, idGrade: 0 }); continue; }
    needy.push({ id: row.id, name: row.name });
  }

  if (needy.length === 0) return out;

  const days = countOrNull(opts.logWindowDays) || LOG_EVIDENCE_WINDOW_DAYS;
  const at = opts.now ? new Date(opts.now) : new Date();

  let coverage = null;
  const rulesByDevice = new Map();
  try {
    coverage = await getDeviceLogCoverage(pool, days, at);
    const res = await pool.query(UNMEASURED_RULES_SQL, [needy.map((d) => d.id)]);
    for (const r of (res && Array.isArray(res.rows) ? res.rows : [])) {
      if (!rulesByDevice.has(r.device_id)) rulesByDevice.set(r.device_id, []);
      rulesByDevice.get(r.device_id).push(r);
    }
  } catch (err) {
    // ⛔ Shared setup: every needy device stays unknown, and says so.
    failures.push({ source: 'rule_log_evidence', error: errorText(err) });
    return out;
  }

  const covFor = (id) => (coverage && typeof coverage.get === 'function' ? coverage.get(id) || null : null);

  for (const dev of needy) {
    try {
      const deviceRules = rulesByDevice.get(dev.id) || [];
      if (deviceRules.length === 0) { out.set(dev.id, { answered: 0, idGrade: 0 }); continue; }

      const hitMaps = await getLoggedRuleHits(pool, dev.id, days, at);
      const enriched = enrichRulesWithLogEvidence(deviceRules, covFor(dev.id), hitMaps);

      let answered = 0;
      let idGrade = 0;
      for (const e of enriched) {
        // ⛔ Only the two LOG grades count. `'device'` is unreachable here (every
        // row was selected on `hit_count IS NULL`) and is excluded explicitly
        // anyway, so a future change to the selection cannot quietly start
        // counting device-reported rules as a log-derived answer.
        if (e.usageGrade !== 'log-id' && e.usageGrade !== 'log-name') continue;
        answered += 1;
        // ⛔ `deletionEvidence` is READ, never recomputed from the grade string.
        // It is the engine's own answer to "is this strong enough to remove a
        // rule", and restating it here is how the two would drift apart.
        if (e.deletionEvidence === true) idGrade += 1;
      }
      out.set(dev.id, { answered, idGrade });
    } catch (err) {
      // ⛔ Per device, so one unreadable firewall does not blank the other
      // fifteen. This one's counts stay absent from the map — null, not zero.
      failures.push({
        source: `rule_log_evidence:${dev.name || dev.id}`,
        error: errorText(err),
      });
    }
  }

  return out;
}

/** A thrown non-Error still has to read as something. */
function errorText(err) {
  return (err && err.message) ? err.message : String(err);
}

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
function toEngineInput(row, logEvidence) {
  // ⛔ NO ENTRY MEANS UNREADABLE, AND UNREADABLE IS `null`. `le && le.answered`
  // would turn a real 0 into null; `le ? le.answered : null` keeps the measured
  // zero and the unknown apart, which is the whole distinction this file exists
  // to protect.
  const le = (logEvidence && typeof logEvidence.get === 'function')
    ? logEvidence.get(row.id) || null
    : null;
  return {
    deviceId: row.id,
    deviceName: row.name,
    vendor: row.vendor,
    rules: countOrNull(row.rules),
    rulesUnmeasured: countOrNull(row.rules_unmeasured),
    // ⛔ Of `rulesUnmeasured`, how many the firewall's OWN LOGS can answer, and
    // how many of those by the vendor's rule ID rather than by name. `null` =
    // could not be read; see gatherLogEvidence.
    rulesLogAnswered: le ? le.answered : null,
    rulesLogAnsweredDeletionGrade: le ? le.idGrade : null,
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
 *   pinnable by a test rather than being whatever the suite ran at. Also the
 *   clock the log-evidence window is measured back from.
 * @param {number} [opts.logWindowDays] the log-evidence window, default 30 —
 *   the product-wide `EVIDENCE_WINDOW_DAYS`. Exposed so a test can pin it, not
 *   so a page can pick its own: a register grading usage over a different
 *   window from /analysis would disagree with the page it indexes.
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

  // ⛔ THE COUNTS ARE THE REGISTER. If this statement fails the register cannot
  // be built at all, so it produces an EMPTY result that is explicitly labelled
  // as broken rather than an empty one that looks complete. The second source
  // below has its OWN try/catch and its OWN `failures` entry, and the two must
  // never be folded together — one dead source would then blank the other.
  try {
    const res = await pool.query(REGISTER_SQL, [ids]);
    rows = (res && Array.isArray(res.rows)) ? res.rows : [];
  } catch (err) {
    failures.push({ source: 'coverage_counts', error: errorText(err) });
  }

  // ⛔ SOURCE TWO, AND IT CAN ONLY EVER MAKE THE PICTURE SMALLER. It answers
  // "of the rules the device could not measure, how many do the logs answer",
  // and its failure degrades the `ruleUsage` cell to uncertain rather than
  // removing it. It is skipped entirely — zero extra queries — when no device
  // has an unmeasured rule.
  const logEvidence = await gatherLogEvidence(pool, rows, opts, failures);

  // ⛔ Ranked by the engine, never re-sorted here. `rankRegister` puts stale
  // findings above pure gaps and then orders by answers withheld — a
  // consequence ordering, not a gap count — and a second sort in this file
  // would eventually disagree with the one the tests pin.
  const entries = rankRegister(rows.map((row) => assessDevice(toEngineInput(row, logEvidence))));

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
