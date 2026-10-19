'use strict';
// lib/engines/evidenceWindow.js
//
// ONE definition of "how far back does log evidence reach", resolved once and
// shared. It was duplicated as four separate literals — `logEvidenceDays` in
// ruleAnalysis.js, `EVIDENCE_WINDOW_DAYS` in ruleChangeRequestReport.js (which
// ruleHygiene.js imports) and `LOG_EVIDENCE_WINDOW_DAYS` in
// coverageRegisterData.js — and coverageRegisterData.js's own header states the
// invariant that made that dangerous: "the register must agree with the pages
// it indexes". Four literals cannot be relied on to agree, and the register
// disagreeing with the page it links to is a coverage report that contradicts
// the thing it is reporting on.
//
// ⛔ A BIGGER WINDOW IS NOT UNIFORMLY BETTER, AND RAISING THE LITERAL TO 90
// WOULD HAVE DELETED EVERY `unused` FINDING ON THE FLEET. ruleHitCorrelation.js
// gates coverage on `sufficientHistory = historyHours >= windowHours`, so a
// window LONGER than the history that exists makes `covered` false for every
// device — and `ruleAnalysis.js` only emits `unused` for a MEASURED zero, which
// requires `covered`. MEASURED, not reasoned about: running the real gate at 90
// days against the reference fleet's 41.1 days of `syslog_rollup_hourly` takes
// coverage from 15 of 15 devices to 0 of 15. A 30 -> 90 bump reads as "more
// evidence" and silently produces LESS: the 185 live `unused` findings
// disappear, the rule-cleanup loop empties, and nothing anywhere errors.
//
// ⛔ SO THE WINDOW IS ADAPTIVE, AND BOUNDED ON BOTH SIDES. It asks how much
// history actually exists and uses that, capped at MAX and floored at MIN.
//
// ⛔ THE FLOOR IS THE NO-REGRESSION GUARANTEE, NOT A PREFERENCE. MIN is exactly
// the literal every consumer used before this module existed, so the resolved
// window can never be narrower than the behaviour it replaced. When less than
// MIN days of history exist the window stays at MIN and `sufficientHistory`
// correctly reports false — which is what already happens today, rather than a
// new and quieter failure.
//
// ⛔ IT IS KEYED ON THE YOUNGEST LOG SOURCE, AND THE REASON IS THE RATIO
// BUDGET, NOT `sufficientHistory`. An earlier draft of this comment said a
// window longer than a late-joining device's own history "would drop that
// device's coverage". That is wrong and it was measured to be wrong, so it is
// corrected here rather than quietly deleted: `sufficientHistory` is computed
// from the GLOBAL first bucket and is deliberately fleet-wide (see
// ruleHitCorrelation.js, which says so), and the per-device test is
// `ratio >= MIN_COVERAGE_RATIO` at 0.9 — which a device missing the first 0.8
// of a 41-day window still clears at 0.984.
//
// ⛔ AND IT PROTECTS LESS THAN AN EARLIER VERSION OF THIS COMMENT CLAIMED.
// `min(bucket_hour)` is a device's EARLIEST bucket, not the start of its
// CONTINUOUS coverage, so one old isolated bucket defeats the rule entirely: a
// firewall that logged for an hour 45 days ago, went quiet, and resumed 28 days
// ago reports 45 days of "history" and does not lower the fleet window. At a
// 40-day window its own ratio is ~0.70, below MIN_COVERAGE_RATIO, so it loses
// coverage and every `unused` finding on it disappears — where at the old fixed
// 30 it would have scored 0.933 and kept them.
// ⛔ THAT EXPOSURE IS REAL, NARROW, AND IN THE CONSERVATIVE DIRECTION, and it is
// written down rather than implied: it needs a device whose continuous coverage
// began between MIN and the resolved window while its first bucket is older, it
// self-heals as that device accumulates history, and it LOSES findings rather
// than fabricating them. Measured today, no device is anywhere near it — the
// worst per-device ratio at 39 days is 0.983, i.e. every firewall has >=98% of
// the window's buckets. Closing it properly means asking for each device's
// longest continuous run, or verifying the candidate window's per-device ratio
// before adopting it, which is a second bounded query and a follow-up.
//
// Measured on the reference fleet 2026-10-19, running the real gate at four
// window sizes:
//
//     window | sufficientHistory | devices covered | worst ratio
//       30d  |        yes        |      15/15      |   0.982
//       39d  |        yes        |      15/15      |   0.983
//       41d  |        yes        |      15/15      |   0.984
//       90d  |        NO         |       0/15      |   0.448
//
// So 41 would also have worked today, and the youngest-source rule costs two
// days of window. It is kept because that 10% ratio budget exists to absorb
// COLLECTOR RESTARTS AND NETWORK BLIPS — this fleet's own deploys produce
// exactly those gaps, which is what ruleHitCorrelation.js's own comment on
// MIN_COVERAGE_RATIO says it is for. Spending it instead on a device's late
// onboarding leaves nothing for a real outage, and the failure mode then is
// not an error: it is every `unused` finding disappearing at once.
//
// ⛔ The accepted cost is stated rather than hidden: onboarding a new firewall
// returns the whole fleet to the MIN floor until that device has MIN+MARGIN
// days of its own history. That is never worse than the old fixed literal,
// which is why it is acceptable; a per-device window is the alternative and it
// breaks the register-agrees-with-the-page invariant above.
//
// ⛔ A DEVICE WITH NO ROLLUP ROWS AT ALL IS EXCLUDED FROM THE MINIMUM. It has
// no history, so including it would peg the fleet at the floor for ever —
// and it is already excluded downstream, because a device with no buckets gets
// `historyHours = null` and so fails `sufficientHistory` whatever the window.

// The floor: what every consumer used as a hardcoded literal before this
// module. Never go below it — see the no-regression note above.
const MIN_EVIDENCE_WINDOW_DAYS = 30;

// The cap. Beyond ~90 days a "this rule is unused" claim is resting on traffic
// patterns a quarter old, and the rollups are permanent so the window would
// otherwise grow without bound.
const MAX_EVIDENCE_WINDOW_DAYS = 90;

// ⛔ ONE DAY OF SLACK, BECAUSE THE GATE IS AN EXACT BUCKET-COUNT COMPARISON.
// `sufficientHistory` compares inclusive hour-bucket counts, so a window equal
// to the available history passes by a single bucket. The resolver and the
// consumer do not read the clock at the same instant, and a consumer whose
// `now` is marginally earlier loses that bucket — flipping every device from
// covered to uncovered, which costs every `unused` finding at once. The margin
// makes the window strictly interior to the history that exists.
const SAFETY_MARGIN_DAYS = 1;

/**
 * Pure. Given how many days of history exist, decide the window.
 *
 * @param {number|null} availableDays  whole or fractional days of history, or
 *   null when it could not be measured.
 * @returns {{days:number, reason:string, availableDays:number|null,
 *            min:number, max:number, margin:number}}
 */
function resolveEvidenceWindow(availableDays) {
  const base = {
    min: MIN_EVIDENCE_WINDOW_DAYS,
    max: MAX_EVIDENCE_WINDOW_DAYS,
    margin: SAFETY_MARGIN_DAYS,
    availableDays: null,
  };

  // ⛔ UNKNOWN FALLS BACK TO THE FLOOR, NEVER TO THE CAP AND NEVER TO null.
  // The cap would collapse `covered` fleet-wide on exactly the reads that
  // failed, which is this codebase's signature bug — a failed read producing a
  // confident, plausible, wrong answer. null would break every consumer's
  // arithmetic. The floor is the behaviour that shipped for months.
  if (availableDays == null) {
    return { ...base, days: MIN_EVIDENCE_WINDOW_DAYS, reason: 'unknown_history' };
  }
  const n = Number(availableDays);
  if (!Number.isFinite(n) || n < 0) {
    return { ...base, days: MIN_EVIDENCE_WINDOW_DAYS, reason: 'unreadable_history' };
  }

  const usable = Math.floor(n) - SAFETY_MARGIN_DAYS;
  let days = usable;
  let reason = 'adaptive';
  if (usable >= MAX_EVIDENCE_WINDOW_DAYS) {
    days = MAX_EVIDENCE_WINDOW_DAYS;
    reason = 'capped';
  } else if (usable <= MIN_EVIDENCE_WINDOW_DAYS) {
    days = MIN_EVIDENCE_WINDOW_DAYS;
    reason = 'floored';
  }
  return { ...base, days, reason, availableDays: n };
}

/**
 * The one read. Returns the days of history held by the YOUNGEST log source,
 * or null when that cannot be measured.
 *
 * ⛔ NEVER THROWS. A resolver that threw would take down rule analysis, the
 * change-request report, rule hygiene and the coverage register together — all
 * four of which worked perfectly well on a fixed literal. An unreadable answer
 * is null, which the pure function turns into the floor.
 */
async function loadFleetLogHistoryDays(pool, now) {
  try {
    const at = now instanceof Date ? now : new Date();
    // ⛔ max(min(...)) over devices, i.e. the LATEST per-device first bucket:
    // the youngest source decides. `device_id IS NOT NULL` drops unmatched
    // senders — a firewall SecVault does not manage is stored deliberately
    // (see the collector's rules) but it is not a device whose coverage is
    // being gated, and letting one peg the fleet at the floor would be an
    // unmanaged sender silently degrading managed ones.
    const { rows } = await pool.query(
      `SELECT max(first_bucket) AS youngest
         FROM (SELECT device_id, min(bucket_hour) AS first_bucket
                 FROM syslog_rollup_hourly
                WHERE device_id IS NOT NULL
                GROUP BY device_id) per_device`
    );
    const youngest = rows && rows[0] ? rows[0].youngest : null;
    if (!youngest) return null;
    const first = youngest instanceof Date ? youngest : new Date(youngest);
    if (Number.isNaN(first.getTime())) return null;
    const days = (at.getTime() - first.getTime()) / 86400000;
    // ⛔ A FIRST BUCKET IN THE FUTURE IS A CLOCK DISAGREEMENT, NOT HISTORY —
    // the same call vpn_sessions makes on a negative duration. Report it as
    // unmeasurable rather than as a negative or a zero.
    if (!Number.isFinite(days) || days < 0) return null;
    return days;
  } catch {
    return null;
  }
}

// ⛔ RESOLVED ONCE PER POOL, NOT ONCE PER DEVICE. `loadOptionsFromSettings` sits
// inside `runAnalysisForDevice`, which both `runAnalysisForAllDevices` and
// `collectAndStore` call PER DEVICE — so the nightly pass issued one aggregate
// per firewall instead of one for the fleet, and `/devices/[id]/rules`,
// `/coverage`, `/segmentation` and `/applications` each added one to every page
// load where they previously added none.
// ⛔ THE CORRECTNESS HALF MATTERS MORE THAN THE COST. Each device resolved
// independently, so if `floor(availableDays)` ticked mid-run two firewalls in
// the SAME pass could get different windows — and that number is written into
// the stored finding text, persisting "no traffic in 39 days" beside "in 40
// days" for one run. One resolution per pass makes that impossible.
// ⛔ KEYED ON THE POOL OBJECT, which is what makes it safe in tests: production
// has one singleton pool so the pass shares an entry, while every test builds a
// fresh stub and therefore always issues the query. A time-only cache would
// have made query-count assertions depend on execution speed.
const CACHE_TTL_MS = 60 * 1000;
const cacheByPool = new WeakMap();

/**
 * Convenience: resolve straight from a pool. Never throws.
 *
 * ⛔ An explicit `now` BYPASSES the cache and is threaded into the read. The
 * resolver used to ignore it and read the real wall clock while its caller
 * handed its own pinned clock to getDeviceLogCoverage — and with only one day
 * of margin, a caller pinning `now` even a few days back resolved a window
 * WIDER than the history its own clock could see, making `sufficientHistory`
 * false for the whole fleet. No production caller does that today, but
 * `opts.now` is a documented option on four of these functions and
 * scripts/dbCheck.js already passes one.
 */
async function resolveEvidenceWindowDays(pool, now) {
  if (now instanceof Date) {
    return resolveEvidenceWindow(await loadFleetLogHistoryDays(pool, now));
  }
  const hit = pool && typeof pool === 'object' ? cacheByPool.get(pool) : null;
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.value;

  const value = resolveEvidenceWindow(await loadFleetLogHistoryDays(pool));

  // ⛔ A RESOLVER THAT SILENTLY STOPPED WORKING WOULD BE INVISIBLE. `reason` is
  // returned but nothing in the product renders it, so "we measured 30 days of
  // history" and "the history query failed" print the same "30 days" on every
  // page, PDF and CSV. If this query ever breaks — a grant, a rename, a
  // timeout — the feature reverts to the old literal for ever with no banner
  // and no log line, which is the guard-that-cannot-fire pattern this codebase
  // names most often. So an unmeasurable history says so, once per cache fill.
  if (value.reason === 'unknown_history' || value.reason === 'unreadable_history') {
    console.warn(
      `[evidenceWindow] Could not measure how much log history exists (${value.reason}); `
        + `falling back to the ${value.days}-day floor. Rule-usage evidence is still correct, `
        + 'but it is not using any history beyond that floor.'
    );
  }

  if (pool && typeof pool === 'object') cacheByPool.set(pool, { at: Date.now(), value });
  return value;
}

// Tests and long-lived callers that need a guaranteed fresh read.
function resetEvidenceWindowCache(pool) {
  if (pool) cacheByPool.delete(pool);
}

module.exports = {
  resetEvidenceWindowCache,
  MIN_EVIDENCE_WINDOW_DAYS,
  MAX_EVIDENCE_WINDOW_DAYS,
  SAFETY_MARGIN_DAYS,
  resolveEvidenceWindow,
  loadFleetLogHistoryDays,
  resolveEvidenceWindowDays,
};
