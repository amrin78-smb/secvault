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

/**
 * Convenience: resolve straight from a pool. Never throws.
 */
async function resolveEvidenceWindowDays(pool, now) {
  const available = await loadFleetLogHistoryDays(pool, now);
  return resolveEvidenceWindow(available);
}

module.exports = {
  MIN_EVIDENCE_WINDOW_DAYS,
  MAX_EVIDENCE_WINDOW_DAYS,
  SAFETY_MARGIN_DAYS,
  resolveEvidenceWindow,
  loadFleetLogHistoryDays,
  resolveEvidenceWindowDays,
};
