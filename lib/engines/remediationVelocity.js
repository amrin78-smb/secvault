'use strict';

// lib/engines/remediationVelocity.js
//
// A8 — HOW LONG A KNOWN VULNERABILITY STAYS OPEN ON THIS FLEET.
//
// Pure: takes already-fetched exposure rows and a clock, returns a survival
// curve and a headline. No pool, no queries, no `new Date()` it was not handed.
// The plumbing is `remediationVelocityData.js`.
//
// Kaplan-Meier with right-censoring. ~30 lines of actual estimator; everything
// else in this file exists to stop the estimator being believed further than the
// data supports.
//
// ── ⛔ THE FIRST OUTPUT IS AN INDICTMENT, AND THAT IS THE POINT ───────────
//
// Measured on the live fleet 2026-09-28: 246 open exposures across 16 firewalls,
// 74 days of version history, and **0 devices have changed version — ever**.
// Sixteen devices, sixteen distinct (device, version) pairs in 3,954 collected
// rows. Nothing has been patched in the entire observation window.
//
// So the curve is flat at 1.0 and EVERY observation is censored. That is not a
// degenerate case to code around — it is the finding, and it is invisible today
// because nothing in this product measures it.
//
// ── ⛔ `assessed_at` IS NOT AN EXPOSURE START. NEVER USE IT ───────────────
//
// `device_cve_assessments.assessed_at` is rewritten on every match run: all 246
// live rows carry the SAME timestamp, today's. It records when SecVault last
// looked, not when the advisory opened on that device. A duration measured from
// it would report every exposure as hours old, forever, resetting every six
// hours — a confident, plausible, wrong number, which is this codebase's
// signature defect. `tests/remediationVelocity.test.js` scans for it.
//
// ── ⛔ TWO CLOCKS, AND THEY DISAGREE BY MONTHS ────────────────────────────
//
// Measured on the same fleet: 59 of 246 exposures were published by the vendor
// more than 30 days before SecVault first ingested them; mean 26.9 days, MAX
// 275.7. The fleet's only KEV-listed ADVISORY, CVE-2026-24858 — which is three
// exposures, one per affected firewall, not one — was published 2026-01-27 and
// first ingested 2026-07-16: 170 days in which those firewalls were vulnerable
// and nothing here could have said so.
//
//   `sinceKnown`     — from when SecVault could first have told you. This is
//                      the one an operator is accountable for.
//   `sincePublished` — from when the vendor disclosed it. This is how long the
//                      firewall was actually exposed.
//
// ⛔ BOTH ARE REPORTED, ALWAYS, AND NEITHER IS "THE" NUMBER. Reporting only
// `sinceKnown` understates the fleet's real exposure by 175 days on that KEV
// finding. Reporting only `sincePublished` bills the operator for time before
// this product knew the advisory existed. A single blended figure would be
// wrong in both directions at once.
//
// ── ⛔ EVERY DURATION IS A LOWER BOUND ────────────────────────────────────
//
// Both clocks are LEFT-CENSORED and we cannot see past either wall:
//   - a device observed on an affected version since 2026-07-16 may have been
//     on it for years; 2 of 16 devices sit exactly on that collection-start
//     date, so for those two the clock is the install date, not a fact about
//     the firewall;
//   - an advisory first ingested on the day the feed was switched on was real
//     long before.
// So a reported age is "at least this long", never "this long". Same contract
// as `vpn_sessions.duration_is_lower_bound`, and for the same reason.

// ⛔ The single sentence this engine is allowed to claim. Exported so the UI
// cannot paraphrase it into something stronger, the way A7's OUTCOME_CLAIM and
// applicationView's IMPACT_CLAIM are.
const VELOCITY_CLAIM =
  'SecVault measures how long a known vulnerability has stayed open on a firewall, from the '
  + 'date it could first have told you and from the date the vendor disclosed it. Both are '
  + 'lower bounds: a firewall may have been running an affected version before SecVault first '
  + 'collected from it. An exposure that is still open is counted as still open, never as '
  + 'remediated quickly.';

// ⛔ NOT "resolved"/"closed"/"fixed". An exposure ENDS when the device is
// observed on a version the advisory no longer covers. We did not watch anyone
// patch anything; we watched a version string change.
const OUTCOMES = Object.freeze({
  REMEDIATED: 'remediated',          // observed on a version the advisory does not cover
  OPEN: 'open',                      // still affected at the observation cutoff (censored)
  UNKNOWN_START: 'unknown_start',    // no usable exposure start — counted, never dated
});

// ⛔ A MEDIAN THAT WAS NEVER REACHED IS `null`, NOT THE LARGEST OBSERVATION.
// With every subject censored the survival function never crosses 0.5, and the
// honest answer is "not reached within N days of observation". Substituting the
// longest observed age would report 74 days as the fleet's median time-to-patch
// when the true value is unbounded below by 74 and unknown above it.
const MEDIAN_NOT_REACHED = null;

const DAY_MS = 86400000;

/** Finite number or null — never a coerced zero. See CLAUDE.md on `Number(null)`. */
function num(v) {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'string' && v.trim() !== '') {
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

/** A Date, or null. Never "now" as a fallback — that is a fabricated start. */
function asDate(v) {
  if (v instanceof Date) return Number.isFinite(v.getTime()) ? v : null;
  if (typeof v === 'string' && v.trim() !== '') {
    const d = new Date(v);
    return Number.isFinite(d.getTime()) ? d : null;
  }
  return null;
}

/** Whole days between two dates, or null if either is missing. */
function daysBetween(from, to) {
  if (!from || !to) return null;
  const ms = to.getTime() - from.getTime();
  // ⛔ A NEGATIVE AGE IS NOT A NUMBER AND NOT A ZERO. It means the two clocks
  // disagree — an advisory ingested "after" the cutoff, a device collected in
  // the future. The same call vpn_sessions makes on a negative duration.
  if (ms < 0) return null;
  return ms / DAY_MS;
}

/**
 * One exposure: a (device, advisory) pair, with both clocks and an outcome.
 *
 * ⛔ `exposureStart` IS THE LATER OF the advisory becoming known and the device
 * being first observed on an affected version. Taking the advisory date alone
 * would charge a firewall for the weeks before SecVault had ever collected from
 * it; taking the device date alone would charge it for an advisory that did not
 * exist yet. Neither is a real exposure.
 */
function buildExposure(row, now) {
  const r = row || {};
  const knownAt = asDate(r.advisory_known_at);
  const deviceSeenAt = asDate(r.device_first_seen_at);
  const publishedAt = asDate(r.advisory_published_at);
  const endedAt = asDate(r.remediated_at);

  const start = knownAt && deviceSeenAt
    ? new Date(Math.max(knownAt.getTime(), deviceSeenAt.getTime()))
    : (knownAt || deviceSeenAt || null);

  // ⛔ THE CUTOFF IS `now`, WHICH IS HANDED IN. An engine that reads its own
  // clock cannot be tested against a fixed fleet snapshot, and a test that
  // passes only today is not a test.
  const cutoff = endedAt || now;

  const outcome = start === null
    ? OUTCOMES.UNKNOWN_START
    : (endedAt ? OUTCOMES.REMEDIATED : OUTCOMES.OPEN);

  return {
    deviceId: r.device_id || null,
    deviceName: r.device_name || null,
    cveId: r.cve_id || null,
    kevListed: r.kev_listed === true,
    priorityBand: r.priority_band || null,
    cvssScore: num(r.cvss_score),
    outcome,
    // ⛔ BOTH CLOCKS, ALWAYS. See the header. `null` where the source date is
    // missing — never substituted from the other clock, which would silently
    // report one measurement under the other's name.
    daysSinceKnown: daysBetween(start, cutoff),
    daysSincePublished: daysBetween(publishedAt, cutoff),
    // ⛔ Both are lower bounds and every consumer is told so in the data, not
    // only in prose that a table can render without.
    isLowerBound: true,
    exposureStart: start,
    publishedAt,
    remediatedAt: endedAt,
    // How long SecVault could not have told you. Not a fault of the firewall,
    // and the reason `sincePublished` alone is unfair to the operator.
    unawareDays: publishedAt && knownAt ? daysBetween(publishedAt, knownAt) : null,
  };
}

/**
 * Kaplan-Meier survival, right-censored.
 *
 * "Survival" here means STILL VULNERABLE, which is the opposite of the word's
 * everyday sense. ⛔ NO CONSUMER MAY RENDER S(t) AS A GOOD NUMBER: on this fleet
 * S(t) = 1.0 for every t, and a naive UI showing "100%" in green would be
 * reporting total failure to patch as a perfect score. `survivingPct` is
 * deliberately named for what it counts, and `remediatedPct` is provided beside
 * it so a renderer never has to invert it itself.
 *
 * @param {Array} exposures from buildExposure
 * @returns {{points: Array, medianDays: number|null, events: number,
 *            censored: number, observedToDays: number|null}}
 */
function kaplanMeier(exposures) {
  const list = Array.isArray(exposures) ? exposures : [];
  // ⛔ UNKNOWN_START IS EXCLUDED FROM THE CURVE AND COUNTED SEPARATELY. It has
  // no time axis to sit on. Dropping it silently would shrink the denominator
  // and make the fleet look better measured than it is.
  const usable = list.filter((e) => e
    && e.outcome !== OUTCOMES.UNKNOWN_START
    && num(e.daysSinceKnown) !== null);

  const atRiskTotal = usable.length;
  if (atRiskTotal === 0) {
    return {
      points: [],
      medianDays: MEDIAN_NOT_REACHED,
      events: 0,
      censored: 0,
      atRisk: 0,
      observedToDays: null,
    };
  }

  // Sort by time; at equal times, EVENTS BEFORE CENSORINGS — the standard
  // convention, and it matters: a subject censored at the same instant as an
  // event is still at risk for that event.
  const sorted = usable.slice().sort((a, b) => {
    const d = a.daysSinceKnown - b.daysSinceKnown;
    if (d !== 0) return d;
    const ae = a.outcome === OUTCOMES.REMEDIATED ? 0 : 1;
    const be = b.outcome === OUTCOMES.REMEDIATED ? 0 : 1;
    return ae - be;
  });

  const points = [];
  let surviving = 1;
  let atRisk = atRiskTotal;
  let events = 0;
  let censored = 0;

  let i = 0;
  while (i < sorted.length) {
    const t = sorted[i].daysSinceKnown;
    let d = 0;  // events at t
    let c = 0;  // censored at t
    while (i < sorted.length && sorted[i].daysSinceKnown === t) {
      if (sorted[i].outcome === OUTCOMES.REMEDIATED) d++;
      else c++;
      i++;
    }
    if (d > 0 && atRisk > 0) {
      surviving *= (atRisk - d) / atRisk;
      points.push({ days: t, survivingPct: surviving * 100, atRisk, events: d });
    }
    events += d;
    censored += c;
    atRisk -= (d + c);
  }

  // ⛔ NOT REACHED is null, not the last observation. See MEDIAN_NOT_REACHED.
  let medianDays = MEDIAN_NOT_REACHED;
  for (const p of points) {
    if (p.survivingPct <= 50) { medianDays = p.days; break; }
  }

  const observedToDays = sorted.length
    ? sorted[sorted.length - 1].daysSinceKnown
    : null;

  return { points, medianDays, events, censored, atRisk: atRiskTotal, observedToDays };
}

/**
 * The fleet headline.
 *
 * ⛔ `remediatedPct === 0` MUST NOT RENDER AS "0 DAYS TO PATCH" OR AS AN
 * ALL-CLEAR. Zero events means nothing was fixed. It is the worst possible
 * result and it is arithmetically indistinguishable from the best if a
 * renderer only reads the survival number.
 */
function summariseVelocity(exposures, now) {
  const list = Array.isArray(exposures) ? exposures : [];
  const km = kaplanMeier(list);

  const unknownStart = list.filter((e) => e && e.outcome === OUTCOMES.UNKNOWN_START).length;
  const open = list.filter((e) => e && e.outcome === OUTCOMES.OPEN).length;
  const remediated = list.filter((e) => e && e.outcome === OUTCOMES.REMEDIATED).length;

  const openAges = list
    .filter((e) => e && e.outcome === OUTCOMES.OPEN)
    .map((e) => num(e.daysSinceKnown))
    .filter((n) => n !== null);

  const kev = list.filter((e) => e && e.kevListed && e.outcome === OUTCOMES.OPEN);
  const kevAges = kev.map((e) => num(e.daysSinceKnown)).filter((n) => n !== null);

  // ⛔ The gap between the two clocks, reported as its own fact. It is the
  // product's own blind window and belongs on the page that judges response
  // time, or the operator is measured against a start date we chose.
  const unaware = list.map((e) => num(e.unawareDays)).filter((n) => n !== null);

  return {
    exposures: list.length,
    open,
    remediated,
    unknownStart,
    // ⛔ Named for what it is. A renderer must not have to invert anything.
    remediatedPct: list.length ? (remediated / list.length) * 100 : null,
    allCensored: list.length > 0 && remediated === 0,
    medianDaysToRemediate: km.medianDays,
    observedToDays: km.observedToDays,
    longestOpenDays: openAges.length ? Math.max(...openAges) : null,
    kevOpen: kev.length,
    kevLongestOpenDays: kevAges.length ? Math.max(...kevAges) : null,
    meanUnawareDays: unaware.length
      ? unaware.reduce((a, b) => a + b, 0) / unaware.length
      : null,
    maxUnawareDays: unaware.length ? Math.max(...unaware) : null,
    curve: km,
    claim: VELOCITY_CLAIM,
    generatedAt: now instanceof Date ? now : null,
  };
}

/**
 * The sentence the page leads with.
 *
 * ⛔ IT REFUSES AN ALL-CLEAR WHILE ANYTHING IS CENSORED AND NOTHING WAS FIXED —
 * the rule `lib/evidence.js` enforces product-wide. "No remediations observed"
 * is a finding, not an absence of one.
 */
function velocityHeadline(summary) {
  const s = summary || {};
  if (!s.exposures) {
    return {
      tone: 'unknown',
      text: 'No exposures could be measured, so nothing can be said about how quickly this '
        + 'fleet remediates.',
    };
  }
  if (s.allCensored) {
    const days = num(s.observedToDays);
    const window = days === null ? 'the observation window' : `${Math.round(days)} days`;
    const kevPart = s.kevOpen > 0 && num(s.kevLongestOpenDays) !== null
      ? ` ${s.kevOpen} of them ${s.kevOpen === 1 ? 'is' : 'are'} on CISA's known-exploited list `
        + `and ${s.kevOpen === 1 ? 'has' : 'have'} been open at least `
        + `${Math.round(s.kevLongestOpenDays)} days.`
      : '';
    return {
      // ⛔ NEVER 'ok'. Nothing was remediated.
      tone: 'bad',
      text: `Not one of ${s.exposures} open exposures was remediated in ${window} of observation, `
        + `so a median time-to-patch does not exist for this fleet yet.${kevPart}`,
    };
  }
  const median = num(s.medianDaysToRemediate);
  if (median === null) {
    return {
      tone: 'unknown',
      text: `${s.remediated} of ${s.exposures} exposures were remediated, which is not yet enough `
        + 'for a median time-to-patch — over half are still open.',
    };
  }
  return {
    tone: 'ok',
    text: `Half of this fleet's exposures were remediated within ${Math.round(median)} days, `
      + 'measured from the date SecVault could first have reported them.',
  };
}

module.exports = {
  buildExposure,
  kaplanMeier,
  summariseVelocity,
  velocityHeadline,
  daysBetween,
  OUTCOMES,
  VELOCITY_CLAIM,
  MEDIAN_NOT_REACHED,
};
