'use strict';
//
// lib/engines/complianceFreshness.js — how old is this compliance result?
//
// ⛔ THE SCORE AND ITS AGE ARE TWO FACTS, AND ONLY ONE WAS ON SCREEN. A
// compliance audit runs inside `collectAndStore`, gated on
// `result.configCollected` — so a firewall that stops being collectable stops
// being audited, and its findings simply stop moving. The page then renders a
// months-old score beside a fresh one with nothing to tell them apart.
//
// Measured on the live fleet 2026-09-22, and this is not hypothetical:
//
//   TSR_EKC   last config 1,116h (46 days)   last audit 669h (27 days)
//   TSR-TL    last config   252h (10 days)   last audit 252h (10 days)
//   the other 14                 ~12h                   ~12h
//
// Two of sixteen firewalls were scored on evidence from 10 and 27 days ago,
// presented as current. That is this codebase's signature bug — a failed read
// rendering as a fact — sitting on the compliance page.
//
// ⛔ THIS DOES NOT CHANGE A SCORE. Age is reported ALONGSIDE, never folded in.
// A stale 60% is still 60% of what was measured; what is wrong is not the
// arithmetic but the absence of a date. Same call the exception workflow makes.
//
// ⛔ THE AGE THAT MATTERS IS THE EVIDENCE'S, NOT THE EVALUATION'S — and these
// are NOT the same number. `runComplianceAuditForDevice` reads
// `getLatestConfigParsed()`, i.e. the newest `device_configs` row, WHATEVER ITS
// AGE, and stamps `audit_findings.detected_at = now()`. So re-running the checks
// on a firewall that stopped being collectable produces a brand-new timestamp
// over month-old evidence, and grading on that timestamp would report the
// device as freshly verified.
//
// That is not hypothetical either. Measured 2026-09-22:
//
//   TSR_EKC   config collected 1,116h ago   audit run 669h ago   (gap: 18 days)
//
// An audit had already run 18 days after the last successful collection. Grading
// on the run time understates the real age of the evidence by that gap — and a
// "run checks now" button, pressed today, would understate it by 46 days. The
// button is still worth having; what it may never do is launder a stale
// configuration into a fresh-looking score.
//
// So `freshnessOf` grades ONE timestamp and callers pass the EVIDENCE time, and
// `complianceFreshness()` takes both and reports the lag between them.
//
// Pure: takes timestamps and a clock, returns a verdict. No pool.

// Compliance rides the config pull, so the pull interval IS the expected
// cadence. Read at call time rather than captured, so a deployment that
// lengthened it is honoured — the same pattern trafficWindow's
// detailRetentionDays() uses.
const DEFAULT_PULL_HOURS = 24;

function pullIntervalHours(env = process.env) {
  const n = Number(env.CONFIG_PULL_INTERVAL_HOURS);
  return Number.isFinite(n) && n > 0 ? Math.min(Math.trunc(n), 24 * 30) : DEFAULT_PULL_HOURS;
}

// ⛔ MULTIPLES OF THE CADENCE, NOT ABSOLUTE HOURS. A fleet on a 6-hour pull and
// one on a weekly pull do not share a definition of "late", and hardcoding 48h
// would call the second permanently stale and the first permanently fresh.
const AGEING_AFTER_INTERVALS = 2;
const STALE_AFTER_INTERVALS = 7;

const FRESH = 'fresh';
const AGEING = 'ageing';
const STALE = 'stale';
const NEVER = 'never';
const UNKNOWN = 'unknown';

const STATES = Object.freeze({ FRESH, AGEING, STALE, NEVER, UNKNOWN });

/**
 * @param {Date|string|null} lastRunAt
 * @param {Date} now
 * @returns {{state:string, hours:number|null, intervals:number|null, expectedHours:number}}
 */
function freshnessOf(lastRunAt, now = new Date(), env = process.env) {
  const expectedHours = pullIntervalHours(env);
  const base = { expectedHours, hours: null, intervals: null };

  // ⛔ NEVER AUDITED IS ITS OWN STATE, NOT "very stale". A device added
  // yesterday that has not been collected yet has no result to be old; calling
  // that stale would put an alarming age on a device nothing is wrong with,
  // and calling it fresh would be worse.
  if (lastRunAt === null || lastRunAt === undefined || lastRunAt === '') {
    return { ...base, state: NEVER };
  }

  const then = lastRunAt instanceof Date ? lastRunAt : new Date(lastRunAt);
  // ⛔ AN UNPARSEABLE TIMESTAMP IS UNKNOWN, NEVER FRESH. Defaulting a bad value
  // to "recent" is the failed-read-as-a-fact rule in its smallest form.
  if (Number.isNaN(then.getTime())) return { ...base, state: UNKNOWN };

  const ms = now.getTime() - then.getTime();
  // ⛔ A FUTURE TIMESTAMP IS A CLOCK DISAGREEMENT, NOT FRESHNESS — the same
  // call vpn_sessions makes on a negative duration.
  if (ms < 0) return { ...base, state: UNKNOWN };

  const hours = ms / 3600000;
  const intervals = expectedHours > 0 ? hours / expectedHours : null;
  let state = FRESH;
  if (intervals !== null && intervals > STALE_AFTER_INTERVALS) state = STALE;
  else if (intervals !== null && intervals > AGEING_AFTER_INTERVALS) state = AGEING;

  return { state, hours, intervals, expectedHours };
}

/** Human age, for a chip. Never "0 hours ago" — that reads as broken. */
function ageLabel(f) {
  if (!f || f.state === NEVER) return 'never run';
  if (f.state === UNKNOWN) return 'age unknown';
  const h = f.hours;
  if (h < 1) return 'under an hour ago';
  if (h < 48) return `${Math.round(h)}h ago`;
  return `${Math.round(h / 24)} days ago`;
}

/**
 * The sentence a page prints beside a score. ⛔ It always says what the score
 * IS still worth: a stale result is real evidence about an old configuration,
 * not garbage, and wording it as garbage would push people to ignore the page
 * rather than fix the collection.
 */
function freshnessNote(f, deviceName) {
  const who = deviceName ? `${deviceName}'s` : 'This';
  switch (f && f.state) {
    case NEVER:
      return `${who} configuration has never been audited, so there is no score — `
        + 'that is a gap in collection, not a clean result.';
    case AGEING:
      return `${who} configuration was last collected ${ageLabel(f)}, longer than the usual `
        + `${f.expectedHours}h cadence, so these checks describe it as it was then.`;
    case UNKNOWN:
      return `${who} last collection time could not be read, so how current this score is `
        + 'is unknown.';
    case STALE:
      return `${who} configuration was last collected ${ageLabel(f)}, and that is what these `
        + `checks were evaluated against. Collection normally runs every ${f.expectedHours}h, so `
        + 'it has most likely been failing — the score is real, but it describes an old '
        + 'configuration, and re-running the checks would only re-read the same old one.';
    default:
      return `${who} configuration was last collected ${ageLabel(f)}.`;
  }
}

/** Fleet roll-up: how many devices are behind, for a banner. */
function summariseFreshness(devices, now = new Date(), env = process.env) {
  const rows = (devices || []).map((d) => ({
    deviceName: d.deviceName || d.name || null,
    ...freshnessOf(d.lastRunAt ?? d.last_run_at ?? null, now, env),
  }));
  const count = (s) => rows.filter((r) => r.state === s).length;
  return {
    rows,
    total: rows.length,
    fresh: count(FRESH),
    ageing: count(AGEING),
    stale: count(STALE),
    never: count(NEVER),
    unknown: count(UNKNOWN),
    // ⛔ ANY device not fresh is worth saying out loud on the fleet view, and
    // the page must not render an all-clear while this is non-zero — the rule
    // lib/evidence.js already enforces product-wide.
    behind: rows.filter((r) => r.state !== FRESH).map((r) => r.deviceName).filter(Boolean),
  };
}

/**
 * The honest verdict for a compliance result, from BOTH of its timestamps.
 *
 * ⛔ GRADED ON `evidenceAt` (when the configuration was collected), never on
 * `evaluatedAt` (when the checks last ran). An evaluation cannot be more
 * current than the configuration it read, and grading on the later of the two
 * is how a stale config gets laundered into a fresh-looking score.
 *
 * `evaluationLagHours` is the gap between them — positive whenever the checks
 * were re-run against an already-old config. ⛔ It is reported, never used to
 * adjust the state: it is a fact about how the result was produced, and the
 * state is a fact about the evidence.
 *
 * @param {{evidenceAt?: Date|string|null, evaluatedAt?: Date|string|null}} t
 */
function complianceFreshness(t, now = new Date(), env = process.env) {
  const src = t || {};
  const evidence = freshnessOf(src.evidenceAt ?? null, now, env);
  const evaluation = freshnessOf(src.evaluatedAt ?? null, now, env);

  // ⛔ A LAG IS ONLY A NUMBER WHEN BOTH ENDS ARE MEASURED. Either side missing
  // or unreadable leaves it null — never 0, which would read as "evaluated the
  // moment it was collected", the most reassuring possible wrong answer.
  const lag = evidence.hours !== null && evaluation.hours !== null
    ? evidence.hours - evaluation.hours
    : null;

  return {
    ...evidence,
    evaluation,
    evaluationLagHours: lag,
    // ⛔ True when the checks ran against a config that was ALREADY older than
    // the expected cadence when they ran. This is the state the run button
    // creates, so a page offering that button has to be able to say it.
    evaluatedAgainstOldConfig: lag !== null && lag > evidence.expectedHours,
  };
}

module.exports = {
  STATES,
  freshnessOf,
  complianceFreshness,
  ageLabel,
  freshnessNote,
  summariseFreshness,
  pullIntervalHours,
  AGEING_AFTER_INTERVALS,
  STALE_AFTER_INTERVALS,
};
