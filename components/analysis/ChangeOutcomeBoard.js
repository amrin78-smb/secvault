// components/analysis/ChangeOutcomeBoard.js
//
// WHAT FOLLOWED A CONFIGURATION CHANGE, rendered. The judgement is made by the
// pure lib/engines/changeOutcome.js and fetched by changeOutcomeData.js; this
// file only decides how it LOOKS — and on this feature, how it looks is almost
// all of what can go wrong.
//
// ── ⛔ THE ONE RULE THE WHOLE VIEW EXISTS TO HOLD ───────────────────────────
//
// CO-OCCURRENCE, NEVER CAUSATION. A firewall change and a traffic movement on
// the same day are two facts in sequence. This product cannot see a mechanism
// between them and must not imply one, so every phrase here is "was followed
// by". tests/changeOutcomeBoard.test.js rejects the causal vocabulary from every
// string this file emits, with comments stripped first — this repo has been
// bitten more than once by a source scan satisfied by the very comment
// explaining the thing it was hunting.
//
// ⛔ AND THE CLAIM IS RENDERED VERBATIM FROM THE DATA, NEVER RESTATED. The
// engine attaches one sentence to every answer. This file holds no copy of it: a
// second wording would be a second claim, and it would drift from the one the
// engine's own tests pin. ConformanceBoard.js takes the same position for the
// same reason.
//
// ── ⛔ ZERO IS THE HONEST HEADLINE, AND IT IS A RESULT ─────────────────────
//
// Live on the reference fleet: 203 changes, 137 with an incomplete window, 66
// judged, and NONE of the 66 followed by a movement larger than its firewall's
// own ordinary day-to-day variation. An earlier version of the engine reported
// ten "effects" including +814%; all ten were artefacts of an incomplete window
// or a too-loose band.
//
// So this board does not apologise for the zero and does not pad it. It is
// stated as a measurement over a named number of judged changes — and ⛔ "none
// exceeded over 66 judged" and "none judged at all" are DIFFERENT SENTENCES with
// different shapes, since the second is an absence of evidence wearing the
// first's clothes. `headline()` splits them and a test drives both.
//
// ── ⛔ FOUR WAYS A RENDERING RUINS THIS ENGINE ─────────────────────────────
//
//   1. PUTTING A VERDICT ON THE SEVERITY RAMP. Red means danger everywhere else
//      in this product, and `exceeded_normal_variation` IS NOT A FAULT — it is
//      one observation about volume, and the movement may be the change working
//      exactly as intended. Nothing in this file carries a severity hue. The one
//      tinted verdict uses the INFO pair, which this product already uses for a
//      notice rather than a severity, and the incompleteness banner uses the
//      WARN pair so no reader reads it as belonging to the rows underneath.
//
//   2. HIDING `window_incomplete` IN A FOOTER. It is the MAJORITY state (137 of
//      203) and it is a limit of OURS, not a fact about the firewall. It gets a
//      named, counted panel above the per-firewall lists, and it must read
//      differently from `no_traffic_window`: one says the window reaches outside
//      the period SecVault was collecting, the other says the window is inside
//      that period and holds nothing.
//
//   3. SHOWING A VERDICT WITH NO VISIBLE BASIS. Every judged change prints how
//      many of that firewall's own ordinary daily swings the movement is larger
//      than, out of how many were observed, and the firewall's band. A verdict
//      with no basis is exactly what this engine was rewritten twice to stop.
//
//   4. GIVING IT A SCORE'S SHAPE. No arithmetic in this file at all — no
//      rounding, no share of changes marked as fine, no single figure. The
//      numbers rendered are the ones the engine published.
//
// ⛔ `failures` IS BANNERED ABOVE EVERYTHING, AND WHILE IT IS NON-EMPTY NO
// VERDICT AND NO COUNT IS PRINTED. A board that lost a read renders short, and a
// short board here reads as a firewall nothing has happened to. That refusal is
// not there because the surviving rows are worthless; it is there because a
// reader cannot tell a truncated list from a quiet firewall, and this board's
// whole value is that a reader can trust what it does not say.
//
// Server component. No client JS: every control is a native <details>, and it
// takes its data purely as props so it can be dropped onto any page that already
// fetches it.

import Card, { CardBody } from '../ui/Card';
import Table from '../ui/Table';
import StatCard from '../ui/StatCard';
import Disclosure from '../ui/Disclosure';
import EmptyState from '../ui/EmptyState';
import NotMeasured from '../ui/NotMeasured';
import { IconAlertTriangle, IconClock } from '../icons';

// ── The verdicts, as literal strings ───────────────────────────────────────
//
// ⛔ NOT IMPORTED FROM THE ENGINE, AND THAT IS NOT LAZINESS. This is a client-
// importable ES module and the engine is CommonJS, and every pure helper below
// has to be evaluable on its own so a test can drive it without a DOM.
// tests/changeOutcomeBoard.test.js requires the engine and asserts that these
// keys are exactly its `VERDICTS`, so the two cannot drift apart in silence.
export const VERDICT = {
  EXCEEDED: 'exceeded_normal_variation',
  INDISTINGUISHABLE: 'indistinguishable',
  WINDOW_INCOMPLETE: 'window_incomplete',
  NO_TRAFFIC_WINDOW: 'no_traffic_window',
  INSUFFICIENT_BASELINE: 'insufficient_baseline',
  BASELINE_DEGENERATE: 'baseline_degenerate',
};

// ── The wording, exported so a test can pin it ──────────────────────────────

// ⛔ MECHANICS, NOT MEANING. This says what the board LINES UP. What a listed
// movement MEANS is the engine's claim, rendered from the data beside it — see
// claimText below and the header's note on why there is no copy here.
export const BOARD_PURPOSE =
  'Every configuration change SecVault detected is lined up against the traffic it recorded in '
  + 'the hours either side, and compared with how much that firewall normally varies from one '
  + 'day to the next.';

export const CLAIM_MISSING_NOTE =
  'The statement this engine attaches to every answer did not arrive with this data, so it is '
  + 'not shown. It is deliberately not restated here in other words: a second wording of it '
  + 'would be a second claim.';

export const FAILURE_NOTE =
  'Part of this board could not be read, so no verdict and no count is shown at all. A change '
  + 'missing from the list below has not been cleared — it was never compared.';

export const INCOMPLETE_COUNT_REASON =
  'This board is incomplete, so this count was withheld rather than printed over whatever '
  + 'could be read.';

export const INCOMPLETE_VERDICT_REASON =
  'No verdict is shown while part of this board is unreadable. A short list of changes reads '
  + 'exactly like a firewall nothing has happened to, and that is the one wrong answer this '
  + 'board must never give.';

// ⛔ THE MAJORITY STATE, AND A LIMIT OF OURS. Never a severity, never a footer.
export const WINDOW_INCOMPLETE_NOTE =
  'SecVault was not collecting traffic for the whole window either side of these changes, so '
  + 'the two sides cannot be compared. This is a limit of what SecVault holds, not an '
  + 'observation about the firewall, and it is the most common state on this board.';

// ⛔ A DIFFERENT FACT FROM THE ONE ABOVE, and it has to read that way: the
// window is inside the collected period and the traffic in it is simply absent.
export const NO_TRAFFIC_NOTE =
  'SecVault holds no traffic for the hours before these changes, so there is no starting point '
  + 'to compare the hours after them against. Nothing was compared.';

export const INSUFFICIENT_BASELINE_NOTE =
  'This firewall has too few day-to-day observations for a band to be built, so its changes '
  + 'were not judged at all. That is a gap in what SecVault holds about this firewall, and it '
  + 'is not a statement that its changes were uneventful.';

export const BASELINE_DEGENERATE_NOTE =
  'This firewall’s daily traffic does not vary, so there is no spread to compare a movement '
  + 'against. Every movement would clear a band of zero, so none is reported.';

export const UNKNOWN_VERDICT_NOTE =
  'This verdict is not one this view recognises, so it is drawn as an absence of a result '
  + 'rather than as one.';

export const MISSING_BASIS_NOTE =
  'This movement was not compared against anything, so it is a figure and not a verdict.';

export const NOTHING_JUDGED_NOTE =
  'No change here could be judged. Each one is missing part of its window, missing traffic on '
  + 'one side, or belongs to a firewall with no band. Nothing below says these changes were '
  + 'uneventful.';

export const HEADLINE_UNREADABLE_NOTE =
  'The verdict counts did not arrive with this data, so no headline is shown.';

// ⛔ THE ZERO, STATED AS A MEASUREMENT AND NOT AS AN EMPTY STATE. The suffix is
// what stops it being read as a clearance of the changes that were NOT judged.
export const NONE_EXCEEDED_PREFIX = 'All of the';

export const NONE_EXCEEDED_SUFFIX =
  'That is a measurement over those changes, not an absence of data, and it says nothing about '
  + 'the changes that could not be judged.';

export const SOME_EXCEEDED_SUFFIX =
  'SecVault saw the change and the movement in sequence, and observed nothing between them.';

export const OBSERVED_NONE_NOTE =
  'SecVault holds no traffic at all for this firewall, so no window either side of a change '
  + 'can be complete.';

export const BASELINE_UNKNOWN_NOTE =
  'No band travelled with this firewall, so nothing here was compared.';

export const NO_CHANGES_NOTE =
  'No configuration change has been detected on this firewall, so there is nothing to line up '
  + 'against its traffic.';

export const EMPTY_BOARD_NOTE =
  'No firewall was assessed, so nothing was lined up against anything. An empty board is an '
  + 'absence of comparison, not a fleet whose changes were uneventful.';

export const LIMITS_HEADING = 'Changes that could not be judged';

export const LIMITS_NOTE =
  'These are counted and named rather than folded into the result above. Each one is a change '
  + 'SecVault holds and could not compare, and leaving them out would make the judged changes '
  + 'look like the whole history.';

// ── ⛔ VISUAL WEIGHT. The rules at the top of this file, expressed as DATA. ──
//
// Read by tests/changeOutcomeBoard.test.js, which fails the build if the
// ranking inverts or if a severity hue appears. `rank` is the reading order an
// eye takes: 0 is loudest.
//
// ⛔ EXACTLY ONE STATE CARRIES A HUE, AND IT IS THE INFO PAIR, NOT RED.
// `exceeded_normal_variation` is one observation about traffic volume; it is not
// a fault, and the movement may be the change doing precisely what it was made
// to do. Red would read as "this firewall is exposed", green as "this one is
// fine", and both are verdicts this engine cannot make. The severity ramp is not
// touched anywhere in this file.
//
// ⛔ THE FOUR UNJUDGEABLE STATES RANK ABOVE `indistinguishable`, WHICH IS THE
// OPPOSITE OF WHAT LOOKS NATURAL. A change nothing could be said about would
// otherwise be the quietest thing on the board and read as the cleanest —
// exactly the inversion this codebase names most often. They are hueless and
// hatched, which is what says "there is no data here"; a flat grey fill reads as
// a real, minor, muted category instead.
//
// SegmentationBoard.js shipped its three violation tints in the reverse of its
// own action order and satisfied the rule it was written against to the letter.
// That is why this ranking is data a test compares, not a CSS string a test
// would have to grep for.
export const VERDICT_WEIGHT = {
  exceeded_normal_variation: {
    kind: 'exceeded_normal_variation',
    rank: 0,
    label: 'Followed by a larger movement',
    swatch: 'tint',
    background: 'var(--tint-info)',
    color: 'var(--tint-info-fg)',
    accent: 'var(--tint-info-fg)',
    border: '1px solid var(--tint-info-fg)',
    fontWeight: 700,
  },
  window_incomplete: {
    kind: 'window_incomplete',
    rank: 1,
    label: 'Window not fully collected',
    swatch: 'hatch',
    background: 'var(--surface-subtle)',
    color: 'var(--unmeasured)',
    accent: 'var(--unmeasured)',
    border: '1px dashed var(--border)',
    fontWeight: 700,
  },
  insufficient_baseline: {
    kind: 'insufficient_baseline',
    rank: 1,
    label: 'No band for this firewall',
    swatch: 'hatch',
    background: 'var(--surface-subtle)',
    color: 'var(--unmeasured)',
    accent: 'var(--unmeasured)',
    border: '1px dashed var(--border)',
    fontWeight: 700,
  },
  no_traffic_window: {
    kind: 'no_traffic_window',
    rank: 2,
    label: 'No traffic to compare',
    swatch: 'hatch',
    background: 'var(--surface-subtle)',
    color: 'var(--unmeasured)',
    accent: 'var(--unmeasured)',
    border: '1px dashed var(--border)',
    fontWeight: 600,
  },
  baseline_degenerate: {
    kind: 'baseline_degenerate',
    rank: 2,
    label: 'No spread to compare against',
    swatch: 'hatch',
    background: 'var(--surface-subtle)',
    color: 'var(--unmeasured)',
    accent: 'var(--unmeasured)',
    border: '1px dashed var(--border)',
    fontWeight: 600,
  },
  indistinguishable: {
    kind: 'indistinguishable',
    rank: 3,
    label: 'Within normal variation',
    swatch: 'outline',
    background: 'transparent',
    color: 'var(--text-muted)',
    accent: 'var(--border)',
    border: '1px solid var(--border-light)',
    fontWeight: 400,
  },
  // ⛔ THE FALLBACK, AND IT IS NOT `indistinguishable`. A verdict this file does
  // not recognise is one it cannot characterise, and characterising it as the
  // quiet measured state would let a data change quietly report an unread answer
  // as a result. It falls to the hueless family and says so in words.
  unknown: {
    kind: 'unknown',
    rank: 1,
    label: 'Verdict not recognised',
    swatch: 'hatch',
    background: 'var(--surface-subtle)',
    color: 'var(--unmeasured)',
    accent: 'var(--unmeasured)',
    border: '1px dashed var(--border)',
    fontWeight: 600,
  },
};

// ⛔ The reading order of the panels and the tiles, hueless states first among
// equals. Derived from VERDICT_WEIGHT's own ranks so the two cannot disagree.
export const VERDICT_ORDER = Object.keys(VERDICT_WEIGHT)
  .filter((k) => k !== 'unknown')
  .sort((a, b) => VERDICT_WEIGHT[a].rank - VERDICT_WEIGHT[b].rank);

// The four states that mean "nothing was compared", in reading order.
export const UNJUDGEABLE = VERDICT_ORDER.filter(
  (k) => k !== VERDICT.EXCEEDED && k !== VERDICT.INDISTINGUISHABLE,
);

/**
 * ⛔ AN UNRECOGNISED VERDICT NEVER RESOLVES TO `indistinguishable`. The asymmetry
 * is the whole point: an unknown shape drawn as unjudgeable is merely
 * over-reported, while the same shape drawn as the measured quiet state is a
 * result derived from something this view could not read.
 */
export function verdictWeight(verdict) {
  const w = VERDICT_WEIGHT[verdict];
  return w && w.kind !== 'unknown' ? w : VERDICT_WEIGHT.unknown;
}

/** The sentence a verdict carries. ⛔ Never omitted for the unjudgeable four. */
export function verdictNote(verdict) {
  if (verdict === VERDICT.WINDOW_INCOMPLETE) return WINDOW_INCOMPLETE_NOTE;
  if (verdict === VERDICT.NO_TRAFFIC_WINDOW) return NO_TRAFFIC_NOTE;
  if (verdict === VERDICT.INSUFFICIENT_BASELINE) return INSUFFICIENT_BASELINE_NOTE;
  if (verdict === VERDICT.BASELINE_DEGENERATE) return BASELINE_DEGENERATE_NOTE;
  if (verdict === VERDICT.EXCEEDED) return null;
  if (verdict === VERDICT.INDISTINGUISHABLE) return null;
  return UNKNOWN_VERDICT_NOTE;
}

// ── Pure helpers (no imported identifier is referenced below) ───────────────

/**
 * ⛔ NOT `Number(v)`. `Number(null)`, `Number('')`, `Number([])` and
 * `Number(false)` are all 0 and 0 is finite, so a bare coercion turns "this
 * figure did not arrive" into a measured zero — the precise bug the engine this
 * view renders exists to avoid.
 */
export function numOrNull(v) {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

/** One verdict's fleet count, or null when it is not a real number. */
export function verdictCount(summary, verdict) {
  const by = summary && typeof summary === 'object' ? summary.byVerdict : null;
  if (!by || typeof by !== 'object') return null;
  return numOrNull(by[verdict]);
}

/**
 * How many changes were actually judged — the only two verdicts that involved a
 * comparison. ⛔ Null if either side is unreadable: a total built from one known
 * and one unknown half is not a total.
 */
export function judgedCount(summary) {
  const quiet = verdictCount(summary, VERDICT.INDISTINGUISHABLE);
  const larger = verdictCount(summary, VERDICT.EXCEEDED);
  if (quiet === null || larger === null) return null;
  return quiet + larger;
}

/**
 * The headline sentence.
 *
 * ⛔ THREE SHAPES, NOT ONE. "None of the 66 judged changes was followed by a
 * larger movement" is a measurement. "None was judged" is an absence of one, and
 * printing the first sentence in the second situation is the failed-read-as-a-
 * fact bug wearing this feature's clothes. The unreadable case is a third.
 */
export function headline(summary) {
  const larger = verdictCount(summary, VERDICT.EXCEEDED);
  const judged = judgedCount(summary);
  if (larger === null || judged === null) {
    return { kind: 'unreadable', text: HEADLINE_UNREADABLE_NOTE, judged, exceeded: larger };
  }
  if (judged === 0) {
    return { kind: 'nothing_judged', text: NOTHING_JUDGED_NOTE, judged, exceeded: larger };
  }
  if (larger === 0) {
    return {
      kind: 'none_exceeded',
      text: `${NONE_EXCEEDED_PREFIX} ${judged} change${judged === 1 ? '' : 's'} SecVault could `
        + `judge ${judged === 1 ? 'was' : 'were'} followed by traffic inside that firewall’s own `
        + `ordinary day-to-day variation. ${NONE_EXCEEDED_SUFFIX}`,
      judged,
      exceeded: larger,
    };
  }
  return {
    kind: 'some_exceeded',
    text: `${larger} of the ${judged} changes SecVault could judge `
      + `${larger === 1 ? 'was' : 'were'} followed by traffic outside that firewall’s own `
      + `ordinary day-to-day variation. ${SOME_EXCEEDED_SUFFIX}`,
    judged,
    exceeded: larger,
  };
}

/**
 * Whatever `failures` turns out to be, as lines a human can read.
 * ⛔ TOLERANT ON PURPOSE. The banner must fire on a shape this file does not
 * recognise as readily as on the expected array — a failures value that cannot
 * be parsed is itself evidence the board is incomplete, and swallowing it would
 * render the short list silently.
 */
export function failureList(failures) {
  if (failures === null || failures === undefined || failures === '') return [];
  const describe = (f) => {
    if (typeof f === 'string') return f;
    if (f && typeof f === 'object') {
      const where = f.source || f.key || f.name || 'a source';
      const why = f.error || f.message || f.reason || 'unknown error';
      return `${where}: ${why}`;
    }
    return String(f);
  };
  if (Array.isArray(failures)) {
    return failures.filter((f) => f !== null && f !== undefined && f !== '').map(describe);
  }
  if (typeof failures === 'object') {
    return Object.keys(failures).map((k) => `${k}: ${describe(failures[k])}`);
  }
  return [describe(failures)];
}

/** ⛔ Any failure at all. There is no threshold and no "minor" case. */
export function boardIsIncomplete(failures) {
  return failureList(failures).length > 0;
}

/**
 * ⛔ A COUNT COMPUTED OVER A BOARD THAT LOST A SOURCE IS NOT A MEASUREMENT.
 * changeOutcomeData.js summarises whatever survived, so on a failure every total
 * is 0 — and "0 changes followed by a larger movement" beside a live fleet is the
 * single most dangerous thing this view can print.
 */
export function reportableCount(n, incomplete) {
  return incomplete ? null : n;
}

/** The engine's claim, verbatim, or an explicit admission that it is absent. */
export function claimText(summary) {
  const claim = summary && typeof summary === 'object' ? summary.claim : null;
  return typeof claim === 'string' && claim.trim() !== '' ? claim : null;
}

/**
 * ⛔ A BOARD WITH NO TIMESTAMP IS AN ASSERTION, NOT EVIDENCE. A missing or
 * unreadable stamp is said out loud rather than dropped.
 */
export function asOf(generatedAt) {
  if (!generatedAt) return 'computed at a time that was not recorded';
  const d = new Date(generatedAt);
  if (Number.isNaN(d.getTime())) return 'computed at a time that could not be read';
  return `as of ${d.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

/** A timestamp, or an honest dash. */
export function stamp(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return `${d.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

/** The window either side, in words. */
export function windowSentence(windowHours) {
  const h = numOrNull(windowHours);
  if (h === null) return 'The window either side of a change did not travel with this data.';
  return `The window compared is ${h} hours either side of the moment the change was detected.`;
}

/**
 * The delta, signed, or null when none was published.
 * ⛔ NO ARITHMETIC. The engine already rounded it; recomputing or reformatting
 * the number is how a second, slightly different figure appears on screen.
 */
export function deltaLabel(change) {
  const d = numOrNull(change && change.deltaPct);
  if (d === null) return null;
  return `${d > 0 ? '+' : ''}${d}%`;
}

/**
 * ⛔ WHAT THE MOVEMENT WAS COMPARED WITH, in the firewall's own terms. "Larger
 * than 12 of 19 ordinary daily swings" is a claim a reader can check, where a
 * bare verdict is one they must take on trust. Null when the engine published no
 * comparison, in which case the caller prints MISSING_BASIS_NOTE instead.
 */
export function basisSentence(change) {
  if (!change || typeof change !== 'object') return null;
  const larger = numOrNull(change.largerThanDays);
  const ordinary = numOrNull(change.ordinaryDays);
  if (larger === null || ordinary === null) return null;
  const band = numOrNull(change.baseline && change.baseline.bandPct);
  const judged = change.verdict === VERDICT.EXCEEDED || change.verdict === VERDICT.INDISTINGUISHABLE;
  const side = change.verdict === VERDICT.EXCEEDED ? 'outside' : 'inside';
  const tail = (band === null || !judged)
    ? ''
    : ` It sits ${side} this firewall’s band of ${band}%.`;
  return `Larger than ${larger} of ${ordinary} ordinary daily swings on this firewall.${tail}`;
}

/**
 * The firewall's own band, described.
 * ⛔ THE UNUSABLE CASES ARE NAMED SEPARATELY. "Too few observations" and "no
 * spread at all" are different facts, and neither of them is "this firewall's
 * changes were quiet".
 */
export function baselineSentence(device) {
  const b = device && typeof device === 'object' ? device.baseline : null;
  if (!b || typeof b !== 'object') return BASELINE_UNKNOWN_NOTE;
  if (b.usable) {
    const band = numOrNull(b.bandPct);
    const obs = numOrNull(b.observations);
    const floor = numOrNull(b.resolutionPct);
    const bandPart = band === null
      ? 'This firewall’s band did not travel with this data.'
      : `Band ${band}%: the day-over-day change in event volume this firewall stays under on all `
        + 'but its noisiest observed days.';
    const obsPart = obs === null
      ? ' The number of observations behind it could not be read.'
      : ` Measured from ${obs} of its own day-to-day swings.`;
    const floorPart = floor === null
      ? ''
      : ` With that many observations the finest share of ordinary days expressible is ${floor}%.`;
    return `${bandPart}${obsPart}${floorPart}`;
  }
  if (b.reason === VERDICT.BASELINE_DEGENERATE) return BASELINE_DEGENERATE_NOTE;
  if (b.reason === VERDICT.INSUFFICIENT_BASELINE) {
    const obs = numOrNull(b.observations);
    const needed = numOrNull(b.needed);
    if (obs === null || needed === null) return INSUFFICIENT_BASELINE_NOTE;
    return `${INSUFFICIENT_BASELINE_NOTE} It has ${obs} of the ${needed} day-to-day `
      + 'observations a band needs.';
  }
  return BASELINE_UNKNOWN_NOTE;
}

/** The period SecVault was actually collecting for this firewall. */
export function observedSentence(device) {
  const from = device && device.observedFrom;
  const to = device && device.observedTo;
  if (!from || !to) return OBSERVED_NONE_NOTE;
  return `Traffic collected from ${stamp(from)} to ${stamp(to)}. A change needs its whole `
    + 'window inside that period to be comparable.';
}

/** The changes on one firewall, in the order the engine gave them. */
export function changeList(device) {
  return device && Array.isArray(device.changes) ? device.changes.filter(Boolean) : [];
}

// ── Pieces ─────────────────────────────────────────────────────────────────

/**
 * ⛔ HATCHING, NOT A FLAT GREY FILL, for everything hueless. A flat grey segment
 * reads as a real category with a muted colour; the texture is what says "no
 * data here". Same reasoning as components/ui/NotMeasured.js's NotMeasuredBar.
 */
function Swatch({ weight }) {
  const hatched = weight.swatch === 'hatch';
  return (
    <span
      aria-hidden="true"
      style={{
        width: 14,
        height: 8,
        flex: 'none',
        borderRadius: 3,
        border: weight.border,
        background: hatched ? 'var(--hatch)' : weight.background,
        backgroundColor: hatched ? 'var(--surface-subtle)' : undefined,
      }}
    />
  );
}

function VerdictChip({ verdict }) {
  const weight = verdictWeight(verdict);
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--s2)',
        padding: 'var(--s1) var(--s2)',
        borderRadius: 'var(--radius-sm)',
        border: weight.border,
        background: weight.swatch === 'tint' ? weight.background : 'transparent',
        color: weight.color,
        fontSize: 'var(--text-xs)',
        fontWeight: weight.fontWeight,
        whiteSpace: 'nowrap',
      }}
    >
      <Swatch weight={weight} />
      {weight.label}
    </span>
  );
}

function Line({ children, muted = false }) {
  return (
    <div
      style={{
        fontSize: 'var(--text-sm)',
        lineHeight: 1.5,
        color: muted ? 'var(--text-muted)' : 'var(--text-secondary)',
      }}
    >
      {children}
    </div>
  );
}

function statValue(n, reason) {
  return n === null ? <NotMeasured reason={reason} /> : n;
}

/**
 * ⛔ NEVER OMITTED, NEVER FOLDED, AND ABOVE EVERYTHING IT QUALIFIES. The WARN
 * pair, not the DANGER pair: a reader must not carry a danger hue down into the
 * rows, where nothing is a fault.
 */
function FailuresBanner({ failures }) {
  const lines = failureList(failures);
  if (lines.length === 0) return null;
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--s2)',
        padding: 'var(--s4)',
        borderRadius: 'var(--radius)',
        border: '1px solid var(--tint-warn-fg)',
        background: 'var(--tint-warn)',
        color: 'var(--tint-warn-fg)',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--s2)',
          fontSize: 'var(--text-base)',
          fontWeight: 700,
        }}
      >
        <IconAlertTriangle width={16} height={16} />
        This board is incomplete — {lines.length} source{lines.length === 1 ? '' : 's'} could not
        be read
      </div>
      <div style={{ fontSize: 'var(--text-sm)', lineHeight: 1.5 }}>{FAILURE_NOTE}</div>
      <ul style={{ margin: 0, paddingLeft: 'var(--s5)', fontSize: 'var(--text-sm)', lineHeight: 1.6 }}>
        {lines.map((line) => (
          <li key={line} style={{ fontFamily: 'var(--font-mono)' }}>{line}</li>
        ))}
      </ul>
    </div>
  );
}

/**
 * ⛔ THE HEADLINE IS HUELESS IN EVERY SHAPE. A zero here is a measurement, and a
 * green panel would turn it into an all-clear over the 137 changes nothing could
 * be said about.
 */
function Headline({ summary }) {
  const answer = headline(summary);
  const hatched = answer.kind !== 'none_exceeded' && answer.kind !== 'some_exceeded';
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--s2)',
        padding: 'var(--s4)',
        borderRadius: 'var(--radius)',
        border: hatched ? '1px dashed var(--border)' : '1px solid var(--border)',
        background: hatched ? 'var(--surface-subtle)' : 'var(--bg-card)',
      }}
    >
      <div
        style={{
          fontSize: 'var(--text-lg)',
          fontWeight: 700,
          lineHeight: 1.4,
          color: hatched ? 'var(--unmeasured)' : 'var(--text-primary)',
        }}
      >
        {answer.text}
      </div>
    </div>
  );
}

/**
 * ⛔ NAMED AND COUNTED, ABOVE THE PER-FIREWALL LISTS. `window_incomplete` is the
 * majority state on this board and it is a limit of ours; a footer would let a
 * reader take the judged changes for the whole history.
 */
function LimitsPanel({ summary, incomplete }) {
  const rows = UNJUDGEABLE.map((verdict) => ({
    verdict,
    count: reportableCount(verdictCount(summary, verdict), incomplete),
    note: verdictNote(verdict),
  }));
  const anything = rows.some((r) => r.count === null || r.count > 0);
  if (!anything) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--s2)',
          fontSize: 'var(--text-base)',
          fontWeight: 700,
          color: 'var(--text-primary)',
        }}
      >
        <IconClock width={16} height={16} />
        {LIMITS_HEADING}
      </div>
      <Line muted>{LIMITS_NOTE}</Line>
      <Table minWidth={600}>
        <colgroup>
          <col style={{ width: '28%' }} />
          <col style={{ width: '12%' }} />
          <col style={{ width: '60%' }} />
        </colgroup>
        <thead>
          <tr>
            <th>State</th>
            <th>Changes</th>
            <th>What it means here</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.verdict}>
              <td style={{ verticalAlign: 'top' }}>
                <VerdictChip verdict={row.verdict} />
              </td>
              <td style={{ verticalAlign: 'top', color: 'var(--unmeasured)' }}>
                {statValue(row.count, INCOMPLETE_COUNT_REASON)}
              </td>
              <td style={{ verticalAlign: 'top' }}>
                <Line>{row.note}</Line>
              </td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

function ChangeRow({ change }) {
  const delta = deltaLabel(change);
  const basis = basisSentence(change);
  const note = verdictNote(change.verdict);
  return (
    <tr>
      <td style={{ verticalAlign: 'top', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
        {stamp(change.detectedAt)}
      </td>
      <td style={{ verticalAlign: 'top', color: 'var(--text-primary)' }}>
        {change.summary || 'Configuration change detected'}
      </td>
      <td style={{ verticalAlign: 'top' }}>
        <VerdictChip verdict={change.verdict} />
      </td>
      <td style={{ verticalAlign: 'top', fontFamily: 'var(--font-mono)' }}>
        {delta === null
          ? <NotMeasured reason="No movement was computed for this change." />
          : delta}
      </td>
      <td style={{ verticalAlign: 'top' }}>
        {basis ? <Line>{basis}</Line> : <Line muted>{MISSING_BASIS_NOTE}</Line>}
        {note ? <Line muted>{note}</Line> : null}
      </td>
    </tr>
  );
}

function DeviceSection({ device }) {
  const changes = changeList(device);
  return (
    <Card>
      <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--s2)', flexWrap: 'wrap' }}>
          <span style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)' }}>
            {device.deviceName || 'Unnamed firewall'}
          </span>
          <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            {changes.length} change{changes.length === 1 ? '' : 's'}
          </span>
        </div>

        {/* ⛔ THE BASIS, ABOVE THE ROWS THAT REST ON IT. A band nobody can see
            is a verdict a reader has to take on trust. */}
        <Line>{baselineSentence(device)}</Line>
        <Line muted>{observedSentence(device)}</Line>
        <Line muted>{windowSentence(device.windowHours)}</Line>

        {changes.length === 0 ? (
          <Line muted>{NO_CHANGES_NOTE}</Line>
        ) : (
          <Table minWidth={860}>
            <colgroup>
              <col style={{ width: '15%' }} />
              <col style={{ width: '22%' }} />
              <col style={{ width: '19%' }} />
              <col style={{ width: '10%' }} />
              <col style={{ width: '34%' }} />
            </colgroup>
            <thead>
              <tr>
                <th>Detected</th>
                <th>Change</th>
                <th>What followed</th>
                <th>Movement</th>
                <th>Compared with</th>
              </tr>
            </thead>
            <tbody>
              {changes.map((change) => (
                <ChangeRow key={change.changeId || `${change.detectedAt}`} change={change} />
              ))}
            </tbody>
          </Table>
        )}
      </CardBody>
    </Card>
  );
}

// ── The board ──────────────────────────────────────────────────────────────

export default function ChangeOutcomeBoard({
  devices,
  summary,
  failures,
  windowHours,
  generatedAt,
}) {
  const list = Array.isArray(devices) ? devices.filter(Boolean) : [];
  const incomplete = boardIsIncomplete(failures);
  const claim = claimText(summary);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s5)' }}>
      <div
        style={{
          fontSize: 'var(--text-base)',
          color: 'var(--text-secondary)',
          maxWidth: '95ch',
          lineHeight: 1.6,
        }}
      >
        {BOARD_PURPOSE} {windowSentence(windowHours)}{' '}
        <span style={{ color: 'var(--text-muted)' }}>({asOf(generatedAt)})</span>
      </div>

      {/* ⛔ THE ENGINE'S OWN SENTENCE, VERBATIM. No copy of it lives in this
          file — a second wording would be a second claim. */}
      <div
        style={{
          padding: 'var(--s3) var(--s4)',
          borderLeft: '3px solid var(--border)',
          fontSize: 'var(--text-sm)',
          lineHeight: 1.6,
          color: 'var(--text-secondary)',
          maxWidth: '95ch',
        }}
      >
        {claim || CLAIM_MISSING_NOTE}
      </div>

      {/* ⛔ FIRST, ABOVE THE NUMBERS. Underneath them it reads as a footnote to
          a set of counts that already looked complete. */}
      <FailuresBanner failures={failures} />

      {incomplete ? (
        <div
          style={{
            padding: 'var(--s4)',
            borderRadius: 'var(--radius)',
            border: '1px dashed var(--border)',
            background: 'var(--surface-subtle)',
            color: 'var(--unmeasured)',
            fontSize: 'var(--text-sm)',
            lineHeight: 1.6,
          }}
        >
          {INCOMPLETE_VERDICT_REASON}
        </div>
      ) : (
        <>
          <Headline summary={summary} />

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
              gap: 'var(--s4)',
            }}
          >
            {VERDICT_ORDER.map((verdict) => {
              const weight = verdictWeight(verdict);
              return (
                <StatCard
                  key={verdict}
                  label={weight.label}
                  value={statValue(
                    reportableCount(verdictCount(summary, verdict), incomplete),
                    INCOMPLETE_COUNT_REASON,
                  )}
                  color={weight.accent}
                  textColor={weight.color}
                />
              );
            })}
          </div>

          <LimitsPanel summary={summary} incomplete={incomplete} />

          {list.length === 0 ? (
            <EmptyState message={EMPTY_BOARD_NOTE} />
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
              {list.map((device) => (
                <DeviceSection key={device.deviceId || device.deviceName} device={device} />
              ))}
            </div>
          )}
        </>
      )}

      <Disclosure summary="How a verdict here is reached">
        <p>
          A band is measured from the firewall’s OWN day-to-day swings, never from a fleet
          average. The reference fleet spans a twelvefold difference in how much its firewalls
          vary from one day to the next, so one shared band would flag routine fluctuation on the
          noisiest of them and miss a real movement on the quietest.
        </p>
        <p>
          A change is judged only when SecVault holds the whole window either side of it. A window
          that reaches into the hours before collection started produces a large and completely
          meaningless figure, so those changes are listed and left unjudged rather than being
          given a verdict they cannot support.
        </p>
        <p>
          A count of changes is not a measure of anything in either direction, and no total here
          is combined into a single figure. Each verdict is reported in its own right, beside the
          number of the firewall’s own ordinary daily swings the movement was compared against.
        </p>
      </Disclosure>
    </div>
  );
}
