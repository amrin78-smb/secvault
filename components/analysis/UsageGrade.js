// components/analysis/UsageGrade.js
//
// The VIEW half of A3. `lib/engines/ruleHitCorrelation.js` decides HOW WELL a
// rule's usage figure is known; this file is the only place that draws it.
//
// ⛔ WHY A GRADE IS ON SCREEN AT ALL. `syslog_rule_hits_hourly` identifies a
// rule differently per vendor, and the split is total: measured on the live
// fleet, Fortinet's 61,835 rollup rows carry a rule id on every single one,
// while Palo Alto's 80,203 carry NULL on every single one and can only be
// matched by NAME. A name is neither unique nor stable across a config change,
// so a rule RENAMED during the window is absent from the logs under its new
// name while it is busily passing traffic under its old one.
//
// A match saying "in use" is harmless — it only ever REFUSES a deletion. An
// ABSENCE saying "unused" is what takes a rule off a firewall. So the operator
// has to be able to see, at the point the number is shown, which of those two
// kinds of answer they are looking at. Hiding it behind a tooltip would not do
// it: for `log-name` the caveat is VISIBLE TEXT beside the figure.
//
// ── THE FOUR GRADES ──────────────────────────────────────────────────────
//   device     the firewall's own counter. Strongest; no caveat needed.
//   log-id     from logs, matched by the vendor's own rule ID. Strong.
//   log-name   from logs, by rule NAME only. Carries its caveat on screen.
//   null       NOT MEASURED — hueless, per the design system.
//
// ⛔ COLOUR. Red is danger and nothing else, so a weak grade may not be red.
// Violet belongs to EvidenceMark alone and may not be borrowed here however
// much this is "about evidence" — the moment a second thing is violet the mark
// stops being learnable at a glance. That leaves teal (strongest), blue
// (strong), warn (carries a caveat), and NO HUE for not-measured. The last is
// `NotMeasured`, not a muted badge: a flat grey chip reads as a real but quiet
// category, which is exactly the reading this whole feature exists to prevent.
//
// ⛔ THE DESCRIPTORS ARE EXPORTED DATA, not strings buried in JSX, so
// tests/usageGrade.test.js can compare them rather than grep for CSS. Keep
// every new grade's copy in this table.

import Badge from '../ui/Badge';
import NotMeasured from '../ui/NotMeasured';

/**
 * The one claim a usage figure makes, and the limit on it. Exported so a
 * caller can print it above a table without re-wording it.
 */
export const USAGE_CLAIM =
  'Every usage figure states where it came from. Only the firewall\'s own counter and a '
  + 'log match on the vendor\'s rule ID are strong enough to remove a rule on.';

/**
 * ⛔ ONE ROW PER GRADE. `deletionEvidence` mirrors ruleHitCorrelation.js's own
 * field and must keep agreeing with it: only `device` and `log-id` qualify.
 *
 * `short` is what fits in a table cell; `label` is the long form for a legend
 * or a header. `caveat` is null for every grade that does not need one —
 * inventing a caveat for a strong grade would teach the operator to ignore the
 * one that matters.
 */
export const USAGE_GRADES = {
  device: {
    grade: 'device',
    short: 'device',
    label: 'Device counter',
    badgeColor: 'teal',
    tone: 'measured',
    deletionEvidence: true,
    caveat: null,
    caveatShort: null,
    title:
      'The firewall reported this count from its own hit counter. It is cumulative since that '
      + 'counter was last reset, so it spans the counter\'s lifetime rather than a window.',
  },
  'log-id': {
    grade: 'log-id',
    short: 'log id',
    label: 'Logs, by rule ID',
    badgeColor: 'info',
    tone: 'measured',
    deletionEvidence: true,
    caveat: null,
    caveatShort: null,
    title:
      'This firewall cannot report hit counters, so the figure comes from its own logs, matched '
      + 'by the vendor\'s rule ID. An ID is exact and survives a rename.',
  },
  'log-name': {
    grade: 'log-name',
    short: 'log name',
    label: 'Logs, by rule name only',
    badgeColor: 'warning',
    tone: 'measured',
    deletionEvidence: false,
    caveat:
      'This firewall\'s logs identify rules by name only, so the figure rests on the rule name '
      + 'being unchanged across the window. A rule renamed during it reads as having had no '
      + 'traffic while it is still passing some — not enough on its own to remove the rule.',
    caveatShort: 'name match only — a rename would hide traffic',
    title:
      'This firewall\'s logs carry no rule ID, so the rule was matched by NAME. A name is '
      + 'neither unique nor stable across a config change.',
  },
};

/**
 * ⛔ NOT MEASURED IS A STATE, NOT A MISSING VALUE, and it has no hue:
 * `badgeColor` is null and nothing in this entry may ever be given one. An
 * absence of news is not good news and not bad news, and drawing it as either
 * is the same lie in a different direction.
 */
export const USAGE_NOT_MEASURED = {
  grade: null,
  short: 'not measured',
  label: 'Not measured',
  badgeColor: null,
  tone: 'unmeasured',
  deletionEvidence: false,
  caveat: null,
  caveatShort: null,
  title:
    'Neither the firewall\'s own counter nor its logs can say whether this rule has passed '
    + 'traffic. That is an absence of evidence, never evidence of absence.',
};

/**
 * Why a log-derived answer is missing, in one sentence per `logEvidence` code.
 *
 * ⛔ `insufficient-history` AND `no-coverage` ARE DIFFERENT FACTS AND MUST READ
 * DIFFERENTLY. The first is SECVAULT'S limit — the rollup does not go back far
 * enough for the window being asked about, and every device on the fleet shares
 * it. The second is the DEVICE'S — it was not sending logs throughout a window
 * we do have. Conflating them reports our own install date as a fault of the
 * firewall, which is the precise bug A3 fixed in the engine; repeating it in
 * the sentence would undo the fix where the operator actually reads it.
 *
 * `{days}` is substituted by logEvidenceSentence().
 */
export const LOG_EVIDENCE_REASONS = {
  hits: {
    state: 'hits',
    text: 'Seen in this firewall\'s own logs over the last {days} days.',
  },
  'measured-zero': {
    state: 'measured-zero',
    text:
      'No matching traffic in {days} days of firewall logs, over a window this device logged '
      + 'throughout. A measured zero, not an absent answer.',
  },
  'no-coverage': {
    state: 'not-measured',
    text:
      'Not measured: this firewall did not send logs throughout the {days}-day window, so its '
      + 'silence measures the collector, not the rule.',
  },
  'insufficient-history': {
    state: 'not-measured',
    text:
      'Not measured: SecVault has not been collecting logs long enough to say. The {days}-day '
      + 'window is longer than the log history this installation holds — a limit of ours, not a '
      + 'fact about this firewall.',
  },
  'window-too-short': {
    state: 'not-measured',
    text:
      'Not measured: this firewall logged in too few hours of the {days}-day window for its '
      + 'silence to mean anything.',
  },
  'rule-logging-disabled': {
    state: 'not-measured',
    text:
      'Not measured: logging is switched off on this rule, so it cannot appear in the logs at '
      + 'all however much traffic it passes. Its absence is not evidence.',
  },
  'no-rule-identity': {
    state: 'not-measured',
    text:
      'Not measured: this firewall\'s logs do not say which rule matched, so no rule on it can '
      + 'be found — or ruled out — in them.',
  },
};

export const LOG_EVIDENCE_UNKNOWN = {
  state: 'not-measured',
  text: 'Not measured: no log evidence is available for this rule.',
};

const DEFAULT_WINDOW_DAYS = 30;

/**
 * The descriptor for a grade. An unrecognised grade resolves to NOT MEASURED
 * rather than to the nearest match — a value this file has not been taught is
 * not something to make a confident claim about.
 */
export function usageGradeDescriptor(grade) {
  if (grade && Object.prototype.hasOwnProperty.call(USAGE_GRADES, grade)) {
    return USAGE_GRADES[grade];
  }
  return USAGE_NOT_MEASURED;
}

/** One sentence for a `logEvidence` code, with the window substituted in. */
export function logEvidenceSentence(code, windowDays) {
  const days = Number.isFinite(Number(windowDays)) && Number(windowDays) > 0
    ? Math.trunc(Number(windowDays))
    : DEFAULT_WINDOW_DAYS;
  const entry = (code && Object.prototype.hasOwnProperty.call(LOG_EVIDENCE_REASONS, code))
    ? LOG_EVIDENCE_REASONS[code]
    : LOG_EVIDENCE_UNKNOWN;
  return entry.text.replace('{days}', String(days));
}

/**
 * The hover text for a figure: what the grade means, then the window it was
 * measured over.
 */
export function usageTitle(grade, logEvidence, windowDays) {
  const d = usageGradeDescriptor(grade);
  const sentence = logEvidenceSentence(logEvidence, windowDays);
  if (d.grade === 'device') return d.title;
  return `${d.title} ${sentence}`;
}

// ── view ──────────────────────────────────────────────────────────────────
// Everything above is pure data and pure functions, so tests/usageGrade.test.js
// can evaluate it directly. Everything below is JSX.

/**
 * The chip itself. Module top level, never nested in another component.
 *
 * ⛔ A null grade renders through NotMeasured, which is hueless and carries a
 * reason on hover — never a muted Badge, which reads as a quiet category.
 */
export function UsageGradeBadge({ grade, reason }) {
  const d = usageGradeDescriptor(grade);
  if (!d.badgeColor) {
    return <NotMeasured text={d.short} reason={reason || d.title} />;
  }
  return (
    <Badge color={d.badgeColor} title={reason ? `${d.title} ${reason}` : d.title}>
      {d.short}
    </Badge>
  );
}

/**
 * A rule's usage figure, with what it rests on.
 *
 * Takes a rule already enriched by the correlation engine:
 *   { effectiveHitCount, usageGrade, logEvidence, logWindowDays }
 *
 * ⛔ THREE OUTCOMES AND THEY MUST NOT BLUR. A real count, a MEASURED zero (a
 * real, earned number and the evidence a cleanup runs on), and NOT MEASURED —
 * which is an em-dash with a reason, never a 0 and never a blank cell.
 *
 * ⛔ The `log-name` caveat is printed, not just hovered. It is the difference
 * between a figure that may inform a deletion and one that may not, and a
 * tooltip is not a place to put that.
 */
export default function RuleUsageCell({ rule }) {
  const r = rule || {};
  const days = r.logWindowDays;
  const count = r.effectiveHitCount;
  const sentence = logEvidenceSentence(r.logEvidence, days);

  if (count === null || count === undefined) {
    return <NotMeasured reason={sentence} />;
  }

  const d = usageGradeDescriptor(r.usageGrade);
  return (
    <span style={{ display: 'inline-flex', flexDirection: 'column', gap: 'var(--s1)' }}>
      <span
        style={{ fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)' }}
        title={usageTitle(r.usageGrade, r.logEvidence, days)}
      >
        {Number(count).toLocaleString()}
      </span>
      <UsageGradeBadge grade={r.usageGrade} reason={sentence} />
      {d.caveatShort ? (
        <span
          style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', lineHeight: 1.35 }}
          title={d.caveat}
        >
          {d.caveatShort}
        </span>
      ) : null}
    </span>
  );
}
