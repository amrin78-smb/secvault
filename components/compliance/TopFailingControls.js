import Link from 'next/link';
import Card, { CardTitle } from '../ui/Card';
import Badge from '../ui/Badge';
import NotMeasured from '../ui/NotMeasured';
import { SEVERITY_BADGE_COLOR, SEVERITY_LABEL } from '../analysis/severityRamp';
import { FAILING, sortControls } from '../../lib/engines/complianceControls';

// The handful of controls failing on the most firewalls — a teaser into
// /compliance/controls, which is the page that answers the question properly.
//
// ⛔ IT DOES NO DATA ACCESS, AND THAT IS A CORRECTNESS RULE RATHER THAN A
// PERFORMANCE ONE. The page mounting this already holds `gatherControls`'
// output; a second query here would be a second measurement of the same fact,
// taken a few hundred milliseconds later against a database that is also
// taking ~1,000 syslog inserts a second. It would eventually disagree with the
// table beside it, and the reader has no way to tell which of the two numbers
// on one screen is the real one. One read, two renderings.
//
// ⛔ EVERY NUMBER HERE IS A COUNT OF FIREWALLS. `audit_findings` rows are
// (device, check) PAIRS, so a control is failing on four firewalls and passing
// on eleven simultaneously — both true. Rendering a control as simply "failed"
// picks one of those answers and discards the rest, which is
// `complianceControls.js`'s founding rule ("A CONTROL HAS NO SINGLE
// FLEET-WIDE STATUS") thrown away by the widget that summarises it.
//
// ⛔ NO PERCENTAGE, ANYWHERE. `scorePct` is the one compliance figure this
// product publishes. A "69% compliant" here would be a second percentage over
// a different denominator sitting on the SAME SCREEN as the headline score,
// disagreeing with it — exactly the artefact `compliance_exceptions` is barred
// from creating ("COUNTS AND A HUELESS GRADE, NEVER A RIVAL PERCENTAGE").
//
// ⛔ AND AN EMPTY WIDGET IS NOT AN ALL-CLEAR. Zero failing controls over a
// library nothing has answered is the SAME ZERO as a perfectly compliant
// fleet. That is this codebase's signature bug — a failed read recorded as an
// affirmative value — in its most reassuring possible form: a green tick on a
// compliance dashboard. See `emptyState()` below, which is the most important
// function in this file.

// ⛔ FIVE, AND THE REMAINDER IS ALWAYS DISCLOSED. CLAUDE.md's v2.222.0 rule
// for a summary widget: cap the list, count the remainder, never let a
// truncated list look complete. A list the operator works to the bottom of
// believing they are finished is the more insidious failure — worse than a
// long list, because it ends.
const MAX_ROWS = 5;

/** A real, readable count — never `Number(null)`, which is a finite 0. */
function finite(v) {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

/**
 * How much of the library was NOT actually evaluated.
 *
 * ⛔ THREE OUTCOMES, NOT TWO, AND IT FAILS CLOSED. `known: false` covers a
 * summary whose gap fields are absent or unreadable — and an unproven
 * completeness is never printed as a clean one. A missing field read as 0
 * would turn "we cannot tell whether this library was evaluated" into "it was
 * fully evaluated and everything passed", which is the one sentence this
 * widget must never be able to produce by accident.
 *
 * `notEvaluable` is deliberately NOT part of this. It is PERMANENT — nothing
 * an operator changes on a firewall makes those checks answerable, and they
 * are excluded from the score rather than counted against it. Folding it in
 * here would make a correctly-behaving library permanently unable to report a
 * clean result, which teaches an operator to ignore the caveat that matters.
 */
function gapState(summary) {
  const s = summary && typeof summary === 'object' ? summary : {};
  const notMeasured = finite(s.notMeasured);
  const partial = finite(s.partial);
  if (notMeasured === null || partial === null) {
    return { known: false, notMeasured, partial, total: null };
  }
  return { known: true, notMeasured, partial, total: notMeasured + partial };
}

/** The hueless hatched swatch — the one carrier of "this is a gap in OUR reach". */
function hatchSwatch() {
  return (
    <span
      aria-hidden="true"
      style={{
        width: 14,
        height: 8,
        flex: 'none',
        borderRadius: 3,
        border: '1px solid var(--border)',
        background: 'var(--hatch)',
        backgroundColor: 'var(--surface-subtle)',
      }}
    />
  );
}

/**
 * The severity chip. Plain function called imperatively — NEVER a component
 * defined inside another component (CLAUDE.md's first Critical Rule: a nested
 * definition remounts the whole subtree on every render and loses input
 * focus).
 *
 * ⛔ AN UNRECOGNISED SEVERITY IS SHOWN RAW AND HUELESS, never mapped to a
 * default. `medium` is the column's DEFAULT, so silently badging an
 * unrecognised value as Medium would invent a grading the library never
 * recorded — the same call `ControlsTable` makes one page over.
 */
function severityChip(control) {
  if (!control.severity) {
    return <NotMeasured reason="This check carries no severity." />;
  }
  if (!control.severityKnown) {
    return (
      <span
        title={`“${control.severity}” is not one of this product's severity levels, so it is shown as the library recorded it rather than mapped to a default.`}
        style={{ color: 'var(--unmeasured)', fontSize: 'var(--text-xs)' }}
      >
        {control.severity}
      </span>
    );
  }
  return (
    <Badge color={SEVERITY_BADGE_COLOR[control.severity]}>
      {SEVERITY_LABEL[control.severity] || control.severity}
    </Badge>
  );
}

/**
 * "4 of 16 firewalls failing" — the split, never a verdict.
 *
 * ⛔ THE DENOMINATOR IS `applicable`, NOT `answered`. "4 of 4 failing" over a
 * fleet of sixteen where twelve were never asked is true and useless, and it
 * makes the worst-covered control look like the best-understood one. Where
 * `applicable` could not be read it SAYS so rather than quietly falling back
 * to the smaller number — a fallback there would make every control on the
 * page look fully covered.
 */
function firewallLine(control) {
  const failing = control.counts.fail;
  const applicable = control.applicableDeviceCount;
  const of = applicable === null || applicable === undefined
    ? 'an unknown number of'
    : applicable;
  return (
    <span
      style={{
        color: 'var(--tint-danger-fg)',
        fontWeight: 600,
        fontVariantNumeric: 'tabular-nums',
        fontSize: 'var(--text-sm)',
      }}
    >
      {failing} of {of} firewalls failing
    </span>
  );
}

/**
 * The gap, carried beside the failure count on the SAME row.
 *
 * ⛔ THE GAP TRAVELS WITH THE COUNT. "Failing on 3 of 8" with 5 never asked is
 * a WORSE picture than the 3 admits, and those five unasked firewalls are
 * precisely where the next failure comes from. Printing the failure count
 * alone would let a reader treat 3 as the whole answer.
 *
 * ⛔ HUELESS, ALWAYS. A gap in SecVault's measurement is not a severity of the
 * customer's, so it never goes on the severity ramp.
 */
function gapLine(control) {
  const gap = control.notEvaluatedDeviceCount;
  if (gap === null || gap === undefined) {
    return (
      <span
        style={{ color: 'var(--unmeasured)', fontSize: 'var(--text-xs)', display: 'inline-flex', alignItems: 'center', gap: 6 }}
        title="The number of firewalls this check applies to could not be read, so the coverage of this row is unknown."
      >
        {hatchSwatch()}
        coverage unknown
      </span>
    );
  }
  if (gap <= 0) return null;
  return (
    <span
      style={{ color: 'var(--unmeasured)', fontSize: 'var(--text-xs)', display: 'inline-flex', alignItems: 'center', gap: 6 }}
      title={`${gap} applicable ${gap === 1 ? 'firewall has' : 'firewalls have'} no answer for this check — they were never asked, which is not the same as having passed.`}
    >
      {hatchSwatch()}
      {gap} never asked
    </span>
  );
}

/**
 * ⛔ THE SINGLE MOST IMPORTANT FUNCTION HERE. Nothing failing is not the same
 * fact as nothing measured, and on a compliance dashboard the two zeroes are
 * byte-identical: `summary.failingControls === 0` either way.
 *
 * So the all-clear is GATED ON PROVEN COMPLETENESS, not on the absence of
 * failures, and the three outcomes are WORDED APART rather than merely tinted
 * apart — a reader must never have to inspect a colour to work out which of
 * them they are looking at (the rule /work follows for its own two empty
 * states).
 */
function emptyState(summary) {
  const gap = gapState(summary);

  // (1) We could not even establish whether the library was evaluated. Fails
  // closed to "unknown", hueless — never to a tick.
  if (!gap.known) {
    return (
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--s2)', color: 'var(--unmeasured)', fontSize: 'var(--text-sm)' }}>
        {hatchSwatch()}
        <span>
          No control is failing. Whether the library was fully evaluated could not be
          determined, so this is not an all-clear.
        </span>
      </div>
    );
  }

  // (2) Measured, and measurably incomplete. The counts are named separately
  // because they send an operator to different places: `notMeasured` clears
  // itself the next time a config is collected and the audit runs, while
  // `partial` is a control passing only on the firewalls SecVault could ask.
  if (gap.total > 0) {
    const parts = [];
    if (gap.notMeasured > 0) {
      parts.push(`${gap.notMeasured} ${gap.notMeasured === 1 ? 'control has' : 'controls have'} never been measured`);
    }
    if (gap.partial > 0) {
      parts.push(`${gap.partial} ${gap.partial === 1 ? 'is passing' : 'are passing'} only on the firewalls SecVault could ask`);
    }
    return (
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--s2)', color: 'var(--unmeasured)', fontSize: 'var(--text-sm)' }}>
        {hatchSwatch()}
        <span>
          No control is failing, but the library was not fully evaluated: {parts.join(', and ')}.
          This is not an all-clear.
        </span>
      </div>
    );
  }

  // (3) The only path that may claim a clean result: every control the library
  // holds was evaluated, on every firewall it applies to, and none failed.
  return (
    <div style={{ color: 'var(--tint-success-fg)', fontSize: 'var(--text-sm)' }}>
      No control is failing on any firewall, and every control in the library was evaluated.
    </div>
  );
}

/**
 * @param {object[]} controls  `gatherControls().controls` — already built and
 *        already sorted by the engine. Not re-queried, not re-derived.
 * @param {object} summary     `gatherControls().summary` — computed over the
 *        WHOLE library, before any filter.
 */
export default function TopFailingControls({ controls, summary }) {
  const list = Array.isArray(controls) ? controls : [];

  // ⛔ SORTED WITH THE ENGINE'S OWN `sortControls`, NEVER A LOCAL COMPARATOR.
  // The caller hands this an already-sorted array and filtering preserves that
  // order, so this is a no-op today — but a local `.sort()` here would be a
  // SECOND ordering that could drift from the table this widget links into,
  // and then the "top 5" on the dashboard would not be the first 5 rows of the
  // page it promises to show them on. Importing the one definition cannot
  // drift; re-implementing it eventually does.
  //
  // ⛔ `c.counts` IS PART OF THE ADMISSION TEST, not a defensive flourish.
  // `sortControls` reads `counts.fail` directly, so a shapeless row would
  // throw and take down the page this widget is mounted on — chrome killing
  // its host. A row that cannot be rendered is dropped from the LIST only: the
  // remainder sentence below is denominated on the SUMMARY, so a dropped row
  // is still counted in "showing 5 of N" rather than vanishing from the total.
  const failing = sortControls(
    list.filter((c) => c && c.status === FAILING && c.counts && typeof c.counts === 'object')
  );
  const shown = failing.slice(0, MAX_ROWS);

  // ⛔ THE DENOMINATOR IS THE SUMMARY'S, AND THE MAX IS A FAIL-SAFE. The
  // summary is computed over the unfiltered library, which is the number the
  // operator will actually find on /compliance/controls?status=failing. If the
  // two ever disagree, the LARGER wins: under-stating the remainder makes a
  // truncated list look complete, which is the dangerous direction here.
  const summaryFailing = finite(summary && summary.failingControls);
  const totalFailing = Math.max(failing.length, summaryFailing === null ? 0 : summaryFailing);
  const truncated = totalFailing > shown.length;

  return (
    <Card>
      <div className="card-body-compact">
        <CardTitle compact>Top failing controls</CardTitle>

        {shown.length === 0 ? (
          emptyState(summary)
        ) : (
          <>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 'var(--s3)' }}>
              {/* ⛔ THE UNIT IS NAMED ON SCREEN, not only in the engine's
                  comments. Every mock of this page gets it wrong, and a reader
                  who assumes a control is simply "failed" will read the number
                  beside it as a severity rather than as a firewall count. */}
              Ranked by how many firewalls fail them. A control can be failing on one firewall
              and passing on another; both are true.
            </div>

            <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
              {shown.map((c) => (
                <li key={c.slug} style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 'var(--s2)', flexWrap: 'wrap' }}>
                    {/* ⛔ `encodeURIComponent` ON THE SLUG. `audit_checks.check_id`
                        is operator-visible curated TEXT, not a UUID — a future
                        check id containing a slash or a space would otherwise
                        build a URL pointing somewhere else entirely. */}
                    <Link
                      href={`/compliance/controls/${encodeURIComponent(c.slug)}`}
                      style={{ fontWeight: 600, fontSize: 'var(--text-sm)' }}
                    >
                      {c.name}
                    </Link>
                    {severityChip(c)}
                  </span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 'var(--s3)', flexWrap: 'wrap' }}>
                    {firewallLine(c)}
                    {gapLine(c)}
                  </span>
                </li>
              ))}
            </ul>

            {truncated && (
              // ⛔ THE REMAINDER IS DISCLOSED IN WORDS, NEVER IMPLIED BY THE
              // "view all" LINK. An operator who reads five rows and a link
              // reasonably concludes the five ARE the failing controls; the
              // sentence is what stops them acting on a list that ends before
              // the work does.
              <div style={{ marginTop: 'var(--s3)', fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
                Showing {shown.length} of {totalFailing} failing controls.
              </div>
            )}
          </>
        )}

        <div style={{ marginTop: 'var(--s3)', fontSize: 'var(--text-xs)' }}>
          <Link href="/compliance/controls?status=failing">All failing controls</Link>
        </div>
      </div>
    </Card>
  );
}
