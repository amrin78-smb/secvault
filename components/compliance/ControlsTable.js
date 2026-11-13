import Link from 'next/link';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import TimeAgo from '../ui/TimeAgo';
import NotMeasured from '../ui/NotMeasured';
import { SEVERITY_BADGE_COLOR, SEVERITY_LABEL } from '../analysis/severityRamp';
import {
  FAILING,
  WARNING,
  NOT_MEASURED,
  PARTIAL,
  CLEAN,
  NOT_EVALUABLE,
  NOT_APPLICABLE,
  STATE_LABELS,
  STATE_TONES,
} from '../../lib/engines/complianceControls';
import { vendorLabel } from '../devices/vendorMeta';
import { WRAP_CELL } from '../ui/tableStyles';

// The check library read across the fleet: one row per CONTROL.
//
// ⛔ EVERY NUMBER IN THIS TABLE IS A COUNT OF FIREWALLS, AND EVERY CELL SAYS
// SO. A control is not pass or fail — it is failing on four firewalls and
// passing on eleven, simultaneously. A column headed "Status" with a single
// badge would be picking one of those answers and discarding the rest, so the
// badge states the ROLL-UP and the cell beside it always carries the split it
// was rolled up from.
//
// ⛔ THERE IS NO PERCENTAGE COLUMN. One compliance percentage exists in this
// product and it is the headline score; a per-control "69% compliant" computed
// over a different denominator would sit on the same screen disagreeing with
// it. Counts, and a state.

const STANDARD_LABEL = {
  PCI_DSS: 'PCI DSS',
  ISO_27001: 'ISO 27001',
  CIS_V8: 'CIS v8',
  NIST: 'NIST',
  SANS: 'SANS',
};

const TONE_BADGE = { danger: 'danger', warning: 'warning', success: 'success' };

// ⛔ EVERY STATE EXPLAINS ITSELF ON HOVER, AND THE FOUR NON-FAILURES EXPLAIN
// THEMSELVES DIFFERENTLY. "Never measured" and "not evaluable from config"
// look alike and send an operator to opposite places: the first clears itself
// the next time a config is collected, the second never clears at all.
const STATUS_REASON = {
  [FAILING]: 'At least one firewall answered this check with a failure. That is a measurement.',
  [WARNING]: 'No firewall failed, but at least one answered indeterminately — the check ran against a collected config and could not reach a verdict.',
  [NOT_MEASURED]: 'This check applies to firewalls in this fleet and not one of them has an answer. Clears itself once a config is collected and the audit runs.',
  [PARTIAL]: 'Passing on every firewall SecVault could ask, and it could not ask all of them. This is not a clean result.',
  [CLEAN]: 'Passing on every firewall this check applies to, with no firewall left unanswered.',
  [NOT_EVALUABLE]: 'Declared unanswerable from a config snapshot. Permanent — nothing an operator changes on a firewall makes this check answerable, so it is excluded from the score rather than counted against it.',
  [NOT_APPLICABLE]: 'No active firewall is of this check’s vendor, so the check can never run here.',
};

// ⛔ WHY THE FOUR HUELESS STATES DO NOT GET A `muted` BADGE. --text-muted and
// --unmeasured are four hex digits apart and indistinguishable on screen, so a
// grey badge would make "never measured" and "passing" differ only by the WORD
// inside them. The hatch is the carrier, exactly as it is on a stat tile's
// dashed border and in NotMeasuredBar — a texture nothing else in the product
// uses.
function statusChip(control) {
  const tone = STATE_TONES[control.status];
  const label = STATE_LABELS[control.status] || control.status;
  const reason = STATUS_REASON[control.status] || null;
  if (TONE_BADGE[tone]) {
    return <Badge color={TONE_BADGE[tone]} title={reason}>{label}</Badge>;
  }
  return (
    <span
      title={reason}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: '2px 8px',
        borderRadius: 'var(--radius-pill)',
        border: '1px solid var(--border)',
        fontSize: 'var(--text-xs)',
        fontWeight: 600,
        color: 'var(--unmeasured)',
        background: 'var(--hatch)',
        backgroundColor: 'var(--surface-subtle)',
      }}
    >
      <span
        aria-hidden="true"
        style={{
          width: 10,
          height: 6,
          flex: 'none',
          borderRadius: 2,
          border: '1px solid var(--border)',
          background: 'var(--hatch)',
          backgroundColor: 'var(--bg-card)',
        }}
      />
      {label}
    </span>
  );
}


/**
 * The firewall split behind the badge. Plain function, called imperatively —
 * never a nested component (CLAUDE.md's first Critical Rule).
 *
 * ⛔ THE DENOMINATOR IS `applicable`, NOT `answered`. "4 of 4 failing" over a
 * fleet of sixteen where twelve were never asked is true and useless; the
 * reader needs to see the twelve. Where `applicable` could not be read it says
 * so rather than quietly falling back to the smaller number, which would make
 * every control look fully covered.
 */
function firewallCell(control) {
  const { counts, applicableDeviceCount: applicable, answeredDeviceCount: answered } = control;
  const denom = applicable === null ? null : applicable;
  const of = denom === null ? 'an unknown number of' : denom;

  if (control.status === NOT_APPLICABLE) {
    return <NotMeasured reason={`No active firewall is ${control.vendor ? `a ${vendorLabel(control.vendor)}` : 'of this vendor'}, so this check never runs here.`} />;
  }
  if (control.status === NOT_EVALUABLE) {
    return <NotMeasured reason={STATUS_REASON[NOT_EVALUABLE]} text={`— of ${of}`} />;
  }
  if (control.status === NOT_MEASURED) {
    return (
      <span style={{ color: 'var(--unmeasured)', fontVariantNumeric: 'tabular-nums' }}
        title={`0 of ${of} applicable firewalls have an answer for this check.`}>
        0 of {of} answered
      </span>
    );
  }

  const failing = counts.fail;
  const lines = [];
  if (failing > 0) {
    lines.push(
      <span key="fail" style={{ color: 'var(--tint-danger-fg)', fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>
        {failing} of {of} failing
      </span>
    );
  } else if (counts.warning > 0) {
    lines.push(
      <span key="warn" style={{ color: 'var(--tint-warn-fg)', fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>
        {counts.warning} of {of} indeterminate
      </span>
    );
  } else {
    lines.push(
      <span key="pass" style={{ fontVariantNumeric: 'tabular-nums' }}>
        {counts.pass} of {of} passing
      </span>
    );
  }

  // ⛔ THE GAP IS STATED ON EVERY ROW THAT HAS ONE, not only on `partial`. A
  // control failing on 4 of 16 with 9 never asked is a WORSE picture than the
  // badge alone admits, and the unasked nine are where the next failure comes
  // from.
  const gap = control.notEvaluatedDeviceCount;
  if (gap === null) {
    lines.push(
      <span key="gap" style={{ color: 'var(--unmeasured)', fontSize: 'var(--text-xs)' }}
        title="The number of firewalls this check applies to could not be read, so the coverage of this row is unknown.">
        coverage unknown
      </span>
    );
  } else if (gap > 0) {
    lines.push(
      <span key="gap" style={{ color: 'var(--unmeasured)', fontSize: 'var(--text-xs)' }}
        title={`${gap} applicable ${gap === 1 ? 'firewall has' : 'firewalls have'} no answer for this check — they were never asked, which is not the same as having passed.`}>
        {gap} never asked
      </span>
    );
  }
  if (counts.na > 0) {
    lines.push(
      <span key="na" style={{ color: 'var(--unmeasured)', fontSize: 'var(--text-xs)' }}
        title="SecVault could not put this question to these firewalls — no usable config, or no ruleset collected. Excluded from the score rather than counted against it.">
        {counts.na} not answerable
      </span>
    );
  }
  if (counts.unreadable > 0) {
    lines.push(
      <span key="bad" style={{ color: 'var(--unmeasured)', fontSize: 'var(--text-xs)' }}
        title="These findings carry a status SecVault does not recognise. They are counted here rather than being read as a pass.">
        {counts.unreadable} unreadable
      </span>
    );
  }

  // ⛔ `inline-flex`, NOT `flex`. As a block child of <summary> it pushed the
  // disclosure triangle onto its own line above the counts, which reads as a
  // stray glyph rather than as a control.
  const body = (
    <span style={{ display: 'inline-flex', flexDirection: 'column', gap: 2, verticalAlign: 'top' }}>
      {lines}
    </span>
  );

  // ⛔ THE NAMES ARE ONE CLICK AWAY, NEVER A SEPARATE PAGE. "Which firewalls"
  // is the next question after "how many", and a count with no way through to
  // the list is where an operator leaves this page for a spreadsheet.
  if (control.failingDevices.length === 0) return body;
  return (
    <details>
      <summary style={{ cursor: 'pointer', listStyle: 'revert' }}>{body}</summary>
      <ul style={{ margin: '6px 0 0', paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 2 }}>
        {control.failingDevices.map((d) => (
          <li key={d.deviceId} style={{ fontSize: 'var(--text-xs)' }}>
            <Link href={`/compliance/${d.deviceId}`}>{d.deviceName || d.deviceId}</Link>
          </li>
        ))}
      </ul>
    </details>
  );
}

function severityCell(control) {
  if (!control.severity) return <NotMeasured reason="This check carries no severity." />;
  if (!control.severityKnown) {
    return (
      <span title={`"${control.severity}" is not one of this product's severity levels, so it is shown as the library recorded it rather than mapped to a default.`}
        style={{ color: 'var(--unmeasured)' }}>
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

export default function ControlsTable({ controls }) {
  return (
    <Table>
      <colgroup>
        {/* ⛔ WIDTHS MEASURED AGAINST THE RENDERED PAGE, NOT GUESSED. The first
            draft gave Accepted 7% and Last run 8%, which clipped their own
            COLUMN HEADINGS to "ACCE…" and "LAST R…" at 1440px — a header a
            reader cannot finish is worse than a narrow one, because the cell
            below it then means nothing. */}
        <col style={{ width: '27%' }} />
        <col style={{ width: '10%' }} />
        <col style={{ width: '16%' }} />
        <col style={{ width: '13%' }} />
        <col style={{ width: '15%' }} />
        <col style={{ width: '9%' }} />
        <col style={{ width: '10%' }} />
      </colgroup>
      <thead>
        <tr>
          <th scope="col">Control</th>
          <th scope="col">Severity</th>
          <th scope="col">Frameworks</th>
          <th scope="col">Status</th>
          <th scope="col">Firewalls</th>
          <th scope="col" title="Firewalls with a live, unexpired exception recorded against this control. An exception never changes a finding's status and never moves the score.">
            Accepted
          </th>
          <th scope="col">Last run</th>
        </tr>
      </thead>
      <tbody>
        {controls.map((c) => (
          <tr key={c.slug}>
            <td style={WRAP_CELL}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <span style={{ fontWeight: 600 }}>{c.name}</span>
                <code style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{c.slug}</code>
                {/* ⛔ TWO SEPARATE THINGS WERE WRONG HERE AND ONLY ONE WAS
                    VISIBLE. `app/globals.css` sets `white-space: nowrap` on
                    EVERY `td`, so the first draft's descriptions were cut at
                    the column edge mid-word — not clamped, not ellipsised,
                    just gone, and the control NAMES with them. The cells now
                    carry `WRAP_CELL` (the shared opt-out) so the text wraps;
                    this clamp then bounds a paragraph-long seed description to
                    two lines with the whole string on hover. A clamp that
                    keeps the full value reachable is not the truncation the
                    density rule forbids — a hard clip is. */}
                {c.description && (
                  <span
                    title={c.description}
                    style={{
                      fontSize: 'var(--text-xs)',
                      color: 'var(--text-secondary)',
                      display: '-webkit-box',
                      WebkitLineClamp: 2,
                      WebkitBoxOrient: 'vertical',
                      overflow: 'hidden',
                    }}
                  >
                    {c.description}
                  </span>
                )}
                {c.vendor && (
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                    {vendorLabel(c.vendor)} only
                  </span>
                )}
              </div>
            </td>
            <td style={WRAP_CELL}>{severityCell(c)}</td>
            <td style={WRAP_CELL}>
              <span style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {c.standards.length === 0
                  ? <NotMeasured reason="This check is not mapped to any framework in the library." />
                  : c.standards.map((s) => (
                    <Badge key={s} color="info">{STANDARD_LABEL[s] || s}</Badge>
                  ))}
              </span>
            </td>
            <td style={WRAP_CELL}>{statusChip(c)}</td>
            <td style={WRAP_CELL}>{firewallCell(c)}</td>
            <td style={{ ...WRAP_CELL, fontVariantNumeric: 'tabular-nums' }}>
              {c.exceptionDeviceCount === null
                ? <NotMeasured reason="The recorded exceptions could not be read, so whether this control is covered by one is unknown." />
                : c.exceptionDeviceCount}
            </td>
            <td style={WRAP_CELL}><TimeAgo value={c.lastEvaluated} empty="Never" /></td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
