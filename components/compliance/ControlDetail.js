import Link from 'next/link';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import TimeAgo from '../ui/TimeAgo';
import Card, { CardBody, CardTitle } from '../ui/Card';
import NotMeasured from '../ui/NotMeasured';
import { SEVERITY_BADGE_COLOR, SEVERITY_LABEL } from '../analysis/severityRamp';
import { STATE_LABELS, STATE_TONES } from '../../lib/engines/complianceControls';
import { vendorLabel } from '../devices/vendorMeta';
import { WRAP_CELL } from '../ui/tableStyles';

// ONE control, everything SecVault knows about it.
//
// ⛔ WHY THIS EXISTS. `audit_checks.remediation_guidance` is the only
// plain-English statement in this product of how to FIX a control, and until
// this page it was reachable only by opening a firewall, then one of its 74
// findings — so you could read how to fix a control only for the one firewall
// you happened to pick, and only if that firewall had been audited at all.
//
// ⛔ EVERY FIGURE HERE IS A COUNT OF FIREWALLS AND THERE IS NO PERCENTAGE.
// `scorePct` is the single compliance percentage this product publishes. A
// per-control "69% compliant" computed over a different denominator would sit
// on the same screen disagreeing with it — the artefact `compliance_exceptions`
// is barred from creating, for the same reason. Counts, and a state.
//
// ⛔ THE ROLL-UP IS `buildControl`'s, NOT A SECOND ONE. The badge at the top of
// this page is the same object the row on /compliance/controls rendered. A
// detail page that recomputed its own status would eventually disagree with the
// row that linked to it, and a reader would have no way to tell which was
// lying.

const STANDARD_LABEL = {
  PCI_DSS: 'PCI DSS',
  ISO_27001: 'ISO 27001',
  CIS_V8: 'CIS v8',
  NIST: 'NIST',
  SANS: 'SANS',
};

const TONE_BADGE = { danger: 'danger', warning: 'warning', success: 'success', muted: 'muted' };

// ⛔ A HATCHED, HUELESS CHIP — NOT A GREY BADGE. `--text-muted` and
// `--unmeasured` are four hex digits apart and indistinguishable on screen, so
// a grey badge would make "never answered" and "passing" differ only by the
// WORD inside them. The hatch is the carrier, exactly as it is on a stat tile's
// dashed border and in NotMeasuredBar. Plain function called imperatively,
// never a nested component (CLAUDE.md's first Critical Rule).
function huelessChip(label, reason) {
  return (
    <span
      title={reason}
      aria-label={reason ? `Not measured: ${reason}` : undefined}
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

function rollupChip(control) {
  const tone = STATE_TONES[control.status];
  const label = STATE_LABELS[control.status] || control.status;
  if (TONE_BADGE[tone] && tone !== 'muted') {
    return <Badge color={TONE_BADGE[tone]}>{label}</Badge>;
  }
  return huelessChip(label, 'This is a statement about SecVault’s reach, not a severity of the fleet’s.');
}

// ── one firewall's answer ───────────────────────────────────────────────────
//
// ⛔ SIX ANSWERS, NOT FOUR, AND THE TWO ADDITIONS ARE THE ONES THAT MATTER.
// `null` is a firewall this control APPLIES TO that has no finding row at all
// — nobody put the question to it. `unreadable` is a status column value
// SecVault does not recognise (`audit_findings.status` has no CHECK
// constraint). Rendering either as a pass, or as an empty cell, is this
// codebase's signature bug: a failed read recorded as an affirmative value.
//
// ⛔ `na` IS NOT A PASS AND IS EXCLUDED FROM THE SCORE. SecVault could not put
// the question to this firewall — no usable config, no ruleset collected, or
// a check declared unanswerable by construction. That is a gap in OUR reach,
// so it gets no hue; colouring it green would score a firewall as compliant
// on a question nobody asked it.
const ANSWER_REASON = {
  na: 'SecVault could not put this question to this firewall — no usable config, no ruleset collected, or a check that cannot be answered from a config snapshot at all. Excluded from the score rather than counted against it.',
  unreadable: 'This finding carries a status SecVault does not recognise. It is shown as unreadable rather than read as a pass.',
  never: 'This firewall is in scope for this control and has no answer for it. It was never asked — which is not the same as having passed. Clears itself once a config is collected and the audit runs.',
};

function answerCell(row) {
  if (row.status === 'fail') return <Badge color="danger">Fail</Badge>;
  if (row.status === 'warning') {
    return (
      <Badge color="warning" title="The check ran against a collected config and could not reach a verdict. That uncertainty is a fact about this firewall, so it counts against the score.">
        Indeterminate
      </Badge>
    );
  }
  if (row.status === 'pass') return <Badge color="success">Pass</Badge>;
  if (row.status === 'na') return huelessChip('Not answerable', ANSWER_REASON.na);
  if (row.status === 'unreadable') {
    return huelessChip(
      row.rawStatus ? `Unreadable: ${row.rawStatus}` : 'Unreadable',
      ANSWER_REASON.unreadable
    );
  }
  // ⛔ THE ROW THIS PAGE EXISTS FOR. Never omitted, never blank, never a pass.
  return huelessChip('Never answered', ANSWER_REASON.never);
}

// ⛔ DISPLAY ORDER, NOT A VERDICT — nothing here decides a status. It mirrors
// the engine's own intent in `STATE_RANK`, where `not_measured` ranks ABOVE
// `clean`: a firewall nobody asked is a coverage gap worth closing, and
// sorting it under the passes would bury the only rows on this page that are
// actionable without touching a firewall.
const ANSWER_RANK = { fail: 0, warning: 1, unreadable: 2, never: 3, na: 4, pass: 5 };
const rankOf = (row) => ANSWER_RANK[row.status === null ? 'never' : row.status] ?? 9;

function sortRows(rows) {
  return [...rows].sort((a, b) => {
    // Out-of-scope answers last whatever they say: they are a curated-data
    // fault, not a fleet problem, and must not head a list an operator works.
    if (a.inScope !== b.inScope) return a.inScope ? -1 : 1;
    const byAnswer = rankOf(a) - rankOf(b);
    if (byAnswer !== 0) return byAnswer;
    return String(a.deviceName || '').localeCompare(String(b.deviceName || ''));
  });
}

// ── the definition block ────────────────────────────────────────────────────

function factRow(label, value) {
  return (
    <div style={{ display: 'flex', gap: 'var(--s3)', alignItems: 'baseline' }}>
      <span style={{ flex: 'none', width: 140, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
        {label}
      </span>
      <span style={{ fontSize: 'var(--text-sm)' }}>{value}</span>
    </div>
  );
}

function severityValue(control) {
  if (!control.severity) return <NotMeasured reason="This check carries no severity." />;
  if (!control.severityKnown) {
    // ⛔ SHOWN AS THE LIBRARY RECORDED IT, never mapped to the column's
    // `medium` DEFAULT — a value we did not understand must not be dressed up
    // as a grading somebody chose.
    return (
      <span
        style={{ color: 'var(--unmeasured)' }}
        title={`"${control.severity}" is not one of this product's severity levels, so it is shown verbatim rather than mapped to a default.`}
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

// ── the firewall split, in counts of firewalls ──────────────────────────────

function splitLine(control, detail) {
  const { counts } = control;
  const applicable = control.applicableDeviceCount;
  const of = applicable === null ? 'an unknown number of' : applicable;
  const parts = [];
  if (counts.fail > 0) parts.push(`${counts.fail} failing`);
  if (counts.warning > 0) parts.push(`${counts.warning} indeterminate`);
  if (counts.pass > 0) parts.push(`${counts.pass} passing`);
  if (counts.na > 0) parts.push(`${counts.na} not answerable`);
  if (counts.unreadable > 0) parts.push(`${counts.unreadable} unreadable`);
  // ⛔ THE GAP IS STATED ON EVERY CONTROL THAT HAS ONE, failing or not. A
  // control failing on 4 of 16 with 9 never asked is a worse picture than the
  // badge admits, and the nine unasked firewalls are where the next failure
  // comes from.
  if (detail.neverAnsweredCount > 0) parts.push(`${detail.neverAnsweredCount} never asked`);
  if (parts.length === 0) parts.push('no firewall has answered this control');
  return `${parts.join(' · ')} — of ${of} ${applicable === 1 ? 'firewall' : 'firewalls'} this control applies to`;
}

export default function ControlDetail({ detail }) {
  const { control } = detail;
  const rows = sortRows(detail.devices);
  const exceptions = detail.exceptions;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {detail.errors.length > 0 && (
        // ⛔ A PARTIAL READ IS BANNERED, NEVER SWALLOWED. A section quietly
        // reporting "no exceptions" because the table could not be read is the
        // failed-read-as-a-fact rule wearing a heading.
        <div className="notice-row" style={{ color: 'var(--tint-warn-fg)' }}>
          {detail.errors.join(' · ')}
        </div>
      )}

      {/* ── the roll-up ─────────────────────────────────────────────────── */}
      <Card>
        <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--s3)', flexWrap: 'wrap' }}>
            {rollupChip(control)}
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
              {splitLine(control, detail)}
            </span>
          </div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
            Last evaluated <TimeAgo value={control.lastEvaluated} empty="never" />
            {' · '}
            {/* ⛔ null IS NOT 0. "No exception covers this control" and "we could
                not read the record" send an operator to different places. */}
            {control.exceptionDeviceCount === null
              ? <NotMeasured text="acceptances unknown" reason="The recorded exceptions could not be read, so whether this control is covered by one is unknown." />
              : `${control.exceptionDeviceCount} live ${control.exceptionDeviceCount === 1 ? 'exception' : 'exceptions'}`}
          </div>
        </CardBody>
      </Card>

      {/* ── what the control is ─────────────────────────────────────────── */}
      <Card>
        <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
          <CardTitle>What this control checks</CardTitle>
          {/* ⛔ NOT CLAMPED. The table clamps a seed description to two lines
              because it has 74 of them in one column; this page has one, and
              the whole reason to open it is to read the thing in full. */}
          {control.description
            ? <p style={{ margin: 0, fontSize: 'var(--text-sm)', whiteSpace: 'pre-wrap' }}>{control.description}</p>
            : <NotMeasured reason="This check carries no description in the library." text="No description is recorded for this check." />}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
            {factRow('Slug', <code style={{ fontSize: 'var(--text-xs)' }}>{control.slug}</code>)}
            {factRow('Severity', severityValue(control))}
            {factRow(
              'Frameworks',
              control.standards.length === 0
                ? <NotMeasured reason="This check is not mapped to any framework in the library." />
                : (
                  <span style={{ display: 'inline-flex', flexWrap: 'wrap', gap: 4 }}>
                    {control.standards.map((s) => (
                      <Badge key={s} color="info">{STANDARD_LABEL[s] || s}</Badge>
                    ))}
                  </span>
                )
            )}
            {factRow(
              'Applies to',
              control.vendor
                ? `${vendorLabel(control.vendor)} firewalls only`
                : 'every firewall, whatever the vendor'
            )}
            {factRow(
              'Evaluated by',
              control.predicateType
                ? (
                  <code style={{ fontSize: 'var(--text-xs)' }} title={
                    control.predicateType === 'not_evaluable_from_config'
                      ? 'Declared unanswerable from a config snapshot. PERMANENT — nothing an operator changes on a firewall makes this answerable, so it is excluded from the score rather than counted against it.'
                      : undefined
                  }>
                    {control.predicateType}
                  </code>
                )
                : <NotMeasured reason="This check records no predicate type, so how it would be evaluated is unknown." />
            )}
          </div>
        </CardBody>
      </Card>

      {/* ── how to fix it ───────────────────────────────────────────────── */}
      <Card>
        <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
          <CardTitle>Remediation</CardTitle>
          {detail.remediationGuidance
            ? (
              <p style={{ margin: 0, fontSize: 'var(--text-sm)', whiteSpace: 'pre-wrap', maxWidth: '80ch' }}>
                {detail.remediationGuidance}
              </p>
            )
            : (
              // ⛔ AN ABSENT GUIDANCE IS NAMED AS A LIBRARY GAP, not left blank.
              // A blank section reads as "nothing to do here", which is the
              // opposite of what a failing control with no guidance means.
              <NotMeasured
                reason="The check library records no remediation guidance for this check. That is a gap in SecVault's curated data, not a statement that no action is needed."
                text="No remediation guidance is recorded for this check."
              />
            )}
        </CardBody>
      </Card>

      {/* ── every firewall's answer ─────────────────────────────────────── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
        <CardTitle>Every firewall’s answer</CardTitle>
        <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', maxWidth: '80ch' }}>
          One row per firewall this control applies to — including the ones that have never been
          asked. A firewall with no answer is listed as <strong>never answered</strong>, never as
          passing: an absent measurement is not a result.
        </p>
        {rows.length === 0 ? (
          // ⛔ WORDED AS A SCOPE FACT, NOT AN ALL-CLEAR. No applicable firewall
          // means this control can never run here, which says nothing good or
          // bad about the fleet.
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--unmeasured)' }}>
            No active firewall is{' '}
            {control.vendor ? `a ${vendorLabel(control.vendor)}` : 'in scope for this control'}, so
            it never runs here. This is not a pass.
          </p>
        ) : (
          <Table>
            <colgroup>
              <col style={{ width: '24%' }} />
              <col style={{ width: '16%' }} />
              <col style={{ width: '46%' }} />
              <col style={{ width: '14%' }} />
            </colgroup>
            <thead>
              <tr>
                <th scope="col">Firewall</th>
                <th scope="col">Answer</th>
                <th scope="col">What the check found</th>
                <th scope="col">Detected</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.deviceId}>
                  <td style={WRAP_CELL}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                      <Link href={`/compliance/${r.deviceId}`}>{r.deviceName || r.deviceId}</Link>
                      {r.vendor && (
                        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                          {vendorLabel(r.vendor)}
                        </span>
                      )}
                      {!r.inScope && (
                        // ⛔ NAMED, NOT HIDDEN. The roll-up counts this answer
                        // (the fleet query has no vendor filter), so dropping
                        // the row would leave the page claiming a failure with
                        // no failing firewall in the list.
                        <span
                          style={{ fontSize: 'var(--text-xs)', color: 'var(--unmeasured)' }}
                          title="This firewall is not of this control's vendor, yet it carries an answer for it. The answer is counted in the roll-up above, so it is shown rather than dropped — it indicates a curated-data or audit-run fault, not a fleet problem."
                        >
                          outside this control’s vendor scope
                        </span>
                      )}
                    </div>
                  </td>
                  <td style={WRAP_CELL}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                      {answerCell(r)}
                      {r.answerCount > 1 && (
                        <span
                          style={{ fontSize: 'var(--text-xs)', color: 'var(--unmeasured)' }}
                          title="More than one finding row exists for this firewall and this check. The worst answer is shown — a failure must not hide behind a stale pass — and the duplication is reported rather than swallowed."
                        >
                          {r.answerCount} answers recorded
                        </span>
                      )}
                    </div>
                  </td>
                  <td style={WRAP_CELL}>
                    {r.detail
                      ? <span style={{ fontSize: 'var(--text-sm)' }}>{r.detail}</span>
                      : r.status === null
                        ? <NotMeasured reason={ANSWER_REASON.never} text="never asked" />
                        : <NotMeasured reason="This finding recorded no detail text." />}
                  </td>
                  <td style={WRAP_CELL}>
                    <TimeAgo value={r.detectedAt} empty="Never" />
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </div>

      {/* ── accepted risk ───────────────────────────────────────────────── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
        <CardTitle>Accepted risk</CardTitle>
        <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', maxWidth: '80ch' }}>
          {/* ⛔ STATED ON THE PAGE. An exception never changes a finding's
              status and the compliance score is computed as if none existed —
              a failing firewall above is still failing, whatever is recorded
              here. Letting a label somebody typed move a measurement is how a
              compliance score becomes a number people manage. */}
          An exception is an operator’s recorded decision to accept a failure on one firewall. It
          never changes a finding’s status and never moves the compliance score — the rows above are
          unaffected by anything listed here.
        </p>
        {exceptions === null ? (
          <NotMeasured
            reason="The compliance_exceptions table could not be read on this load."
            text="The recorded exceptions could not be read, so whether any risk is formally accepted for this control is unknown."
          />
        ) : exceptions.length === 0 ? (
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            No exception has been recorded against this control on any active firewall.
          </p>
        ) : (
          <Table>
            <colgroup>
              <col style={{ width: '22%' }} />
              <col style={{ width: '14%' }} />
              <col style={{ width: '16%' }} />
              <col style={{ width: '48%' }} />
            </colgroup>
            <thead>
              <tr>
                <th scope="col">Firewall</th>
                <th scope="col">State</th>
                <th scope="col">Expires</th>
                <th scope="col">Why it was accepted</th>
              </tr>
            </thead>
            <tbody>
              {exceptions.map((e) => (
                <tr key={e.id}>
                  <td style={WRAP_CELL}>
                    <Link href={`/compliance/${e.deviceId}`}>
                      {detail.deviceNames[e.deviceId] || e.deviceId}
                    </Link>
                  </td>
                  <td style={WRAP_CELL}>
                    {/* ⛔ FOUR STATES, EVALUATED AT READ TIME by
                        `exceptionState` — never a stored column and never a
                        SQL predicate re-expressing "is this live". A lapsed
                        acceptance is DANGER (a failing check with nothing
                        covering it is a real, actionable fact), not grey and
                        not blank. */}
                    {e.expiryUnreadable
                      ? huelessChip('Expiry unreadable', 'This exception’s expiry date could not be read, so it fails closed to lapsed. That is a different story from one that genuinely ran out.')
                      : <Badge color={TONE_BADGE[e.tone] || 'muted'}>{e.label}</Badge>}
                  </td>
                  <td style={WRAP_CELL}>
                    {e.expiresAt
                      ? <TimeAgo value={e.expiresAt} empty="—" />
                      : <NotMeasured reason="The expiry on this exception could not be read." />}
                  </td>
                  <td style={WRAP_CELL}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2, fontSize: 'var(--text-sm)' }}>
                      <span>{e.reason}</span>
                      {e.compensatingControl && (
                        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
                          Compensating control: {e.compensatingControl}
                        </span>
                      )}
                      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                        Accepted by {e.acceptedBy || 'an unrecorded owner'}
                      </span>
                      {/* ⛔ AN EXCEPTION OVER A CHECK NOBODY IS ASKING IS NOT
                          COVER, and is named as such rather than counted as
                          protection. */}
                      {e.checkNotEvaluated && (
                        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--unmeasured)' }}>
                          This check is not currently being evaluated on this firewall, so the
                          exception covers nothing measurable.
                        </span>
                      )}
                      {e.checkNoLongerFailing && (
                        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--unmeasured)' }}>
                          This check is no longer failing on this firewall.
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </div>
    </div>
  );
}
