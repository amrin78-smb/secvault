'use client';

// components/applications/ApplicationCard.js
//
// One declared application: what it is, what it needs, and what the rules
// actually say about each of those needs.
//
// ⛔ PERMITTED AND USED ARE SEPARATE COLUMNS, and that separation is the whole
// feature. "A rule permits this" and "a rule permitting this has seen traffic"
// are different measurements with different failure modes, and every competing
// product collapses them into one status — which is how a rule that cannot
// report usage ends up presented as a rule that is not used.
//
// ⛔ THE USED COLUMN SPEAKS ABOUT RULES, NEVER ABOUT THE FLOW. No stored rollup
// in this product carries both ends of a flow, so per-flow usage is not
// answerable from anything SecVault holds. The footnote under the table says so
// in plain words, OUTSIDE any disclosure, because a reader who skips it would
// otherwise draw a conclusion the data does not support.
//
// ⛔ EDITING CHANGES NOTHING ON SCREEN BY ITSELF. An editor collects values and
// hands them to the board, which PUTs them and re-runs the server evaluation.
// Nothing here keeps a local copy of an application, a flow, or a verdict — the
// row an operator just edited is re-read from the server like every other row,
// so the heading, the table and the sentence above the page cannot disagree
// about what was saved. See the note at the top of ApplicationBoard.js.

import { useCallback, useEffect, useState } from 'react';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Table from '../ui/Table';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import Disclosure from '../ui/Disclosure';
import { AppStateChip, FindingCell, PermittedCell, UsedCell } from './FlowChips';
import { AddFlowForm, EditApplicationForm, EditFlowForm, ErrorNote } from './ApplicationForms';
import { endpointsLabel, expectationLabel, serviceLabel } from './flowVocabulary';

/**
 * ⛔ A LIFECYCLE STATE IS SHOWN, NEVER ACTED ON. Nothing in this file filters,
 * collapses or greys out an application because of its status: a retired
 * application that the rulebase still permits is one of the most useful things
 * this page can tell anyone, and a product that quietly dropped it from the
 * list would be hiding exactly that. The badge states the fact and the title
 * says what it does and does not imply.
 *
 * ⛔ AND IT CARRIES NO SEVERITY HUE. Retiring is not a problem and retired is
 * not an all-clear; colour in this product means risk, and neither of these is
 * a risk judgement. `warning` would read as "something is wrong with this
 * application", which is a claim nobody made.
 */
const STATUS_BADGE = {
  retiring: {
    label: 'Retiring',
    title:
      'Declared as being decommissioned. It is still listed here in full and its flows are still '
      + 'evaluated against the rulebase — the state is a label, not a filter.',
  },
  retired: {
    label: 'Retired',
    title:
      'Declared retired. It is still listed here in full and its flows are still evaluated: a '
      + 'retired application the rules continue to permit is worth knowing about, so nothing is '
      + 'hidden because of this state.',
  },
};

function StatusBadge({ status }) {
  if (!status || status === 'active') return null;
  // An unrecognised state is printed verbatim rather than swallowed — a status
  // this file has not been taught is still a fact about the row.
  const meta = STATUS_BADGE[status] || {
    label: status,
    title: 'A lifecycle state SecVault does not recognise. It is shown exactly as it is stored.',
  };
  return <Badge color="muted" title={meta.title}>{meta.label}</Badge>;
}

function hitLabel(rule) {
  // ⛔ TRI-STATE, PRESERVED ALL THE WAY TO THE PIXEL. null is "this firewall
  // cannot report a count", which is not zero and must not be drawn as one.
  if (!rule || rule.effectiveHitCount === null || rule.effectiveHitCount === undefined) {
    return <span style={{ color: 'var(--unmeasured)' }}>usage not measured</span>;
  }
  return `${Number(rule.effectiveHitCount).toLocaleString()} hits`;
}

function RuleLine({ rule, deviceName }) {
  return (
    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
      {deviceName} · {rule.name || '(unnamed)'}
      {rule.ruleId !== null && rule.ruleId !== undefined ? ` · id ${rule.ruleId}` : ''}
      {rule.sequence !== null && rule.sequence !== undefined ? ` · #${rule.sequence}` : ''}
      {' · '}
      {hitLabel(rule)}
      {rule.hasUnresolved && (
        <span style={{ color: 'var(--unmeasured)' }}>
          {' '}· references an address or service this firewall did not report
        </span>
      )}
    </div>
  );
}

/**
 * Is there anything to disclose under this flow at all?
 *
 * ⛔ ASKED BEFORE THE ROW IS BUILT, not inside the component. `<FlowEvidence/>`
 * is a React element and a React element is ALWAYS truthy, so `{el && <tr>…}`
 * emitted an empty `<tr><td colSpan="6"></td></tr>` under every flow the
 * evaluator had nothing to say about — a blank bordered row that reads as a
 * second, empty flow.
 */
function hasFlowEvidence(evaluated) {
  if (!evaluated) return false;
  const len = (v) => (Array.isArray(v) ? v.length : 0);
  return len(evaluated.permittedBy) > 0
    || len(evaluated.blockedBy) > 0
    || len(evaluated.unverifiedReasons) > 0;
}

function FlowEvidence({ evaluated }) {
  const permittedBy = Array.isArray(evaluated.permittedBy) ? evaluated.permittedBy : [];
  const blockedBy = Array.isArray(evaluated.blockedBy) ? evaluated.blockedBy : [];
  const reasons = Array.isArray(evaluated.unverifiedReasons) ? evaluated.unverifiedReasons : [];
  if (!hasFlowEvidence(evaluated)) return null;

  return (
    <Disclosure summary="Show the rules behind this answer">
      {permittedBy.length > 0 && (
        <div>
          <strong>Permitted by</strong>
          {permittedBy.map((p) => (
            <div key={p.deviceId} style={{ marginTop: 'var(--s1)' }}>
              {p.rules.map((r) => <RuleLine key={r.deviceRuleId} rule={r} deviceName={p.deviceName || p.deviceId} />)}
            </div>
          ))}
        </div>
      )}
      {blockedBy.length > 0 && (
        <div>
          <strong>Denied by</strong>
          {blockedBy.map((b) => (
            <div key={b.deviceId} style={{ marginTop: 'var(--s1)' }}>
              {b.rules.map((r) => <RuleLine key={r.deviceRuleId} rule={r} deviceName={b.deviceName || b.deviceId} />)}
            </div>
          ))}
        </div>
      )}
      {reasons.length > 0 && (
        <div>
          {/* ⛔ Not a footnote about polish — these are the reasons the answer
              above is not settled, and they are listed verbatim so the operator
              can tell a gap in the firewall from a gap in SecVault. */}
          <strong style={{ color: 'var(--unmeasured)' }}>Why this is not fully verified</strong>
          <ul style={{ margin: 'var(--s1) 0 0', paddingLeft: 'var(--s5)', color: 'var(--unmeasured)' }}>
            {reasons.map((r, i) => <li key={i}>{r}</li>)}
          </ul>
        </div>
      )}
    </Disclosure>
  );
}

/**
 * ⛔ THE EDITOR SITS BENEATH THE ROW IT EDITS, and the row stays on screen while
 * it is open. Replacing the row with the form would take away the verdict the
 * operator is editing in response to — they came here because the Permitted or
 * Used column said something, and hiding it mid-correction is how the wrong
 * field gets changed.
 */
function FlowRows({ evaluated, busy, editing, error, onEdit, onCancelEdit, onSaveFlow, onRemoveFlow }) {
  const flow = evaluated.flow || {};
  const showEvidence = hasFlowEvidence(evaluated);
  return (
    <>
      <tr>
        <td>
          <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', wordBreak: 'break-word' }}>
            {endpointsLabel(flow)}
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
            {serviceLabel(flow)}
          </div>
          {flow.note && (
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{flow.note}</div>
          )}
        </td>
        <td>
          <Badge color={flow.expectation === 'deny' ? 'muted' : 'info'}>{expectationLabel(flow)}</Badge>
        </td>
        <td><PermittedCell evaluated={evaluated} /></td>
        <td><UsedCell evaluated={evaluated} /></td>
        <td><FindingCell evaluated={evaluated} /></td>
        <td>
          <div style={{ display: 'flex', gap: 'var(--s2)', flexWrap: 'wrap' }}>
            {/* ⛔ NEVER HIDDEN FOR A ROLE. Both routes behind these buttons are
                gated on the operate capability and answer a 403 with the reason;
                a button removed because of a guess about the session leaves an
                operator concluding the product is broken rather than that they
                lack access. */}
            <Button variant="secondary" disabled={busy} onClick={editing ? onCancelEdit : onEdit}>
              {editing ? 'Cancel' : 'Edit'}
            </Button>
            <Button variant="secondary" disabled={busy} onClick={() => onRemoveFlow(flow.id)}>Remove</Button>
          </div>
        </td>
      </tr>
      {editing && (
        <tr>
          <td colSpan={6}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
              {/* ⛔ THE REASON IS SHOWN WHERE THE EDIT WAS MADE. The PUT returns
                  the engine's own parse failure — "Source "10.0.0.300" is not a
                  valid address or CIDR." — which names the field that is wrong.
                  Replacing it with a generic message would throw away the only
                  part of it that makes the mistake fixable. */}
              {error && <ErrorNote>{error}</ErrorNote>}
              <EditFlowForm
                busy={busy}
                flow={flow}
                onSubmit={(body) => onSaveFlow(flow.id, body)}
                onClose={onCancelEdit}
              />
            </div>
          </td>
        </tr>
      )}
      {showEvidence && (
        <tr>
          <td colSpan={6}><FlowEvidence evaluated={evaluated} /></td>
        </tr>
      )}
    </>
  );
}

/**
 * ⛔ A FAILED READ OF THE DECLARED FLOWS IS NOT "NO FLOWS DECLARED".
 *
 * Both of the evaluator's failure paths hand this card an application with an
 * EMPTY flow list: `loadFleet` throwing returns `{application, unevaluated:true}`
 * with no flows at all, and a failed `application_flows` query leaves every
 * application with zero rows and a `summary.state` of `undeclared`. Rendered the
 * ordinary way, both printed "No flows declared yet, so nothing about this
 * application has been checked" — a confident, false statement about the
 * operator's OWN declaration, produced entirely by a read that failed. The
 * banner above the board says a source broke; this said the declaration is
 * empty, and the second is the one an operator believes, because it is written
 * on the application itself.
 *
 * `flow_count` comes from the applications query (a `count(f.id)` join), which
 * SUCCEEDED in both paths — so the honest answer is available and is stated.
 */
function UnreadableFlows({ application, fleetFailed }) {
  const count = Number(application && application.flow_count);
  return (
    <div style={{
      backgroundImage: 'var(--hatch)',
      backgroundColor: 'var(--surface-subtle)',
      border: '1px dashed var(--border)',
      borderRadius: 'var(--radius)',
      padding: 'var(--s4)',
      color: 'var(--unmeasured)',
      fontSize: 'var(--text-base)',
      lineHeight: 1.55,
    }}>
      <strong style={{ color: 'var(--unmeasured)' }}>
        {Number.isFinite(count) && count > 0
          ? `${count} declared flow${count === 1 ? '' : 's'} could not be read.`
          : 'This application’s declared flows could not be read.'}
      </strong>
      <div style={{ marginTop: 'var(--s2)' }}>
        {fleetFailed
          ? 'The fleet rulebase could not be loaded, so nothing was evaluated against it.'
          : 'The declared flows could not be loaded from the database.'}
        {' '}
        Nothing here says this application has no flows, and nothing here says it is in order —
        it has not been checked at all.
      </div>
    </div>
  );
}

// ── Retiring an application ────────────────────────────────────────────────
//
// ⛔ BOTH LISTS ARE SHOWN BEFORE ANYTHING IS SUBMITTED. This action proposes
// FIREWALL RULES FOR DELETION, so the operator sees what would be proposed AND
// what was held back, with each reason, and then clicks a second time. A
// one-click action whose effect is a surprise is worse than two clicks here —
// and a screen that showed only the proposal would be presenting a shorter list
// that looks complete, which is the failure this whole product exists to remove.
//
// ⛔ THIS PANEL FETCHES A PROPOSAL, NOT THE EVALUATION. ApplicationBoard's rule
// against fetching here is about the page's VERDICTS: a second copy of those,
// taken at a different instant, can disagree with the sentence above the table.
// A retirement proposal is not rendered anywhere else on the page, so there is
// no second copy of anything — and it is far too expensive to compute for every
// application on every page load.

const RETIRE_REASON_LABEL = {
  also_claimed: 'Another application claims it',
  unverified_evaluation: 'Not fully verified',
  no_vendor_identifier: 'No identifier to verify against',
  usage_not_measured: 'Usage never measured',
  cleanup_engine_withheld: 'Held back by rule analysis',
  not_cleanup_eligible: 'Not flagged as removable',
};

function RetireRuleLine({ item }) {
  return (
    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
      {item.deviceName || item.deviceId} · {item.ruleName || '(unnamed)'}
      {item.ruleIdVendor ? ` · id ${item.ruleIdVendor}` : ''}
      {item.sequence !== null && item.sequence !== undefined ? ` · #${item.sequence}` : ''}
      {' · '}
      {hitLabel(item)}
    </div>
  );
}

function RetireProposedTable({ proposed }) {
  return (
    <Table minWidth={720}>
      <colgroup>
        <col style={{ width: '22%' }} />
        <col style={{ width: '40%' }} />
        <col style={{ width: '20%' }} />
        <col style={{ width: '18%' }} />
      </colgroup>
      <thead>
        <tr>
          <th>Firewall</th>
          <th>Rule</th>
          <th title="The rule's own measured usage. A rule is never proposed on an unmeasured count.">
            Usage
          </th>
          <th title="What SecVault's rule analysis independently found about this rule.">Also found</th>
        </tr>
      </thead>
      <tbody>
        {proposed.map((p) => (
          <tr key={`${p.deviceId}-${p.ruleIdVendor}`}>
            <td>{p.deviceName || p.deviceId}</td>
            <td>
              <div style={{ fontFamily: 'var(--font-mono)', wordBreak: 'break-word' }}>
                {p.ruleName || '(unnamed)'}
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                id {p.ruleIdVendor}
                {p.sequence !== null && p.sequence !== undefined ? ` · #${p.sequence}` : ''}
              </div>
            </td>
            <td>{hitLabel(p)}</td>
            <td>{p.findingType ? <Badge color="muted">{p.findingType}</Badge> : '—'}</td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

/**
 * ⛔ THE WITHHELD LIST IS NOT A FOOTNOTE. Each entry carries the engine's own
 * sentence, because "we held 29 rules back" with no reasons is a shorter list
 * wearing a label — and several of these reasons are things the operator can
 * act on (collect the missing objects, fix an unreadable flow) rather than
 * limits they must accept.
 */
function RetireWithheldTable({ withheld }) {
  return (
    <Table minWidth={720}>
      <colgroup>
        <col style={{ width: '22%' }} />
        <col style={{ width: '26%' }} />
        <col style={{ width: '52%' }} />
      </colgroup>
      <thead>
        <tr>
          <th>Firewall</th>
          <th>Rule</th>
          <th>Why it is not proposed</th>
        </tr>
      </thead>
      <tbody>
        {withheld.map((w, i) => (
          <tr key={`${w.deviceId}-${w.ruleIdVendor || 'no-id'}-${i}`}>
            <td>{w.deviceName || w.deviceId}</td>
            <td>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', wordBreak: 'break-word' }}>
                {w.ruleName || '(unnamed)'}
              </div>
              {hitLabel(w)}
            </td>
            <td>
              <Badge color="muted">{RETIRE_REASON_LABEL[w.reasonCode] || w.reasonCode}</Badge>
              <div style={{ marginTop: 'var(--s1)', color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>
                {w.reason}
              </div>
              {Array.isArray(w.unverifiedReasons) && w.unverifiedReasons.length > 0 && (
                <ul style={{ margin: 'var(--s1) 0 0', paddingLeft: 'var(--s5)', color: 'var(--unmeasured)', fontSize: 'var(--text-xs)' }}>
                  {w.unverifiedReasons.map((r, j) => <li key={j}>{r}</li>)}
                </ul>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function RetireOutcome({ result }) {
  const requests = Array.isArray(result.requests) ? result.requests : [];
  const failures = Array.isArray(result.failures) ? result.failures : [];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
      {requests.length > 0 && (
        <div>
          <strong>
            {result.submitted} rule{result.submitted === 1 ? '' : 's'} proposed for removal across{' '}
            {requests.length} firewall{requests.length === 1 ? '' : 's'}.
          </strong>
          <ul style={{ margin: 'var(--s2) 0 0', paddingLeft: 'var(--s5)', color: 'var(--text-secondary)' }}>
            {requests.map((r) => (
              <li key={r.requestId}>
                {r.deviceName || r.deviceId}: {r.ruleCount} rule{r.ruleCount === 1 ? '' : 's'} ·{' '}
                <a href={`/devices/${r.deviceId}/analysis?tab=cleanup`}>open the change request</a>
              </li>
            ))}
          </ul>
        </div>
      )}
      {/* ⛔ A PARTIAL RESULT NEVER READS AS A WHOLE ONE. An operator told "done"
          while one firewall was skipped never looks at it again. */}
      {failures.length > 0 && (
        <ErrorNote>
          {failures.length} firewall{failures.length === 1 ? '' : 's'} could not be asked:{' '}
          {failures.map((f) => `${f.deviceName || f.deviceId} (${f.error})`).join('; ')}
        </ErrorNote>
      )}
      <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
        Nothing has been deleted. SecVault will report each rule as removed only when a ruleset
        collected after this request no longer contains it — there is no way to mark it done by hand.
      </p>
    </div>
  );
}

function RetirePanel({ application, busy, onClose }) {
  const [loading, setLoading] = useState(true);
  const [plan, setPlan] = useState(null);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState(null);

  const appId = application.id;

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`/api/applications/${encodeURIComponent(appId)}/retire`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const body = await res.json().catch(() => ({}));
      // ⛔ THE ROUTE'S OWN MESSAGE REACHES THE OPERATOR, including the 403 that
      // names the missing capability. A button that silently does nothing gets
      // filed as a broken product rather than as a permission they lack.
      if (!res.ok) { setError(body.error || `Could not work out what to retire (HTTP ${res.status}).`); return; }
      setPlan(body.plan || null);
    } catch (err) {
      setError('Could not reach SecVault — nothing was proposed and nothing was changed.');
    } finally {
      setLoading(false);
    }
  }, [appId]);

  useEffect(() => { load(); }, [load]);

  const submit = useCallback(async () => {
    if (!plan || plan.proposed.length === 0) return;
    setSubmitting(true);
    setError('');
    try {
      const res = await fetch(`/api/applications/${encodeURIComponent(appId)}/retire`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // ⛔ WHAT WAS ON SCREEN IS SENT BACK, and the server treats it as a
        // ceiling: anything it now proposes that is not in this list stops the
        // submission. The operator confirms what they SAW, not whatever the
        // rulebase happens to say at the moment of the click.
        body: JSON.stringify({ confirm: true, expect: plan.proposed.map((p) => p.ruleIdVendor) }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(body.error || `Nothing was submitted (HTTP ${res.status}).`);
        if (body.plan) setPlan(body.plan);
        return;
      }
      setResult(body);
    } catch (err) {
      setError('Could not reach SecVault — nothing was submitted.');
    } finally {
      setSubmitting(false);
    }
  }, [appId, plan]);

  const proposed = plan && Array.isArray(plan.proposed) ? plan.proposed : [];
  const withheld = plan && Array.isArray(plan.withheld) ? plan.withheld : [];
  const notes = plan && Array.isArray(plan.notes) ? plan.notes : [];
  const working = busy || submitting;

  return (
    <div style={{
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: 'var(--s4)',
      display: 'flex',
      flexDirection: 'column',
      gap: 'var(--s4)',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 'var(--s3)', flexWrap: 'wrap' }}>
        <strong style={{ fontSize: 'var(--text-base)' }}>
          Retire “{application.name}” — which rules exist only to serve it?
        </strong>
        <Button variant="secondary" disabled={submitting} onClick={onClose}>Close</Button>
      </div>

      {error && <ErrorNote>{error}</ErrorNote>}

      {loading && (
        <p style={{ margin: 0, color: 'var(--text-muted)' }}>
          Checking every declared application against every collected rulebase…
        </p>
      )}

      {result ? <RetireOutcome result={result} /> : plan && (
        <>
          <p style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            {/* ⛔ THE CLAIM IS STATED EXACTLY. "A rule permits one of this
                application's declared flows and no other declared application's"
                is a much narrower statement than "this rule is only used by this
                application", and the difference is the operator's to judge. */}
            SecVault proposes a rule only when it permits one of this application’s declared flows,
            no other declared application claims it, its usage was actually measured, and SecVault’s
            own rule analysis independently flagged it as removable. Everything else is listed
            below with the reason it was held back.
          </p>

          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            {plan.summary.claimedRules} rule{plan.summary.claimedRules === 1 ? '' : 's'} claimed ·{' '}
            {plan.summary.proposedRules} proposed across {plan.summary.devices} firewall
            {plan.summary.devices === 1 ? '' : 's'} · {plan.summary.withheldRules} held back
            {plan.coverage ? ` · traffic measured over ${plan.coverage.windowDays} days` : ''}
          </div>

          {notes.map((n) => (
            <div key={n.code} style={{
              backgroundImage: 'var(--hatch)',
              backgroundColor: 'var(--surface-subtle)',
              border: '1px dashed var(--border)',
              borderRadius: 'var(--radius)',
              padding: 'var(--s3)',
              color: 'var(--unmeasured)',
              fontSize: 'var(--text-sm)',
              lineHeight: 1.55,
            }}>
              {n.text}
            </div>
          ))}

          {proposed.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
              <strong>Would be proposed for removal</strong>
              <RetireProposedTable proposed={proposed} />
            </div>
          )}

          {withheld.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
              <strong style={{ color: 'var(--unmeasured)' }}>
                Held back ({withheld.length}) — not proposed, and not cleared either
              </strong>
              <RetireWithheldTable withheld={withheld} />
            </div>
          )}

          <div style={{ display: 'flex', gap: 'var(--s3)', alignItems: 'center', flexWrap: 'wrap' }}>
            {/* ⛔ NEVER HIDDEN FOR A ROLE — the route is gated and answers a 403
                with the reason, which is shown above. */}
            <Button variant="danger" disabled={working || proposed.length === 0} onClick={submit}>
              {submitting
                ? 'Raising…'
                : `Raise ${proposed.length} rule${proposed.length === 1 ? '' : 's'} as a change request`}
            </Button>
            <Button variant="secondary" disabled={working} onClick={load}>Re-check</Button>
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              This raises a change request per firewall. It deletes nothing, changes no rule, and
              leaves this application’s status exactly as you set it.
            </span>
          </div>
        </>
      )}
    </div>
  );
}

export default function ApplicationCard({
  entry,
  busy,
  error = '',
  errorAt = '',
  flowsUnreadable = false,
  onAddFlow,
  onUpdateApp,
  onUpdateFlow,
  onRemoveFlow,
  onRemoveApp,
}) {
  const [confirming, setConfirming] = useState(false);
  const [editingApp, setEditingApp] = useState(false);
  // ⛔ ONE EDITOR AT A TIME, BY ID rather than by index. A flow's position in
  // this table changes whenever the list is re-read, so an index would open the
  // editor on whichever flow happened to land in that slot after a refresh.
  const [editingFlowId, setEditingFlowId] = useState(null);
  // ⛔ CLOSED BY DEFAULT, AND OPENED DELIBERATELY. The panel evaluates every
  // declared application against every collected rulebase to work out what only
  // this one claims — far too expensive to run for every card on every load,
  // and it is a proposal to delete firewall rules, which nobody should meet by
  // scrolling past it.
  const [retiring, setRetiring] = useState(false);
  const app = entry.application || {};
  const flows = Array.isArray(entry.flows) ? entry.flows : [];
  // ⛔ Either failure means the flow list on screen is a read that failed, not a
  // measurement. See UnreadableFlows above.
  const unreadable = flows.length === 0 && (!!entry.unevaluated || !!flowsUnreadable);

  return (
    <Card>
      <CardHeader style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 'var(--s3)', flexWrap: 'wrap' }}>
        <CardTitle style={{ display: 'flex', alignItems: 'center', gap: 'var(--s2)', flexWrap: 'wrap' }}>
          {app.name}
          {app.criticality === 'critical' && <Badge color="danger">Critical</Badge>}
          <StatusBadge status={app.status} />
          {unreadable ? (
            // ⛔ NEVER AppStateChip HERE. With no flows readable the engine's
            // summary state is `undeclared`, which the chip renders as the
            // flat assertion "No flows declared" — a fact manufactured out of
            // a failed read.
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--unmeasured)', fontWeight: 400 }}>
              {entry.unevaluated
                ? 'not evaluated — the fleet rulebase could not be loaded'
                : 'not evaluated — the declared flows could not be read'}
            </span>
          ) : (
            <AppStateChip summary={entry.summary} />
          )}
        </CardTitle>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--s3)' }}>
          <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            {app.owner ? `Owner: ${app.owner}` : 'No owner recorded'}
          </span>
          <Button variant="secondary" disabled={busy} onClick={() => setEditingApp((v) => !v)}>
            {editingApp ? 'Close editor' : 'Edit'}
          </Button>
          {/* ⛔ "Retire…" NOT "Retire". It opens a review; it does not retire
              anything, and a label that promised otherwise would be a one-click
              action whose effect is deleting firewall rules. */}
          <Button variant="secondary" disabled={busy} onClick={() => setRetiring((v) => !v)}>
            {retiring ? 'Close retirement' : 'Retire…'}
          </Button>
          {confirming ? (
            <>
              <Button variant="danger" disabled={busy} onClick={() => { setConfirming(false); onRemoveApp(app.id); }}>
                Confirm delete
              </Button>
              <Button variant="secondary" disabled={busy} onClick={() => setConfirming(false)}>Cancel</Button>
            </>
          ) : (
            <Button variant="secondary" disabled={busy} onClick={() => setConfirming(true)}>Delete</Button>
          )}
        </div>
      </CardHeader>

      <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
        {editingApp && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
            {error && errorAt === `app:${app.id}` && <ErrorNote>{error}</ErrorNote>}
            {/* The editor is mounted only while it is open, so its fields are
                seeded from this application as it currently stands and it can
                never be showing values belonging to a previous one. */}
            <EditApplicationForm
              busy={busy}
              application={app}
              onSubmit={(body) => onUpdateApp(app.id, body)}
              onClose={() => setEditingApp(false)}
            />
          </div>
        )}

        {retiring && (
          <RetirePanel application={app} busy={busy} onClose={() => setRetiring(false)} />
        )}

        {app.note && (
          <p style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>{app.note}</p>
        )}

        {unreadable ? (
          <UnreadableFlows application={app} fleetFailed={!!entry.unevaluated} />
        ) : flows.length === 0 ? (
          <p style={{ margin: 0, color: 'var(--unmeasured)', fontSize: 'var(--text-base)' }}>
            No flows declared yet, so nothing about this application has been checked. Add the
            connections it needs — and the ones it must never make — below.
          </p>
        ) : (
          <>
            {/* ⛔ tableLayout:'fixed' comes from ui/Table and is required by the
                percentage widths below; without it these columns collapse
                unpredictably on overflow. The last column carries two controls
                now, so it is wide enough for both — a column narrower than its
                buttons wraps them into a ragged stack. */}
            <Table minWidth={920}>
              <colgroup>
                <col style={{ width: '24%' }} />
                <col style={{ width: '11%' }} />
                <col style={{ width: '15%' }} />
                <col style={{ width: '17%' }} />
                <col style={{ width: '19%' }} />
                <col style={{ width: '14%' }} />
              </colgroup>
              <thead>
                <tr>
                  <th>Flow</th>
                  <th>You declared</th>
                  <th title="Whether any enabled rule permits the declared flow. A statement about the rulebase, not a promise that a packet would arrive.">
                    Permitted
                  </th>
                  <th title="Whether the rules that permit this flow have seen traffic. This is measured on the RULES, never on the flow itself.">
                    Permitting rules used
                  </th>
                  <th>What it means</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {flows.map((evaluated, idx) => {
                  const flowId = (evaluated.flow && evaluated.flow.id) || null;
                  return (
                    <FlowRows
                      key={flowId || `flow-${idx}`}
                      evaluated={evaluated}
                      busy={busy}
                      editing={!!flowId && editingFlowId === flowId}
                      error={error && errorAt === `flow:${flowId}` ? error : ''}
                      onEdit={() => setEditingFlowId(flowId)}
                      onCancelEdit={() => setEditingFlowId(null)}
                      onSaveFlow={onUpdateFlow}
                      onRemoveFlow={onRemoveFlow}
                    />
                  );
                })}
              </tbody>
            </Table>

            {/* ⛔ OUTSIDE ANY DISCLOSURE. A reader who never opens a collapsed
                block must still not draw a wrong conclusion from the column
                heading above, and "used" is the column where that is easiest to
                get wrong. */}
            <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              Usage is measured on the rules that permit a flow, not on the flow itself — no stored
              log in this product carries both ends of a flow. Where a firewall reports its own hit
              counter, that count is cumulative since the counter was last reset, so “in use” can
              mean traffic older than the evaluation window.
            </p>
          </>
        )}

        <div style={{ borderTop: '1px solid var(--border-light)', paddingTop: 'var(--s4)' }}>
          <AddFlowForm busy={busy} idPrefix={`add-flow-${app.id}`} onSubmit={(body) => onAddFlow(app.id, body)} />
        </div>
      </CardBody>
    </Card>
  );
}
