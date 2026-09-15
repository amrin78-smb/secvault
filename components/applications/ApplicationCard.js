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

import { useState } from 'react';
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

function FlowEvidence({ evaluated }) {
  const permittedBy = Array.isArray(evaluated.permittedBy) ? evaluated.permittedBy : [];
  const blockedBy = Array.isArray(evaluated.blockedBy) ? evaluated.blockedBy : [];
  const reasons = Array.isArray(evaluated.unverifiedReasons) ? evaluated.unverifiedReasons : [];
  if (permittedBy.length === 0 && blockedBy.length === 0 && reasons.length === 0) return null;

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
  const evidence = <FlowEvidence evaluated={evaluated} />;
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
      {evidence && (
        <tr>
          <td colSpan={6}>{evidence}</td>
        </tr>
      )}
    </>
  );
}

export default function ApplicationCard({
  entry,
  busy,
  error = '',
  errorAt = '',
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
  const app = entry.application || {};
  const flows = Array.isArray(entry.flows) ? entry.flows : [];

  return (
    <Card>
      <CardHeader style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 'var(--s3)', flexWrap: 'wrap' }}>
        <CardTitle style={{ display: 'flex', alignItems: 'center', gap: 'var(--s2)', flexWrap: 'wrap' }}>
          {app.name}
          {app.criticality === 'critical' && <Badge color="danger">Critical</Badge>}
          <StatusBadge status={app.status} />
          {entry.unevaluated ? (
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--unmeasured)', fontWeight: 400 }}>
              not evaluated — the fleet rulebase could not be loaded
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

        {app.note && (
          <p style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>{app.note}</p>
        )}

        {flows.length === 0 ? (
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
