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

import { useState } from 'react';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Table from '../ui/Table';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import Disclosure from '../ui/Disclosure';
import { AppStateChip, FindingCell, PermittedCell, UsedCell } from './FlowChips';
import { AddFlowForm } from './ApplicationForms';
import { endpointsLabel, expectationLabel, serviceLabel } from './flowVocabulary';

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

function FlowRows({ evaluated, busy, onRemoveFlow }) {
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
          <Button variant="secondary" disabled={busy} onClick={() => onRemoveFlow(flow.id)}>Remove</Button>
        </td>
      </tr>
      {evidence && (
        <tr>
          <td colSpan={6}>{evidence}</td>
        </tr>
      )}
    </>
  );
}

export default function ApplicationCard({ entry, busy, onAddFlow, onRemoveFlow, onRemoveApp }) {
  const [confirming, setConfirming] = useState(false);
  const app = entry.application || {};
  const flows = Array.isArray(entry.flows) ? entry.flows : [];

  return (
    <Card>
      <CardHeader style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 'var(--s3)', flexWrap: 'wrap' }}>
        <CardTitle style={{ display: 'flex', alignItems: 'center', gap: 'var(--s2)', flexWrap: 'wrap' }}>
          {app.name}
          {app.criticality === 'critical' && <Badge color="danger">Critical</Badge>}
          {app.status && app.status !== 'active' && <Badge color="muted">{app.status}</Badge>}
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
                unpredictably on overflow. */}
            <Table minWidth={860}>
              <colgroup>
                <col style={{ width: '26%' }} />
                <col style={{ width: '12%' }} />
                <col style={{ width: '16%' }} />
                <col style={{ width: '18%' }} />
                <col style={{ width: '20%' }} />
                <col style={{ width: '8%' }} />
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
                  <th />
                </tr>
              </thead>
              <tbody>
                {flows.map((evaluated, idx) => (
                  <FlowRows
                    key={(evaluated.flow && evaluated.flow.id) || `flow-${idx}`}
                    evaluated={evaluated}
                    busy={busy}
                    onRemoveFlow={onRemoveFlow}
                  />
                ))}
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
          <AddFlowForm busy={busy} onSubmit={(body) => onAddFlow(app.id, body)} />
        </div>
      </CardBody>
    </Card>
  );
}
