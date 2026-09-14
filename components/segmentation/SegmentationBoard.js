'use client';

// components/segmentation/SegmentationBoard.js
//
// The declared segmentation matrix and the findings it produces.
//
// ⛔ THE FINDINGS LIST COMES FIRST, THE MATRIX SECOND. A grid is how you EDIT
// policy; a ranked list is how you ACT on it. Leading with the grid would make
// the operator derive "what should I do today" from a wall of cells, which is
// exactly the failure this product's answer-first rework exists to avoid.
//
// ⛔ FOUR OUTCOMES, AND THE FOURTH HAS NO HUE. "Permitted but never used" and
// "permitted, traffic not measurable" are DIFFERENT answers and must never share
// a colour: the first is a safe deletion candidate, the second must be assumed
// live. Collapsing them would recommend removing a rule that may be carrying
// production traffic — the mistake every competing tool makes.

import { useCallback, useEffect, useState } from 'react';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';

const VERDICT_STYLE = {
  violation_active: { bg: 'var(--tint-danger)', fg: 'var(--tint-danger-fg)', border: 'var(--sev-crit)', short: 'CAN + DID' },
  violation_permitted: { bg: 'var(--tint-danger)', fg: 'var(--tint-danger-fg)', border: 'var(--sev-crit)', short: 'CAN' },
  violation_unverified: { bg: 'var(--tint-warn)', fg: 'var(--tint-warn-fg)', border: 'var(--sev-med)', short: 'CAN ?' },
  unused_permission: { bg: 'var(--tint-warn)', fg: 'var(--tint-warn-fg)', border: 'var(--sev-med)', short: 'UNUSED' },
  expected_allow_missing: { bg: 'var(--tint-warn)', fg: 'var(--tint-warn-fg)', border: 'var(--sev-med)', short: 'MISSING' },
  ok_in_use: { bg: 'var(--tint-success)', fg: 'var(--tint-success-fg)', border: 'var(--sev-ok)', short: 'IN USE' },
  ok_blocked: { bg: 'var(--tint-success)', fg: 'var(--tint-success-fg)', border: 'var(--sev-ok)', short: 'BLOCKED' },
  // ⛔ NO HUE. Not measurable is not good news and not bad news.
  ok_unverified: { bg: 'var(--surface-subtle)', fg: 'var(--unmeasured)', border: 'var(--border)', short: '?' },
  unknown: { bg: 'var(--surface-subtle)', fg: 'var(--unmeasured)', border: 'var(--border)', short: '—' },
};

const ACTION_ORDER = [
  'violation_active',
  'violation_unverified',
  'violation_permitted',
  'expected_allow_missing',
  'unused_permission',
];

function Cell({ result }) {
  const s = VERDICT_STYLE[result.verdict] || VERDICT_STYLE.unknown;
  const hatched = result.verdict === 'unknown' || result.verdict === 'ok_unverified';
  return (
    <span
      title={`${result.sourceZone} → ${result.destZone}: ${result.verdict}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: '4px 8px',
        borderRadius: 'var(--radius-sm)',
        border: `1px solid ${s.border}`,
        background: s.bg,
        backgroundImage: hatched ? 'var(--hatch)' : undefined,
        color: s.fg,
        fontFamily: 'var(--font-mono)',
        fontSize: 'var(--text-xs)',
        fontWeight: 700,
        letterSpacing: '0.04em',
      }}
    >
      {s.short}
    </span>
  );
}

export default function SegmentationBoard() {
  const [data, setData] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [form, setForm] = useState({ sourceZone: '', destZone: '', expectation: 'deny', note: '' });

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/segmentation');
      const d = await res.json();
      if (!res.ok) { setError(d.error || 'Could not evaluate segmentation.'); return; }
      setData(d);
    } catch (e) {
      setError('Could not reach the segmentation engine.');
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function addIntent(e) {
    e.preventDefault();
    setBusy(true); setError('');
    try {
      const res = await fetch('/api/segmentation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      const d = await res.json();
      if (!res.ok) { setError(d.error || 'Could not save.'); return; }
      setForm({ ...form, sourceZone: '', destZone: '', note: '' });
      await load();
    } finally { setBusy(false); }
  }

  async function remove(id) {
    setBusy(true);
    try {
      await fetch(`/api/segmentation?id=${encodeURIComponent(id)}`, { method: 'DELETE' });
      await load();
    } finally { setBusy(false); }
  }

  if (!data) return null;

  const zones = data.zones || [];
  const intents = data.intents || [];
  const actionable = intents
    .filter((i) => ACTION_ORDER.includes(i.verdict))
    .sort((a, b) => ACTION_ORDER.indexOf(a.verdict) - ACTION_ORDER.indexOf(b.verdict));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* ── what needs doing ─────────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle>
            What to act on
            {actionable.length > 0 && (
              <Badge color="danger" style={{ marginLeft: 8 }}>{actionable.length}</Badge>
            )}
          </CardTitle>
        </CardHeader>
        <CardBody>
          {intents.length === 0 ? (
            <EmptyState message="No segmentation intent declared yet. Add one below — start with the pair you would most hate to be reachable." />
          ) : actionable.length === 0 ? (
            <p style={{ margin: 0, color: 'var(--text-secondary)' }}>
              Every declared intent matches what the rules actually permit.
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {actionable.map((i) => {
                const s = VERDICT_STYLE[i.verdict];
                return (
                  <div
                    key={i.id}
                    style={{
                      borderLeft: `3px solid ${s.border}`,
                      background: 'var(--surface-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '10px 12px',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                        {i.sourceZone} → {i.destZone}
                      </span>
                      <Cell result={i} />
                      <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                        {i.permittingRuleCount} permitting rule{i.permittingRuleCount === 1 ? '' : 's'}
                        {i.unmeasuredRuleCount > 0 && (
                          <> · <strong style={{ color: 'var(--unmeasured)' }}>
                            {i.unmeasuredRuleCount} with no usage data
                          </strong></>
                        )}
                      </span>
                    </div>
                    <div style={{ marginTop: 4, fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
                      {(VERDICT_STYLE[i.verdict] && DETAIL[i.verdict]) || ''}
                    </div>
                    {i.examples && i.examples.length > 0 && (
                      <div style={{ marginTop: 6, fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                        {i.examples.map((e, n) => (
                          <div key={n}>
                            {e.deviceName || e.deviceId} · {e.ruleName || '(unnamed)'}
                            {e.sequence !== null ? ` · #${e.sequence}` : ''}
                            {' · '}
                            {e.hits === null
                              ? <span style={{ color: 'var(--unmeasured)' }}>usage not measured</span>
                              : `${e.hits.toLocaleString()} hits`}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </CardBody>
      </Card>

      {/* ── the matrix ───────────────────────────────────────────────────── */}
      {intents.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Declared intent</CardTitle></CardHeader>
          <CardBody>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ borderCollapse: 'separate', borderSpacing: '4px', fontSize: 'var(--text-sm)' }}>
                <tbody>
                  {intents.map((i) => (
                    <tr key={i.id}>
                      <td style={{ fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap', color: 'var(--text-primary)' }}>
                        {i.sourceZone} → {i.destZone}
                      </td>
                      <td>
                        <Badge color={i.expectation === 'deny' ? 'muted' : 'info'}>
                          must {i.expectation === 'deny' ? 'not connect' : 'connect'}
                        </Badge>
                      </td>
                      <td><Cell result={i} /></td>
                      <td style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>{i.note || ''}</td>
                      <td>
                        <Button variant="secondary" disabled={busy} onClick={() => remove(i.id)}>Remove</Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* ⛔ Coverage stated under the matrix, never as a footnote. A matrix
                whose verdicts rest on rules that cannot report usage is not the
                same as one that can, and the reader must be told which they are
                looking at. */}
            <div style={{ marginTop: 12, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              Evaluated over {data.windowDays} days against {data.ruleCount.toLocaleString()} rules on{' '}
              {data.deviceCount} firewall{data.deviceCount === 1 ? '' : 's'}.
              {data.rulesWithoutHitData > 0 && (
                <> <strong style={{ color: 'var(--unmeasured)' }}>
                  {data.rulesWithoutHitData.toLocaleString()} of them cannot report usage at all
                </strong>, so any path permitted only by those rules is shown as unmeasurable rather
                than unused.</>
              )}
            </div>
          </CardBody>
        </Card>
      )}

      {/* ── declare ──────────────────────────────────────────────────────── */}
      <Card>
        <CardHeader><CardTitle>Declare an intent</CardTitle></CardHeader>
        <CardBody>
          <form onSubmit={addIntent} style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <div className="form-field" style={{ margin: 0 }}>
              <label htmlFor="src">From zone</label>
              <select id="src" className="select" value={form.sourceZone}
                onChange={(e) => setForm({ ...form, sourceZone: e.target.value })}>
                <option value="">select…</option>
                {zones.map((z) => <option key={z} value={z}>{z}</option>)}
              </select>
            </div>
            <div className="form-field" style={{ margin: 0 }}>
              <label htmlFor="dst">To zone</label>
              <select id="dst" className="select" value={form.destZone}
                onChange={(e) => setForm({ ...form, destZone: e.target.value })}>
                <option value="">select…</option>
                {zones.map((z) => <option key={z} value={z}>{z}</option>)}
              </select>
            </div>
            <div className="form-field" style={{ margin: 0 }}>
              <label htmlFor="exp">Expectation</label>
              <select id="exp" className="select" value={form.expectation}
                onChange={(e) => setForm({ ...form, expectation: e.target.value })}>
                <option value="deny">must NOT connect</option>
                <option value="allow">must connect</option>
              </select>
            </div>
            <div className="form-field" style={{ margin: 0, flex: '1 1 220px' }}>
              <label htmlFor="note">Note (optional)</label>
              <input id="note" className="input" value={form.note}
                onChange={(e) => setForm({ ...form, note: e.target.value })}
                placeholder="e.g. PCI DSS 1.3" />
            </div>
            <Button type="submit" variant="primary" disabled={busy || !form.sourceZone || !form.destZone}>
              Save
            </Button>
          </form>
          {error && (
            <p style={{ marginTop: 10, marginBottom: 0, color: 'var(--tint-danger-fg)', fontSize: 'var(--text-base)' }}>
              {error}
            </p>
          )}
        </CardBody>
      </Card>
    </div>
  );
}

// Kept beside the styles so a new verdict cannot be added with a colour but no
// explanation.
const DETAIL = {
  violation_active: 'A rule allows this, and traffic has actually used it.',
  violation_permitted: 'A rule allows this. Nothing has used it in the window — a standing hole, and the safest kind to close.',
  violation_unverified: 'A rule allows this. Whether anything used it cannot be determined, so assume it is live.',
  unused_permission: 'Permitted as intended, but nothing has used it. The permission has no demonstrated purpose.',
  expected_allow_missing: 'You expect this to work and no enabled rule permits it. Either the intent is wrong or a rule is missing.',
};
