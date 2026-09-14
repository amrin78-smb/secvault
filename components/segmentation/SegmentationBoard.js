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
//
// ⛔ THE SERVER PAGE HANDS US THE FIRST EVALUATION (`initial`). We do not fetch
// one on mount. Doing both ran the whole ~19-query, ~700ms evaluation twice per
// page view and let the server-rendered headline and this matrix disagree if a
// rule pull landed between the two. `load()` still exists and is called after a
// mutation — the one moment the data can genuinely have changed under us.

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

function ErrorNote({ children }) {
  return (
    <p style={{
      marginTop: 10,
      marginBottom: 0,
      color: 'var(--tint-danger-fg)',
      background: 'var(--tint-danger)',
      border: '1px solid var(--sev-crit)',
      borderRadius: 'var(--radius-sm)',
      padding: '8px 10px',
      fontSize: 'var(--text-base)',
    }}>
      {children}
    </p>
  );
}

export default function SegmentationBoard({ initial = null, initialError = '' }) {
  const [data, setData] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(initialError || '');
  // WHERE the failure belongs on screen. One shared error string rendered in two
  // places would print every message twice; rendered only at the top, a
  // validation error from the declare form (the last card on the page) can be
  // off-screen at the moment it is raised.
  const [errorAt, setErrorAt] = useState('board');
  const fail = useCallback((msg, at) => { setError(msg); setErrorAt(at); }, []);
  const [form, setForm] = useState({ sourceZone: '', destZone: '', expectation: 'deny', note: '' });

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/segmentation');
      const d = await res.json().catch(() => ({}));
      if (!res.ok) { fail(d.error || 'Could not evaluate segmentation.', 'board'); return false; }
      setData(d);
      setError('');
      return true;
    } catch (e) {
      fail('Could not reach the segmentation engine.', 'board');
      return false;
    }
  }, [fail]);

  // ⛔ ONLY when the server could not hand us an evaluation. A successful
  // `initial` is already the answer; refetching it would restore the duplicate
  // ~700ms evaluation this component was changed to remove. A server-side
  // failure is NOT retried automatically either — the operator presses Retry,
  // so a broken engine is not hammered once per mount.
  useEffect(() => {
    if (!initial && !initialError) load();
  }, [initial, initialError, load]);

  async function addIntent(e) {
    e.preventDefault();
    setBusy(true); setError('');
    try {
      const res = await fetch('/api/segmentation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      const d = await res.json().catch(() => ({}));
      if (!res.ok) { fail(d.error || 'Could not save.', 'form'); return; }
      setForm({ ...form, sourceZone: '', destZone: '', note: '' });
      await load();
    } catch (err) {
      // ⛔ try/finally WITHOUT a catch made a network failure an unhandled
      // promise rejection: the form simply sat there, the intent was never
      // saved, and nothing on the page said so. On a page whose whole purpose is
      // to record what MUST NOT be reachable, a silently dropped declaration is
      // the worst possible failure — the operator believes the boundary is being
      // watched and it is not.
      fail('Could not reach the segmentation engine — the intent was not saved.', 'form');
    } finally { setBusy(false); }
  }

  async function remove(id) {
    setBusy(true); setError('');
    try {
      const res = await fetch(`/api/segmentation?id=${encodeURIComponent(id)}`, { method: 'DELETE' });
      // ⛔ `res.ok` WAS NEVER CHECKED. A 403 — which is precisely what a role
      // without OPERATE gets here — reloaded the board unchanged, so the Remove
      // button looked like it did nothing at all. An operator who cannot tell a
      // permission boundary from a broken button files the second bug and stops
      // trusting the first.
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        fail(d.error || `Could not remove that intent (HTTP ${res.status}).`, 'board');
        return;
      }
      await load();
    } catch (err) {
      fail('Could not reach the segmentation engine — the intent was not removed.', 'board');
    } finally { setBusy(false); }
  }

  // ⛔ NEVER `return null` HERE. The error state used to be rendered inside the
  // JSX below, underneath an early `if (!data) return null` — so the one case it
  // existed for (no data, because the fetch failed) was the exact case where it
  // could not mount. A 500 produced a page with a header sentence and then
  // nothing: no matrix, no form, no reason, no retry, nothing to distinguish
  // "the engine is broken" from "you have declared no intent yet".
  if (!data) {
    return (
      <Card>
        <CardHeader><CardTitle>Segmentation</CardTitle></CardHeader>
        <CardBody>
          {error ? (
            <>
              <ErrorNote>{error}</ErrorNote>
              <div style={{ marginTop: 10 }}>
                <Button variant="secondary" disabled={busy} onClick={() => { setBusy(true); load().finally(() => setBusy(false)); }}>
                  Retry
                </Button>
              </div>
            </>
          ) : (
            <p style={{ margin: 0, color: 'var(--text-muted)' }}>Evaluating segmentation…</p>
          )}
        </CardBody>
      </Card>
    );
  }

  const zones = data.zones || [];
  const intents = data.intents || [];
  const uncollected = Array.isArray(data.devicesWithoutRules) ? data.devicesWithoutRules : [];
  const unreadableActions = Number(data.rulesWithUnrecognisedAction) || 0;
  const actionable = intents
    .filter((i) => ACTION_ORDER.includes(i.verdict))
    .sort((a, b) => ACTION_ORDER.indexOf(a.verdict) - ACTION_ORDER.indexOf(b.verdict));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* An error raised by a mutation, while we still have data to show. */}
      {error && errorAt === 'board' && <ErrorNote>{error}</ErrorNote>}

      {/* ── what needs doing ─────────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle>
            What to act on
            {actionable.length > 0 && (
              // ⛔ Badge takes {color, children, className, title} and NOTHING
              // else — a `style` prop is silently dropped on the floor, which is
              // how this count ended up jammed against the heading. Spacing goes
              // on a wrapper, and on the token scale rather than a raw 8px.
              <span style={{ marginLeft: 'var(--s2)' }}>
                <Badge color="danger">{actionable.length}</Badge>
              </span>
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
                        {i.unrecognisedActionRuleCount > 0 && (
                          <> · <strong style={{ color: 'var(--unmeasured)' }}>
                            {i.unrecognisedActionRuleCount} with an action SecVault cannot read
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
                looking at.

                ⛔ `data.windowDays` is the window the evidence ACTUALLY spans,
                which is not always the one that was requested — see
                resolveWindowDays in lib/engines/segmentationData.js. This line
                previously printed the request, so `?days=-5` rendered
                "Evaluated over -5 days" over a 30-day measurement. */}
            <div style={{ marginTop: 12, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              Evaluated over {data.windowDays} days against {Number(data.ruleCount).toLocaleString()} rules on{' '}
              {data.deviceCount} firewall{data.deviceCount === 1 ? '' : 's'}.
              {data.rulesWithoutHitData > 0 && (
                <> <strong style={{ color: 'var(--unmeasured)' }}>
                  {Number(data.rulesWithoutHitData).toLocaleString()} of them cannot report usage at all
                </strong>, so any path permitted only by those rules is shown as unmeasurable rather
                than unused.</>
              )}
              {/* ⛔ Most hit counts are the DEVICE'S OWN lifetime counter, not a
                  count over this window. Saying "in the last N days" for all of
                  them would be untrue for ~87% of the live fleet's rules. */}
              {' '}Where a firewall reports its own hit counter, that count is cumulative since the
              counter was last reset, so "in use" can mean traffic older than this window.
              {uncollected.length > 0 && (
                // ⛔ Coverage is per device. A pair whose permitting rule might
                // live on an unread firewall is reported UNKNOWN, not "blocked",
                // and the operator is told which firewalls are missing.
                <> <strong style={{ color: 'var(--unmeasured)' }}>
                  {uncollected.length} active firewall{uncollected.length === 1 ? ' has' : 's have'} no
                  collected ruleset ({uncollected.slice(0, 5).join(', ')}
                  {uncollected.length > 5 ? `, +${uncollected.length - 5} more` : ''})
                </strong>, so no path can be confirmed blocked until they are pulled.</>
              )}
              {unreadableActions > 0 && (
                <> <strong style={{ color: 'var(--unmeasured)' }}>
                  {unreadableActions.toLocaleString()} enabled rule{unreadableActions === 1 ? ' uses' : 's use'} an
                  action SecVault does not recognise
                </strong>, so a pair matched only by those rules is shown as unknown rather than
                blocked — an unreadable verb may well be an allow.</>
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
          {error && errorAt === 'form' && <ErrorNote>{error}</ErrorNote>}
        </CardBody>
      </Card>
    </div>
  );
}

// Kept beside the styles so a new verdict cannot be added with a colour but no
// explanation.
//
// ⛔ THESE MIRROR VERDICTS[].detail IN lib/engines/segmentation.js AND MUST NOT
// CLAIM MORE THAN IT DOES. "No traffic in the window" was wrong for most rules:
// `effectiveHitCount` prefers the device's own cumulative counter over the
// log-derived windowed count (1,524 of 1,757 rules live), so the number behind
// these sentences usually spans the counter's lifetime, not the window.
const DETAIL = {
  violation_active: 'A rule allows this, and traffic has been recorded against it. Where the count is the device\'s own it is cumulative since that counter was last reset, so the traffic is not necessarily recent — but it did happen.',
  violation_permitted: 'A rule allows this and has recorded no traffic at all — a standing hole, and the safest kind to close.',
  violation_unverified: 'A rule allows this. Whether anything used it cannot be determined, so assume it is live.',
  unused_permission: 'Permitted as intended, with no traffic recorded against any permitting rule. The permission has no demonstrated purpose.',
  expected_allow_missing: 'You expect this to work and no enabled rule permits it. Either the intent is wrong or a rule is missing.',
};
