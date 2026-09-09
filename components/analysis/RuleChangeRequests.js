'use client';

import { useState, useRef, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Badge from '../ui/Badge';
import NotMeasured from '../ui/NotMeasured';

// The rule-cleanup loop's UI: propose rules for removal, hand the list to
// whoever edits the firewall, then read back whether they actually went.
//
// ⛔ WHAT MAKES THIS DIFFERENT FROM AN EXPORT BUTTON. ManageEngine Firewall
// Analyzer has listed unused rules for years. The half it cannot do — and the
// only reason this screen exists — is the VERIFY half: SecVault re-collects the
// ruleset on a schedule, so it can state whether the change was made. Every
// completion state rendered here is therefore MEASURED. There is no control in
// this file that marks a request done, and adding one would delete the feature
// while leaving the screen looking identical.
//
// ⛔ AND THE OTHER HALF: WITHHELD RULES ARE SHOWN, LOUDLY. getCleanupCandidates
// refuses to offer a rule whose hit count was never measured (the vendor or
// transport cannot report one) or which carries no vendor identifier that would
// survive the next ruleset DELETE+reinsert. A cleanup screen that silently
// renders the shorter list looks complete and is not — it is the
// failed-read-as-a-fact bug with a delete button attached. WithheldNotice below
// states the count and the reasons beside the list, never in a footnote.
//
// Client component: selection state, the create/submit/abandon POSTs and the
// on-demand item detail all need the browser. The candidate TABLE itself is
// rendered on the server and passed in as `children` — the checkboxes are plain
// uncontrolled inputs named `ruleIds`, read out of FormData on submit, so a
// 136-row candidate list costs no client state at all.

const STATUS_META = {
  draft: { color: 'muted', label: 'Draft' },
  submitted: { color: 'info', label: 'Submitted' },
  verified: { color: 'success', label: 'Verified' },
  partial: { color: 'warning', label: 'Partly done' },
  abandoned: { color: 'muted', label: 'Abandoned' },
};

// ⛔ `unverifiable` is ABSENT from this map on purpose. It is not a status with
// a colour; it is the absence of a measurement, and it renders through
// NotMeasured with a reason. See ItemOutcome.
const OUTCOME_META = {
  removed: { color: 'success', label: 'Removed' },
  still_present: { color: 'warning', label: 'Still present' },
};

const UNVERIFIABLE_REASON =
  'No rules collection has succeeded for this device since the request was submitted, '
  + 'so SecVault cannot tell whether the rule was removed. This is a gap in our '
  + 'collection, not a statement about the operator or the rule.';

const PENDING_REASON =
  'Not checked yet — this request has not been submitted, so there is nothing to '
  + 'compare a later ruleset against.';

function formatWhen(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

// ── Withheld ──────────────────────────────────────────────────────────────

/**
 * The rules the engine REFUSED to offer, with the reason it refused them.
 *
 * ⛔ This renders even when the candidate list is long and healthy, and it
 * renders ABOVE the list, not below it. The whole failure mode being guarded
 * against is a screen that looks finished because the excluded rows are simply
 * not drawn.
 *
 * ⛔ No severity hue: hatching plus --unmeasured. "We could not measure this"
 * is not bad news and not good news, and colouring it either way is the same
 * lie in a different direction (see components/ui/NotMeasured.js).
 */
export function WithheldNotice({ withheld }) {
  const rows = Array.isArray(withheld) ? withheld : [];
  if (rows.length === 0) return null;

  // Group by the engine's own sentence — it writes one per exclusion kind, and
  // quoting it verbatim keeps the UI from inventing a softer wording.
  const byReason = new Map();
  for (const r of rows) {
    const key = r.reason || 'Withheld for an unstated reason.';
    if (!byReason.has(key)) byReason.set(key, []);
    byReason.get(key).push(r);
  }

  return (
    <div
      style={{
        display: 'flex',
        gap: 'var(--s3)',
        alignItems: 'flex-start',
        padding: 'var(--s3)',
        marginBottom: 'var(--s3)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        background: 'var(--surface-subtle)',
      }}
    >
      <span
        aria-hidden="true"
        style={{
          flex: 'none',
          width: 18,
          height: 18,
          marginTop: 2,
          borderRadius: 4,
          border: '1px solid var(--border)',
          background: 'var(--hatch)',
          backgroundColor: 'var(--surface-subtle)',
        }}
      />
      <div style={{ minWidth: 0 }}>
        <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
          {rows.length} more rule{rows.length === 1 ? ' was' : 's were'} held back and{' '}
          {rows.length === 1 ? 'is' : 'are'} not in the list below.
        </div>
        <div style={{ marginTop: 4, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
          SecVault will not propose a rule for deletion when it cannot show the evidence, or could
          not confirm the removal afterwards.
        </div>
        <ul
          style={{
            margin: 'var(--s2) 0 0',
            paddingLeft: '1.1em',
            fontSize: 'var(--text-sm)',
            color: 'var(--text-secondary)',
          }}
        >
          {[...byReason.entries()].map(([reason, group]) => (
            <li key={reason} style={{ marginBottom: 4 }}>
              <strong style={{ color: 'var(--text-primary)' }}>{group.length}</strong> — {reason}
            </li>
          ))}
        </ul>
        <details style={{ marginTop: 'var(--s2)' }}>
          <summary
            style={{ cursor: 'pointer', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}
          >
            Show the held-back rule{rows.length === 1 ? '' : 's'}
          </summary>
          <ul
            style={{
              margin: 'var(--s2) 0 0',
              paddingLeft: '1.1em',
              fontSize: 'var(--text-sm)',
              color: 'var(--text-secondary)',
            }}
          >
            {rows.map((r, i) => (
              <li
                key={`${r.ruleIdVendor || 'no-id'}-${r.findingType}-${i}`}
                style={{ marginBottom: 2 }}
              >
                <span style={{ color: 'var(--text-primary)' }}>
                  {r.ruleName || r.ruleIdVendor || '(unnamed rule)'}
                </span>{' '}
                <Badge color="muted">{r.findingType}</Badge>{' '}
                {/* ⛔ The excluded value renders as NOT MEASURED, never as 0
                    hits and never as a blank identifier. */}
                <NotMeasured
                  reason={r.reason}
                  text={r.ruleIdVendor ? 'no hit count' : 'no rule id'}
                />
              </li>
            ))}
          </ul>
        </details>
      </div>
    </div>
  );
}

// ── Create a request ──────────────────────────────────────────────────────

/**
 * Wraps the server-rendered candidate table in a form and adds the
 * title/note/create controls.
 *
 * `children` is the <Table> of eligible rules; each row carries a plain
 * `<input type="checkbox" name="ruleIds" value={rule_id_vendor}>`.
 */
export function CleanupRequestPanel({ deviceId, canWrite, eligibleCount, withheld, children }) {
  const router = useRouter();
  const formRef = useRef(null);
  const [selected, setSelected] = useState(0);
  const [title, setTitle] = useState('');
  const [note, setNote] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  // Deduped: a rule can carry more than one removable finding (unused AND
  // shadow AND redundant, measured on the live fleet), and a request stores one
  // item per RULE. Counting checked boxes would over-report.
  const recount = useCallback(() => {
    const form = formRef.current;
    if (!form) return;
    const ids = new Set(new FormData(form).getAll('ruleIds').filter(Boolean));
    setSelected(ids.size);
  }, []);

  function setAll(checked) {
    const form = formRef.current;
    if (!form) return;
    const boxes = form.querySelectorAll('input[name="ruleIds"]');
    for (const box of boxes) box.checked = checked;
    recount();
  }

  async function onSubmit(e) {
    e.preventDefault();
    if (saving) return;
    const form = e.currentTarget;
    const ruleIds = [...new Set(new FormData(form).getAll('ruleIds').filter(Boolean))];
    if (ruleIds.length === 0) {
      setError('Select at least one rule');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const res = await fetch(`/api/devices/${deviceId}/rule-change-requests`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: title.trim() || undefined,
          note: note.trim() || undefined,
          ruleIds,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) throw new Error(data.error || 'Could not create the request');
      setAll(false);
      setTitle('');
      setNote('');
      router.refresh();
    } catch (err) {
      setError(err.message || 'Could not create the request');
    } finally {
      setSaving(false);
    }
  }

  return (
    <form ref={formRef} onSubmit={onSubmit} onChange={recount} style={{ marginBottom: 'var(--s5)' }}>
      <div style={{ marginBottom: 'var(--s2)' }}>
        <div style={{ fontWeight: 600, fontSize: 'var(--text-md)', color: 'var(--text-primary)' }}>
          Removal candidates
        </div>
        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginTop: 2 }}>
          {eligibleCount} rule{eligibleCount === 1 ? '' : 's'} can be proposed for removal — each
          has a measured hit count and a vendor identifier SecVault can check again afterwards.
        </div>
      </div>

      {/* ⛔ Before the list, never after it, and never behind a disclosure on
          its own — the count and the reasons are always visible. */}
      <WithheldNotice withheld={withheld} />

      {children}

      {canWrite ? (
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'flex-end',
            gap: 'var(--s3)',
            marginTop: 'var(--s3)',
          }}
        >
          <div style={{ display: 'flex', gap: 'var(--s2)' }}>
            <button type="button" className="btn btn-secondary" onClick={() => setAll(true)}>
              Select all
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => setAll(false)}>
              Clear
            </button>
          </div>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: '1 1 200px' }}>
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Title</span>
            <input
              type="text"
              className="input"
              placeholder="Rule cleanup"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              disabled={saving}
            />
          </label>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: '2 1 280px' }}>
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
              Note for whoever makes the change
            </span>
            <input
              type="text"
              className="input"
              placeholder="Optional — change window, ticket reference…"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              disabled={saving}
            />
          </label>
          <button type="submit" className="btn btn-primary" disabled={saving || selected === 0}>
            {saving ? 'Creating…' : `Create change request (${selected})`}
          </button>
          {error && (
            <span
              style={{ fontSize: 'var(--text-sm)', color: 'var(--red)' }}
              title={error}
              role="status"
            >
              ⚠ {error}
            </span>
          )}
        </div>
      ) : (
        <div
          style={{ marginTop: 'var(--s3)', fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}
        >
          Creating a change request needs an admin account.
        </div>
      )}
    </form>
  );
}

// ── Request list + detail ─────────────────────────────────────────────────

function RequestStatusBadge({ status }) {
  const meta = STATUS_META[status] || { color: 'muted', label: status || 'Unknown' };
  return <Badge color={meta.color}>{meta.label}</Badge>;
}

/**
 * One item's outcome.
 *
 * ⛔ FOUR STATES, AND TWO OF THEM CARRY NO COLOUR.
 *   removed        MEASURED: gone from a ruleset collected after submission.
 *                  Green, with the moment it was verified.
 *   still_present  MEASURED: it is still there. Amber — a real, earned finding.
 *   unverifiable   NOT MEASURED. No pull has succeeded since submission, so
 *                  nothing can be concluded. NotMeasured + reason, never a red
 *                  "not done" — that would report SecVault's own collection gap
 *                  as the operator's inaction.
 *   pending        NOT MEASURED either: nothing has been looked for yet.
 */
function ItemOutcome({ outcome, verifiedAt }) {
  if (outcome === 'unverifiable') {
    return <NotMeasured reason={UNVERIFIABLE_REASON} text="Not verifiable yet" />;
  }
  if (outcome === 'pending' || !outcome) {
    return <NotMeasured reason={PENDING_REASON} text="Not checked yet" />;
  }
  const meta = OUTCOME_META[outcome];
  if (!meta) {
    return <NotMeasured reason={`Unrecognised outcome "${outcome}".`} text={outcome} />;
  }
  const when = formatWhen(verifiedAt);
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <Badge color={meta.color}>{meta.label}</Badge>
      {when ? (
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          verified {when}
        </span>
      ) : null}
    </span>
  );
}

function RequestRow({ request, canWrite }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);

  async function toggle() {
    const next = !open;
    setOpen(next);
    if (!next || detail) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/rule-change-requests/${request.id}`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) throw new Error(data.error || 'Could not load the request');
      setDetail(data);
    } catch (err) {
      setError(err.message || 'Could not load the request');
    } finally {
      setLoading(false);
    }
  }

  async function act(action) {
    if (busy) return;
    setBusy(action);
    setError(null);
    try {
      const res = await fetch(`/api/rule-change-requests/${request.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) throw new Error(data.error || `Could not ${action} the request`);
      setDetail(null);
      router.refresh();
    } catch (err) {
      setError(err.message || `Could not ${action} the request`);
    } finally {
      setBusy(null);
    }
  }

  const items = Number(request.item_count || 0);
  const removed = Number(request.removed_count || 0);
  const stillPresent = Number(request.still_present_count || 0);
  const unverifiable = Number(request.unverifiable_count || 0);
  // A submitted request whose items are ALL unmeasured is not "in progress" and
  // not "failed" — no ruleset has been collected since it was submitted, so
  // there is nothing to conclude. Said in words here rather than left for the
  // reader to infer from three zeroes.
  const nothingMeasurable =
    request.status === 'submitted' && items > 0 && removed === 0 && stillPresent === 0;

  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: 'var(--s3)',
        marginBottom: 'var(--s2)',
        background: 'var(--bg-card)',
      }}
    >
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--s3)' }}>
        <button
          type="button"
          onClick={toggle}
          aria-expanded={open}
          style={{
            background: 'none',
            border: 'none',
            padding: 0,
            cursor: 'pointer',
            fontWeight: 600,
            fontSize: 'var(--text-sm)',
            color: 'var(--accent-teal)',
            textAlign: 'left',
          }}
        >
          {open ? '▾' : '▸'} {request.title || 'Rule cleanup'}
        </button>
        <RequestStatusBadge status={request.status} />
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          {items} rule{items === 1 ? '' : 's'}
          {removed > 0 ? ` · ${removed} removed` : ''}
          {stillPresent > 0 ? ` · ${stillPresent} still present` : ''}
        </span>
        {unverifiable > 0 && (
          <NotMeasured reason={UNVERIFIABLE_REASON} text={`${unverifiable} not verifiable yet`} />
        )}
        <span style={{ flex: 1 }} />
        {canWrite && request.status === 'draft' && (
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => act('submit')}
            disabled={Boolean(busy)}
            style={{ fontSize: 'var(--text-xs)', padding: '4px 10px' }}
          >
            {busy === 'submit' ? 'Submitting…' : 'Submit'}
          </button>
        )}
        {canWrite && (request.status === 'draft' || request.status === 'submitted') && (
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => act('abandon')}
            disabled={Boolean(busy)}
            style={{ fontSize: 'var(--text-xs)', padding: '4px 10px' }}
          >
            {busy === 'abandon' ? 'Abandoning…' : 'Abandon'}
          </button>
        )}
      </div>

      <div
        style={{
          marginTop: 4,
          fontSize: 'var(--text-xs)',
          color: 'var(--text-muted)',
          display: 'flex',
          flexWrap: 'wrap',
          gap: 'var(--s3)',
        }}
      >
        <span>
          Created {formatWhen(request.created_at)}
          {request.created_by ? ` by ${request.created_by}` : ''}
        </span>
        {request.submitted_at && <span>Submitted {formatWhen(request.submitted_at)}</span>}
        {request.verified_at && <span>Verified {formatWhen(request.verified_at)}</span>}
      </div>

      {/* ⛔ Stated in words, because "0 removed, 0 still present" reads as a
          failure and is not one. */}
      {nothingMeasurable && (
        <div style={{ marginTop: 'var(--s2)', fontSize: 'var(--text-sm)' }}>
          <NotMeasured
            reason={UNVERIFIABLE_REASON}
            text="Nothing can be concluded yet — no rules collection has succeeded since this was submitted."
          />
        </div>
      )}

      {request.note && (
        <div
          style={{
            marginTop: 'var(--s2)',
            fontSize: 'var(--text-sm)',
            color: 'var(--text-secondary)',
            fontStyle: 'italic',
          }}
        >
          &ldquo;{request.note}&rdquo;
        </div>
      )}

      {error && (
        <div
          style={{ marginTop: 'var(--s2)', fontSize: 'var(--text-sm)', color: 'var(--red)' }}
          role="status"
        >
          ⚠ {error}
        </div>
      )}

      {open && (
        <div style={{ marginTop: 'var(--s3)' }}>
          {loading && (
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>Loading…</span>
          )}
          {detail && Array.isArray(detail.items) && detail.items.length > 0 && (
            <div
              style={{
                overflowX: 'auto',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
              }}
            >
              {/* tableLayout:'fixed' is mandatory alongside the colgroup below. */}
              <table
                style={{
                  tableLayout: 'fixed',
                  width: '100%',
                  minWidth: 620,
                  borderCollapse: 'collapse',
                }}
              >
                <colgroup>
                  <col style={{ width: '38%' }} />
                  <col style={{ width: '16%' }} />
                  <col style={{ width: '16%' }} />
                  <col style={{ width: '30%' }} />
                </colgroup>
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Finding</th>
                    <th>Hits when proposed</th>
                    <th>Outcome</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.items.map((it) => (
                    <tr key={it.id}>
                      <td title={it.rule_id_vendor}>{it.rule_name || it.rule_id_vendor}</td>
                      <td>
                        <Badge color="muted">{it.finding_type}</Badge>
                      </td>
                      <td>
                        {/* Every item has a MEASURED hit count by construction —
                            createRequest refuses the others — so a null here
                            means something bypassed the engine. Say that
                            instead of printing 0. */}
                        {it.hit_count_at_request === null ||
                        it.hit_count_at_request === undefined ? (
                          <NotMeasured reason="No hit count was recorded when this rule was proposed." />
                        ) : (
                          Number(it.hit_count_at_request)
                        )}
                      </td>
                      <td>
                        <ItemOutcome outcome={it.outcome} verifiedAt={it.verified_at} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {detail && Array.isArray(detail.items) && detail.items.length === 0 && (
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              This request has no rules on it.
            </span>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * The device's change requests.
 *
 * `loadError` is not politeness. If the request tables could not be read, an
 * empty list would say "no requests exist", which is a different and much more
 * comfortable claim than "we could not look". The two must never render alike.
 */
export default function RuleChangeRequests({ requests, canWrite, loadError = null }) {
  const rows = Array.isArray(requests) ? requests : [];

  return (
    <div style={{ marginBottom: 'var(--s5)' }}>
      <div style={{ fontWeight: 600, fontSize: 'var(--text-md)', color: 'var(--text-primary)' }}>
        Change requests
      </div>
      <div
        style={{
          fontSize: 'var(--text-sm)',
          color: 'var(--text-secondary)',
          margin: '2px 0 var(--s3)',
        }}
      >
        A request is marked verified only when a rules collection that ran <em>after</em> it was
        submitted no longer contains the rules. There is no way to mark one done by hand.
      </div>

      {loadError ? (
        <div style={{ fontSize: 'var(--text-sm)' }}>
          <NotMeasured
            reason={loadError}
            text="Change requests could not be read — that is not the same as there being none."
          />
        </div>
      ) : rows.length === 0 ? (
        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
          No change requests for this device yet.
        </div>
      ) : (
        rows.map((r) => <RequestRow key={r.id} request={r} canWrite={canWrite} />)
      )}
    </div>
  );
}
