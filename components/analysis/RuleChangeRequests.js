'use client';

import { useState, useRef, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Badge from '../ui/Badge';
import NotMeasured from '../ui/NotMeasured';
// ⛔ ONE DEFINITION OF "MAY THIS BE SUBMITTED", SHARED WITH THE ROUTE AND THE
// SQL. The obvious alternative — a small `state === 'pending'` test in this
// file — is a second copy of a rule whose whole job is to hold a change back,
// and the copy that drifted would be the one disabling (or failing to disable)
// the button. lib/engines/ruleChangeRequests.js has ZERO imports of its own, so
// a client bundle can load it the way lib/evidence.js and lib/licenceBanner.js
// are already loaded.
import { submissionBlock } from '../../lib/engines/ruleChangeRequests';

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
// ⛔ AND THE THIRD HALF (v2.225.0): AN APPROVAL IS NOT A COMPLETION. The
// approve/reject controls below write `approval_state` and nothing else — the
// request they approve is still a DRAFT afterwards and still has to be
// submitted. If an approval ever moved a request to `verified`, every sentence
// above would still be on screen and none of it would be true. Self-approval is
// refused by the SERVER; the control states that refusal rather than hiding.
//
// ⛔ A REQUEST SECVAULT CANNOT VERIFY SAYS SO IN ITS OWN WORDS. A modification,
// an addition or an object change is not answerable by absence from the next
// ruleset, so those items carry `not_supported` — rendered through CannotVerify,
// which is hueless like NotMeasured but worded and labelled apart from it,
// because "no collection has succeeded yet" clears itself and "we do not
// measure this" never will.
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

// ⛔ APPROVAL IS ITS OWN AXIS, NOT A STATUS. A request's `status` says where it
// is in the loop (draft -> submitted -> verified/partial); `approval_state` says
// whether a human has authorised it. Merging them into one badge would make
// "approved" look like a stage of completion, which is the one thing an
// approval must never be mistaken for.
//
// ⛔ `not_required` IS DELIBERATELY NOT A GREEN BADGE. It means the requester
// never asked for an approval step — the absence of a control, not a pass. It
// renders as muted text rather than a tick.
const APPROVAL_META = {
  pending: { color: 'warning', label: 'Awaiting approval' },
  approved: { color: 'success', label: 'Approved' },
  rejected: { color: 'danger', label: 'Rejected' },
};

const REQUEST_TYPE_LABEL = {
  rule_deletion: 'Delete rules',
  rule_modification: 'Modify rules',
  rule_addition: 'Add rules',
  object_change: 'Change objects',
};

const UNVERIFIABLE_REASON =
  'No rules collection has succeeded for this device since the request was submitted, '
  + 'so SecVault cannot tell whether the rule was removed. This is a gap in our '
  + 'collection, not a statement about the operator or the rule.';

// ⛔ A DIFFERENT SENTENCE FROM UNVERIFIABLE_REASON, AND THE DIFFERENCE IS THE
// WHOLE POINT. "Not verifiable yet" is a COLLECTION gap: it clears itself the
// next time a rules pull succeeds, and the operator's next step is to fix
// collection. This is a CAPABILITY gap: no collection will ever clear it,
// because absence from the ruleset answers a deletion and nothing else. Showing
// one as the other leaves somebody waiting for a confirmation that is never
// coming — our limitation reported as their collection problem.
const NOT_SUPPORTED_REASON =
  'SecVault cannot verify this kind of change. A deletion is confirmed by the rule being absent '
  + 'from the ruleset we re-collect; a modification, an addition or an object change is not '
  + 'answerable that way, so no future collection will confirm it. Whoever makes the change has '
  + 'to confirm it.';

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
  // ⛔ FALSE BY DEFAULT, which is the whole asymmetry schema.sql's
  // `not_required` default encodes: requiring approval is an explicit choice,
  // never a silent upgrade of behaviour that has always worked without one.
  const [requiresApproval, setRequiresApproval] = useState(false);
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
          requiresApproval,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) throw new Error(data.error || 'Could not create the request');
      setAll(false);
      setTitle('');
      setNote('');
      setRequiresApproval(false);
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
          {/* ⛔ Says what approval does AND what it does not do. An approval
              authorises the change; it is never evidence the change was made,
              and the request still has to be submitted afterwards. */}
          <label
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              fontSize: 'var(--text-sm)',
              color: 'var(--text-secondary)',
            }}
            title={
              'The request cannot be submitted until another administrator approves it. An '
              + 'approval authorises the change; it is not a record that the change was made.'
            }
          >
            <input
              type="checkbox"
              checked={requiresApproval}
              onChange={(e) => setRequiresApproval(e.target.checked)}
              disabled={saving}
            />
            Require approval before this can be submitted
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

// ── Raise a change that is NOT a deletion ─────────────────────────────────

// ⛔ `rule_deletion` IS DELIBERATELY ABSENT FROM THIS LIST. A deletion is
// evidence-backed: it may only be built from getCleanupCandidates, which
// withholds every rule whose hit count was never measured. This form takes a
// typed subject, so offering "delete" here would be a way around that refusal.
//
// ⛔ The engine makes that structural rather than trusting this list: a POST of
// `requestType: 'rule_deletion'` goes down prepareDeletionItems() and ignores
// `items` entirely, so the eligibility check cannot be bypassed by an API
// caller either.
const COMPOSER_TYPES = [
  ['rule_modification', 'Modify an existing rule'],
  ['rule_addition', 'Add a new rule'],
  ['object_change', 'Change a network object'],
];

const SUBJECT_LABEL = {
  rule_modification: 'Rule ID on the firewall',
  // ⛔ NAMED AS A LABEL, NOT AN ID. There is no rule to reference yet, and the
  // field must not invite somebody to type a vendor id that does not exist.
  rule_addition: 'Name you intend to give the new rule',
  object_change: 'Object name',
};

const SUBJECT_HINT = {
  rule_modification:
    'SecVault looks this up in the ruleset it last collected and records whether it found it. '
    + 'A rule it cannot find is still accepted — that may be our collection gap, not your typo.',
  rule_addition:
    'A label for the rule you are asking for. It is not a firewall rule id, and SecVault does not '
    + 'create anything.',
  object_change: 'The object as it is named on the firewall. SecVault does not look objects up.',
};

const emptyItem = () => ({ subject: '', requestedChange: '' });

/**
 * Raise a modification / addition / object change.
 *
 * ⛔ IT SAYS, BEFORE ANYTHING IS TYPED, THAT SECVAULT CANNOT VERIFY THIS. The
 * cleanup loop's whole claim is that completion is MEASURED, and this form
 * produces the one kind of request where it is not. Finding that out afterwards
 * — from a request stuck at "submitted" for ever — would read as a product
 * fault rather than a stated limit.
 */
export function ChangeRequestComposer({ deviceId, canWrite }) {
  const router = useRouter();
  const [requestType, setRequestType] = useState('rule_modification');
  const [title, setTitle] = useState('');
  const [note, setNote] = useState('');
  const [requiresApproval, setRequiresApproval] = useState(false);
  const [rows, setRows] = useState([emptyItem()]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  if (!canWrite) return null;

  function setRow(index, field, value) {
    setRows((prev) => prev.map((r, i) => (i === index ? { ...r, [field]: value } : r)));
  }

  const ready = rows.some((r) => r.subject.trim() !== '' && r.requestedChange.trim() !== '');

  async function onSubmit(e) {
    e.preventDefault();
    if (saving) return;
    const items = rows
      .map((r) => ({ subject: r.subject.trim(), requestedChange: r.requestedChange.trim() }))
      .filter((r) => r.subject !== '' || r.requestedChange !== '');
    if (items.length === 0) {
      setError('Add at least one item to the request');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const res = await fetch(`/api/devices/${deviceId}/rule-change-requests`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          requestType,
          title: title.trim() || undefined,
          note: note.trim() || undefined,
          items,
          requiresApproval,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) throw new Error(data.error || 'Could not create the request');
      setRows([emptyItem()]);
      setTitle('');
      setNote('');
      setRequiresApproval(false);
      router.refresh();
    } catch (err) {
      setError(err.message || 'Could not create the request');
    } finally {
      setSaving(false);
    }
  }

  const fieldCol = { display: 'flex', flexDirection: 'column', gap: 4 };
  const hintStyle = { fontSize: 'var(--text-xs)', color: 'var(--text-muted)' };

  return (
    <details style={{ marginBottom: 'var(--s5)' }}>
      <summary style={{ cursor: 'pointer', fontWeight: 600, color: 'var(--text-primary)' }}>
        Raise a change that is not a deletion
      </summary>
      <form onSubmit={onSubmit} style={{ marginTop: 'var(--s3)' }}>
        <div
          style={{
            padding: 'var(--s3)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            background: 'var(--surface-subtle)',
            fontSize: 'var(--text-sm)',
            color: 'var(--text-secondary)',
            marginBottom: 'var(--s3)',
          }}
        >
          <strong style={{ color: 'var(--text-primary)' }}>
            SecVault cannot verify this kind of change.
          </strong>{' '}
          A deletion is confirmed by the rule being absent from the ruleset we re-collect. A
          modification, an addition or an object change is not answerable that way, so a request
          raised here stays at &ldquo;submitted&rdquo; and whoever makes the change confirms it.
          Nothing here is derived from an analysis — it is your instruction, recorded.
        </div>

        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 'var(--s3)',
            marginBottom: 'var(--s3)',
          }}
        >
          <label style={{ ...fieldCol, flex: '1 1 200px' }}>
            <span style={hintStyle}>What kind of change</span>
            <select
              className="input"
              value={requestType}
              onChange={(e) => setRequestType(e.target.value)}
              disabled={saving}
            >
              {COMPOSER_TYPES.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label style={{ ...fieldCol, flex: '1 1 200px' }}>
            <span style={hintStyle}>Title</span>
            <input
              type="text"
              className="input"
              placeholder="Rule change request"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              disabled={saving}
            />
          </label>
          <label style={{ ...fieldCol, flex: '2 1 280px' }}>
            <span style={hintStyle}>Note for whoever makes the change</span>
            <input
              type="text"
              className="input"
              placeholder="Optional — change window, ticket reference…"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              disabled={saving}
            />
          </label>
        </div>

        <div style={{ ...hintStyle, marginBottom: 4 }}>{SUBJECT_HINT[requestType]}</div>

        {rows.map((row, i) => (
          <div
            key={`item-${i}`}
            style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--s3)', marginBottom: 'var(--s2)' }}
          >
            <label style={{ ...fieldCol, flex: '1 1 200px' }}>
              <span style={hintStyle}>{SUBJECT_LABEL[requestType]}</span>
              <input
                type="text"
                className="input"
                value={row.subject}
                onChange={(e) => setRow(i, 'subject', e.target.value)}
                disabled={saving}
              />
            </label>
            <label style={{ ...fieldCol, flex: '2 1 320px' }}>
              {/* ⛔ REQUIRED, and the API refuses without it: a change request
                  with no instruction cannot be acted on by the person it is
                  handed to, and SecVault cannot verify it either. */}
              <span style={hintStyle}>What should change (required)</span>
              <input
                type="text"
                className="input"
                value={row.requestedChange}
                onChange={(e) => setRow(i, 'requestedChange', e.target.value)}
                disabled={saving}
              />
            </label>
            {rows.length > 1 && (
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setRows((prev) => prev.filter((_, j) => j !== i))}
                disabled={saving}
                style={{ fontSize: 'var(--text-xs)', padding: '4px 10px', alignSelf: 'flex-end' }}
              >
                Remove
              </button>
            )}
          </div>
        ))}

        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--s3)' }}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setRows((prev) => [...prev, emptyItem()])}
            disabled={saving}
          >
            Add another item
          </button>
          <label
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              fontSize: 'var(--text-sm)',
              color: 'var(--text-secondary)',
            }}
            title={
              'The request cannot be submitted until another administrator approves it. An '
              + 'approval authorises the change; it is not a record that the change was made.'
            }
          >
            <input
              type="checkbox"
              checked={requiresApproval}
              onChange={(e) => setRequiresApproval(e.target.checked)}
              disabled={saving}
            />
            Require approval before this can be submitted
          </label>
          <button type="submit" className="btn btn-primary" disabled={saving || !ready}>
            {saving ? 'Creating…' : 'Create change request'}
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
      </form>
    </details>
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
 *   not_supported  NOT MEASURABLE, EVER, for this kind of request. Hueless and
 *                  worded apart from unverifiable — see NOT_SUPPORTED_REASON.
 */
/**
 * "SecVault cannot verify this kind of change."
 *
 * ⛔ HUELESS LIKE NotMeasured, BUT NOT NotMeasured. It shares the visual family
 * on purpose — this is not good news or bad news and must never be drawn on the
 * severity ramp — but NotMeasured's accessible name is "Not measured: <reason>",
 * and this is not a measurement that failed. It is a question this product does
 * not ask. A screen-reader user must hear the difference, because that is where
 * the two states' first steps diverge.
 *
 * Module top level, never nested inside another component.
 */
function CannotVerify({ text = 'Cannot be verified' }) {
  return (
    <span
      title={NOT_SUPPORTED_REASON}
      aria-label={`Cannot be verified: ${NOT_SUPPORTED_REASON}`}
      style={{ color: 'var(--unmeasured)' }}
    >
      {text}
    </span>
  );
}

function ItemOutcome({ outcome, verifiedAt }) {
  // ⛔ BEFORE the unverifiable branch, and never folded into it.
  if (outcome === 'not_supported') {
    return <CannotVerify />;
  }
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

/**
 * The approval line on a request row.
 *
 * ⛔ IT STATES THE ABSENCE OF A STEP TOO. A request raised without an approval
 * step says so in muted text; leaving the line out entirely would make an
 * unapproved change indistinguishable from an approved one at a glance, on the
 * screen where somebody decides whether to hand it over.
 *
 * Module top level, never nested inside another component.
 */
function ApprovalLine({ request }) {
  const state = request.approval_state || 'not_required';
  const meta = APPROVAL_META[state];
  const who = request.approved_by || null;
  const when = formatWhen(request.approved_at);

  if (!meta) {
    // Covers `not_required` AND anything unrecognised. ⛔ An unknown value is
    // NOT rendered as approved — it says SecVault cannot tell.
    return (
      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
        {state === 'not_required'
          ? 'No approval step — nobody has signed this off'
          : `Unrecognised approval state "${state}"`}
      </span>
    );
  }

  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
      <Badge color={meta.color}>{meta.label}</Badge>
      {who && (
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          {/* ⛔ "decided by", not "approved by": the same column carries the
              actor of a REJECTION, and it is read together with the state. */}
          by {who}
          {when ? ` · ${when}` : ''}
        </span>
      )}
    </span>
  );
}

function RequestRow({ request, canWrite, canApprove = false, viewerName = null }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  const [rejecting, setRejecting] = useState(false);
  const [rejectReason, setRejectReason] = useState('');

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

  async function act(action, extra) {
    if (busy) return;
    setBusy(action);
    setError(null);
    try {
      const res = await fetch(`/api/rule-change-requests/${request.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, ...(extra || {}) }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) throw new Error(data.error || `Could not ${action} the request`);
      setDetail(null);
      setRejecting(false);
      setRejectReason('');
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
  const notSupported = Number(request.not_supported_count || 0);
  const requestType = request.request_type || 'rule_deletion';
  const isDeletion = requestType === 'rule_deletion';
  const approvalState = request.approval_state || 'not_required';
  // ⛔ ONE DEFINITION, imported. Non-null means the API would refuse a submit,
  // so the button is disabled carrying this exact sentence — the UI is EQUAL to
  // the route, never stricter than it.
  const blocked = submissionBlock(approvalState);
  // ⛔ SELF-APPROVAL IS REFUSED SERVER-SIDE AND THE CONTROL SAYS SO RATHER THAN
  // VANISHING. A hidden button over a route that would have accepted the call
  // reads as a broken product; this route would REFUSE, so stating the refusal
  // is equal to it and tells the requester what to do instead (find another
  // administrator). An unknown viewer identity is treated as self, because the
  // engine refuses when it cannot tell the two apart.
  const ownRequest =
    !viewerName
    || !request.created_by
    || String(viewerName).toLowerCase() === String(request.created_by).toLowerCase();
  const canDecide = canApprove && approvalState === 'pending';

  // A submitted DELETION request whose items are ALL unmeasured is not "in
  // progress" and not "failed" — no ruleset has been collected since it was
  // submitted, so there is nothing to conclude. Said in words here rather than
  // left for the reader to infer from three zeroes.
  //
  // ⛔ DELETION ONLY. On a modification request this sentence would blame our
  // COLLECTION for a gap that is really our CAPABILITY — the request is not
  // waiting on a ruleset pull, and never will be.
  const nothingMeasurable =
    isDeletion && request.status === 'submitted' && items > 0 && removed === 0 && stillPresent === 0;

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
        <Badge color="muted" title={`Request type: ${requestType}`}>
          {REQUEST_TYPE_LABEL[requestType] || requestType}
        </Badge>
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          {items} item{items === 1 ? '' : 's'}
          {removed > 0 ? ` · ${removed} removed` : ''}
          {stillPresent > 0 ? ` · ${stillPresent} still present` : ''}
        </span>
        {unverifiable > 0 && (
          <NotMeasured reason={UNVERIFIABLE_REASON} text={`${unverifiable} not verifiable yet`} />
        )}
        {/* ⛔ Its own chip with its own wording, never added to the
            "not verifiable yet" count beside it. */}
        {notSupported > 0 && (
          <CannotVerify text={`${notSupported} SecVault cannot verify`} />
        )}
        <span style={{ flex: 1 }} />
        {canDecide && (
          <>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => act('approve')}
              disabled={Boolean(busy) || ownRequest}
              title={
                ownRequest
                  ? 'You raised this request, so you cannot approve it. Approval has to come from '
                    + 'another administrator.'
                  : 'Authorise this change. It does NOT record that the change was made.'
              }
              style={{ fontSize: 'var(--text-xs)', padding: '4px 10px' }}
            >
              {busy === 'approve' ? 'Approving…' : 'Approve'}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setRejecting((v) => !v)}
              disabled={Boolean(busy)}
              style={{ fontSize: 'var(--text-xs)', padding: '4px 10px' }}
            >
              Reject
            </button>
          </>
        )}
        {canWrite && request.status === 'draft' && (
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => act('submit')}
            // ⛔ DISABLED WITH THE REASON, not hidden. The route refuses this
            // call while approval is outstanding, so the control states the
            // same refusal instead of disappearing.
            disabled={Boolean(busy) || Boolean(blocked)}
            title={blocked || 'Hand this request over.'}
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

      <div style={{ marginTop: 'var(--s2)' }}>
        <ApprovalLine request={request} />
      </div>

      {/* ⛔ The blocked reason is on screen, not only on the disabled button's
          tooltip — a tooltip is unreachable by touch and invisible to anyone
          who does not hover the one control they cannot use. */}
      {request.status === 'draft' && blocked && (
        <div
          style={{ marginTop: 'var(--s2)', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}
        >
          {blocked}
        </div>
      )}

      {/* ⛔ A REJECTION NEEDS A REASON AND THE API REFUSES WITHOUT ONE, so the
          control collects one rather than firing a request that will fail. The
          requester's only alternative is to guess why they were refused. */}
      {rejecting && canDecide && (
        <div
          style={{
            marginTop: 'var(--s2)',
            display: 'flex',
            flexWrap: 'wrap',
            gap: 'var(--s2)',
            alignItems: 'flex-end',
          }}
        >
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: '1 1 320px' }}>
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
              Why are you rejecting this? The requester sees this.
            </span>
            <input
              type="text"
              className="input"
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              disabled={Boolean(busy)}
            />
          </label>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => act('reject', { reason: rejectReason.trim() })}
            disabled={Boolean(busy) || rejectReason.trim() === ''}
            style={{ fontSize: 'var(--text-xs)', padding: '4px 10px' }}
          >
            {busy === 'reject' ? 'Rejecting…' : 'Confirm rejection'}
          </button>
        </div>
      )}

      {/* Shown ALONGSIDE the note, never instead of it — the same rule the
          abandon reason follows. The note is what was asked for; this is why it
          was refused, and a request may well be re-raised on the strength of
          it. */}
      {request.rejected_reason && (
        <div
          style={{ marginTop: 'var(--s2)', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}
        >
          <strong style={{ color: 'var(--text-primary)' }}>Rejected because:</strong>{' '}
          {request.rejected_reason}
        </div>
      )}

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
                {/* ⛔ The header and the body are gated the SAME number of
                    times. A column present in the <thead> and absent from the
                    <tbody> shifts every later cell one column left — a table
                    that is wrong rather than narrow. */}
                <colgroup>
                  <col style={{ width: isDeletion ? '38%' : '24%' }} />
                  <col style={{ width: '16%' }} />
                  {!isDeletion && <col style={{ width: '30%' }} />}
                  <col style={{ width: '16%' }} />
                  <col style={{ width: isDeletion ? '30%' : '14%' }} />
                </colgroup>
                <thead>
                  <tr>
                    <th>{isDeletion ? 'Rule' : 'Subject'}</th>
                    <th>{isDeletion ? 'Finding' : 'Raised as'}</th>
                    {!isDeletion && <th>Requested change</th>}
                    <th>
                      {isDeletion ? 'Hits when proposed' : 'Hits when raised'}
                    </th>
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
                      {!isDeletion && (
                        <td style={{ color: 'var(--text-secondary)' }}>
                          {it.requested_change || (
                            /* ⛔ Not a blank cell. An item with no instruction
                               cannot be acted on, and an empty cell reads as
                               "nothing to do". */
                            <NotMeasured reason="No requested change was recorded on this item." />
                          )}
                        </td>
                      )}
                      <td>
                        {/* On a DELETION every item has a MEASURED hit count by
                            construction — createRequest refuses the others — so
                            a null there means something bypassed the engine. On
                            a non-deletion a null is NORMAL (a rule that does
                            not exist yet has no counter). Either way it renders
                            as unmeasured, never as 0. */}
                        {it.hit_count_at_request === null ||
                        it.hit_count_at_request === undefined ? (
                          <NotMeasured
                            reason={
                              isDeletion
                                ? 'No hit count was recorded when this rule was proposed.'
                                : 'No hit count applies: SecVault has no counter for this subject, '
                                  + 'and none is needed — nothing here rests on one.'
                            }
                          />
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
export default function RuleChangeRequests({
  requests,
  canWrite,
  canApprove = false,
  viewerName = null,
  loadError = null,
}) {
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
        rows.map((r) => (
          <RequestRow
            key={r.id}
            request={r}
            canWrite={canWrite}
            canApprove={canApprove}
            viewerName={viewerName}
          />
        ))
      )}
    </div>
  );
}
