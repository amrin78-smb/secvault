'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Card, { CardBody, CardHeader, CardTitle } from '../ui/Card';
import LoadingSpinner from '../ui/LoadingSpinner';

// Compliance exceptions for one device — the recorded decision that a FAILING
// check is accepted here, with a compensating control, an owner and an expiry.
//
// ⛔ THE SCORE ABOVE THIS PANEL IS COMPUTED AS IF NONE OF THIS EXISTED, AND
// THIS PANEL SAYS SO IN WORDS. A failing check with an accepted exception is
// still a fail: the firewall is still configured that way. The panel therefore
// reports COUNTS beside the score and deliberately NOT a second percentage —
// two compliance percentages on one page, differing by a set of hand-typed
// labels, is exactly the artefact that turns a measurement into a number people
// manage. See lib/engines/complianceExceptions.js's header.
//
// ⛔ FOUR STATES, FOUR TREATMENTS, and none of them may look like any other or
// like the absence of an exception:
//
//   accepted  green tint, expiry date + days remaining
//   expiring  amber tint, "Expires in N days" — its own VISIBLE state, so
//             nobody is surprised by a lapse (30-day window, justified in the
//             engine)
//   expired   RED tint, "Lapsed" — a failing check with nothing covering it any
//             more is a real, actionable fact, not a quiet grey footnote
//   revoked   muted, in a separate History block, naming who withdrew it
//
// ⛔ AND A FIFTH, HUELESS TREATMENT for what could not be measured: an expiry
// that could not be read, and an exception sitting over a check that is not
// being evaluated on this device at all. Neither is good news or bad news, so
// neither gets a hue — --unmeasured, per the design system's "NOT MEASURED is a
// first-class visual state with NO HUE" rule.
//
// ⛔ Every sub-component is defined at MODULE TOP LEVEL. A component defined
// inside another remounts on every keystroke and loses input focus, which on a
// panel whose whole job is a form would be immediately fatal.

const TONE_STYLE = {
  success: { bg: 'var(--tint-success)', fg: 'var(--tint-success-fg)' },
  warning: { bg: 'var(--tint-warn)', fg: 'var(--tint-warn-fg)' },
  danger: { bg: 'var(--tint-danger)', fg: 'var(--tint-danger-fg)' },
  muted: { bg: 'var(--surface-subtle)', fg: 'var(--text-muted)' },
};

const BADGE_COLOR = {
  success: 'success',
  warning: 'warning',
  danger: 'danger',
  muted: 'muted',
};

function toneStyle(tone) {
  return TONE_STYLE[tone] || TONE_STYLE.muted;
}

function formatDay(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 10);
}

// The one-line summary of an exception's own timing. Separate from the state
// badge because the badge says WHAT and this says WHEN.
function timingText(item) {
  if (item.state === 'revoked') {
    const on = formatDay(item.revokedAt);
    return `Revoked${item.revokedBy ? ` by ${item.revokedBy}` : ''}${on ? ` on ${on}` : ''}.`;
  }
  if (item.expiryUnreadable) {
    // ⛔ Never "expires today" and never a 0. We do not know when it expires,
    // and the honest sentence says so.
    return 'Expiry could not be read, so this is not counted as accepted.';
  }
  const day = formatDay(item.expiresAt);
  const n = item.daysRemaining;
  if (item.state === 'expired') {
    const ago = typeof n === 'number' ? Math.abs(n) : null;
    return `Lapsed${day ? ` on ${day}` : ''}${ago !== null ? `, ${ago} day${ago === 1 ? '' : 's'} ago` : ''}.`;
  }
  if (typeof n === 'number') {
    return `Expires ${day} — ${n} day${n === 1 ? '' : 's'} remaining.`;
  }
  return `Expires ${day}.`;
}

// ── hueless chip for the "we could not measure this" cases ─────────────────
function UnmeasuredChip({ text, reason }) {
  return (
    <span
      title={reason}
      aria-label={reason ? `Not measured: ${reason}` : undefined}
      style={{
        display: 'inline-block',
        padding: '2px var(--s2)',
        borderRadius: 'var(--radius-pill)',
        border: '1px dashed var(--unmeasured)',
        color: 'var(--unmeasured)',
        fontSize: 'var(--text-xs)',
        background: 'transparent',
      }}
    >
      {text}
    </span>
  );
}

function StateChip({ item }) {
  // ⛔ An unreadable expiry is shown HUELESS even though the state fell closed
  // to `expired`. Painting it red would claim we measured a lapse; painting it
  // green would be the failed-read-as-a-fact bug. It is an absence of news.
  if (item.expiryUnreadable) {
    return (
      <UnmeasuredChip
        text="Expiry unreadable"
        reason={
          'The stored expiry could not be read as a date, so this exception is not '
          + 'counted as accepted. Revoke it and record a replacement.'
        }
      />
    );
  }
  return <Badge color={BADGE_COLOR[item.tone] || 'muted'}>{item.label}</Badge>;
}

// Notes about COVERAGE — what this exception does and does not tell you. These
// are the honest caveats, not decoration: an exception over a check SecVault is
// not evaluating on this device is not evidence of anything.
function CoverageNotes({ item }) {
  const notes = [];
  if (item.state !== 'revoked' && item.checkNotEvaluated) {
    notes.push({
      hueless: true,
      text: 'This check is not currently being evaluated on this device',
      reason:
        'There is no compliance result for this check on this device — it has not been '
        + 'audited, or the check is no longer in the check library. The exception is not '
        + 'evidence that the check passes.',
    });
  }
  if (item.state !== 'revoked' && item.checkNoLongerFailing) {
    notes.push({
      hueless: false,
      text: `This check now reports "${item.currentStatus}" — the exception is no longer needed`,
      reason: null,
    });
  }
  if (notes.length === 0) return null;
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--s2)', marginTop: 'var(--s2)' }}>
      {notes.map((n) =>
        n.hueless ? (
          <UnmeasuredChip key={n.text} text={n.text} reason={n.reason} />
        ) : (
          <span
            key={n.text}
            style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}
          >
            {n.text}
          </span>
        )
      )}
    </div>
  );
}

function ExceptionItem({ item, canWrite, busyId, onRevoke }) {
  const tone = toneStyle(item.tone);
  const revoking = busyId === item.id;
  return (
    <li
      style={{
        listStyle: 'none',
        border: '1px solid var(--border)',
        borderLeft: `3px solid ${item.expiryUnreadable ? 'var(--unmeasured)' : tone.fg}`,
        borderRadius: 'var(--radius)',
        background: 'var(--bg-card)',
        padding: 'var(--s3)',
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--s2)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--s2)', flexWrap: 'wrap' }}>
        <StateChip item={item} />
        <div style={{ flex: '1 1 240px', minWidth: 0 }}>
          <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }}>
            {item.checkName || item.checkSlug}
          </div>
          {/* The slug is the durable identity and stays visible — the name
              comes from the seed library and can be renamed under it. */}
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-xs)',
              color: 'var(--text-muted)',
            }}
          >
            {item.checkSlug}
          </div>
        </div>
        {canWrite && item.state !== 'revoked' && (
          <Button
            type="button"
            variant="secondary"
            onClick={() => onRevoke(item.id)}
            disabled={revoking}
          >
            {revoking && <LoadingSpinner size={12} />}
            {revoking ? 'Revoking…' : 'Revoke'}
          </Button>
        )}
      </div>

      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
        {timingText(item)}
      </div>

      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>{item.reason}</div>

      {item.compensatingControl ? (
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
          <strong>Compensating control:</strong> {item.compensatingControl}
        </div>
      ) : (
        <UnmeasuredChip
          text="No compensating control recorded"
          reason="Nobody stated what mitigates this failure. The exception still stands, but there is no recorded control to verify."
        />
      )}

      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
        Accepted by {item.acceptedBy}
        {formatDay(item.acceptedAt) ? ` on ${formatDay(item.acceptedAt)}` : ''}
      </div>

      <CoverageNotes item={item} />
    </li>
  );
}

// ── the summary line ───────────────────────────────────────────────────────
function SummaryLine({ summary, expiringWindowDays }) {
  const parts = [];
  if (summary.failingChecks === null) {
    // ⛔ null, not 0 — "we were not told how many checks are failing" is not
    // "no checks are failing".
    parts.push(<UnmeasuredChip key="unk" text="Failing check count unavailable" reason="This panel was rendered without the device's finding counts." />);
  } else {
    parts.push(
      <span key="fail">
        <strong>{summary.failingChecks}</strong> failing check
        {summary.failingChecks === 1 ? '' : 's'}
      </span>
    );
    parts.push(
      <span key="cov">
        <strong>{summary.covering}</strong> with a live exception
      </span>
    );
    parts.push(
      <span key="un">
        <strong>{summary.unaccepted}</strong> with none
      </span>
    );
  }
  if (summary.expiring > 0) {
    parts.push(
      <span key="exp" style={{ color: 'var(--tint-warn-fg)' }}>
        <strong>{summary.expiring}</strong> expiring within {expiringWindowDays} days
      </span>
    );
  }
  if (summary.expired > 0) {
    parts.push(
      <span key="lap" style={{ color: 'var(--tint-danger-fg)' }}>
        <strong>{summary.expired}</strong> lapsed
      </span>
    );
  }
  return (
    <div
      style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: 'var(--s3)',
        fontSize: 'var(--text-sm)',
        color: 'var(--text-primary)',
      }}
    >
      {parts}
    </div>
  );
}

function defaultExpiry() {
  // 90 days out — a sensible default for a review cycle, well clear of the
  // 30-day `expiring` window so a newly recorded exception does not open in a
  // warning state.
  const d = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
  return d.toISOString().slice(0, 10);
}

function tomorrow() {
  return new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
}

const FIELD_STYLE = {
  width: '100%',
  padding: 'var(--s2)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)',
  background: 'var(--bg-card)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-sm)',
  fontFamily: 'var(--font-sans)',
};

const LABEL_STYLE = {
  display: 'block',
  fontSize: 'var(--text-xs)',
  fontWeight: 600,
  color: 'var(--text-secondary)',
  marginBottom: 'var(--s1)',
};

/**
 * @param {object[]} exceptions       descriptors from lib/engines/complianceExceptions.js
 * @param {object[]} availableChecks  failing checks with no live exception yet
 * @param {object}   summary          counts (never a percentage)
 * @param {boolean}  canWrite         session holds OPERATE
 */
export default function ExceptionsPanel({
  deviceId,
  exceptions = [],
  availableChecks = [],
  summary,
  expiringWindowDays = 30,
  canWrite = false,
}) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [checkSlug, setCheckSlug] = useState('');
  const [reason, setReason] = useState('');
  const [control, setControl] = useState('');
  const [expiresAt, setExpiresAt] = useState(defaultExpiry);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState(null);
  const [error, setError] = useState(null);

  const live = exceptions.filter((e) => e.state !== 'revoked');
  const history = exceptions.filter((e) => e.state === 'revoked');

  async function handleCreate(event) {
    event.preventDefault();
    if (saving) return;
    setSaving(true);
    setError(null);
    try {
      const res = await fetch(`/api/compliance/${deviceId}/exceptions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // ⛔ No acceptedBy field. The server takes it from the session; sending
        // one would be ignored, and offering one in the UI would imply it could
        // be chosen.
        body: JSON.stringify({ checkSlug, reason, compensatingControl: control, expiresAt }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) throw new Error(data.error || 'Could not record the exception');
      setCheckSlug('');
      setReason('');
      setControl('');
      setExpiresAt(defaultExpiry());
      setOpen(false);
      router.refresh();
    } catch (err) {
      setError(err.message || 'Could not record the exception');
    } finally {
      setSaving(false);
    }
  }

  async function handleRevoke(id) {
    if (busyId) return;
    setBusyId(id);
    setError(null);
    try {
      const res = await fetch(`/api/compliance/${deviceId}/exceptions/${id}`, { method: 'DELETE' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) throw new Error(data.error || 'Could not revoke the exception');
      router.refresh();
    } catch (err) {
      setError(err.message || 'Could not revoke the exception');
    } finally {
      setBusyId(null);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Accepted risk (compliance exceptions)</CardTitle>
        {canWrite && availableChecks.length > 0 && (
          <Button type="button" variant="secondary" onClick={() => setOpen((v) => !v)}>
            {open ? 'Cancel' : 'Record an exception'}
          </Button>
        )}
      </CardHeader>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
          {/* ⛔ THE CONTRACT, STATED ON SCREEN. Without this sentence a reader
              can reasonably assume the accepted count has been netted off the
              score above, and the whole point is that it has not. */}
          <p
            style={{
              margin: 0,
              fontSize: 'var(--text-xs)',
              color: 'var(--text-secondary)',
              background: 'var(--surface-subtle)',
              border: '1px solid var(--border-light)',
              borderRadius: 'var(--radius-sm)',
              padding: 'var(--s2) var(--s3)',
            }}
          >
            An exception records that a failure is accepted, and why. It does not change the
            check&apos;s result and it does not change the compliance score on this page — that
            score is computed as if none of these existed, because the firewall is still
            configured this way. Expiry is checked every time this page is read; a lapsed
            exception stops counting as accepted immediately.
          </p>

          {summary && <SummaryLine summary={summary} expiringWindowDays={expiringWindowDays} />}

          {error && (
            <div
              role="alert"
              style={{
                fontSize: 'var(--text-sm)',
                color: 'var(--tint-danger-fg)',
                background: 'var(--tint-danger)',
                border: '1px solid var(--tint-danger-fg)',
                borderRadius: 'var(--radius-sm)',
                padding: 'var(--s2) var(--s3)',
              }}
            >
              <strong>Nothing was changed.</strong> {error}
            </div>
          )}

          {open && canWrite && (
            <form
              onSubmit={handleCreate}
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--s3)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                padding: 'var(--s3)',
                background: 'var(--surface-subtle)',
              }}
            >
              <div>
                <label style={LABEL_STYLE} htmlFor="ce-check">
                  Failing check
                </label>
                {/* ⛔ Only checks that are ACTUALLY FAILING and have no live
                    exception are offered. The server re-checks this anyway —
                    the list is the convenience, the server is the guarantee. */}
                <select
                  id="ce-check"
                  required
                  value={checkSlug}
                  onChange={(e) => setCheckSlug(e.target.value)}
                  style={FIELD_STYLE}
                >
                  <option value="">Select a failing check…</option>
                  {availableChecks.map((c) => (
                    <option key={c.checkSlug} value={c.checkSlug}>
                      {c.checkName || c.checkSlug}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label style={LABEL_STYLE} htmlFor="ce-reason">
                  Why is this accepted? (required)
                </label>
                <textarea
                  id="ce-reason"
                  required
                  rows={3}
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  style={{ ...FIELD_STYLE, resize: 'vertical' }}
                />
              </div>

              <div>
                <label style={LABEL_STYLE} htmlFor="ce-control">
                  Compensating control (optional)
                </label>
                <textarea
                  id="ce-control"
                  rows={2}
                  value={control}
                  onChange={(e) => setControl(e.target.value)}
                  style={{ ...FIELD_STYLE, resize: 'vertical' }}
                />
              </div>

              <div>
                <label style={LABEL_STYLE} htmlFor="ce-expiry">
                  Expires (required)
                </label>
                <input
                  id="ce-expiry"
                  type="date"
                  required
                  min={tomorrow()}
                  value={expiresAt}
                  onChange={(e) => setExpiresAt(e.target.value)}
                  style={{ ...FIELD_STYLE, maxWidth: 220 }}
                />
                <div
                  style={{
                    fontSize: 'var(--text-xs)',
                    color: 'var(--text-secondary)',
                    marginTop: 'var(--s1)',
                  }}
                >
                  An expiry is mandatory. An exception with no end date is a permanent silent
                  pass on a check that is still failing.
                </div>
              </div>

              <div>
                <Button type="submit" variant="primary" disabled={saving}>
                  {saving && <LoadingSpinner size={14} />}
                  {saving ? 'Recording…' : 'Record exception'}
                </Button>
              </div>
            </form>
          )}

          {live.length === 0 ? (
            <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
              No exceptions recorded for this firewall. Every failing check below is an open
              failure with nothing accepted against it.
            </p>
          ) : (
            <ul style={{ margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
              {live.map((item) => (
                <ExceptionItem
                  key={item.id}
                  item={item}
                  canWrite={canWrite}
                  busyId={busyId}
                  onRevoke={handleRevoke}
                />
              ))}
            </ul>
          )}

          {history.length > 0 && (
            <details>
              <summary
                style={{
                  cursor: 'pointer',
                  fontSize: 'var(--text-xs)',
                  fontWeight: 600,
                  color: 'var(--text-secondary)',
                }}
              >
                Revoked history ({history.length})
              </summary>
              {/* ⛔ Kept, never deleted. Who accepted what and who later
                  withdrew it is the durable value of this table. */}
              <ul
                style={{
                  margin: 'var(--s2) 0 0',
                  padding: 0,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 'var(--s2)',
                }}
              >
                {history.map((item) => (
                  <ExceptionItem
                    key={item.id}
                    item={item}
                    canWrite={false}
                    busyId={busyId}
                    onRevoke={handleRevoke}
                  />
                ))}
              </ul>
            </details>
          )}
        </div>
      </CardBody>
    </Card>
  );
}
