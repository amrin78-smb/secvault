'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

// Generic per-row acknowledge control for the fleet /alerts page. Branches on
// item.ack.kind since the three event sources backing this page (rule
// findings, patch_now CVE assessments, config diffs) each have their own ack
// mechanism with a different shape:
//   'finding' -> POST /api/devices/{deviceId}/acknowledgements
//                body { rule_id_vendor, finding_type, status } -- 4-state
//   'cve'     -> POST /api/devices/{deviceId}/cve-acknowledgements
//                body { advisory_id, status } -- 4-state
//   'diff'    -> PUT  /api/devices/{deviceId}/diffs/{diffId}, no body --
//                one-shot acknowledge, not a 4-state status (see
//                app/api/devices/[id]/diffs/[diffId]/route.js -- it only ever
//                sets acknowledged_at/acknowledged_by, there is no "dismiss"
//                or "actioned" concept for a config diff)
// Same optimistic-update / revert-on-error / router.refresh() idiom as
// components/analysis/AcknowledgeControl.js (4-state selects) and
// components/config/AcknowledgeButton.js (diff acknowledge button).
const STATUS_OPTIONS = [
  { value: 'new', label: 'New' },
  { value: 'acknowledged', label: 'Acknowledged' },
  { value: 'dismissed', label: 'Dismissed' },
  { value: 'actioned', label: 'Actioned' },
];

function formatWhen(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleString();
}

export default function AlertAckControl({ item }) {
  const router = useRouter();
  const [status, setStatus] = useState(item.status);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [diffNote, setDiffNote] = useState('');
  const [showDiffNote, setShowDiffNote] = useState(false);

  // Resync local status when the server-authoritative item.status changes for
  // a reason other than this control's own in-flight save -- same reasoning
  // (and same [currentStatus]-only dependency, skipped while saving) as
  // AcknowledgeControl.js's identical effect.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (saving) return;
    setStatus(item.status);
  }, [item.status]);

  async function postFourState(next) {
    const previous = status;
    setStatus(next); // optimistic
    setSaving(true);
    setError(null);
    try {
      const url =
        item.ack.kind === 'finding'
          ? `/api/devices/${item.deviceId}/acknowledgements`
          : `/api/devices/${item.deviceId}/cve-acknowledgements`;
      const body =
        item.ack.kind === 'finding'
          ? { rule_id_vendor: item.ack.rule_id_vendor, finding_type: item.ack.finding_type, status: next }
          : { advisory_id: item.ack.advisory_id, status: next };
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) {
        throw new Error(data.error || 'Failed to save');
      }
      router.refresh();
    } catch (err) {
      setStatus(previous); // revert
      setError(err.message || 'Failed to save');
    } finally {
      setSaving(false);
    }
  }

  async function acknowledgeDiff() {
    if (saving) return;
    setSaving(true);
    setError(null);
    try {
      const res = await fetch(`/api/devices/${item.deviceId}/diffs/${item.ack.diff_id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: diffNote.trim() || undefined }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || 'Failed to acknowledge change');
      }
      router.refresh();
    } catch (err) {
      setError(err.message || 'Failed to acknowledge change');
    } finally {
      setSaving(false);
    }
  }

  if (item.ack.kind === 'diff') {
    if (item.status === 'acknowledged') {
      const who = item.acknowledgedBy ? ` by ${item.acknowledgedBy}` : '';
      const when = formatWhen(item.acknowledgedAt);
      return (
        <span style={{ display: 'inline-flex', flexDirection: 'column', gap: 2 }}>
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
            Acknowledged{who}
            {when ? ` · ${when}` : ''}
          </span>
          {item.acknowledgedNote && (
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontStyle: 'italic' }}>
              &ldquo;{item.acknowledgedNote}&rdquo;
            </span>
          )}
        </span>
      );
    }
    return (
      <span style={{ display: 'inline-flex', flexDirection: 'column', gap: 4, alignItems: 'flex-start' }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={acknowledgeDiff}
            disabled={saving}
            style={{ fontSize: 'var(--text-xs)', padding: '4px 10px' }}
          >
            {saving ? 'Acknowledging…' : 'Acknowledge'}
          </button>
          {!showDiffNote && (
            <button
              type="button"
              onClick={() => setShowDiffNote(true)}
              style={{
                background: 'none',
                border: 'none',
                padding: 0,
                fontSize: 'var(--text-xs)',
                color: 'var(--text-muted)',
                textDecoration: 'underline',
                cursor: 'pointer',
              }}
            >
              + note
            </button>
          )}
          {error && (
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--red)' }} title={error}>
              ⚠
            </span>
          )}
        </span>
        {showDiffNote && (
          <input
            type="text"
            className="input"
            placeholder="Optional reason"
            value={diffNote}
            onChange={(e) => setDiffNote(e.target.value)}
            disabled={saving}
            style={{ fontSize: 'var(--text-xs)', padding: '4px 8px', minWidth: 200 }}
          />
        )}
      </span>
    );
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <select
        value={status}
        onChange={(e) => postFourState(e.target.value)}
        disabled={saving}
        aria-label="Alert status"
        className="select"
        style={{ fontSize: 'var(--text-xs)', padding: '4px 26px 4px 8px', opacity: saving ? 0.5 : 1 }}
      >
        {STATUS_OPTIONS.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
      {error && (
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--red)' }} title={error}>
          ⚠
        </span>
      )}
    </div>
  );
}
