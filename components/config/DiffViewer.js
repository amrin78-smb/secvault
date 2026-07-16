'use client';

import { useState } from 'react';
import LoadingSpinner from '../ui/LoadingSpinner';

// Renders one grouped section of a config diff (Added / Removed / Modified).
// Defined at module top level (never nested inside DiffViewer — CLAUDE.md rule).
//
// Visual treatment preserved from the pre-migration version: a colored left
// border + a faint tinted background behind the row list, with the section
// title carrying the stronger "fg" tone color and the row text staying
// neutral. That maps directly onto the suite's tint pair tokens (tinted bg +
// matching fg for the title) plus the solid hue for the left border accent.
const TONE_STYLES = {
  success: { border: 'var(--green)', bg: 'var(--tint-success)', fg: 'var(--tint-success-fg)' },
  danger: { border: 'var(--red)', bg: 'var(--tint-danger)', fg: 'var(--tint-danger-fg)' },
  warning: { border: 'var(--yellow)', bg: 'var(--tint-warn)', fg: 'var(--tint-warn-fg)' },
};

function formatValue(value) {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}

function DiffSection({ title, tone, rows, renderRow }) {
  if (!Array.isArray(rows) || rows.length === 0) return null;
  const toneStyle = TONE_STYLES[tone] || TONE_STYLES.warning;

  return (
    <div
      style={{
        borderLeft: `4px solid ${toneStyle.border}`,
        background: toneStyle.bg,
        borderRadius: 'var(--radius-sm)',
        padding: '8px 12px',
      }}
    >
      <div
        style={{
          marginBottom: 4,
          fontSize: 'var(--text-xs)',
          fontWeight: 600,
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          color: toneStyle.fg,
        }}
      >
        {title} ({rows.length})
      </div>
      <ul
        className="mono"
        style={{ display: 'flex', flexDirection: 'column', gap: 2, color: 'var(--text-primary)', listStyle: 'none' }}
      >
        {rows.map((row, i) => (
          <li key={i} style={{ wordBreak: 'break-all' }}>
            {renderRow(row)}
          </li>
        ))}
      </ul>
    </div>
  );
}

function renderAddedRow(row) {
  return `${row.path}: ${formatValue(row.value)}`;
}

function renderRemovedRow(row) {
  return `${row.path}: ${formatValue(row.value)}`;
}

function renderModifiedRow(row) {
  return `${row.path}: ${formatValue(row.old)} → ${formatValue(row.new)}`;
}

export default function DiffViewer({ deviceId, diffId }) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [diff, setDiff] = useState(null); // { added, removed, modified }
  const [error, setError] = useState(null);

  async function handleToggle() {
    const next = !open;
    setOpen(next);
    if (!next || diff || loading) return;

    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/devices/${deviceId}/diffs/${diffId}`);
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || 'Failed to load diff');
      }
      const row = await res.json();
      setDiff(row.diff || {});
    } catch (err) {
      setError(err.message || 'Failed to load diff');
    } finally {
      setLoading(false);
    }
  }

  const added = diff?.added || [];
  const removed = diff?.removed || [];
  const modified = diff?.modified || [];
  const isEmpty = diff && added.length === 0 && removed.length === 0 && modified.length === 0;

  return (
    <div>
      <button
        type="button"
        onClick={handleToggle}
        style={{
          fontSize: 'var(--text-base)',
          color: 'var(--primary)',
          background: 'none',
          border: 'none',
          padding: 0,
          cursor: 'pointer',
          textDecoration: 'underline',
          fontFamily: 'inherit',
        }}
      >
        {open ? 'Hide diff' : 'View diff'}
      </button>

      {open && (
        <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 8 }}>
          {loading && <LoadingSpinner size={18} />}
          {error && <p style={{ fontSize: 'var(--text-base)', color: 'var(--red)' }}>{error}</p>}
          {diff && !loading && !error && (
            <>
              <DiffSection title="Added" tone="success" rows={added} renderRow={renderAddedRow} />
              <DiffSection title="Removed" tone="danger" rows={removed} renderRow={renderRemovedRow} />
              <DiffSection title="Modified" tone="warning" rows={modified} renderRow={renderModifiedRow} />
              {isEmpty && <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-muted)' }}>This diff contains no entries.</p>}
            </>
          )}
        </div>
      )}
    </div>
  );
}
