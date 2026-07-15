'use client';

import { useState } from 'react';
import LoadingSpinner from '../ui/LoadingSpinner';

// Renders one grouped section of a config diff (Added / Removed / Modified).
// Defined at module top level (never nested inside DiffViewer — CLAUDE.md rule).
const TONE_CLASSES = {
  success: 'border-l-success bg-success/5 text-success',
  danger: 'border-l-danger bg-danger/5 text-danger',
  warning: 'border-l-warning bg-warning/5 text-warning',
};

function formatValue(value) {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}

function DiffSection({ title, tone, rows, renderRow }) {
  if (!Array.isArray(rows) || rows.length === 0) return null;
  const toneClasses = TONE_CLASSES[tone] || TONE_CLASSES.warning;

  return (
    <div className={`rounded border-l-4 ${toneClasses} px-3 py-2`}>
      <div className="mb-1 text-xs font-semibold uppercase tracking-wide">
        {title} ({rows.length})
      </div>
      <ul className="space-y-0.5 font-mono text-xs text-text-primary">
        {rows.map((row, i) => (
          <li key={i} className="break-all">
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
        className="text-sm text-accent hover:underline"
      >
        {open ? 'Hide diff' : 'View diff'}
      </button>

      {open && (
        <div className="mt-2 space-y-2">
          {loading && <LoadingSpinner size={18} />}
          {error && <p className="text-sm text-danger">{error}</p>}
          {diff && !loading && !error && (
            <>
              <DiffSection title="Added" tone="success" rows={added} renderRow={renderAddedRow} />
              <DiffSection title="Removed" tone="danger" rows={removed} renderRow={renderRemovedRow} />
              <DiffSection title="Modified" tone="warning" rows={modified} renderRow={renderModifiedRow} />
              {isEmpty && <p className="text-sm text-text-muted">This diff contains no entries.</p>}
            </>
          )}
        </div>
      )}
    </div>
  );
}
