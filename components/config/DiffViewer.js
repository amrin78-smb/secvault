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

// Objects/arrays get pretty-printed + (for large ones) collapsed behind a
// toggle instead of the old single-line JSON.stringify wall of text.
function isExpandableValue(value) {
  return value !== null && typeof value === 'object';
}

// Above this many characters of pretty-printed JSON, a value renders
// collapsed by default with a "Show details" toggle instead of inline.
const LARGE_VALUE_THRESHOLD = 400;

function summarizeValue(value) {
  if (Array.isArray(value)) {
    const n = value.length;
    return `[${n} item${n === 1 ? '' : 's'}]`;
  }
  const n = Object.keys(value).length;
  return `{${n} key${n === 1 ? '' : 's'}}`;
}

const PATH_LABEL_STYLE = {
  fontWeight: 600,
  color: 'var(--text-primary)',
};

const PRE_STYLE = {
  margin: '4px 0 0',
  padding: '8px 10px',
  background: 'var(--bg-primary)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)',
  fontFamily: 'inherit',
  fontSize: 'inherit',
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-word',
  color: 'var(--text-primary)',
  maxHeight: 320,
  overflow: 'auto',
};

const TOGGLE_BUTTON_STYLE = {
  fontSize: 'var(--text-xs)',
  color: 'var(--primary)',
  background: 'none',
  border: 'none',
  padding: 0,
  marginLeft: 6,
  cursor: 'pointer',
  textDecoration: 'underline',
  fontFamily: 'inherit',
};

// Pretty-prints an object/array value. Small values render inline; large
// ones (per LARGE_VALUE_THRESHOLD) render collapsed behind a toggle so a
// ~4000-character subtree doesn't dump an unreadable wall of text into the
// row list. Top-level function per CLAUDE.md — never nest a component
// definition inside another component's function body.
function CollapsibleValue({ value }) {
  const [expanded, setExpanded] = useState(false);
  const pretty = JSON.stringify(value, null, 2);
  const isLarge = pretty.length > LARGE_VALUE_THRESHOLD;

  if (!isLarge) {
    return <pre style={PRE_STYLE}>{pretty}</pre>;
  }

  return (
    <span style={{ display: 'block', marginTop: 4 }}>
      <span style={{ color: 'var(--text-muted)' }}>{summarizeValue(value)}</span>
      <button type="button" onClick={() => setExpanded((e) => !e)} style={TOGGLE_BUTTON_STYLE}>
        {expanded ? '▾ Hide details' : '▸ Show details'}
      </button>
      {expanded && <pre style={PRE_STYLE}>{pretty}</pre>}
    </span>
  );
}

// One "path: value" row for an Added/Removed entry. Value is inline for
// primitives, pretty-printed (and possibly collapsible) below the path for
// objects/arrays.
function DiffValueRow({ path, value }) {
  const expandable = isExpandableValue(value);
  return (
    <span style={{ display: 'block' }}>
      <span style={PATH_LABEL_STYLE}>{path}{expandable ? ':' : ''}</span>
      {expandable ? <CollapsibleValue value={value} /> : <span>: {formatValue(value)}</span>}
    </span>
  );
}

// One "− old" / "+ new" line within a Modified row.
function LabeledValue({ label, labelColor, value }) {
  const expandable = isExpandableValue(value);
  return (
    <span style={{ display: 'block' }}>
      <span style={{ color: labelColor, fontWeight: 600 }}>{label}{expandable ? ':' : ''}</span>
      {expandable ? <CollapsibleValue value={value} /> : <span> {formatValue(value)}</span>}
    </span>
  );
}

// A full Modified row: simple "old → new" inline when both sides are
// primitives, or a stacked "− old" / "+ new" comparison when either side is
// an object/array — stacked (not side-by-side) so both are fully readable
// without a cramped two-column squeeze, which matters for a tool operators
// use to actually compare configs, not just glance at them.
function DiffModifiedRow({ path, oldValue, newValue }) {
  const anyExpandable = isExpandableValue(oldValue) || isExpandableValue(newValue);

  if (!anyExpandable) {
    return (
      <span style={{ display: 'block' }}>
        <span style={PATH_LABEL_STYLE}>{path}</span>
        <span>: {formatValue(oldValue)} → {formatValue(newValue)}</span>
      </span>
    );
  }

  return (
    <span style={{ display: 'block' }}>
      <span style={PATH_LABEL_STYLE}>{path}</span>
      <span style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 4 }}>
        <LabeledValue label="− old" labelColor="var(--red)" value={oldValue} />
        <LabeledValue label="+ new" labelColor="var(--green)" value={newValue} />
      </span>
    </span>
  );
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
  return <DiffValueRow path={row.path} value={row.value} />;
}

function renderRemovedRow(row) {
  return <DiffValueRow path={row.path} value={row.value} />;
}

function renderModifiedRow(row) {
  return <DiffModifiedRow path={row.path} oldValue={row.old} newValue={row.new} />;
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
