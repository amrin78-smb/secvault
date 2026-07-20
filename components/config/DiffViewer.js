'use client';

import { useState } from 'react';
import LoadingSpinner from '../ui/LoadingSpinner';
import Table from '../ui/Table';
import Badge from '../ui/Badge';

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

// Same idea, applied to plain string values. Unlike paths (bounded by
// truncatePathForDisplay in configDiff.js) and objects/arrays (bounded by
// CollapsibleValue above), a primitive string value had no size bound at
// all — a large free-text field, or a corrupted blob landing as a VALUE
// instead of a KEY, would dump inline unbounded. Mirrors LARGE_VALUE_THRESHOLD.
const LARGE_STRING_THRESHOLD = 400;

function isLargeString(value) {
  return typeof value === 'string' && value.length > LARGE_STRING_THRESHOLD;
}

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

// Same collapse treatment as CollapsibleValue, for a large plain-string
// value — kept as a separate component rather than folding into
// CollapsibleValue because a raw string should never be routed through
// JSON.stringify/summarizeValue (which assumes an object/array shape).
function CollapsibleString({ value }) {
  const [expanded, setExpanded] = useState(false);
  const preview = value.slice(0, 200);

  return (
    <span style={{ display: 'block', marginTop: 4 }}>
      <span style={{ color: 'var(--text-muted)' }}>{preview}… ({value.length} chars)</span>
      <button type="button" onClick={() => setExpanded((e) => !e)} style={TOGGLE_BUTTON_STYLE}>
        {expanded ? '▾ Hide details' : '▸ Show details'}
      </button>
      {expanded && <pre style={PRE_STYLE}>{value}</pre>}
    </span>
  );
}

// True when a value needs its own block-level rendering (CollapsibleValue for
// objects/arrays, CollapsibleString for large strings) rather than inline
// formatValue() text.
function needsBlockRender(value) {
  return isExpandableValue(value) || isLargeString(value);
}

// Renders whichever block-level treatment applies. Caller must already know
// needsBlockRender(value) is true.
function renderBlockValue(value) {
  return isExpandableValue(value) ? <CollapsibleValue value={value} /> : <CollapsibleString value={value} />;
}

// One "path: value" row for an Added/Removed entry. Value is inline for
// small primitives, block-rendered (and possibly collapsible) below the path
// for objects/arrays and large strings.
function DiffValueRow({ path, value }) {
  const block = needsBlockRender(value);
  return (
    <span style={{ display: 'block' }}>
      <span style={PATH_LABEL_STYLE}>{path}{block ? ':' : ''}</span>
      {block ? renderBlockValue(value) : <span>: {formatValue(value)}</span>}
    </span>
  );
}

// One "− old" / "+ new" line within a Modified row.
function LabeledValue({ label, labelColor, value }) {
  const block = needsBlockRender(value);
  return (
    <span style={{ display: 'block' }}>
      <span style={{ color: labelColor, fontWeight: 600 }}>{label}{block ? ':' : ''}</span>
      {block ? renderBlockValue(value) : <span> {formatValue(value)}</span>}
    </span>
  );
}

// A full Modified row: simple "old → new" inline when both sides are small
// primitives, or a stacked "− old" / "+ new" comparison when either side is
// an object/array or a large string — stacked (not side-by-side) so both are
// fully readable without a cramped two-column squeeze, which matters for a
// tool operators use to actually compare configs, not just glance at them.
function DiffModifiedRow({ path, oldValue, newValue }) {
  const anyBlock = needsBlockRender(oldValue) || needsBlockRender(newValue);

  if (!anyBlock) {
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

// ---------------------------------------------------------------------------
// Rule Changes table (classifyDiff()'s `ruleChanges`) — the headline view,
// matching ManageEngine Firewall Analyzer's own rule-change table (rule name /
// field / old → new) instead of a raw path:value dump. Defined at module top
// level per CLAUDE.md.
// ---------------------------------------------------------------------------

const CHANGE_BADGE_COLOR = { added: 'success', removed: 'danger', modified: 'warning' };
const CHANGE_BADGE_LABEL = { added: 'Added', removed: 'Removed', modified: 'Modified' };

function RuleChangeBadge({ changeType }) {
  return <Badge color={CHANGE_BADGE_COLOR[changeType] || 'muted'}>{CHANGE_BADGE_LABEL[changeType] || changeType}</Badge>;
}

// Value cell for one rule-level change — adapts DiffModifiedRow's own
// old/new logic (inline "old → new" for small primitives, stacked "− old"/
// "+ new" for objects/arrays or large strings) to a table cell instead of a
// <li> block, and reuses the same block-render helpers so an object-valued
// or very long string field doesn't dump raw text inline.
function RuleChangeValueCell({ change }) {
  if (change.changeType === 'modified') {
    const anyBlock = needsBlockRender(change.old) || needsBlockRender(change.new);
    if (!anyBlock) {
      return <span>{formatValue(change.old)} → {formatValue(change.new)}</span>;
    }
    return (
      <span style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <LabeledValue label="− old" labelColor="var(--red)" value={change.old} />
        <LabeledValue label="+ new" labelColor="var(--green)" value={change.new} />
      </span>
    );
  }
  // added / removed
  return needsBlockRender(change.value) ? renderBlockValue(change.value) : <span>{formatValue(change.value)}</span>;
}

// Rule name is repeated on every field-level change row rather than
// rowSpan'd across a group — this app doesn't use rowSpan anywhere else
// (checked before deciding), and repeating a short rule name per row is
// simpler and avoids the layout/border edge cases rowSpan introduces inside
// this app's <Table> wrapper.
function RuleChangesTable({ ruleChanges }) {
  if (!Array.isArray(ruleChanges) || ruleChanges.length === 0) return null;

  return (
    <div>
      <div
        style={{
          marginBottom: 4,
          fontSize: 'var(--text-xs)',
          fontWeight: 600,
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          color: 'var(--text-muted)',
        }}
      >
        Rule Changes
      </div>
      <Table>
        <colgroup>
          <col style={{ width: '22%' }} />
          <col style={{ width: '12%' }} />
          <col style={{ width: '20%' }} />
          <col style={{ width: '46%' }} />
        </colgroup>
        <thead>
          <tr>
            <th>Rule Name</th>
            <th>Change</th>
            <th>Field</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {ruleChanges.flatMap((rc) =>
            rc.changes.map((change, i) => (
              <tr key={`${rc.ruleName}-${i}`}>
                <td className="mono" title={rc.ruleName} style={{ wordBreak: 'break-word' }}>
                  {rc.ruleName}
                </td>
                <td>
                  <RuleChangeBadge changeType={change.changeType} />
                </td>
                <td className="mono" title={change.field || '(entire rule)'} style={{ wordBreak: 'break-word' }}>
                  {change.field || '(entire rule)'}
                </td>
                <td className="mono" style={{ wordBreak: 'break-word' }}>
                  <RuleChangeValueCell change={change} />
                </td>
              </tr>
            ))
          )}
        </tbody>
      </Table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Collapsed section groups (classifyDiff()'s `sections`) — fixes the original
// bug report (a 500-entry address-object diff rendering as 500 stacked raw
// rows): one summary line per section, collapsed by default, reusing the
// exact same DiffSection/DiffValueRow/DiffModifiedRow row renderers the old
// flat Added/Removed/Modified list already used, just now scoped per section
// instead of spanning the whole diff.
// ---------------------------------------------------------------------------

function sectionSummaryLine(section) {
  const parts = [];
  if (section.addedCount > 0) parts.push(`${section.addedCount} added`);
  if (section.removedCount > 0) parts.push(`${section.removedCount} removed`);
  if (section.modifiedCount > 0) parts.push(`${section.modifiedCount} modified`);
  return parts.join(', ');
}

function SectionGroup({ section }) {
  const [expanded, setExpanded] = useState(false);
  const entries = Array.isArray(section.entries) ? section.entries : [];
  const addedEntries = entries.filter((e) => e.changeType === 'added');
  const removedEntries = entries.filter((e) => e.changeType === 'removed');
  const modifiedEntries = entries.filter((e) => e.changeType === 'modified');

  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-sm)',
        padding: '8px 12px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 4 }}>
        <span>
          <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{section.label}</span>
          <span style={{ color: 'var(--text-muted)' }}> — {sectionSummaryLine(section)}</span>
        </span>
        <button type="button" onClick={() => setExpanded((e) => !e)} style={{ ...TOGGLE_BUTTON_STYLE, marginLeft: 0 }}>
          {expanded ? '▾ Hide details' : '▸ Show details'}
        </button>
      </div>
      {expanded && (
        <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <DiffSection title="Added" tone="success" rows={addedEntries} renderRow={renderAddedRow} />
          <DiffSection title="Removed" tone="danger" rows={removedEntries} renderRow={renderRemovedRow} />
          <DiffSection title="Modified" tone="warning" rows={modifiedEntries} renderRow={renderModifiedRow} />
        </div>
      )}
    </div>
  );
}

export default function DiffViewer({ deviceId, diffId }) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [diff, setDiff] = useState(null); // { added, removed, modified } — raw, kept for backward compat
  const [classified, setClassified] = useState(null); // { ruleChanges, sections } — see lib/engines/configDiff.js classifyDiff()
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
      setClassified(row.classified || { ruleChanges: [], sections: [] });
    } catch (err) {
      setError(err.message || 'Failed to load diff');
    } finally {
      setLoading(false);
    }
  }

  const ruleChanges = classified?.ruleChanges || [];
  const sections = classified?.sections || [];
  const isEmpty = classified && ruleChanges.length === 0 && sections.length === 0;

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
          {diff && classified && !loading && !error && (
            <>
              <RuleChangesTable ruleChanges={ruleChanges} />
              {sections.map((section, i) => (
                <SectionGroup key={`${section.label}-${i}`} section={section} />
              ))}
              {isEmpty && <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-muted)' }}>This diff contains no entries.</p>}
            </>
          )}
        </div>
      )}
    </div>
  );
}
