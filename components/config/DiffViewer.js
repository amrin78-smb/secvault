'use client';

import { useState } from 'react';
import LoadingSpinner from '../ui/LoadingSpinner';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import { ruleFromBraceEntry } from '../../lib/adapters/paloalto/sshParser';

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

// ---------------------------------------------------------------------------
// ValueTree — readable nested object/array renderer (replaces raw JSON)
// ---------------------------------------------------------------------------
// A one-sided added/removed (or old→new) value that isn't a FLAT object (which
// gets FlatObjectTable) used to fall back to a pretty-printed JSON.stringify
// wall — e.g. an `application-filter` object `{ "AI-Apps-Filter": { category:
// [...], subcategory: "..." } }` rendered as raw braces. This renders ANY
// value as a labeled, indented key/value tree instead: primitives inline,
// arrays-of-primitives joined, nested objects/arrays indented under their key
// with a thin rule — no JSON braces. Keys are shown VERBATIM (not title-cased)
// because a config key is often a meaningful identifier/name (e.g. the filter
// name "AI-Apps-Filter") that a Title-Case transform would mangle.
const TREE_BOX_STYLE = {
  margin: '4px 0 0',
  padding: '8px 10px',
  background: 'var(--bg-primary)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)',
  color: 'var(--text-primary)',
  maxHeight: 320,
  overflow: 'auto',
};

function isTreePrimitive(v) {
  return v === null || typeof v !== 'object';
}

function joinTreePrimitives(arr) {
  return arr.map((v) => formatValue(v)).join(', ');
}

function ValueTree({ value }) {
  if (Array.isArray(value)) {
    if (value.length === 0) return <span style={{ color: 'var(--text-muted)' }}>(empty)</span>;
    if (value.every(isTreePrimitive)) {
      return <span style={{ wordBreak: 'break-word' }}>{joinTreePrimitives(value)}</span>;
    }
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {value.map((item, i) => (
          <div key={i} style={{ borderLeft: '2px solid var(--border)', paddingLeft: 8 }}>
            <ValueTree value={item} />
          </div>
        ))}
      </div>
    );
  }
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.length === 0) return <span style={{ color: 'var(--text-muted)' }}>(empty)</span>;
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        {keys.map((k) => {
          const v = value[k];
          const inline = isTreePrimitive(v) || (Array.isArray(v) && v.every(isTreePrimitive));
          return (
            <div key={k} style={inline ? { display: 'flex', gap: 6, flexWrap: 'wrap' } : undefined}>
              <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{k}:</span>
              {inline ? (
                <span style={{ color: 'var(--text-secondary)', wordBreak: 'break-word' }}>
                  {Array.isArray(v) ? (v.length === 0 ? '(empty)' : joinTreePrimitives(v)) : formatValue(v)}
                </span>
              ) : (
                <div style={{ marginTop: 2, paddingLeft: 10, borderLeft: '2px solid var(--border)' }}>
                  <ValueTree value={v} />
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  }
  return <span style={{ wordBreak: 'break-word' }}>{formatValue(value)}</span>;
}

// Renders an object/array value as a readable ValueTree (see above). Large
// values (per LARGE_VALUE_THRESHOLD) collapse behind a toggle so a big subtree
// doesn't dominate the row list. Top-level function per CLAUDE.md — never nest
// a component definition inside another component's function body.
function CollapsibleValue({ value }) {
  const [expanded, setExpanded] = useState(false);
  const isLarge = JSON.stringify(value).length > LARGE_VALUE_THRESHOLD;

  if (!isLarge) {
    return (
      <div style={TREE_BOX_STYLE}>
        <ValueTree value={value} />
      </div>
    );
  }

  return (
    <span style={{ display: 'block', marginTop: 4 }}>
      <span style={{ color: 'var(--text-muted)' }}>{summarizeValue(value)}</span>
      <button type="button" onClick={() => setExpanded((e) => !e)} style={TOGGLE_BUTTON_STYLE}>
        {expanded ? '▾ Hide details' : '▸ Show details'}
      </button>
      {expanded && (
        <div style={TREE_BOX_STYLE}>
          <ValueTree value={value} />
        </div>
      )}
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

// ---------------------------------------------------------------------------
// Generic "flat object" Field|Value table — the non-rule counterpart to
// RuleDetailGrid further down this file. Address/service objects, zones,
// VPN records, admin accounts, NAT/PBF rules etc. have no per-domain
// normalizer (unlike PAN-OS security rules, which reuse ruleFromBraceEntry())
// — they're just whatever flat-ish raw dict the vendor's config tree happens
// to contain. Rather than guess at a domain-specific shape, this renders ANY
// object whose own values are all primitives (or arrays of primitives) as a
// clean field/value table; anything with deeper nesting falls back to
// exactly the pre-existing raw-JSON CollapsibleValue rendering above — a
// wrong/guessed table is worse than the reliable raw fallback.
// ---------------------------------------------------------------------------

// Gate deciding table-vs-raw-JSON. Deliberately conservative: ANY nested
// object, or an array containing so much as one object element, returns
// false and the caller keeps the existing raw-JSON treatment. An empty
// object ({}) also returns false — a zero-row table renders as nothing
// visible, which is a worse presentation than CollapsibleValue's existing
// one-line "{0 keys}" summary for that already-rare shape.
function isFlatObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  if (keys.length === 0) return false;
  for (const key of keys) {
    const v = value[key];
    if (v === null || v === undefined) continue;
    const t = typeof v;
    if (t === 'string' || t === 'number' || t === 'boolean') continue;
    if (Array.isArray(v)) {
      const hasNestedObject = v.some((item) => item !== null && typeof item === 'object');
      if (hasNestedObject) return false;
      continue;
    }
    // Nested object (and not an array) — too deep to safely table-ize.
    return false;
  }
  return true;
}

// Small per-file mechanical field-label transform — matches this file's
// existing convention of duplicating a two-line helper locally rather than
// reaching into another module (see joinArray/actionBorderColor's comment
// further down, and configDiff.js's own per-adapter SECRET_KEY_PATTERN
// duplication). Deliberately NOT the same casing as configDiff.js's
// humanizeFieldForSentence() (that one lowercases for mid-sentence use) —
// this wants Title Case for a table column header, matching how the Rules
// page's own columns ("Src Zone", "Dst Zone") read. A straightforward
// mechanical split-and-capitalize; a slightly awkward label (e.g.
// "Accprofile" for a field with no separator) beats a guessed-nicer one.
function titleCaseField(field) {
  return String(field)
    .replace(/[-_]+/g, ' ')
    .split(' ')
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

// Placeholder for an array-valued field with zero elements. Distinct from
// formatValue()'s '—' (which means "this single value is null/undefined") —
// this means "the array itself is empty," a different fact worth reading
// differently at a glance.
const EMPTY_ARRAY_PLACEHOLDER = '(empty)';

// Joins an array of primitives for one table cell. Deliberately NOT
// RuleDetailGrid's joinArray() below (which is tied to that grid's own
// '—'-for-empty convention) — kept separate per this file's small-local-
// duplication convention, and because the two tables' empty-value
// conventions don't need to match each other.
function joinPrimitiveArray(value) {
  if (!Array.isArray(value) || value.length === 0) return EMPTY_ARRAY_PLACEHOLDER;
  return value.map((item) => formatValue(item)).join(', ');
}

// Display string for one field's value inside a flat-object table cell —
// array-of-primitives joins, everything else (already guaranteed a
// primitive by isFlatObject()'s gate) goes through the existing
// formatValue().
function flatFieldDisplay(value) {
  return Array.isArray(value) ? joinPrimitiveArray(value) : formatValue(value);
}

// One added/removed flat-object value, e.g. an address object
// ({"ip-netmask": "10.0.0.5", "description": "web server"}) or a Fortinet
// admin record. Caller must already know isFlatObject(value) is true.
function FlatObjectTable({ value }) {
  const keys = Object.keys(value);
  return (
    <Table>
      <colgroup>
        <col style={{ width: '30%' }} />
        <col style={{ width: '70%' }} />
      </colgroup>
      <tbody>
        {keys.map((key) => {
          const display = flatFieldDisplay(value[key]);
          return (
            <tr key={key}>
              <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{titleCaseField(key)}</td>
              <td title={typeof display === 'string' ? display : undefined} style={{ wordBreak: 'break-word' }}>
                {display}
              </td>
            </tr>
          );
        })}
      </tbody>
    </Table>
  );
}

// Placeholder for a key that exists on only one side of a modified flat
// object — distinct from an empty-string value, which reads instead as
// formatValue('') i.e. a genuinely blank field that WAS present.
const KEY_NOT_PRESENT_PLACEHOLDER = '(not present)';

// A modified flat-object value where BOTH old and new are flat objects, e.g.
// "only the ip-netmask changed, everything else on this address object
// stayed the same" — a three-column Field | Old | New table over the union
// of keys present on either side, changed rows highlighted the same red/
// green convention this file already uses for "− old" / "+ new" lines.
// Caller must already know isFlatObject(oldValue) && isFlatObject(newValue).
function FlatObjectDiffTable({ oldValue, newValue }) {
  const keys = Array.from(new Set([...Object.keys(oldValue), ...Object.keys(newValue)]));
  return (
    <Table>
      <colgroup>
        <col style={{ width: '26%' }} />
        <col style={{ width: '37%' }} />
        <col style={{ width: '37%' }} />
      </colgroup>
      <thead>
        <tr>
          <th>Field</th>
          <th>Old</th>
          <th>New</th>
        </tr>
      </thead>
      <tbody>
        {keys.map((key) => {
          const hasOld = Object.prototype.hasOwnProperty.call(oldValue, key);
          const hasNew = Object.prototype.hasOwnProperty.call(newValue, key);
          const oldDisplay = hasOld ? flatFieldDisplay(oldValue[key]) : KEY_NOT_PRESENT_PLACEHOLDER;
          const newDisplay = hasNew ? flatFieldDisplay(newValue[key]) : KEY_NOT_PRESENT_PLACEHOLDER;
          const changed = !hasOld || !hasNew || oldDisplay !== newDisplay;
          return (
            <tr key={key}>
              <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{titleCaseField(key)}</td>
              <td
                title={typeof oldDisplay === 'string' ? oldDisplay : undefined}
                style={{ wordBreak: 'break-word', color: changed ? 'var(--red)' : undefined }}
              >
                {oldDisplay}
              </td>
              <td
                title={typeof newDisplay === 'string' ? newDisplay : undefined}
                style={{ wordBreak: 'break-word', color: changed ? 'var(--green)' : undefined }}
              >
                {newDisplay}
              </td>
            </tr>
          );
        })}
      </tbody>
    </Table>
  );
}

// One "path: value" row for an Added/Removed entry. Value is inline for
// small primitives, block-rendered (and possibly collapsible) below the path
// for objects/arrays and large strings.
//
// When classifyDiff() recognizes the path shape it supplies
// `friendlyDescription` (e.g. `Local user "satish" was removed`) — that
// renders as the bold primary label instead of the raw path, with the raw
// path moved to a `title` tooltip for transparency/debugging. Same
// hover-for-the-technical-value convention already used in this file by
// RuleChangesTable's `<td title={...}>` cells. When there's no description
// (the overwhelming majority of rows today), this renders byte-for-byte what
// it always has.
function DiffValueRow({ path, value, friendlyDescription }) {
  const block = needsBlockRender(value);
  // isFlatObject() is only ever checked once block is already true (it can
  // only be true for an object/array/large-string value) — a flat object
  // swaps in the Field|Value table in place of the raw-JSON CollapsibleValue,
  // everything else about the block/inline colon logic below is untouched.
  const flatTable = block && isFlatObject(value);
  const hasDescription = typeof friendlyDescription === 'string' && friendlyDescription.length > 0;
  const label = hasDescription ? friendlyDescription : path;
  return (
    <span style={{ display: 'block' }}>
      <span style={PATH_LABEL_STYLE} title={hasDescription ? path : undefined}>
        {label}{block ? ':' : ''}
      </span>
      {block ? (flatTable ? <FlatObjectTable value={value} /> : renderBlockValue(value)) : <span>: {formatValue(value)}</span>}
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
//
// Same friendlyDescription treatment as DiffValueRow above: recognized shape
// swaps the bold label for the plain-English description (raw path moved to
// a `title` tooltip); the old → new values themselves are always shown
// regardless — the description supplements the label, it never hides what
// actually changed.
function DiffModifiedRow({ path, oldValue, newValue, friendlyDescription }) {
  const anyBlock = needsBlockRender(oldValue) || needsBlockRender(newValue);
  // Both sides flat objects (e.g. an address object where only ip-netmask
  // changed) get the three-column Field|Old|New table instead of two stacked
  // raw-JSON blobs. Either side failing the flat-object gate (nested, or a
  // totally different shape/type) keeps exactly the existing stacked
  // LabeledValue rendering below — never guessed at a mismatched pair.
  const bothFlat = isFlatObject(oldValue) && isFlatObject(newValue);
  const hasDescription = typeof friendlyDescription === 'string' && friendlyDescription.length > 0;
  const label = hasDescription ? friendlyDescription : path;
  const labelTitle = hasDescription ? path : undefined;

  if (!anyBlock) {
    return (
      <span style={{ display: 'block' }}>
        <span style={PATH_LABEL_STYLE} title={labelTitle}>{label}</span>
        <span>: {formatValue(oldValue)} → {formatValue(newValue)}</span>
      </span>
    );
  }

  if (bothFlat) {
    return (
      <span style={{ display: 'block' }}>
        <span style={PATH_LABEL_STYLE} title={labelTitle}>{label}</span>
        <span style={{ display: 'block', marginTop: 4 }}>
          <FlatObjectDiffTable oldValue={oldValue} newValue={newValue} />
        </span>
      </span>
    );
  }

  return (
    <span style={{ display: 'block' }}>
      <span style={PATH_LABEL_STYLE} title={labelTitle}>{label}</span>
      <span style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 4 }}>
        <LabeledValue label="− old" labelColor="var(--red)" value={oldValue} />
        <LabeledValue label="+ new" labelColor="var(--green)" value={newValue} />
      </span>
    </span>
  );
}

// A single Added/Removed/Modified list can be huge — a real case is a HISTORICAL
// user-group membership row recorded before the value-based array diff existed,
// which shows one "membership changed: X → Y" line per shifted entry (200+ rows).
// Those old rows can't be re-diffed (the source snapshots are gone), so cap the
// visible rows here and hide the rest behind a "Show all (N)" toggle so the list
// never floods the page. Applies to every section list, not just that case.
const SECTION_ROW_LIMIT = 12;

function DiffSection({ title, tone, rows, renderRow }) {
  const [showAll, setShowAll] = useState(false);
  if (!Array.isArray(rows) || rows.length === 0) return null;
  const toneStyle = TONE_STYLES[tone] || TONE_STYLES.warning;
  const overLimit = rows.length > SECTION_ROW_LIMIT;
  const visibleRows = showAll ? rows : rows.slice(0, SECTION_ROW_LIMIT);

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
        {visibleRows.map((row, i) => (
          <li key={i} style={{ wordBreak: 'break-all' }}>
            {renderRow(row)}
          </li>
        ))}
      </ul>
      {overLimit && (
        <button type="button" onClick={() => setShowAll((s) => !s)} style={{ ...TOGGLE_BUTTON_STYLE, marginLeft: 0, marginTop: 6 }}>
          {showAll ? '▾ Show fewer' : `▸ Show all ${rows.length}`}
        </button>
      )}
    </div>
  );
}

function renderAddedRow(row) {
  return <DiffValueRow path={row.path} value={row.value} friendlyDescription={row.friendlyDescription} />;
}

function renderRemovedRow(row) {
  return <DiffValueRow path={row.path} value={row.value} friendlyDescription={row.friendlyDescription} />;
}

function renderModifiedRow(row) {
  return (
    <DiffModifiedRow
      path={row.path}
      oldValue={row.old}
      newValue={row.new}
      friendlyDescription={row.friendlyDescription}
    />
  );
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

// ---------------------------------------------------------------------------
// Whole-rule added/removed detail table — renders ruleFromBraceEntry()'s
// NormalizedRule-shaped output as a small "Field | Value" table instead of
// the raw JSON blob a whole-added/removed rule used to dump inline. Same
// column set (and same labels) as the fleet Rules page
// (app/(dashboard)/devices/[id]/rules/page.js), minus `#`/`Hits` — a
// point-in-time historical diff has no stable sequence number and no live
// hit count.
//
// `joinArray`/`actionBorderColor` are DELIBERATELY duplicated here rather
// than imported from the Rules page — that page is a server component page
// module, not a shared lib export, and this codebase's own established
// convention is small per-file duplication over reaching into a page file
// (e.g. SECRET_KEY_PATTERN is duplicated per-adapter rather than
// centralized). Keep these two in sync with the Rules page's copies if the
// value-formatting conventions ever change there.
function joinArray(value) {
  if (!Array.isArray(value) || value.length === 0) return '—';
  return value.join(', ');
}

function actionBorderColor(action) {
  if (action === 'allow') return 'var(--green)';
  if (action === 'deny' || action === 'drop' || action === 'reject' || action === 'block') return 'var(--red)';
  return 'var(--border)';
}

// One row per NormalizedRule field. Order matches the Rules page's column
// order (skipping `#` and `Hits`, which don't apply to a single historical
// rule snapshot).
const RULE_DETAIL_FIELDS = [
  { label: 'Name', render: (r) => r.rule_name || '—' },
  { label: 'Enabled', render: (r) => (r.enabled ? 'Yes' : 'No') },
  { label: 'Action', render: (r) => r.action || '—' },
  { label: 'Src Zone', render: (r) => joinArray(r.src_zones) },
  { label: 'Dst Zone', render: (r) => joinArray(r.dst_zones) },
  { label: 'Src Address', render: (r) => joinArray(r.src_addresses) },
  { label: 'Dst Address', render: (r) => joinArray(r.dst_addresses) },
  { label: 'Services', render: (r) => joinArray(r.services) },
  { label: 'Comment', render: (r) => r.comment || '—' },
  { label: 'Applications', render: (r) => joinArray(r.applications) },
  { label: 'Schedule', render: (r) => r.schedule || '—' },
  { label: 'Log', render: (r) => (r.log_enabled ? 'Yes' : 'No') },
];

// Per-change-type accent (left border + status square), reused by the rule
// accordion below. Maps to the same green/red/yellow the Badge tones use.
const CHANGE_TONE = {
  added: 'var(--green)',
  removed: 'var(--red)',
  modified: 'var(--yellow)',
};

// Compact single-rule detail — the fields flow into a RESPONSIVE grid
// (auto-fit, ~3-4 columns on a wide diff) instead of the old 12-row vertical
// "Field | Value" table, which was the single biggest space hog in this view
// (a real user complaint: every added rule dumped a full-height stacked table,
// always expanded). Each cell is a small label-over-value block that wraps
// cleanly, so a long Applications list flows within its own cell rather than
// clipping off-screen. `Name` is dropped here — it's already the accordion
// card's title. Left border keeps the action color cue.
function RuleDetailGrid({ rule }) {
  const accent = actionBorderColor(rule.action);
  return (
    <div
      style={{
        borderLeft: `3px solid ${accent}`,
        paddingLeft: 10,
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
        gap: '10px 16px',
      }}
    >
      {RULE_DETAIL_FIELDS.filter((f) => f.label !== 'Name').map(({ label, render }) => {
        const value = render(rule);
        return (
          <div key={label} style={{ minWidth: 0 }}>
            <div
              style={{
                fontSize: 'var(--text-xs)',
                textTransform: 'uppercase',
                letterSpacing: '0.04em',
                color: 'var(--text-muted)',
                marginBottom: 2,
              }}
            >
              {label}
            </div>
            <div
              className="mono"
              style={{ color: 'var(--text-primary)', wordBreak: 'break-word' }}
              title={typeof value === 'string' ? value : undefined}
            >
              {value}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// True when `rule` (ruleFromBraceEntry()'s output) actually looks like a
// real rule rather than an all-blank result from a malformed/unexpected
// `change.value` shape (e.g. `{}`) — a name with zero populated fields is
// exactly what an empty-object input produces, and that must fall back to
// the raw-JSON rendering rather than show an empty-looking table.
function looksLikeRealRule(rule) {
  if (!rule || typeof rule !== 'object') return false;
  const hasName = typeof rule.rule_name === 'string' && rule.rule_name.length > 0;
  const hasAnyField =
    (typeof rule.action === 'string' && rule.action.length > 0) ||
    (Array.isArray(rule.src_zones) && rule.src_zones.length > 0) ||
    (Array.isArray(rule.dst_zones) && rule.dst_zones.length > 0) ||
    (Array.isArray(rule.src_addresses) && rule.src_addresses.length > 0) ||
    (Array.isArray(rule.dst_addresses) && rule.dst_addresses.length > 0) ||
    (Array.isArray(rule.services) && rule.services.length > 0) ||
    (Array.isArray(rule.applications) && rule.applications.length > 0);
  return hasName && hasAnyField;
}

// Attempts to build a NormalizedRule from a whole-rule added/removed
// change's `value` (the raw PAN-OS SSH-brace-tree rule dict — the only
// transport whose rule dicts reach the Rule Changes table, per
// classifyPath()'s existing XML/API-unresolvable-index gap). Defensive at
// every step, same discipline this whole file already uses everywhere else:
// never let a malformed/unexpected `change.value` shape throw up into the
// page render — returns null on ANY doubt, and the caller falls back to the
// existing raw-JSON rendering.
function tryBuildRuleFromChange(change) {
  const attrs = change && change.value;
  if (!attrs || typeof attrs !== 'object' || Array.isArray(attrs)) return null;
  const ruleName = typeof change.ruleName === 'string' && change.ruleName.length > 0 ? change.ruleName : null;
  try {
    const rule = ruleFromBraceEntry(ruleName, attrs, null);
    return looksLikeRealRule(rule) ? rule : null;
  } catch (_err) {
    return null;
  }
}

// Compact value renderer for ONE field-level rule change — inline "old → new"
// for small primitives (colored red/green), stacked for objects/large strings.
function RuleFieldValue({ change }) {
  if (change.changeType === 'modified') {
    const anyBlock = needsBlockRender(change.old) || needsBlockRender(change.new);
    if (!anyBlock) {
      return (
        <span>
          <span style={{ color: 'var(--red)' }}>{formatValue(change.old)}</span>
          {' → '}
          <span style={{ color: 'var(--green)' }}>{formatValue(change.new)}</span>
        </span>
      );
    }
    return (
      <span style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <LabeledValue label="− old" labelColor="var(--red)" value={change.old} />
        <LabeledValue label="+ new" labelColor="var(--green)" value={change.new} />
      </span>
    );
  }
  return needsBlockRender(change.value) ? renderBlockValue(change.value) : <span>{formatValue(change.value)}</span>;
}

// Field-level changes (a rule that had individual fields edited, not wholly
// added/removed) rendered as a responsive label-over-value grid — same compact
// shape as RuleDetailGrid, one cell per changed field, so N field edits take a
// few rows, not N stacked table rows.
function RuleFieldChangeList({ changes }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px 16px' }}>
      {changes.map((change, i) => (
        <div key={i} style={{ minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
            <span
              style={{
                fontSize: 'var(--text-xs)',
                textTransform: 'uppercase',
                letterSpacing: '0.04em',
                color: 'var(--text-muted)',
              }}
            >
              {change.fieldLabel || change.field}
            </span>
            <RuleChangeBadge changeType={change.changeType} />
          </div>
          <div className="mono" style={{ color: 'var(--text-primary)', wordBreak: 'break-word' }}>
            <RuleFieldValue change={change} />
          </div>
        </div>
      ))}
    </div>
  );
}

// One accordion card per rule — COLLAPSED by default (the key space saving,
// matching ManageEngine Firewall Analyzer's rule-change tracking). The header
// is a single line: a ▸/▾ affordance, the rule name, a badge per change type,
// and a one-line summary that ellipsis-truncates instead of clipping off the
// right edge (full text on hover + in the expanded body). Expanding shows the
// compact detail grid (whole rule) and/or the field-change grid.
function RuleChangeCard({ group, expanded, onToggle }) {
  const changes = Array.isArray(group.changes) ? group.changes : [];
  const wholeRule = changes.find((c) => c.field === null && (c.changeType === 'added' || c.changeType === 'removed'));
  const fieldChanges = changes.filter((c) => c.field !== null);
  const builtRule = wholeRule ? tryBuildRuleFromChange(wholeRule) : null;

  const types = [...new Set(changes.map((c) => c.changeType))];
  const primaryType = types.length === 1 ? types[0] : 'modified';
  const accent = CHANGE_TONE[primaryType] || CHANGE_TONE.modified;

  let summary;
  if (wholeRule && typeof wholeRule.friendlyDescription === 'string' && wholeRule.friendlyDescription.length > 0) {
    summary = wholeRule.friendlyDescription;
  } else if (wholeRule) {
    summary = `Entire rule ${wholeRule.changeType === 'added' ? 'added' : 'removed'}`;
  } else {
    const n = fieldChanges.length;
    summary = `${n} field${n === 1 ? '' : 's'} changed`;
  }

  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderLeft: `3px solid ${accent}`,
        borderRadius: 'var(--radius-sm)',
      }}
    >
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={expanded}
        style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          padding: '6px 10px',
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          textAlign: 'left',
          fontFamily: 'inherit',
        }}
      >
        <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>{expanded ? '▾' : '▸'}</span>
        <span className="mono" style={{ fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap' }}>
          {group.ruleName}
        </span>
        {types.map((t) => (
          <RuleChangeBadge key={t} changeType={t} />
        ))}
        <span
          style={{
            flex: 1,
            minWidth: 0,
            color: 'var(--text-secondary)',
            fontSize: 'var(--text-xs)',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
          title={summary}
        >
          {summary}
        </span>
      </button>
      {expanded && (
        <div style={{ padding: '8px 10px', borderTop: '1px solid var(--border)', display: 'flex', flexDirection: 'column', gap: 10 }}>
          {builtRule && <RuleDetailGrid rule={builtRule} />}
          {/* Whole-rule add/remove that couldn't be parsed into a NormalizedRule
              falls back to the reliable raw-value rendering, same as before. */}
          {wholeRule && !builtRule &&
            (needsBlockRender(wholeRule.value) ? renderBlockValue(wholeRule.value) : <span className="mono">{formatValue(wholeRule.value)}</span>)}
          {fieldChanges.length > 0 && <RuleFieldChangeList changes={fieldChanges} />}
        </div>
      )}
    </div>
  );
}

// Accordion list of rule-change cards with Expand all / Collapse all, replacing
// the old always-expanded 4-column table (Rule Name | Change | Field | Value)
// whose Value column embedded a full-height per-rule table — the space hog and
// off-screen clipping a user reported. Collapsed by default; each card owns its
// own expand state via a shared Set keyed by index.
function RuleChangesTable({ ruleChanges }) {
  const [expandedKeys, setExpandedKeys] = useState(() => new Set());
  if (!Array.isArray(ruleChanges) || ruleChanges.length === 0) return null;

  const keys = ruleChanges.map((rc, i) => `${rc.ruleName}-${i}`);

  function toggle(key) {
    setExpandedKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  const linkBtn = { ...TOGGLE_BUTTON_STYLE, marginLeft: 0 };

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap', marginBottom: 6 }}>
        <span
          style={{
            fontSize: 'var(--text-xs)',
            fontWeight: 600,
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            color: 'var(--text-muted)',
          }}
        >
          Rule Changes ({ruleChanges.length})
        </span>
        <span style={{ display: 'flex', gap: 12 }}>
          <button type="button" onClick={() => setExpandedKeys(new Set(keys))} style={linkBtn}>
            Expand all
          </button>
          <button type="button" onClick={() => setExpandedKeys(new Set())} style={linkBtn}>
            Collapse all
          </button>
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {ruleChanges.map((rc, i) => (
          <RuleChangeCard key={keys[i]} group={rc} expanded={expandedKeys.has(keys[i])} onToggle={() => toggle(keys[i])} />
        ))}
      </div>
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

// ---------------------------------------------------------------------------
// Indexed-rule groups (Palo Alto XML/API "Security Rules" section) — regroups
// the flat per-field entries classifyDiff() tags with ruleIndex/ruleField
// (see extractIndexedRuleEntry() in lib/engines/configDiff.js) back into one
// ManageEngine-style table per rule, keyed by the rule's positional array
// index. The rule NAME can't be resolved from an indexed diff entry, so a
// group is labelled by position ("Rule #6") — except a whole-rule add/remove
// carries the full rule object including its @_name sibling, which IS surfaced
// when present. Defined at module top level per CLAUDE.md.
// ---------------------------------------------------------------------------

// Friendlier labels for the raw PAN-OS security-rule tag names that surface as
// ruleField here (`log-end`, `disabled`, ...). These are PAN-OS's own XML
// element names (fast-xml-parser keeps them verbatim — see
// lib/adapters/paloalto/parser.js), so the keys are exact, not guessed; a tag
// not in this map falls back to a mechanical Title Case of its own name
// (titleCaseField), never dropped. Display-only — a slightly-off label never
// affects parsing or classification.
const RULE_FIELD_LABELS = {
  'log-start': 'Log at Session Start',
  'log-end': 'Log at Session End',
  disabled: 'Disabled',
  action: 'Action',
  from: 'Source Zone',
  to: 'Destination Zone',
  source: 'Source Address',
  destination: 'Destination Address',
  'source-user': 'Source User',
  service: 'Service',
  application: 'Application',
  category: 'URL Category',
  'profile-setting': 'Security Profile',
  'rule-type': 'Rule Type',
  'negate-source': 'Negate Source',
  'negate-destination': 'Negate Destination',
  description: 'Description',
  tag: 'Tag',
  'log-setting': 'Log Forwarding',
  schedule: 'Schedule',
};

// ruleField runs one or two levels deep (`log-end`, or `profile-setting.profiles`).
// The first segment gets a curated/Title-Cased label; any deeper segments are
// appended with a small separator so a nested field still reads as one label.
function humanizeRuleField(field) {
  if (!field) return '(entire rule)';
  const segments = String(field).split('.');
  const head = RULE_FIELD_LABELS[segments[0]] || titleCaseField(segments[0]);
  if (segments.length === 1) return head;
  return [head, ...segments.slice(1).map(titleCaseField)].join(' › ');
}

// Value cell for one indexed-rule field change — same old→new / block-render
// logic the rest of this file uses, adapted to the {changeType, value|old|new}
// shape classifyDiff() attaches to a section entry.
function IndexedRuleValueCell({ entry }) {
  if (entry.changeType === 'modified') {
    const anyBlock = needsBlockRender(entry.old) || needsBlockRender(entry.new);
    if (!anyBlock) {
      return <span>{formatValue(entry.old)} → {formatValue(entry.new)}</span>;
    }
    return (
      <span style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <LabeledValue label="− old" labelColor="var(--red)" value={entry.old} />
        <LabeledValue label="+ new" labelColor="var(--green)" value={entry.new} />
      </span>
    );
  }
  // added / removed
  const value = entry.value;
  if (needsBlockRender(value)) {
    return isFlatObject(value) ? <FlatObjectTable value={value} /> : renderBlockValue(value);
  }
  return <span>{formatValue(value)}</span>;
}

// A whole-rule add/remove entry (ruleField === null) carries the full rule
// object, whose @_name sibling IS the rule's real name — surface it to label
// the group when present. Returns null when no group entry carries a name
// (the common per-field-modify case), so the caller falls back to the
// positional "Rule #N" label.
function resolveGroupRuleName(entries) {
  for (const e of entries) {
    if (e.ruleField === null && e.value && typeof e.value === 'object' && !Array.isArray(e.value)) {
      const name = e.value['@_name'];
      if (typeof name === 'string' && name.length > 0) return name;
    }
  }
  return null;
}

function IndexedRuleGroup({ index, entries }) {
  const name = resolveGroupRuleName(entries);
  const title = name ? `Rule "${name}"` : `Rule #${index + 1}`;
  const count = entries.length;
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '6px 10px' }}>
      <div style={{ marginBottom: 4 }}>
        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{title}</span>
        <span style={{ color: 'var(--text-muted)' }}> — {count} change{count === 1 ? '' : 's'}</span>
      </div>
      <Table>
        <colgroup>
          <col style={{ width: '32%' }} />
          <col style={{ width: '16%' }} />
          <col style={{ width: '52%' }} />
        </colgroup>
        <thead>
          <tr>
            <th>Field</th>
            <th>Change</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e, i) => (
            <tr key={i}>
              <td style={{ fontWeight: 600, color: 'var(--text-primary)', wordBreak: 'break-word' }}>
                {humanizeRuleField(e.ruleField)}
              </td>
              <td>
                <RuleChangeBadge changeType={e.changeType} />
              </td>
              <td className="mono" style={{ wordBreak: 'break-word' }}>
                <IndexedRuleValueCell entry={e} />
              </td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

// Groups a section's indexed-rule entries by their positional ruleIndex,
// returning [index, entries][] sorted by position. Entries without a numeric
// ruleIndex (every non-indexed-rule path) are ignored here and rendered by
// the existing Added/Removed/Modified lists instead.
function groupIndexedRuleEntries(entries) {
  const groups = new Map();
  for (const e of entries) {
    if (typeof e.ruleIndex !== 'number') continue;
    if (!groups.has(e.ruleIndex)) groups.set(e.ruleIndex, []);
    groups.get(e.ruleIndex).push(e);
  }
  return [...groups.entries()].sort((a, b) => a[0] - b[0]);
}

function SectionGroup({ section }) {
  const [expanded, setExpanded] = useState(false);
  const entries = Array.isArray(section.entries) ? section.entries : [];

  // Indexed (XML/API) rulebase entries get regrouped into one table per rule;
  // everything else keeps the existing flat Added/Removed/Modified rendering.
  const ruleGroups = groupIndexedRuleEntries(entries);
  const nonRuleEntries = entries.filter((e) => typeof e.ruleIndex !== 'number');
  const addedEntries = nonRuleEntries.filter((e) => e.changeType === 'added');
  const removedEntries = nonRuleEntries.filter((e) => e.changeType === 'removed');
  const modifiedEntries = nonRuleEntries.filter((e) => e.changeType === 'modified');

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
          {ruleGroups.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {ruleGroups.map(([index, groupEntries]) => (
                <IndexedRuleGroup key={index} index={index} entries={groupEntries} />
              ))}
            </div>
          )}
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
