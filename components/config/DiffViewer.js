'use client';

import { useState } from 'react';
import LoadingSpinner from '../ui/LoadingSpinner';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import { ruleFromBraceEntry } from '../../lib/adapters/paloalto/sshParser';
import { parseRuleEntry } from '../../lib/adapters/paloalto/parser';

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

// ---------------------------------------------------------------------------
// ValueTable — the nested-structure renderer (supersedes ValueTree above)
// ---------------------------------------------------------------------------
// ValueTree's indented key/value tree was already an improvement on raw JSON,
// but it still READS as a serialized structure: an operator scanning a config
// subtree ("shared", a certificate entry, a local-user record) gets a wall of
// `key:` lines with no column alignment and no visual separation between one
// record and the next. This renders the same data as real tables:
//
//   * object                  -> two-column Field | Value table, value cell recurses
//   * array of objects        -> ONE table, columns = union of the objects' keys
//                                (the biggest readability win — N records read as
//                                N rows rather than N stacked sub-trees)
//   * array of primitives     -> comma-joined text
//   * primitive               -> text
//
// ValueTree is KEPT, not deleted: it remains the fallback past MAX_TABLE_DEPTH,
// where nesting tables inside table cells starts costing more horizontal room
// than it buys in clarity.
const MAX_TABLE_DEPTH = 4;

// Widest array-of-objects that renders as a columnar table. Past this the
// column union gets unwieldy and it falls back to per-item tables.
const MAX_OBJECT_TABLE_COLUMNS = 8;

// PAN-OS XML wraps every list in a `<member>` element, so a set of zones
// reaches the diff tree as `{ member: ['DMZ1', 'DMZ3'] }`. That wrapper is the
// vendor's XML grammar, not information — rendering it produced a pointless
// extra nesting level ("To: member: DMZ1, DMZ3"). Unwrap a single-key
// `member` object to its contents. Deliberately ONLY when `member` is the
// sole key, so a record that happens to also carry other fields is never
// silently reduced to one of them.
function unwrapMember(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return value;
  const keys = Object.keys(value);
  if (keys.length === 1 && keys[0] === 'member') return value.member;
  return value;
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// True when every element is a plain object — the shape that earns a columnar
// table. An array mixing objects and primitives does not (a primitive has no
// column to sit under).
function isObjectArray(value) {
  return Array.isArray(value) && value.length > 0 && value.every(isPlainObject);
}

// Column set for an object array: the union of every element's keys, in
// first-seen order so the first record's field order leads (vendors emit
// their most identifying field first — `@_name`, `id`, `feature`).
function unionKeys(items) {
  const seen = [];
  const set = new Set();
  for (const item of items) {
    for (const k of Object.keys(item)) {
      if (!set.has(k)) { set.add(k); seen.push(k); }
    }
  }
  return seen;
}

const HEADER_CELL_STYLE = { whiteSpace: 'nowrap' };

// ⛔ `white-space` INHERITS. Several ancestors in this page's tree set
// `nowrap` (see app/globals.css), and a nowrap cell cannot wrap no matter how
// generous `word-break` is — a long value then lays out as one enormous line
// that is clipped by the cell and unreachable, since the row is not itself a
// scroll container. Every value cell therefore RESETS white-space explicitly
// rather than relying on the default. `overflowWrap: anywhere` additionally
// breaks unbroken tokens (base64, certificate bodies, long object names) that
// have no space to wrap at.
const WRAP_STYLE = { whiteSpace: 'normal', overflowWrap: 'anywhere', wordBreak: 'break-word' };
const FIELD_CELL_STYLE = { fontWeight: 600, color: 'var(--text-primary)', ...WRAP_STYLE };
const VALUE_CELL_STYLE = { ...WRAP_STYLE, verticalAlign: 'top' };

// The shared <Table> component ALREADY wraps itself in an overflow-x:auto
// bordered box, so a wide table scrolls within its card without any extra
// wrapper here.

function ObjectArrayTable({ items, depth }) {
  const keys = unionKeys(items);
  if (keys.length > MAX_OBJECT_TABLE_COLUMNS) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {items.map((item, i) => (
          <ValueTable key={i} value={item} depth={depth + 1} />
        ))}
      </div>
    );
  }
  return (
    <Table>
      <thead>
        <tr>
          {keys.map((k) => (
            <th key={k} style={HEADER_CELL_STYLE}>{titleCaseField(k)}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {items.map((item, i) => (
          <tr key={i}>
            {keys.map((k) => (
              <td key={k} style={VALUE_CELL_STYLE}>
                {Object.prototype.hasOwnProperty.call(item, k) ? (
                  <ValueTable value={item[k]} depth={depth + 1} />
                ) : (
                  <span style={{ color: 'var(--text-muted)' }}>{KEY_NOT_PRESENT_PLACEHOLDER}</span>
                )}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function ValueTable({ value, depth = 0 }) {
  const v = unwrapMember(value);

  if (depth >= MAX_TABLE_DEPTH) return <ValueTree value={v} />;

  if (Array.isArray(v)) {
    if (v.length === 0) return <span style={{ color: 'var(--text-muted)' }}>{EMPTY_ARRAY_PLACEHOLDER}</span>;
    if (v.every(isTreePrimitive)) return <span style={{ wordBreak: 'break-word' }}>{joinTreePrimitives(v)}</span>;
    if (isObjectArray(v)) return <ObjectArrayTable items={v} depth={depth} />;
    // Mixed array — each element on its own, one under the next.
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {v.map((item, i) => (
          <ValueTable key={i} value={item} depth={depth + 1} />
        ))}
      </div>
    );
  }

  if (isPlainObject(v)) {
    const keys = Object.keys(v);
    if (keys.length === 0) return <span style={{ color: 'var(--text-muted)' }}>{EMPTY_ARRAY_PLACEHOLDER}</span>;
    return (
      <Table>
        <colgroup>
          <col style={{ width: '30%' }} />
          <col style={{ width: '70%' }} />
        </colgroup>
        <tbody>
          {keys.map((k) => (
            <tr key={k}>
              <td style={FIELD_CELL_STYLE}>{titleCaseField(k)}</td>
              <td style={VALUE_CELL_STYLE}>
                <ValueTable value={v[k]} depth={depth + 1} />
              </td>
            </tr>
          ))}
        </tbody>
      </Table>
    );
  }

  // ⛔ A config value can be enormous — a real case on a live device is a
  // 300KB base64 image embedded in the config. Rendering that inline made one
  // table cell hundreds of thousands of pixels wide. Route it through the same
  // collapse treatment a large string already gets elsewhere in this file.
  if (isLargeString(v)) return <CollapsibleString value={v} />;
  return <span style={WRAP_STYLE}>{formatValue(v)}</span>;
}

// Renders an object/array value as a ValueTable (see above). Large values (per
// LARGE_VALUE_THRESHOLD) collapse behind a toggle so a big subtree doesn't
// dominate the row list. Top-level function per CLAUDE.md — never nest a
// component definition inside another component's function body.
function CollapsibleValue({ value }) {
  const [expanded, setExpanded] = useState(false);
  const isLarge = JSON.stringify(value).length > LARGE_VALUE_THRESHOLD;

  if (!isLarge) {
    return (
      <div style={TREE_BOX_STYLE}>
        <ValueTable value={value} />
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
          <ValueTable value={value} />
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
// RuleSnapshotTable further down this file. Address/service objects, zones,
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
// reaching into another module (see joinArray's own comment
// further down, and configDiff.js's own per-adapter SECRET_KEY_PATTERN
// duplication). Deliberately NOT the same casing as configDiff.js's
// humanizeFieldForSentence() (that one lowercases for mid-sentence use) —
// this wants Title Case for a table column header, matching how the Rules
// page's own columns ("Src Zone", "Dst Zone") read. A straightforward
// mechanical split-and-capitalize; a slightly awkward label (e.g.
// "Accprofile" for a field with no separator) beats a guessed-nicer one.
// Acronyms a mechanical capitalize would mangle into "Uuid"/"Ip"/"Vsys". Only
// entries that are unambiguous as a WHOLE word — deliberately not "id" (a
// field genuinely named "id" reads fine as "Id", and "ID" would also rewrite
// the "id" inside nothing else since matching is per-word). Display-only.
const FIELD_ACRONYMS = {
  ip: 'IP',
  uuid: 'UUID',
  url: 'URL',
  dns: 'DNS',
  ntp: 'NTP',
  ha: 'HA',
  vpn: 'VPN',
  ssl: 'SSL',
  ssh: 'SSH',
  snmp: 'SNMP',
  nat: 'NAT',
  vsys: 'VSYS',
  vdom: 'VDOM',
  cpu: 'CPU',
  mtu: 'MTU',
  tcp: 'TCP',
  udp: 'UDP',
  ike: 'IKE',
  psk: 'PSK',
};

// fast-xml-parser is configured with `attributeNamePrefix: '@_'`, so a PAN-OS
// XML attribute reaches the diff tree as `@_name`/`@_uuid`. Rendering that
// verbatim produced labels like "@ Name" — the prefix is a parser artifact,
// not part of the device's own vocabulary, so strip it before labelling.
function stripAttrPrefix(field) {
  return String(field).replace(/^@_/, '');
}

function titleCaseField(field) {
  return stripAttrPrefix(field)
    .replace(/[-_]+/g, ' ')
    .split(' ')
    .filter(Boolean)
    .map((word) => FIELD_ACRONYMS[word.toLowerCase()] || word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

// Placeholder for an array-valued field with zero elements. Distinct from
// formatValue()'s '—' (which means "this single value is null/undefined") —
// this means "the array itself is empty," a different fact worth reading
// differently at a glance.
const EMPTY_ARRAY_PLACEHOLDER = '(empty)';

// Joins an array of primitives for one table cell. Deliberately NOT
// the rule tables' joinArray() below (which is tied to their own
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
// `joinArray` is DELIBERATELY duplicated here rather
// than imported from the Rules page — that page is a server component page
// module, not a shared lib export, and this codebase's own established
// convention is small per-file duplication over reaching into a page file
// (e.g. SECRET_KEY_PATTERN is duplicated per-adapter rather than
// centralized). Keep this in sync with the Rules page's copy if the
// value-formatting conventions ever change there.
function joinArray(value) {
  if (!Array.isArray(value) || value.length === 0) return '—';
  return value.join(', ');
}

// Per-change-type accent (left border + status square), reused by the rule
// accordion below. Maps to the same green/red/yellow the Badge tones use.
const CHANGE_TONE = {
  added: 'var(--green)',
  removed: 'var(--red)',
  modified: 'var(--yellow)',
};

// ---------------------------------------------------------------------------
// RuleSnapshotTable — whole rule(s) as a ManageEngine-style horizontal table
// ---------------------------------------------------------------------------
// A whole rule that was ADDED or REMOVED is the single most important thing in
// a config diff, and it was the last place still dumping a raw structure dump
// (`{15 keys}` expanding into `to: member: DMZ1…`, `@_uuid: …`). It now renders
// as the same shape a firewall operator already reads everywhere else: one
// header row of rule attributes, one row of values, tinted green for added and
// red for removed.
//
// Horizontal (not the vertical Field|Value stack) because that is how a rule is
// read in every firewall UI — left to right, one line per rule. The table lives
// in its own `overflow-x: auto` box, so a wide rule scrolls WITHIN the card
// instead of clipping at the right page edge.
const RULE_SNAPSHOT_COLUMNS = [
  { label: 'Rule Name', render: (r) => r.rule_name || '—', nowrap: true },
  { label: 'Src Zone', render: (r) => joinArray(r.src_zones) },
  { label: 'Dst Zone', render: (r) => joinArray(r.dst_zones) },
  { label: 'Source', render: (r) => joinArray(r.src_addresses) },
  { label: 'Destination', render: (r) => joinArray(r.dst_addresses) },
  { label: 'Service', render: (r) => joinArray(r.services) },
  { label: 'Application', render: (r) => joinArray(r.applications) },
  { label: 'Action', render: (r) => r.action || '—', nowrap: true },
  { label: 'Log', render: (r) => (r.log_enabled ? 'Enabled' : 'Disabled'), nowrap: true },
  { label: 'Status', render: (r) => (r.enabled ? 'Enabled' : 'Disabled'), nowrap: true },
];

// Shown under the table only when populated — a rule with no schedule and no
// description shouldn't pay two columns of width for two em-dashes.
const RULE_SNAPSHOT_FOOTNOTES = [
  { label: 'Schedule', get: (r) => r.schedule },
  { label: 'Comment', get: (r) => r.comment },
];

const SNAPSHOT_TONE = {
  added: { bg: 'var(--tint-success)', fg: 'var(--tint-success-fg)', label: 'New Details' },
  removed: { bg: 'var(--tint-danger)', fg: 'var(--tint-danger-fg)', label: 'Old Details' },
  modified: { bg: 'var(--tint-warn)', fg: 'var(--tint-warn-fg)', label: 'Details' },
};

// Below this the 11 rule columns start compressing into unreadable slivers, so
// the table keeps its natural width and scrolls inside its own bordered box
// (which <Table> already provides) rather than squeezing.
const RULE_TABLE_MIN_WIDTH = 1000;

// `rows`: [{ label, rule, changeType }] — one entry for a whole-rule add/remove,
// TWO ("Old Details" / "New Details") for a modified rule, so both states read
// as adjacent rows of ONE table instead of two separate tables the eye has to
// diff manually.
//
// ⛔ `layout="auto"`: this table has no colgroup and no percentage widths, so
// the default 'fixed' would slice the width into 11 equal columns and truncate
// every heading. See the Table component's own note.
function RuleSnapshotTable({ rows }) {
  const safeRows = Array.isArray(rows) ? rows.filter((r) => r && r.rule) : [];
  if (safeRows.length === 0) return null;

  // Schedule/comment sit under the table rather than paying two columns of
  // width — most rules populate neither. Labelled per row only when the rows
  // disagree, so an unchanged comment isn't printed twice.
  const notes = [];
  for (const row of safeRows) {
    for (const f of RULE_SNAPSHOT_FOOTNOTES) {
      const value = f.get(row.rule);
      if (typeof value !== 'string' || value.length === 0) continue;
      if (notes.some((n) => n.label === f.label && n.value === value)) continue;
      notes.push({ label: f.label, value, rowLabel: row.label });
    }
  }
  const multiRow = safeRows.length > 1;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <Table layout="auto" minWidth={RULE_TABLE_MIN_WIDTH}>
        <thead>
          <tr>
            {multiRow && <th style={HEADER_CELL_STYLE}> </th>}
            {RULE_SNAPSHOT_COLUMNS.map((c) => (
              <th key={c.label} style={HEADER_CELL_STYLE}>{c.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {safeRows.map((row, i) => {
            const tone = SNAPSHOT_TONE[row.changeType] || SNAPSHOT_TONE.modified;
            return (
              <tr key={i} style={{ background: tone.bg }}>
                {multiRow && (
                  <td style={{ fontWeight: 600, color: tone.fg, whiteSpace: 'nowrap' }}>
                    {row.label || tone.label}
                  </td>
                )}
                {RULE_SNAPSHOT_COLUMNS.map((c) => {
                  const value = c.render(row.rule);
                  return (
                    <td
                      key={c.label}
                      title={typeof value === 'string' ? value : undefined}
                      style={{ ...WRAP_STYLE, whiteSpace: c.nowrap ? 'nowrap' : 'normal', verticalAlign: 'top' }}
                    >
                      {value}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </Table>
      {notes.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px 18px', fontSize: 'var(--text-xs)' }}>
          {notes.map((n, i) => (
            <span key={i}>
              <span style={{ color: 'var(--text-muted)' }}>
                {n.label}{multiRow ? ` (${n.rowLabel})` : ''}:{' '}
              </span>
              <span style={{ color: 'var(--text-primary)' }}>{n.value}</span>
            </span>
          ))}
        </div>
      )}
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

// XML/API-transport counterpart to tryBuildRuleFromChange() above. Where that
// one normalizes an SSH brace-tree rule dict, this one normalizes the PAN-OS
// XML rule object (`{'@_name': ..., to: {member: [...]}, action: 'allow', ...}`)
// that reaches an indexed rulebase diff entry, reusing the adapter's own
// parseRuleEntry() rather than re-deriving the field mapping here. Same
// defensive discipline: any doubt returns null and the caller keeps the
// existing raw rendering. The `0` index is a placeholder — parseRuleEntry uses
// it only for `sequence_number`, which a point-in-time diff snapshot has no
// meaningful value for and RuleSnapshotTable does not display.
function tryBuildRuleFromXmlValue(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  try {
    const rule = parseRuleEntry(value, 0);
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
// label-over-value shape, one cell per changed field, so N field edits take a
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
  // A whole-rule entry can also arrive as 'modified' (a bare rulebase path
  // whose value type-mismatched between two snapshots, e.g. a partial SSH
  // brace-parse) — field is still null so it falls outside both wholeRule
  // (added/removed only) and fieldChanges (field !== null) below. Tracked
  // separately so it still gets a body rendering instead of silently
  // vanishing behind an empty "0 fields changed" summary.
  const wholeRuleModified = changes.find((c) => c.field === null && c.changeType === 'modified');
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
  } else if (wholeRuleModified) {
    summary =
      typeof wholeRuleModified.friendlyDescription === 'string' && wholeRuleModified.friendlyDescription.length > 0
        ? wholeRuleModified.friendlyDescription
        : 'Entire rule modified';
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
          {builtRule && (
            <RuleSnapshotTable
              rows={[
                {
                  label: wholeRule.changeType === 'added' ? 'New Details' : 'Old Details',
                  rule: builtRule,
                  changeType: wholeRule.changeType,
                },
              ]}
            />
          )}
          {/* Whole-rule add/remove that couldn't be parsed into a NormalizedRule
              falls back to the reliable raw-value rendering, same as before. */}
          {wholeRule && !builtRule &&
            (needsBlockRender(wholeRule.value) ? renderBlockValue(wholeRule.value) : <span className="mono">{formatValue(wholeRule.value)}</span>)}
          {/* Same raw-fallback discipline as the wholeRule-without-builtRule
              case above, but for the field:null + changeType:'modified' shape
              (old/new instead of a single value) — otherwise this change is
              silently dropped from the rendered body entirely. */}
          {wholeRuleModified && (
            <span className="mono" style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <LabeledValue label="− old" labelColor="var(--red)" value={wholeRuleModified.old} />
              <LabeledValue label="+ new" labelColor="var(--green)" value={wholeRuleModified.new} />
            </span>
          )}
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
  // added / removed. NOTE: a WHOLE-rule entry (ruleField === null) that
  // normalizes into a real rule never reaches here — IndexedRuleGroup hoists it
  // out into a full-width RuleSnapshotTable via splitRuleGroupEntries(). What
  // arrives here is either a per-field value or a whole-rule value that FAILED
  // to normalize, which keeps the reliable raw rendering below.
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

// Splits a rule group's entries into the whole-rule snapshots (which render as
// a full-width rule table) and the per-field edits (which don't). A whole-rule
// 'modified' contributes TWO rows — old and new — so the pair reads as adjacent
// rows of one table. Any whole-rule entry that fails to normalize into a real
// rule falls back to the per-field list, keeping the existing raw rendering
// rather than silently vanishing.
function splitRuleGroupEntries(entries) {
  const snapshotRows = [];
  const fieldEntries = [];
  for (const e of entries) {
    if (e.ruleField !== null) { fieldEntries.push(e); continue; }
    if (e.changeType === 'modified') {
      const oldRule = tryBuildRuleFromXmlValue(e.old);
      const newRule = tryBuildRuleFromXmlValue(e.new);
      if (oldRule && newRule) {
        snapshotRows.push({ label: 'Old Details', rule: oldRule, changeType: 'removed' });
        snapshotRows.push({ label: 'New Details', rule: newRule, changeType: 'added' });
        continue;
      }
    } else {
      const rule = tryBuildRuleFromXmlValue(e.value);
      if (rule) {
        snapshotRows.push({
          label: e.changeType === 'added' ? 'New Details' : 'Old Details',
          rule,
          changeType: e.changeType,
        });
        continue;
      }
    }
    fieldEntries.push(e);
  }
  return { snapshotRows, fieldEntries };
}

const PILL_ROW_STYLE = { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 6 };

// One per-field edit as a pill pair + its value, replacing the Field | Change |
// Value table row this used to be. The field name and change type are metadata
// ABOUT the change, not columns of firewall data — as table columns they stole
// half the width from the value that actually matters.
function IndexedFieldChange({ entry }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
        <span
          style={{
            fontSize: 'var(--text-xs)',
            textTransform: 'uppercase',
            letterSpacing: '0.04em',
            color: 'var(--text-muted)',
          }}
        >
          {humanizeRuleField(entry.ruleField)}
        </span>
        <RuleChangeBadge changeType={entry.changeType} />
      </div>
      <div className="mono" style={WRAP_STYLE}>
        <IndexedRuleValueCell entry={entry} />
      </div>
    </div>
  );
}

// ⛔ The rule table is NOT nested inside a Field | Change | Value table any
// more. Wrapping it in a `VALUE` cell left it roughly half the card's width, so
// all 11 rule columns truncated to "RULE…", "SRC …", "3BB,…" — the table was
// technically present and practically unreadable. The change type is now a pill
// in the group header and the rule table spans the full card, scrolling within
// its own box if it needs more room than that.
function IndexedRuleGroup({ index, entries }) {
  const name = resolveGroupRuleName(entries);
  const title = name ? `Rule "${name}"` : `Rule #${index + 1}`;
  const { snapshotRows, fieldEntries } = splitRuleGroupEntries(entries);
  const types = [...new Set(entries.map((e) => e.changeType))];
  const count = entries.length;

  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '8px 10px' }}>
      <div style={PILL_ROW_STYLE}>
        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{title}</span>
        {types.map((t) => (
          <RuleChangeBadge key={t} changeType={t} />
        ))}
        <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
          {count} change{count === 1 ? '' : 's'}
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {snapshotRows.length > 0 && <RuleSnapshotTable rows={snapshotRows} />}
        {fieldEntries.length > 0 && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '10px 16px' }}>
            {fieldEntries.map((e, i) => (
              <IndexedFieldChange key={i} entry={e} />
            ))}
          </div>
        )}
      </div>
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

// ---------------------------------------------------------------------------
// DiffBody — the pure presentational render tree for a classifyDiff() result
// ({ ruleChanges, sections }). Extracted VERBATIM from DiffViewer's own render
// so both callers share one implementation:
//
//   1. DiffViewer (below) — lazily fetches /api/devices/[id]/diffs/[diffId] on
//      expand, then renders this with the fetched `classified` payload. Its
//      props/behaviour are unchanged by this extraction.
//   2. The device Changes page (a SERVER component) — computes
//      classifyDiff(diffConfigs(...)) server-side for arbitrary-version and
//      baseline-drift comparisons and renders this directly. A named export
//      from a 'use client' module IS importable by a server component; it just
//      becomes a client boundary, which is exactly what the interactive
//      accordions/collapse toggles inside this tree need.
//
// Deliberately does NOT render the "no entries" empty state — each caller
// words that differently ("This diff contains no entries." vs. the drift
// view's positive "No drift — ..."), so that stays with the caller.
export function DiffBody({ ruleChanges, sections }) {
  const safeRuleChanges = Array.isArray(ruleChanges) ? ruleChanges : [];
  const safeSections = Array.isArray(sections) ? sections : [];
  return (
    <>
      <RuleChangesTable ruleChanges={safeRuleChanges} />
      {safeSections.map((section, i) => (
        <SectionGroup key={`${section.label}-${i}`} section={section} />
      ))}
    </>
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
              <DiffBody ruleChanges={ruleChanges} sections={sections} />
              {isEmpty && <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-muted)' }}>This diff contains no entries.</p>}
            </>
          )}
        </div>
      )}
    </div>
  );
}
