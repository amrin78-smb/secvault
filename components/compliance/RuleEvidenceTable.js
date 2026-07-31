// Compact, presentational "offending rules" evidence table for a failed
// compliance check whose finding carries matched_rule_ids (see
// lib/engines/configAuditor.js's evaluateRuleScanCheck()). Mirrors
// app/(dashboard)/devices/[id]/rules/page.js's exact cell-formatting
// convention for the JSONB array fields (src_addresses/dst_addresses/
// services/src_zones/dst_zones) -- comma-joined, "—" fallback for
// empty/null/non-array -- rather than inventing a new one, per this task's
// own instruction to reuse that file's convention.
//
// Presentation note: the multi-value list columns render as a WRAPPED set of
// small pills so a rule with many addresses/services is fully readable inline.
// The app's global `td` rule (app/globals.css) forces every cell to
// `white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:220px`,
// which would otherwise show only the first value + "…" (full list only on
// hover). Because the shared Table enforces `tableLayout:'fixed'` with a
// <colgroup>, column widths come from the colgroup, NOT the td max-width --
// so overriding these td styles to wrap grows the row taller within its
// allocated column width and does not disturb the fixed layout.
import Table from '../ui/Table';

// Identical logic to devices/[id]/rules/page.js's joinArray() -- that file
// doesn't export it, so it's mirrored here rather than imported. Used for the
// cell `title` tooltip (accessibility / quick copy) alongside the pill render.
function joinArray(value) {
  if (!Array.isArray(value) || value.length === 0) return '—';
  return value.join(', ');
}

// td style override for the wrapping list columns: cancels the global
// single-line-ellipsis rule so the pill set wraps and shows every value.
const WRAP_CELL = {
  whiteSpace: 'normal',
  overflow: 'visible',
  textOverflow: 'clip',
  maxWidth: 'none',
  wordBreak: 'break-word',
  verticalAlign: 'top',
};

// Neutral pill for a single list value. Uses theme surface/text tokens (which
// flip in dark mode) + a border rather than a hardcoded hex, per the design
// system's adaptive-surface rule. `white-space:normal`/`wordBreak` let a long
// single value (e.g. a wide CIDR-list object name) wrap inside the pill too.
const PILL = {
  display: 'inline-block',
  padding: '2px 8px',
  background: 'var(--bg-primary)',
  color: 'var(--text-secondary)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)',
  fontSize: 'var(--text-xs)',
  lineHeight: 1.4,
  whiteSpace: 'normal',
  wordBreak: 'break-word',
};

const PILL_WRAP = {
  display: 'flex',
  flexWrap: 'wrap',
  gap: '4px',
};

// Module-level (never defined inside the row component) so it doesn't remount
// per keystroke/render. Renders a JSONB array field as a wrapped pill set,
// falling back to the shared "—" placeholder for empty/null/non-array.
function ListPills({ value }) {
  if (!Array.isArray(value) || value.length === 0) {
    return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  }
  return (
    <span style={PILL_WRAP}>
      {value.map((v, i) => (
        <span key={i} style={PILL}>{String(v)}</span>
      ))}
    </span>
  );
}

export default function RuleEvidenceTable({ rules }) {
  if (!Array.isArray(rules) || rules.length === 0) return null;

  return (
    <Table>
      <colgroup>
        <col style={{ width: '16%' }} />
        <col style={{ width: '9%' }} />
        <col style={{ width: '21%' }} />
        <col style={{ width: '21%' }} />
        <col style={{ width: '15%' }} />
        <col style={{ width: '9%' }} />
        <col style={{ width: '9%' }} />
      </colgroup>
      <thead>
        <tr>
          <th>Rule Name</th>
          <th>Action</th>
          <th>Source</th>
          <th>Destination</th>
          <th>Service</th>
          <th>Src Zone</th>
          <th>Dst Zone</th>
        </tr>
      </thead>
      <tbody>
        {rules.map((r) => (
          <tr key={r.id}>
            <td title={r.rule_name || ''}>{r.rule_name || '—'}</td>
            <td>{r.action || '—'}</td>
            <td style={WRAP_CELL} title={joinArray(r.src_addresses)}>
              <ListPills value={r.src_addresses} />
            </td>
            <td style={WRAP_CELL} title={joinArray(r.dst_addresses)}>
              <ListPills value={r.dst_addresses} />
            </td>
            <td style={WRAP_CELL} title={joinArray(r.services)}>
              <ListPills value={r.services} />
            </td>
            <td style={WRAP_CELL} title={joinArray(r.src_zones)}>
              <ListPills value={r.src_zones} />
            </td>
            <td style={WRAP_CELL} title={joinArray(r.dst_zones)}>
              <ListPills value={r.dst_zones} />
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
