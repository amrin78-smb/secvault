// Compact, presentational "offending rules" evidence table for a failed
// compliance check whose finding carries matched_rule_ids (see
// lib/engines/configAuditor.js's evaluateRuleScanCheck()). Mirrors
// app/(dashboard)/devices/[id]/rules/page.js's exact cell-formatting
// convention for the JSONB array fields (src_addresses/dst_addresses/
// services/src_zones/dst_zones) -- comma-joined, "—" fallback for
// empty/null/non-array -- rather than inventing a new one, per this task's
// own instruction to reuse that file's convention.
import Table from '../ui/Table';

// Identical logic to devices/[id]/rules/page.js's joinArray() -- that file
// doesn't export it, so it's mirrored here rather than imported.
function joinArray(value) {
  if (!Array.isArray(value) || value.length === 0) return '—';
  return value.join(', ');
}

export default function RuleEvidenceTable({ rules }) {
  if (!Array.isArray(rules) || rules.length === 0) return null;

  return (
    <Table>
      <colgroup>
        <col style={{ width: '20%' }} />
        <col style={{ width: '10%' }} />
        <col style={{ width: '20%' }} />
        <col style={{ width: '20%' }} />
        <col style={{ width: '15%' }} />
        <col style={{ width: '7.5%' }} />
        <col style={{ width: '7.5%' }} />
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
            <td title={joinArray(r.src_addresses)}>{joinArray(r.src_addresses)}</td>
            <td title={joinArray(r.dst_addresses)}>{joinArray(r.dst_addresses)}</td>
            <td title={joinArray(r.services)}>{joinArray(r.services)}</td>
            <td title={joinArray(r.src_zones)}>{joinArray(r.src_zones)}</td>
            <td title={joinArray(r.dst_zones)}>{joinArray(r.dst_zones)}</td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
