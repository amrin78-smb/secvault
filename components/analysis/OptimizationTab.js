import { pool } from '../../lib/db';
import Table from '../ui/Table';
import EmptyState from '../ui/EmptyState';
import SeverityBadge from './SeverityBadge';
import FindingTypeBadge from './FindingTypeBadge';
import AcknowledgeControl from './AcknowledgeControl';

// Rule Analysis Dashboard Phase 2 -- "Optimization" tab. Surfaces the three
// finding types that represent avoidable rule-hygiene risk an operator can
// act on directly (as opposed to the Cleanup tab's unused/expiring/redundant
// findings, or the Reorder tab's shadow/reorder_candidate findings): risky
// services, any-any rules, and overly permissive rules. Same query shape as
// getFindings() in app/(dashboard)/devices/[id]/analysis/page.js, narrowed
// to this tab's finding types and joined to finding_acknowledgements for the
// per-row Status control.
async function getOptimizationFindings(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT
       rar.id AS finding_id,
       rar.finding_type,
       rar.severity,
       rar.detail,
       rar.remediation,
       fr.rule_name,
       fr.sequence_number,
       fr.rule_id_vendor,
       COALESCE(fa.status, 'new') AS ack_status
     FROM rule_analysis_results rar
     JOIN firewall_rules fr ON fr.id = rar.rule_id
     LEFT JOIN finding_acknowledgements fa
       ON fa.device_id = rar.device_id
       AND fa.rule_id_vendor = fr.rule_id_vendor
       AND fa.finding_type = rar.finding_type
     WHERE rar.device_id = $1
       AND rar.finding_type IN ('risky_service', 'any_any', 'overly_permissive')
     ORDER BY
       CASE rar.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
       rar.finding_type ASC,
       fr.sequence_number ASC NULLS LAST`,
    [deviceId]
  );
  return result.rows;
}

function ruleLabel(row) {
  const seq = row.sequence_number != null ? `#${row.sequence_number}` : '#—';
  return `${seq} ${row.rule_name || '(unnamed rule)'}`;
}

export default async function OptimizationTab({ deviceId }) {
  const findings = await getOptimizationFindings(pool, deviceId);

  if (findings.length === 0) {
    return (
      <EmptyState message="No optimization findings — risky services, any-any rules, or overly permissive rules will appear here." />
    );
  }

  return (
    <Table>
      <colgroup>
        <col style={{ width: '9%' }} />
        <col style={{ width: '13%' }} />
        <col style={{ width: '20%' }} />
        <col style={{ width: '44%' }} />
        <col style={{ width: '14%' }} />
      </colgroup>
      <thead>
        <tr className="border-b border-border bg-bg-surface text-left text-text-secondary">
          <th className="px-2 py-2">Severity</th>
          <th className="px-2 py-2">Type</th>
          <th className="px-2 py-2">Rule</th>
          <th className="px-2 py-2">Detail</th>
          <th className="px-2 py-2">Status</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((row) => (
          <tr key={row.finding_id} className="border-b border-border">
            <td className="px-2 py-2">
              <SeverityBadge severity={row.severity} />
            </td>
            <td className="px-2 py-2">
              <FindingTypeBadge type={row.finding_type} />
            </td>
            <td className="truncate px-2 py-2" title={ruleLabel(row)}>
              {ruleLabel(row)}
            </td>
            <td className="px-2 py-2 text-text-secondary" title={row.detail || ''}>
              {row.detail || '—'}
            </td>
            <td className="px-2 py-2">
              {row.rule_id_vendor ? (
                <AcknowledgeControl
                  deviceId={deviceId}
                  ruleIdVendor={row.rule_id_vendor}
                  findingType={row.finding_type}
                  currentStatus={row.ack_status}
                />
              ) : (
                <span className="text-xs text-text-muted">—</span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
