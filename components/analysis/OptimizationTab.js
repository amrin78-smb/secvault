import { pool } from '../../lib/db';
import Table from '../ui/Table';
import EmptyState from '../ui/EmptyState';
import SeverityBadge from './SeverityBadge';
import FindingTypeBadge from './FindingTypeBadge';
import AcknowledgeControl from './AcknowledgeControl';

// Rule Analysis Dashboard Phase 2 -- "Optimization" tab. Surfaces the
// finding types that represent avoidable rule-hygiene risk an operator can
// act on directly (as opposed to the Cleanup tab's unused/expiring/redundant
// findings, or the Reorder tab's shadow/reorder_candidate findings): risky
// services, any-any rules, overly permissive rules, and (added alongside
// operator-supplied Zone Classification -- Settings > Zones)
// external_exposure, an enabled allow rule spanning an explicitly-classified
// External zone directly to an explicitly-classified Internal one. Same
// query shape as getFindings() in app/(dashboard)/devices/[id]/analysis/page.js,
// narrowed to this tab's finding types and joined to finding_acknowledgements
// for the per-row Status control.
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
       AND rar.finding_type IN ('risky_service', 'any_any', 'overly_permissive', 'external_exposure')
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

export default async function OptimizationTab({ deviceId, canWrite = false }) {
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
        <tr>
          <th>Severity</th>
          <th>Type</th>
          <th>Rule</th>
          <th>Detail</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((row) => (
          <tr key={row.finding_id}>
            <td>
              <SeverityBadge severity={row.severity} />
            </td>
            <td>
              <FindingTypeBadge type={row.finding_type} />
            </td>
            <td title={ruleLabel(row)}>{ruleLabel(row)}</td>
            <td style={{ color: 'var(--text-secondary)' }} title={row.detail || ''}>
              {row.detail || '—'}
            </td>
            <td>
              {canWrite && row.rule_id_vendor ? (
                <AcknowledgeControl
                  deviceId={deviceId}
                  ruleIdVendor={row.rule_id_vendor}
                  findingType={row.finding_type}
                  currentStatus={row.ack_status}
                />
              ) : canWrite ? (
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>—</span>
              ) : (
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{row.ack_status}</span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
