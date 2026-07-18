import { pool } from '../../lib/db';
import Table from '../ui/Table';
import EmptyState from '../ui/EmptyState';
import SeverityBadge from './SeverityBadge';
import FindingTypeBadge from './FindingTypeBadge';
import AcknowledgeControl from './AcknowledgeControl';

// Cleanup tab (Rule Analysis Dashboard Phase 2): unused / redundant /
// overly_permissive / correlation findings, with a per-row acknowledge
// status control. correlation (added alongside the 10th finding type) is a
// ruleset-simplification suggestion, same class as redundant -- belongs here
// alongside it. Async server component -- does its own pool.query, same
// pattern as app/(dashboard)/devices/[id]/analysis/page.js. Do not add
// 'use client'.

function ruleLabel(row) {
  const seq = row.sequence_number != null ? `#${row.sequence_number}` : '#—';
  return `${seq} ${row.rule_name || '(unnamed rule)'}`;
}

async function getCleanupFindings(dbPool, deviceId) {
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
       AND rar.finding_type IN ('unused', 'redundant', 'overly_permissive', 'correlation')
     ORDER BY
       CASE rar.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
       rar.finding_type ASC,
       fr.sequence_number ASC NULLS LAST`,
    [deviceId]
  );
  return result.rows;
}

export default async function CleanupTab({ deviceId }) {
  const findings = await getCleanupFindings(pool, deviceId);

  if (findings.length === 0) {
    return (
      <EmptyState message="No cleanup findings — unused, redundant, or overly permissive rules will appear here." />
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
              {row.rule_id_vendor ? (
                <AcknowledgeControl
                  deviceId={deviceId}
                  ruleIdVendor={row.rule_id_vendor}
                  findingType={row.finding_type}
                  currentStatus={row.ack_status}
                />
              ) : (
                <span style={{ color: 'var(--text-muted)' }} title="No stable rule identifier — cannot acknowledge">
                  —
                </span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
