import { pool } from '../../lib/db';
import { resolvePage, paginateArray, DEFAULT_PAGE_SIZE } from '../../lib/pagination';
import Pagination from '../ui/Pagination';
import { WRAP_CELL } from '../ui/tableStyles';
import Table from '../ui/Table';
import EmptyState from '../ui/EmptyState';
import SeverityBadge from './SeverityBadge';
import FindingTypeBadge from './FindingTypeBadge';
import AcknowledgeControl from './AcknowledgeControl';

// Cleanup tab (Rule Analysis Dashboard Phase 2): unused / redundant /
// overly_permissive / correlation / generalization findings, with a per-row
// acknowledge status control. correlation and generalization are both
// ruleset-simplification suggestions, same class as redundant -- belong here
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
       AND rar.finding_type IN ('unused', 'redundant', 'overly_permissive', 'correlation', 'generalization')
     ORDER BY
       CASE rar.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
       rar.finding_type ASC,
       fr.sequence_number ASC NULLS LAST`,
    [deviceId]
  );
  return result.rows;
}

export default async function CleanupTab({ deviceId, canWrite = false, searchParams }) {
  const findings = await getCleanupFindings(pool, deviceId);
  // ⛔ Paginated. One live device renders 216 rows here and another 360 on
  // the Findings tab, with no counts, no grouping and no way to move
  // through them. Every sibling tab on this same tab bar (Reorder, Risky
  // Rules, Objects, Relationships) was already paginated with exactly this
  // helper; these two were simply missed.
  const paged = paginateArray(findings, resolvePage(searchParams?.page), DEFAULT_PAGE_SIZE);
  const pageParams = { ...searchParams, tab: 'cleanup' };

  if (findings.length === 0) {
    return (
      <EmptyState message="No cleanup findings — unused, redundant, or overly permissive rules will appear here." />
    );
  }

  return (
    <>
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
        {paged.rows.map((row) => (
          <tr key={row.finding_id}>
            <td>
              <SeverityBadge severity={row.severity} />
            </td>
            <td>
              <FindingTypeBadge type={row.finding_type} />
            </td>
            <td title={ruleLabel(row)}>{ruleLabel(row)}</td>
            <td style={{ ...WRAP_CELL, color: 'var(--text-secondary)' }}>
              {row.detail || '—'}
              {/* ⛔ `remediation` was SELECTed by this query and then thrown
                  away — the advice is the half of a finding a reader can act
                  on. Rendered the way RuleRelationshipTab already does it. */}
              {row.remediation ? (
                <div style={{ marginTop: 4, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                  Suggested fix: {row.remediation}
                </div>
              ) : null}
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
                <span style={{ color: 'var(--text-muted)' }} title="No stable rule identifier — cannot acknowledge">
                  —
                </span>
              ) : (
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{row.ack_status}</span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </Table>

      <Pagination
        basePath={`/devices/${deviceId}/analysis`}
        searchParams={pageParams}
        page={paged.page}
        pageSize={paged.pageSize}
        total={paged.total}
        label="cleanup findings"
      />
    </>
  );
}
