import { pool } from '../../lib/db';
import Table from '../ui/Table';
import EmptyState from '../ui/EmptyState';
import SeverityBadge from './SeverityBadge';
import AcknowledgeControl from './AcknowledgeControl';

// Rule Analysis Dashboard Phase 2 -- "Reorder" tab. Surfaces reorder_candidate
// findings: a deny/drop/reject rule that appears after an earlier allow rule
// whose zones/addresses/services fully cover it, so the deny can never fire
// (see lib/engines/ruleAnalysis.js's pairwise reorder_candidate check). Unlike
// the Cleanup/Optimization tabs, each row here needs to show TWO rules -- the
// shadowed deny rule (rar.rule_id / fr.*) and the earlier allow rule that
// shadows it (rar.affected_rule_ids, a jsonb array of firewall_rules.id).
//
// affected_rule_ids is only ever resolved against a firewall_rules snapshot
// taken in the SAME request (query 2 below) -- never persisted or reused
// across requests. firewall_rules is fully DELETE+reinserted on every device
// collect, so those ids are not stable across pulls, but within one render
// they refer to the same snapshot rule_analysis_results.rule_id was joined
// against, so resolving them here is safe.
//
// "Export Recommended Order" (added alongside ManageEngine Firewall
// Analyzer parity work) synthesizes this tab's individual findings into
// ONE recommended full rule order via GET
// /api/devices/[id]/reorder-recommendation?format=csv -- see
// lib/engines/ruleReorder.js for the topological-sort algorithm. Read-only:
// exports a CSV for a human to apply manually, never writes back to the
// device.

async function getReorderFindings(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT
       rar.id AS finding_id,
       rar.severity,
       rar.detail,
       rar.remediation,
       rar.affected_rule_ids,
       fr.rule_name,
       fr.sequence_number,
       fr.rule_id_vendor
     FROM rule_analysis_results rar
     JOIN firewall_rules fr ON fr.id = rar.rule_id
     WHERE rar.device_id = $1 AND rar.finding_type = 'reorder_candidate'
     ORDER BY fr.sequence_number ASC NULLS LAST`,
    [deviceId]
  );
  return result.rows;
}

// All rules for this device, used to build the id -> {rule_name,
// sequence_number} lookup map for resolving affected_rule_ids entries.
async function getDeviceRules(dbPool, deviceId) {
  const result = await dbPool.query(
    'SELECT id, rule_name, sequence_number FROM firewall_rules WHERE device_id = $1',
    [deviceId]
  );
  return result.rows;
}

async function getAcknowledgements(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT rule_id_vendor, status
     FROM finding_acknowledgements
     WHERE device_id = $1 AND finding_type = 'reorder_candidate'`,
    [deviceId]
  );
  return result.rows;
}

function ruleLabel(row) {
  const seq = row.sequence_number != null ? `#${row.sequence_number}` : '#—';
  return `${seq} ${row.rule_name || '(unnamed rule)'}`;
}

// Resolve a reorder_candidate finding's affected_rule_ids (the earlier allow
// rule(s) that shadow this deny rule) into a human-readable label, using the
// id -> {rule_name, sequence_number} map built from the device's full rule
// snapshot. An id that isn't found (e.g. that rule was itself removed since
// the analysis last ran) falls back to a placeholder rather than crashing.
function shadowingRuleLabel(affectedRuleIds, ruleMap) {
  const ids = Array.isArray(affectedRuleIds) ? affectedRuleIds : [];
  if (ids.length === 0) return '—';
  return ids
    .map((id) => {
      const match = ruleMap.get(id);
      if (!match) return '(rule no longer present)';
      const seq = match.sequence_number != null ? `#${match.sequence_number}` : '#—';
      return `${seq} ${match.rule_name || '(unnamed rule)'}`;
    })
    .join(', ');
}

export default async function ReorderTab({ deviceId, canWrite = false }) {
  const [findings, deviceRules, acks] = await Promise.all([
    getReorderFindings(pool, deviceId),
    getDeviceRules(pool, deviceId),
    getAcknowledgements(pool, deviceId),
  ]);

  if (findings.length === 0) {
    return (
      <EmptyState message="No reorder findings — rules whose traffic is already fully covered by an earlier allow rule will appear here." />
    );
  }

  const ruleMap = new Map(deviceRules.map((r) => [r.id, r]));
  const ackMap = new Map(acks.map((a) => [a.rule_id_vendor, a.status]));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <a
          href={`/api/devices/${deviceId}/reorder-recommendation?format=csv`}
          className="btn btn-secondary"
          style={{ fontSize: 'var(--text-xs)' }}
        >
          Export Recommended Order
        </a>
      </div>
      <Table>
      <colgroup>
        <col style={{ width: '9%' }} />
        <col style={{ width: '20%' }} />
        <col style={{ width: '20%' }} />
        <col style={{ width: '37%' }} />
        <col style={{ width: '14%' }} />
      </colgroup>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Shadowed Rule (Deny)</th>
          <th>Shadowing Rule (Allow)</th>
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
            <td title={ruleLabel(row)}>{ruleLabel(row)}</td>
            <td title={shadowingRuleLabel(row.affected_rule_ids, ruleMap)}>
              {shadowingRuleLabel(row.affected_rule_ids, ruleMap)}
            </td>
            <td style={{ color: 'var(--text-secondary)' }} title={row.detail || ''}>
              {row.detail || '—'}
            </td>
            <td>
              {canWrite && row.rule_id_vendor ? (
                <AcknowledgeControl
                  deviceId={deviceId}
                  ruleIdVendor={row.rule_id_vendor}
                  findingType="reorder_candidate"
                  currentStatus={ackMap.get(row.rule_id_vendor) || 'new'}
                />
              ) : canWrite ? (
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>—</span>
              ) : (
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                  {ackMap.get(row.rule_id_vendor) || 'new'}
                </span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
    </div>
  );
}
