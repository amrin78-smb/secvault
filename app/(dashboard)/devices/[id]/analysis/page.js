import Link from 'next/link';
import { pool } from '../../../../../lib/db';
import Table from '../../../../../components/ui/Table';
import EmptyState from '../../../../../components/ui/EmptyState';
import SeverityBadge from '../../../../../components/analysis/SeverityBadge';
import FindingTypeBadge from '../../../../../components/analysis/FindingTypeBadge';
import RunAnalysisButton from '../../../../../components/analysis/RunAnalysisButton';

export const dynamic = 'force-dynamic';

function formatDateTime(value) {
  if (!value) return 'Never';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'Never';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

async function getDevice(dbPool, id) {
  const result = await dbPool.query('SELECT id, name FROM devices WHERE id = $1', [id]);
  return result.rows[0] || null;
}

async function getSummary(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT
       COUNT(*)::int AS total,
       COUNT(*) FILTER (WHERE severity = 'critical')::int AS critical,
       COUNT(*) FILTER (WHERE severity = 'high')::int AS high,
       COUNT(*) FILTER (WHERE severity = 'medium')::int AS medium,
       COUNT(*) FILTER (WHERE severity = 'info')::int AS info,
       MAX(analyzed_at) AS last_analyzed_at
     FROM rule_analysis_results
     WHERE device_id = $1`,
    [deviceId]
  );
  return result.rows[0] || { total: 0, critical: 0, high: 0, medium: 0, info: 0, last_analyzed_at: null };
}

async function getFindings(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT
       rar.id,
       rar.finding_type,
       rar.severity,
       rar.detail,
       rar.remediation,
       fr.rule_name,
       fr.sequence_number
     FROM rule_analysis_results rar
     JOIN firewall_rules fr ON fr.id = rar.rule_id
     WHERE rar.device_id = $1
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

export default async function DeviceAnalysisPage({ params }) {
  const device = await getDevice(pool, params.id);

  if (!device) {
    return (
      <div>
        <Link href="/devices" className="text-sm text-accent hover:underline">
          ← Back to devices
        </Link>
        <p className="mt-4 text-text-secondary">Device not found.</p>
      </div>
    );
  }

  const [summary, findings] = await Promise.all([
    getSummary(pool, device.id),
    getFindings(pool, device.id),
  ]);

  return (
    <div className="space-y-6">
      <div>
        <Link href={`/devices/${device.id}`} className="text-sm text-accent hover:underline">
          ← Back to {device.name}
        </Link>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-lg font-semibold text-text-primary">Rule Analysis — {device.name}</h1>
        <RunAnalysisButton deviceId={device.id} />
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
        <div className="rounded-lg border border-border bg-bg-surface p-4">
          <div className="text-xs uppercase tracking-wide text-text-muted">Critical</div>
          <div className="mt-1 text-2xl font-semibold text-danger">{summary.critical}</div>
        </div>
        <div className="rounded-lg border border-border bg-bg-surface p-4">
          <div className="text-xs uppercase tracking-wide text-text-muted">High</div>
          <div className="mt-1 text-2xl font-semibold text-warning">{summary.high}</div>
        </div>
        <div className="rounded-lg border border-border bg-bg-surface p-4">
          <div className="text-xs uppercase tracking-wide text-text-muted">Medium</div>
          <div className="mt-1 text-2xl font-semibold text-info">{summary.medium}</div>
        </div>
        <div className="rounded-lg border border-border bg-bg-surface p-4">
          <div className="text-xs uppercase tracking-wide text-text-muted">Info</div>
          <div className="mt-1 text-2xl font-semibold text-text-muted">{summary.info}</div>
        </div>
        <div className="rounded-lg border border-border bg-bg-surface p-4">
          <div className="text-xs uppercase tracking-wide text-text-muted">Total Findings</div>
          <div className="mt-1 text-2xl font-semibold text-text-primary">{summary.total}</div>
        </div>
        <div className="rounded-lg border border-border bg-bg-surface p-4">
          <div className="text-xs uppercase tracking-wide text-text-muted">Last Analyzed</div>
          <div className="mt-1 text-sm font-medium text-text-primary">
            {formatDateTime(summary.last_analyzed_at)}
          </div>
        </div>
      </div>

      {findings.length === 0 ? (
        <EmptyState message="No findings — run analysis or collect rules first." />
      ) : (
        <Table>
          <colgroup>
            <col style={{ width: '9%' }} />
            <col style={{ width: '13%' }} />
            <col style={{ width: '20%' }} />
            <col style={{ width: '31%' }} />
            <col style={{ width: '27%' }} />
          </colgroup>
          <thead>
            <tr className="border-b border-border bg-bg-surface text-left text-text-secondary">
              <th className="px-2 py-2">Severity</th>
              <th className="px-2 py-2">Type</th>
              <th className="px-2 py-2">Rule</th>
              <th className="px-2 py-2">Detail</th>
              <th className="px-2 py-2">Remediation</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id} className="border-b border-border">
                <td className="px-2 py-2">
                  <SeverityBadge severity={f.severity} />
                </td>
                <td className="px-2 py-2">
                  <FindingTypeBadge type={f.finding_type} />
                </td>
                <td className="truncate px-2 py-2" title={ruleLabel(f)}>
                  <Link href={`/devices/${device.id}/rules`} className="text-accent hover:underline">
                    {ruleLabel(f)}
                  </Link>
                </td>
                <td className="px-2 py-2 text-text-secondary" title={f.detail || ''}>
                  {f.detail || '—'}
                </td>
                <td className="px-2 py-2 text-text-secondary" title={f.remediation || ''}>
                  {f.remediation || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}
