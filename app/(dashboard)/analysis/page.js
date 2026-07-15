import Link from 'next/link';
import { pool } from '../../../lib/db';
import Table from '../../../components/ui/Table';
import EmptyState from '../../../components/ui/EmptyState';

export const dynamic = 'force-dynamic';

// One row per active device, with per-severity finding counts. LEFT JOIN so
// devices with zero findings still appear (all counts render as 0).
async function getFleetRows(dbPool) {
  const result = await dbPool.query(
    `SELECT
       d.id,
       d.name,
       d.vendor,
       d.site,
       COUNT(rar.id) FILTER (WHERE rar.severity = 'critical')::int AS critical,
       COUNT(rar.id) FILTER (WHERE rar.severity = 'high')::int AS high,
       COUNT(rar.id) FILTER (WHERE rar.severity = 'medium')::int AS medium,
       COUNT(rar.id) FILTER (WHERE rar.severity = 'info')::int AS info,
       COUNT(rar.id)::int AS total
     FROM devices d
     LEFT JOIN rule_analysis_results rar ON rar.device_id = d.id
     WHERE d.active = true
     GROUP BY d.id, d.name, d.vendor, d.site
     ORDER BY critical DESC, high DESC, total DESC, d.name ASC`
  );
  return result.rows;
}

export default async function FleetAnalysisPage() {
  const rows = await getFleetRows(pool);

  const totals = rows.reduce(
    (acc, r) => ({
      critical: acc.critical + r.critical,
      high: acc.high + r.high,
      medium: acc.medium + r.medium,
      info: acc.info + r.info,
      total: acc.total + r.total,
    }),
    { critical: 0, high: 0, medium: 0, info: 0, total: 0 }
  );

  return (
    <div className="space-y-6">
      <h1 className="text-lg font-semibold text-text-primary">Rule Health — Fleet</h1>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
        <div className="rounded-lg border border-border bg-bg-surface p-4">
          <div className="text-xs uppercase tracking-wide text-text-muted">Critical</div>
          <div className="mt-1 text-2xl font-semibold text-danger">{totals.critical}</div>
        </div>
        <div className="rounded-lg border border-border bg-bg-surface p-4">
          <div className="text-xs uppercase tracking-wide text-text-muted">High</div>
          <div className="mt-1 text-2xl font-semibold text-warning">{totals.high}</div>
        </div>
        <div className="rounded-lg border border-border bg-bg-surface p-4">
          <div className="text-xs uppercase tracking-wide text-text-muted">Medium</div>
          <div className="mt-1 text-2xl font-semibold text-info">{totals.medium}</div>
        </div>
        <div className="rounded-lg border border-border bg-bg-surface p-4">
          <div className="text-xs uppercase tracking-wide text-text-muted">Info</div>
          <div className="mt-1 text-2xl font-semibold text-text-muted">{totals.info}</div>
        </div>
        <div className="rounded-lg border border-border bg-bg-surface p-4">
          <div className="text-xs uppercase tracking-wide text-text-muted">Total Findings</div>
          <div className="mt-1 text-2xl font-semibold text-text-primary">{totals.total}</div>
        </div>
      </div>

      {rows.length === 0 ? (
        <EmptyState message="No active devices — add devices to see rule health." />
      ) : (
        <Table>
          <colgroup>
            <col style={{ width: '26%' }} />
            <col style={{ width: '13%' }} />
            <col style={{ width: '16%' }} />
            <col style={{ width: '9%' }} />
            <col style={{ width: '9%' }} />
            <col style={{ width: '9%' }} />
            <col style={{ width: '9%' }} />
            <col style={{ width: '9%' }} />
          </colgroup>
          <thead>
            <tr className="border-b border-border bg-bg-surface text-left text-text-secondary">
              <th className="px-2 py-2">Device</th>
              <th className="px-2 py-2">Vendor</th>
              <th className="px-2 py-2">Site</th>
              <th className="px-2 py-2">Critical</th>
              <th className="px-2 py-2">High</th>
              <th className="px-2 py-2">Medium</th>
              <th className="px-2 py-2">Info</th>
              <th className="px-2 py-2">Total</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="border-b border-border">
                <td className="truncate px-2 py-2" title={r.name}>
                  <Link href={`/devices/${r.id}/analysis`} className="text-accent hover:underline">
                    {r.name}
                  </Link>
                </td>
                <td className="px-2 py-2 text-text-secondary">{r.vendor || '—'}</td>
                <td className="truncate px-2 py-2 text-text-secondary" title={r.site || ''}>
                  {r.site || '—'}
                </td>
                <td className={`px-2 py-2 ${r.critical > 0 ? 'font-medium text-danger' : 'text-text-muted'}`}>
                  {r.critical}
                </td>
                <td className={`px-2 py-2 ${r.high > 0 ? 'font-medium text-warning' : 'text-text-muted'}`}>
                  {r.high}
                </td>
                <td className={`px-2 py-2 ${r.medium > 0 ? 'text-info' : 'text-text-muted'}`}>{r.medium}</td>
                <td className="px-2 py-2 text-text-muted">{r.info}</td>
                <td className="px-2 py-2 text-text-primary">{r.total}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}
