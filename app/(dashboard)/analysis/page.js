import Link from 'next/link';
import { pool } from '../../../lib/db';
import Table from '../../../components/ui/Table';
import Badge from '../../../components/ui/Badge';
import EmptyState from '../../../components/ui/EmptyState';
import StatCard from '../../../components/ui/StatCard';
import PageHeader from '../../../components/ui/PageHeader';
import { computeRiskScoreFromCounts } from '../../../lib/engines/riskScore';

export const dynamic = 'force-dynamic';

// Same convention as devices/[id]/analysis/page.js.
const RISK_BAND_COLOR = { low: 'success', medium: 'info', high: 'warning', critical: 'danger' };
const RISK_BAND_LABEL = { low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' };

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
  const rawRows = await getFleetRows(pool);
  const rows = rawRows.map((r) => ({ ...r, risk: computeRiskScoreFromCounts(r) }));

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
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <PageHeader title="Rule Health — Fleet" />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 16 }}>
        <StatCard label="Critical" value={totals.critical} color={totals.critical > 0 ? 'var(--red)' : 'var(--text-muted)'} />
        <StatCard label="High" value={totals.high} color={totals.high > 0 ? 'var(--yellow)' : 'var(--text-muted)'} />
        <StatCard label="Medium" value={totals.medium} color={totals.medium > 0 ? 'var(--blue)' : 'var(--text-muted)'} />
        <StatCard label="Info" value={totals.info} color="var(--text-muted)" />
        <StatCard label="Total Findings" value={totals.total} color="var(--text-primary)" />
      </div>

      {rows.length === 0 ? (
        <EmptyState message="No active devices — add devices to see rule health." />
      ) : (
        <Table>
          <colgroup>
            <col style={{ width: '20%' }} />
            <col style={{ width: '11%' }} />
            <col style={{ width: '13%' }} />
            <col style={{ width: '13%' }} />
            <col style={{ width: '8%' }} />
            <col style={{ width: '8%' }} />
            <col style={{ width: '8%' }} />
            <col style={{ width: '8%' }} />
            <col style={{ width: '11%' }} />
          </colgroup>
          <thead>
            <tr>
              <th>Device</th>
              <th>Vendor</th>
              <th>Site</th>
              <th>Risk</th>
              <th>Critical</th>
              <th>High</th>
              <th>Medium</th>
              <th>Info</th>
              <th>Total</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td title={r.name}>
                  <Link href={`/devices/${r.id}/analysis`} className="link-quiet">
                    {r.name}
                  </Link>
                </td>
                <td style={{ color: 'var(--text-secondary)' }}>{r.vendor || '—'}</td>
                <td style={{ color: 'var(--text-secondary)' }} title={r.site || ''}>
                  {r.site || '—'}
                </td>
                <td>
                  <Badge color={RISK_BAND_COLOR[r.risk.band]}>
                    {RISK_BAND_LABEL[r.risk.band]} ({r.risk.score})
                  </Badge>
                </td>
                <td
                  style={{
                    color: r.critical > 0 ? 'var(--red)' : 'var(--text-muted)',
                    fontWeight: r.critical > 0 ? 600 : 400,
                  }}
                >
                  {r.critical}
                </td>
                <td
                  style={{
                    color: r.high > 0 ? 'var(--yellow)' : 'var(--text-muted)',
                    fontWeight: r.high > 0 ? 600 : 400,
                  }}
                >
                  {r.high}
                </td>
                <td style={{ color: r.medium > 0 ? 'var(--blue)' : 'var(--text-muted)' }}>{r.medium}</td>
                <td style={{ color: 'var(--text-muted)' }}>{r.info}</td>
                <td>{r.total}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </div>
  );
}
