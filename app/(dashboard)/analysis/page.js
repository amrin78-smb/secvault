import Link from 'next/link';
import { vendorLabel } from '../../../components/devices/vendorMeta';
import { pool } from '../../../lib/db';
import Table from '../../../components/ui/Table';
import Badge from '../../../components/ui/Badge';
import EmptyState from '../../../components/ui/EmptyState';
import StatCard from '../../../components/ui/StatCard';
import PageHeader from '../../../components/ui/PageHeader';
import { computeRiskScoreFromCounts } from '../../../lib/engines/riskScore';
import {
  BAND_BADGE_COLOR,
  BAND_LABEL,
  SEVERITY_FILL,
  SEVERITY_TEXT_COLOR,
} from '../../../components/analysis/severityRamp';

export const dynamic = 'force-dynamic';

// ⛔ Band colours and labels come from components/analysis/severityRamp.js
// and are NOT redeclared here. The private copy this file used to hold was the
// pre-v2.87.0 ramp: `medium` rendered BLUE (one step from --primary teal, which
// the palette rewrite forbade on any severity) and `high` rendered --yellow,
// the ramp's MEDIUM hue, so a high-risk device and a medium-risk one argued
// over one colour.

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
       COUNT(rar.id)::int AS total,
       MAX(rar.analyzed_at) AS last_analyzed_at
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
      <PageHeader
        title="Rule hygiene — Fleet"
        subtitle="Rule findings across every active firewall. Open a firewall to see its cleanup, optimization and reorder detail."
      />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 16 }}>
        {/* Tile accents are GRAPHICS (a 4px left border), so they take the raw
            --sev-* hues via SEVERITY_FILL. The table cells below are TEXT and
            take SEVERITY_TEXT_COLOR instead — see severityRamp.js. */}
        <StatCard label="Critical" value={totals.critical} color={totals.critical > 0 ? SEVERITY_FILL.critical : 'var(--text-muted)'} />
        <StatCard label="High" value={totals.high} color={totals.high > 0 ? SEVERITY_FILL.high : 'var(--text-muted)'} />
        <StatCard label="Medium" value={totals.medium} color={totals.medium > 0 ? SEVERITY_FILL.medium : 'var(--text-muted)'} />
        <StatCard label="Info" value={totals.info} color={totals.info > 0 ? SEVERITY_FILL.info : 'var(--text-muted)'} />
        <StatCard label="Total Findings" value={totals.total} color="var(--text-primary)" />
      </div>

      {rows.length === 0 ? (
        <EmptyState message="No active devices — add one to see rule hygiene." />
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
                <td style={{ color: 'var(--text-secondary)' }} title={r.vendor || ''}>
                  {vendorLabel(r.vendor, { short: true }) || '—'}
                </td>
                <td style={{ color: 'var(--text-secondary)' }} title={r.site || ''}>
                  {r.site || '—'}
                </td>
                <td>
                  {/* ⛔ "never analysed" is a REAL state, distinct from "low". A
                      device with no rule_analysis_results rows has earned no band
                      at all and must not be filed under the BEST one:
                      computeRiskScoreFromCounts returns {'{score:0, band:"low"}'} for
                      all-zero counts, so an unanalysed firewall rendered a green
                      "Low (0)" identical to the cleanest device in the fleet.
                      app/(dashboard)/devices/page.js already documents and
                      implements the correct behaviour — these two fleet pages
                      disagreed. Invisible today only because all 15 devices have
                      findings; it fires the day someone adds a firewall, which is
                      exactly when someone is watching. */}
                  {r.last_analyzed_at ? (
                    <Badge color={BAND_BADGE_COLOR[r.risk.band] || 'muted'}>
                      {BAND_LABEL[r.risk.band] || r.risk.band} ({r.risk.score})
                    </Badge>
                  ) : (
                    <Badge
                      color="muted"
                      title="This device has never been analysed, so it has no rule-hygiene band yet"
                    >
                      Not analysed
                    </Badge>
                  )}
                </td>
                {/* ⛔ TABLE-CELL TEXT, not a graphic. --red/--yellow/--blue are
                    the raw ramp hues, and globals.css measures --yellow at
                    3.64:1 on white — it clears 1.4.11's 3:1 for a graphical
                    object and FAILS 1.4.3's 4.5:1 for text. The --tint-*-fg
                    pairs in SEVERITY_TEXT_COLOR clear 4.5:1 in both themes by
                    construction. (The StatCards above are 32px/800 and clear
                    the large-text threshold on the raw hue, so they keep it.) */}
                <td
                  style={{
                    color: r.critical > 0 ? SEVERITY_TEXT_COLOR.critical : 'var(--text-muted)',
                    fontWeight: r.critical > 0 ? 600 : 400,
                  }}
                >
                  {r.critical}
                </td>
                <td
                  style={{
                    color: r.high > 0 ? SEVERITY_TEXT_COLOR.high : 'var(--text-muted)',
                    fontWeight: r.high > 0 ? 600 : 400,
                  }}
                >
                  {r.high}
                </td>
                <td style={{ color: r.medium > 0 ? SEVERITY_TEXT_COLOR.medium : 'var(--text-muted)' }}>{r.medium}</td>
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
