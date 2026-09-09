import Link from 'next/link';
import { pool } from '../../lib/db';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';
import { BAND_BADGE_COLOR, BAND_LABEL } from '../analysis/severityRamp';

// Dashboard widget: top-N active devices by their LATEST rule-analysis risk
// score. device_risk_history is populated every time runAnalysisForDevice()
// runs (lib/engines/ruleAnalysis.js) -- both scheduled collects and manual
// "Run Analysis" clicks -- see CLAUDE.md's Rule Analysis Dashboard Phase 4
// section. "Latest row per device" via a LATERAL join, same pattern
// app/(dashboard)/page.js's getDevices() already uses for
// device_versions/device_cve_assessments. INNER JOIN LATERAL deliberately
// (not LEFT) -- a device with no risk history yet has nothing to rank and
// should simply not appear in this widget.
//
// ⛔ Bands come from components/analysis/severityRamp.js — one source, not a
// local copy kept "in step" by comment. This file's copy was still the
// pre-v2.87.0 ramp, so a medium-risk device wore a BLUE badge one step from
// the --primary brand hue.

async function getTopRiskyDevices(dbPool, limit) {
  const { rows } = await dbPool.query(
    `SELECT d.id, d.name, d.vendor, latest.score, latest.band, latest.recorded_at
     FROM devices d
     JOIN LATERAL (
       SELECT score, band, recorded_at
       FROM device_risk_history
       WHERE device_risk_history.device_id = d.id
       ORDER BY recorded_at DESC
       LIMIT 1
     ) latest ON true
     WHERE d.active = true
     ORDER BY latest.score DESC
     LIMIT $1`,
    [limit]
  );
  return rows;
}

// limit: how many devices to show, default 5 (a typical "top N" dashboard
// widget size -- callers may override for a denser/lighter layout).
export default async function TopRiskyDevices({ limit = 5 }) {
  const devices = await getTopRiskyDevices(pool, limit);

  if (devices.length === 0) {
    return <EmptyState message="Run rule analysis on a device to see its risk score here." />;
  }

  return (
    <Table className="dashboard-compact-table">
      <colgroup>
        <col style={{ width: '42%' }} />
        <col style={{ width: '26%' }} />
        <col style={{ width: '32%' }} />
      </colgroup>
      <thead>
        <tr>
          <th>Device</th>
          <th>Vendor</th>
          <th>Risk Score</th>
        </tr>
      </thead>
      <tbody>
        {devices.map((device) => (
          <tr key={device.id}>
            <td>
              <Link href={`/devices/${device.id}/analysis?tab=risk`} className="link-quiet">
                {device.name}
              </Link>
            </td>
            <td>
              <Badge color="info">{device.vendor}</Badge>
            </td>
            <td>
              <Badge color={BAND_BADGE_COLOR[device.band] || 'muted'}>
                {BAND_LABEL[device.band] || device.band} ({device.score})
              </Badge>
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
