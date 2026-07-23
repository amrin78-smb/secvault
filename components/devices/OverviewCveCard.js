import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import StatCard from '../ui/StatCard';
import CVETable from '../cve/CVETable';

// Overview-tab card: patch-now/scheduled counts + a short "needs attention"
// CVE table, reusing the EXISTING CVETable component (same rows shape
// devices/[id]/page.js's own CVE Posture tab already queries) rather than a
// new table implementation. Async server component with its OWN query — same
// "widget owns its DB access" convention as components/dashboard/
// ConfigChangesWidget.js.
//
// Deliberately does NOT render an "Affected Feature" column or a "High Risk
// Issues" tile — neither concept exists in this app's data model (confirmed
// during this feature's own feasibility research): advisories carries no
// human component/feature label, and there is no combined CVE+rule-finding
// metric computed anywhere. Only real, already-collected fields are shown.

const TOP_LIMIT = 5;

async function getOverviewCveData(deviceId) {
  const { rows } = await pool.query(
    `SELECT a.cve_id, a.cvss_score, dca.kev_listed, dca.priority_band, dca.fixed_in, dca.is_fixed_recommended
     FROM device_cve_assessments dca
     JOIN advisories a ON a.id = dca.advisory_id
     WHERE dca.device_id = $1
     ORDER BY
       CASE dca.priority_band WHEN 'patch_now' THEN 0 WHEN 'scheduled' THEN 1 ELSE 2 END,
       a.cvss_score DESC NULLS LAST`,
    [deviceId]
  );
  const patchNowCount = rows.filter((r) => r.priority_band === 'patch_now').length;
  const scheduledCount = rows.filter((r) => r.priority_band === 'scheduled').length;
  return { total: rows.length, patchNowCount, scheduledCount, topRows: rows.slice(0, TOP_LIMIT) };
}

export default async function OverviewCveCard({ deviceId }) {
  const { total, patchNowCount, scheduledCount, topRows } = await getOverviewCveData(deviceId);

  return (
    <Card>
      <CardBody>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'baseline', justifyContent: 'space-between', gap: 12, marginBottom: 16 }}>
          <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)' }}>
            Top CVEs Requiring Attention
          </div>
          <Link href={`/devices/${deviceId}?tab=cve`} style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
            View all CVEs →
          </Link>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 16, marginBottom: 16 }}>
          <StatCard label="Patch Now" value={patchNowCount} color={patchNowCount > 0 ? 'var(--red)' : 'var(--text-muted)'} />
          <StatCard label="Scheduled" value={scheduledCount} color={scheduledCount > 0 ? 'var(--yellow)' : 'var(--text-muted)'} />
          <StatCard label="Total Tracked CVEs" value={total} color="var(--text-muted)" />
        </div>

        <CVETable rows={topRows} />
      </CardBody>
    </Card>
  );
}
