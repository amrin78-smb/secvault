import { pool } from '../../../lib/db';
import CVETable from '../../../components/cve/CVETable';
import AssessNowButton from '../../../components/cve/AssessNowButton';
import PageHeader from '../../../components/ui/PageHeader';
import StatCard from '../../../components/ui/StatCard';
import Button from '../../../components/ui/Button';

export const dynamic = 'force-dynamic';

const BAND_LABELS = ['patch_now', 'scheduled', 'monitor'];

// ────────────────────────────────────────────────────────────────────────
// NOTE on "Assess Now":
// Used to be a Server Action (`assessNowAction`, 'use server') triggered by a
// plain <form>, calling /api/cve/assess via an internalFetch() cookie-
// forwarding helper with no client JS in front of it -- clicking it did a
// genuine top-level form navigation with zero pending UI, and just sat there
// until runMatchForAllDevices() finished across the whole fleet. Replaced with
// AssessNowButton.js, a client component using the same fetch+spinner+
// router.refresh() pattern as CredentialForm.js/RunAnalysisButton.js/
// DeviceActions.js/SyncNowButton.js.
// ────────────────────────────────────────────────────────────────────────

async function getSummary(dbPool) {
  const result = await dbPool.query(
    `SELECT
       COUNT(DISTINCT dca.advisory_id) AS total_cves,
       COUNT(*) FILTER (WHERE dca.priority_band = 'patch_now') AS patch_now_count,
       COUNT(*) FILTER (WHERE dca.priority_band = 'scheduled') AS scheduled_count,
       COUNT(*) FILTER (WHERE dca.priority_band = 'monitor') AS monitor_count
     FROM device_cve_assessments dca
     JOIN devices d ON d.id = dca.device_id
     WHERE d.active = true`
  );
  return (
    result.rows[0] || { total_cves: 0, patch_now_count: 0, scheduled_count: 0, monitor_count: 0 }
  );
}

async function getFleetCves(dbPool, searchParams) {
  const conditions = ['d.active = true'];
  const params = [];

  const priorityBand = searchParams?.priority_band;
  if (priorityBand && BAND_LABELS.includes(priorityBand)) {
    params.push(priorityBand);
    conditions.push(`dca.priority_band = $${params.length}`);
  }

  const kevOnly = searchParams?.kev_only === '1' || searchParams?.kev_only === 'true';
  if (kevOnly) {
    conditions.push('dca.kev_listed = true');
  }

  const vendor = searchParams?.vendor;
  if (vendor) {
    params.push(vendor);
    conditions.push(`d.vendor = $${params.length}`);
  }

  // CVSS band thresholds are fixed literals (not user input), safe to inline.
  const cvssBand = searchParams?.cvss_band;
  if (cvssBand === 'critical') conditions.push('a.cvss_score >= 9');
  else if (cvssBand === 'high') conditions.push('a.cvss_score >= 7 AND a.cvss_score < 9');
  else if (cvssBand === 'medium') conditions.push('a.cvss_score >= 4 AND a.cvss_score < 7');
  else if (cvssBand === 'low') conditions.push('a.cvss_score < 4');

  const where = `WHERE ${conditions.join(' AND ')}`;

  const sql = `
    SELECT
      a.cve_id,
      a.cvss_score,
      bool_or(dca.kev_listed) AS kev_listed,
      MIN(CASE dca.priority_band WHEN 'patch_now' THEN 0 WHEN 'scheduled' THEN 1 ELSE 2 END) AS band_rank,
      COUNT(DISTINCT dca.device_id)::int AS affected_device_count,
      (array_agg(dca.fixed_in) FILTER (WHERE dca.fixed_in IS NOT NULL))[1] AS fixed_in,
      bool_or(dca.is_fixed_recommended) AS is_fixed_recommended
    FROM device_cve_assessments dca
    JOIN advisories a ON a.id = dca.advisory_id
    JOIN devices d ON d.id = dca.device_id
    ${where}
    GROUP BY a.cve_id, a.cvss_score
    ORDER BY band_rank ASC, a.cvss_score DESC NULLS LAST
    LIMIT 300
  `;

  const result = await dbPool.query(sql, params);
  return result.rows.map((row) => ({
    ...row,
    priority_band: BAND_LABELS[row.band_rank] ?? 'monitor',
  }));
}

export default async function FleetCvePage({ searchParams }) {
  const [summary, rows] = await Promise.all([getSummary(pool), getFleetCves(pool, searchParams)]);

  const priorityBandValue = searchParams?.priority_band || '';
  const kevOnlyChecked = searchParams?.kev_only === '1' || searchParams?.kev_only === 'true';
  const cvssBandValue = searchParams?.cvss_band || '';
  const vendorValue = searchParams?.vendor || '';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <PageHeader title="Fleet CVE Posture" actions={<AssessNowButton />} />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 16 }}>
        <StatCard label="Unique CVEs" value={summary.total_cves} />
        <StatCard label="Patch Now" value={summary.patch_now_count} color="var(--red)" />
        <StatCard label="Scheduled" value={summary.scheduled_count} color="var(--yellow)" />
        <StatCard label="Monitor" value={summary.monitor_count} color="var(--text-muted)" />
      </div>

      <form method="GET" className="filter-row">
        <div className="form-field">
          <label htmlFor="priority_band">Priority Band</label>
          <select id="priority_band" name="priority_band" defaultValue={priorityBandValue} className="select">
            <option value="">All bands</option>
            <option value="patch_now">Patch Now</option>
            <option value="scheduled">Scheduled</option>
            <option value="monitor">Monitor</option>
          </select>
        </div>
        <div className="form-field">
          <label htmlFor="cvss_band">CVSS Band</label>
          <select id="cvss_band" name="cvss_band" defaultValue={cvssBandValue} className="select">
            <option value="">All CVSS</option>
            <option value="critical">Critical (9.0+)</option>
            <option value="high">High (7.0-8.9)</option>
            <option value="medium">Medium (4.0-6.9)</option>
            <option value="low">Low (&lt;4.0)</option>
          </select>
        </div>
        <div className="form-field">
          <label htmlFor="vendor">Vendor</label>
          <select id="vendor" name="vendor" defaultValue={vendorValue} className="select">
            <option value="">All vendors</option>
            <option value="forcepoint">Forcepoint</option>
            <option value="fortinet">Fortinet</option>
            <option value="paloalto">Palo Alto</option>
            <option value="checkpoint">Check Point</option>
            <option value="cisco_asa">Cisco ASA</option>
            <option value="sangfor">Sangfor</option>
          </select>
        </div>
        <label
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            fontSize: 'var(--text-base)',
            color: 'var(--text-secondary)',
          }}
        >
          <input type="checkbox" name="kev_only" value="1" defaultChecked={kevOnlyChecked} />
          KEV only
        </label>
        <Button type="submit" variant="secondary">
          Filter
        </Button>
      </form>

      <CVETable rows={rows} showDeviceColumn deviceColumnLabel="Devices Affected" />
    </div>
  );
}
