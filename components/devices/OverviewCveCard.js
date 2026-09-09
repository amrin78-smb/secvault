import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import StatCard from '../ui/StatCard';
import NotMeasured from '../ui/NotMeasured';
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

// ⛔ ZERO ASSESSMENTS IS NOT ZERO CVEs. versionMatcher.js's
// runMatchForAllDevices() skips any device with no device_versions row
// outright ("no version row - skipped"), so an un-versioned device holds zero
// device_cve_assessments rows and used to render three confident zeros here —
// the failed-read-as-a-fact bug, one layer up in the UI. The version row is
// the one thing that definitively separates "never assessed" from "assessed
// and clean", so it is fetched alongside the assessments.
//
// ⛔ What this still CANNOT tell apart (deliberately not guessed): a device
// that HAS a version and zero assessments may be genuinely clean or may never
// have had the matcher run over it. matchDeviceToAdvisories() only emits rows
// for advisories that still apply and the reconciliation DELETE removes the
// rest, so no assessed_at survives for a clean device. Fixing that needs a
// persisted `devices.last_cve_assessed_at` — see the full note in
// components/devices/DevicePostureCells.js's CveCell.
async function getOverviewCveData(deviceId) {
  const [assessments, versions] = await Promise.all([
    pool.query(
      `SELECT a.cve_id, a.cvss_score, dca.kev_listed, dca.priority_band, dca.fixed_in, dca.is_fixed_recommended
       FROM device_cve_assessments dca
       JOIN advisories a ON a.id = dca.advisory_id
       WHERE dca.device_id = $1
       ORDER BY
         CASE dca.priority_band WHEN 'patch_now' THEN 0 WHEN 'scheduled' THEN 1 ELSE 2 END,
         a.cvss_score DESC NULLS LAST`,
      [deviceId]
    ),
    pool.query('SELECT 1 FROM device_versions WHERE device_id = $1 LIMIT 1', [deviceId]),
  ]);
  const rows = assessments.rows;
  const patchNowCount = rows.filter((r) => r.priority_band === 'patch_now').length;
  const scheduledCount = rows.filter((r) => r.priority_band === 'scheduled').length;
  return {
    total: rows.length,
    patchNowCount,
    scheduledCount,
    topRows: rows.slice(0, TOP_LIMIT),
    hasVersion: versions.rows.length > 0,
  };
}

const NO_VERSION_REASON =
  'No firmware version has been collected from this device, so CVE matching has never run for it. This is an absence of assessment, not a clean result.';

export default async function OverviewCveCard({ deviceId }) {
  const { total, patchNowCount, scheduledCount, topRows, hasVersion } =
    await getOverviewCveData(deviceId);

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
          <StatCard
            label="Patch Now"
            value={hasVersion ? patchNowCount : <NotMeasured reason={NO_VERSION_REASON} />}
            color={
              !hasVersion ? 'var(--unmeasured)' : patchNowCount > 0 ? 'var(--red)' : 'var(--text-muted)'
            }
          />
          <StatCard
            label="Scheduled"
            value={hasVersion ? scheduledCount : <NotMeasured reason={NO_VERSION_REASON} />}
            color={
              !hasVersion ? 'var(--unmeasured)' : scheduledCount > 0 ? 'var(--yellow)' : 'var(--text-muted)'
            }
          />
          <StatCard
            label="Total Tracked CVEs"
            value={hasVersion ? total : <NotMeasured reason={NO_VERSION_REASON} />}
            color={hasVersion ? 'var(--text-muted)' : 'var(--unmeasured)'}
          />
        </div>

        {/* ⛔ CVETable's built-in empty row reads "No CVEs found.", which is
            indistinguishable from a real clean result. It is a shared component
            (components/cve/CVETable.js) and is not edited from here, so the
            honest sentence replaces the table when there is nothing to show. */}
        {topRows.length === 0 ? (
          <div
            style={{
              border: '1px dashed var(--border)',
              borderRadius: 'var(--radius)',
              padding: 'var(--s5) var(--s4)',
              fontSize: 'var(--text-base)',
              color: 'var(--text-muted)',
            }}
          >
            {hasVersion
              ? 'No advisory currently applies to this device’s collected version. Rerun an assessment after the next version pull to keep this current.'
              : NO_VERSION_REASON}
          </div>
        ) : (
          <CVETable rows={topRows} />
        )}
      </CardBody>
    </Card>
  );
}
