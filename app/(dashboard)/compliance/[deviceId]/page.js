import Link from 'next/link';
import { pool } from '../../../../lib/db';
import PageHeader from '../../../../components/ui/PageHeader';
import Badge from '../../../../components/ui/Badge';
import StatCard from '../../../../components/ui/StatCard';
import EmptyState from '../../../../components/ui/EmptyState';
import RunAuditButton from '../../../../components/compliance/RunAuditButton';
import StandardTabs from '../../../../components/compliance/StandardTabs';
import { STANDARDS, scoreColor, SCORE_COLOR_VAR } from '../../../../components/compliance/ComplianceMatrix';
import { isValidUuid } from '../../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

// Per-device Compliance view. Same "server component queries the DB
// directly for its own render" convention as the fleet page
// (app/(dashboard)/compliance/page.js) and app/(dashboard)/alerts/page.js --
// deliberately duplicates the same scorePct/aggregation formula the sibling
// GET /api/compliance/[deviceId] route computes, rather than internally
// fetching that route for this page's initial render (no page in this app
// self-fetches its own paired API GET route -- checked across app/(dashboard)
// before writing this). RunAuditButton still POSTs to the sibling
// /run route -- that write path is exactly what API routes are for.
//
// Standards tabs are client-side (StandardTabs.js, 'use client') rather than
// this app's usual `?tab=` server-navigation convention (see
// devices/[id]/analysis/page.js) -- deliberate deviation: switching
// standards here only re-filters an ALREADY-FETCHED findings array (the API
// contract returns every standard's findings in one response), there is no
// new per-tab query the way analysis's cleanup/optimization/reorder/risk/
// tracking tabs each run their own.

function formatDateTime(value) {
  if (!value) return 'Never run';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'Never run';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

// Same formula as app/(dashboard)/compliance/page.js's scorePctFromCounts --
// see that file's comment for why 'na' is excluded from the denominator and
// why the result is null (not 0) when nothing is measurable.
function scorePctFromCounts(counts) {
  const measurable = counts.pass + counts.fail + counts.warning;
  return measurable > 0 ? Math.round((counts.pass / measurable) * 100) : null;
}

async function getDevice(dbPool, id) {
  const result = await dbPool.query('SELECT id, name, vendor FROM devices WHERE id = $1', [id]);
  return result.rows[0] || null;
}

async function getFindings(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT af.id, ac.id AS check_uuid, ac.check_id AS check_slug, ac.name, ac.severity,
            ac.standards, af.status, af.detail, ac.remediation_guidance, af.detected_at
     FROM audit_findings af
     JOIN audit_checks ac ON ac.id = af.check_id
     WHERE af.device_id = $1
     ORDER BY
       CASE af.status WHEN 'fail' THEN 0 WHEN 'warning' THEN 1 WHEN 'pass' THEN 2 ELSE 3 END,
       CASE ac.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
       ac.name ASC`,
    [deviceId]
  );
  return result.rows.map((r) => ({
    id: r.id,
    checkId: r.check_uuid,
    checkSlug: r.check_slug,
    name: r.name,
    severity: r.severity,
    standards: Array.isArray(r.standards) ? r.standards : [],
    status: r.status,
    detail: r.detail,
    remediationGuidance: r.remediation_guidance,
    detectedAt: r.detected_at,
  }));
}

function aggregateStandards(findings) {
  const counts = {};
  for (const s of STANDARDS) counts[s.key] = { pass: 0, fail: 0, warning: 0, na: 0, total: 0 };
  for (const f of findings) {
    for (const key of f.standards) {
      if (!counts[key]) continue;
      counts[key][f.status] = (counts[key][f.status] || 0) + 1;
      counts[key].total += 1;
    }
  }
  const result = {};
  for (const s of STANDARDS) {
    result[s.key] = { ...counts[s.key], scorePct: scorePctFromCounts(counts[s.key]) };
  }
  return result;
}

function notFound() {
  return (
    <div>
      <Link href="/compliance" style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
        ← Back to Compliance
      </Link>
      <p style={{ marginTop: 16, color: 'var(--text-secondary)' }}>Device not found.</p>
    </div>
  );
}

export default async function DeviceCompliancePage({ params }) {
  // A malformed deviceId in the URL (stale/hand-edited link) must never reach
  // pool.query() -- Postgres throws a raw "invalid input syntax for type
  // uuid" error for a UUID-typed column, which would crash this page's
  // render. Same guard app/(dashboard)/alerts/page.js applies to its
  // device_id query-param filter.
  if (!isValidUuid(params.deviceId)) {
    return notFound();
  }

  const device = await getDevice(pool, params.deviceId);
  if (!device) {
    return notFound();
  }

  const findings = await getFindings(pool, device.id);
  const standards = aggregateStandards(findings);
  const lastRunAt = findings.reduce((latest, f) => {
    if (!f.detectedAt) return latest;
    return !latest || new Date(f.detectedAt) > new Date(latest) ? f.detectedAt : latest;
  }, null);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <Link href="/compliance" style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
          ← Back to Compliance
        </Link>
      </div>

      <PageHeader
        title={`Compliance — ${device.name}`}
        subtitle={
          <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Badge color="info">{device.vendor}</Badge>
            <span>Last run: {formatDateTime(lastRunAt)}</span>
          </span>
        }
        actions={<RunAuditButton deviceId={device.id} />}
      />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16 }}>
        {STANDARDS.map((s) => {
          const stat = standards[s.key];
          const color = SCORE_COLOR_VAR[scoreColor(stat.scorePct)];
          return (
            <StatCard
              key={s.key}
              label={s.label}
              value={stat.scorePct == null ? '—' : `${stat.scorePct}%`}
              sub={`${stat.pass} pass · ${stat.fail} fail · ${stat.warning} warning · ${stat.na} n/a`}
              color={color}
            />
          );
        })}
      </div>

      {findings.length === 0 ? (
        <EmptyState message="No compliance findings yet — run an audit to see results." />
      ) : (
        <StandardTabs standards={STANDARDS} findings={findings} />
      )}
    </div>
  );
}
