import Link from 'next/link';
import { pool } from '../../../../../lib/db';
import PageHeader from '../../../../../components/ui/PageHeader';
import Badge from '../../../../../components/ui/Badge';
import EmptyState from '../../../../../components/ui/EmptyState';
import StandardTabs from '../../../../../components/compliance/StandardTabs';
import { STANDARDS } from '../../../../../components/compliance/ComplianceMatrix';
import { isValidUuid } from '../../../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

// Dedicated "All Checks" page — a REAL page, not content stacked below the
// StandardCard grid on compliance/[deviceId]/page.js. Split out 2026-07-18
// after a user reported that page required scrolling past 5 summary cards
// to reach the browsable tabs+table, immediately after the SAME feedback
// had already moved single-check drill-down onto its own page
// (checks/[findingId]/page.js) — this closes the other half of the same
// complaint. compliance/[deviceId]/page.js is now JUST the summary cards;
// this page is JUST the multi-standard browsable table, one click away via
// each StandardCard's "+N more" link or the "View All Checks" header
// action.
//
// Duplicates getDevice/getFindings/getRuleEvidenceMap from the sibling
// compliance/[deviceId]/page.js rather than importing them (neither file
// exports its helpers) — matching this app's established per-file query
// duplication convention (see e.g. the Alerts/events split in CLAUDE.md).

async function getDevice(dbPool, id) {
  const result = await dbPool.query('SELECT id, name, vendor FROM devices WHERE id = $1', [id]);
  return result.rows[0] || null;
}

async function getFindings(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT af.id, ac.id AS check_uuid, ac.check_id AS check_slug, ac.name, ac.severity,
            ac.standards, af.status, af.detail, ac.remediation_guidance, af.detected_at,
            af.matched_rule_ids
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
    matchedRuleIds: Array.isArray(r.matched_rule_ids) ? r.matched_rule_ids : [],
  }));
}

async function getRuleEvidenceMap(dbPool, ruleIds) {
  if (!ruleIds || ruleIds.length === 0) return new Map();
  const result = await dbPool.query(
    `SELECT id, rule_name, action, src_addresses, dst_addresses, services, src_zones, dst_zones
     FROM firewall_rules
     WHERE id = ANY($1::uuid[])`,
    [ruleIds]
  );
  const map = new Map();
  for (const row of result.rows) map.set(row.id, row);
  return map;
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

export default async function ComplianceStandardsPage({ params }) {
  if (!isValidUuid(params.deviceId)) {
    return notFound();
  }

  const device = await getDevice(pool, params.deviceId);
  if (!device) {
    return notFound();
  }

  const findingsRaw = await getFindings(pool, device.id);
  const allRuleIds = Array.from(new Set(findingsRaw.flatMap((f) => f.matchedRuleIds || [])));
  const ruleMap = await getRuleEvidenceMap(pool, allRuleIds);
  const findings = findingsRaw.map((f) => ({
    ...f,
    ruleEvidence: (f.matchedRuleIds || []).map((id) => ruleMap.get(id)).filter(Boolean),
  }));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <Link href={`/compliance/${device.id}`} style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
          ← Back to Compliance — {device.name}
        </Link>
      </div>

      <PageHeader
        title={`All Checks — ${device.name}`}
        subtitle={<Badge color="info">{device.vendor}</Badge>}
      />

      {findings.length === 0 ? (
        <EmptyState message="No compliance findings yet — run an audit to see results." />
      ) : (
        <StandardTabs standards={STANDARDS} findings={findings} deviceId={device.id} />
      )}
    </div>
  );
}
