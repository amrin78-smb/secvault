import Link from 'next/link';
import { pool } from '../../../../../../lib/db';
import PageHeader from '../../../../../../components/ui/PageHeader';
import Badge from '../../../../../../components/ui/Badge';
import Card, { CardBody } from '../../../../../../components/ui/Card';
import EmptyState from '../../../../../../components/ui/EmptyState';
import RuleEvidenceTable from '../../../../../../components/compliance/RuleEvidenceTable';
import { isValidUuid } from '../../../../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

// Dedicated per-check detail page — a REAL page navigation, not a same-page
// anchor/expand. Added 2026-07-18 after a user explicitly reported that
// clicking a failed check from a StandardCard's "Failed: N" list only
// scrolled to a shared table further down the SAME page (the original
// rule-evidence drill-down design) instead of opening a distinct page for
// that one check — this route is the fix. StandardTabs.js's inline
// expand/RuleEvidenceTable rendering (for browsing the full per-standard
// table) is UNCHANGED and still exists as a secondary, at-a-glance option;
// this page is now the PRIMARY interaction for a single named check, linked
// from both StandardCard's failed-check list and the check-name cell in
// StandardTabs' table.
//
// Same "server component queries the DB directly" convention as the sibling
// compliance/[deviceId]/page.js — deliberately duplicates a chunk of that
// page's query/resolution logic rather than importing it (neither file
// exports its helpers), matching this app's established per-file-duplication
// tradeoff for small queries.
//
// audit_findings rows are fully DELETE+reinserted on every compliance run
// (see lib/engines/configAuditor.js) — a findingId from an OLDER run can
// legitimately 404 here if a re-run has already happened. Handled as a
// clear "this check result has changed since you followed that link,
// showing the current view" message, not a raw 404, since it's an expected,
// recoverable state, not a broken link.

function formatDateTime(value) {
  if (!value) return 'Never run';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'Never run';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

const STATUS_BADGE = {
  pass: { label: 'Pass', color: 'success' },
  fail: { label: 'Fail', color: 'danger' },
  warning: { label: 'Warning', color: 'warning' },
  na: { label: 'N/A', color: 'muted' },
};

const SEVERITY_BADGE = {
  critical: { label: 'Critical', color: 'danger' },
  high: { label: 'High', color: 'warning' },
  medium: { label: 'Medium', color: 'info' },
  low: { label: 'Low', color: 'muted' },
  info: { label: 'Info', color: 'muted' },
};

async function getDevice(dbPool, id) {
  const result = await dbPool.query('SELECT id, name, vendor FROM devices WHERE id = $1', [id]);
  return result.rows[0] || null;
}

async function getFinding(dbPool, deviceId, findingId) {
  const result = await dbPool.query(
    `SELECT af.id, ac.check_id AS check_slug, ac.name, ac.description, ac.severity,
            ac.standards, af.status, af.detail, ac.remediation_guidance, af.detected_at,
            af.matched_rule_ids
     FROM audit_findings af
     JOIN audit_checks ac ON ac.id = af.check_id
     WHERE af.id = $1 AND af.device_id = $2`,
    [findingId, deviceId]
  );
  return result.rows[0] || null;
}

async function getRuleEvidence(dbPool, ruleIds) {
  if (!ruleIds || ruleIds.length === 0) return [];
  const result = await dbPool.query(
    `SELECT id, rule_name, action, src_addresses, dst_addresses, services, src_zones, dst_zones
     FROM firewall_rules
     WHERE id = ANY($1::uuid[])`,
    [ruleIds]
  );
  return result.rows;
}

function backLink(deviceId, standardKey) {
  const base = `/compliance/${deviceId}`;
  // Point at the standards sub-page, not the summary page's own URL — the
  // 2026-07-18 split moved StandardTabs' hashchange/scrollIntoView handling
  // off compliance/[deviceId]/page.js onto compliance/[deviceId]/standards/
  // page.js, so a #standardKey anchor on the summary page's own URL is inert.
  return standardKey ? `${base}/standards#${standardKey}` : base;
}

export default async function ComplianceCheckDetailPage({ params }) {
  if (!isValidUuid(params.deviceId) || !isValidUuid(params.findingId)) {
    return (
      <div>
        <Link href="/compliance" style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
          ← Back to Compliance
        </Link>
        <p style={{ marginTop: 16, color: 'var(--text-secondary)' }}>Invalid link.</p>
      </div>
    );
  }

  const device = await getDevice(pool, params.deviceId);
  if (!device) {
    return (
      <div>
        <Link href="/compliance" style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
          ← Back to Compliance
        </Link>
        <p style={{ marginTop: 16, color: 'var(--text-secondary)' }}>Device not found.</p>
      </div>
    );
  }

  const finding = await getFinding(pool, device.id, params.findingId);
  if (!finding) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Link href={backLink(device.id)} style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
          ← Back to Compliance — {device.name}
        </Link>
        <EmptyState message="This check result is from an earlier audit run and no longer exists — compliance findings are recomputed on every run. Go back and open the check from the current results." />
      </div>
    );
  }

  const ruleEvidence = await getRuleEvidence(pool, finding.matched_rule_ids);
  const sev = SEVERITY_BADGE[finding.severity] || SEVERITY_BADGE.info;
  const st = STATUS_BADGE[finding.status] || STATUS_BADGE.na;
  const standards = Array.isArray(finding.standards) ? finding.standards : [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <Link
          href={backLink(device.id, standards[0])}
          style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}
        >
          ← Back to Compliance — {device.name}
        </Link>
      </div>

      <PageHeader
        title={finding.name}
        subtitle={
          <span style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <Badge color="info">{device.vendor}</Badge>
            <Badge color={sev.color}>{sev.label}</Badge>
            <Badge color={st.color}>{st.label}</Badge>
            {standards.map((s) => (
              <Badge key={s} color="muted">
                {s}
              </Badge>
            ))}
            <span>Last checked: {formatDateTime(finding.detected_at)}</span>
          </span>
        }
      />

      <Card>
        <CardBody>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {finding.description && (
              <div>
                <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, marginBottom: 4 }}>What this checks</div>
                <p style={{ margin: 0, color: 'var(--text-secondary)' }}>{finding.description}</p>
              </div>
            )}

            <div>
              <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, marginBottom: 4 }}>Result</div>
              <p style={{ margin: 0, color: 'var(--text-secondary)' }}>{finding.detail || '—'}</p>
            </div>

            {finding.remediation_guidance && (
              <div>
                <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, marginBottom: 4 }}>Recommendation</div>
                <p style={{ margin: 0, color: 'var(--text-secondary)' }}>{finding.remediation_guidance}</p>
              </div>
            )}
          </div>
        </CardBody>
      </Card>

      {ruleEvidence.length > 0 && (
        <Card>
          <CardBody>
            <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, marginBottom: 8 }}>
              Offending rule{ruleEvidence.length === 1 ? '' : 's'} ({ruleEvidence.length})
            </div>
            <RuleEvidenceTable rules={ruleEvidence} />
          </CardBody>
        </Card>
      )}
    </div>
  );
}
