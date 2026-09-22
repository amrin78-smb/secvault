import Link from 'next/link';
import { pool } from '../../../../../lib/db';
import PageHeader from '../../../../../components/ui/PageHeader';
import Badge from '../../../../../components/ui/Badge';
import EmptyState from '../../../../../components/ui/EmptyState';
import StandardTabs from '../../../../../components/compliance/StandardTabs';
import Card, { CardBody } from '../../../../../components/ui/Card';
import { EvidenceMark } from '../../../../../components/ui/Evidence';
import { STANDARDS } from '../../../../../components/compliance/ComplianceMatrix';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { vendorLabel } from '../../../../../components/devices/vendorMeta';
import {
  COVERAGE_CLAIM,
  buildStandardCoverage,
  coverageEvidence,
} from '../../../../../lib/engines/complianceCoverage';

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

// ⛔ THE TABS ON THIS PAGE ARE FRAMEWORK NAMES, so the page has to say what
// standing behind each name actually is. The curated library is 45 checks and a
// check carries a `standards` ARRAY; measured live the five mappings are
// CIS_V8 44 / ISO_27001 35 / PCI_DSS 21 / SANS 12 / NIST 7, three of NIST's
// seven being vendor-scoped. A tab labelled "NIST" over six checks invites the
// reader to treat the contents as a NIST assessment, which they are not.
//
// ⛔ A FAILED READ IS null, NEVER `{mapped: 0}` — "0 of 45 checks map to PCI
// DSS" reads as "SecVault does not support this standard", which is a claim and
// a false one.
async function getCheckLibraryCoverage(dbPool, vendor) {
  try {
    const { rows } = await dbPool.query(
      `SELECT s AS standard,
              count(*)::int AS mapped,
              count(*) FILTER (WHERE ac.vendor IS NULL OR ac.vendor = $1)::int AS applicable,
              (SELECT count(*)::int FROM audit_checks) AS library_total
       FROM audit_checks ac, unnest(ac.standards) s
       GROUP BY s`,
      [vendor]
    );
    if (rows.length === 0) return null;
    const byStandard = {};
    let libraryTotal = null;
    for (const r of rows) {
      if (typeof r.standard !== 'string' || !Number.isFinite(Number(r.mapped))) continue;
      byStandard[r.standard] = { mapped: Number(r.mapped), applicable: Number(r.applicable) };
      if (Number.isFinite(Number(r.library_total))) libraryTotal = Number(r.library_total);
    }
    if (libraryTotal === null) return null;
    return { libraryTotal, byStandard };
  } catch (err) {
    console.warn('[compliance] check-library coverage read failed on the All Checks page:', err.message);
    return null;
  }
}

// ⛔ DISTINCT CHECKS AND THE SCORE, from the findings already fetched — no
// second query. `na` rows are counted as EVALUATED but not as ANSWERED: the
// question was put to the device and SecVault could not answer it, which is a
// different fact from a check that never ran, and both are different from a
// pass or a fail.
function perStandardCoverage(findings, library, vendor) {
  const out = {};
  for (const s of STANDARDS) {
    const counts = { pass: 0, fail: 0, warning: 0, na: 0 };
    const evaluated = new Set();
    const answered = new Set();
    for (const f of findings) {
      if (!f.standards.includes(s.key)) continue;
      if (Object.prototype.hasOwnProperty.call(counts, f.status)) counts[f.status] += 1;
      if (!f.checkSlug) continue;
      evaluated.add(f.checkSlug);
      if (f.status !== 'na') answered.add(f.checkSlug);
    }
    const measurable = counts.pass + counts.fail + counts.warning;
    const lib = library && library.byStandard[s.key] ? library.byStandard[s.key] : null;
    out[s.key] = buildStandardCoverage({
      standard: s.key,
      label: s.label,
      scope: 'device',
      deviceCount: 1,
      libraryTotal: library ? library.libraryTotal : null,
      mapped: lib ? lib.mapped : null,
      applicable: lib ? lib.applicable : null,
      evaluatedChecks: evaluated.size,
      answeredChecks: answered.size,
      findings: counts,
      // Same formula as everywhere else, excluding `na` from the denominator;
      // null (never 0) when nothing was answerable.
      scorePct: measurable > 0 ? Math.round((counts.pass / measurable) * 100) : null,
    });
  }
  return { coverage: out, vendor };
}

// Plain function returning JSX at module top level, called imperatively —
// never a component defined inside a component.
function coverageTable(coverageByStandard) {
  const pip = (on, i) => (
    <span
      key={i}
      style={{
        width: 13,
        height: 8,
        flex: 'none',
        borderRadius: 3,
        border: '1px solid var(--border)',
        background: on ? 'var(--unmeasured)' : 'var(--surface-subtle)',
        backgroundImage: on ? 'none' : 'var(--hatch)',
      }}
    />
  );
  return (
    <Card>
      <CardBody>
        <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
          What each tab is computed over
        </div>
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 'var(--s3)' }}>
          {COVERAGE_CLAIM}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
          {STANDARDS.map((s) => {
            const c = coverageByStandard[s.key];
            const evidence = c ? coverageEvidence(c) : null;
            const pips = [];
            for (let i = 0; i < (c ? c.pipTotal : 3); i += 1) pips.push(pip(c ? i < c.pips : false, i));
            return (
              <div
                key={s.key}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: 'var(--s3)',
                  paddingTop: 'var(--s2)',
                  borderTop: '1px solid var(--border-light)',
                  fontSize: 'var(--text-xs)',
                  lineHeight: 1.5,
                  color: 'var(--text-muted)',
                }}
              >
                <span
                  style={{
                    flex: 'none',
                    width: 96,
                    fontWeight: 600,
                    fontSize: 'var(--text-sm)',
                    color: 'var(--text-secondary)',
                  }}
                >
                  {s.label}
                </span>
                <span
                  aria-hidden="true"
                  title={c ? c.gradeLabel : 'Evidence not known'}
                  style={{ display: 'inline-flex', gap: 3, flex: 'none', marginTop: 4 }}
                >
                  {pips}
                </span>
                <span style={{ flex: '1 1 auto' }}>
                  <b style={{ color: 'var(--unmeasured)', fontWeight: 600 }}>
                    {c ? c.gradeLabel : 'Evidence not known'}
                  </b>
                  {' · '}
                  {c ? c.headline : 'the library check counts could not be read'}
                  {c && c.detail ? '; ' : '. '}
                  {c ? c.detail : ''}
                </span>
                {evidence && <EvidenceMark evidence={evidence} subject={`${s.label} coverage`} />}
              </div>
            );
          })}
        </div>
      </CardBody>
    </Card>
  );
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

  const library = await getCheckLibraryCoverage(pool, device.vendor);
  const { coverage } = perStandardCoverage(findings, library, device.vendor);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <Link href={`/compliance/${device.id}`} style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
          ← Back to Compliance — {device.name}
        </Link>
      </div>

      <PageHeader
        title={`All Checks — ${device.name}`}
        subtitle={<Badge color="info" title={device.vendor}>{vendorLabel(device.vendor)}</Badge>}
      />

      {findings.length === 0 ? (
        <EmptyState message="No compliance findings yet — run an audit to see results." />
      ) : (
        <>
          {coverageTable(coverage)}
          <StandardTabs standards={STANDARDS} findings={findings} deviceId={device.id} />
        </>
      )}
    </div>
  );
}
