import Link from 'next/link';
import { pool } from '../../../../../lib/db';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { STANDARDS, scoreColor, SCORE_COLOR_VAR } from '../../../../../components/compliance/ComplianceMatrix';
import PrintReportButton from '../../../../../components/compliance/PrintReportButton';

export const dynamic = 'force-dynamic';

// Print-friendly sibling of app/(dashboard)/compliance/[deviceId]/page.js --
// same "server component queries the DB directly for its own render"
// convention as every other page in this app (see that file's own header
// comment, and the Fleet Alerts Page / Compliance Engine sections of
// CLAUDE.md for the documented precedent that this kind of duplication is
// deliberate, not an oversight). Next.js page files aren't meant to be
// imported as modules by other pages, so getDevice/getFindings/
// aggregateStandards/scorePctFromCounts are copied here rather than
// imported from the sibling page.
//
// Unlike the live page (StandardTabs.js, client-side, one standard visible
// at a time), this report has no tabs -- it renders ALL 4 standards' full
// findings in one scroll, since that's the whole point of an exportable /
// printable report. Status/severity are plain colored text instead of the
// interactive Badge pill component -- simpler and prints better (a filled
// pill can render as a solid block on some printers/PDF exporters).

function formatDateTime(value) {
  if (!value) return 'Never run';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'Never run';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

// Same formula as the sibling page.js / app/(dashboard)/compliance/page.js's
// scorePctFromCounts -- 'na' excluded from the denominator, null (not 0)
// when nothing is measurable.
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

// Plain-text status/severity labeling for print -- same color intent as
// StandardTabs.js's STATUS_BADGE/SEVERITY_BADGE Badge-color maps, just
// resolved straight to a CSS var instead of a Badge `color` prop name,
// since a print report wants dense colored text, not pill chrome.
const STATUS_LABEL = {
  pass: { label: 'Pass', color: 'var(--green)' },
  fail: { label: 'Fail', color: 'var(--red)' },
  warning: { label: 'Warning', color: 'var(--yellow)' },
  na: { label: 'N/A', color: 'var(--text-muted)' },
};

const SEVERITY_LABEL = {
  critical: { label: 'Critical', color: 'var(--red)' },
  high: { label: 'High', color: 'var(--yellow)' },
  medium: { label: 'Medium', color: 'var(--blue)' },
  low: { label: 'Low', color: 'var(--text-muted)' },
  info: { label: 'Info', color: 'var(--text-muted)' },
};

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

export default async function CompliancePrintPage({ params }) {
  // Same malformed-UUID guard as the sibling live page -- a stale/hand-edited
  // link must never reach pool.query() and crash the render on a raw
  // Postgres "invalid input syntax for type uuid" error.
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
  const generatedAt = formatDateTime(new Date().toISOString());

  return (
    <div>
      <div
        className="no-print"
        style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}
      >
        <Link href={`/compliance/${device.id}`} style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
          ← Back to Compliance
        </Link>
        <PrintReportButton />
      </div>

      <div className="print-report">
        <header style={{ marginBottom: 24, borderBottom: '2px solid var(--border)', paddingBottom: 12 }}>
          <h1 style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, margin: 0 }}>SecVault Compliance Report</h1>
          <p style={{ marginTop: 6, fontSize: 'var(--text-md)', color: 'var(--text-secondary)' }}>
            {device.name} <span style={{ color: 'var(--text-muted)' }}>({device.vendor})</span>
          </p>
          <p style={{ marginTop: 4, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            Generated: {generatedAt} &middot; Last audit run: {formatDateTime(lastRunAt)}
          </p>
        </header>

        {STANDARDS.map((s) => {
          const stat = standards[s.key];
          const color = SCORE_COLOR_VAR[scoreColor(stat.scorePct)];
          const sFindings = findings.filter((f) => f.standards.includes(s.key));

          return (
            <section key={s.key}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'baseline',
                  justifyContent: 'space-between',
                  marginBottom: 8,
                }}
              >
                <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 700, margin: 0 }}>{s.label}</h2>
                <span style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color }}>
                  {stat.scorePct == null ? '—' : `${stat.scorePct}%`}
                </span>
              </div>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginBottom: 10 }}>
                {stat.pass} pass &middot; {stat.fail} fail &middot; {stat.warning} warning &middot; {stat.na} n/a
              </p>

              {sFindings.length === 0 ? (
                <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                  No findings mapped to this standard.
                </p>
              ) : (
                <table>
                  <colgroup>
                    <col style={{ width: '24%' }} />
                    <col style={{ width: '10%' }} />
                    <col style={{ width: '10%' }} />
                    <col style={{ width: '30%' }} />
                    <col style={{ width: '26%' }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th>Check Name</th>
                      <th>Severity</th>
                      <th>Status</th>
                      <th>Detail</th>
                      <th>Remediation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sFindings.map((f) => {
                      const sev = SEVERITY_LABEL[f.severity] || SEVERITY_LABEL.info;
                      const st = STATUS_LABEL[f.status] || STATUS_LABEL.na;
                      return (
                        <tr key={f.id}>
                          <td>{f.name}</td>
                          <td style={{ color: sev.color, fontWeight: 600 }}>{sev.label}</td>
                          <td style={{ color: st.color, fontWeight: 600 }}>{st.label}</td>
                          <td style={{ color: 'var(--text-secondary)' }}>{f.detail || '—'}</td>
                          <td style={{ color: 'var(--text-secondary)' }}>{f.remediationGuidance || '—'}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </section>
          );
        })}
      </div>
    </div>
  );
}
