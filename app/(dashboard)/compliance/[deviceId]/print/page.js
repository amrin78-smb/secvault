import Link from 'next/link';
import { pool } from '../../../../../lib/db';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { vendorLabel } from '../../../../../components/devices/vendorMeta';
import { STANDARDS, scoreColor, SCORE_COLOR_VAR } from '../../../../../components/compliance/ComplianceMatrix';
import PrintReportButton from '../../../../../components/compliance/PrintReportButton';
import { SEVERITY_LABEL, SEVERITY_TEXT_COLOR } from '../../../../../components/analysis/severityRamp';
import {
  complianceFreshness, ageLabel, freshnessNote, STATES,
} from '../../../../../lib/engines/complianceFreshness';

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

// ⛔ "Never run" is the right word for an AUDIT and the wrong one for a
// COLLECTION, and an unreadable timestamp is neither of those — same three
// outcomes the live sibling page distinguishes.
function formatCollected(value) {
  if (!value) return 'never collected';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'collection time unreadable';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

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

// ⛔ THE AGE OF THE EVIDENCE, WHICH IS NOT THE AGE OF THE AUDIT. This page
// printed "Last audit run" alone, and that is the FLATTERING timestamp: the
// audit reads the newest device_configs row WHATEVER ITS AGE and stamps
// detected_at = now(). Measured on the live fleet 2026-09-22, TSR_EKC's
// evidence was 1,116h old and its audit 669h old, so this report went out of
// the door describing a 46-day-old configuration as a 27-day-old audit, with
// no qualifier anywhere — and unlike the screen, a printed page has no hover,
// no tooltip and no second chance to ask. Same read the live sibling page does.
async function getLatestConfigCollectedAt(dbPool, deviceId) {
  const { rows } = await dbPool.query(
    `SELECT collected_at FROM device_configs
     WHERE device_id = $1 ORDER BY collected_at DESC LIMIT 1`,
    [deviceId]
  );
  return rows.length ? rows[0].collected_at : null;
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
// ⛔ TEXT, NOT A GRAPHIC — and on PAPER, where there is no hover, no title
// attribute and no second chance. These were the raw ramp hues (--red/--yellow/
// --blue), and globals.css measures --yellow at 3.64:1 on white: it clears
// 1.4.11's 3:1 for a graphical object and FAILS 1.4.3's 4.5:1 for text. Every
// value here is now a --tint-*-fg token, the pair globals.css guarantees at
// >=4.5:1 in both themes.
const STATUS_LABEL = {
  pass: { label: 'Pass', color: 'var(--tint-success-fg)' },
  fail: { label: 'Fail', color: 'var(--tint-danger-fg)' },
  warning: { label: 'Warning', color: 'var(--tint-warn-fg)' },
  na: { label: 'N/A', color: 'var(--text-muted)' },
};

// ⛔ Severity words come from components/analysis/severityRamp.js. The local
// map that used to live here was the pre-v2.87.0 ramp — 'high' in --yellow
// (the ramp's MEDIUM hue) and 'medium' in --blue, which the palette rewrite
// pulled off severity entirely so the brand teal can never read as one. It was
// printing that ramp onto paper a release after the screen stopped using it.
function severityCell(severity) {
  const key = SEVERITY_LABEL[severity] ? severity : 'info';
  return { label: SEVERITY_LABEL[key], color: SEVERITY_TEXT_COLOR[key] };
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

  const configCollectedAt = await getLatestConfigCollectedAt(pool, device.id);
  const freshness = complianceFreshness(
    { evidenceAt: configCollectedAt, evaluatedAt: lastRunAt }, new Date()
  );
  // ⛔ THE CAVEAT IS PRINTED, NOT HIDDEN BEHIND A TITLE ATTRIBUTE. Anything but
  // a genuinely fresh result carries its own sentence on the page — never a
  // green all-clear over evidence that stopped moving, and never a colour-only
  // hint that a printer resolves to grey.
  const needsCaveat = freshness.state !== STATES.FRESH || freshness.evaluatedAgainstOldConfig;

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
            {device.name} <span style={{ color: 'var(--text-muted)' }}>({vendorLabel(device.vendor)})</span>
          </p>
          <p style={{ marginTop: 4, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            Generated: {generatedAt} &middot; Configuration collected:{' '}
            {formatCollected(configCollectedAt)} ({ageLabel(freshness)}) &middot; Checks last run:{' '}
            {formatDateTime(lastRunAt)}
          </p>
          {needsCaveat && (
            /* ⛔ HUELESS, per the design system's "NOT MEASURED has no hue" rule,
               and on paper that matters more than on screen: an amber warning
               prints as grey anyway, so the words have to carry it. A stale
               result is still real evidence about an old configuration — the
               wording says so rather than calling the score garbage, which
               would push a reader to ignore the page instead of fixing the
               collection. */
            <p
              style={{
                marginTop: 8,
                padding: '8px 10px',
                fontSize: 'var(--text-sm)',
                color: 'var(--unmeasured)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
              }}
            >
              {freshnessNote(freshness, device.name)}
              {freshness.evaluatedAgainstOldConfig
                && ' The checks were last run against a configuration that was already older than '
                  + 'the expected collection cadence, so the audit timestamp above is more recent '
                  + 'than the evidence behind these results.'}
            </p>
          )}
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
                /* ⛔ tableLayout: 'fixed' — a named Critical Rule, and the only
                    thing that makes the <col> percentages below binding. Without
                    it the table runs in 'auto', where the percentages are hints a
                    browser is free to ignore: on the real report the two prose
                    columns (Detail averages 124 chars, Remediation 143) won the
                    negotiation and squeezed Check Name, the column the reader
                    scans by. The shared <Table> component enforces this for
                    every other table in the app; this hand-rolled one opted
                    itself out.
                    ⛔ Do NOT also "fix" truncation here — globals.css already
                    resets max-width/white-space/overflow for .print-report, so
                    fixed layout wraps these cells rather than clipping them. */
                <table style={{ tableLayout: 'fixed' }}>
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
                      const sev = severityCell(f.severity);
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
