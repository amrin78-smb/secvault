// lib/engines/complianceReport.js
// CommonJS ONLY — required by services/engine-worker.js's
// runComplianceReportJob() and app/api/compliance/report/**. See
// lib/schema.sql's compliance_report_log comment for the full design
// rationale (fleet-wide PDF, on-demand + monthly-scheduled delivery).

'use strict';

const fs = require('fs');
const path = require('path');
const { computeFleetComplianceScores } = require('./dashboardSnapshot');
const {
  listEnabledChannelsWithSecrets,
  recordChannelSuccess,
  recordChannelError,
} = require('../notificationChannels');
const { dispatchNotification } = require('../notify');

// Mirrors components/compliance/ComplianceMatrix.js's STANDARDS/scoreColor/
// SCORE_COLOR_VAR exactly (same 5 keys, same label text, same >80/>=60/else
// score-band thresholds) — duplicated, not imported. ComplianceMatrix.js is
// an ES module (`export const`); this file is required directly by
// services/engine-worker.js under plain `node`, which cannot parse ESM
// export syntax. Same ESM/CJS-boundary convention CLAUDE.md already
// documents for components/devices/vendorMeta.js <-> lib/adapters/index.js
// ("Two registries, deliberately duplicated").
const STANDARDS = [
  { key: 'PCI_DSS', label: 'PCI DSS' },
  { key: 'ISO_27001', label: 'ISO 27001' },
  { key: 'CIS_V8', label: 'CIS v8' },
  { key: 'NIST', label: 'NIST' },
  { key: 'SANS', label: 'SANS' },
];

function scoreColorVar(pct) {
  if (pct == null) return 'var(--text-muted)';
  if (pct > 80) return 'var(--green)';
  if (pct >= 60) return 'var(--yellow)';
  return 'var(--red)';
}

function emptyStandardStats() {
  const stats = {};
  for (const s of STANDARDS) stats[s.key] = { pass: 0, fail: 0, warning: 0, na: 0, total: 0, scorePct: null };
  return stats;
}

function finalizeScorePct(stats) {
  for (const s of STANDARDS) {
    const c = stats[s.key];
    const measurable = c.pass + c.fail + c.warning;
    c.scorePct = measurable > 0 ? Math.round((100 * c.pass) / measurable) : null;
  }
}

// ⛔ Deliberate 5th instance of this app's already-self-documented duplicated
// scoring formula (see app/api/compliance/fleet/route.js's own "BUG FIXED
// 2026-07-18... kept as a literal array, not an import, per this file's own
// established 'duplicated query/shape, not shared' convention" comment) —
// NOT unified with the other 4 sites in this change, to avoid touching
// already-working, already-tested compliance pages while adding this
// feature. The fleet-wide aggregate above reuses
// lib/engines/dashboardSnapshot.js's computeFleetComplianceScores() instead
// of a 6th duplicate of THAT formula, since that function already has
// exactly one other caller and extending it was zero-risk; this per-device
// breakdown and the findings query below have no reusable function to
// extend, so they're new, acknowledged duplicates instead.
async function buildPerDeviceStandards(pool) {
  const { rows: devices } = await pool.query(
    'SELECT id, name, vendor FROM devices WHERE active = true ORDER BY name ASC'
  );

  const { rows: findingRows } = await pool.query(
    `SELECT af.device_id, af.status, ac.standards
     FROM audit_findings af
     JOIN audit_checks ac ON ac.id = af.check_id
     JOIN devices d ON d.id = af.device_id
     WHERE d.active = true`
  );

  const statsByDevice = new Map();
  for (const device of devices) statsByDevice.set(device.id, emptyStandardStats());

  for (const row of findingRows) {
    const stats = statsByDevice.get(row.device_id);
    if (!stats) continue;
    const standardsForRow = Array.isArray(row.standards) ? row.standards : [];
    for (const key of standardsForRow) {
      if (!stats[key]) continue;
      stats[key].total += 1;
      if (row.status === 'pass' || row.status === 'fail' || row.status === 'warning' || row.status === 'na') {
        stats[key][row.status] += 1;
      }
    }
  }

  return devices.map((device) => {
    const stats = statsByDevice.get(device.id);
    finalizeScorePct(stats);
    return { deviceId: device.id, deviceName: device.name, vendor: device.vendor, standards: stats };
  });
}

// Only 'fail' and 'warning' findings, across every active device — 'pass'/
// 'na' are excluded deliberately (see the module-level design note in the
// approved plan: a monthly auditor report showing every passing check on
// every device would be hundreds of redundant rows on a fleet this size).
// 'warning' is included alongside 'fail', NOT fail-only — CLAUDE.md's own
// standing rule ("`unknown` must never silently default to `no`") applies
// here by the same logic: a warning is an unresolved predicate, not a
// pass, and a document titled "Compliance Report" omitting it would
// misrepresent the fleet's real posture to whoever reads it.
async function buildFindingsAppendix(pool) {
  const { rows } = await pool.query(
    `SELECT af.device_id, d.name AS device_name, ac.name AS check_name, ac.severity,
            af.status, af.detail, ac.remediation_guidance
     FROM audit_findings af
     JOIN audit_checks ac ON ac.id = af.check_id
     JOIN devices d ON d.id = af.device_id
     WHERE d.active = true AND af.status IN ('fail', 'warning')
     ORDER BY
       d.name ASC,
       CASE af.status WHEN 'fail' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
       CASE ac.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
       ac.name ASC`
  );

  const byDevice = new Map();
  for (const row of rows) {
    if (!byDevice.has(row.device_id)) byDevice.set(row.device_id, { deviceName: row.device_name, findings: [] });
    byDevice.get(row.device_id).findings.push({
      checkName: row.check_name,
      severity: row.severity,
      status: row.status,
      detail: row.detail,
      remediationGuidance: row.remediation_guidance,
    });
  }
  return Array.from(byDevice.values());
}

/**
 * Assembles every piece of data the report template needs. Best-effort per
 * query is NOT applied here (unlike most engine-worker jobs) — a report
 * with silently-missing data is worse than a failed report generation the
 * caller can see and retry; a thrown error here propagates straight up to
 * generateReportPdf()'s caller.
 * @param {import('pg').Pool} pool
 */
async function buildReportData(pool) {
  const [fleet, perDevice, findingsAppendix] = await Promise.all([
    computeFleetComplianceScores(pool),
    buildPerDeviceStandards(pool),
    buildFindingsAppendix(pool),
  ]);
  return { fleet, perDevice, findingsAppendix, generatedAt: new Date() };
}

function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatDateTime(date) {
  return date.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

const SEVERITY_LABEL = {
  critical: { label: 'Critical', color: 'var(--red)' },
  high: { label: 'High', color: 'var(--yellow)' },
  medium: { label: 'Medium', color: 'var(--blue)' },
  low: { label: 'Low', color: 'var(--text-muted)' },
  info: { label: 'Info', color: 'var(--text-muted)' },
};

const STATUS_LABEL = {
  fail: { label: 'Fail', color: 'var(--red)' },
  warning: { label: 'Warning', color: 'var(--yellow)' },
};

// Reads the REAL app/globals.css off disk and inlines it, so the report's
// .print-report/@media print rules and every --var() color token stay
// perfectly in sync with the live app's design system with zero hand
// duplication.
//
// ⛔ Bug found live (2026-08-02, Playwright post-deploy check): a plain
// __dirname-relative path (lib/engines/ -> project root -> app/globals.css)
// works under services/engine-worker.js (plain `node`, __dirname is the
// real source file location) but 500'd with ENOENT under the Next.js API
// route -- Next's production build moves/transforms this file into `.next/`,
// so __dirname at runtime there points inside the build output, not the
// source tree. `process.cwd()` is the reliable anchor instead: both
// SecVault-App (`next start`) and SecVault-Engine are NSSM-registered with
// the identical AppDirectory ("C:\Apps\SecVault", see CLAUDE.md's NSSM
// registration section), so cwd is the real app root in both runtimes.
// Tried first; the __dirname path is kept only as a defensive fallback
// (e.g. a script invoked from an unexpected working directory in dev).
//
// The one line stripped is deliberate: globals.css:8 is a live
// `@import url('https://fonts.googleapis.com/...')` for the Inter
// typeface. A background PDF-generation job (and the on-demand download
// route) should have ZERO external network dependents — inlined verbatim,
// headless Chromium would attempt that fetch on every single report
// generation, adding latency or an outright failure on a restricted
// network. The existing font-family fallback stack (globals.css, `'Inter',
// system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif`)
// already degrades cleanly to system-ui/Segoe UI with no other effect.
function loadInlineableGlobalsCss() {
  const candidates = [
    path.join(process.cwd(), 'app', 'globals.css'),
    path.join(__dirname, '..', '..', 'app', 'globals.css'),
  ];
  const cssPath = candidates.find((p) => fs.existsSync(p));
  if (!cssPath) {
    throw new Error(`app/globals.css not found — tried: ${candidates.join(', ')}`);
  }
  const raw = fs.readFileSync(cssPath, 'utf8');
  return raw.replace(/^@import.*$/gm, '');
}

/**
 * Builds a self-contained HTML string for the report — no external network
 * dependents (see loadInlineableGlobalsCss above), no dependency on the
 * live Next.js app being reachable (this is rendered via puppeteer's
 * page.setContent(), never by navigating to a live authenticated URL —
 * see generateReportPdf()'s own comment for why). Visual grammar
 * intentionally mirrors app/(dashboard)/compliance/[deviceId]/print/page.js
 * (header + one <section> per standard, .print-report wrapper class) for
 * consistency with the per-device print report a reader may already be
 * familiar with — but content is fleet-scoped (score tables + a fail/
 * warning findings appendix), not a per-device full-detail dump.
 */
function renderReportHtml(data) {
  const { fleet, perDevice, findingsAppendix, generatedAt } = data;
  const css = loadInlineableGlobalsCss();

  const fleetSummaryRows = STANDARDS.map((s) => {
    const pct = fleet.byStandard[s.key];
    const counts = fleet.byStandardCounts[s.key] || { pass: 0, fail: 0, warning: 0 };
    return `
      <tr>
        <td>${escapeHtml(s.label)}</td>
        <td style="color:${scoreColorVar(pct)};font-weight:600;">${pct == null ? '—' : `${pct}%`}</td>
        <td>${counts.pass}</td>
        <td>${counts.fail}</td>
        <td>${counts.warning}</td>
      </tr>`;
  }).join('');

  const perDeviceRows = perDevice
    .map((d) => {
      const cells = STANDARDS.map((s) => {
        const pct = d.standards[s.key].scorePct;
        return `<td style="color:${scoreColorVar(pct)};font-weight:600;">${pct == null ? '—' : `${pct}%`}</td>`;
      }).join('');
      return `
      <tr>
        <td>${escapeHtml(d.deviceName)}</td>
        <td>${escapeHtml(d.vendor)}</td>
        ${cells}
      </tr>`;
    })
    .join('');

  const findingsSections = findingsAppendix
    .map((group) => {
      const rows = group.findings
        .map((f) => {
          const sev = SEVERITY_LABEL[f.severity] || SEVERITY_LABEL.info;
          const st = STATUS_LABEL[f.status] || STATUS_LABEL.fail;
          return `
        <tr>
          <td>${escapeHtml(f.checkName)}</td>
          <td style="color:${sev.color};font-weight:600;">${sev.label}</td>
          <td style="color:${st.color};font-weight:600;">${st.label}</td>
          <td>${escapeHtml(f.detail) || '—'}</td>
          <td>${escapeHtml(f.remediationGuidance) || '—'}</td>
        </tr>`;
        })
        .join('');
      return `
      <section>
        <h2 style="font-size:var(--text-lg);font-weight:700;margin:0 0 8px;">${escapeHtml(group.deviceName)}</h2>
        <table>
          <colgroup>
            <col style="width:24%" /><col style="width:10%" /><col style="width:10%" />
            <col style="width:30%" /><col style="width:26%" />
          </colgroup>
          <thead>
            <tr><th>Check Name</th><th>Severity</th><th>Status</th><th>Detail</th><th>Remediation</th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </section>`;
    })
    .join('');

  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>SecVault Compliance Report</title>
<style>${css}</style>
</head>
<body>
<div class="print-report">
  <header style="margin-bottom:24px;border-bottom:2px solid var(--border);padding-bottom:12px;">
    <h1 style="font-size:var(--text-2xl);font-weight:700;margin:0;">SecVault Compliance Report</h1>
    <p style="margin-top:6px;font-size:var(--text-md);color:var(--text-secondary);">Fleet-wide summary</p>
    <p style="margin-top:4px;font-size:var(--text-sm);color:var(--text-muted);">Generated: ${formatDateTime(generatedAt)}</p>
  </header>

  <section>
    <h2 style="font-size:var(--text-lg);font-weight:700;margin:0 0 8px;">
      Fleet Summary
      <span style="color:${scoreColorVar(fleet.overall)};">${fleet.overall == null ? '—' : `${fleet.overall}%`}</span>
    </h2>
    <table>
      <colgroup><col style="width:32%" /><col style="width:17%" /><col style="width:17%" /><col style="width:17%" /><col style="width:17%" /></colgroup>
      <thead><tr><th>Standard</th><th>Score</th><th>Pass</th><th>Fail</th><th>Warning</th></tr></thead>
      <tbody>${fleetSummaryRows}</tbody>
    </table>
  </section>

  <section>
    <h2 style="font-size:var(--text-lg);font-weight:700;margin:0 0 8px;">Per-Device Scores</h2>
    <table>
      <thead>
        <tr>
          <th>Device</th><th>Vendor</th>
          ${STANDARDS.map((s) => `<th>${escapeHtml(s.label)}</th>`).join('')}
        </tr>
      </thead>
      <tbody>${perDeviceRows}</tbody>
    </table>
  </section>

  <section>
    <h2 style="font-size:var(--text-lg);font-weight:700;margin:0 0 8px;">Findings Requiring Attention</h2>
    <p style="font-size:var(--text-sm);color:var(--text-secondary);margin-bottom:10px;">
      Failing and warning checks only, grouped by device. Passing/not-applicable checks are omitted for brevity.
    </p>
    ${findingsSections || '<p style="color:var(--text-muted);">No failing or warning findings across the fleet.</p>'}
  </section>
</div>
</body>
</html>`;
}

// Renders from a self-contained in-memory HTML string via page.setContent(),
// NEVER by navigating puppeteer to a live URL on the running Next.js app —
// avoids needing a background job to authenticate into its own admin-gated
// pages, and matches every other engine-worker job's existing "query pool
// directly, no HTTP loopback into the app" pattern. `puppeteer-core` (not
// bundled `puppeteer`) + PUPPETEER_EXECUTABLE_PATH pointed at the server's
// existing Microsoft Edge install — confirmed present on the real
// production server, avoids depending on this deployment being able to
// download ~200-300MB of Chromium (Install-SecVault.ps1 deliberately
// bundles its own dependencies rather than assuming outbound internet
// access is available at all) and avoids a bundled browser's cache path
// going invisible to SecVault-Engine (which runs as LocalSystem, a
// different profile than whichever account runs Update-SecVault.ps1).
// Same fallback-default convention every other configurable env var in this
// codebase uses (e.g. engine-worker.js's getSnapshotRetentionDays()) rather
// than a hard throw when unset — this exact path is confirmed present on
// the real production server (Windows Server 2022, Edge 150.0.4078.65), so
// a missing .env.local entry shouldn't hard-fail report generation when a
// known-good default exists.
const DEFAULT_PUPPETEER_EXECUTABLE_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';

async function generateReportPdf(pool) {
  const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || DEFAULT_PUPPETEER_EXECUTABLE_PATH;
  // ⛔ puppeteer-core@25's package.json declares "type": "module" with no CJS
  // entry point at all — a plain require('puppeteer-core') fails both under
  // Next.js's webpack build ("ESM packages need to be imported") AND under
  // plain node (services/engine-worker.js is CommonJS-only). Node's dynamic
  // import() works from a CommonJS module for exactly this case; `launch`
  // is a real named export (confirmed: Object.keys(await
  // import('puppeteer-core')) includes 'launch' as a function).
  const { launch } = await import('puppeteer-core');
  const data = await buildReportData(pool);
  const html = renderReportHtml(data);

  // ⛔ Bug found live (2026-08-02, Playwright post-deploy check, again):
  // Edge launched fine in local testing but failed on the real server with
  // "Failed to launch the browser process: Code: 1002" (empty stderr) --
  // both SecVault-App and SecVault-Engine run as LocalSystem inside an NSSM
  // Windows Service, i.e. Session 0, which has no desktop/window-station.
  // Chromium's OS-level sandbox setup requires desktop integration that
  // Session 0 doesn't provide -- this is the well-documented "Chromium
  // won't launch under a Windows Service" failure class, and --no-sandbox
  // is the standard fix. Accepted here specifically because it changes
  // nothing about the real threat model: this process already runs as
  // LocalSystem (the most privileged Windows account, strictly more
  // powerful than anything the sandbox boundary protects against) AND only
  // ever renders self-contained, internally-generated HTML from our own
  // DB (see renderReportHtml — no external network fetch, no untrusted
  // page navigation ever happens in this browser instance).
  const browser = await launch({
    executablePath,
    headless: true,
    args: ['--no-sandbox', '--disable-gpu'],
  });
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });
    const pdfBuffer = await page.pdf({ format: 'A4', printBackground: true });
    return pdfBuffer;
  } finally {
    await browser.close();
  }
}

function currentPeriod(date = new Date()) {
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`;
}

/**
 * Shared orchestration for BOTH the scheduled monthly job
 * (services/engine-worker.js's runComplianceReportJob) and the manual
 * POST /api/compliance/report/generate route — one code path, so "generate
 * now" and "the cron tick" can never drift out of step. Idempotent per
 * calendar month via compliance_report_log's partial unique index (see that
 * table's own comment in lib/schema.sql): skips entirely, no PDF generated,
 * no email sent, if a 'success' row already exists for this period.
 *
 * status='success' requires at least one channel to have actually received
 * the report — if every matching channel's send fails (e.g. every
 * configured SMTP relay is down), this logs 'error' instead of 'success'
 * with recipient_count=0, specifically so the partial unique index does
 * NOT block a retry later that same month. Per-channel failures are
 * separately visible on that channel's own last_error (recordChannelError),
 * same as every other alert type.
 * @param {import('pg').Pool} pool
 * @returns {Promise<{skipped: boolean, reason?: string, period: string, sent?: number}>}
 */
async function dispatchMonthlyReport(pool) {
  const period = currentPeriod();

  const already = await pool.query(
    `SELECT id FROM compliance_report_log WHERE period = $1 AND status = 'success'`,
    [period]
  );
  if (already.rows.length > 0) {
    return { skipped: true, reason: 'already sent this period', period };
  }

  const channels = await listEnabledChannelsWithSecrets(pool);
  const targets = channels.filter(
    (c) => c.channelType === 'email' && Array.isArray(c.alertTypes) && c.alertTypes.includes('compliance_report')
  );
  if (targets.length === 0) {
    return { skipped: true, reason: 'no channel configured for compliance_report', period };
  }

  const startedAt = new Date();
  try {
    const pdfBuffer = await generateReportPdf(pool);
    const message = {
      alertType: 'compliance_report',
      title: `SecVault Monthly Compliance Report — ${period}`,
      summary: `The fleet-wide compliance report for ${period} is attached.`,
      attachments: [
        {
          filename: `secvault-compliance-report-${period}.pdf`,
          content: pdfBuffer,
          contentType: 'application/pdf',
        },
      ],
    };

    let sent = 0;
    const errors = [];
    for (const channel of targets) {
      try {
        await dispatchNotification(channel, message);
        await recordChannelSuccess(channel.id, pool);
        sent += 1;
      } catch (err) {
        errors.push(`${channel.name}: ${err.message}`);
        await recordChannelError(channel.id, err.message, pool);
      }
    }

    if (sent === 0) {
      await pool.query(
        `INSERT INTO compliance_report_log (period, status, recipient_count, error, started_at, finished_at)
         VALUES ($1, 'error', 0, $2, $3, now())`,
        [period, `All ${targets.length} channel(s) failed to send: ${errors.join('; ')}`, startedAt]
      );
      return { skipped: false, period, sent: 0 };
    }

    await pool.query(
      `INSERT INTO compliance_report_log (period, status, recipient_count, started_at, finished_at)
       VALUES ($1, 'success', $2, $3, now())`,
      [period, sent, startedAt]
    );
    return { skipped: false, period, sent };
  } catch (err) {
    await pool.query(
      `INSERT INTO compliance_report_log (period, status, recipient_count, error, started_at, finished_at)
       VALUES ($1, 'error', 0, $2, $3, now())`,
      [period, err.message, startedAt]
    );
    throw err;
  }
}

module.exports = { buildReportData, renderReportHtml, generateReportPdf, dispatchMonthlyReport };
