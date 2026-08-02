// lib/engines/complianceReport.js
// CommonJS ONLY — required by services/engine-worker.js's
// runComplianceReportJob() and app/api/compliance/report/**. See
// lib/schema.sql's compliance_report_log comment for the full design
// rationale (fleet-wide PDF, on-demand + monthly-scheduled delivery).

'use strict';

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

// ⛔ Rewritten 2026-08-02: the original implementation rendered a self-contained
// HTML string and used puppeteer-core (headless Edge) to convert it to a PDF.
// That worked in every manual test (locally, and even a raw msedge.exe launch
// on the real production server) but consistently failed with an opaque
// "Failed to launch the browser process: Code: 1002" / empty-stderr error
// SPECIFICALLY when launched from inside the SecVault-App/SecVault-Engine NSSM
// Windows services -- root cause never conclusively identified after several
// live diagnostic passes (ruled out: missing browser, wrong path, Session-0
// sandbox restrictions, GPU, active Defender/ASR blocking). Per the sibling
// NocVault suite apps (logvault/ddivault/spanvault), the established,
// battle-tested pattern for exactly this "generate a branded PDF report from
// a Node service" need is `pdfkit` -- a pure-JS vector PDF library with no
// child process, no browser, no launch step at all. Ported directly from
// spanvault/api/reportsPdf.js's helpers (drawCover/drawKpiTiles/drawTable/
// sectionTitle/stampHeadersFooters/pdfSafe/installPdfSafeText), same brand
// hex palette (confirmed identical to this app's own app/globals.css tokens
// -- the suite shares one design system, see CLAUDE.md's Design System
// section), same Buffer-returning generateReportPdf(pool) contract so both
// the on-demand route and the scheduled job need zero further changes.
const PDFDocument = require('pdfkit');

// Same brand palette as every other NocVault suite app's PDF reports (see
// spanvault/api/reportsPdf.js) -- confirmed identical to this app's own
// app/globals.css :root tokens (--primary/--navy/--border/--text-muted/
// --green/--yellow/--red/--blue), not a coincidence: the whole suite shares
// one design system. RED here is the BRAND accent (--primary, #C8102E, used
// for cover chrome/accent bars) -- STATUS_RED (--red, #dc2626) is the
// separate status-danger color SecVault's own UI already distinguishes from
// its brand red everywhere else (Badge/StatusDot etc.).
const RED = '#C8102E';
const NAVY = '#1a2744';
const MUTED = '#64748b';
const LIGHT = '#f1f5f9';
const BORDER = '#e2e8f0';
const GREEN = '#16a34a';
const YELLOW = '#d97706';
const BLUE = '#2563eb';
const STATUS_RED = '#dc2626';

function scoreColorHex(pct) {
  if (pct == null) return MUTED;
  if (pct > 80) return GREEN;
  if (pct >= 60) return YELLOW;
  return STATUS_RED;
}

function fmtStamp(date) {
  return date.toLocaleString('en-GB', { hour12: false, timeZone: 'UTC' }) + ' UTC';
}

const SEVERITY_LABEL = {
  critical: { label: 'Critical', color: STATUS_RED },
  high: { label: 'High', color: YELLOW },
  medium: { label: 'Medium', color: BLUE },
  low: { label: 'Low', color: MUTED },
  info: { label: 'Info', color: MUTED },
};

const STATUS_LABEL = {
  fail: { label: 'Fail', color: STATUS_RED },
  warning: { label: 'Warning', color: YELLOW },
};

// pdfkit's built-in Helvetica uses WinAnsi (CP1252), which lacks glyphs this
// file would otherwise use (– — • curly quotes). Same fix as every sibling
// suite app: sanitize to ASCII and monkey-patch doc.text so every call site
// (cover/tables/footer) is covered from one place.
function pdfSafe(s) {
  if (s == null) return '';
  return String(s)
    .replace(/[–—―]/g, '-')
    .replace(/•/g, '-')
    .replace(/[''‚‛]/g, "'")
    .replace(/[""„‟]/g, '"')
    .replace(/ /g, ' ');
}
function installPdfSafeText(doc) {
  const origText = doc.text.bind(doc);
  doc.text = (text, ...rest) => origText(pdfSafe(text), ...rest);
  return doc;
}

// Branded cover page — same structure as every sibling suite app's PDF cover
// (navy header band + red accent bar + logo chip + title + meta rows +
// summary chips), using SecVault's own name/tagline and this file's own
// fleet-summary numbers as the chips.
function drawCover(doc, o, layout) {
  const { title, company, generatedAt, summary } = o;
  const { pageW, left, contentW } = layout;

  doc.rect(0, 0, pageW, 150).fill(NAVY);
  doc.rect(0, 150, pageW, 6).fill(RED);
  doc.roundedRect(left, 44, 64, 64, 10).fill(RED);
  doc.fillColor('#fff').fontSize(30).font('Helvetica-Bold').text('S', left, 60, { width: 64, align: 'center' });
  doc.fillColor('#fff').fontSize(22).font('Helvetica-Bold').text('SecVault', left + 80, 56);
  doc.fillColor('#cbd5e1').fontSize(11).font('Helvetica').text('Firewall Security Platform', left + 80, 86);

  doc.fillColor(NAVY).fontSize(28).font('Helvetica-Bold').text(title, left, 196, { width: contentW });
  doc.moveTo(left, 238).lineTo(left + 120, 238).lineWidth(3).stroke(RED);

  const meta = [
    ['Company', company],
    ['Generated', generatedAt],
  ];
  let my = 262;
  doc.fontSize(11);
  meta.forEach(([k, v]) => {
    doc.fillColor(MUTED).font('Helvetica-Bold').text(k, left, my, { width: 120 });
    doc.fillColor('#0f172a').font('Helvetica').text(v, left + 130, my, { width: contentW - 130 });
    my += 22;
  });

  if (summary && summary.length) {
    my += 12;
    doc.fillColor(NAVY).fontSize(13).font('Helvetica-Bold').text('Summary', left, my);
    my += 22;
    let cx = left;
    const chipW = Math.min(170, (contentW - 30) / Math.max(summary.length, 1));
    summary.forEach((s) => {
      doc.roundedRect(cx, my, chipW - 10, 52, 8).fillAndStroke(LIGHT, BORDER);
      doc.fillColor(s.color || NAVY).fontSize(18).font('Helvetica-Bold').text(String(s.value), cx + 10, my + 8, { width: chipW - 26 });
      doc.fillColor(MUTED).fontSize(8).font('Helvetica').text(s.label, cx + 10, my + 32, { width: chipW - 26 });
      cx += chipW;
    });
  }
}

function sectionTitle(doc, layout, text) {
  const { left, contentW, pageH } = layout;
  if (doc.y + 46 > pageH - doc.page.margins.bottom) doc.addPage();
  doc.fillColor(NAVY).fontSize(12).font('Helvetica-Bold').text(text, left, doc.y, { width: contentW });
  doc.y += 8;
}

// Generic wrapped-height zebra table — ported verbatim (structure/behavior)
// from spanvault/api/reportsPdf.js's drawTable. Measures each cell's wrapped
// height via doc.heightOfString so a row is tall enough for its tallest
// cell, and breaks to a new page (redrawing the header) when a row would
// overflow. `o2.continueOnPage` flows the table on the current page instead
// of starting a fresh one — used for every table here since sectionTitle
// already placed the heading on the current page.
function drawTable(doc, tbl, layout, o2 = {}) {
  const { columns, rows } = tbl;
  const { left, contentW, pageH } = layout;
  if (o2.continueOnPage) {
    doc.y = doc.y + 8;
  } else {
    doc.addPage();
  }
  const rowH = 18;
  const headerH = 22;
  const pad = 5;
  const totalW = columns.reduce((a, c) => a + (c.width || 80), 0);
  const scale = contentW / totalW;
  const colX = [];
  let acc = left;
  columns.forEach((c) => {
    colX.push(acc);
    acc += (c.width || 80) * scale;
  });
  const colW = (c) => (c.width || 80) * scale;

  function drawHeader() {
    const y = doc.y;
    doc.rect(left, y, contentW, headerH).fill(NAVY);
    doc.fillColor('#fff').fontSize(8).font('Helvetica-Bold');
    columns.forEach((c, i) => {
      doc.text(c.label, colX[i] + 4, y + 7, { width: colW(c) - 8, align: c.align || 'left', ellipsis: true, lineBreak: false });
    });
    doc.y = y + headerH;
  }

  drawHeader();
  rows.forEach((r, idx) => {
    doc.font('Helvetica').fontSize(8);
    let rh = rowH;
    columns.forEach((c) => {
      const txt = String(r[c.key] == null ? '' : r[c.key]);
      const th = doc.heightOfString(pdfSafe(txt), { width: colW(c) - 8 }) + pad * 2;
      if (th > rh) rh = th;
    });
    if (doc.y + rh > pageH - doc.page.margins.bottom) {
      doc.addPage();
      drawHeader();
      doc.font('Helvetica').fontSize(8);
    }
    const y = doc.y;
    if (idx % 2 === 1) doc.rect(left, y, contentW, rh).fill(LIGHT);
    columns.forEach((c, i) => {
      const color = typeof c.color === 'function' ? c.color(r) || '#1e293b' : c.color || '#1e293b';
      doc
        .fillColor(color)
        .font('Helvetica')
        .fontSize(8)
        .text(String(r[c.key] == null ? '' : r[c.key]), colX[i] + 4, y + pad, { width: colW(c) - 8, align: c.align || 'left' });
    });
    doc.y = y + rh;
  });

  if (rows.length === 0) {
    doc.fillColor(MUTED).fontSize(11).font('Helvetica-Oblique').text('No data.', left, doc.y + 14, { width: contentW, align: 'center' });
  }
}

// Header/footer/page numbers stamped on every buffered page in one final
// pass — identical approach to every sibling suite app (an explicit bounded
// `height` on each stamp is what stops pdfkit auto-paginating a footer drawn
// near the page bottom into a phantom extra page).
function stampHeadersFooters(doc, { title, company, generatedAt }) {
  const pageW = doc.page.width;
  const pageH = doc.page.height;
  const left = doc.page.margins.left;
  const right = pageW - doc.page.margins.right;
  const contentW = right - left;
  const range = doc.bufferedPageRange();
  const stampH = 12;
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    if (i > range.start) {
      doc
        .fillColor(MUTED)
        .fontSize(8)
        .font('Helvetica')
        .text(title, left, 18, { width: contentW / 2, align: 'left', lineBreak: false, height: stampH });
      doc.text(company, left + contentW / 2, 18, { width: contentW / 2, align: 'right', lineBreak: false, height: stampH });
      doc.moveTo(left, 30).lineTo(right, 30).lineWidth(0.5).strokeColor(BORDER).stroke();
    }
    doc
      .fillColor(MUTED)
      .fontSize(8)
      .font('Helvetica')
      .text(`Generated ${generatedAt}`, left, pageH - 26, { width: contentW / 2, align: 'left', lineBreak: false, height: stampH });
    doc.text(`Page ${i - range.start + 1} of ${range.count}`, left + contentW / 2, pageH - 26, {
      width: contentW / 2,
      align: 'right',
      lineBreak: false,
      height: stampH,
    });
  }
}

// Builds the three drawTable() row/column shapes from buildReportData()'s
// output — pure data transforms, no pdfkit calls, so they're easy to reason
// about independently of layout.
function buildFleetSummaryTable(fleet) {
  return {
    columns: [
      { key: 'standard', label: 'Standard', width: 160 },
      { key: 'score', label: 'Score', width: 70, color: (r) => r._color },
      { key: 'pass', label: 'Pass', width: 60 },
      { key: 'fail', label: 'Fail', width: 60 },
      { key: 'warning', label: 'Warning', width: 70 },
    ],
    rows: STANDARDS.map((s) => {
      const pct = fleet.byStandard[s.key];
      const counts = fleet.byStandardCounts[s.key] || { pass: 0, fail: 0, warning: 0 };
      return {
        standard: s.label,
        score: pct == null ? '-' : `${pct}%`,
        pass: counts.pass,
        fail: counts.fail,
        warning: counts.warning,
        _color: scoreColorHex(pct),
      };
    }),
  };
}

function buildPerDeviceTable(perDevice) {
  return {
    columns: [
      { key: 'device', label: 'Device', width: 110 },
      { key: 'vendor', label: 'Vendor', width: 80 },
      ...STANDARDS.map((s) => ({
        key: s.key,
        label: s.label,
        width: 65,
        color: (r) => r[`_${s.key}Color`],
      })),
    ],
    rows: perDevice.map((d) => {
      const row = { device: d.deviceName, vendor: d.vendor };
      STANDARDS.forEach((s) => {
        const pct = d.standards[s.key].scorePct;
        row[s.key] = pct == null ? '-' : `${pct}%`;
        row[`_${s.key}Color`] = scoreColorHex(pct);
      });
      return row;
    }),
  };
}

function buildFindingsTable(group) {
  return {
    columns: [
      { key: 'checkName', label: 'Check Name', width: 130 },
      { key: 'severity', label: 'Severity', width: 55, color: (r) => r._sevColor },
      { key: 'status', label: 'Status', width: 55, color: (r) => r._stColor },
      { key: 'detail', label: 'Detail', width: 150 },
      { key: 'remediation', label: 'Remediation', width: 130 },
    ],
    rows: group.findings.map((f) => {
      const sev = SEVERITY_LABEL[f.severity] || SEVERITY_LABEL.info;
      const st = STATUS_LABEL[f.status] || STATUS_LABEL.fail;
      return {
        checkName: f.checkName,
        severity: sev.label,
        status: st.label,
        detail: f.detail || '-',
        remediation: f.remediationGuidance || '-',
        _sevColor: sev.color,
        _stColor: st.color,
      };
    }),
  };
}

// Draws the full report body onto an already-covered doc: fleet summary ->
// per-device scores -> one findings-appendix table per device group (only
// devices with fail/warning findings appear — matches the design decision
// to omit pass/na rows for brevity while never omitting warning, per
// CLAUDE.md's "unknown must never silently default to no" spirit).
function renderReportBody(doc, data, layout) {
  const { fleet, perDevice, findingsAppendix } = data;

  sectionTitle(doc, layout, `Fleet Summary — ${fleet.overall == null ? '-' : `${fleet.overall}%`}`);
  drawTable(doc, buildFleetSummaryTable(fleet), layout, { continueOnPage: true });

  sectionTitle(doc, layout, 'Per-Device Scores');
  drawTable(doc, buildPerDeviceTable(perDevice), layout, { continueOnPage: true });

  sectionTitle(doc, layout, 'Findings Requiring Attention');
  doc
    .fillColor(MUTED)
    .fontSize(9)
    .font('Helvetica')
    .text('Failing and warning checks only, grouped by device. Passing/not-applicable checks are omitted for brevity.', layout.left, doc.y, {
      width: layout.contentW,
    });
  doc.y += 10;

  if (!findingsAppendix.length) {
    doc.fillColor(MUTED).fontSize(10).font('Helvetica-Oblique').text('No failing or warning findings across the fleet.', layout.left, doc.y);
  } else {
    findingsAppendix.forEach((group) => {
      sectionTitle(doc, layout, group.deviceName);
      drawTable(doc, buildFindingsTable(group), layout, { continueOnPage: true });
    });
  }
}

// Pure-JS vector PDF generation via pdfkit — no browser, no child process,
// no service-account launch permissions to worry about. Same convention as
// every sibling NocVault suite app (logvault/ddivault/spanvault all use
// pdfkit for exactly this "generate a branded PDF from a Node service"
// need) — see this file's top-of-file comment for why puppeteer-core was
// abandoned. bufferPages:true is required for stampHeadersFooters()'s final
// switchToPage() pass to see every page already drawn.
async function generateReportPdf(pool) {
  const data = await buildReportData(pool);
  const doc = installPdfSafeText(
    new PDFDocument({ size: 'A4', layout: 'portrait', margin: 36, bufferPages: true })
  );
  const layout = {
    pageW: doc.page.width,
    pageH: doc.page.height,
    left: doc.page.margins.left,
    right: doc.page.width - doc.page.margins.right,
    contentW: doc.page.width - doc.page.margins.left - doc.page.margins.right,
  };
  const generatedAt = fmtStamp(data.generatedAt);

  drawCover(
    doc,
    {
      title: 'Compliance Report',
      company: 'SecVault',
      generatedAt,
      summary: [
        { label: 'Fleet Score', value: data.fleet.overall == null ? '-' : `${data.fleet.overall}%`, color: scoreColorHex(data.fleet.overall) },
        { label: 'Devices', value: data.perDevice.length, color: NAVY },
        { label: 'Open Findings', value: data.findingsAppendix.reduce((n, g) => n + g.findings.length, 0), color: STATUS_RED },
      ],
    },
    layout
  );

  renderReportBody(doc, data, layout);
  stampHeadersFooters(doc, { title: 'SecVault Compliance Report', company: 'SecVault', generatedAt });

  return new Promise((resolve, reject) => {
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    doc.end();
  });
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

module.exports = { buildReportData, generateReportPdf, dispatchMonthlyReport };
