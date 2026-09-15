// lib/engines/complianceReport.js
// CommonJS ONLY — required by services/engine-worker.js's
// runComplianceReportJob() and app/api/compliance/report/**. See
// lib/schema.sql's compliance_report_log comment for the full design
// rationale (fleet-wide PDF, on-demand + monthly-scheduled delivery).

'use strict';

const { computeFleetComplianceScores } = require('./dashboardSnapshot');
const { PRODUCT_NAME } = require('../branding');
// ⛔ The shared PDF chassis. These SEVEN helpers used to live here AND in
// lib/engines/ruleChangeRequestReport.js, and the two copies had drifted — the
// other one grew an `ensureSpace` guard against pdfkit orphaning a table header
// across five pages, and this file never received it. See lib/reports/chassis.js.
const {
  ACCENT, NAVY, MUTED, LIGHT, BORDER, GREEN,
  pdfSafe, installPdfSafeText, fmtStamp,
  drawCover, sectionTitle, drawTable, stampHeadersFooters,
} = require('../reports/chassis');
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

const STANDARD_KEYS = STANDARDS.map((s) => s.key);
const STANDARD_LABEL = new Map(STANDARDS.map((s) => [s.key, s.label]));

/**
 * Resolves the optional `standard` scope.
 *
 * ⛔ AN UNKNOWN STANDARD THROWS; it does not fall back to the whole fleet. A
 * report silently widening from "PCI DSS" to "everything" while still being
 * titled and filed as a PCI document is a mislabelled audit artefact, which is
 * the one output this product must never produce. The route also allow-lists
 * the value against the catalogue's own declared choices, so this is the second
 * of two independent gates rather than the only one.
 */
function resolveStandard(standard) {
  if (standard === null || standard === undefined || standard === '') return null;
  if (!STANDARD_KEYS.includes(standard)) {
    throw new Error(`Unknown compliance standard: ${standard}`);
  }
  return standard;
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
async function buildFindingsAppendix(pool, standard = null) {
  // ⛔ PARAMETERISED, and the value has already been allow-listed twice. The
  // `standards` column is a TEXT[], so membership is `@>` against a
  // single-element array — never string interpolation, never a LIKE.
  const params = [];
  let standardClause = '';
  if (standard) {
    params.push([standard]);
    standardClause = ` AND ac.standards @> $${params.length}::text[]`;
  }
  const { rows } = await pool.query(
    `SELECT af.device_id, d.name AS device_name, ac.name AS check_name, ac.severity,
            af.status, af.detail, ac.remediation_guidance
     FROM audit_findings af
     JOIN audit_checks ac ON ac.id = af.check_id
     JOIN devices d ON d.id = af.device_id
     WHERE d.active = true AND af.status IN ('fail', 'warning')${standardClause}
     ORDER BY
       d.name ASC,
       CASE af.status WHEN 'fail' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
       CASE ac.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
       ac.name ASC`,
    params
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
 * How much of the check library the chosen standard actually covers.
 *
 * ⛔ THIS IS THE SENTENCE THAT KEEPS A SCOPED REPORT HONEST. A check carries a
 * `standards` ARRAY — one check commonly maps to several frameworks — so
 * narrowing to PCI DSS does not filter a fleet, it changes the DENOMINATOR. A
 * PCI score of 62% and an overall score of 51% are both correct and are
 * answers to different questions. Printed side by side in two documents with
 * no explanation, they read as a bug in one of them, and the reader has no way
 * to tell which. So the scoped report states its own coverage on the cover.
 *
 * Returns null on a read failure rather than a zero — "0 of 45 checks map to
 * PCI DSS" is a claim, and a false one.
 */
async function standardCoverage(pool, standard) {
  if (!standard) return null;
  try {
    const { rows } = await pool.query(
      `SELECT count(*)::int AS total,
              count(*) FILTER (WHERE standards @> $1::text[])::int AS mapped
         FROM audit_checks`,
      [[standard]]
    );
    const r = rows[0];
    if (!r || typeof r.total !== 'number') return null;
    return { standard, label: STANDARD_LABEL.get(standard) || standard, ...r };
  } catch (_err) {
    return null;
  }
}

/**
 * Assembles every piece of data the report template needs. Best-effort per
 * query is NOT applied here (unlike most engine-worker jobs) — a report
 * with silently-missing data is worse than a failed report generation the
 * caller can see and retry; a thrown error here propagates straight up to
 * generateReportPdf()'s caller.
 * @param {import('pg').Pool} pool
 */
async function buildReportData(pool, options = {}) {
  const standard = resolveStandard(options.standard);
  const [fleet, perDevice, findingsAppendix, coverage] = await Promise.all([
    computeFleetComplianceScores(pool),
    buildPerDeviceStandards(pool),
    buildFindingsAppendix(pool, standard),
    standardCoverage(pool, standard),
  ]);
  return { fleet, perDevice, findingsAppendix, coverage, standard, generatedAt: new Date() };
}

/**
 * The fleet figure for ONE standard, summed from the per-device stats that
 * were already computed.
 *
 * ⛔ Deliberately NOT a sixth copy of the scoring formula reaching into the
 * database again: these are the same findings over the same active devices, so
 * summing the per-device counts gives the identical numerator and denominator.
 * ⛔ Nothing measurable gives null, NEVER 0 — the same rule as `na` being
 * excluded from the denominator. A standard no device can be assessed against
 * must not print as total non-compliance.
 */
function fleetForStandard(perDevice, standard) {
  const c = { pass: 0, fail: 0, warning: 0, na: 0 };
  for (const d of perDevice) {
    const s = d.standards && d.standards[standard];
    if (!s) continue;
    c.pass += s.pass; c.fail += s.fail; c.warning += s.warning; c.na += s.na;
  }
  const measurable = c.pass + c.fail + c.warning;
  return { ...c, scorePct: measurable > 0 ? Math.round((100 * c.pass) / measurable) : null };
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

// The PDF's palette, mirroring app/globals.css's LIGHT tokens by hand.
//
// ⛔ THESE MUST BE UPDATED WITH THE TOKENS, and nothing enforces it. pdfkit
// draws to a page, not to a DOM, so there is no var() to resolve and no
// stylesheet to inherit -- these literals are the only palette the report
// has. When the tokens moved in v2.87.0 this file was left behind for a
// while, which is exactly the drift to watch for: the product on screen and
// the report a customer receives are the same brand or they are not.
//
// ⛔ Always the LIGHT theme values. A report is printed and emailed; there is
// no viewer preference to read, and a dark-theme PDF is unreadable on paper.
//
// ⛔ ACCENT vs STATUS_RED is the distinction this file must not lose. In
// v2.87.0 the brand moved OFF red precisely so that red means danger and
// nothing else -- so cover chrome and accent bars are now TEAL, and red
// appears in this document only where something is actually wrong. A report
// whose header bar is the same colour as its critical findings trains the
// reader to ignore the colour, on paper just as on screen.
const YELLOW = '#B7791F';      // --yellow / --sev-med
const BLUE = '#2F6FE0';        // --blue
const STATUS_RED = '#D4353B';  // --red / --sev-crit
// ⛔ No hue, by design -- the printed form of --unmeasured. A compliance
// standard with nothing measurable must not print as a 0% or as a pass.
const UNMEASURED = '#6D7784';


function scoreColorHex(pct) {
  // ⛔ A null score is "nothing was measurable", not a low score and not a
  // muted label -- CLAUDE.md excludes `na` from the denominator entirely.
  // It gets the dedicated unmeasured grey so it cannot be read as a value.
  if (pct == null) return UNMEASURED;
  if (pct > 80) return GREEN;
  if (pct >= 60) return YELLOW;
  return STATUS_RED;
}

const STATUS_LABEL = {
  fail: { label: 'Fail', color: STATUS_RED },
  warning: { label: 'Warning', color: YELLOW },
};

const SEVERITY_LABEL = {
  critical: { label: 'Critical', color: STATUS_RED },
  high: { label: 'High', color: YELLOW },
  medium: { label: 'Medium', color: BLUE },
  low: { label: 'Low', color: MUTED },
  info: { label: 'Info', color: MUTED },
};

// Builds the three drawTable() row/column shapes from buildReportData()'s
// output — pure data transforms, no pdfkit calls, so they're easy to reason
// about independently of layout.
function buildFleetSummaryTable(fleet, standard = null) {
  // ⛔ A scoped report shows ONLY its own standard. Listing the other four
  // beside it — greyed, or worse, populated — invites the reader to compare
  // numbers computed over different denominators, which is exactly the
  // confusion the coverage note above exists to prevent.
  const shown = standard ? STANDARDS.filter((s) => s.key === standard) : STANDARDS;
  return {
    columns: [
      { key: 'standard', label: 'Standard', width: 160 },
      { key: 'score', label: 'Score', width: 70, color: (r) => r._color },
      { key: 'pass', label: 'Pass', width: 60 },
      { key: 'fail', label: 'Fail', width: 60 },
      { key: 'warning', label: 'Warning', width: 70 },
    ],
    rows: shown.map((s) => {
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

function buildPerDeviceTable(perDevice, standard = null) {
  // ⛔ THE SCOPED TABLE IS A DIFFERENT SHAPE, not the same table with four
  // columns hidden. With only one score left, a Device/Vendor/percentage row
  // is three cells of mostly whitespace and says less than the five-standard
  // version it replaced. The counts behind the percentage are what a scoped
  // reader actually needs — and showing `na` explicitly is what stops a
  // device scoring 100% off two measurable checks from looking fully assessed.
  if (standard) {
    return {
      columns: [
        { key: 'device', label: 'Device', width: 130 },
        { key: 'vendor', label: 'Vendor', width: 80 },
        { key: 'score', label: 'Score', width: 60, color: (r) => r._color },
        { key: 'pass', label: 'Pass', width: 50 },
        { key: 'fail', label: 'Fail', width: 50 },
        { key: 'warning', label: 'Warning', width: 60 },
        { key: 'na', label: 'Not assessable', width: 80, color: () => UNMEASURED },
      ],
      rows: perDevice.map((d) => {
        const c = d.standards[standard] || { pass: 0, fail: 0, warning: 0, na: 0, scorePct: null };
        return {
          device: d.deviceName,
          vendor: d.vendor,
          score: c.scorePct == null ? '-' : `${c.scorePct}%`,
          pass: c.pass,
          fail: c.fail,
          warning: c.warning,
          na: c.na,
          _color: scoreColorHex(c.scorePct),
        };
      }),
    };
  }
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
  const { fleet, perDevice, findingsAppendix, standard, coverage } = data;

  // ⛔ The scoped headline is the standard's OWN score, not the fleet overall.
  // Printing the overall figure under a "PCI DSS Compliance Report" heading
  // would attribute a number to a framework it was not computed for.
  const headline = standard
    ? fleetForStandard(perDevice, standard).scorePct
    : fleet.overall;
  const scopeName = standard ? (STANDARD_LABEL.get(standard) || standard) : 'Fleet';

  sectionTitle(doc, layout, `${scopeName} Summary — ${headline == null ? '-' : `${headline}%`}`);

  if (standard) {
    const line = coverage
      ? `${coverage.mapped} of ${coverage.total} checks in SecVault's library carry a ${coverage.label} mapping. `
        + `This score is computed over those ${coverage.mapped} only, so it is not comparable with the `
        + 'overall compliance score or with another standard\u2019s score \u2014 the denominators differ. '
        + 'Checks SecVault cannot ask of a device are excluded from the score entirely and are counted '
        + 'separately as not assessable.'
      // ⛔ The coverage read failed. Say that, rather than printing the score
      // with no caveat at all — an unqualified scoped score is the misreading
      // this whole note exists to prevent.
      : 'The number of library checks mapped to this standard could not be read. This score covers only '
        + 'the checks that carry this mapping, so it is not comparable with the overall compliance score.';
    doc.fillColor(MUTED).fontSize(9).font('Helvetica')
      .text(line, layout.left, doc.y, { width: layout.contentW });
    doc.y += 10;
  }

  drawTable(doc, buildFleetSummaryTable(fleet, standard), layout, { continueOnPage: true });

  sectionTitle(doc, layout, 'Per-Device Scores');
  drawTable(doc, buildPerDeviceTable(perDevice, standard), layout, { continueOnPage: true });

  sectionTitle(doc, layout, 'Findings Requiring Attention');
  doc
    .fillColor(MUTED)
    .fontSize(9)
    .font('Helvetica')
    .text(standard
      ? `Failing and warning checks mapped to ${scopeName}, grouped by device. Passing/not-applicable checks are omitted for brevity.`
      : 'Failing and warning checks only, grouped by device. Passing/not-applicable checks are omitted for brevity.', layout.left, doc.y, {
      width: layout.contentW,
    });
  doc.y += 10;

  if (!findingsAppendix.length) {
    doc.fillColor(MUTED).fontSize(10).font('Helvetica-Oblique').text(standard
      ? `No failing or warning findings mapped to ${scopeName} across the fleet.`
      : 'No failing or warning findings across the fleet.', layout.left, doc.y);
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
async function generateReportPdf(pool, options = {}) {
  const data = await buildReportData(pool, options);
  const standardLabel = data.standard
    ? (STANDARD_LABEL.get(data.standard) || data.standard)
    : null;
  const title = standardLabel ? `${standardLabel} Compliance Report` : 'Compliance Report';
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
      title,
      company: PRODUCT_NAME,
      generatedAt,
      // ⛔ Reproduces THIS report's pre-chassis cover exactly: 28pt title at a
      // fixed y, accent rule at 238, 11pt/120px/22px metadata rhythm. Unifying
      // the two covers is a design decision, not a refactor side effect.
      fixedGeometry: true,
      titleSize: 28,
      summary: [
        data.standard
          ? (() => {
            const f = fleetForStandard(data.perDevice, data.standard);
            return { label: `${standardLabel} Score`, value: f.scorePct == null ? '-' : `${f.scorePct}%`, color: scoreColorHex(f.scorePct) };
          })()
          : { label: 'Fleet Score', value: data.fleet.overall == null ? '-' : `${data.fleet.overall}%`, color: scoreColorHex(data.fleet.overall) },
        { label: 'Devices', value: data.perDevice.length, color: NAVY },
        { label: 'Open Findings', value: data.findingsAppendix.reduce((n, g) => n + g.findings.length, 0), color: STATUS_RED },
      ],
    },
    layout
  );

  renderReportBody(doc, data, layout);
  stampHeadersFooters(doc, {
    title: standardLabel ? `SecVault ${standardLabel} Compliance Report` : 'SecVault Compliance Report',
    company: 'SecVault',
    generatedAt,
  });

  return new Promise((resolve, reject) => {
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    doc.end();
  });
}

/**
 * The reporting period: **the calendar month that just ended**, as `YYYY-MM`,
 * derived from the SERVER'S LOCAL clock — the same clock the monthly cron in
 * services/engine-worker.js fires on (node-cron is registered there with no
 * `timezone` option, so it fires in server-local time; see CLAUDE.md's Engine
 * Worker note that every "fixed HH:MM" job in this codebase is server-local,
 * not UTC).
 *
 * ⛔ It used to be `getUTCFullYear()/getUTCMonth()` — the CURRENT month, on a
 * DIFFERENT clock from the cron. On the reference deployment (Asia/Bangkok,
 * UTC+7, confirmed by `current_setting('TimeZone')`) `0 6 1 * *` fires at
 * 06:00 ICT on the 1st, which is 23:00 UTC on the LAST DAY OF THE PREVIOUS
 * MONTH. The two clocks disagreeing across a month boundary broke the
 * once-a-month guarantee in both directions, arithmetically:
 *
 *   1 Oct 06:00 ICT  → UTC month Sep → period 2026-09 → sent, 'success' row for 2026-09
 *   engine restart later that same day (the job also runs at startup)
 *                    → UTC month Oct → period 2026-10 → the SAME report emailed AGAIN
 *   1 Nov 06:00 ICT  → UTC month Oct → period 2026-10 → 'success' row already exists
 *                    → the scheduled tick is SKIPPED, and stays skipped every month after
 *
 * So: double-send in month one, then silence forever. Not yet observed in data
 * (compliance_report_log is empty — no channel is configured for
 * 'compliance_report' on this deployment yet), so this is arithmetic-confirmed,
 * not data-confirmed.
 *
 * Deriving "the month that just ended" from the same clock the cron fires on
 * fixes both halves at once: every tick and every restart ANYWHERE within local
 * October answers 2026-09, so the idempotency row means what it says, and the
 * 1 Nov tick asks a genuinely new question (2026-10).
 *
 * ⛔ CLAUDE.md's rule: the cron's timezone and this derivation are ONE decision.
 * If a `timezone` option is ever added to that cron.schedule() call, this
 * function must move to the same zone in the same commit — changing either
 * alone silently re-opens the bug above.
 */
function reportingPeriod(date = new Date()) {
  // Local getters throughout. Day 1 of (this month - 1); the Date constructor
  // normalises month -1 into December of the previous year on its own.
  const previous = new Date(date.getFullYear(), date.getMonth() - 1, 1);
  return `${previous.getFullYear()}-${String(previous.getMonth() + 1).padStart(2, '0')}`;
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
 *
 * `options.period` ('YYYY-MM') lets the caller state the period EXPLICITLY
 * rather than have it inferred here — services/engine-worker.js's cron job
 * passes it, so the tick and the period it claims are computed from one clock
 * at one call site instead of two functions independently guessing. Omitted
 * (the manual POST /api/compliance/report/generate route), it falls back to the
 * same reportingPeriod() default, so both callers still agree.
 * @param {import('pg').Pool} pool
 * @param {{period?: string}} [options]
 * @returns {Promise<{skipped: boolean, reason?: string, period: string, sent?: number}>}
 */
async function dispatchMonthlyReport(pool, options = {}) {
  const period =
    options && typeof options.period === 'string' && /^\d{4}-\d{2}$/.test(options.period)
      ? options.period
      : reportingPeriod();

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

module.exports = {
  STANDARDS,
  STANDARD_KEYS,
  resolveStandard,
  standardCoverage,
  fleetForStandard,
  buildFleetSummaryTable,
  buildPerDeviceTable,
  buildReportData,
  generateReportPdf,
  dispatchMonthlyReport,
  reportingPeriod,
};
