// lib/reports/fleetLifecycle.js
//
// R7 — "Fleet Lifecycle & Support". Fleet-wide, with an optional narrowing to
// one firewall.
//
// It answers one question: WHAT IS ABOUT TO EXPIRE, GO STALE, OR FALL OVER —
// the renewal-planning and readiness document.
//
// ⛔ THE HAZARD THIS DOCUMENT EXISTS TO AVOID IS A LAPSED SUPPORT CONTRACT, AND
// THE WAY A CONTRACT LAPSES IS NOT THAT SOMEBODY READ THE DATE WRONG. It is
// that the date was never read at all and the row looked fine anyway.
//
// `device_licenses` is TRI-STATE on expiry, and the three states are NOT
// interchangeable:
//
//     expires_at set                  -> a real, parsed date. Plan against it.
//     expires_at NULL, raw 'Never'    -> PERPETUAL. Nothing to renew, ever.
//     expires_at NULL, any other raw  -> UNKNOWN. The vendor gave us a string
//                                        we could not parse. Somebody has to go
//                                        and look.
//
// A report that prints the last two the same way — a blank cell, a dash, "no
// expiry" — tells the reader that an unreadable entitlement is a permanent one.
// That is the failed-read-as-a-fact rule committed in ink, on the one document
// whose entire purpose is to stop a contract lapsing, and it is silent: the page
// looks complete, the table is short, and the renewal never gets raised.
//
// So this report:
//   1. renders the three states with THREE DIFFERENT strings, and gives the
//      unknown one no hue at all;
//   2. counts unknown expiries ON THE COVER, beside the expiring count;
//   3. keeps a fourth, genuinely different state separate — FortiOS reports
//      'n/a' for a component this box has no entitlement for at all. That is a
//      device-asserted fact, not missing information. It must never appear in a
//      renewal table (there is nothing to renew) and must never read as
//      "unknown" (nobody needs to go and look);
//   4. names every firewall SecVault CANNOT ask, and says why — because a
//      renewal list that silently omits four of six vendors is not a short list,
//      it is a wrong one.
//
// ⛔ EVERY VERDICT COMES FROM lib/engines/deviceHealth.js, UNCHANGED. That
// module is the single definition of "is that expiring / stale / degraded", and
// it is shared with /lifecycle and the device Overview card. A second copy of
// the thresholds here would drift, and the first anyone would know is a PDF and
// a screen disagreeing about the same firewall in front of a customer.
//
// CommonJS — same reason as every other report: the App Router route and plain
// node callers both load it.

'use strict';

const PDFDocument = require('pdfkit');

const {
  NAVY, MUTED, GREEN, INK,
  // ⛔ The status ramp comes from the chassis, never from local hex literals.
  // A pair that is amber on screen and red in the PDF an auditor is holding is
  // two different claims about the same firewall.
  STATUS_RED, ORANGE, YELLOW, BLUE, UNMEASURED,
  fmtStamp, installPdfSafeText,
  layoutOf,
  drawCover, sectionTitle, paragraph, labelledNote, drawTable, stampHeadersFooters,
} = require('./chassis');

const { PRODUCT_NAME } = require('../branding');

// ⛔ IMPORTED, NOT RE-DERIVED. Thresholds, the warning window, the HA fault
// list and the disk bands all live in the engine. This file decides how they
// are WORDED on a page; it never decides what they are.
const {
  licenseStatus,
  worstLicenseStatus,
  signatureStatus,
  worstSignatureStatus,
  haStatus,
  diskStatus,
  DEFAULT_LICENSE_WARN_DAYS,
  DEFAULT_SIGNATURE_STALE_DAYS,
  DISK_WARNING_PERCENT,
  DISK_CRITICAL_PERCENT,
} = require('../engines/deviceHealth');

// ── the marks ─────────────────────────────────────────────────────────────

// ⛔ The printed form of UNKNOWN. chassis.pdfSafe() folds this to an ASCII
// hyphen (Helvetica is WinAnsi), which is exactly right: what must never appear
// in an expiry cell is a blank, and what must never appear is a word that reads
// like an answer. A dash reads as "no value"; "Perpetual" reads as a fact.
const NOT_MEASURED_MARK = '—';

const UNKNOWN_EXPIRY_TEXT = `${NOT_MEASURED_MARK} Unknown - vendor string not readable`;
const PERPETUAL_TEXT = 'Perpetual (never expires)';
const NOT_LICENSED_TEXT = 'Not licensed - no entitlement to renew';

const MS_PER_DAY = 24 * 60 * 60 * 1000;

// ── small formatters ──────────────────────────────────────────────────────

function num(n) {
  return Number(n || 0).toLocaleString('en-GB');
}

function plural(n, one, many) {
  return Number(n) === 1 ? one : many;
}

/**
 * DATE columns arrive from node-postgres as a LOCAL-midnight Date, so the local
 * getters are the correct read. toISOString() would shift the day backwards on
 * any positive-offset server — a licence expiring 2026-10-28 printing as
 * 2026-10-27 on an audit artefact. Same treatment as /lifecycle's formatDate().
 */
function formatDate(value) {
  if (!value) return null;
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

/**
 * Display-only day delta.
 *
 * ⛔ Deliberately NOT licenseStatus().daysRemaining, which is null whenever the
 * DEVICE's own `expired` flag decided the verdict. That is the right call for
 * banding and the wrong one for planning: somebody raising a renewal still
 * wants to see how long ago it lapsed.
 */
function dayDelta(value, now) {
  if (!value) return null;
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return Math.floor((d.getTime() - now.getTime()) / MS_PER_DAY);
}

function daysText(delta) {
  if (delta === null || delta === undefined) return NOT_MEASURED_MARK;
  if (delta < 0) return `${num(Math.abs(delta))}d ago`;
  if (delta === 0) return 'today';
  return `in ${num(delta)}d`;
}

/**
 * Clamp a caller-supplied table cap. ⛔ Never 0 — a cap of 0 silently empties a
 * section, which on the page is indistinguishable from "nothing was found".
 */
function clampCap(v, def) {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.max(Math.trunc(n), 1);
}

/**
 * "Showing N of M". ⛔ NEVER A SILENT CAP: a truncated renewal list that does
 * not say it is truncated is a WRONG answer, not a shorter one — the reader
 * budgets for the rows they can see.
 */
function truncationNote(shown, total, noun) {
  if (shown >= total) return null;
  return `Showing ${num(shown)} of ${num(total)} ${noun}, soonest first. `
    + 'The remainder are not in this document - the full list is in the app.';
}

// ── expiry rendering: the centre of this document ─────────────────────────

/**
 * How one licence's expiry READS.
 *
 * ⛔ THE FOUR STATES MUST PRODUCE FOUR DIFFERENT STRINGS. This function is the
 * single place that is true, and it is exported so a test can assert the
 * inequality directly rather than hope a table happens to differ.
 *
 * @param {object} row  a device_licenses row
 * @param {string} status  the verdict from deviceHealth.licenseStatus()
 * @returns {{text:string, kind:'date'|'perpetual'|'unknown'|'not_licensed'}}
 */
function expiryCell(row, status) {
  const date = formatDate(row && row.expires_at);
  if (date) return { text: date, kind: 'date' };
  if (status === 'perpetual') return { text: PERPETUAL_TEXT, kind: 'perpetual' };
  if (status === 'not_licensed') return { text: NOT_LICENSED_TEXT, kind: 'not_licensed' };
  // ⛔ EVERYTHING ELSE IS UNKNOWN, INCLUDING an 'expired' verdict that came from
  // the device's own flag with no date behind it. "The box says this lapsed,
  // and we do not know when" is not a date and must not be drawn as one.
  return {
    text: row && row.expires_raw
      // The vendor's own string, verbatim, in brackets. A reader chasing an
      // unparseable expiry needs to see what the firewall actually said —
      // otherwise the only way to act on this row is to log into the device.
      ? `${UNKNOWN_EXPIRY_TEXT} ("${String(row.expires_raw).trim()}")`
      : UNKNOWN_EXPIRY_TEXT,
    kind: 'unknown',
  };
}

/**
 * ⛔ UNKNOWN AND PERPETUAL GET DIFFERENT COLOURS, AND UNKNOWN GETS NO HUE.
 * Colouring an unreadable expiry green (it is not good news) or red (it is not
 * bad news either) both assert something SecVault does not know.
 */
function licenseColor(status) {
  switch (status) {
    case 'expired': return STATUS_RED;
    case 'expiring': return ORANGE;
    case 'ok': return GREEN;
    case 'perpetual': return BLUE;
    // Neither of these is a renewal signal; neither earns a ramp colour.
    case 'not_licensed': return MUTED;
    default: return UNMEASURED;
  }
}

const LICENSE_LABEL = Object.freeze({
  expired: 'EXPIRED',
  expiring: 'Expiring',
  ok: 'OK',
  perpetual: 'Perpetual',
  not_licensed: 'Not licensed',
  unknown: 'UNKNOWN',
});

function licenseLabel(status) {
  return LICENSE_LABEL[status] || 'UNKNOWN';
}

function haColor(status) {
  switch (status) {
    case 'degraded': return STATUS_RED;
    case 'healthy': return GREEN;
    case 'standalone': return MUTED;
    default: return UNMEASURED;
  }
}

const HA_LABEL = Object.freeze({
  degraded: 'DEGRADED',
  healthy: 'Healthy',
  standalone: 'Standalone (no HA pair)',
  unknown: 'UNKNOWN',
});

function haLabel(status) {
  return HA_LABEL[status] || 'UNKNOWN';
}

/**
 * ⛔ `version_compat_ok` IS TRI-STATE AND NULL IS NOT "OK". NULL means the
 * device reported no Version Compatibility block at all — standalone, or an
 * older PAN-OS. Rendering that as a match would claim a pair is
 * version-consistent on the strength of a question never answered.
 */
function compatCell(value) {
  if (value === true) return { text: 'Match', color: GREEN };
  if (value === false) return { text: 'MISMATCH', color: STATUS_RED };
  return { text: `${NOT_MEASURED_MARK} Not reported`, color: UNMEASURED };
}

function diskColor(status) {
  switch (status) {
    case 'critical': return STATUS_RED;
    case 'warning': return ORANGE;
    case 'ok': return GREEN;
    default: return UNMEASURED;
  }
}

function signatureColor(status) {
  if (status === 'stale') return ORANGE;
  if (status === 'ok') return GREEN;
  return UNMEASURED;
}

// ── coverage: what SecVault can and cannot ask each firewall ──────────────

const FACTS = Object.freeze(['licenses', 'ha', 'disk', 'content']);

const FACT_LABEL = Object.freeze({
  licenses: 'Licences & support contracts',
  ha: 'High availability',
  disk: 'Disk capacity',
  content: 'Content / signature versions',
});

/**
 * Four coverage states, and the two middle ones are the point.
 *
 * ⛔ "THIS FIREWALL CANNOT BE ASKED" AND "THIS FIREWALL CAN BE ASKED AND WE
 * HAVE NOTHING" ARE DIFFERENT PROBLEMS with different owners. The first is a
 * known limit of the product and needs no action on the device. The second is a
 * COLLECTION FAILURE on a firewall that would have answered — and it is the one
 * that silently shortens a renewal list, because the firewall looks like one of
 * the unsupported ones.
 *
 * @param {boolean|null} supported  can this vendor/access method report it?
 *                                  null = SecVault could not determine that.
 * @param {boolean} hasRows         did any rows actually arrive?
 * @param {boolean} queryOk         did the read itself succeed?
 * @returns {'collected'|'not_supported'|'not_collected'|'unknown'}
 */
function factCoverage(supported, hasRows, queryOk) {
  // ⛔ FIRST, because a failed read outranks everything below it. If we could
  // not read the table we do not know whether rows exist, and "no rows" from a
  // failed query is the single most dangerous value this function could return.
  if (queryOk === false) return 'unknown';
  if (hasRows) return 'collected';
  if (supported === false) return 'not_supported';
  if (supported === true) return 'not_collected';
  return 'unknown';
}

const COVERAGE_LABEL = Object.freeze({
  collected: 'Collected',
  not_supported: 'Cannot be asked',
  not_collected: 'NOT COLLECTED',
  unknown: 'Unknown',
});

function coverageColor(state) {
  if (state === 'collected') return GREEN;
  // ⛔ Amber, not hueless: a firewall that CAN answer and has not is a gap
  // somebody can close, and it is the state that quietly shortens this report.
  if (state === 'not_collected') return ORANGE;
  // A product limit and an unreadable table are both "we do not know", and
  // neither is good or bad news. No hue.
  return UNMEASURED;
}

/**
 * The sentence that travels WITH a coverage cell. Pure and exported so the
 * wording is pinned — every one of these exists to stop an absence being read
 * as a clean result.
 */
function coverageReason(fact, state, vendor, mgmtMethod) {
  const access = `${vendor}${mgmtMethod ? ` over ${mgmtMethod}` : ''}`;
  switch (state) {
    case 'collected':
      return '';
    case 'not_supported':
      return `SecVault cannot read ${FACT_LABEL[fact].toLowerCase()} from ${access}. `
        + 'This is a gap in what the product can ask, not a statement about the firewall.';
    case 'not_collected':
      return `${access} CAN report ${FACT_LABEL[fact].toLowerCase()}, but nothing has been `
        + 'collected. Treat this as a collection failure to investigate, not as an empty result.';
    default:
      return `Whether ${access} can report ${FACT_LABEL[fact].toLowerCase()} could not be `
        + 'determined for this run, and no rows were found. Neither an answer nor the absence of '
        + 'one is claimed here.';
  }
}

/**
 * Which of the four facts a (vendor, access method) pair can supply.
 *
 * ⛔ DERIVED FROM THE ADAPTER REGISTRY, NOT FROM A TABLE TYPED IN HERE. A
 * hardcoded vendor matrix in a report is a promise that goes stale the first
 * time an adapter gains a method, and it goes stale SILENTLY — the document
 * keeps saying a firewall cannot be asked long after it can, and the reader
 * stops chasing a gap that has been closed. (Live proof that this happens:
 * Fortinet-over-SSH gained getHaStatus(), and the prose describing it as
 * deferred outlived the code by some time.)
 *
 * ⛔ CONTENT VERSIONS ARE DELIBERATELY ABSENT from the probe and always resolve
 * to null. They arrive as a FIELD on getVersion()'s response rather than as a
 * method of their own, so there is nothing to detect — and inventing a
 * confident false here would be worse than an honest unknown.
 *
 * ⛔ NOTHING IS CALLED ON THE ADAPTER. This constructs one with a null pool
 * purely to ask which methods exist. It opens no connection, issues no command
 * and touches no device; a report must never talk to a firewall.
 *
 * Any failure resolves to all-null, i.e. UNKNOWN — never to "supported" and
 * never to "unsupported".
 */
function probeFactSupport(vendor, mgmtMethod) {
  const unknown = { licenses: null, ha: null, disk: null, content: null };
  try {
    // Lazy require: if the adapter graph cannot load in this process, coverage
    // degrades to unknown rather than taking the whole report down with it.
    const { getAdapter } = require('../adapters');
    const adapter = getAdapter({ id: null, vendor, mgmt_method: mgmtMethod }, null);
    return {
      licenses: typeof adapter.getLicenses === 'function',
      ha: typeof adapter.getHaStatus === 'function',
      disk: typeof adapter.getDiskUsage === 'function',
      content: null,
    };
  } catch (err) {
    return unknown;
  }
}

function makeSupportProbe() {
  const cache = new Map();
  return (vendor, mgmtMethod) => {
    const key = `${vendor}|${mgmtMethod || ''}`;
    if (!cache.has(key)) cache.set(key, probeFactSupport(vendor, mgmtMethod));
    return cache.get(key);
  };
}

// ── renewal ordering ──────────────────────────────────────────────────────

/**
 * Soonest first, and ⛔ EVERY UNDATED ROW LAST.
 *
 * PostgreSQL sorts NULLs FIRST for ASC, which on this table would put every
 * unreadable and every perpetual entitlement at the head of a list whose
 * heading says "soonest first" — the two rows that are NOT deadlines,
 * presented as the most urgent ones, pushing a contract that lapses next month
 * below the fold. The SQL carries NULLS LAST and so does this comparator, so
 * the order survives any later regrouping in JS.
 *
 * Among undated rows, UNKNOWN comes before perpetual: one needs a human, the
 * other needs nothing.
 */
function compareRenewals(a, b) {
  const at = a.expiresAt ? new Date(a.expiresAt).getTime() : null;
  const bt = b.expiresAt ? new Date(b.expiresAt).getTime() : null;
  if (at !== null && bt !== null) {
    if (at !== bt) return at - bt;
  } else if (at !== null) {
    return -1;
  } else if (bt !== null) {
    return 1;
  } else {
    const rank = (x) => (x.status === 'unknown' ? 0 : 1);
    const ra = rank(a);
    const rb = rank(b);
    if (ra !== rb) return ra - rb;
  }
  return String(a.deviceName || '').localeCompare(String(b.deviceName || ''));
}

/**
 * Licences bought together on one contract share an expiry date. Live, a single
 * Palo Alto carries nine entitlements expiring the same day and a FortiGate
 * carries thirty-four — listing them individually turns ONE purchasing decision
 * into thirty-four rows and makes a plan into a scroll.
 *
 * ⛔ The group's status is the WORST of its members, via the engine's own
 * worstLicenseStatus(), so nothing urgent hides inside a collapsed group.
 */
function groupRenewals(entries, now, warnDays) {
  const groups = new Map();
  for (const e of entries) {
    const dateKey = e.row.expires_at
      ? formatDate(e.row.expires_at)
      // Key on the raw string so unreadable values still group per device
      // rather than each becoming its own singleton row.
      : `raw:${e.row.expires_raw || 'none'}`;
    const key = `${e.deviceId}|${dateKey}`;
    let g = groups.get(key);
    if (!g) {
      g = {
        key,
        deviceId: e.deviceId,
        deviceName: e.deviceName,
        vendor: e.vendor,
        mgmtMethod: e.mgmtMethod,
        expiresAt: e.row.expires_at || null,
        expiresRaw: e.row.expires_raw || null,
        rows: [],
        features: [],
        status: 'unknown',
        daysRemaining: null,
        expiry: null,
      };
      groups.set(key, g);
    }
    g.rows.push(e.row);
    if (e.row.feature) g.features.push(String(e.row.feature).trim());
  }

  for (const g of groups.values()) {
    const worst = worstLicenseStatus(g.rows, now, warnDays);
    g.status = worst.status;
    g.delta = dayDelta(g.expiresAt, now);
    g.expiry = expiryCell(g.rows[0], worst.status);
    g.label = g.features.length === 1
      ? g.features[0]
      : `${num(g.features.length)} ${plural(g.features.length, 'entitlement', 'entitlements')}: `
        + g.features.slice(0, 6).join(', ')
        + (g.features.length > 6 ? `, +${num(g.features.length - 6)} more` : '');
  }

  return Array.from(groups.values()).sort(compareRenewals);
}

// ── the headline ──────────────────────────────────────────────────────────

/**
 * The answer-first sentence at the top of the document.
 *
 * ⛔ AN ALL-CLEAR IS FORBIDDEN WHILE COVERAGE IS INCOMPLETE. "The fleet's
 * support is in good order" is a claim about every firewall, and it cannot be
 * made from a subset. If four of six vendors cannot report a licence, the most
 * this document may say is that the firewalls it CAN see look fine.
 *
 * Pure — takes totals, returns a string.
 */
function headlineSentence(totals) {
  const fleet = `${num(totals.devices)} ${plural(totals.devices, 'firewall', 'firewalls')}`;

  const urgent = [];
  if (totals.licensesExpired > 0) {
    urgent.push(`${num(totals.licensesExpired)} ${plural(totals.licensesExpired, 'entitlement has', 'entitlements have')} already expired`);
  }
  if (totals.licensesExpiring > 0) {
    urgent.push(`${num(totals.licensesExpiring)} ${plural(totals.licensesExpiring, 'expires', 'expire')} within ${num(totals.warnDays)} days`);
  }
  if (totals.haDegraded > 0) {
    urgent.push(`${num(totals.haDegraded)} HA ${plural(totals.haDegraded, 'pair is', 'pairs are')} degraded`);
  }
  if (totals.diskCritical > 0) {
    urgent.push(`${num(totals.diskCritical)} ${plural(totals.diskCritical, 'firewall is', 'firewalls are')} above ${DISK_CRITICAL_PERCENT}% on a filesystem`);
  }
  if (totals.signaturesStale > 0) {
    urgent.push(`${num(totals.signaturesStale)} ${plural(totals.signaturesStale, 'firewall carries', 'firewalls carry')} content older than ${num(totals.staleDays)} days`);
  }

  const gaps = [];
  if (totals.licensesUnknownExpiry > 0) {
    gaps.push(
      `${num(totals.licensesUnknownExpiry)} ${plural(totals.licensesUnknownExpiry, 'entitlement carries', 'entitlements carry')} an expiry date `
      + 'SecVault could not read, so none of them can be planned for or ruled out'
    );
  }
  if (totals.devicesNoLicenseData > 0) {
    gaps.push(
      `${num(totals.devicesNoLicenseData)} ${plural(totals.devicesNoLicenseData, 'firewall has', 'firewalls have')} no licence data at all, `
      + 'so anything expiring on them is absent from this document rather than absent from the estate'
    );
  }
  if (totals.devicesNoHaData > 0) {
    gaps.push(
      `${num(totals.devicesNoHaData)} ${plural(totals.devicesNoHaData, 'firewall has', 'firewalls have')} no HA status collected`
    );
  }
  if (totals.devicesNoDiskData > 0) {
    gaps.push(
      `${num(totals.devicesNoDiskData)} ${plural(totals.devicesNoDiskData, 'firewall reports', 'firewalls report')} no disk usage`
    );
  }
  if (totals.devicesNoContentData > 0) {
    gaps.push(
      `${num(totals.devicesNoContentData)} ${plural(totals.devicesNoContentData, 'firewall reports', 'firewalls report')} no content or signature versions`
    );
  }
  if (totals.haCompatUnreported > 0) {
    gaps.push(
      `${num(totals.haCompatUnreported)} HA ${plural(totals.haCompatUnreported, 'pair has', 'pairs have')} not reported whether their `
      + 'software versions match, which is not the same as reporting that they do'
    );
  }

  const head = urgent.length === 0
    // ⛔ Not "everything is fine". Whether this can be read as good news is
    // decided entirely by the gaps clause below.
    ? `Across ${fleet} SecVault found nothing expired, expiring within ${num(totals.warnDays)} days, `
      + 'degraded or out of disk.'
    : `Across ${fleet}, ${urgent.join('; ')}.`;

  if (gaps.length === 0) {
    return urgent.length === 0
      ? `${head} Every firewall in scope reported its licences, its HA state, its disk and its `
        + 'content versions, and every expiry date was readable.'
      : `${head} Every firewall in scope reported all four, and every expiry date was readable.`;
  }

  // ⛔ THE ONLY SENTENCE THAT MAY FOLLOW AN EMPTY URGENT LIST WHEN A GAP EXISTS.
  return `${head} THIS IS NOT A COMPLETE PICTURE: ${gaps.join('; ')}. `
    + 'Nothing above is offered as an all-clear for the estate.';
}

// ── data assembly ─────────────────────────────────────────────────────────

const DEFAULT_MAX_RENEWAL_ROWS = 250;

const DEVICE_COLUMNS = `id, name, vendor, mgmt_method, mgmt_ip, site, active,
            asset_criticality, last_collected_at, last_connectivity_ok`;

/**
 * Fetch everything the cover and the body need.
 *
 * ⛔ THE DEVICE LIST IS NOT BEST-EFFORT — without it there is no document. The
 * FOUR FACT TABLES ARE, and their failure is RECORDED rather than swallowed:
 * a licence query that throws must leave every firewall's licence coverage
 * UNKNOWN and say so on the page. The alternative — an empty array flowing on
 * into an empty renewal table — renders a clean, confident, completely wrong
 * "nothing is expiring".
 *
 * @param {import('pg').Pool} pool
 * @param {object} [options]
 * @param {string} [options.deviceId]  omit for a fleet-wide report
 * @param {Date}   [options.now]
 * @param {number} [options.warnDays]
 * @param {number} [options.staleDays]
 * @param {number} [options.maxRenewalRows]
 * @returns {Promise<object|null>} null only when a named device does not exist.
 */
async function buildFleetLifecycleData(pool, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date();
  const warnDays = Number.isFinite(Number(options.warnDays))
    ? Number(options.warnDays) : DEFAULT_LICENSE_WARN_DAYS;
  const staleDays = Number.isFinite(Number(options.staleDays))
    ? Number(options.staleDays) : DEFAULT_SIGNATURE_STALE_DAYS;
  const maxRenewalRows = clampCap(options.maxRenewalRows, DEFAULT_MAX_RENEWAL_ROWS);
  const deviceId = options.deviceId || null;

  // ⛔ A gathering failure is a first-class section in the document, not a log
  // line. A section that quietly disappears reads as a section with nothing in
  // it, and "we could not look" is then presented as "there was nothing there".
  const sectionErrors = [];

  // ⛔ A device-scoped report deliberately does NOT filter on `active`. An
  // operator planning the renewal of a firewall they have just deactivated
  // still needs its contracts; returning null would look like the device had
  // vanished from inventory rather than that it was switched off.
  const { rows: deviceRows } = deviceId
    ? await pool.query(
      `SELECT ${DEVICE_COLUMNS}
         FROM devices
        WHERE id = $1::uuid`,
      [deviceId]
    )
    : await pool.query(
      `SELECT ${DEVICE_COLUMNS}
         FROM devices
        WHERE active = true
        ORDER BY name`
    );

  if (deviceRows.length === 0) return null;
  const ids = deviceRows.map((d) => d.id);

  /** Best-effort read. Returns `{ok, rows}` — never a bare array. */
  async function tryQuery(section, sql, params, guidance) {
    try {
      const { rows } = await pool.query(sql, params);
      return { ok: true, rows };
    } catch (err) {
      sectionErrors.push({ section, message: `${section} could not be read (${err.message}). ${guidance}` });
      return { ok: false, rows: [] };
    }
  }

  // ⛔ ORDER BY l.expires_at ASC NULLS LAST. PostgreSQL's ASC default is NULLS
  // FIRST, which would head a "soonest first" renewal list with every
  // unreadable and every perpetual entitlement — the rows that are not
  // deadlines, ranked above the ones that are.
  const licenseRes = await tryQuery(
    'Licences and support contracts',
    `SELECT l.id, l.device_id, l.feature, l.description, l.serial,
            l.expires_at, l.expires_raw, l.expired, l.collected_at
       FROM device_licenses l
      WHERE l.device_id = ANY($1::uuid[])
      ORDER BY l.expires_at ASC NULLS LAST, l.feature ASC`,
    [ids],
    'Every firewall\'s licence coverage is reported as UNKNOWN below. SecVault is NOT claiming '
    + 'that nothing is expiring.'
  );

  const haRes = await tryQuery(
    'High availability',
    `SELECT h.device_id, h.enabled, h.mode, h.local_state, h.peer_state, h.peer_mgmt_ip,
            h.peer_connection_status, h.config_sync_state, h.last_nonfunctional_reason,
            h.version_compat_ok, h.version_compat, h.collected_at
       FROM device_ha_status h
      WHERE h.device_id = ANY($1::uuid[])`,
    [ids],
    'No redundancy verdict is offered for any firewall. An absent HA section is not a healthy one.'
  );

  const diskRes = await tryQuery(
    'Disk capacity',
    `SELECT u.device_id, u.filesystem, u.mounted_on, u.size_raw, u.used_raw, u.avail_raw,
            u.use_percent, u.collected_at
       FROM device_disk_usage u
      WHERE u.device_id = ANY($1::uuid[])
      ORDER BY u.use_percent DESC NULLS LAST`,
    [ids],
    'No filesystem is reported as full or as healthy.'
  );

  const contentRes = await tryQuery(
    'Content and signature versions',
    `SELECT c.device_id, c.component, c.version, c.released_at, c.collected_at
       FROM device_content_versions c
      WHERE c.device_id = ANY($1::uuid[])
      ORDER BY c.component ASC`,
    [ids],
    'No firewall is reported as carrying current signatures, nor as carrying stale ones.'
  );

  const versionRes = await tryQuery(
    'Installed software version',
    `SELECT DISTINCT ON (device_id) device_id, version_string, build, model, collected_at
       FROM device_versions
      WHERE device_id = ANY($1::uuid[])
      ORDER BY device_id, collected_at DESC`,
    [ids],
    'The installed version column reads as unknown.'
  );

  const byDevice = (rows) => {
    const m = new Map();
    for (const r of rows) {
      if (!m.has(r.device_id)) m.set(r.device_id, []);
      m.get(r.device_id).push(r);
    }
    return m;
  };
  const licensesBy = byDevice(licenseRes.rows);
  const haBy = new Map(haRes.rows.map((r) => [r.device_id, r]));
  const diskBy = byDevice(diskRes.rows);
  const contentBy = byDevice(contentRes.rows);
  const versionBy = new Map(versionRes.rows.map((r) => [r.device_id, r]));

  const supportOf = makeSupportProbe();

  // ── per-device assembly ─────────────────────────────────────────────────
  const devices = deviceRows.map((d) => {
    const supported = supportOf(d.vendor, d.mgmt_method);
    const licenses = licensesBy.get(d.id) || [];
    const haRow = haBy.get(d.id) || null;
    const disks = diskBy.get(d.id) || [];
    const content = contentBy.get(d.id) || [];
    const version = versionBy.get(d.id) || null;

    const coverage = {
      licenses: factCoverage(supported.licenses, licenses.length > 0, licenseRes.ok),
      ha: factCoverage(supported.ha, Boolean(haRow), haRes.ok),
      disk: factCoverage(supported.disk, disks.length > 0, diskRes.ok),
      // ⛔ `supported.content` is always null — see probeFactSupport(). A
      // firewall with no content rows is therefore UNKNOWN, never "cannot be
      // asked": SecVault genuinely does not know which it is.
      content: factCoverage(supported.content, content.length > 0, contentRes.ok),
    };

    // Each licence with its own verdict, from the engine.
    const licenseItems = licenses.map((row) => {
      const s = licenseStatus(row, now, warnDays);
      return {
        row,
        status: s.status,
        daysRemaining: s.daysRemaining,
        delta: dayDelta(row.expires_at, now),
        expiry: expiryCell(row, s.status),
      };
    });

    // ⛔ `worstLicenseStatus` of an EMPTY array returns 'unknown', which is
    // exactly right and must not be second-guessed into 'ok' by a length check.
    const worstLicense = worstLicenseStatus(licenses, now, warnDays);
    const ha = haStatus(haRow);
    const disk = diskStatus(disks);
    const contentItems = content.map((row) => {
      const s = signatureStatus(row, now, staleDays);
      return { row, status: s.status, ageDays: s.ageDays };
    });
    const worstSignature = worstSignatureStatus(content, now, staleDays);

    return {
      id: d.id,
      name: d.name,
      vendor: d.vendor,
      mgmtMethod: d.mgmt_method,
      mgmtIp: d.mgmt_ip,
      site: d.site,
      active: d.active,
      assetCriticality: d.asset_criticality,
      lastCollectedAt: d.last_collected_at,
      lastConnectivityOk: d.last_connectivity_ok,
      versionString: version ? version.version_string : null,
      model: version ? version.model : null,
      supported,
      coverage,
      licenses: licenseItems,
      worstLicense,
      haRow,
      ha,
      disks,
      disk,
      content: contentItems,
      worstSignature,
      // Components the device listed with no release date — PAN-OS reports none
      // for url-filtering. Their age is unknowable, and it is NOT zero.
      contentNoReleaseDate: contentItems.filter((c) => c.status === 'unknown').length,
    };
  });

  // ── renewal timeline ────────────────────────────────────────────────────
  // ⛔ 'not_licensed' rows are EXCLUDED, per deviceHealth.js's own rule: FortiOS
  // says 'n/a' for a component this box has no entitlement for, and there is
  // nothing to renew. They are COUNTED below and named in the coverage section,
  // so the exclusion is visible rather than a silently shorter table.
  const renewalEntries = [];
  let notLicensed = 0;
  for (const dev of devices) {
    for (const item of dev.licenses) {
      if (item.status === 'not_licensed') { notLicensed += 1; continue; }
      renewalEntries.push({
        deviceId: dev.id,
        deviceName: dev.name,
        vendor: dev.vendor,
        mgmtMethod: dev.mgmtMethod,
        row: item.row,
        status: item.status,
      });
    }
  }
  const renewals = groupRenewals(renewalEntries, now, warnDays);

  // ── totals ──────────────────────────────────────────────────────────────
  const countLicenses = (pred) => devices.reduce(
    (a, d) => a + d.licenses.filter(pred).length, 0
  );
  const countDevices = (pred) => devices.filter(pred).length;

  const totals = {
    warnDays,
    staleDays,
    devices: devices.length,

    licenses: devices.reduce((a, d) => a + d.licenses.length, 0),
    licensesExpired: countLicenses((l) => l.status === 'expired'),
    licensesExpiring: countLicenses((l) => l.status === 'expiring'),
    licensesOk: countLicenses((l) => l.status === 'ok'),
    licensesPerpetual: countLicenses((l) => l.status === 'perpetual'),
    // ⛔ THE NUMBER THIS DOCUMENT EXISTS FOR, beside the expiring count and
    // never folded into it.
    licensesUnknownExpiry: countLicenses((l) => l.status === 'unknown'),
    licensesNotLicensed: notLicensed,
    renewalEvents: renewals.length,
    renewalEventsExpired: renewals.filter((r) => r.status === 'expired').length,
    renewalEventsExpiring: renewals.filter((r) => r.status === 'expiring').length,
    renewalEventsUnknown: renewals.filter((r) => r.status === 'unknown').length,

    haDegraded: countDevices((d) => d.ha.status === 'degraded'),
    haHealthy: countDevices((d) => d.ha.status === 'healthy'),
    haStandalone: countDevices((d) => d.ha.status === 'standalone'),
    haUnknown: countDevices((d) => d.ha.status === 'unknown'),
    // Pairs in HA that have NOT told us whether their versions match. NULL is
    // not a match — see compatCell().
    haCompatUnreported: countDevices(
      (d) => d.haRow && d.haRow.enabled === true
        && (d.haRow.version_compat_ok === null || d.haRow.version_compat_ok === undefined)
    ),
    haCompatMismatch: countDevices((d) => d.haRow && d.haRow.version_compat_ok === false),

    diskCritical: countDevices((d) => d.disk.status === 'critical'),
    diskWarning: countDevices((d) => d.disk.status === 'warning'),
    diskOk: countDevices((d) => d.disk.status === 'ok'),
    diskUnknown: countDevices((d) => d.disk.status === 'unknown'),

    signaturesStale: countDevices((d) => d.worstSignature.status === 'stale'),
    signaturesOk: countDevices((d) => d.worstSignature.status === 'ok'),
    signaturesUnknown: countDevices((d) => d.worstSignature.status === 'unknown'),
    contentNoReleaseDate: devices.reduce((a, d) => a + d.contentNoReleaseDate, 0),

    // Coverage. ⛔ "No data" here counts BOTH not_supported and not_collected
    // and unknown — every firewall this report cannot speak for.
    devicesNoLicenseData: countDevices((d) => d.coverage.licenses !== 'collected'),
    devicesNoHaData: countDevices((d) => d.coverage.ha !== 'collected'),
    devicesNoDiskData: countDevices((d) => d.coverage.disk !== 'collected'),
    devicesNoContentData: countDevices((d) => d.coverage.content !== 'collected'),
    // The materially different sub-case: it CAN answer and we have nothing.
    devicesCollectionGap: countDevices(
      (d) => FACTS.some((f) => d.coverage[f] === 'not_collected')
    ),
  };

  const coverageGaps = FACTS.map((fact) => ({
    fact,
    label: FACT_LABEL[fact],
    notSupported: devices.filter((d) => d.coverage[fact] === 'not_supported').length,
    notCollected: devices.filter((d) => d.coverage[fact] === 'not_collected').length,
    unknown: devices.filter((d) => d.coverage[fact] === 'unknown').length,
    collected: devices.filter((d) => d.coverage[fact] === 'collected').length,
  }));

  return {
    scope: deviceId ? 'device' : 'fleet',
    device: deviceId ? devices[0] : null,
    generatedAt: now,
    warnDays,
    staleDays,
    diskWarningPercent: DISK_WARNING_PERCENT,
    diskCriticalPercent: DISK_CRITICAL_PERCENT,
    devices,
    renewals,
    coverageGaps,
    totals,
    sectionErrors,
    caps: { maxRenewalRows },
    headline: headlineSentence(totals),
  };
}

// ── tables ────────────────────────────────────────────────────────────────

function buildRenewalTable(groups, includeDevice) {
  const columns = [];
  if (includeDevice) columns.push({ key: 'device', label: 'Firewall', width: 60, font: 'Helvetica-Bold' });
  columns.push(
    { key: 'expiry', label: 'Expires', width: 108, color: (r) => r._color, font: 'Helvetica-Bold' },
    { key: 'days', label: 'When', width: 40, color: (r) => r._color },
    { key: 'status', label: 'Status', width: 40, color: (r) => r._color, font: 'Helvetica-Bold' },
    { key: 'items', label: 'Entitlements on this contract date', width: 190 },
    { key: 'access', label: 'Vendor / access', width: 52, color: MUTED }
  );
  return {
    columns,
    rows: groups.map((g) => ({
      device: g.deviceName,
      expiry: g.expiry.text,
      // ⛔ A dash, never a 0 and never a blank. An undated entitlement has no
      // "when", and the cell must not be readable as "due now" or "no rush".
      days: g.expiry.kind === 'date' ? daysText(g.delta) : NOT_MEASURED_MARK,
      status: licenseLabel(g.status),
      items: g.label,
      access: `${g.vendor}${g.mgmtMethod ? ` / ${g.mgmtMethod}` : ''}`,
      _color: licenseColor(g.status),
    })),
  };
}

function buildHaTable(devices) {
  return {
    columns: [
      { key: 'device', label: 'Firewall', width: 62, font: 'Helvetica-Bold' },
      { key: 'status', label: 'Redundancy', width: 66, color: (r) => r._color, font: 'Helvetica-Bold' },
      { key: 'mode', label: 'Mode / local state', width: 62, color: MUTED },
      { key: 'peer', label: 'Peer', width: 62, color: MUTED },
      { key: 'sync', label: 'Config sync', width: 52, color: (r) => r._syncColor },
      { key: 'compat', label: 'Version compatibility', width: 56, color: (r) => r._compatColor, font: 'Helvetica-Bold' },
      { key: 'notes', label: 'What the firewall reported', width: 150, color: (r) => r._notesColor },
    ],
    rows: devices.map((d) => {
      const row = d.haRow;
      const compat = compatCell(row ? row.version_compat_ok : null);
      const sync = row && row.config_sync_state ? String(row.config_sync_state) : null;
      const syncOk = sync ? /^synchronized$/i.test(sync.trim()) : null;
      const notes = d.ha.reasons.length > 0
        ? d.ha.reasons.join(' ')
        : (d.coverage.ha === 'collected'
          ? (d.ha.status === 'standalone'
            ? 'The firewall reported that HA is not enabled. This is a collected fact, not a gap.'
            : 'Peer up, configuration synchronized, nothing reported non-functional.')
          : coverageReason('ha', d.coverage.ha, d.vendor, d.mgmtMethod));
      return {
        device: d.name,
        // ⛔ Coverage beats verdict. A firewall we never asked is not
        // "standalone" and is not "unknown HA" in the same sense — it is a
        // firewall this report cannot speak for, and the cell says so.
        status: d.coverage.ha === 'collected'
          ? haLabel(d.ha.status)
          : `${NOT_MEASURED_MARK} ${COVERAGE_LABEL[d.coverage.ha]}`,
        mode: row && row.enabled
          ? `${row.mode || NOT_MEASURED_MARK} / ${row.local_state || NOT_MEASURED_MARK}`
          : NOT_MEASURED_MARK,
        peer: row && row.enabled
          ? `${row.peer_state || NOT_MEASURED_MARK}${row.peer_mgmt_ip ? ` (${row.peer_mgmt_ip})` : ''}`
          : NOT_MEASURED_MARK,
        sync: row && row.enabled ? (sync || `${NOT_MEASURED_MARK} Not reported`) : NOT_MEASURED_MARK,
        compat: row && row.enabled ? compat.text : NOT_MEASURED_MARK,
        notes,
        _color: d.coverage.ha === 'collected' ? haColor(d.ha.status) : UNMEASURED,
        // ⛔ ABSENT IS NEVER GREEN. A pair that reported no sync state has not
        // told us it is in sync.
        _syncColor: syncOk === true ? GREEN : syncOk === false ? ORANGE : UNMEASURED,
        _compatColor: row && row.enabled ? compat.color : UNMEASURED,
        _notesColor: d.ha.reasons.length > 0 ? STATUS_RED : MUTED,
      };
    }),
  };
}

function buildDiskTable(devices) {
  return {
    columns: [
      { key: 'device', label: 'Firewall', width: 62, font: 'Helvetica-Bold' },
      { key: 'status', label: 'Worst filesystem', width: 62, color: (r) => r._color, font: 'Helvetica-Bold' },
      { key: 'pct', label: 'Used', width: 30, align: 'right', color: (r) => r._color, font: 'Helvetica-Bold' },
      { key: 'mount', label: 'Mount point', width: 78, color: MUTED },
      { key: 'size', label: 'Size', width: 34, align: 'right', color: MUTED },
      { key: 'used', label: 'Used', width: 34, align: 'right', color: MUTED },
      { key: 'avail', label: 'Available', width: 38, align: 'right', color: MUTED },
      { key: 'mounts', label: 'Filesystems seen', width: 40, align: 'right', color: MUTED },
      { key: 'note', label: 'Notes', width: 132, color: (r) => r._noteColor },
    ],
    rows: devices.map((d) => {
      const worst = d.disk.row || null;
      const covered = d.coverage.disk === 'collected';
      return {
        device: d.name,
        status: covered
          ? (d.disk.status === 'unknown'
            ? `${NOT_MEASURED_MARK} No usable percentage`
            : d.disk.status.toUpperCase())
          : `${NOT_MEASURED_MARK} ${COVERAGE_LABEL[d.coverage.disk]}`,
        // ⛔ Only the percentage is numeric. Everything else stays the device's
        // own `df -h` string, verbatim.
        pct: d.disk.usePercent === null || d.disk.usePercent === undefined
          ? NOT_MEASURED_MARK
          : `${d.disk.usePercent}%`,
        mount: worst ? (worst.mounted_on || worst.filesystem || NOT_MEASURED_MARK) : NOT_MEASURED_MARK,
        size: worst && worst.size_raw ? worst.size_raw : NOT_MEASURED_MARK,
        used: worst && worst.used_raw ? worst.used_raw : NOT_MEASURED_MARK,
        avail: worst && worst.avail_raw ? worst.avail_raw : NOT_MEASURED_MARK,
        mounts: covered ? num(d.disks.length) : NOT_MEASURED_MARK,
        note: covered
          ? (d.disk.status === 'critical'
            ? `At or above ${DISK_CRITICAL_PERCENT}%. Log or content updates can fail once a filesystem fills.`
            : d.disk.status === 'warning'
              ? `At or above ${DISK_WARNING_PERCENT}%. Watch this one.`
              : '')
          : coverageReason('disk', d.coverage.disk, d.vendor, d.mgmtMethod),
        _color: covered ? diskColor(d.disk.status) : UNMEASURED,
        _noteColor: covered && d.disk.status === 'critical' ? STATUS_RED : UNMEASURED,
      };
    }),
  };
}

function buildSignatureTable(devices, staleDays) {
  return {
    columns: [
      { key: 'device', label: 'Firewall', width: 62, font: 'Helvetica-Bold' },
      { key: 'version', label: 'Software version', width: 56, color: MUTED },
      { key: 'status', label: 'Content freshness', width: 62, color: (r) => r._color, font: 'Helvetica-Bold' },
      { key: 'oldest', label: 'Oldest component', width: 66 },
      { key: 'released', label: 'Released', width: 50, color: MUTED },
      { key: 'age', label: 'Age', width: 34, align: 'right', color: (r) => r._color },
      { key: 'components', label: 'Components', width: 40, align: 'right', color: MUTED },
      { key: 'note', label: 'Notes', width: 140, color: (r) => r._noteColor },
    ],
    rows: devices.map((d) => {
      const covered = d.coverage.content === 'collected';
      const worst = d.worstSignature;
      const row = worst.row || null;
      const undated = d.contentNoReleaseDate;
      const notes = [];
      if (!covered) {
        notes.push(coverageReason('content', d.coverage.content, d.vendor, d.mgmtMethod));
      } else {
        if (worst.status === 'stale') {
          notes.push(`Older than ${num(staleDays)} days.`);
        }
        if (undated > 0) {
          // ⛔ Counted, never treated as fresh. A component with no release date
          // has an unknowable age, and an unknowable age is not a young one.
          notes.push(
            `${num(undated)} ${plural(undated, 'component reports', 'components report')} no release date, `
            + 'so their age is unknown - not current.'
          );
        }
        if (worst.status === 'unknown' && undated === 0) {
          notes.push('No component carried a readable release date, so freshness is unknown.');
        }
      }
      return {
        device: d.name,
        version: d.versionString || NOT_MEASURED_MARK,
        status: covered
          ? (worst.status === 'unknown' ? `${NOT_MEASURED_MARK} Unknown` : worst.status.toUpperCase())
          : `${NOT_MEASURED_MARK} ${COVERAGE_LABEL[d.coverage.content]}`,
        oldest: row ? (row.component || NOT_MEASURED_MARK) : NOT_MEASURED_MARK,
        released: row && row.released_at ? formatDate(row.released_at) : NOT_MEASURED_MARK,
        age: worst.ageDays === null || worst.ageDays === undefined
          ? NOT_MEASURED_MARK
          : `${num(worst.ageDays)}d`,
        components: covered ? num(d.content.length) : NOT_MEASURED_MARK,
        note: notes.join(' '),
        _color: covered ? signatureColor(worst.status) : UNMEASURED,
        _noteColor: covered && worst.status === 'stale' ? ORANGE : UNMEASURED,
      };
    }),
  };
}

function buildCoverageTable(devices) {
  const cell = (d, fact) => COVERAGE_LABEL[d.coverage[fact]];
  return {
    columns: [
      { key: 'device', label: 'Firewall', width: 62, font: 'Helvetica-Bold' },
      { key: 'access', label: 'Vendor / access', width: 56, color: MUTED },
      { key: 'licenses', label: 'Licences', width: 50, color: (r) => r._c.licenses, font: 'Helvetica-Bold' },
      { key: 'ha', label: 'HA state', width: 50, color: (r) => r._c.ha, font: 'Helvetica-Bold' },
      { key: 'disk', label: 'Disk', width: 50, color: (r) => r._c.disk, font: 'Helvetica-Bold' },
      { key: 'content', label: 'Content versions', width: 50, color: (r) => r._c.content, font: 'Helvetica-Bold' },
      { key: 'why', label: 'What is missing, and why', width: 190, color: (r) => r._whyColor },
    ],
    rows: devices.map((d) => {
      const why = FACTS
        .filter((f) => d.coverage[f] !== 'collected')
        .map((f) => `${FACT_LABEL[f]}: ${coverageReason(f, d.coverage[f], d.vendor, d.mgmtMethod)}`)
        .join(' ');
      return {
        device: d.name,
        access: `${d.vendor}${d.mgmtMethod ? ` / ${d.mgmtMethod}` : ''}`,
        licenses: cell(d, 'licenses'),
        ha: cell(d, 'ha'),
        disk: cell(d, 'disk'),
        content: cell(d, 'content'),
        why: why || 'All four facts collected from this firewall.',
        _c: {
          licenses: coverageColor(d.coverage.licenses),
          ha: coverageColor(d.coverage.ha),
          disk: coverageColor(d.coverage.disk),
          content: coverageColor(d.coverage.content),
        },
        _whyColor: why ? UNMEASURED : MUTED,
      };
    }),
  };
}

// ── body ──────────────────────────────────────────────────────────────────

/**
 * ⛔ THE LEGEND IS NOT DECORATION, AND IT COMES FIRST.
 *
 * This document leaves the tool. It is read by whoever signs the renewal, who
 * may have no SecVault account and no reason to know that a blank expiry cell
 * has two completely different meanings. Without this page, "Perpetual" and
 * "we could not read the date" are one thing, and the second one is how a
 * contract lapses.
 */
function renderWhatThisProves(doc, layout, data) {
  sectionTitle(doc, layout, 'What this report can and cannot prove');
  paragraph(
    doc, layout,
    'Every line below carries the fact the judgement rests on, so you can disagree with a specific '
    + 'reading rather than with the tool. Four things can be true of an entitlement\'s expiry date, '
    + 'and they are NOT interchangeable.',
    INK
  );
  doc.y += 4;

  const bullets = [
    ['A date', INK,
      'The firewall reported an expiry date SecVault could read. Plan against it. This is the only '
      + 'state from which a renewal deadline can be derived.'],
    [PERPETUAL_TEXT, BLUE,
      'The firewall reported, in as many words, that this entitlement never expires - Palo Alto '
      + 'returns "Never". There is nothing to renew and nothing to plan. This is a POSITIVE answer '
      + 'from the device, not an absence of one.'],
    [UNKNOWN_EXPIRY_TEXT, UNMEASURED,
      'The firewall gave a value SecVault could not parse into a date, so this entitlement\'s expiry '
      + 'is UNKNOWN. It is NOT perpetual and it is NOT fine. It may have lapsed already, it may lapse '
      + 'next week, and this document cannot tell you which. The vendor\'s own string is printed '
      + 'beside it so somebody can go and read it. These are counted on the cover, deliberately '
      + 'beside the expiring count and never folded into it.'],
    [NOT_LICENSED_TEXT, MUTED,
      'The firewall reported that it holds no entitlement for this component at all - FortiOS says '
      + '"n/a". That is a definite answer, not missing information, so it needs no investigation and '
      + 'appears in no renewal table. It is counted separately so the numbers still add up.'],
  ];
  bullets.forEach(([label, color, text]) => labelledNote(doc, layout, label, color, text));

  doc.y += 6;
  labelledNote(
    doc, layout,
    'Version compatibility across an HA pair', UNMEASURED,
    'Reported as Match, MISMATCH, or NOT REPORTED - three states, not two. A pair that reported no '
    + 'compatibility block has not told us its members are consistent, and this report will not fill '
    + 'that silence in with a match. The same applies to configuration sync: a blank is never drawn '
    + 'as synchronized.'
  );
  labelledNote(
    doc, layout,
    'A suspended HA member is not automatically a fault', MUTED,
    'A member suspended by an administrator ("User requested") is a deliberate action on an '
    + 'otherwise healthy pair, and SecVault deliberately does not record it as a reason the pair went '
    + 'non-functional. A pair in that state reads as healthy here, which is correct - the fault list '
    + 'is for link failures, sync failures and version mismatches.'
  );
  labelledNote(
    doc, layout,
    'Disk figures come from the firewall, not from SNMP', INK,
    'Every filesystem line is the device\'s own disk-space output. The sizes are printed exactly as '
    + 'the firewall wrote them; only the percentage is treated as a number. So these carry none of '
    + 'the confidence caveat attached to metrics polled over a generic SNMP MIB.'
  );
  labelledNote(
    doc, layout,
    `${NOT_MEASURED_MARK} anywhere else on the page`, UNMEASURED,
    'A dash means the figure is UNKNOWN for that firewall. It never means zero, never means none, '
    + 'and never means fine. Every firewall carrying one is named in the coverage section at the end '
    + 'of this document, with the reason.'
  );
}

function renderSectionErrors(doc, layout, sectionErrors) {
  if (!sectionErrors || sectionErrors.length === 0) return;
  doc.y += 8;
  sectionTitle(doc, layout, 'Parts of this report could not be gathered');
  // ⛔ Named, not hidden. A section that silently vanishes reads as a section
  // with nothing in it, and on this document that reads as "nothing expiring".
  paragraph(
    doc, layout,
    'The following did not return data for this run. Nothing below is reported as a clean result on '
    + 'their behalf, and no firewall is described as healthy on the strength of a read that failed.',
    STATUS_RED
  );
  sectionErrors.forEach((e) => labelledNote(doc, layout, e.section, UNMEASURED, e.message));
}

function renderRenewals(doc, layout, data) {
  const { totals, renewals, caps } = data;
  doc.y += 10;
  sectionTitle(doc, layout, `Renewal timeline (${num(totals.renewalEvents)} contract ${plural(totals.renewalEvents, 'date', 'dates')})`);
  paragraph(
    doc, layout,
    'Soonest first. Entitlements sharing an expiry date on the same firewall are grouped, because '
    + 'they are one purchasing decision rather than several. Undated rows sort LAST, never first - '
    + 'an entitlement with no readable date is not the most urgent thing on this list, and putting '
    + 'it at the top would push a contract that lapses next month below the fold.',
    MUTED
  );

  if (totals.licensesUnknownExpiry > 0) {
    paragraph(
      doc, layout,
      `${num(totals.licensesUnknownExpiry)} ${plural(totals.licensesUnknownExpiry, 'entitlement', 'entitlements')} `
      + `across ${num(totals.renewalEventsUnknown)} ${plural(totals.renewalEventsUnknown, 'row', 'rows')} below carry an expiry `
      + 'SecVault could not read. They are listed with the firewall\'s own words so they can be '
      + 'chased, and they are NOT counted as expiring and NOT counted as fine.',
      UNMEASURED
    );
  }
  if (totals.licensesNotLicensed > 0) {
    paragraph(
      doc, layout,
      `A further ${num(totals.licensesNotLicensed)} ${plural(totals.licensesNotLicensed, 'component was', 'components were')} reported by their `
      + 'firewalls as carrying no entitlement at all. There is nothing to renew for those, so they '
      + 'are excluded from this table and counted here instead - the table is shorter for a stated '
      + 'reason rather than for an invisible one.',
      MUTED
    );
  }

  const shown = renewals.slice(0, caps.maxRenewalRows);
  const note = truncationNote(shown.length, renewals.length, 'contract dates');
  if (note) paragraph(doc, layout, note, MUTED);

  drawTable(doc, buildRenewalTable(shown, data.scope === 'fleet'), layout, {
    continueOnPage: true,
    // ⛔ Not "nothing is expiring". An empty renewal table on a fleet with no
    // licence coverage is a coverage statement, not a renewal statement.
    emptyText: totals.devicesNoLicenseData > 0
      ? 'No licence data was collected from the firewalls in scope. This is NOT a statement that nothing expires.'
      : 'No entitlements with an expiry date were reported by the firewalls in scope.',
  });
}

function renderHa(doc, layout, data) {
  const { totals, devices } = data;
  doc.y += 10;
  sectionTitle(doc, layout, `High availability and redundancy (${num(totals.devices)} ${plural(totals.devices, 'firewall', 'firewalls')})`);
  paragraph(
    doc, layout,
    totals.haDegraded > 0
      ? `${num(totals.haDegraded)} ${plural(totals.haDegraded, 'pair is', 'pairs are')} not currently providing the redundancy `
        + 'it is configured for. Every reason below is the firewall\'s own report, quoted.'
      : 'No pair reported a condition that stops it providing redundancy. Standalone firewalls are '
        + 'listed as standalone, which is a collected fact rather than a gap.',
    totals.haDegraded > 0 ? STATUS_RED : INK
  );
  if (totals.haCompatUnreported > 0) {
    paragraph(
      doc, layout,
      `${num(totals.haCompatUnreported)} HA ${plural(totals.haCompatUnreported, 'pair has', 'pairs have')} not reported a version `
      + 'compatibility block at all. That is shown as NOT REPORTED, not as a match - the pair has '
      + 'not told us its members run consistent software, and this report will not say that it did.',
      UNMEASURED
    );
  }
  drawTable(doc, buildHaTable(devices), layout, {
    continueOnPage: true,
    emptyText: 'No firewalls in scope.',
  });
}

function renderDisk(doc, layout, data) {
  const { totals, devices } = data;
  doc.y += 10;
  sectionTitle(doc, layout, 'Disk capacity');
  paragraph(
    doc, layout,
    `Worst filesystem per firewall, from the device's own disk-space report. ${num(DISK_WARNING_PERCENT)}% is a `
    + `warning and ${num(DISK_CRITICAL_PERCENT)}% is critical. Sizes are printed exactly as the firewall wrote `
    + 'them; only the percentage is read as a number.'
    + (totals.devicesNoDiskData > 0
      ? ` ${num(totals.devicesNoDiskData)} ${plural(totals.devicesNoDiskData, 'firewall reports', 'firewalls report')} no disk usage at `
        + 'all and is shown as such, not as empty.'
      : ''),
    MUTED
  );
  drawTable(doc, buildDiskTable(devices), layout, {
    continueOnPage: true,
    emptyText: 'No firewalls in scope.',
  });
}

function renderSignatures(doc, layout, data) {
  const { totals, devices, staleDays } = data;
  doc.y += 10;
  sectionTitle(doc, layout, 'Content and signature freshness');
  paragraph(
    doc, layout,
    `Threat, antivirus and application content older than ${num(staleDays)} days is reported as stale. These `
    + 'versions are extracted from the system information SecVault already collects - no extra '
    + 'command is issued to any firewall for this.',
    MUTED
  );
  if (totals.contentNoReleaseDate > 0) {
    paragraph(
      doc, layout,
      `${num(totals.contentNoReleaseDate)} ${plural(totals.contentNoReleaseDate, 'component', 'components')} across the fleet carry a version `
      + 'string but no release date. Their age is UNKNOWN and is not inferred from a date-shaped '
      + 'version number - they are counted here and excluded from the freshness verdict rather than '
      + 'quietly treated as current.',
      UNMEASURED
    );
  }
  drawTable(doc, buildSignatureTable(devices, staleDays), layout, {
    continueOnPage: true,
    emptyText: 'No firewalls in scope.',
  });
}

/**
 * ⛔ THE SECTION THAT MAKES THE REST OF THE DOCUMENT HONEST.
 *
 * A renewal list that silently omits every firewall SecVault cannot ask is not
 * a short list, it is a wrong one — and it is wrong in the direction that costs
 * money, because the reader budgets for what they can see. Every active
 * firewall appears here whether or not it contributed a single row above.
 */
function renderCoverage(doc, layout, data) {
  const { devices, coverageGaps, totals } = data;
  doc.y += 10;
  sectionTitle(doc, layout, 'What SecVault cannot see, on which firewalls, and why');
  paragraph(
    doc, layout,
    'SecVault reads these four facts over each vendor\'s own management API or CLI, and COVERAGE IS '
    + 'PARTIAL BY DESIGN - not every vendor and access method exposes all four. A firewall that '
    + 'cannot report a licence appears below as not measured; it is never reported as having no '
    + 'licences and it is never left out. Leaving it out is the single most damaging thing this '
    + 'document could do, because a renewal list that is silently incomplete still looks complete.',
    INK
  );
  doc.y += 4;

  labelledNote(
    doc, layout,
    'Cannot be asked', UNMEASURED,
    'This vendor and access method has no way to report that fact to SecVault. Nothing can be '
    + 'changed on the firewall to fix it - it is a limit of the product, and it is stated rather '
    + 'than hidden.'
  );
  labelledNote(
    doc, layout,
    'NOT COLLECTED', ORANGE,
    'This firewall CAN report that fact and SecVault has nothing. That is a collection problem worth '
    + 'investigating, and it is deliberately not drawn the same way as the line above - the two look '
    + 'identical in an empty table and have completely different owners.'
  );
  labelledNote(
    doc, layout,
    'Unknown', UNMEASURED,
    'Either the read failed for this run, or SecVault could not establish whether this firewall can '
    + 'supply that fact. Content and signature versions arrive as part of the version response '
    + 'rather than as a capability of their own, so their absence is always reported this way rather '
    + 'than as an unsupported feature.'
  );

  doc.y += 6;
  const gapLines = coverageGaps
    .filter((g) => g.notSupported + g.notCollected + g.unknown > 0)
    .map((g) => {
      const parts = [];
      if (g.notSupported > 0) parts.push(`${num(g.notSupported)} cannot be asked`);
      if (g.notCollected > 0) parts.push(`${num(g.notCollected)} can be asked but returned nothing`);
      if (g.unknown > 0) parts.push(`${num(g.unknown)} unknown`);
      return `${g.label}: collected from ${num(g.collected)} of ${num(totals.devices)} `
        + `${plural(totals.devices, 'firewall', 'firewalls')} (${parts.join(', ')}).`;
    });
  if (gapLines.length === 0) {
    paragraph(
      doc, layout,
      'Every firewall in scope reported all four facts. Nothing in this document rests on an '
      + 'unanswered question.',
      GREEN
    );
  } else {
    gapLines.forEach((line) => paragraph(doc, layout, line, UNMEASURED));
  }

  drawTable(doc, buildCoverageTable(devices), layout, {
    continueOnPage: true,
    emptyText: 'No firewalls in scope.',
  });
}

function renderMethodology(doc, layout, data) {
  doc.y += 10;
  sectionTitle(doc, layout, 'How this report was produced');
  paragraph(
    doc, layout,
    'SecVault collects licences, HA state, disk usage and content versions from each firewall over '
    + 'that vendor\'s own management API or CLI, stores the raw facts, and derives every status here '
    + 'at the moment this document was generated. Nothing is typed in by hand and no expiry is '
    + 'inferred from a vendor datasheet.',
    INK
  );
  const bullets = [
    ['Status is derived, not stored', INK,
      'Expiring, stale, degraded and critical are functions of the collected facts plus the current '
      + 'time. They are computed when the report runs, so a date that passed yesterday is reflected '
      + 'today without anything needing to be re-collected.'],
    [`The ${num(data.warnDays)}-day warning window`, INK,
      'A support contract needs procurement lead time, so an entitlement is flagged well before it '
      + 'lapses rather than at the last moment. Anything already past its date is reported as '
      + 'EXPIRED regardless of the window, and where the firewall itself says an entitlement has '
      + 'expired, the firewall is believed over our own arithmetic.'],
    ['What this report does not claim', UNMEASURED,
      'It does not claim a firewall is supported, only that it reported a support entitlement with a '
      + 'date in the future. It does not claim an HA pair would successfully fail over, only that the '
      + 'pair reported no condition preventing it. And it makes no claim at all about any fact it '
      + 'could not read - those are named, counted, and listed above.'],
  ];
  bullets.forEach(([label, color, text]) => labelledNote(doc, layout, label, color, text));

  doc.y += 6;
  paragraph(
    doc, layout,
    'Figures reflect the most recent successful collection from each firewall. A firewall whose '
    + 'collection is failing keeps its previous values rather than losing them, so an old reading is '
    + 'preferred to a fabricated empty one - check the coverage section before treating any figure '
    + 'here as current.',
    MUTED
  );
}

function renderBody(doc, data, layout) {
  doc.addPage();

  // Answer first, in a sentence, before any table.
  sectionTitle(doc, layout, 'Summary');
  paragraph(doc, layout, data.headline, INK, 10);
  doc.y += 6;

  renderWhatThisProves(doc, layout, data);
  renderSectionErrors(doc, layout, data.sectionErrors);
  renderRenewals(doc, layout, data);
  renderHa(doc, layout, data);
  renderDisk(doc, layout, data);
  renderSignatures(doc, layout, data);
  renderCoverage(doc, layout, data);
  renderMethodology(doc, layout, data);
}

// ── PDF ───────────────────────────────────────────────────────────────────

const TITLE = 'Fleet Lifecycle & Support';

/** Pure-ish: report data -> PDF Buffer. No DB, no network, no browser. */
function renderFleetLifecyclePdf(data) {
  const doc = installPdfSafeText(
    new PDFDocument({ size: 'A4', layout: 'portrait', margin: 36, bufferPages: true })
  );
  const layout = layoutOf(doc);
  const generatedAt = fmtStamp(data.generatedAt || new Date());
  const { totals, scope, device } = data;
  const subject = scope === 'device' && device
    ? `${device.name} (${device.vendor}${device.mgmtMethod ? ` / ${device.mgmtMethod}` : ''})`
    : 'Fleet-wide';

  drawCover(
    doc,
    {
      title: TITLE,
      subtitle: scope === 'device'
        ? `${subject} - support expiry, redundancy, disk and content freshness`
        : 'What is about to expire, go stale, or fall over across the firewall estate',
      company: PRODUCT_NAME,
      generatedAt,
      footerStamp: true,
      meta: [
        ['Scope', scope === 'device' ? subject : `${num(totals.devices)} firewalls`],
        scope === 'device' && device && device.site ? ['Site', device.site] : null,
        ['Warning window', `${num(totals.warnDays)} days`],
        ['Entitlements examined', totals.licenses > 0
          ? num(totals.licenses)
          : `${NOT_MEASURED_MARK} (no licence data collected)`],
        ['Already expired', num(totals.licensesExpired)],
        // ⛔ ON THE COVER, in its own row, beside the expiring count and never
        // folded into it. This is the number that decides whether the rest of
        // the document can be trusted as a complete renewal plan.
        ['Expiry date UNREADABLE', num(totals.licensesUnknownExpiry)],
        ['Firewalls with no licence data', num(totals.devicesNoLicenseData)],
        ['HA pairs degraded', num(totals.haDegraded)],
        ['HA pairs not reporting version compatibility', num(totals.haCompatUnreported)],
        ['Firewalls above the disk warning mark', num(totals.diskCritical + totals.diskWarning)],
        ['Firewalls with content older than the staleness window', num(totals.signaturesStale)],
      ].filter(Boolean),
      summary: [
        { label: 'Firewalls', value: num(totals.devices), color: NAVY },
        // ⛔ THE LABEL NAMES BOTH STATES BECAUSE THE VALUE CONTAINS BOTH. This
        // chip is the renewal WORKLOAD — already lapsed plus due inside the
        // window — and it was labelled "Expiring within 60d" while carrying the
        // sum. Live that read 49 beside a meta row saying "Already expired 21"
        // and a headline sentence saying "21 have already expired; 28 expire
        // within 60 days": a reader adding the cover's own two figures got 70
        // renewals out of 49. A mislabelled figure is worse than a missing one,
        // because it is plausible and nobody re-derives a cover.
        {
          label: `Expired or expiring in ${num(totals.warnDays)}d`,
          value: num(totals.licensesExpiring + totals.licensesExpired),
          color: (totals.licensesExpiring + totals.licensesExpired) > 0 ? STATUS_RED : GREEN,
        },
        // ⛔ HUELESS ON PURPOSE. An unreadable expiry is neither good news nor
        // bad news; it is the SIZE OF THE QUESTION this report could not
        // answer, and colouring it either way turns a coverage figure into an
        // assessment.
        { label: 'Unknown expiry', value: num(totals.licensesUnknownExpiry), color: UNMEASURED },
        {
          label: 'HA degraded',
          value: num(totals.haDegraded),
          color: totals.haDegraded > 0 ? STATUS_RED : GREEN,
        },
      ],
    },
    layout
  );

  renderBody(doc, data, layout);
  stampHeadersFooters(doc, {
    title: `${PRODUCT_NAME} ${TITLE}`,
    company: scope === 'device' && device ? device.name : `${num(totals.devices)} firewalls`,
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
 * @param {import('pg').Pool} pool
 * @param {object} [options] `{deviceId}` for one firewall; omit for the fleet.
 * @returns {Promise<Buffer|null>} null only when a named device does not exist.
 */
async function generateFleetLifecyclePdf(pool, options = {}) {
  const data = await buildFleetLifecycleData(pool, options);
  if (!data) return null;
  return renderFleetLifecyclePdf(data);
}

module.exports = {
  TITLE,
  NOT_MEASURED_MARK,
  UNKNOWN_EXPIRY_TEXT,
  PERPETUAL_TEXT,
  NOT_LICENSED_TEXT,
  FACTS,
  FACT_LABEL,
  COVERAGE_LABEL,
  formatDate,
  dayDelta,
  daysText,
  truncationNote,
  expiryCell,
  licenseColor,
  licenseLabel,
  haColor,
  haLabel,
  compatCell,
  diskColor,
  signatureColor,
  factCoverage,
  coverageColor,
  coverageReason,
  probeFactSupport,
  compareRenewals,
  groupRenewals,
  headlineSentence,
  buildFleetLifecycleData,
  renderFleetLifecyclePdf,
  generateFleetLifecyclePdf,
};
