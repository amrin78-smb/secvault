// lib/reports/vpnAccessReview.js
//
// R9 — "VPN Access Review". The quarterly access-review document.
//
// It answers one question: WHO CONNECTED REMOTELY, FROM WHERE, FOR HOW LONG —
// and what did the authentication detections flag?
//
// ⛔ THIS DOCUMENT NAMES PEOPLE. Usernames, source addresses, client devices,
// login times. That is personal data, and in this product personal data is
// gated on the `view_identity` capability, never on `operate` — the same rule
// the VPN identity tabs and the log search route already follow. Nothing in
// this file resolves a session or decides who may read the result; the
// catalogue entry declares the capability and the download route enforces it.
// There is deliberately no other way to reach this builder.
//
// ── ⛔ THE FIVE THINGS THIS DOCUMENT IS NOT ALLOWED TO CLAIM ──────────────
//
// 1. AN EXACT DURATION. The START of a session is exact — the device reported
//    its own login time. The END is only ever known to within ONE POLL
//    INTERVAL, because all SecVault observes is "present in this poll, absent
//    in the next". So every duration here is a LOWER BOUND with a stated error
//    bar: the true value lies in [duration_seconds, duration_seconds +
//    duration_precision_seconds]. A session SHORTER than the poll interval may
//    never have been observed at all, which is why no page in this report
//    reports "total connected time" without saying that this is a SAMPLE of
//    connections and not a complete register.
//
// 2. AN UNKNOWN END. `ended_at IS NULL` means STILL CONNECTED AS OF
//    `last_seen_at`. It never means "ended at a time we do not know". Printing
//    it as a blank, a dash or a guessed timestamp would turn the most certain
//    thing in the row into the least.
//
// 3. A ZERO-LENGTH SESSION FROM A NEGATIVE ONE. A negative observed duration
//    is PROOF that the firewall's clock or timezone disagrees with the
//    server's. It is evidence of a configuration problem, not a measurement of
//    a session, so it is reported as `clock_mismatch` and never as 0.
//
// 4. FLEET-WIDE VPN HISTORY. Per-session detail exists for ONE vendor today:
//    only Palo Alto's getVpnSessionSummary() returns a per-session array.
//    Fortinet returns a bare COUNT with no per-user detail, and the remaining
//    four vendors have no VPN capability wired at all. So this report names
//    the gateways it covers AND the ones it cannot, on its own coverage page.
//    A firewall absent from the per-user tables is a gap in what SecVault can
//    see, never a firewall nobody connects through.
//
// 5. AN ALL-CLEAR OVER INCOMPLETE COVERAGE. A detection whose baseline is too
//    thin renders HUELESS and says "not enough history" — never green, never
//    "no anomalies". "We have not got the history to answer" and "we looked
//    and found nothing" are opposite statements, and only one of them is
//    reassuring. An observation that could not be judged is COUNTED
//    (`unverifiableTotal`) rather than dropped: dropping it makes a coverage
//    gap look like a clean result.
//
// ── Reuse, not re-derivation ─────────────────────────────────────────────
// Session history and its duration arithmetic come from
// lib/engines/vpnSessions.js UNCHANGED (getVpnSessionHistory already decorates
// every row with the lower-bound flag, the error bar and the unavailable
// reason). The detections come from lib/engines/vpnDetections.js UNCHANGED,
// including their baseline verdicts and their unverifiable counts. The
// per-device "is VPN even configured here" verdict comes from
// lib/engines/vpnSummary.js UNCHANGED. Nothing about a detection, a duration
// or a VPN config shape is decided in this file — two implementations of
// "was this session long" or "is this a sprayer" would eventually disagree,
// and the wrong one would be the one printed and filed.
//
// Drawing is entirely lib/reports/chassis.js. No cover, table, heading or
// footer is hand-rolled here.
//
// CommonJS — same reason as every engine: the App Router and plain-node
// callers both load it.

'use strict';

const PDFDocument = require('pdfkit');

const {
  NAVY, MUTED, GREEN, INK,
  STATUS_RED, ORANGE, YELLOW, BLUE, UNMEASURED,
  fmtStamp, installPdfSafeText,
  layoutOf,
  drawCover, sectionTitle, paragraph, labelledNote, drawTable, stampHeadersFooters,
} = require('./chassis');

const { PRODUCT_NAME } = require('../branding');

// ⛔ Imported, never re-implemented. getVpnSessionHistory() owns the duration
// arithmetic AND the three states it can end in; MAX_HISTORY_LIMIT is its own
// clamp, and asking for more than it will return would silently truncate the
// document without anything saying so.
const {
  getVpnSessionHistory,
  MAX_HISTORY_LIMIT,
} = require('../engines/vpnSessions');

// ⛔ Imported, never re-implemented. The detection rules, their thresholds and
// — most importantly — their baseline verdicts belong to this engine.
const {
  getVpnDetections,
  STATUS,
  MAX_WINDOW_HOURS,
} = require('../engines/vpnDetections');

const { summarizeVpnConfig } = require('../engines/vpnSummary');

// ── marks ─────────────────────────────────────────────────────────────────

// ⛔ The printed form of an UNKNOWN value. chassis.pdfSafe() folds it to an
// ASCII hyphen, which is the point: what must never appear in one of these
// cells is a `0`. A dash reads as "no value"; a zero reads as a measurement.
const NOT_MEASURED_MARK = '—';

// ⛔ EVERY duration printed anywhere in this document carries this prefix.
// Exported so a test can assert it rather than hope for it: the failure mode
// is a perfectly plausible "4h 12m" that reads as an exact figure.
const LOWER_BOUND_PREFIX = 'at least ';

// ── window ────────────────────────────────────────────────────────────────

// A quarter. This is an ACCESS REVIEW, and the review period an auditor asks
// for is the quarter, not the last day. Stated on the cover so nobody has to
// infer it.
const DEFAULT_WINDOW_DAYS = 90;
// vpn_sessions retention is a year (VPN_SESSION_RETENTION_DAYS), so a longer
// window than that would promise history the database does not keep.
const MAX_WINDOW_DAYS = 365;

const DEFAULT_MAX_USER_ROWS = 200;
const DEFAULT_MAX_SESSION_ROWS = 120;
const DEFAULT_MAX_FINDING_ROWS = 80;
// A sample of the unverifiable list, never its length — the COUNT is the claim.
const MAX_UNVERIFIABLE_SAMPLE = 10;

const MS_PER_DAY = 86400000;

// ── small formatters ──────────────────────────────────────────────────────

function num(n) {
  return Number(n || 0).toLocaleString('en-GB');
}

function clampWindowDays(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return DEFAULT_WINDOW_DAYS;
  return Math.min(Math.max(Math.trunc(n), 1), MAX_WINDOW_DAYS);
}

/**
 * Clamp a caller-supplied table cap. ⛔ Never 0: a cap of 0 would silently
 * empty a section, which on the page is indistinguishable from "nothing was
 * found" — the exact confusion this report exists to remove.
 */
function clampCap(v, def) {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.max(Math.trunc(n), 1);
}

/** Coarse, human duration. Never used without its lower-bound qualifier. */
function fmtHms(seconds) {
  // ⛔ `Number(null)` is 0, not NaN. Without this guard an ABSENT value would
  // print as "0s" — a measurement of zero where the truth is "no value", which
  // is the one substitution this whole document exists to refuse.
  if (seconds === null || seconds === undefined || seconds === '') return NOT_MEASURED_MARK;
  const n = Number(seconds);
  if (!Number.isFinite(n)) return NOT_MEASURED_MARK;
  const s = Math.max(0, Math.round(n));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return d + 'd ' + h + 'h';
  if (h > 0) return h + 'h ' + m + 'm';
  if (m > 0) return m + 'm';
  return s + 's';
}

/**
 * ⛔ THE SINGLE PLACE A DURATION BECOMES TEXT.
 *
 * Three outcomes, three different sentences, and none of them is a bare
 * number:
 *   lower_bound     "at least 4h 12m (+ up to 30m unobserved)"
 *   clock_mismatch  the device's clock disagrees with the server's — this is
 *                   a fault report, NOT a zero-length session
 *   not_computable  nothing to measure from
 *
 * The `+ up to` phrasing is deliberate and is not a ±. The observed value is
 * a FLOOR: the true duration is in [d, d + precision], never below d.
 *
 * Takes a row exactly as getVpnSessionHistory() decorates it.
 */
function durationDisplay(row) {
  const r = row || {};
  const reason = r.duration_unavailable_reason || null;
  const secs = r.duration_seconds;

  if (secs === null || secs === undefined) {
    if (reason === 'clock_mismatch') {
      return {
        state: 'clock_mismatch',
        color: UNMEASURED,
        text: 'Not measured - this firewall\'s clock disagrees with the server\'s',
      };
    }
    return {
      state: 'not_computable',
      color: UNMEASURED,
      text: 'Not measured - no end reference for this session',
    };
  }

  const precision = r.duration_precision_seconds;
  // ⛔ An UNKNOWN error bar is stated as unknown. A row written before the poll
  // cadence was recorded has no error bar, and printing the floor alone there
  // would quietly promote it to an exact figure.
  const bar = precision === null || precision === undefined
    ? ' (how much longer is unknown)'
    : ' (+ up to ' + fmtHms(precision) + ' unobserved)';

  return {
    state: 'lower_bound',
    color: INK,
    text: LOWER_BOUND_PREFIX + fmtHms(secs) + bar,
  };
}

/**
 * ⛔ `ended_at IS NULL` IS A STATEMENT, NOT A GAP.
 *
 * It means the session was still up at `last_seen_at`. It does NOT mean the
 * end time is unknown, and it must never render as a dash — a dash in this
 * column would file the most certain rows in the table under "we do not know".
 */
function sessionEndDisplay(row) {
  const r = row || {};
  const open = r.ended_at === null || r.ended_at === undefined || r.is_open === true;
  if (open) {
    return {
      state: 'open',
      color: BLUE,
      text: 'Still connected as of ' + (r.last_seen_at ? fmtStamp(r.last_seen_at) : NOT_MEASURED_MARK),
    };
  }
  return { state: 'ended', color: MUTED, text: fmtStamp(r.ended_at) };
}

/**
 * How a detection's own state must READ.
 *
 * ⛔ ONLY `measured` MAY EVER BE GREEN, and only when it has nothing left
 * unjudged and the fleet has no reporting gap behind it. Everything else is
 * HUELESS. A baseline-gated detection that rendered as a pass would be this
 * codebase's failed-read-as-a-fact bug printed on paper, where it cannot be
 * corrected by a refresh — and it is the reassuring direction, which is the
 * dangerous one.
 *
 * @param {object} d a detection as vpnDetections.js returns it
 * @param {object} [ctx] `{hasReportingGap:boolean}` fleet-level coverage
 */
function detectionStateDisplay(d, ctx = {}) {
  const det = d || {};
  const findings = Array.isArray(det.findings) ? det.findings.length : 0;
  const unverifiable = Number(det.unverifiableTotal || 0);

  if (det.status === STATUS.NO_DATA) {
    return {
      state: 'no_data',
      color: UNMEASURED,
      label: 'No VPN authentication data',
      note: 'No VPN authentication evidence reached SecVault in this window, so this question was '
        + 'never put. This is not a finding of "nothing happened".',
    };
  }

  if (det.status !== STATUS.MEASURED) {
    const b = det.baseline || {};
    const need = b.required === undefined || b.required === null ? NOT_MEASURED_MARK : String(b.required);
    const have = b.have === undefined || b.have === null ? NOT_MEASURED_MARK : String(b.have);
    return {
      state: 'insufficient_baseline',
      color: UNMEASURED,
      label: 'Not enough history',
      note: 'This detection needs ' + need + ' days of VPN authentication history and SecVault holds '
        + have + '. It did NOT run, and that is not the same as finding nothing. '
        + num(unverifiable) + ' observation(s) are therefore unjudged rather than cleared.',
    };
  }

  if (findings > 0) {
    const worst = worstSeverity(det.findings);
    return {
      state: 'flagged',
      color: severityColor(worst),
      label: num(findings) + ' flagged',
      note: null,
    };
  }

  if (unverifiable > 0) {
    return {
      state: 'nothing_verifiable',
      color: UNMEASURED,
      label: 'Nothing verifiable',
      // ⛔ Not "clear". Everything this detection saw was unjudgeable, which is
      // an absence of evidence and not evidence of absence.
      note: 'The rule ran, but every one of its ' + num(unverifiable) + ' observation(s) was '
        + 'unjudgeable - typically because the only firewall that saw it does not log successful '
        + 'VPN authentications at all. Nothing here is cleared.',
    };
  }

  if (ctx.hasReportingGap) {
    return {
      state: 'clear_with_gap',
      color: UNMEASURED,
      label: 'Nothing found (coverage incomplete)',
      note: 'This rule ran and found nothing - but at least one firewall in scope reports no '
        + 'successful VPN authentications at all, so the fleet it ran over is not the whole fleet.',
    };
  }

  return { state: 'clear', color: GREEN, label: 'Nothing found', note: null };
}

const SEVERITY_ORDER = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);

function severityColor(sev) {
  switch (sev) {
    case 'critical': return STATUS_RED;
    case 'high': return ORANGE;
    case 'medium': return YELLOW;
    case 'low': return BLUE;
    default: return MUTED;
  }
}

function worstSeverity(findings) {
  let best = null;
  for (const f of Array.isArray(findings) ? findings : []) {
    const i = SEVERITY_ORDER.indexOf(f && f.severity);
    if (i < 0) continue;
    if (best === null || i < best) best = i;
  }
  return best === null ? 'info' : SEVERITY_ORDER[best];
}

/**
 * "Showing N of M".
 *
 * ⛔ NEVER A SILENT CAP. A truncated table that does not say it is truncated is
 * a WRONG answer, not a shorter one: the reader counts the rows and believes
 * the number. Returns null when nothing was dropped.
 */
function truncationNote(shown, total, noun) {
  if (shown >= total) return null;
  return 'Showing ' + num(shown) + ' of ' + num(total) + ' ' + noun + '. '
    + 'The remainder are not in this document - the full list is in the app.';
}

// ── per-user aggregation ──────────────────────────────────────────────────

/**
 * Fold session-history rows into one row per user.
 *
 * ⛔ THE THREE DURATION STATES ARE COUNTED SEPARATELY AND NEVER SUMMED
 * TOGETHER. `connectedSecondsFloor` is the sum of the MEASURED lower bounds
 * only; the sessions with no measurable duration are counted beside it, not
 * folded in as zeroes. Adding a clock-mismatched session in as 0 would make a
 * user's total look smaller with more evidence, which is the wrong direction
 * and invisible on the page.
 *
 * ⛔ `precisionSecondsTotal` is the accumulated ERROR BAR — the amount of time
 * that may have elapsed after the last sighting of each measured session. It
 * is what makes "at least X" honest: the true total lies in
 * [floor, floor + errorBar], with `precisionUnknownSessions` more on top of
 * that which cannot be bounded at all.
 *
 * Pure: takes rows exactly as getVpnSessionHistory() returns them.
 */
function summariseUsers(rows) {
  const byUser = new Map();

  for (const r of Array.isArray(rows) ? rows : []) {
    const username = r.username == null || r.username === '' ? '(unnamed)' : String(r.username);
    let u = byUser.get(username);
    if (!u) {
      u = {
        username,
        sessions: 0,
        openSessions: 0,
        devices: new Set(),
        sourceIps: new Set(),
        clients: new Set(),
        tunnelTypes: new Set(),
        firstLoginAt: null,
        lastSeenAt: null,
        sessionsMeasured: 0,
        sessionsClockMismatch: 0,
        sessionsNotComputable: 0,
        connectedSecondsFloor: 0,
        precisionSecondsTotal: 0,
        precisionUnknownSessions: 0,
      };
      byUser.set(username, u);
    }

    u.sessions += 1;
    const end = sessionEndDisplay(r);
    if (end.state === 'open') u.openSessions += 1;
    if (r.device_name) u.devices.add(r.device_name);
    if (r.source_ip) u.sourceIps.add(r.source_ip);
    if (r.client) u.clients.add(r.client);
    if (r.tunnel_type) u.tunnelTypes.add(r.tunnel_type);

    const login = toDate(r.login_time);
    if (login && (u.firstLoginAt === null || login < u.firstLoginAt)) u.firstLoginAt = login;
    const last = toDate(r.ended_at) || toDate(r.last_seen_at);
    if (last && (u.lastSeenAt === null || last > u.lastSeenAt)) u.lastSeenAt = last;

    const dur = durationDisplay(r);
    if (dur.state === 'lower_bound') {
      u.sessionsMeasured += 1;
      u.connectedSecondsFloor += Number(r.duration_seconds) || 0;
      if (r.duration_precision_seconds === null || r.duration_precision_seconds === undefined) {
        u.precisionUnknownSessions += 1;
      } else {
        u.precisionSecondsTotal += Number(r.duration_precision_seconds) || 0;
      }
    } else if (dur.state === 'clock_mismatch') {
      u.sessionsClockMismatch += 1;
    } else {
      u.sessionsNotComputable += 1;
    }
  }

  const out = [...byUser.values()].map((u) => ({
    username: u.username,
    sessions: u.sessions,
    openSessions: u.openSessions,
    devices: [...u.devices].sort(),
    sourceIpCount: u.sourceIps.size,
    sourceIps: [...u.sourceIps].sort(),
    clientCount: u.clients.size,
    tunnelTypes: [...u.tunnelTypes].sort(),
    firstLoginAt: u.firstLoginAt,
    lastSeenAt: u.lastSeenAt,
    sessionsMeasured: u.sessionsMeasured,
    sessionsClockMismatch: u.sessionsClockMismatch,
    sessionsNotComputable: u.sessionsNotComputable,
    connectedSecondsFloor: u.sessionsMeasured > 0 ? u.connectedSecondsFloor : null,
    precisionSecondsTotal: u.precisionSecondsTotal,
    precisionUnknownSessions: u.precisionUnknownSessions,
  }));

  // Total and stable — the table is CAPPED, so an unstable sort would change
  // which users survive truncation between two runs of the same report, and an
  // audit artefact that differs run to run for no stated reason is not evidence.
  out.sort((a, b) => (
    b.sessions - a.sessions
    || (b.connectedSecondsFloor || 0) - (a.connectedSecondsFloor || 0)
    || String(a.username).localeCompare(String(b.username))
  ));
  return out;
}

function toDate(v) {
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v;
  if (typeof v === 'string' || typeof v === 'number') {
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  return null;
}

/**
 * How a gateway is represented in this document.
 *
 * ⛔ THREE STATES, and the middle one is the honest one this product exists to
 * keep:
 *   named       per-session history exists — users on it appear by name
 *   count_only  SecVault polls this firewall's VPN and gets a NUMBER, never a
 *               list. Nobody on it can be named, and their sessions are absent
 *               from every table in this report.
 *   none        no VPN session telemetry of any kind reaches SecVault
 *
 * Pure.
 */
function gatewayRepresentation(g) {
  const d = g || {};
  if (Number(d.sessions || 0) > 0) return 'named';
  if (d.snapshotAt || Number(d.activeNow || 0) > 0) return 'count_only';
  return 'none';
}

/**
 * The answer-first sentence.
 *
 * ⛔ AN ALL-CLEAR IS FORBIDDEN WHILE COVERAGE IS INCOMPLETE. Zero detection
 * findings over a fleet where most gateways contribute no per-user history,
 * where two detections could not run, and where hundreds of observations went
 * unjudged, is not a clean access review. The only path to an unqualified
 * sentence is every gap being genuinely zero.
 *
 * Pure — takes totals, returns a string.
 */
function headlineSentence(totals) {
  const t = totals || {};
  const head = 'Over the last ' + num(t.windowDays) + ' days SecVault observed '
    + num(t.sessions) + ' VPN session' + (t.sessions === 1 ? '' : 's')
    + ' for ' + num(t.users) + ' distinct user' + (t.users === 1 ? '' : 's')
    + ' across ' + num(t.gatewaysNamed) + ' of ' + num(t.gatewaysTotal) + ' firewall'
    + (t.gatewaysTotal === 1 ? '' : 's') + ', and '
    + (t.detectionsFlagged === 0
      ? 'no authentication detection flagged anything it could verify'
      : num(t.detectionsFlagged) + ' authentication detection finding'
        + (t.detectionsFlagged === 1 ? '' : 's') + ' were raised')
    + '.';

  const gaps = [];
  const unrepresented = Number(t.gatewaysTotal || 0) - Number(t.gatewaysNamed || 0);
  if (unrepresented > 0) {
    gaps.push(
      num(unrepresented) + ' firewall' + (unrepresented === 1 ? '' : 's')
      + ' in scope contribute NO per-user VPN session history, so anyone connecting through '
      + (unrepresented === 1 ? 'it' : 'them') + ' is absent from every table below'
    );
  }
  if (Number(t.detectionsGated || 0) > 0) {
    gaps.push(
      num(t.detectionsGated) + ' of ' + num(t.detectionsTotal)
      + ' detections did not have enough history to run at all'
    );
  }
  if (Number(t.unverifiableTotal || 0) > 0) {
    gaps.push(
      num(t.unverifiableTotal) + ' observation' + (t.unverifiableTotal === 1 ? '' : 's')
      + ' could not be judged either way and '
      + (t.unverifiableTotal === 1 ? 'is' : 'are') + ' counted rather than cleared'
    );
  }
  if (Number(t.sessionsNoDuration || 0) > 0) {
    gaps.push(
      num(t.sessionsNoDuration) + ' session' + (t.sessionsNoDuration === 1 ? '' : 's')
      + ' carry no measurable duration'
    );
  }
  if (t.sessionsTruncated) {
    // ⛔ THE USER COUNT IS TRUNCATED TOO, AND SAYING SO IS THE POINT. `users` is
    // the number of distinct usernames in the sessions that could be READ;
    // `usersInWindow` is how many actually connected. Live those are 413 and
    // 424 — so the headline and the cover both stated 413 as "distinct users"
    // while eleven people who connected in the window are named nowhere in the
    // document. Disclosing the session cap alone does not disclose that: a
    // reader has no way to get from "2,000 of 2,155 sessions" to "and eleven
    // users are missing entirely".
    const namedGap = Number(t.usersInWindow || 0) > Number(t.users || 0)
      ? ', so ' + num(t.users) + ' of the ' + num(t.usersInWindow)
        + ' users who connected in the window are named here'
      : '';
    gaps.push(
      'only the ' + num(t.sessions) + ' most recent of ' + num(t.sessionsInWindow)
      + ' sessions in the window could be read into this document' + namedGap
    );
  }

  if (gaps.length === 0) {
    return head + ' Every firewall in scope contributed per-user session history, every detection '
      + 'ran against a sufficient baseline, and every session carried a measurable duration.';
  }
  return head + ' This is NOT a complete picture of remote access: ' + gaps.join('; ') + '.';
}

// ── data assembly ─────────────────────────────────────────────────────────

/**
 * Fetch everything the cover and the body need.
 *
 * ⛔ THE SESSION READS ARE NOT BEST-EFFORT. The devices and the session history
 * either arrive or the export fails: an access review with silently-missing
 * sessions is worse than an error the operator can see and retry, because an
 * empty user table reads as "nobody connected".
 *
 * ⛔ THE DETECTIONS STAGE *IS* BEST-EFFORT, and its failure is RECORDED rather
 * than swallowed. It reads the syslog VPN auth rollup, which is a separate
 * subsystem on a separate schedule; if it cannot be read the document must say
 * "we could not run the detections", never present an empty detections section
 * that reads as "nothing was detected".
 *
 * @param {import('pg').Pool} pool
 * @param {object} [options]
 * @param {string} [options.deviceId] narrow to one gateway; omit for the fleet
 * @param {number} [options.days]     review window, default 90
 * @param {Date}   [options.now]
 * @param {number} [options.maxUserRows]
 * @param {number} [options.maxSessionRows]
 * @param {number} [options.maxFindingRows]
 * @returns {Promise<object|null>} null only when a named device does not exist.
 */
/**
 * The cover's one-line statement of how deep the record actually is.
 * ⛔ Never renders as the review window when the two differ.
 */
function historyCoverageMeta(data) {
  if (data.historyCoversWindow === null) return 'Could not be determined';
  if (!data.historyStart) return 'No sessions retained';
  const covers = data.historyCoversWindow;
  return fmtStamp(data.historyStart)
    + (covers ? ' (covers the window)' : ' - SHORTER than the review window');
}

/** The prose form of the same fact. */
function historySentence(data) {
  if (data.historyCoversWindow === null) {
    return 'The earliest retained session could not be read, so the period these figures cover is unknown.';
  }
  if (!data.historyStart) {
    return 'No session records are retained, so nothing below is drawn from observed connections.';
  }
  if (data.historyCoversWindow) {
    return 'Session records cover ' + fmtStamp(data.windowStart) + ' to ' + fmtStamp(data.generatedAt)
      + ', the whole of the review window.';
  }
  return 'Session records begin at ' + fmtStamp(data.historyStart) + ', which is LATER than the start '
    + 'of the review window - so these figures cover a shorter period than the cover requests.';
}

async function buildVpnAccessReviewData(pool, options = {}) {
  const opts = options && typeof options === 'object' ? options : {};
  const now = opts.now instanceof Date && !Number.isNaN(opts.now.getTime()) ? opts.now : new Date();
  const windowDays = clampWindowDays(opts.days);
  const since = new Date(now.getTime() - windowDays * MS_PER_DAY);
  const deviceId = opts.deviceId || null;
  const caps = {
    maxUserRows: clampCap(opts.maxUserRows, DEFAULT_MAX_USER_ROWS),
    maxSessionRows: clampCap(opts.maxSessionRows, DEFAULT_MAX_SESSION_ROWS),
    maxFindingRows: clampCap(opts.maxFindingRows, DEFAULT_MAX_FINDING_ROWS),
  };

  // ⛔ A gathering failure is a first-class row in the document, not a log line.
  // A section that quietly disappears is read as a section with nothing in it.
  const sectionErrors = [];

  // ⛔ A device-scoped review deliberately does NOT filter on `active`. An
  // operator reviewing access through a gateway they have just decommissioned
  // still needs its record — that is exactly when an access review is asked for.
  const { rows: deviceRows } = deviceId
    ? await pool.query(
      `SELECT id, name, vendor, mgmt_method, mgmt_ip, site, active
         FROM devices
        WHERE id = $1::uuid`,
      [deviceId]
    )
    : await pool.query(
      `SELECT id, name, vendor, mgmt_method, mgmt_ip, site, active
         FROM devices
        ORDER BY name`
    );

  if (deviceId && deviceRows.length === 0) return null;
  const ids = deviceRows.map((d) => d.id);
  const sinceIso = since.toISOString();

  // ⛔ Session history comes from the ENGINE, with its duration decoration
  // intact. The limit is the engine's own maximum; the count query below exists
  // precisely so a truncation can be DETECTED and stated rather than silently
  // shortening the review.
  const sessionRows = await getVpnSessionHistory(pool, {
    deviceId: deviceId || undefined,
    since,
    limit: MAX_HISTORY_LIMIT,
  });

  // ⛔ `COALESCE(ended_at, last_seen_at) >= $1` is the SAME overlap predicate
  // getVpnSessionHistory() uses for `since`. A different one here would make
  // the truncation check compare two different populations and report a
  // truncation that is not there, or worse, miss one that is.
  const totalsSql = deviceId
    ? `SELECT count(*)::int AS sessions_in_window,
              count(DISTINCT username)::int AS users_in_window
         FROM vpn_sessions
        WHERE COALESCE(ended_at, last_seen_at) >= $1::timestamptz
          AND device_id = $2::uuid`
    : `SELECT count(*)::int AS sessions_in_window,
              count(DISTINCT username)::int AS users_in_window
         FROM vpn_sessions
        WHERE COALESCE(ended_at, last_seen_at) >= $1::timestamptz`;
  const { rows: totalRows } = await pool.query(
    totalsSql,
    deviceId ? [sinceIso, deviceId] : [sinceIso]
  );
  const sessionsInWindow = totalRows[0] ? Number(totalRows[0].sessions_in_window) : 0;

  // ⛔ HOW FAR BACK THE RECORD ACTUALLY GOES — asked separately from the window,
  // because the two are not the same thing and the difference is the report's
  // most dangerous silence.
  //
  // `vpn_sessions` began on 2026-09-10 (v2.99.0) and ages on
  // VPN_SESSION_RETENTION_DAYS. So a review can be ASKED for 365 days while the
  // table holds five. Without this, the cover said "Review window 365 days,
  // 15/09/2025 to 15/09/2026" above a count of 411 users — and an auditor would
  // read 411 remote users in a year from five days of evidence. Every other
  // coverage gap in this document is already stated; this one was not, and it
  // is the one that scales the headline figure.
  //
  // ⛔ NULL means no retained history at all, NOT "covers the whole window".
  // The absence of a minimum is the absence of records, which is the strongest
  // possible reason to say something rather than nothing.
  let historyStart = null;
  let historyError = null;
  try {
    const depthSql = deviceId
      ? `SELECT min(COALESCE(ended_at, last_seen_at)) AS earliest FROM vpn_sessions WHERE device_id = $1::uuid`
      : 'SELECT min(COALESCE(ended_at, last_seen_at)) AS earliest FROM vpn_sessions';
    const { rows: depthRows } = await pool.query(depthSql, deviceId ? [deviceId] : []);
    const raw = depthRows[0] ? depthRows[0].earliest : null;
    historyStart = raw ? new Date(raw) : null;
    if (historyStart && Number.isNaN(historyStart.getTime())) historyStart = null;
  } catch (err) {
    // ⛔ An unreadable depth is UNKNOWN, never "the window is fully covered".
    historyError = err.message || String(err);
    // ⛔ `message`, NOT `reason`. renderSectionErrors() draws `e.message`, so a
    // key named anything else renders the heading with an EMPTY body — a failed
    // gather that announces itself and then says nothing, which is the one
    // outcome this section exists to prevent. Every other push in this file,
    // and in every sibling report, uses `message`.
    sectionErrors.push({
      section: 'History depth',
      message: 'The earliest retained session could not be read, so this report cannot say whether '
        + 'the review window is actually covered by retained records.',
    });
  }
  // How much of the requested window the records can actually speak for.
  const historyCoversWindow = historyError
    ? null
    : Boolean(historyStart && historyStart.getTime() <= since.getTime());
  const historyDays = historyStart
    ? Math.max(0, Math.round((now.getTime() - historyStart.getTime()) / MS_PER_DAY))
    : null;
  const usersInWindow = totalRows[0] ? Number(totalRows[0].users_in_window) : 0;

  // ── per-gateway coverage ────────────────────────────────────────────────
  const perDevice = new Map();
  const snapshotById = new Map();
  const activeById = new Map();
  const configById = new Map();

  if (ids.length > 0) {
    const { rows: byDevice } = await pool.query(
      `SELECT device_id,
              count(*)::int AS sessions,
              count(DISTINCT username)::int AS users,
              count(*) FILTER (WHERE ended_at IS NULL)::int AS open_sessions,
              min(login_time) AS first_login_at,
              max(last_seen_at) AS last_seen_at
         FROM vpn_sessions
        WHERE COALESCE(ended_at, last_seen_at) >= $1::timestamptz
          AND device_id = ANY($2::uuid[])
        GROUP BY device_id`,
      [sinceIso, ids]
    );
    for (const r of byDevice) perDevice.set(r.device_id, r);

    // ⛔ The COUNT-ONLY evidence. A firewall whose adapter reports a session
    // COUNT but no per-user array appears here and nowhere else — that is the
    // whole reason this query exists, and dropping it would let a polled
    // gateway look identical to an unpolled one.
    const { rows: snaps } = await pool.query(
      `SELECT DISTINCT ON (device_id) device_id, active_session_count, sampled_at
         FROM vpn_session_snapshots
        WHERE device_id = ANY($1::uuid[])
        ORDER BY device_id, sampled_at DESC`,
      [ids]
    );
    for (const r of snaps) snapshotById.set(r.device_id, r);

    const { rows: actives } = await pool.query(
      `SELECT device_id, count(*)::int AS active_now
         FROM vpn_active_sessions
        WHERE device_id = ANY($1::uuid[])
        GROUP BY device_id`,
      [ids]
    );
    for (const r of actives) activeById.set(r.device_id, r);

    // ⛔ "Is VPN even configured on this firewall" is a DIFFERENT question from
    // "did SecVault see sessions on it", and the pair is the finding: a gateway
    // with remote access configured and no session history is a blind spot, not
    // an idle gateway.
    const { rows: configs } = await pool.query(
      `SELECT DISTINCT ON (device_id) device_id, config_parsed, collected_at
         FROM device_configs
        WHERE device_id = ANY($1::uuid[])
        ORDER BY device_id, collected_at DESC`,
      [ids]
    );
    for (const r of configs) configById.set(r.device_id, r);
  }

  const gateways = deviceRows.map((d) => {
    const s = perDevice.get(d.id) || null;
    const snap = snapshotById.get(d.id) || null;
    const act = activeById.get(d.id) || null;
    const cfg = configById.get(d.id) || null;
    // summarizeVpnConfig is pure and vendor-aware; it is NOT re-implemented here.
    const vpnConfig = summarizeVpnConfig(d.vendor, cfg ? cfg.config_parsed : null);
    const g = {
      id: d.id,
      name: d.name,
      vendor: d.vendor,
      mgmtMethod: d.mgmt_method,
      site: d.site,
      active: d.active,
      sessions: s ? Number(s.sessions) : 0,
      users: s ? Number(s.users) : 0,
      openSessions: s ? Number(s.open_sessions) : 0,
      firstLoginAt: s ? s.first_login_at : null,
      lastSeenAt: s ? s.last_seen_at : null,
      snapshotAt: snap ? snap.sampled_at : null,
      snapshotCount: snap ? Number(snap.active_session_count) : null,
      activeNow: act ? Number(act.active_now) : 0,
      vpnSupported: vpnConfig ? vpnConfig.supported === true : false,
      vpnConfigured: vpnConfig ? vpnConfig.hasConfig === true : false,
      configCollectedAt: cfg ? cfg.collected_at : null,
    };
    g.representation = gatewayRepresentation(g);
    return g;
  });

  // ── detections ──────────────────────────────────────────────────────────
  //
  // ⛔ THE DETECTION WINDOW IS NOT THE REVIEW WINDOW, and the difference is
  // stated rather than hidden. The engine clamps itself to MAX_WINDOW_HOURS,
  // so a 90-day review carries an 8-day detection window at most. Reporting
  // the review window over a detection table that measured 8 days would be a
  // mislabelled figure — the worst kind, because it is plausible.
  //
  // ⛔ AND THE DETECTIONS ARE ALWAYS FLEET-WIDE. vpnDetections.js has no
  // per-device filter, so a device-scoped review still carries the fleet's
  // detections, labelled as such. Silently presenting them as this gateway's
  // would be a claim the data cannot support.
  const requestedDetectionHours = Math.min(windowDays * 24, MAX_WINDOW_HOURS);
  let detections = null;
  try {
    detections = await getVpnDetections(pool, { hours: requestedDetectionHours, now });
  } catch (err) {
    sectionErrors.push({
      section: 'VPN authentication detections',
      message: 'Could not be run (' + err.message + '). No detection result is reported below, and '
        + 'nothing in this document should be read as "no suspicious authentication activity was '
        + 'found" - the rules did not run.',
    });
  }

  const detectionList = detections && Array.isArray(detections.detections)
    ? detections.detections
    : [];
  const reportingGapDevices = detections && detections.coverage
    ? (detections.coverage.reportingGapDevices || [])
    : [];
  const hasReportingGap = reportingGapDevices.length > 0;

  const detectionsFlagged = detectionList.reduce(
    (a, d) => a + (d.status === STATUS.MEASURED && Array.isArray(d.findings) ? d.findings.length : 0),
    0
  );
  const detectionsGated = detectionList.filter((d) => d.status !== STATUS.MEASURED).length;
  // ⛔ THE TOTAL, NOT THE ARRAY LENGTH. vpnDetections.js caps its unverifiable
  // list for display and returns `unverifiableTotal` alongside precisely so a
  // consumer cannot read the sample size as the population. Summing
  // `unverifiable.length` here would under-report by hundreds and make a
  // coverage gap look like a clean result.
  const unverifiableTotal = detectionList.reduce(
    (a, d) => a + Number(d.unverifiableTotal || 0),
    0
  );

  // ── users and notable sessions ──────────────────────────────────────────
  const users = summariseUsers(sessionRows);
  const flaggedUsernames = new Set();
  for (const d of detectionList) {
    if (d.status !== STATUS.MEASURED) continue;
    for (const f of Array.isArray(d.findings) ? d.findings : []) {
      if (f && f.username) flaggedUsernames.add(String(f.username));
    }
  }
  const notable = selectNotableSessions(sessionRows, flaggedUsernames);

  // ── totals ──────────────────────────────────────────────────────────────
  const sessionsOpen = sessionRows.filter((r) => sessionEndDisplay(r).state === 'open').length;
  const sessionsClockMismatch = sessionRows.filter(
    (r) => durationDisplay(r).state === 'clock_mismatch'
  ).length;
  const sessionsNotComputable = sessionRows.filter(
    (r) => durationDisplay(r).state === 'not_computable'
  ).length;
  const measuredRows = sessionRows.filter((r) => durationDisplay(r).state === 'lower_bound');
  const connectedSecondsFloor = measuredRows.reduce(
    (a, r) => a + (Number(r.duration_seconds) || 0), 0
  );
  const precisionSecondsTotal = measuredRows.reduce(
    (a, r) => a + (r.duration_precision_seconds === null || r.duration_precision_seconds === undefined
      ? 0
      : Number(r.duration_precision_seconds) || 0),
    0
  );
  const precisionUnknownSessions = measuredRows.filter(
    (r) => r.duration_precision_seconds === null || r.duration_precision_seconds === undefined
  ).length;
  const pollIntervals = [...new Set(
    sessionRows
      .map((r) => r.duration_precision_seconds)
      .filter((v) => v !== null && v !== undefined)
      .map((v) => Number(v))
  )].sort((a, b) => a - b);

  const totals = {
    windowDays,
    sessions: sessionRows.length,
    sessionsInWindow,
    // ⛔ The engine clamps at MAX_HISTORY_LIMIT. If we got exactly that many, or
    // the database holds more than we read, the review is TRUNCATED and must
    // say so on its own cover.
    sessionsTruncated: sessionsInWindow > sessionRows.length,
    users: users.length,
    usersInWindow,
    sessionsOpen,
    sessionsClockMismatch,
    sessionsNotComputable,
    sessionsNoDuration: sessionsClockMismatch + sessionsNotComputable,
    sessionsMeasured: measuredRows.length,
    connectedSecondsFloor: measuredRows.length > 0 ? connectedSecondsFloor : null,
    precisionSecondsTotal,
    precisionUnknownSessions,
    pollIntervals,
    gatewaysTotal: gateways.length,
    gatewaysNamed: gateways.filter((g) => g.representation === 'named').length,
    gatewaysCountOnly: gateways.filter((g) => g.representation === 'count_only').length,
    gatewaysNone: gateways.filter((g) => g.representation === 'none').length,
    gatewaysConfiguredButUnnamed: gateways.filter(
      (g) => g.vpnConfigured && g.representation !== 'named'
    ).length,
    detectionsTotal: detectionList.length,
    detectionsFlagged,
    detectionsGated,
    unverifiableTotal,
    reportingGapDevices: reportingGapDevices.length,
  };

  return {
    scope: deviceId ? 'device' : 'fleet',
    device: deviceId ? gateways[0] : null,
    generatedAt: now,
    windowDays,
    windowStart: since,
    // ⛔ The window that was ASKED FOR, versus the record that exists to answer
    // it. `historyCoversWindow: null` is "we could not tell", never "yes".
    historyStart,
    historyDays,
    historyCoversWindow,
    historyError,
    // What the detection engine ACTUALLY measured, read back from its own
    // answer rather than from what was asked for.
    detectionWindowHours: detections ? detections.windowHours : null,
    detectionBaseline: detections ? detections.baseline : null,
    detectionCoverage: detections ? detections.coverage : null,
    hasReportingGap,
    reportingGapDevices,
    detections: detectionList,
    gateways,
    users,
    sessions: sessionRows,
    notable,
    totals,
    caps,
    sectionErrors,
    headline: headlineSentence(totals),
  };
}

/**
 * The "notable sessions" selection, and the definition is stated in the
 * document itself.
 *
 * ⛔ THE TWO EVIDENCE-PROBLEM CLASSES COME FIRST, ABOVE THE LONG SESSIONS. A
 * clock-mismatched session is proof of a device misconfiguration and is the
 * row an access review most needs to see; burying it under the ten longest
 * connections would be sorting by what is interesting rather than by what is
 * wrong.
 *
 * Pure.
 */
const NOTABLE_REASONS = Object.freeze({
  clock_mismatch: 'Duration not measurable - firewall clock disagrees with the server',
  not_computable: 'Duration not measurable - no end reference',
  flagged_user: 'This user was named by an authentication detection',
  open: 'Still connected',
  longest: 'Among the longest observed connections',
});

const NOTABLE_RANK = Object.freeze(['clock_mismatch', 'not_computable', 'flagged_user', 'open', 'longest']);

function selectNotableSessions(rows, flaggedUsernames) {
  const flagged = flaggedUsernames instanceof Set ? flaggedUsernames : new Set();
  const out = [];
  for (const r of Array.isArray(rows) ? rows : []) {
    const dur = durationDisplay(r);
    const end = sessionEndDisplay(r);
    let reason = null;
    if (dur.state === 'clock_mismatch') reason = 'clock_mismatch';
    else if (dur.state === 'not_computable') reason = 'not_computable';
    else if (r.username && flagged.has(String(r.username))) reason = 'flagged_user';
    else if (end.state === 'open') reason = 'open';
    else reason = 'longest';
    out.push({ row: r, reason, dur, end });
  }
  out.sort((a, b) => (
    NOTABLE_RANK.indexOf(a.reason) - NOTABLE_RANK.indexOf(b.reason)
    || (Number(b.row.duration_seconds) || 0) - (Number(a.row.duration_seconds) || 0)
    || String(a.row.username || '').localeCompare(String(b.row.username || ''))
  ));
  return out;
}

// ── tables ────────────────────────────────────────────────────────────────

function buildUserTable(users, includeDevice) {
  const columns = [
    { key: 'user', label: 'User', width: 76, font: 'Helvetica-Bold' },
    { key: 'sessions', label: 'Sessions', width: 30, align: 'right' },
    { key: 'open', label: 'Open now', width: 30, align: 'right', color: BLUE },
  ];
  if (includeDevice) columns.push({ key: 'devices', label: 'Gateways', width: 74, color: MUTED });
  columns.push(
    { key: 'sources', label: 'Source addresses', width: 40, align: 'right', color: MUTED },
    { key: 'first', label: 'First login', width: 66, color: MUTED },
    { key: 'last', label: 'Last seen', width: 66, color: MUTED },
    // ⛔ The words "at least" are INSIDE the cell, not in a footnote. A
    // spreadsheet import, a screenshot or a reader who skipped page two must
    // still be unable to read this as an exact figure.
    { key: 'connected', label: 'Connected time (lower bound)', width: 96, color: (r) => r._durColor },
    { key: 'unmeasured', label: 'Sessions with no measurable duration', width: 74, color: UNMEASURED, font: 'Helvetica-Bold' }
  );

  return {
    columns,
    rows: users.map((u) => {
      const noDuration = u.sessionsClockMismatch + u.sessionsNotComputable;
      const connected = u.connectedSecondsFloor === null
        ? 'Not measured for any session'
        : LOWER_BOUND_PREFIX + fmtHms(u.connectedSecondsFloor)
          + (u.precisionSecondsTotal > 0
            ? ' (+ up to ' + fmtHms(u.precisionSecondsTotal) + ' unobserved)'
            : '')
          + (u.precisionUnknownSessions > 0
            ? ' plus ' + num(u.precisionUnknownSessions) + ' session(s) with an unknown error bar'
            : '');
      return {
        user: u.username,
        sessions: num(u.sessions),
        open: u.openSessions > 0 ? num(u.openSessions) : '',
        devices: u.devices.join(', '),
        sources: num(u.sourceIpCount),
        first: u.firstLoginAt ? fmtStamp(u.firstLoginAt) : NOT_MEASURED_MARK,
        last: u.lastSeenAt ? fmtStamp(u.lastSeenAt) : NOT_MEASURED_MARK,
        connected,
        // ⛔ A dash, never a 0: "no sessions had an unmeasurable duration" and
        // "we did not check" must not share a glyph, and here the count IS
        // known, so a blank would be the wrong direction too.
        unmeasured: noDuration > 0 ? num(noDuration) : '0',
        _durColor: u.connectedSecondsFloor === null ? UNMEASURED : INK,
      };
    }),
  };
}

function buildSessionTable(items, includeDevice) {
  const columns = [
    { key: 'user', label: 'User', width: 68, font: 'Helvetica-Bold' },
  ];
  if (includeDevice) columns.push({ key: 'device', label: 'Gateway', width: 56, color: MUTED });
  columns.push(
    { key: 'source', label: 'Source address', width: 56, color: MUTED },
    { key: 'assigned', label: 'Assigned address', width: 56, color: MUTED },
    { key: 'login', label: 'Login (exact)', width: 66, color: MUTED },
    // ⛔ "Still connected as of ..." lives in this column. It is a statement,
    // not an absence, and it must never be drawn as a dash.
    { key: 'end', label: 'End of session', width: 86, color: (r) => r._endColor },
    { key: 'duration', label: 'Duration', width: 96, color: (r) => r._durColor },
    { key: 'reason', label: 'Why this session is listed', width: 100, color: MUTED }
  );

  return {
    columns,
    rows: items.map((n) => ({
      user: n.row.username == null ? NOT_MEASURED_MARK : String(n.row.username),
      device: n.row.device_name || NOT_MEASURED_MARK,
      source: n.row.source_ip || NOT_MEASURED_MARK,
      assigned: n.row.assigned_ip || NOT_MEASURED_MARK,
      login: n.row.login_time ? fmtStamp(n.row.login_time) : NOT_MEASURED_MARK,
      end: n.end.text,
      duration: n.dur.text,
      reason: NOTABLE_REASONS[n.reason] || n.reason,
      _endColor: n.end.color,
      _durColor: n.dur.color,
    })),
  };
}

function buildGatewayTable(gateways) {
  return {
    columns: [
      { key: 'name', label: 'Firewall', width: 70, font: 'Helvetica-Bold' },
      { key: 'access', label: 'Vendor / access', width: 58, color: MUTED },
      { key: 'represented', label: 'Represented in this report', width: 88, color: (r) => r._repColor, font: 'Helvetica-Bold' },
      { key: 'users', label: 'Users named', width: 40, align: 'right' },
      { key: 'sessions', label: 'Sessions', width: 34, align: 'right' },
      { key: 'counted', label: 'Live count only', width: 44, align: 'right', color: UNMEASURED },
      { key: 'vpn', label: 'VPN configured', width: 48, color: MUTED },
      { key: 'note', label: 'What that means', width: 176, color: (r) => r._noteColor },
    ],
    rows: gateways.map((g) => {
      const rep = g.representation;
      const repLabel = rep === 'named'
        ? 'Named users'
        : rep === 'count_only' ? 'Count only' : 'Not represented';
      const repColor = rep === 'named' ? GREEN : UNMEASURED;
      let note;
      if (rep === 'named') {
        note = 'Per-user session history is collected from this firewall, so its users appear by '
          + 'name in the tables above.';
      } else if (rep === 'count_only') {
        note = 'SecVault polls this firewall\'s VPN and receives a SESSION COUNT with no per-user '
          + 'detail. Nobody connecting through it can be named, and none of their sessions appear '
          + 'anywhere in this report.';
      } else {
        note = 'No VPN session telemetry of any kind reaches SecVault from this firewall. Its '
          + 'absence from the tables above says nothing about whether anyone connects through it.';
      }
      if (g.vpnConfigured && rep !== 'named') {
        note += ' Remote access IS configured here, so this is a blind spot rather than an idle gateway.';
      }
      if (!g.active) note += ' This firewall is currently inactive in inventory.';
      return {
        name: g.name,
        access: g.vendor + (g.mgmtMethod ? ' / ' + g.mgmtMethod : ''),
        represented: repLabel,
        // ⛔ A dash, not a 0, for a gateway that names nobody. It has not got
        // zero users; the question was never answerable for it.
        users: rep === 'named' ? num(g.users) : NOT_MEASURED_MARK,
        sessions: rep === 'named' ? num(g.sessions) : NOT_MEASURED_MARK,
        counted: g.snapshotCount === null ? NOT_MEASURED_MARK : num(g.snapshotCount),
        vpn: g.vpnSupported === false
          ? 'Not supported'
          : g.vpnConfigured ? 'Yes' : NOT_MEASURED_MARK,
        note,
        _repColor: repColor,
        _noteColor: rep === 'named' ? MUTED : UNMEASURED,
      };
    }),
  };
}

function buildDetectionTable(detections, ctx) {
  return {
    columns: [
      { key: 'title', label: 'Detection', width: 84, font: 'Helvetica-Bold' },
      { key: 'question', label: 'Question it answers', width: 128, color: MUTED },
      { key: 'state', label: 'Result', width: 76, color: (r) => r._stateColor, font: 'Helvetica-Bold' },
      { key: 'findings', label: 'Flagged', width: 30, align: 'right' },
      // ⛔ THE TOTAL, beside the findings count, in its own hueless column.
      // This is the number that stops a short findings list reading as a clean
      // one.
      { key: 'unverifiable', label: 'Could not be judged', width: 48, align: 'right', color: UNMEASURED, font: 'Helvetica-Bold' },
      { key: 'baseline', label: 'History it needed / holds', width: 70, color: UNMEASURED },
    ],
    rows: detections.map((d) => {
      const disp = detectionStateDisplay(d, ctx);
      const b = d.baseline || null;
      return {
        title: d.title || d.id,
        question: d.question || '',
        state: disp.label,
        findings: d.status === STATUS.MEASURED ? num((d.findings || []).length) : NOT_MEASURED_MARK,
        unverifiable: num(d.unverifiableTotal || 0),
        baseline: b
          ? num(b.required) + ' days needed / ' + num(b.have) + ' held'
          : 'No historical baseline required',
        _stateColor: disp.color,
      };
    }),
  };
}

function buildFindingTable(items) {
  return {
    columns: [
      { key: 'detection', label: 'Detection', width: 70, font: 'Helvetica-Bold' },
      { key: 'subject', label: 'User or source', width: 76 },
      { key: 'severity', label: 'Severity', width: 34, color: (r) => r._sevColor, font: 'Helvetica-Bold' },
      { key: 'evidence', label: 'What SecVault measured', width: 210 },
      { key: 'verified', label: 'Success claim', width: 96, color: (r) => r._vColor },
    ],
    rows: items.map((f) => ({
      detection: f._detectionTitle,
      subject: f.username || f.srcIp || NOT_MEASURED_MARK,
      severity: f.severity || 'info',
      evidence: f.evidence || '',
      // ⛔ `successClaimVerified === false` means "we cannot tell whether any of
      // this succeeded", NOT "none of it succeeded". Absent (undefined) means
      // the detection makes no success claim at all — a third state, and it
      // must not be rendered as the second.
      verified: f.successClaimVerified === undefined
        ? 'n/a for this detection'
        : f.successClaimVerified
          ? 'Verified: no success observed'
          : 'NOT verifiable - a firewall that saw this logs no successful VPN logins',
      _sevColor: severityColor(f.severity),
      _vColor: f.successClaimVerified === false ? UNMEASURED : MUTED,
    })),
  };
}

// ── body ──────────────────────────────────────────────────────────────────

/**
 * ⛔ THE LEGEND IS NOT DECORATION, AND IT COMES BEFORE THE FIRST DURATION.
 *
 * This document leaves the tool. The reader may be an auditor with no SecVault
 * account, and every duration on the following pages is a floor, every open
 * session is a statement about a moment rather than a gap, and every gateway
 * absent from the tables is a limit of the product rather than a quiet
 * firewall. Without this page none of that is visible in a cell.
 */
function renderHowToRead(doc, layout, data) {
  const { totals } = data;
  sectionTitle(doc, layout, 'How to read this review, and what it cannot tell you');
  paragraph(
    doc,
    layout,
    'Every figure below carries the measurement it rests on, so you can disagree with a specific '
    + 'number rather than with the tool. Four things on these pages mean something narrower than '
    + 'they may appear to.',
    INK
  );
  doc.y += 4;

  const intervals = totals.pollIntervals.length > 0
    ? totals.pollIntervals.map((s) => fmtHms(s)).join(', ')
    : 'an interval that was not recorded';

  const bullets = [
    ['Durations are LOWER BOUNDS, never exact', INK,
      'A session\'s START is exact - the firewall reported its own login time. Its END is only '
      + 'known to within one polling interval, because all SecVault ever observes is "present in '
      + 'this poll, absent in the next". The true length of every session below therefore lies '
      + 'between the figure shown and that figure plus the polling interval (here: ' + intervals
      + '). Every duration in this document is written "' + LOWER_BOUND_PREFIX.trim()
      + ' ..." for that reason.'],
    ['This is a SAMPLE of connections, not a complete register', UNMEASURED,
      'A session that began and ended between two polls may never have been observed AT ALL, so it '
      + 'is in no table here and in no total here. No figure in this document may be read as "the '
      + 'total time this person was connected" or "every connection this person made" - both are '
      + 'floors over the connections that happened to be visible.'],
    ['"Still connected" is a statement, not a missing value', BLUE,
      'A session with no end time was STILL CONNECTED as of the last time SecVault saw it, and the '
      + 'row says exactly when that was. It never means "this session ended at a time we do not '
      + 'know".'],
    ['A negative duration is a CLOCK FAULT, not a short session', UNMEASURED,
      'Where a firewall\'s clock or timezone disagrees with the server\'s, the arithmetic produces '
      + 'a negative length. That is proof of a configuration problem on the firewall, so it is '
      + 'reported as not measurable and is NEVER shown as zero. Those sessions are listed '
      + 'individually further down.'],
  ];
  bullets.forEach(([label, color, text]) => labelledNote(doc, layout, label, color, text));
}

function renderSectionErrors(doc, layout, sectionErrors) {
  if (!sectionErrors || sectionErrors.length === 0) return;
  doc.y += 8;
  sectionTitle(doc, layout, 'Parts of this report could not be gathered');
  paragraph(
    doc, layout,
    'The following did not return data for this run. Nothing below is reported as a clean result on '
    + 'their behalf.',
    STATUS_RED
  );
  sectionErrors.forEach((e) => labelledNote(doc, layout, e.section, UNMEASURED, e.message));
}

function renderUsers(doc, layout, data) {
  const { users, totals, caps } = data;
  doc.y += 10;
  sectionTitle(doc, layout, 'Who connected (' + num(totals.users) + ' users)');

  if (totals.sessionsTruncated) {
    paragraph(
      doc, layout,
      'This review read ' + num(totals.sessions) + ' of the ' + num(totals.sessionsInWindow)
      + ' sessions recorded in the window - the most recent ones. The per-user figures below '
      + 'therefore UNDERSTATE activity for anyone whose earlier sessions fall outside what could be '
      + 'read, and the full history remains available in the app.'
      // ⛔ And the ROW COUNT understates too. The heading above says "N users",
      // which is the users present in the sessions that were read - not the
      // users who connected. Those who fall entirely outside the read are in no
      // row of this table and in no total on the cover.
      + (totals.usersInWindow > totals.users
        ? ' ' + num(totals.usersInWindow - totals.users) + ' user(s) who connected in the window '
          + 'have no session inside that read at all and are therefore ABSENT from this table '
          + 'entirely - ' + num(totals.users) + ' of ' + num(totals.usersInWindow) + ' are named.'
        : ''),
      UNMEASURED
    );
  }

  paragraph(
    doc, layout,
    'One row per named user. Connected time is the sum of the LOWER BOUNDS of that user\'s '
    + 'observed sessions; sessions whose duration could not be measured are counted in their own '
    + 'column rather than added in as zero.',
    MUTED
  );

  const shown = users.slice(0, caps.maxUserRows);
  const note = truncationNote(shown.length, users.length, 'users');
  if (note) paragraph(doc, layout, note, MUTED);

  drawTable(doc, buildUserTable(shown, data.scope === 'fleet'), layout, {
    continueOnPage: true,
    emptyText: 'No VPN session history was recorded for any firewall in scope during this window. '
      + 'That is a statement about what SecVault could collect, not about whether anyone connected.',
  });
}

function renderNotableSessions(doc, layout, data) {
  const { notable, caps, totals } = data;
  doc.y += 10;
  sectionTitle(doc, layout, 'Sessions worth looking at individually');
  paragraph(
    doc, layout,
    'Listed in this order: sessions whose duration could NOT be measured (a firewall clock problem, '
    + 'or no end reference), sessions belonging to a user an authentication detection named, '
    + 'sessions that are still open, and then the longest observed connections. The reason each row '
    + 'is here is printed on the row.',
    MUTED
  );
  if (totals.sessionsClockMismatch > 0) {
    labelledNote(
      doc, layout,
      num(totals.sessionsClockMismatch) + ' session(s) have a clock mismatch', UNMEASURED,
      'The firewall reported a login time LATER than the last moment SecVault saw the session. That '
      + 'is a timezone or clock disagreement between the firewall and this server, and it means '
      + 'those durations are unknown - not zero, and not short.'
    );
  }

  const shown = notable.slice(0, caps.maxSessionRows);
  const note = truncationNote(shown.length, notable.length, 'sessions');
  if (note) paragraph(doc, layout, note, MUTED);

  drawTable(doc, buildSessionTable(shown, data.scope === 'fleet'), layout, {
    continueOnPage: true,
    emptyText: 'No individual sessions to list for this window.',
  });
}

function renderDetections(doc, layout, data) {
  const { detections, totals, caps } = data;
  doc.y += 10;
  sectionTitle(doc, layout, 'Authentication detections');

  if (detections.length === 0) {
    paragraph(
      doc, layout,
      'The detection rules did not run for this report (see the gathering failures above). This is '
      + 'NOT a finding that nothing suspicious happened.',
      UNMEASURED
    );
    return;
  }

  const hours = data.detectionWindowHours;
  paragraph(
    doc, layout,
    'These rules run over VPN authentication logs, which are kept at a different depth from session '
    + 'history. They measured the last '
    + (hours === null || hours === undefined ? 'unknown number of ' : num(hours) + ' ')
    + 'hours, NOT the ' + num(totals.windowDays) + '-day review window above'
    + (data.scope === 'device'
      ? ', and they are computed across the WHOLE fleet rather than for this one firewall.'
      : '.'),
    INK
  );

  const ctx = { hasReportingGap: data.hasReportingGap };
  drawTable(doc, buildDetectionTable(detections, ctx), layout, {
    continueOnPage: true,
    emptyText: 'No detections were computed.',
  });

  // ⛔ EVERY NON-MEASURED DETECTION GETS ITS OWN SENTENCE, hueless, saying what
  // history it needed and what exists. A gated detection folded into a table
  // cell is the one a reader skims past as "fine".
  doc.y += 8;
  let wroteNote = false;
  for (const d of detections) {
    const disp = detectionStateDisplay(d, ctx);
    if (!disp.note) continue;
    if (!wroteNote) {
      sectionTitle(doc, layout, 'Detections that could not give a verdict');
      wroteNote = true;
    }
    labelledNote(doc, layout, (d.title || d.id) + ' - ' + disp.label, disp.color, disp.note);
  }

  if (totals.unverifiableTotal > 0) {
    doc.y += 4;
    labelledNote(
      doc, layout,
      num(totals.unverifiableTotal) + ' observations could not be judged either way', UNMEASURED,
      'These are counted, not discarded. Most arise because the only firewall that saw the activity '
      + 'reports failed VPN logins but no successful ones, so no claim of the form "and nobody got '
      + 'in" is measurable for it. Dropping them would make a coverage gap look like a clean result.'
    );
  }

  // The findings themselves.
  const flagged = [];
  for (const d of detections) {
    if (d.status !== STATUS.MEASURED) continue;
    for (const f of Array.isArray(d.findings) ? d.findings : []) {
      flagged.push({ ...f, _detectionTitle: d.title || d.id });
    }
  }
  flagged.sort((a, b) => (
    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
    || String(a._detectionTitle).localeCompare(String(b._detectionTitle))
  ));

  doc.y += 10;
  sectionTitle(doc, layout, 'Detection findings (' + num(flagged.length) + ')');
  if (flagged.length === 0 && totals.unverifiableTotal > 0) {
    paragraph(
      doc, layout,
      'No finding could be verified - but ' + num(totals.unverifiableTotal) + ' observation(s) went '
      + 'unjudged, so this is not an all-clear.',
      UNMEASURED
    );
  }
  const shownFlagged = flagged.slice(0, caps.maxFindingRows);
  const fnote = truncationNote(shownFlagged.length, flagged.length, 'findings');
  if (fnote) paragraph(doc, layout, fnote, MUTED);
  drawTable(doc, buildFindingTable(shownFlagged), layout, {
    continueOnPage: true,
    emptyText: 'No verifiable detection findings in the detection window.',
  });

  // ⛔ A named sample of what went unjudged, with the COUNT stated above it.
  const sample = [];
  for (const d of detections) {
    for (const u of Array.isArray(d.unverifiable) ? d.unverifiable : []) {
      sample.push({ ...u, _detectionTitle: d.title || d.id });
      if (sample.length >= MAX_UNVERIFIABLE_SAMPLE) break;
    }
    if (sample.length >= MAX_UNVERIFIABLE_SAMPLE) break;
  }
  if (sample.length > 0) {
    doc.y += 10;
    sectionTitle(
      doc, layout,
      'A sample of the unjudged observations (' + num(sample.length) + ' of '
      + num(totals.unverifiableTotal) + ')'
    );
    paragraph(
      doc, layout,
      'Shown to make the count concrete. The COUNT above is the claim; this list is an illustration '
      + 'of it and is deliberately short.',
      MUTED
    );
    drawTable(doc, buildFindingTable(sample), layout, {
      continueOnPage: true,
      emptyText: 'None.',
    });
  }
}

function renderCoverage(doc, layout, data) {
  const { gateways, totals } = data;
  doc.y += 10;
  sectionTitle(doc, layout, 'Coverage: which gateways this review can and cannot speak for');

  paragraph(
    doc, layout,
    'Per-user VPN session history is available from ONE vendor family today. Where a firewall\'s '
    + 'management interface returns only a session COUNT, or no VPN data at all, nobody connecting '
    + 'through it can be named - and their sessions are absent from every table in this document. '
    + 'That is a limit of what SecVault can collect, never a statement that the gateway is unused.',
    INK
  );
  paragraph(
    doc, layout,
    num(totals.gatewaysNamed) + ' of ' + num(totals.gatewaysTotal)
    + ' firewalls contribute named users; ' + num(totals.gatewaysCountOnly)
    + ' report a live session count only; ' + num(totals.gatewaysNone)
    + ' report no VPN session data at all.'
    + (totals.gatewaysConfiguredButUnnamed > 0
      ? ' ' + num(totals.gatewaysConfiguredButUnnamed) + ' of the unrepresented firewalls have '
        + 'remote access CONFIGURED, which makes them blind spots rather than idle gateways.'
      : ''),
    totals.gatewaysNamed === totals.gatewaysTotal ? INK : UNMEASURED
  );

  drawTable(doc, buildGatewayTable(gateways), layout, {
    continueOnPage: true,
    emptyText: 'No firewalls in scope.',
  });

  if (data.reportingGapDevices && data.reportingGapDevices.length > 0) {
    doc.y += 8;
    sectionTitle(doc, layout, 'Firewalls that log failed VPN logins but not successful ones');
    paragraph(
      doc, layout,
      'These firewalls reported failed VPN authentications and no successful ones at all in the '
      + 'detection window. That is a device-side logging setting, not a 100% failure rate - and it '
      + 'means no detection here can assert "and nobody got in" for anything they saw. Those '
      + 'observations are the unjudged ones counted above.',
      UNMEASURED
    );
    data.reportingGapDevices.forEach((d) => {
      labelledNote(
        doc, layout,
        d.deviceName || 'Unnamed firewall', UNMEASURED,
        'Reported ' + num(d.failureEvents) + ' failed VPN authentications and no successful ones'
        + (d.vendor ? ' (' + d.vendor + ')' : '') + '. Successful-login logging appears to be off.'
      );
    });
  }
}

function renderPrecisionNote(doc, layout, data) {
  const { totals } = data;
  doc.y += 10;
  sectionTitle(doc, layout, 'How these numbers were produced, and their precision');

  paragraph(
    doc, layout,
    'SecVault polls each supported firewall\'s VPN subsystem on a fixed cadence and records every '
    + 'connected session it is shown. Nothing here is typed in by hand and nothing is inferred from '
    + 'a vendor datasheet.',
    INK
  );

  const intervals = totals.pollIntervals.length > 0
    ? totals.pollIntervals.map((s) => fmtHms(s)).join(', ')
    : 'not recorded for any session in this window';

  const bullets = [
    ['Start times are exact', INK,
      'The login time is the FIREWALL\'S own report of when the session began, taken from its own '
      + 'clock - and where the firewall supplies an absolute timestamp, that value is used in '
      + 'preference to parsing its display string. This is the one figure in a session row that '
      + 'carries no error bar.'],
    ['End times carry the polling interval as an error bar', UNMEASURED,
      'A session is known to have ended only because a later poll no longer listed it. The end is '
      + 'recorded as the LAST CONFIRMED SIGHTING, never as the time of the poll that found it '
      + 'missing - so a duration is short by up to one interval, never long. Polling interval in '
      + 'force for these sessions: ' + intervals + '. '
      + (totals.precisionUnknownSessions > 0
        ? num(totals.precisionUnknownSessions) + ' session(s) were recorded before the interval was '
          + 'captured and therefore carry an UNKNOWN error bar rather than a stated one.'
        : '')],
    ['Totals are floors over observed sessions only', UNMEASURED,
      'Across this window ' + num(totals.sessionsMeasured) + ' of ' + num(totals.sessions)
      + ' sessions carried a measurable duration'
      + (totals.connectedSecondsFloor === null
        ? '.'
        : ', totalling ' + LOWER_BOUND_PREFIX + fmtHms(totals.connectedSecondsFloor)
          + ' of connected time, with up to ' + fmtHms(totals.precisionSecondsTotal)
          + ' more unobserved.')
      + ' ' + num(totals.sessionsOpen) + ' session(s) were still open at the last poll and are '
      + 'reported as connected AS OF that moment. A connection shorter than one polling interval '
      + 'may never have been observed at all and is in none of these figures.'],
    ['What this report does not claim', UNMEASURED,
      'It does not claim to list every remote connection made in this period, it does not compute '
      + 'distance or travel speed between login locations, and it does not assert that an account '
      + 'was not compromised. Where it could not measure something it says so in the same place the '
      + 'number would have been.'],
  ];
  bullets.forEach(([label, color, text]) => labelledNote(doc, layout, label, color, text));

  doc.y += 6;
  paragraph(
    doc, layout,
    historySentence(data)
    + ' Authentication detections cover a shorter window, stated in their own section.',
    MUTED
  );

  // ⛔ A window the records cannot fill gets its own labelled note, in the
  // colour the rest of this document uses for "not measured". The previous
  // wording — "Session history covers <window start> to <now>" — asserted
  // coverage the table did not have, in the one place a reader would look to
  // check exactly that.
  if (data.historyCoversWindow === false || data.historyCoversWindow === null) {
    doc.y += 4;
    labelledNote(
      doc, layout,
      data.historyCoversWindow === null
        ? 'The depth of the record could not be established'
        : 'This review is SHORTER than the window it was asked for',
      UNMEASURED,
      data.historyCoversWindow === null
        ? 'The earliest retained session could not be read. Treat every total below as covering an '
          + 'unknown period, not the review window on the cover.'
        : 'Session history is retained for a limited period and was introduced more recently than '
          + 'the window requested here. Every total below is drawn from '
          + (data.historyDays === null ? 'the retained records only' : 'the last ' + num(data.historyDays)
            + ' day' + (data.historyDays === 1 ? '' : 's'))
          + ', not from the full '
          + num(data.windowDays) + ' days. A connection made before '
          + fmtStamp(data.historyStart) + ' is in no table here and in no total here, and its absence '
          + 'is not evidence that it did not happen.'
    );
  }
}

function renderBody(doc, data, layout) {
  doc.addPage();

  // Answer first, in a sentence, before any table.
  sectionTitle(doc, layout, 'Summary');
  paragraph(doc, layout, data.headline, INK, 10);
  doc.y += 6;

  renderHowToRead(doc, layout, data);
  renderSectionErrors(doc, layout, data.sectionErrors);
  renderUsers(doc, layout, data);
  renderNotableSessions(doc, layout, data);
  renderDetections(doc, layout, data);
  renderCoverage(doc, layout, data);
  renderPrecisionNote(doc, layout, data);
}

// ── PDF ───────────────────────────────────────────────────────────────────

const TITLE = 'VPN Access Review';

/** Pure-ish: report data -> PDF Buffer. No DB, no network, no browser. */
function renderVpnAccessReviewPdf(data) {
  const doc = installPdfSafeText(
    new PDFDocument({ size: 'A4', layout: 'portrait', margin: 36, bufferPages: true })
  );
  const layout = layoutOf(doc);
  const generatedAt = fmtStamp(data.generatedAt || new Date());
  const { totals, scope, device } = data;
  const subject = scope === 'device' && device
    ? device.name + ' (' + device.vendor + (device.mgmtMethod ? ' / ' + device.mgmtMethod : '') + ')'
    : 'Fleet-wide';

  drawCover(
    doc,
    {
      title: TITLE,
      subtitle: scope === 'device'
        ? subject + ' - who connected remotely, from where, and for how long'
        : 'Who connected remotely, from where, and for how long - across the firewall estate',
      company: PRODUCT_NAME,
      generatedAt,
      footerStamp: true,
      meta: [
        ['Scope', scope === 'device' ? subject : num(totals.gatewaysTotal) + ' firewalls'],
        ['Review window', num(totals.windowDays) + ' days, '
          + fmtStamp(data.windowStart) + ' to ' + generatedAt],
        // ⛔ IMMEDIATELY UNDER THE WINDOW, not in an appendix. A reader who
        // goes no further than page one must not take the window as the period
        // the evidence covers.
        ['Session records actually retained from', historyCoverageMeta(data)],
        // ⛔ ON THE COVER, in the product's own words. A reader who goes no
        // further than page one must still learn that most of the estate is
        // not represented here.
        ['Gateways contributing named users', num(totals.gatewaysNamed) + ' of '
          + num(totals.gatewaysTotal)],
        ['Gateways reporting a session count only', num(totals.gatewaysCountOnly)],
        ['Gateways with no VPN session data', num(totals.gatewaysNone)],
        ['Sessions still open at the last poll', num(totals.sessionsOpen)],
        ['Sessions with no measurable duration', num(totals.sessionsNoDuration)],
        ['Detections without enough history to run', num(totals.detectionsGated) + ' of '
          + num(totals.detectionsTotal)],
        ['Observations that could not be judged', num(totals.unverifiableTotal)],
        data.detectionWindowHours
          ? ['Detection window', num(data.detectionWindowHours) + ' hours (shorter than the review window)']
          : null,
        totals.sessionsTruncated
          ? ['Sessions read of those recorded', num(totals.sessions) + ' of ' + num(totals.sessionsInWindow)]
          : null,
        // ⛔ BESIDE THE SESSION CAP, because the "Distinct users" chip below is
        // the count of users in the sessions that were READ, not the count of
        // users who connected. Live those differ by eleven people.
        totals.usersInWindow > totals.users
          ? ['Users named of those who connected', num(totals.users) + ' of ' + num(totals.usersInWindow)]
          : null,
      ].filter(Boolean),
      summary: [
        { label: 'Review window (days)', value: num(totals.windowDays), color: NAVY },
        { label: 'Distinct users', value: num(totals.users), color: NAVY },
        { label: 'Sessions observed', value: num(totals.sessions), color: NAVY },
        // ⛔ Hueless when nothing was flagged: over incomplete coverage a zero
        // here is not good news, it is the size of what could be judged. Red
        // only when something actually WAS flagged.
        {
          label: 'Detections flagged',
          value: num(totals.detectionsFlagged),
          color: totals.detectionsFlagged > 0 ? STATUS_RED : UNMEASURED,
        },
      ],
    },
    layout
  );

  renderBody(doc, data, layout);
  stampHeadersFooters(doc, {
    title: PRODUCT_NAME + ' ' + TITLE,
    company: scope === 'device' && device ? device.name : num(totals.gatewaysTotal) + ' firewalls',
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
 * @param {object} [options] `{deviceId}` for one gateway, `{days}` for the
 *   review window; omit both for a fleet-wide quarterly review.
 * @returns {Promise<Buffer|null>} null only when a named device does not exist.
 */
async function generateVpnAccessReviewPdf(pool, options = {}) {
  const data = await buildVpnAccessReviewData(pool, options);
  if (!data) return null;
  return renderVpnAccessReviewPdf(data);
}

module.exports = {
  historyCoverageMeta,
  historySentence,
  TITLE,
  NOT_MEASURED_MARK,
  LOWER_BOUND_PREFIX,
  DEFAULT_WINDOW_DAYS,
  MAX_WINDOW_DAYS,
  NOTABLE_REASONS,
  SEVERITY_ORDER,
  clampWindowDays,
  clampCap,
  fmtHms,
  durationDisplay,
  sessionEndDisplay,
  detectionStateDisplay,
  severityColor,
  worstSeverity,
  truncationNote,
  summariseUsers,
  gatewayRepresentation,
  selectNotableSessions,
  headlineSentence,
  buildVpnAccessReviewData,
  renderVpnAccessReviewPdf,
  generateVpnAccessReviewPdf,
};
