'use strict';
// Pins lib/reports/vpnAccessReview.js — the R9 "VPN Access Review" PDF.
//
// ⛔ WHAT THESE TESTS ARE ACTUALLY FOR.
//
// This document names people, and everything it says about them is bounded in
// a way that is invisible once it is printed:
//
//   a duration is a FLOOR, never an exact figure
//   an open session is a STATEMENT about a moment, never a missing end time
//   a negative duration is a CLOCK FAULT, never a zero-length session
//   a gated detection is NOT ENOUGH HISTORY, never an all-clear
//   an unjudged observation is COUNTED, never dropped
//   a gateway that reports only a session count NAMES NOBODY, and its users
//     are absent from every table
//
// Each of those failure modes is silent: nothing crashes, the page looks
// perfectly plausible, and the artefact outlives the session that made it. So
// every test below is a variant of one question: DOES THE DOCUMENT STILL SAY
// "WE COULD NOT MEASURE THIS"? The happy cases are cheap; the unmeasured case
// is the one that regresses quietly.
//
// No database. The stub pool returns canned rows and routes on statement text,
// and the engines under lib/engines are exercised for real against it — so a
// change to how vpnSessions.js decorates a duration is caught here rather than
// being re-implemented and drifting.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { contentStreams } = require('../lib/reports/pdfCompare');
const {
  NOT_MEASURED_MARK,
  LOWER_BOUND_PREFIX,
  DEFAULT_WINDOW_DAYS,
  clampWindowDays,
  fmtHms,
  durationDisplay,
  sessionEndDisplay,
  detectionStateDisplay,
  summariseUsers,
  gatewayRepresentation,
  selectNotableSessions,
  headlineSentence,
  truncationNote,
  buildVpnAccessReviewData,
  renderVpnAccessReviewPdf,
  generateVpnAccessReviewPdf,
} = require('../lib/reports/vpnAccessReview');

const { STATUS } = require('../lib/engines/vpnDetections');

// ── reading the PDF back ──────────────────────────────────────────────────

/**
 * pdfkit writes every glyph run as a HEX STRING inside a TJ array, so the words
 * are not visible as ASCII anywhere in the file. Decode each `<hex>` token in
 * document order and concatenate.
 *
 * ⛔ Concatenated with no separator ON PURPOSE — kerning splits a single word
 * across several tokens, and inserting a space would break every phrase
 * assertion below into unmatchable fragments. (Borrowed verbatim from
 * tests/reportRuleHygiene.test.js; two decoders would eventually disagree.)
 */
function pdfText(buf) {
  let out = '';
  for (const stream of contentStreams(buf)) {
    const re = /<([0-9a-fA-F]+)>/g;
    let m;
    while ((m = re.exec(stream)) !== null) {
      const hex = m[1];
      if (hex.length % 2 !== 0) continue;
      for (let i = 0; i < hex.length; i += 2) {
        out += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
      }
    }
  }
  return out;
}

/** Whitespace-insensitive contains, because pdfkit breaks lines where it likes. */
function says(text, phrase) {
  const norm = (s) => s.replace(/\s+/g, ' ');
  return norm(text).includes(norm(phrase));
}

// ── the fixture ───────────────────────────────────────────────────────────
//
// Shaped after the live reference fleet, which is genuinely three-way on
// coverage: several Palo Alto gateways return a per-session array, the
// Fortinets return a bare count, and some firewalls report nothing at all.

const GW_NAMED = '11111111-1111-1111-1111-111111111111';
const GW_COUNT = '22222222-2222-2222-2222-222222222222';
const GW_NONE = '33333333-3333-3333-3333-333333333333';

const NOW = new Date('2026-09-15T00:00:00Z');
const POLL = 1800; // 30 minutes — the live cadence

/**
 * A row as the DATABASE hands it to getVpnSessionHistory — including the
 * `observed_seconds` the engine's own SQL computes and `is_open`.
 *
 * ⛔ The stub pool returns THESE, not pre-decorated rows, so the engine's
 * duration arithmetic runs for real. An earlier draft returned already-
 * decorated rows and the engine silently overwrote every one of them with
 * `not_computable` — which is exactly how a report ends up quietly reporting
 * "no duration" for a fleet whose durations are fine.
 */
function sessionRow(over = {}) {
  const row = Object.assign({
    id: 'sess-' + Math.random().toString(16).slice(2),
    device_id: GW_NAMED,
    device_name: 'ITC-SK',
    device_vendor: 'paloalto',
    username: 'user.one',
    login_time: new Date('2026-09-14T08:00:00Z'),
    tunnel_type: 'GlobalProtect',
    source_ip: '203.0.113.10',
    assigned_ip: '10.250.0.5',
    client: 'Windows',
    gateway: null,
    first_seen_at: new Date('2026-09-14T08:10:00Z'),
    last_seen_at: new Date('2026-09-14T12:00:00Z'),
    ended_at: new Date('2026-09-14T12:00:00Z'),
    poll_interval_seconds: POLL,
  }, over);
  const end = row.ended_at || row.last_seen_at;
  row.is_open = row.ended_at === null || row.ended_at === undefined;
  row.observed_seconds = end && row.login_time
    ? Math.round((new Date(end).getTime() - new Date(row.login_time).getTime()) / 1000)
    : null;
  return row;
}

/**
 * The SAME three-state rule getVpnSessionHistory applies, for the pure-function
 * tests that need a decorated row without a pool.
 *
 * ⛔ Pinned against the engine by "the fixture's decoration matches the
 * engine's" below — two implementations of this rule drifting apart is how a
 * test starts passing against a shape the engine no longer produces.
 */
function decorated(row) {
  const observed = row.observed_seconds;
  let duration = null;
  let reason = null;
  if (observed === null || observed === undefined) reason = 'not_computable';
  else if (observed < 0) reason = 'clock_mismatch';
  else duration = observed;
  return Object.assign({}, row, {
    is_open: row.ended_at === null || row.ended_at === undefined,
    duration_seconds: duration,
    duration_is_lower_bound: true,
    duration_precision_seconds: row.poll_interval_seconds === null
      || row.poll_interval_seconds === undefined
      ? null
      : Number(row.poll_interval_seconds),
    duration_unavailable_reason: reason,
  });
}

function detection(over = {}) {
  return Object.assign({
    id: 'credential_spray',
    title: 'Credential spray',
    question: 'Is one address trying many different usernames?',
    method: 'One source address, five or more distinct usernames failing.',
    status: STATUS.MEASURED,
    baseline: null,
    findings: [],
    unverifiable: [],
    unverifiableTotal: 0,
    caveats: [],
  }, over);
}

function fixture(overrides = {}) {
  return Object.assign({
    devices: [
      { id: GW_NAMED, name: 'ITC-SK', vendor: 'paloalto', mgmt_method: 'api', mgmt_ip: '10.0.0.1', site: 'ITC', active: true },
      // Polls, gets a NUMBER, names nobody. Its users are absent from every
      // table in the report and the coverage page must say so.
      { id: GW_COUNT, name: 'TSR_EKM', vendor: 'fortinet', mgmt_method: 'ssh', mgmt_ip: '10.0.0.2', site: 'TSR', active: true },
      { id: GW_NONE, name: 'Vietnam-YCC', vendor: 'fortinet', mgmt_method: 'ssh', mgmt_ip: '10.0.0.3', site: 'VN', active: true },
    ],
    sessions: [
      // A clean, ended session.
      sessionRow({ username: 'user.one' }),
      // ⛔ STILL CONNECTED. ended_at NULL is a statement, not a gap.
      sessionRow({
        username: 'user.two',
        login_time: new Date('2026-09-14T22:00:00Z'),
        last_seen_at: new Date('2026-09-15T00:00:00Z'),
        ended_at: null,
      }),
      // ⛔ CLOCK MISMATCH. The firewall reported a login LATER than the last
      // sighting — a negative length, which is a fault report and not a zero.
      sessionRow({
        username: 'user.three',
        login_time: new Date('2026-09-14T19:00:00Z'),
        last_seen_at: new Date('2026-09-14T12:00:00Z'),
        ended_at: new Date('2026-09-14T12:00:00Z'),
      }),
      // ⛔ UNKNOWN ERROR BAR. Written before the poll cadence was recorded, so
      // the amount of unobserved time cannot be bounded at all.
      sessionRow({
        username: 'user.four',
        login_time: new Date('2026-09-13T08:00:00Z'),
        last_seen_at: new Date('2026-09-13T09:00:00Z'),
        ended_at: new Date('2026-09-13T09:00:00Z'),
        poll_interval_seconds: null,
      }),
    ],
    windowTotals: { sessions_in_window: 4, users_in_window: 4 },
    perDevice: [
      { device_id: GW_NAMED, sessions: 4, users: 4, open_sessions: 1, first_login_at: new Date('2026-09-13T08:00:00Z'), last_seen_at: new Date('2026-09-15T00:00:00Z') },
    ],
    snapshots: [
      // GW_COUNT polls and reports a number. GW_NONE reports nothing.
      { device_id: GW_COUNT, active_session_count: 7, sampled_at: new Date('2026-09-15T00:00:00Z') },
    ],
    actives: [
      { device_id: GW_NAMED, active_now: 1 },
    ],
    configs: [
      // ⛔ Remote access IS configured on the count-only gateway — the blind
      // spot the coverage section exists to name.
      { device_id: GW_COUNT, config_parsed: { ssl_vpn: { 'source-interface': 'wan1', port: '10443' } }, collected_at: new Date('2026-09-14T00:00:00Z') },
      { device_id: GW_NONE, config_parsed: {}, collected_at: new Date('2026-09-14T00:00:00Z') },
    ],
    detections: {
      windowHours: 192,
      baselineDays: 30,
      windowStart: new Date('2026-09-07T00:00:00Z'),
      generatedAt: NOW,
      baseline: { spanDays: 6.1, hasHistory: true },
      coverage: {
        devices: [],
        // A firewall that logs failures but not successes. The cost is stated,
        // never hidden.
        reportingGapDevices: [
          { deviceId: GW_COUNT, deviceName: 'TSR_EKM', vendor: 'fortinet', failureEvents: 1860, successEvents: 0 },
        ],
        unattributedCoverage: [],
        totalFailures: 1860,
        totalSuccesses: 12,
        sourcesSeen: 1840,
      },
      detections: [
        detection({
          findings: [{
            kind: 'credential_spray',
            srcIp: '198.51.100.7',
            severity: 'high',
            successClaimVerified: true,
            evidence: '1,821 failed VPN authentications from 198.51.100.7 against at least 908 distinct usernames in the last 192h',
          }],
          unverifiable: [{ kind: 'credential_spray', srcIp: '198.51.100.9', severity: 'medium', successClaimVerified: false, reason: 'no-success-baseline', evidence: '57 failed VPN authentications from 198.51.100.9' }],
          unverifiableTotal: 31,
        }),
        // ⛔ THE ROW THIS WHOLE FILE EXISTS TO PROTECT. Gated: the fleet holds
        // 6.1 days of authentication history and this needs 7. It did NOT run.
        detection({
          id: 'new_country_for_user',
          title: 'New country for a user',
          question: 'Did someone authenticate from a country they have no history in?',
          status: STATUS.INSUFFICIENT,
          baseline: { required: 7, have: 6.1, unit: 'days of VPN authentication history', satisfied: false },
          findings: [],
          // ⛔ The sample is 2 long; the POPULATION is 393. A consumer reading
          // the array's length under-reports by 391.
          unverifiable: [
            { kind: 'new_country_for_user', username: 'user.five', severity: 'medium', reason: 'fleet-baseline-too-short', evidence: '"user.five" authenticated successfully from Japan' },
            { kind: 'new_country_for_user', username: 'user.six', severity: 'medium', reason: 'no-user-baseline', evidence: '"user.six" authenticated successfully from Germany' },
          ],
          unverifiableTotal: 393,
        }),
        detection({
          id: 'country_change',
          title: 'Rapid country change',
          question: 'Did one account authenticate from two countries in quick succession?',
          status: STATUS.MEASURED,
          findings: [],
          unverifiable: [],
          unverifiableTotal: 0,
        }),
      ],
    },
    // Set to a message to make the detections engine throw.
    detectionsThrow: null,
    // The earliest retained session, as the depth probe reads it. Set
    // `historyThrows` to a message to make that probe fail.
    historyStart: null,
    historyThrows: null,
  }, overrides);
}

/**
 * The stub pool. Routes on statement text and records everything it saw.
 *
 * ⛔ Branch order matters: three statements read `vpn_sessions` and two of them
 * mention `COALESCE(ended_at, last_seen_at)`.
 */
function makePool(f) {
  const seen = [];
  return {
    seen,
    async query(text, params) {
      seen.push({ text, params });
      if (/FROM devices/.test(text)) {
        if (params && params[0]) return { rows: f.devices.filter((d) => d.id === params[0]) };
        return { rows: f.devices };
      }
      // getVpnSessionHistory's own SELECT — identified by its LEFT JOIN devices.
      if (/FROM vpn_sessions v/.test(text)) return { rows: f.sessions };
      // The history-depth probe. Matched BEFORE the window-totals branch below,
      // which would otherwise swallow it and hand back a row with no `earliest`.
      if (/AS earliest/.test(text)) {
        if (f.historyThrows) throw new Error(f.historyThrows);
        return { rows: [{ earliest: f.historyStart }] };
      }
      if (/FROM vpn_sessions/.test(text) && /GROUP BY device_id/.test(text)) {
        return { rows: f.perDevice };
      }
      if (/FROM vpn_sessions/.test(text)) return { rows: [f.windowTotals] };
      if (/FROM vpn_session_snapshots/.test(text)) return { rows: f.snapshots };
      if (/FROM vpn_active_sessions/.test(text)) return { rows: f.actives };
      if (/FROM device_configs/.test(text)) return { rows: f.configs };
      if (/FROM syslog_vpn_auth_hourly/.test(text)) {
        throw new Error('the report must not query the VPN auth rollup itself');
      }
      throw new Error('stub pool: unexpected statement\n' + text);
    },
  };
}

/**
 * The detections engine is stubbed at the module boundary rather than through
 * the pool: it issues nine parallel statements against a rollup this report
 * has no business knowing the shape of, and re-encoding them here would make
 * this file a second implementation of that engine.
 */
function buildWith(f, options = {}) {
  const engine = require('../lib/engines/vpnDetections');
  const original = engine.getVpnDetections;
  engine.getVpnDetections = async () => {
    if (f.detectionsThrow) throw new Error(f.detectionsThrow);
    return f.detections;
  };
  // Re-require the report so it picks up the patched export. The module caches
  // its destructured reference at load time, so the patch must be in place
  // before the first require in this process — it is, because `buildWith` is
  // what every test calls.
  delete require.cache[require.resolve('../lib/reports/vpnAccessReview')];
  const mod = require('../lib/reports/vpnAccessReview');
  return mod.buildVpnAccessReviewData(makePool(f), Object.assign({ now: NOW }, options))
    .finally(() => { engine.getVpnDetections = original; });
}

// ── durations ─────────────────────────────────────────────────────────────

describe('a duration is never printed as an exact figure', () => {
  it('⛔ every measured duration carries the lower-bound qualifier and its error bar', () => {
    const d = durationDisplay({
      duration_seconds: 14400,
      duration_is_lower_bound: true,
      duration_precision_seconds: POLL,
      duration_unavailable_reason: null,
    });
    assert.equal(d.state, 'lower_bound');
    assert.ok(d.text.startsWith(LOWER_BOUND_PREFIX), 'missing the "at least" qualifier: ' + d.text);
    assert.ok(d.text.includes('4h'), d.text);
    // The error bar must be stated, not implied.
    assert.ok(d.text.includes('30m'), 'the poll interval is the error bar and must be printed');
    assert.ok(/up to/.test(d.text));
  });

  it('⛔ an UNKNOWN error bar says so rather than silently becoming exact', () => {
    const d = durationDisplay({
      duration_seconds: 3600,
      duration_is_lower_bound: true,
      duration_precision_seconds: null,
      duration_unavailable_reason: null,
    });
    assert.ok(d.text.startsWith(LOWER_BOUND_PREFIX));
    assert.ok(/unknown/i.test(d.text), 'an unknown error bar must be named: ' + d.text);
  });

  it('⛔ a clock_mismatch duration is NOT rendered as 0', () => {
    const d = durationDisplay({
      duration_seconds: null,
      duration_is_lower_bound: true,
      duration_precision_seconds: POLL,
      duration_unavailable_reason: 'clock_mismatch',
    });
    assert.equal(d.state, 'clock_mismatch');
    assert.notEqual(d.text, '0');
    assert.ok(!/\b0s\b|\b0m\b/.test(d.text), 'a clock fault must not read as a zero-length session');
    assert.ok(/clock/i.test(d.text), d.text);
    assert.ok(/not measured/i.test(d.text), d.text);
  });

  it('a duration with nothing to compute from is "not measured", not zero', () => {
    const d = durationDisplay({
      duration_seconds: null,
      duration_precision_seconds: null,
      duration_unavailable_reason: 'not_computable',
    });
    assert.equal(d.state, 'not_computable');
    assert.ok(/not measured/i.test(d.text));
    assert.notEqual(d.text, '0');
  });

  it('fmtHms never returns a bare number that could be read as an exact second count', () => {
    assert.equal(fmtHms(90061), '1d 1h');
    assert.equal(fmtHms(3660), '1h 1m');
    assert.equal(fmtHms(120), '2m');
    // A non-number is the unknown mark, never 0.
    assert.equal(fmtHms(null), NOT_MEASURED_MARK);
    assert.equal(fmtHms(undefined), NOT_MEASURED_MARK);
  });
});

// ── open sessions ─────────────────────────────────────────────────────────

describe('ended_at IS NULL means STILL CONNECTED, never an unknown end', () => {
  it('⛔ renders as "Still connected as of <last sighting>"', () => {
    const e = sessionEndDisplay({ ended_at: null, is_open: true, last_seen_at: new Date('2026-09-15T00:00:00Z') });
    assert.equal(e.state, 'open');
    assert.ok(/still connected/i.test(e.text), e.text);
    assert.ok(e.text.includes('UTC'), 'the moment it was last seen must be stated: ' + e.text);
    assert.notEqual(e.text, NOT_MEASURED_MARK);
    assert.ok(!/unknown/i.test(e.text), 'an open session is not an unknown end time');
  });

  it('an ended session renders its actual end time', () => {
    const e = sessionEndDisplay({ ended_at: new Date('2026-09-14T12:00:00Z'), is_open: false, last_seen_at: new Date('2026-09-14T12:00:00Z') });
    assert.equal(e.state, 'ended');
    assert.ok(e.text.includes('UTC'));
    assert.ok(!/still connected/i.test(e.text));
  });
});

// ── per-user aggregation ──────────────────────────────────────────────────

describe('per-user totals never fold an unmeasurable session in as a zero', () => {
  const rows = [
    decorated(sessionRow({ username: 'u', login_time: new Date('2026-09-14T08:00:00Z'), last_seen_at: new Date('2026-09-14T09:00:00Z'), ended_at: new Date('2026-09-14T09:00:00Z') })),
    decorated(sessionRow({ username: 'u', login_time: new Date('2026-09-14T19:00:00Z'), last_seen_at: new Date('2026-09-14T12:00:00Z'), ended_at: new Date('2026-09-14T12:00:00Z') })),
    decorated(sessionRow({ username: 'u', login_time: new Date('2026-09-14T22:00:00Z'), last_seen_at: new Date('2026-09-15T00:00:00Z'), ended_at: null })),
  ];

  it('counts measured, clock-mismatched and open sessions separately', () => {
    const [u] = summariseUsers(rows);
    assert.equal(u.sessions, 3);
    assert.equal(u.sessionsMeasured, 2);
    assert.equal(u.sessionsClockMismatch, 1);
    assert.equal(u.openSessions, 1);
    // ⛔ The floor is 1h (ended) + 2h (open, measured to its last sighting).
    // The clock-mismatched session contributes NOTHING — not a zero.
    assert.equal(u.connectedSecondsFloor, 3600 + 7200);
    assert.equal(u.precisionSecondsTotal, POLL * 2);
  });

  it('⛔ a user whose every session is unmeasurable gets null, not 0', () => {
    const [u] = summariseUsers([rows[1]]);
    assert.equal(u.sessionsMeasured, 0);
    assert.equal(u.connectedSecondsFloor, null, 'null means unknown; 0 would claim they were never connected');
    assert.equal(u.sessionsClockMismatch, 1);
  });

  it('an unknown error bar is counted separately from a known one', () => {
    const noPoll = decorated(sessionRow({ username: 'u', poll_interval_seconds: null }));
    const [u] = summariseUsers([noPoll]);
    assert.equal(u.precisionUnknownSessions, 1);
    assert.equal(u.precisionSecondsTotal, 0);
  });
});

// ── detections ────────────────────────────────────────────────────────────

describe('a thin baseline is never a clean one', () => {
  it('⛔ insufficient_baseline renders HUELESS and says "not enough history"', () => {
    const disp = detectionStateDisplay({
      status: STATUS.INSUFFICIENT,
      baseline: { required: 7, have: 6.1, satisfied: false },
      findings: [],
      unverifiable: [],
      unverifiableTotal: 393,
    });
    assert.equal(disp.state, 'insufficient_baseline');
    // ⛔ HUELESS. Not green, not any severity colour. The chassis's UNMEASURED
    // token is the only acceptable value here.
    assert.equal(disp.color, '#6D7784');
    assert.ok(/not enough history/i.test(disp.label), disp.label);
    assert.ok(!/clear|pass|ok|no (anomal|finding)/i.test(disp.label));
    assert.ok(disp.note.includes('7'), 'must state what it needed');
    assert.ok(disp.note.includes('6.1'), 'must state what it has');
    assert.ok(/did NOT run/i.test(disp.note));
    assert.ok(/393/.test(disp.note), 'the unjudged population must travel with the verdict');
  });

  it('no_data renders hueless too, and never as "nothing happened"', () => {
    const disp = detectionStateDisplay({ status: STATUS.NO_DATA, findings: [], unverifiableTotal: 0 });
    assert.equal(disp.color, '#6D7784');
    assert.ok(/no vpn authentication data/i.test(disp.label));
  });

  it('⛔ a measured detection with nothing but unjudged observations is NOT a pass', () => {
    const disp = detectionStateDisplay({
      status: STATUS.MEASURED, findings: [], unverifiable: [], unverifiableTotal: 31,
    });
    assert.equal(disp.state, 'nothing_verifiable');
    assert.equal(disp.color, '#6D7784');
    assert.ok(/nothing here is cleared/i.test(disp.note), disp.note);
  });

  it('⛔ a genuinely clean detection goes green ONLY when the fleet has no reporting gap', () => {
    const clean = { status: STATUS.MEASURED, findings: [], unverifiable: [], unverifiableTotal: 0 };
    assert.equal(detectionStateDisplay(clean, { hasReportingGap: false }).color, '#17825A');
    const gapped = detectionStateDisplay(clean, { hasReportingGap: true });
    assert.equal(gapped.color, '#6D7784');
    assert.ok(/coverage incomplete/i.test(gapped.label), gapped.label);
  });

  it('a detection with findings takes its severity colour', () => {
    const disp = detectionStateDisplay({
      status: STATUS.MEASURED,
      findings: [{ severity: 'medium' }, { severity: 'high' }],
      unverifiableTotal: 0,
    });
    assert.equal(disp.state, 'flagged');
    assert.equal(disp.color, '#E05E12'); // ORANGE — the WORST severity present
  });
});

// ── coverage ──────────────────────────────────────────────────────────────

describe('a gateway that names nobody is not a gateway nobody uses', () => {
  it('classifies named / count-only / absent', () => {
    assert.equal(gatewayRepresentation({ sessions: 12 }), 'named');
    assert.equal(gatewayRepresentation({ sessions: 0, snapshotAt: new Date() }), 'count_only');
    assert.equal(gatewayRepresentation({ sessions: 0, activeNow: 3 }), 'count_only');
    assert.equal(gatewayRepresentation({ sessions: 0 }), 'none');
  });

  it('⛔ a count of 0 from a polled gateway is still COUNT-ONLY, not absent', () => {
    // A Fortinet reporting zero connected users has answered a different
    // question from a firewall that reports nothing at all.
    assert.equal(
      gatewayRepresentation({ sessions: 0, snapshotCount: 0, snapshotAt: new Date() }),
      'count_only'
    );
  });
});

// ── the headline ──────────────────────────────────────────────────────────

describe('the headline sentence refuses an all-clear over incomplete coverage', () => {
  const base = {
    windowDays: 90, sessions: 4, users: 4, gatewaysTotal: 3, gatewaysNamed: 1,
    detectionsTotal: 3, detectionsFlagged: 0, detectionsGated: 1,
    unverifiableTotal: 424, sessionsNoDuration: 1, sessionsTruncated: false,
  };

  it('⛔ zero findings + gaps never reads as clean', () => {
    const s = headlineSentence(base);
    assert.ok(says(s, 'NOT a complete picture'), s);
    assert.ok(says(s, '2 firewalls in scope contribute NO per-user VPN session history'), s);
    assert.ok(says(s, '1 of 3 detections did not have enough history to run at all'), s);
    assert.ok(says(s, '424 observations could not be judged'), s);
    assert.ok(says(s, '1 session carry no measurable duration') || says(s, 'carry no measurable duration'), s);
  });

  it('only an entirely gapless run gets an unqualified sentence', () => {
    const s = headlineSentence(Object.assign({}, base, {
      gatewaysNamed: 3, detectionsGated: 0, unverifiableTotal: 0, sessionsNoDuration: 0,
    }));
    assert.ok(!says(s, 'NOT a complete picture'), s);
    assert.ok(says(s, 'Every firewall in scope contributed per-user session history'), s);
  });

  it('a truncated read is disclosed in the headline', () => {
    const s = headlineSentence(Object.assign({}, base, {
      gatewaysNamed: 3, detectionsGated: 0, unverifiableTotal: 0, sessionsNoDuration: 0,
      sessionsTruncated: true, sessions: 2000, sessionsInWindow: 5000,
    }));
    assert.ok(says(s, 'only the 2,000 most recent of 5,000 sessions'), s);
  });

  it('truncationNote returns null when nothing was dropped and discloses when it was', () => {
    assert.equal(truncationNote(10, 10, 'users'), null);
    assert.ok(says(truncationNote(10, 40, 'users'), 'Showing 10 of 40 users'));
  });
});

// ── window ────────────────────────────────────────────────────────────────

describe('the review window', () => {
  it('defaults to a quarter and clamps rather than promising history that is not kept', () => {
    assert.equal(clampWindowDays(undefined), DEFAULT_WINDOW_DAYS);
    assert.equal(clampWindowDays('not a number'), DEFAULT_WINDOW_DAYS);
    assert.equal(clampWindowDays(0), 1);
    assert.equal(clampWindowDays(9999), 365);
    assert.equal(clampWindowDays(30), 30);
  });
});

// ── notable sessions ──────────────────────────────────────────────────────

describe('notable sessions put the evidence problems first', () => {
  it('ranks clock faults above long connections', () => {
    const rows = [
      decorated(sessionRow({ username: 'long', login_time: new Date('2026-09-10T00:00:00Z'), last_seen_at: new Date('2026-09-14T00:00:00Z'), ended_at: new Date('2026-09-14T00:00:00Z') })),
      decorated(sessionRow({ username: 'broken', login_time: new Date('2026-09-14T19:00:00Z'), last_seen_at: new Date('2026-09-14T12:00:00Z'), ended_at: new Date('2026-09-14T12:00:00Z') })),
    ];
    const out = selectNotableSessions(rows, new Set());
    assert.equal(out[0].row.username, 'broken');
    assert.equal(out[0].reason, 'clock_mismatch');
  });

  it('a user named by a detection is listed for that reason', () => {
    const rows = [decorated(sessionRow({ username: 'flagged.user' }))];
    const out = selectNotableSessions(rows, new Set(['flagged.user']));
    assert.equal(out[0].reason, 'flagged_user');
  });
});

// ── end-to-end data build ─────────────────────────────────────────────────

describe('buildVpnAccessReviewData', () => {
  it('partitions the sessions into their real states', async () => {
    const data = await buildWith(fixture());
    assert.equal(data.totals.sessions, 4);
    assert.equal(data.totals.sessionsOpen, 1);
    assert.equal(data.totals.sessionsClockMismatch, 1);
    assert.equal(data.totals.sessionsMeasured, 3);
    assert.equal(data.totals.sessionsNoDuration, 1);
    assert.equal(
      data.totals.sessionsMeasured + data.totals.sessionsNoDuration,
      data.totals.sessions,
      'the duration states must partition the sessions exactly'
    );
    assert.equal(data.totals.precisionUnknownSessions, 1);
  });

  it("⛔ the report consumes the ENGINE's duration decoration, not its own", async () => {
    // The pure-function tests above build rows with this file's `decorated()`.
    // If that ever stops matching what vpnSessions.js actually produces, those
    // tests would keep passing against a shape the report never sees.
    const f = fixture();
    const data = await buildWith(f);
    assert.equal(data.sessions.length, f.sessions.length);
    data.sessions.forEach((got, i) => {
      const mine = decorated(f.sessions[i]);
      assert.equal(got.duration_seconds, mine.duration_seconds, 'duration drifted at row ' + i);
      assert.equal(got.duration_unavailable_reason, mine.duration_unavailable_reason, 'reason drifted at row ' + i);
      assert.equal(got.duration_precision_seconds, mine.duration_precision_seconds, 'error bar drifted at row ' + i);
    });
    assert.ok(data.sessions.every((r) => r.duration_is_lower_bound === true));
  });

  it('⛔ unverifiableTotal is the POPULATION, never the length of the sample array', async () => {
    const data = await buildWith(fixture());
    // 31 + 393 + 0 — the arrays hold 1 and 2 entries respectively.
    assert.equal(data.totals.unverifiableTotal, 424);
    const listed = data.detections.reduce(
      (a, d) => a + (Array.isArray(d.unverifiable) ? d.unverifiable.length : 0), 0
    );
    assert.equal(listed, 3);
    assert.notEqual(data.totals.unverifiableTotal, listed);
  });

  it('counts the gated detections rather than letting them vanish', async () => {
    const data = await buildWith(fixture());
    assert.equal(data.totals.detectionsTotal, 3);
    assert.equal(data.totals.detectionsGated, 1);
    assert.equal(data.totals.detectionsFlagged, 1);
  });

  it('⛔ classifies all three gateway coverage states and names the blind spot', async () => {
    const data = await buildWith(fixture());
    assert.equal(data.totals.gatewaysTotal, 3);
    assert.equal(data.totals.gatewaysNamed, 1);
    assert.equal(data.totals.gatewaysCountOnly, 1);
    assert.equal(data.totals.gatewaysNone, 1);
    // The Fortinet has SSL VPN configured and names nobody — a blind spot.
    assert.equal(data.totals.gatewaysConfiguredButUnnamed, 1);
  });

  it('carries the firewalls that log failures but not successes', async () => {
    const data = await buildWith(fixture());
    assert.equal(data.hasReportingGap, true);
    assert.equal(data.reportingGapDevices.length, 1);
  });

  it('⛔ a detections failure is RECORDED, never swallowed into an empty section', async () => {
    const data = await buildWith(fixture({ detectionsThrow: 'rollup unavailable' }));
    assert.equal(data.detections.length, 0);
    assert.equal(data.sectionErrors.length, 1);
    assert.ok(/rollup unavailable/.test(data.sectionErrors[0].message));
    assert.ok(/did not run/i.test(data.sectionErrors[0].message));
  });

  it('detects and reports a truncated read', async () => {
    const data = await buildWith(fixture({
      windowTotals: { sessions_in_window: 9000, users_in_window: 800 },
    }));
    assert.equal(data.totals.sessionsTruncated, true);
    assert.equal(data.totals.sessionsInWindow, 9000);
  });

  it('returns null only when a NAMED device does not exist', async () => {
    const data = await buildWith(fixture(), { deviceId: '44444444-4444-4444-4444-444444444444' });
    assert.equal(data, null);
  });

  it('a device-scoped build narrows to that gateway', async () => {
    const data = await buildWith(fixture(), { deviceId: GW_NAMED });
    assert.equal(data.scope, 'device');
    assert.equal(data.device.name, 'ITC-SK');
    assert.equal(data.totals.gatewaysTotal, 1);
  });

  it('⛔ the report never queries the raw syslog tables itself', async () => {
    // The stub throws if syslog_vpn_auth_hourly is touched; the detections
    // engine owns that read and the report must not duplicate it. (And nothing
    // here may ever reach syslog_events — 28M rows/day.)
    const f = fixture();
    const pool = makePool(f);
    const engine = require('../lib/engines/vpnDetections');
    const original = engine.getVpnDetections;
    engine.getVpnDetections = async () => f.detections;
    try {
      delete require.cache[require.resolve('../lib/reports/vpnAccessReview')];
      const mod = require('../lib/reports/vpnAccessReview');
      await mod.buildVpnAccessReviewData(pool, { now: NOW });
    } finally {
      engine.getVpnDetections = original;
    }
    assert.ok(!pool.seen.some((s) => /syslog_events/.test(s.text)));
    assert.ok(!pool.seen.some((s) => /syslog_vpn_auth_hourly/.test(s.text)));
  });
});

// ── the document itself ───────────────────────────────────────────────────

describe('the rendered PDF', () => {
  it('is a real PDF and says all of it out loud', async () => {
    const data = await buildWith(fixture());
    const buf = await renderVpnAccessReviewPdf(data);
    assert.ok(Buffer.isBuffer(buf));
    assert.equal(buf.subarray(0, 4).toString(), '%PDF');
    assert.ok(buf.length > 4000, 'suspiciously small for a multi-section report');

    const text = pdfText(buf);

    // ⛔ The lower-bound qualifier reaches the page.
    assert.ok(says(text, LOWER_BOUND_PREFIX.trim()), 'no "at least" anywhere in the document');
    assert.ok(says(text, 'Durations are LOWER BOUNDS, never exact'), 'the precision note is missing');
    assert.ok(
      says(text, 'SAMPLE of connections, not a complete register'),
      'the document must refuse to imply a complete register'
    );

    // ⛔ Still connected, not an unknown end.
    assert.ok(says(text, 'Still connected'), text.slice(0, 200));
    assert.ok(says(text, 'never means "this session ended at a time we do not know"'));

    // ⛔ Clock fault, never a zero.
    assert.ok(says(text, 'clock disagrees with the server'));
    assert.ok(says(text, 'NEVER shown as zero'));

    // ⛔ The gated detection reads as not-enough-history, never as a pass.
    assert.ok(says(text, 'Not enough history'), 'the gated detection must say so on the page');
    assert.ok(says(text, 'New country for a user'));
    assert.ok(says(text, 'did NOT run, and that is not the same as finding nothing'));

    // ⛔ country_change is not impossible travel, and nothing here implies it.
    assert.ok(!/impossible travel/i.test(text), 'no page may imply a travel calculation');

    // ⛔ The unjudged POPULATION is printed.
    assert.ok(says(text, '424'), 'the exact unverifiable total must appear');

    // ⛔ Coverage is named, both halves.
    assert.ok(says(text, 'Coverage: which gateways this review can and cannot speak for'));
    assert.ok(says(text, 'TSR_EKM'));
    assert.ok(says(text, 'Vietnam-YCC'));
    assert.ok(says(text, 'Count only'));
    assert.ok(says(text, 'Not represented'));
    assert.ok(says(text, 'blind spot rather than an idle gateway'));
    assert.ok(says(text, 'log failed VPN logins but not successful ones'));
  });

  it('⛔ the cover states coverage, not only results', async () => {
    const data = await buildWith(fixture());
    const text = pdfText(await renderVpnAccessReviewPdf(data));
    assert.ok(says(text, 'VPN Access Review'));
    assert.ok(says(text, 'Gateways contributing named users'));
    assert.ok(says(text, 'Gateways with no VPN session data'));
    assert.ok(says(text, 'Observations that could not be judged'));
    assert.ok(says(text, 'Detections without enough history to run'));
    assert.ok(says(text, 'Review window'));
  });

  it('⛔ an empty window produces a document that says so, and does not throw', async () => {
    const empty = fixture({
      sessions: [],
      perDevice: [],
      actives: [],
      windowTotals: { sessions_in_window: 0, users_in_window: 0 },
      detections: Object.assign({}, fixture().detections, { detections: [] }),
    });
    const engine = require('../lib/engines/vpnDetections');
    const original = engine.getVpnDetections;
    engine.getVpnDetections = async () => empty.detections;
    let buf;
    try {
      delete require.cache[require.resolve('../lib/reports/vpnAccessReview')];
      const mod = require('../lib/reports/vpnAccessReview');
      buf = await mod.generateVpnAccessReviewPdf(makePool(empty), { now: NOW });
    } finally {
      engine.getVpnDetections = original;
    }
    assert.ok(Buffer.isBuffer(buf));
    assert.equal(buf.subarray(0, 4).toString(), '%PDF');
    const text = pdfText(buf);
    // ⛔ An empty user table is NOT "nobody connected".
    assert.ok(
      says(text, 'That is a statement about what SecVault could collect, not about whether anyone connected.'),
      'an empty result must not read as an all-clear'
    );
    assert.ok(says(text, 'NOT a complete picture'));
  });

  it('generate...Pdf returns a Buffer for a realistic stub', async () => {
    const f = fixture();
    const engine = require('../lib/engines/vpnDetections');
    const original = engine.getVpnDetections;
    engine.getVpnDetections = async () => f.detections;
    let buf;
    try {
      delete require.cache[require.resolve('../lib/reports/vpnAccessReview')];
      const mod = require('../lib/reports/vpnAccessReview');
      buf = await mod.generateVpnAccessReviewPdf(makePool(f), { now: NOW, days: 90 });
    } finally {
      engine.getVpnDetections = original;
    }
    assert.ok(Buffer.isBuffer(buf));
    assert.equal(buf.subarray(0, 4).toString(), '%PDF');
  });
});

describe('⛔ the review window and the record that exists to answer it', () => {
  // THE BUG THIS PINS, found by running the report against the live fleet
  // rather than by reading it: the cover said
  //     "Review window  365 days, 15/09/2025 to 15/09/2026"
  // above "411 distinct users", while `vpn_sessions` only began on 2026-09-10
  // (v2.99.0) and holds FIVE DAYS. Every other coverage gap in this document
  // was already stated — gateways not represented, detections without enough
  // history, sessions with no measurable duration — but not this one, and this
  // is the one that scales the headline figure. An auditor would have read
  // 411 remote users in a year from five days of evidence.
  //
  // The window is what was ASKED FOR. The history is what can ANSWER it. They
  // are different facts and the document must not let the first stand for the
  // second.

  const { historyCoverageMeta, historySentence } = require('../lib/reports/vpnAccessReview');

  const base = {
    windowDays: 365,
    windowStart: new Date('2025-09-15T00:00:00Z'),
    generatedAt: new Date('2026-09-15T00:00:00Z'),
  };
  const covering = {
    ...base, historyStart: new Date('2025-01-01T00:00:00Z'), historyDays: 622, historyCoversWindow: true,
  };
  const short = {
    ...base, historyStart: new Date('2026-09-10T00:00:00Z'), historyDays: 5, historyCoversWindow: false,
  };
  const unknown = { ...base, historyStart: null, historyDays: null, historyCoversWindow: null };
  const empty = { ...base, historyStart: null, historyDays: null, historyCoversWindow: false };

  it('says so plainly when the records DO cover the window', () => {
    assert.match(historyCoverageMeta(covering), /covers the window/);
    assert.match(historySentence(covering), /the whole of the review window/);
  });

  it('⛔ says SHORTER when the records begin after the window does', () => {
    assert.match(historyCoverageMeta(short), /SHORTER than the review window/);
    assert.match(historySentence(short), /LATER than the start/);
    assert.equal(/covers the window/.test(historyCoverageMeta(short)), false);
  });

  it('⛔ an unreadable depth is "could not be determined", NEVER coverage', () => {
    // The failed-read-as-a-fact rule applied to the report's own scope: if we
    // cannot tell how deep the record is, asserting it covers 365 days is a
    // fabricated claim about our own evidence.
    assert.match(historyCoverageMeta(unknown), /Could not be determined/i);
    assert.equal(/covers the window/.test(historyCoverageMeta(unknown)), false);
    assert.match(historySentence(unknown), /could not be read|unknown/i);
  });

  it('⛔ no retained sessions reads as "none retained", not as a quiet period', () => {
    // Zero rows means we have no record, not that nobody connected. Those are
    // the two readings this whole product exists to keep apart.
    assert.match(historyCoverageMeta(empty), /No sessions retained/i);
    assert.equal(/covers the window/.test(historyCoverageMeta(empty)), false);
    assert.match(historySentence(empty), /No session records are retained/i);
  });

  it('the three non-covering states are distinguishable from each other', () => {
    const outs = [short, unknown, empty].map(historyCoverageMeta);
    assert.equal(new Set(outs).size, 3, 'two different gaps render identically: ' + outs.join(' | '));
  });

  it('the cover states it, and directly under the review window', () => {
    // A disclosure an auditor has to hunt for is not a disclosure. Pinned by
    // source order because the value is drawn by the shared chassis and there
    // is no DOM to assert against.
    const path = require('node:path');
    const fs = require('node:fs');
    const SRC = fs.readFileSync(
      path.join(__dirname, '..', 'lib', 'reports', 'vpnAccessReview.js'), 'utf8');
    const win = SRC.indexOf("['Review window'");
    const hist = SRC.indexOf("['Session records actually retained from'");
    assert.ok(win > 0, 'the cover no longer states the review window');
    assert.ok(hist > 0, 'the cover does not state how deep the record is');
    assert.ok(hist > win && hist - win < 400,
      'the retention line must sit immediately after the review window on the cover');
  });

  // ⛔ A FAILED GATHER MUST SAY WHY, NOT JUST SAY ITS NAME.
  //
  // renderSectionErrors() draws `e.section` as the label and `e.message` as the
  // body. The history-depth probe pushed `{section, reason}`, so a failure there
  // rendered the heading "History depth" with an EMPTY explanation underneath —
  // a section announcing that something could not be gathered and then declining
  // to say what, which is indistinguishable from a rendering bug and is exactly
  // the silence this whole section exists to prevent. Every other push in this
  // file, and in every sibling report, uses `message`.
  it('⛔ a failed history-depth read is EXPLAINED on the page, not merely named', async () => {
    const data = await buildWith(fixture({ historyThrows: 'statement timeout' }));

    assert.equal(data.historyCoversWindow, null, 'an unreadable depth is unknown, never coverage');
    const err = data.sectionErrors.find((e) => e.section === 'History depth');
    assert.ok(err, 'the failure must be a first-class row in the document');
    assert.ok(
      err.message && /review window is actually covered/.test(err.message),
      'the explanation must be under the key the renderer draws (`message`), got: '
        + JSON.stringify(Object.keys(err))
    );

    const text = pdfText(await renderVpnAccessReviewPdf(data));
    assert.ok(says(text, 'Parts of this report could not be gathered'));
    assert.ok(
      says(text, 'The earliest retained session could not be read'),
      'the reason must reach the page - a labelled heading with no body is not a disclosure'
    );
  });

  // ⛔ THE USER COUNT IS TRUNCATED TOO.
  //
  // `users` is the distinct usernames inside the sessions that could be READ;
  // `usersInWindow` is how many actually connected. Live those are 413 and 424,
  // and `usersInWindow` was computed, carried into totals, and then rendered
  // nowhere — so the cover chip and the headline both stated 413 as "distinct
  // users" while eleven people who connected in the window appear in no row and
  // no total. Disclosing the SESSION cap does not disclose that: there is no
  // route from "2,000 of 2,155 sessions" to "and eleven users are missing".
  it('⛔ a truncated read discloses the USERS it lost, not only the sessions', async () => {
    const f = fixture({ windowTotals: { sessions_in_window: 9000, users_in_window: 800 } });
    const data = await buildWith(f);
    assert.equal(data.totals.sessionsTruncated, true);
    assert.ok(
      data.totals.usersInWindow > data.totals.users,
      'fixture must model a read that lost whole users, not only sessions'
    );

    const text = pdfText(await renderVpnAccessReviewPdf(data));
    const named = data.totals.users;
    assert.ok(
      says(text, 'Users named of those who connected') && says(text, named + ' of 800'),
      'the cover must state how many of the users who connected are named here'
    );
    assert.ok(
      says(text, 'users who connected in the window are named here'),
      'and the headline must carry the same qualification'
    );
    assert.ok(
      says(text, 'ABSENT from this table'),
      'the per-user table must say that some users are missing from it entirely'
    );
  });

  it('a complete read makes no claim about missing users', async () => {
    // The disclosure must be conditional: an untruncated review must not print
    // a coverage caveat it has not earned.
    const data = await buildWith(fixture());
    assert.equal(data.totals.sessionsTruncated, false);
    const text = pdfText(await renderVpnAccessReviewPdf(data));
    assert.equal(says(text, 'Users named of those who connected'), false);
    assert.equal(says(text, 'ABSENT from this table'), false);
  });

  it('⛔ the old unconditional "history covers <window> to now" sentence is gone', () => {
    // That exact string asserted coverage the table did not have, in the one
    // place a reader would look to check precisely that.
    const path = require('node:path');
    const fs = require('node:fs');
    const SRC = fs.readFileSync(
      path.join(__dirname, '..', 'lib', 'reports', 'vpnAccessReview.js'), 'utf8');
    assert.equal(
      /'Session history covers ' \+ fmtStamp\(data\.windowStart\)/.test(SRC), false,
      'the unconditional coverage claim is back'
    );
  });
});
