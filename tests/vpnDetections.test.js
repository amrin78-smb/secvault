'use strict';
// Pins lib/engines/vpnDetections.js.
//
// WHY THIS FILE EXISTS: every detection in that engine is a CLAIM about a
// firewall fleet, and the cheapest way to get one wrong is the failure this
// repo keeps re-finding — a thing SecVault could not measure, recorded as an
// affirmative fact. Four shapes of that bug live in this engine and each one
// has a test below whose failure message names it:
//
//   1. a THIN baseline reported as a clean one ("no new countries" from one
//      day of history)
//   2. a device that logs no successful VPN authentications read as a device
//      where nobody succeeded (TSR-TL: 1,860 failures, 0 successes, live)
//   3. a per-user attempt count taken from an undivided bucket event_count,
//      or from a username array that was capped at 50, presented as a total
//   4. a country pair plus a clock presented as a travel calculation
//
// ⛔ SO EVERY TEST HERE INCLUDES THE "WE COULD NOT MEASURE THIS" CASE, not
// just the fires/does-not-fire pair. That is the one that regresses silently,
// because its wrong answer is a plausible, reassuring empty list.
//
// ⛔ NO DATABASE. The builders are pure and take already-fetched rows;
// getVpnDetections() only ever calls pool.query(sql, params), so the one test
// that exercises it hands it a stub that records the SQL it was given.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  getVpnDetections,
  buildSprayDetection,
  buildBruteForceDetection,
  buildTargetedAccountDetection,
  buildNewCountryDetection,
  buildCountryChangeDetection,
  buildOffHoursDetection,
  classifyDeviceSuccessBaseline,
  successClaimSupport,
  summariseBaseline,
  windowStartFrom,
  DETECTION_IDS,
  STATUS,
  MIN_BRUTE_FORCE_ATTEMPTS,
  MIN_TARGETED_SOURCES,
  NEW_COUNTRY_MIN_BASELINE_DAYS,
  NEW_COUNTRY_MIN_USER_DAYS,
  COUNTRY_CHANGE_MAX_GAP_HOURS,
  OFF_HOURS_MIN_BASELINE_DAYS,
} = require('../lib/engines/vpnDetections');

// --------------------------------------------------------------------------
// Fixtures
// --------------------------------------------------------------------------

const NOW = new Date('2026-09-10T03:00:00.000Z');
const WINDOW_START = windowStartFrom(NOW, 24); // 2026-09-09T04:00:00Z

// A device that reports both outcomes — its "and none succeeded" is a real
// measurement.
const PALO = {
  device_id: 'dev-palo',
  device_name: 'IDC FW',
  vendor: 'paloalto',
  success_events: 173,
  success_hours: 22,
  failure_events: 2694,
  hours: 26,
};

// ⛔ THE LIVE REPORTING GAP. TSR-TL logged 1,860 VPN authentication failures
// and ZERO successes in 26 hours. It does not have a 100% failure rate; its
// successes are invisible to SecVault.
const FORTI_GAP = {
  device_id: 'dev-forti',
  device_name: 'TSR-TL',
  vendor: 'fortinet',
  success_events: 0,
  success_hours: 0,
  failure_events: 1791,
  hours: 26,
};

function baselineMap(...rows) {
  const m = new Map();
  for (const r of rows.map(classifyDeviceSuccessBaseline)) m.set(r.deviceId, r);
  return m;
}

// The shape getVpnLoginLocations() returns per source, which findUsernameSprayers
// filters. Only the fields the spray rule and this engine read.
function source(over = {}) {
  return {
    srcIp: '93.152.210.31',
    country: 'Bulgaria',
    vendor: 'paloalto',
    success: 0,
    failure: 1737,
    usernames: 861,
    usernamesTruncated: false,
    lastSeenAt: '2026-09-10T02:47:25.373Z',
    total: 1737,
    ...over,
  };
}

function attribution(map) {
  return new Map(Object.entries(map));
}

// --------------------------------------------------------------------------
// Success baseline — the reporting-gap rule
// --------------------------------------------------------------------------

describe('success baseline classification', () => {
  it('a device with failures and no successes is a reporting GAP, not a 100% failure rate', () => {
    const d = classifyDeviceSuccessBaseline(FORTI_GAP);
    assert.equal(d.successBaseline, 'none');
    assert.equal(d.failureEvents, 1791);
    // The share is REAL here (0 of 1791 observed) but the baseline verdict is
    // what any claim must be gated on, never the share.
    assert.equal(d.successShare, 0);
  });

  it('a device with no VPN rows at all is distinguished from one with a gap', () => {
    const d = classifyDeviceSuccessBaseline({
      device_id: 'x', device_name: 'Quiet', vendor: 'paloalto',
      success_events: 0, success_hours: 0, failure_events: 0, hours: 0,
    });
    assert.equal(d.successBaseline, 'no_vpn_data');
    // ⛔ null, not 0 — there is no denominator, and an undefined ratio is not
    // a ratio of zero.
    assert.equal(d.successShare, null);
  });

  it('a weak but real success baseline still counts as measured, and shows its share', () => {
    // TSR_EKM live: 11 successes against 1,827 failures. It DOES log successes,
    // so the question is answerable; the 0.6% is evidence for the reader, not a
    // second silent gate.
    const d = classifyDeviceSuccessBaseline({
      device_id: 'y', device_name: 'TSR_EKM', vendor: 'fortinet',
      success_events: 11, success_hours: 9, failure_events: 1827, hours: 26,
    });
    assert.equal(d.successBaseline, 'measured');
    assert.ok(d.successShare > 0 && d.successShare < 0.01);
  });

  it('EVERY reporting device must support the claim, not merely one of them', () => {
    // Live: 1,183 of ~1,840 source addresses were seen by more than one device.
    // A Palo Alto that logs successes does NOT vouch for what a blind FortiGate
    // let through.
    const map = baselineMap(PALO, FORTI_GAP);
    assert.equal(successClaimSupport(['dev-palo'], map, false).verified, true);
    const both = successClaimSupport(['dev-palo', 'dev-forti'], map, false);
    assert.equal(both.verified, false);
    assert.deepEqual(both.blindDevices.map((b) => b.deviceName), ['TSR-TL']);
  });

  it('failures never attributed to a managed device cannot support the claim either', () => {
    const map = baselineMap(PALO);
    assert.equal(successClaimSupport(['dev-palo'], map, true).verified, false);
    assert.equal(successClaimSupport([], map, false).verified, false);
  });
});

// --------------------------------------------------------------------------
// Credential spray
// --------------------------------------------------------------------------

describe('credential spray', () => {
  it('fires on the Bulgarian address and calls it critical', () => {
    // The live case this detection exists for: one address, 1,737 failures,
    // 861 distinct usernames.
    const d = buildSprayDetection({
      sources: [source()],
      attributionBySource: attribution({
        '93.152.210.31': { deviceIds: ['dev-palo'], deviceNames: ['IDC FW'], vendors: ['paloalto'], unattributed: false, hours: 24 },
      }),
      baselineByDevice: baselineMap(PALO),
      windowHours: 24,
    });
    assert.equal(d.findings.length, 1);
    assert.equal(d.findings[0].severity, 'critical');
    assert.equal(d.findings[0].successClaimVerified, true);
    // ⛔ Evidence, not just a severity. A severity with no numbers behind it is
    // unfalsifiable.
    assert.match(d.findings[0].evidence, /1737 failed VPN authentications from 93\.152\.210\.31/);
    assert.match(d.findings[0].evidence, /861 distinct usernames/);
  });

  it('a source seen only by a firewall with no success baseline is UNVERIFIABLE, not a finding', () => {
    const d = buildSprayDetection({
      sources: [source({ srcIp: '89.23.144.238', country: 'Russian Federation', usernames: 20, failure: 22 })],
      attributionBySource: attribution({
        '89.23.144.238': { deviceIds: ['dev-forti'], deviceNames: ['TSR-TL'], vendors: ['fortinet'], unattributed: false, hours: 13 },
      }),
      baselineByDevice: baselineMap(FORTI_GAP),
      windowHours: 24,
    });
    assert.equal(d.findings.length, 0, 'must not assert "and none succeeded" against a blind device');
    assert.equal(d.unverifiableTotal, 1);
    assert.equal(d.unverifiable[0].reason, 'no-success-baseline');
    // The device is NAMED, so the operator knows which logging setting closes it.
    assert.deepEqual(d.unverifiable[0].blindDevices.map((b) => b.deviceName), ['TSR-TL']);
    // ⛔ The spray SHAPE is still measured — only the success half is not.
    assert.equal(d.unverifiable[0].usernames, 20);
    assert.ok(d.caveats.length > 0);
  });

  it('an unverified success claim never LOWERS the severity', () => {
    const shared = { sources: [source()], baselineByDevice: baselineMap(PALO, FORTI_GAP), windowHours: 24 };
    const verified = buildSprayDetection({
      ...shared,
      attributionBySource: attribution({ '93.152.210.31': { deviceIds: ['dev-palo'], deviceNames: [], vendors: [], unattributed: false, hours: 24 } }),
    });
    const blind = buildSprayDetection({
      ...shared,
      attributionBySource: attribution({ '93.152.210.31': { deviceIds: ['dev-forti'], deviceNames: [], vendors: [], unattributed: false, hours: 24 } }),
    });
    // Not knowing whether they got in is less news, not better news.
    assert.equal(verified.findings[0].severity, blind.unverifiable[0].severity);
  });

  it('a capped username array makes the count a FLOOR, and says so', () => {
    const d = buildSprayDetection({
      sources: [source({ usernames: 50, usernamesTruncated: true })],
      attributionBySource: attribution({
        '93.152.210.31': { deviceIds: ['dev-palo'], deviceNames: [], vendors: [], unattributed: false, hours: 1 },
      }),
      baselineByDevice: baselineMap(PALO),
      windowHours: 24,
    });
    assert.equal(d.findings[0].usernamesIsFloor, true);
    assert.match(d.findings[0].evidence, /at least 50 distinct usernames/);
  });

  it('spray needs no history, so a one-day-old fleet does not weaken it', () => {
    const d = buildSprayDetection({
      sources: [], attributionBySource: new Map(), baselineByDevice: new Map(), windowHours: 24,
    });
    assert.equal(d.status, STATUS.MEASURED);
    assert.equal(d.baseline, null);
  });
});

// --------------------------------------------------------------------------
// Brute force
// --------------------------------------------------------------------------

function bruteRow(over = {}) {
  return {
    username: 'administrator',
    src_ip: '179.43.145.110',
    src_country: 'Panama',
    attempts_floor: 57,
    shared_buckets: false,
    usernames_truncated: false,
    unattributed: false,
    hours: 23,
    first_seen_at: '2026-09-09T03:00:00.000Z',
    last_seen_at: '2026-09-10T02:00:00.000Z',
    device_ids: ['dev-palo'],
    device_names: ['IDC FW'],
    source_username_breadth: 1,
    ...over,
  };
}

describe('brute force against one account', () => {
  it('fires on a concentrated attack and carries the source\'s username breadth', () => {
    const d = buildBruteForceDetection({
      rows: [bruteRow()], baselineByDevice: baselineMap(PALO), windowHours: 24,
    });
    assert.equal(d.findings.length, 1);
    assert.equal(d.findings[0].severity, 'high');
    // ⛔ Breadth is what lets an operator disagree: 1 means genuinely focused,
    // 13 means a sprayer that happened to hit this name hardest.
    assert.equal(d.findings[0].sourceUsernameBreadth, 1);
    assert.match(d.findings[0].evidence, /at least 57 failed authentications for "administrator"/);
  });

  it('a count drawn from buckets naming several usernames is flagged as a floor', () => {
    // ⛔ One rollup row's event_count covers EVERY username in its array with
    // no split, so a shared bucket can only ever contribute 1. The result is an
    // under-count by construction and must never be labelled a total.
    const d = buildBruteForceDetection({
      rows: [bruteRow({ shared_buckets: true, attempts_floor: 10 })],
      baselineByDevice: baselineMap(PALO),
      windowHours: 24,
    });
    assert.equal(d.findings[0].attemptsIsFloor, true);
    assert.match(d.findings[0].evidence, /at least 10 /);
  });

  it('a capped username array also makes the count a floor', () => {
    const d = buildBruteForceDetection({
      rows: [bruteRow({ shared_buckets: false, usernames_truncated: true })],
      baselineByDevice: baselineMap(PALO),
      windowHours: 24,
    });
    assert.equal(d.findings[0].attemptsIsFloor, true);
  });

  it('the live Panama case is UNVERIFIABLE when only blind FortiGates saw it', () => {
    // Exactly what happens on the fleet: 57 attempts against `administrator`,
    // reported by TSR-TL and TSR_EKM. The attack is measured; "and it never
    // worked" is not.
    const d = buildBruteForceDetection({
      rows: [bruteRow({ device_ids: ['dev-forti'], device_names: ['TSR-TL'] })],
      baselineByDevice: baselineMap(FORTI_GAP),
      windowHours: 24,
    });
    assert.equal(d.findings.length, 0);
    assert.equal(d.unverifiableTotal, 1);
    assert.equal(d.unverifiable[0].attemptsFloor, 57);
    assert.equal(d.unverifiable[0].reason, 'no-success-baseline');
  });

  it('the threshold is documented and non-zero', () => {
    assert.ok(MIN_BRUTE_FORCE_ATTEMPTS >= 5);
  });
});

// --------------------------------------------------------------------------
// Targeted account
// --------------------------------------------------------------------------

describe('account targeted from many addresses', () => {
  it('ranks by distinct source count and always marks the attempt count a floor', () => {
    const d = buildTargetedAccountDetection({
      rows: [
        { username: 'quiet.user', sources: 11, countries: 2, attempts_floor: 12, hours: 4, last_seen_at: null },
        { username: 'pongake.lekrat', sources: 71, countries: 8, attempts_floor: 84, hours: 22, last_seen_at: null },
      ],
      windowHours: 24,
    });
    assert.deepEqual(d.findings.map((f) => f.username), ['pongake.lekrat', 'quiet.user']);
    assert.equal(d.findings[0].severity, 'high');
    // ⛔ ALWAYS a floor here: this aggregation is per-username across buckets
    // that each carry an undivided event count.
    assert.ok(d.findings.every((f) => f.attemptsIsFloor === true));
  });

  it('never claims the targeted usernames are or are not real accounts', () => {
    const d = buildTargetedAccountDetection({ rows: [], windowHours: 24 });
    // Live, all 50 targeted names are absent from the successful-auth set — but
    // that set covers ~1 day, so their absence is a fact about the baseline and
    // not about the directory. The caveat is the guard against reading it the
    // other way.
    assert.ok(d.caveats.some((c) => /NOT answerable/i.test(c)));
    assert.ok(MIN_TARGETED_SOURCES >= 5);
  });
});

// --------------------------------------------------------------------------
// New country for a user — the baseline rule
// --------------------------------------------------------------------------

function successRow(username, iso, country, over = {}) {
  return {
    username,
    bucket_hour: iso,
    src_country: country,
    src_ip: '1.2.3.4',
    device_id: 'dev-palo',
    device_name: 'IDC FW',
    usernames_truncated: false,
    ...over,
  };
}

// A user with four separate days of Thai history before the window.
function fourDayThaiBaseline(username) {
  return [
    successRow(username, '2026-09-01T02:00:00.000Z', 'TH'),
    successRow(username, '2026-09-02T02:00:00.000Z', 'TH'),
    successRow(username, '2026-09-03T02:00:00.000Z', 'TH'),
    successRow(username, '2026-09-04T02:00:00.000Z', 'TH'),
  ];
}

const DEEP_BASELINE = summariseBaseline(
  { first_bucket_at: '2026-08-01T00:00:00.000Z', last_bucket_at: '2026-09-10T02:00:00.000Z', history_hours: 900, history_days: 40, truncated_rows: 0 },
  NOW
);

// ⛔ The fleet as it actually is at the time of writing: 26 hourly buckets,
// starting 2026-09-09. One day.
const THIN_BASELINE = summariseBaseline(
  { first_bucket_at: '2026-09-09T01:00:00.000Z', last_bucket_at: '2026-09-10T02:00:00.000Z', history_hours: 26, history_days: 2, truncated_rows: 0 },
  NOW
);

describe('new country for a user', () => {
  it('⛔ a one-day-old fleet reports INSUFFICIENT BASELINE, never "no anomaly"', () => {
    const d = buildNewCountryDetection({
      successRows: [successRow('sl_asrs_manishs', '2026-09-09T10:00:00.000Z', 'IN')],
      baseline: THIN_BASELINE,
      windowStart: WINDOW_START,
    });
    assert.equal(d.status, STATUS.INSUFFICIENT);
    assert.equal(d.findings.length, 0);
    // The user is still surfaced — as unverifiable, with the reason. An empty
    // findings list alone would read as an all-clear.
    assert.equal(d.unverifiableTotal, 1);
    assert.equal(d.unverifiable[0].reason, 'fleet-baseline-too-short');
    assert.equal(d.baseline.satisfied, false);
    assert.equal(d.baseline.required, NEW_COUNTRY_MIN_BASELINE_DAYS);
    assert.ok(d.baseline.have < NEW_COUNTRY_MIN_BASELINE_DAYS);
  });

  it('⛔ "never seen this user" and "this user has never done this" do not render the same', () => {
    const rows = [
      // Known user, four days of TH history, now appearing from India.
      ...fourDayThaiBaseline('known.user'),
      successRow('known.user', '2026-09-09T10:00:00.000Z', 'IN'),
      // A user with no prior successful authentication at all.
      successRow('brand.new', '2026-09-09T10:00:00.000Z', 'IN'),
    ];
    const d = buildNewCountryDetection({ successRows: rows, baseline: DEEP_BASELINE, windowStart: WINDOW_START });
    assert.deepEqual(d.findings.map((f) => f.username), ['known.user']);
    // ⛔ NORMALISED, not raw. Palo Alto emits "TH" and FortiOS emits "Thailand";
    // these builders now fold them together before grouping. See the regression
    // test below for what reading the raw column produced.
    assert.deepEqual(d.findings[0].knownCountries, ['Thailand']);
    assert.equal(d.unverifiableTotal, 1);
    assert.equal(d.unverifiable[0].username, 'brand.new');
    assert.equal(d.unverifiable[0].reason, 'no-user-baseline');
  });

  it('a country already in the user\'s history is not a finding', () => {
    const rows = [...fourDayThaiBaseline('known.user'), successRow('known.user', '2026-09-09T10:00:00.000Z', 'TH')];
    const d = buildNewCountryDetection({ successRows: rows, baseline: DEEP_BASELINE, windowStart: WINDOW_START });
    assert.equal(d.findings.length, 0);
    assert.equal(d.unverifiableTotal, 0);
    assert.equal(d.status, STATUS.MEASURED);
  });

  it('⛔ a capped baseline bucket is EXCLUDED and the finding carries the caveat', () => {
    // A user cut from a 50-entry username cap looks identical to a user who was
    // never there. Counting that absence as history would manufacture findings.
    const rows = [
      ...fourDayThaiBaseline('known.user'),
      successRow('known.user', '2026-09-05T02:00:00.000Z', 'IN', { usernames_truncated: true }),
      successRow('known.user', '2026-09-09T10:00:00.000Z', 'IN'),
    ];
    const d = buildNewCountryDetection({ successRows: rows, baseline: DEEP_BASELINE, windowStart: WINDOW_START });
    assert.equal(d.findings.length, 1);
    assert.equal(d.findings[0].caveat, 'baseline-contains-capped-buckets');
    assert.ok(d.caveats.some((c) => /capped at 50/.test(c)));
  });

  it('a user with too few baseline DAYS is unverifiable even on a deep fleet baseline', () => {
    const rows = [
      successRow('sparse.user', '2026-09-01T02:00:00.000Z', 'TH'),
      successRow('sparse.user', '2026-09-09T10:00:00.000Z', 'IN'),
    ];
    const d = buildNewCountryDetection({ successRows: rows, baseline: DEEP_BASELINE, windowStart: WINDOW_START });
    assert.equal(d.findings.length, 0);
    assert.equal(d.unverifiable[0].reason, 'no-user-baseline');
    assert.ok(NEW_COUNTRY_MIN_USER_DAYS > 1);
  });

  it('no VPN authentication evidence at all is no_data, not a satisfied baseline', () => {
    const empty = summariseBaseline({ first_bucket_at: null, last_bucket_at: null, history_hours: 0, history_days: 0, truncated_rows: 0 }, NOW);
    const d = buildNewCountryDetection({ successRows: [], baseline: empty, windowStart: WINDOW_START });
    assert.equal(d.status, STATUS.NO_DATA);
  });
});

// --------------------------------------------------------------------------
// Country change — the honest form of "impossible travel"
// --------------------------------------------------------------------------

describe('rapid country change', () => {
  it('fires on two countries inside one hourly bucket and does not imply an order', () => {
    // The live case: sl_asrs_manishs, IN and TH in the 07:00Z bucket on ITC-SK.
    const d = buildCountryChangeDetection({
      successRows: [
        successRow('sl_asrs_manishs', '2026-09-09T07:00:00.000Z', 'IN', { src_ip: '45.126.171.52' }),
        successRow('sl_asrs_manishs', '2026-09-09T07:00:00.000Z', 'TH', { src_ip: '27.130.21.125' }),
      ],
      windowStart: WINDOW_START,
    });
    assert.equal(d.findings.length, 1);
    assert.equal(d.findings[0].gapHours, 0);
    assert.equal(d.findings[0].severity, 'high');
    // ⛔ Equal timestamps carry no ordering, so the sentence must not claim one.
    assert.match(d.findings[0].evidence, /within the same hourly bucket/);
    assert.doesNotMatch(d.findings[0].evidence, /and then/);
  });

  it('⛔ never claims a distance, a velocity, or that anything was impossible', () => {
    const d = buildCountryChangeDetection({ successRows: [], windowStart: WINDOW_START });
    const text = [d.title, d.question, d.method, ...d.caveats].join(' ');
    assert.doesNotMatch(text, /impossible travel/i, 'there is no city or coordinate data in this schema');
    assert.ok(d.caveats.some((c) => /no city or coordinate data/i.test(c)));
    // Geo-IP is the vendor's own attribution and a commercial VPN can change it.
    assert.ok(d.caveats.some((c) => /geo-IP/i.test(c)));
  });

  it('a gap beyond the reportable window is not a finding', () => {
    const d = buildCountryChangeDetection({
      successRows: [
        successRow('traveller', '2026-09-09T05:00:00.000Z', 'TH'),
        successRow('traveller', '2026-09-10T02:00:00.000Z', 'GB'),
      ],
      windowStart: WINDOW_START,
    });
    assert.equal(d.findings.length, 0);
    assert.ok(COUNTRY_CHANGE_MAX_GAP_HOURS <= 24);
  });

  it('carries the whole in-window timeline so the chosen pair can be disputed', () => {
    const d = buildCountryChangeDetection({
      successRows: [
        successRow('u', '2026-09-09T05:00:00.000Z', 'TH'),
        successRow('u', '2026-09-09T06:00:00.000Z', 'IN'),
        successRow('u', '2026-09-09T09:00:00.000Z', 'TH'),
      ],
      windowStart: WINDOW_START,
    });
    assert.equal(d.findings[0].timeline.length, 3);
    // The WORST (smallest) gap is the one reported.
    assert.equal(d.findings[0].gapHours, 1);
  });

  it('an unlocated login cannot make a country pair', () => {
    const d = buildCountryChangeDetection({
      successRows: [
        successRow('u', '2026-09-09T05:00:00.000Z', 'TH'),
        successRow('u', '2026-09-09T06:00:00.000Z', null),
      ],
      windowStart: WINDOW_START,
    });
    assert.equal(d.findings.length, 0);
  });
});

// --------------------------------------------------------------------------
// Off-hours — "normal hours" must be measured, never assumed
// --------------------------------------------------------------------------

describe('off-hours successful login', () => {
  it('⛔ with no hour-of-day profile it reports INSUFFICIENT BASELINE, not an all-clear', () => {
    const d = buildOffHoursDetection({
      hourRows: [{ bucket_hour: '2026-09-09T02:00:00.000Z', hour_utc: 2, success_events: 91 }],
      successRows: [successRow('eng_itc_HirunC', '2026-09-09T20:00:00.000Z', 'TH')],
      baseline: THIN_BASELINE,
      windowStart: WINDOW_START,
    });
    assert.equal(d.status, STATUS.INSUFFICIENT);
    assert.equal(d.findings.length, 0);
    assert.equal(d.unverifiableTotal, 1);
    assert.equal(d.unverifiable[0].reason, 'no-hour-profile');
    assert.equal(d.baseline.required, OFF_HOURS_MIN_BASELINE_DAYS);
    // ⛔ No quiet hour may be declared from a profile that does not exist.
    assert.deepEqual(d.quietHours, []);
    assert.deepEqual(d.profile, []);
  });

  it('⛔ "normal hours" comes from the observed distribution, never an assumed office day', () => {
    const text = buildOffHoursDetection({
      hourRows: [], successRows: [], baseline: THIN_BASELINE, windowStart: WINDOW_START,
    }).method;
    assert.match(text, /busiest hour/);
    assert.doesNotMatch(text, /09:00|9am|business hours/i);
  });

  it('with a deep baseline, a login in a genuinely quiet hour is a finding', () => {
    // Hour 2 carries the volume; hour 20 is at 1% of it across the same days.
    const days = ['2026-08-20', '2026-08-21', '2026-08-22', '2026-08-23'];
    const hourRows = [];
    for (const d of days) {
      hourRows.push({ bucket_hour: `${d}T02:00:00.000Z`, hour_utc: 2, success_events: 100 });
      hourRows.push({ bucket_hour: `${d}T20:00:00.000Z`, hour_utc: 20, success_events: 1 });
    }
    const d = buildOffHoursDetection({
      hourRows,
      successRows: [
        successRow('night.owl', '2026-09-09T20:00:00.000Z', 'TH'),
        successRow('day.user', '2026-09-09T05:00:00.000Z', 'TH'),
      ],
      baseline: DEEP_BASELINE,
      windowStart: WINDOW_START,
    });
    assert.equal(d.status, STATUS.MEASURED);
    assert.deepEqual(d.quietHours, [20]);
    assert.deepEqual(d.findings.map((f) => f.username), ['night.owl']);
  });

  it('an hour-of-day nobody has ever authenticated in cannot be called quiet', () => {
    // ⛔ The profile only holds hours that were OBSERVED. An hour with no
    // observation at all is absence of evidence, and a login in it is not a
    // measured anomaly — it is the first datapoint for that hour.
    const days = ['2026-08-20', '2026-08-21', '2026-08-22', '2026-08-23'];
    const hourRows = days.map((d) => ({ bucket_hour: `${d}T02:00:00.000Z`, hour_utc: 2, success_events: 100 }));
    const d = buildOffHoursDetection({
      hourRows,
      successRows: [successRow('u', '2026-09-09T17:00:00.000Z', 'TH')],
      baseline: DEEP_BASELINE,
      windowStart: WINDOW_START,
    });
    assert.deepEqual(d.quietHours, []);
    assert.equal(d.findings.length, 0);
  });
});

// --------------------------------------------------------------------------
// Orchestration — SQL shape, and the guarantees the whole result must keep
// --------------------------------------------------------------------------

function stubPool() {
  const statements = [];
  return {
    statements,
    query(sql, params) {
      statements.push({ sql, params });
      if (/min\(bucket_hour\)/.test(sql)) {
        return Promise.resolve({
          rows: [{
            first_bucket_at: '2026-09-09T01:00:00.000Z',
            last_bucket_at: '2026-09-10T02:00:00.000Z',
            history_hours: 26, history_days: 2, truncated_rows: 0,
          }],
        });
      }
      if (/LEFT JOIN devices d ON d\.id = a\.device_id\n   WHERE a\.bucket_hour/.test(sql) && /success_hours/.test(sql)) {
        return Promise.resolve({ rows: [PALO, FORTI_GAP] });
      }
      return Promise.resolve({ rows: [] });
    },
  };
}

describe('getVpnDetections orchestration', () => {
  it('returns every declared detection, each with a status and a caveat list', async () => {
    const pool = stubPool();
    const r = await getVpnDetections(pool, { hours: 24, now: NOW });
    assert.deepEqual(r.detections.map((d) => d.id), DETECTION_IDS);
    for (const d of r.detections) {
      assert.ok(Object.values(STATUS).includes(d.status), `${d.id} has an unknown status`);
      assert.ok(Array.isArray(d.findings));
      assert.ok(Array.isArray(d.unverifiable));
      assert.equal(typeof d.unverifiableTotal, 'number');
      assert.ok(Array.isArray(d.caveats));
      // ⛔ Every detection must be able to explain itself. A detection whose
      // method nobody can read is a severity nobody can argue with.
      assert.ok(d.question && d.method && d.title);
    }
  });

  it('⛔ never queries syslog_events, only the hourly VPN rollup', async () => {
    const pool = stubPool();
    await getVpnDetections(pool, { hours: 24, now: NOW });
    for (const s of pool.statements) {
      assert.doesNotMatch(s.sql, /\bsyslog_events\b/,
        'the raw table takes ~28M rows/day and the equivalent query was measured at 85.6s');
    }
    assert.ok(pool.statements.length > 0);
  });

  it('every timestamp parameter is cast explicitly', async () => {
    const pool = stubPool();
    await getVpnDetections(pool, { hours: 24, now: NOW });
    const windowed = pool.statements.filter((s) => /bucket_hour >= \$1/.test(s.sql));
    assert.ok(windowed.length >= 5);
    for (const s of windowed) {
      // Without ::timestamptz PostgreSQL raises "could not determine data type
      // of parameter $N".
      assert.match(s.sql, /\$1::timestamptz/);
    }
  });

  it('⛔ the per-user attempt floor is expressed in SQL, not patched up afterwards', async () => {
    const pool = stubPool();
    await getVpnDetections(pool, { hours: 24, now: NOW });
    // ⛔ Scoped to the per-username counts THIS engine builds. vpnAuthStats.js's
    // own query also unnests AND sums, but does so in two separate CTEs over the
    // same filtered set — the correct pattern, and not this file's to police.
    const perUser = pool.statements.filter((s) => /attempts_floor/.test(s.sql));
    assert.equal(perUser.length, 2, 'brute force and targeted account');
    for (const s of perUser) {
      assert.match(s.sql, /unnest\(coalesce\(a\.usernames/);
      assert.match(
        s.sql,
        /CASE WHEN array_length\(a\.usernames, 1\) = 1 THEN a\.event_count ELSE 1 END/,
        'summing event_count under an unnest inflated this fleet\'s failure count 8.2x once already'
      );
    }
    // And the one query that DOES want a real event sum has no unnest at all.
    const profile = pool.statements.filter((s) => /success_events/.test(s.sql) && /sum\(a\.event_count\)/.test(s.sql));
    assert.ok(profile.length >= 1);
    for (const s of profile) assert.doesNotMatch(s.sql, /unnest/);
  });

  it('a device with no device_id is not reported as a firewall with a logging gap', async () => {
    const pool = {
      query(sql) {
        if (/min\(bucket_hour\)/.test(sql)) {
          return Promise.resolve({ rows: [{ first_bucket_at: null, last_bucket_at: null, history_hours: 0, history_days: 0, truncated_rows: 0 }] });
        }
        if (/success_hours/.test(sql)) {
          return Promise.resolve({
            rows: [{ device_id: null, device_name: null, vendor: 'fortinet', success_events: 0, success_hours: 0, failure_events: 5, hours: 2 }],
          });
        }
        return Promise.resolve({ rows: [] });
      },
    };
    const r = await getVpnDetections(pool, { hours: 24, now: NOW });
    assert.equal(r.coverage.reportingGapDevices.length, 0, 'an unmatched sender is not a device');
    assert.equal(r.coverage.unattributedCoverage.length, 1);
  });

  it('the window start is derived from the top of the hour, matching the rollup buckets', () => {
    assert.equal(windowStartFrom(new Date('2026-09-10T03:47:12.000Z'), 24).toISOString(), '2026-09-09T04:00:00.000Z');
    assert.equal(windowStartFrom(new Date('2026-09-10T03:47:12.000Z'), 1).toISOString(), '2026-09-10T03:00:00.000Z');
  });
});

// ── Country spellings must be folded before grouping ────────────────────────
//
// ⛔ REGRESSION PIN. Palo Alto emits ISO alpha-2 ("TH"); FortiOS emits the full
// English name ("Thailand"). Both spellings are live in production and both
// reach SUCCESS rows (measured: fortinet 5 rows "Thailand", paloalto 689 rows
// "TH"). These builders grouped on the RAW column, so one employee
// authenticating through both a FortiGate and a Palo Alto gateway produced:
//
//   severity "high" — authenticated successfully from both TH and Thailand
//   within the same hourly bucket, fromSrcIp == toSrcIp
//
// Same country, same source address, same hour, naming a real person. It was
// latent only because no username currently appears in both vendors' success
// rows; one shared account is all it takes.
describe('country spellings are folded before grouping', () => {
  const { buildCountryChangeDetection, buildNewCountryDetection } = require('../lib/engines/vpnDetections');

  it('⛔ TH and Thailand in the same hour are NOT a country change', () => {
    const rows = [
      successRow('shared.user', '2026-09-09T10:00:00.000Z', 'TH'),
      successRow('shared.user', '2026-09-09T10:00:00.000Z', 'Thailand'),
    ];
    const d = buildCountryChangeDetection({ successRows: rows, baseline: DEEP_BASELINE, windowStart: WINDOW_START });
    assert.equal(d.findings.length, 0, 'one country spelled two ways is one country');
  });

  it('⛔ Thailand is not a NEW country for a user whose history says TH', () => {
    const rows = [
      ...fourDayThaiBaseline('known.user'),
      successRow('known.user', '2026-09-09T10:00:00.000Z', 'Thailand'),
    ];
    const d = buildNewCountryDetection({ successRows: rows, baseline: DEEP_BASELINE, windowStart: WINDOW_START });
    assert.equal(d.findings.length, 0);
  });

  it('a genuinely different country is still a finding', () => {
    const rows = [
      successRow('shared.user', '2026-09-09T10:00:00.000Z', 'TH'),
      successRow('shared.user', '2026-09-09T11:00:00.000Z', 'Singapore'),
    ];
    const d = buildCountryChangeDetection({ successRows: rows, baseline: DEEP_BASELINE, windowStart: WINDOW_START });
    assert.ok(d.findings.length > 0, 'TH -> Singapore is a real change');
  });
});
