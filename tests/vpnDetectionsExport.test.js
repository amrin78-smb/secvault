'use strict';
// tests/vpnDetectionsExport.test.js
//
// Pins lib/engines/vpnDetectionsExport.js — the CSV one VPN detection leaves
// the product as.
//
// ⛔ THE CASE THAT REGRESSES SILENTLY IS NOT A CRASH. Every bug this file
// guards produces a well-formed, plausible, WRONG spreadsheet:
//
//   * `findings` exported and `unverifiable` dropped — a shorter list that
//     looks complete, with no row saying anything is missing.
//   * a sampled unverifiable list exported with no disclosure — the operator
//     works to the bottom of 25 rows and believes there were 25.
//   * a zero-finding export of a BASELINE-GATED detection — reads as an
//     all-clear, which is exactly the claim vpnDetections.js refuses to make.
//   * a null `sourceUsernameBreadth` rendered `0` — "we do not know how many
//     other usernames this address attacked" becoming "it attacked none".
//
// So each of those has its own test, alongside the column-shape and escaping
// ones. Fixtures are hand-built in the SHAPE each builder in
// lib/engines/vpnDetections.js actually emits — the six differ, and a union
// fixture would let a missing column pass.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  renderDetectionCsv,
  exportFilename,
  isExportableDetection,
  columnsFor,
  noteRowsFor,
  DETECTION_COLUMNS,
  numOrBlank,
  boolOrBlank,
  listOrBlank,
  deviceRefs,
  countryTimeline,
  CLASS_FINDING,
  CLASS_UNVERIFIABLE,
  CLASS_NOTE,
} = require('../lib/engines/vpnDetectionsExport');
const { DETECTION_IDS, STATUS } = require('../lib/engines/vpnDetections');

// ── CSV reading, for assertions ──────────────────────────────────────────
//
// Every cell lib/csv.js writes is quoted, which makes a correct parse for
// these documents a simple one — and a hand-rolled reader here is deliberate:
// asserting against a parse means asserting against the VALUES, not against a
// string that happens to contain them.
function parseCsv(csv) {
  const text = csv.replace(/^﻿/, '');
  const lines = text.split('\r\n').filter((l) => l !== '');
  return lines.map((line) => {
    const cells = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i += 1) {
      const ch = line[i];
      if (inQuotes) {
        if (ch === '"' && line[i + 1] === '"') { cur += '"'; i += 1; }
        else if (ch === '"') inQuotes = false;
        else cur += ch;
      } else if (ch === '"') inQuotes = true;
      else if (ch === ',') { cells.push(cur); cur = ''; }
      else cur += ch;
    }
    cells.push(cur);
    return cells;
  });
}

function asObjects(csv) {
  const rows = parseCsv(csv);
  const header = rows[0];
  return rows.slice(1).map((r) => {
    const o = {};
    header.forEach((h, i) => { o[h] = r[i]; });
    return o;
  });
}

function headerOf(csv) {
  return parseCsv(csv)[0];
}

// ── fixtures, one per detection, in that builder's real shape ────────────

const sprayFinding = {
  kind: 'credential_spray',
  srcIp: '203.0.113.9',
  country: 'Bulgaria',
  located: true,
  vendors: ['paloalto'],
  devices: ['HQ-PA'],
  usernames: 908,
  usernamesIsFloor: true,
  failures: 1821,
  hours: 20,
  lastSeenAt: '2026-09-25T04:00:00.000Z',
  severity: 'critical',
  successClaimVerified: true,
  blindDevices: [],
  evidence: '1821 failed VPN authentications from 203.0.113.9',
};

const bruteFinding = {
  kind: 'brute_force',
  username: 'jsmith',
  srcIp: '198.51.100.7',
  country: 'Panama',
  devices: ['TSR-TL'],
  attemptsFloor: 57,
  attemptsIsFloor: true,
  hours: 6,
  firstSeenAt: '2026-09-24T22:00:00.000Z',
  lastSeenAt: '2026-09-25T03:00:00.000Z',
  // ⛔ NULL, on purpose — the breadth read produced no row for this address.
  sourceUsernameBreadth: null,
  severity: 'high',
  successClaimVerified: false,
  blindDevices: [{ deviceId: 'dev-1', deviceName: 'TSR-TL', vendor: 'fortinet' }],
  evidence: 'at least 57 failed authentications for "jsmith"',
};

const targetedFinding = {
  kind: 'account_targeted',
  username: 'admin',
  sources: 31,
  countries: 12,
  attemptsFloor: 44,
  attemptsIsFloor: true,
  hours: 18,
  lastSeenAt: '2026-09-25T05:00:00.000Z',
  severity: 'high',
  evidence: '"admin" failed from 31 distinct source addresses',
};

const newCountryFinding = {
  kind: 'new_country_for_user',
  username: 'achaisiri',
  country: 'India',
  authHours: 2,
  sources: ['10.20.1.5', '10.20.1.6'],
  devices: ['HQ-PA'],
  knownCountries: ['Thailand'],
  baselineDays: 9,
  severity: 'medium',
  caveat: 'baseline-contains-capped-buckets',
  evidence: '"achaisiri" authenticated successfully from India',
};

const countryChangeFinding = {
  kind: 'country_change',
  username: 'bwilson',
  gapHours: 0,
  fromCountry: 'Thailand',
  toCountry: 'Germany',
  fromSrcIp: '203.0.113.1',
  toSrcIp: '203.0.113.2',
  fromAt: new Date('2026-09-25T02:00:00.000Z'),
  toAt: new Date('2026-09-25T02:00:00.000Z'),
  device: 'HQ-PA',
  countries: ['Germany', 'Thailand'],
  timeline: [
    { at: new Date('2026-09-25T02:00:00.000Z'), country: 'Thailand', srcIp: '203.0.113.1' },
    { at: new Date('2026-09-25T02:00:00.000Z'), country: 'Germany', srcIp: '203.0.113.2' },
  ],
  severity: 'high',
  evidence: '"bwilson" authenticated successfully from both Thailand and Germany',
};

const offHoursFinding = {
  kind: 'off_hours_success',
  username: 'nsomchai',
  hourUtc: 19,
  authHours: 1,
  countries: ['Thailand'],
  devices: ['HQ-PA'],
  severity: 'low',
  evidence: '"nsomchai" authenticated successfully at 19:00 UTC',
};

/** A whole detection object, the shape getVpnDetections() puts in `detections`. */
function detection(id, { findings = [], unverifiable = [], unverifiableTotal, status } = {}) {
  return {
    id,
    title: id,
    status: status || STATUS.MEASURED,
    baseline: null,
    findings,
    unverifiable,
    unverifiableTotal: unverifiableTotal === undefined ? unverifiable.length : unverifiableTotal,
    caveats: [],
  };
}

// ────────────────────────────────────────────────────────────────────────

describe('every detection the engine names can be exported, and nothing else', () => {
  it('the id list is the engine\'s own, not a copy', () => {
    // A second list would drift the first time a seventh detection landed, and
    // the copy that drifted would refuse a legitimate export.
    assert.deepEqual(Object.keys(DETECTION_COLUMNS).sort(), [...DETECTION_IDS].sort());
    for (const id of DETECTION_IDS) assert.equal(isExportableDetection(id), true, id);
  });

  it('an unknown detection is refused, never rendered as an empty document', () => {
    assert.equal(isExportableDetection('impossible_travel'), false);
    assert.equal(isExportableDetection(''), false);
    assert.equal(isExportableDetection(null), false);
    assert.equal(columnsFor('impossible_travel'), null);
    const out = renderDetectionCsv({ id: 'impossible_travel', findings: [] });
    assert.equal(out.ok, false);
    assert.equal(out.reason, 'unknown-detection');
    assert.equal(out.csv, undefined, 'a refusal must not carry a document at all');
  });

  it('prototype keys do not resolve to a column set', () => {
    // The same fail-closed guard lib/rbac.js's capabilitiesOf() needed.
    assert.equal(isExportableDetection('constructor'), false);
    assert.equal(isExportableDetection('toString'), false);
  });
});

describe('⛔ columns match what that detection actually emits', () => {
  const envelope = ['detection', 'record_class', 'reason', 'detection_status', 'window_hours', 'severity'];

  it('the envelope leads every detection, in the same order', () => {
    for (const id of DETECTION_IDS) {
      const cols = columnsFor(id).map(([n]) => n);
      assert.deepEqual(cols.slice(0, envelope.length), envelope, id);
    }
  });

  it('no detection declares a column twice', () => {
    for (const id of DETECTION_IDS) {
      const cols = columnsFor(id).map(([n]) => n);
      assert.equal(new Set(cols).size, cols.length, id);
    }
  });

  it('account_targeted carries NO devices, country or success-claim column', () => {
    // buildTargetedAccountDetection() emits none of them. A blank column would
    // say they were looked for on this device and found absent.
    const cols = columnsFor('account_targeted').map(([n]) => n);
    for (const absent of ['devices', 'country', 'success_claim_verified', 'blind_devices']) {
      assert.equal(cols.includes(absent), false, `account_targeted must not carry ${absent}`);
    }
    assert.ok(cols.includes('sources') && cols.includes('countries'));
  });

  it('off_hours_success carries NO timestamp column', () => {
    // The builder groups by (username, hour-of-day) and keeps only the bucket
    // COUNT — the instants are collapsed, so any timestamp would be invented.
    const cols = columnsFor('off_hours_success').map(([n]) => n);
    for (const absent of ['last_seen_at_utc', 'first_seen_at_utc', 'from_at_utc', 'to_at_utc']) {
      assert.equal(cols.includes(absent), false, `off_hours_success must not carry ${absent}`);
    }
    assert.ok(cols.includes('hour_utc'));
  });

  it('country_change carries the pair and the timeline, not one country', () => {
    const cols = columnsFor('country_change').map(([n]) => n);
    assert.ok(cols.includes('from_country') && cols.includes('to_country'));
    assert.ok(cols.includes('timeline'), 'the other observations are what let a reader disagree');
    assert.equal(cols.includes('country'), false);
  });

  it('each detection renders its own fields with real values', () => {
    const cases = [
      ['credential_spray', sprayFinding, { src_ip: '203.0.113.9', usernames: '908', usernames_is_floor: 'yes', vendors: 'paloalto' }],
      ['brute_force', bruteFinding, { username: 'jsmith', attempts_floor: '57', first_seen_at_utc: '2026-09-24T22:00:00.000Z' }],
      ['account_targeted', targetedFinding, { username: 'admin', sources: '31', countries: '12' }],
      ['new_country_for_user', newCountryFinding, { country: 'India', known_countries: 'Thailand', baseline_days: '9', sources: '10.20.1.5; 10.20.1.6' }],
      ['country_change', countryChangeFinding, { gap_hours: '0', from_country: 'Thailand', to_country: 'Germany' }],
      ['off_hours_success', offHoursFinding, { hour_utc: '19', auth_hours: '1', countries: 'Thailand' }],
    ];
    for (const [id, finding, expected] of cases) {
      const out = renderDetectionCsv(detection(id, { findings: [finding] }), { windowHours: 24 });
      assert.equal(out.ok, true, id);
      const [row] = asObjects(out.csv);
      for (const [k, v] of Object.entries(expected)) assert.equal(row[k], v, `${id}.${k}`);
      assert.equal(row.detection, id);
      assert.equal(row.record_class, CLASS_FINDING);
      assert.equal(row.window_hours, '24');
    }
  });

  it('country_change\'s timeline keeps every observation', () => {
    const out = renderDetectionCsv(detection('country_change', { findings: [countryChangeFinding] }));
    const [row] = asObjects(out.csv);
    assert.equal(
      row.timeline,
      '2026-09-25T02:00:00.000Z|Thailand|203.0.113.1; 2026-09-25T02:00:00.000Z|Germany|203.0.113.2'
    );
  });
});

describe('⛔ BOTH arrays are exported — findings alone is a shorter list that looks complete', () => {
  it('unverifiable rows are present, classed apart, and carry their reason', () => {
    const out = renderDetectionCsv(
      detection('brute_force', {
        findings: [{ ...bruteFinding, username: 'verified', successClaimVerified: true, blindDevices: [] }],
        unverifiable: [{ ...bruteFinding, reason: 'no-success-baseline' }],
      }),
      { windowHours: 24 }
    );
    const rows = asObjects(out.csv);
    assert.equal(rows.length, 2);
    assert.equal(rows[0].record_class, CLASS_FINDING);
    assert.equal(rows[0].reason, '', 'a finding is not unverifiable, and says so by being blank');
    assert.equal(rows[1].record_class, CLASS_UNVERIFIABLE);
    assert.equal(rows[1].reason, 'no-success-baseline');
    assert.equal(out.findingCount, 1);
    assert.equal(out.unverifiableListed, 1);
  });

  it('the two arrays share one column set, so a spreadsheet filter works', () => {
    const out = renderDetectionCsv(detection('new_country_for_user', {
      findings: [newCountryFinding],
      unverifiable: [{ ...newCountryFinding, baselineDays: 0, knownCountries: [], reason: 'no-user-baseline' }],
    }));
    const rows = asObjects(out.csv);
    assert.equal(rows[1].reason, 'no-user-baseline');
    // ⛔ "We have never seen this user" is a DIFFERENT statement from "this user
    // has never done this", and the export must not flatten them into a finding.
    assert.equal(rows[1].baseline_days, '0');
    assert.equal(rows[1].known_countries, '');
    assert.equal(rows[1].record_class, CLASS_UNVERIFIABLE);
  });

  it('a detection with an all-unverifiable result still produces every unverifiable row', () => {
    const out = renderDetectionCsv(detection('credential_spray', {
      findings: [],
      unverifiable: [
        { ...sprayFinding, successClaimVerified: false, reason: 'no-success-baseline' },
        { ...sprayFinding, srcIp: '203.0.113.10', successClaimVerified: false, reason: 'no-success-baseline' },
      ],
    }));
    const rows = asObjects(out.csv);
    assert.equal(rows.length, 2);
    assert.equal(out.findingCount, 0);
    assert.ok(rows.every((r) => r.record_class === CLASS_UNVERIFIABLE));
  });
});

describe('⛔ the truncation disclosure — a sampled list must not read as a whole one', () => {
  it('a trailing labelled note row states listed-of-total', () => {
    const unverifiable = Array.from({ length: 25 }, (_, i) => ({
      ...offHoursFinding, username: `u${i}`, reason: 'no-hour-profile',
    }));
    const out = renderDetectionCsv(
      detection('off_hours_success', { unverifiable, unverifiableTotal: 393, status: STATUS.INSUFFICIENT }),
      { windowHours: 24 }
    );
    assert.equal(out.truncated, true);
    assert.equal(out.unverifiableListed, 25);
    assert.equal(out.unverifiableTotal, 393);

    const rows = asObjects(out.csv);
    const notes = rows.filter((r) => r.record_class === CLASS_NOTE);
    const sampled = notes.find((n) => /SAMPLED/.test(n.reason));
    assert.ok(sampled, 'the file itself must say the list was sampled');
    assert.match(sampled.reason, /25 of 393/);
    // ⛔ LABELLED IN THE COLUMN THAT SEPARATES THE ARRAYS, so a consumer
    // filtering record_class == 'finding' never mistakes it for one.
    assert.equal(rows.filter((r) => r.record_class === CLASS_FINDING).length, 0);
    // ⛔ AND IT IS AT THE BOTTOM, never above the header — lib/syslog/logExport.js's
    // rule: a metadata line above the header becomes the header.
    assert.equal(rows[rows.length - 1].record_class, CLASS_NOTE);
    assert.deepEqual(headerOf(out.csv)[0], 'detection');
  });

  it('no sampling note when the whole list is present', () => {
    const out = renderDetectionCsv(detection('brute_force', {
      unverifiable: [{ ...bruteFinding, reason: 'no-success-baseline' }],
      unverifiableTotal: 1,
    }));
    assert.equal(out.truncated, false);
    assert.equal(asObjects(out.csv).some((r) => /SAMPLED/.test(r.reason)), false);
  });

  it('a total below the listed length never fabricates a truncation', () => {
    // Defensive: a malformed total must not invent a disclosure.
    const out = renderDetectionCsv(detection('brute_force', {
      unverifiable: [{ ...bruteFinding, reason: 'x' }, { ...bruteFinding, reason: 'y' }],
      unverifiableTotal: 0,
    }));
    assert.equal(out.truncated, false);
    assert.equal(asObjects(out.csv).filter((r) => r.record_class === CLASS_UNVERIFIABLE).length, 2);
  });

  it('a missing total falls back to the listed length rather than to zero', () => {
    const d = detection('brute_force', { unverifiable: [{ ...bruteFinding, reason: 'x' }] });
    delete d.unverifiableTotal;
    const out = renderDetectionCsv(d);
    assert.equal(out.unverifiableTotal, 1);
    assert.equal(out.truncated, false);
  });
});

describe('⛔ "we could not measure this" — an empty export must never read as an all-clear', () => {
  it('a baseline-gated detection says so on every row AND in a note', () => {
    const out = renderDetectionCsv(
      detection('off_hours_success', { findings: [], unverifiable: [], status: STATUS.INSUFFICIENT }),
      { windowHours: 24 }
    );
    const rows = asObjects(out.csv);
    const note = rows.find((r) => r.record_class === CLASS_NOTE);
    assert.ok(note, 'zero rows alone is a false all-clear');
    assert.match(note.reason, /DID NOT RUN/);
    assert.match(note.reason, /NOT an all-clear/);
    assert.equal(note.detection_status, STATUS.INSUFFICIENT);
    assert.equal(out.status, STATUS.INSUFFICIENT);
  });

  it('no_data is its own state and is stated, not rendered as measured-and-empty', () => {
    const out = renderDetectionCsv(detection('new_country_for_user', { status: STATUS.NO_DATA }));
    const note = asObjects(out.csv).find((r) => r.record_class === CLASS_NOTE);
    assert.match(note.reason, /no_data/);
  });

  it('a MEASURED detection with nothing found gets NO did-not-run note', () => {
    // The other half of the rule: a real all-clear must not be muddied either,
    // or the note stops meaning anything.
    const out = renderDetectionCsv(detection('country_change', { findings: [] }));
    const rows = asObjects(out.csv);
    assert.deepEqual(rows, [], 'header only');
    assert.equal(out.rowCount, 0);
    assert.deepEqual(noteRowsFor(detection('country_change', { findings: [] })), []);
  });

  it('the header is emitted even with zero data rows', () => {
    // csvDocument's own rule: "the export is broken" and "nothing matched" must
    // not look the same.
    const out = renderDetectionCsv(detection('credential_spray', { findings: [] }));
    const header = headerOf(out.csv);
    assert.ok(header.includes('src_ip'));
    assert.ok(header.includes('detection_status'));
    assert.equal(out.rowCount, 0);
  });

  it('detection_status appears on every row, not only in the note', () => {
    const out = renderDetectionCsv(detection('off_hours_success', {
      unverifiable: [{ ...offHoursFinding, reason: 'no-hour-profile' }],
      status: STATUS.INSUFFICIENT,
    }));
    for (const r of asObjects(out.csv)) assert.equal(r.detection_status, STATUS.INSUFFICIENT);
  });
});

describe('⛔ an unknown value is BLANK, never a confident zero or a false', () => {
  it('a null count renders empty, not 0', () => {
    // sourceUsernameBreadth is null when no breadth row exists for the address.
    // `0` would say the source attacked no other username — the opposite claim.
    const out = renderDetectionCsv(detection('brute_force', { findings: [bruteFinding] }));
    const [row] = asObjects(out.csv);
    assert.equal(row.source_username_breadth, '');
    assert.equal(numOrBlank(null), '');
    assert.equal(numOrBlank(undefined), '');
    assert.equal(numOrBlank(0), '0', 'a real zero is still a zero');
  });

  it('a missing boolean renders empty, not "no"', () => {
    assert.equal(boolOrBlank(undefined), '');
    assert.equal(boolOrBlank(null), '');
    assert.equal(boolOrBlank(false), 'no');
    assert.equal(boolOrBlank(true), 'yes');
  });

  it('an unparseable timestamp renders empty rather than an epoch', () => {
    const out = renderDetectionCsv(detection('brute_force', {
      findings: [{ ...bruteFinding, lastSeenAt: 'not-a-date', firstSeenAt: null }],
    }));
    const [row] = asObjects(out.csv);
    assert.equal(row.last_seen_at_utc, '');
    assert.equal(row.first_seen_at_utc, '');
  });

  it('timestamps are UTC with the Z, whatever the input type', () => {
    const out = renderDetectionCsv(detection('country_change', { findings: [countryChangeFinding] }));
    const [row] = asObjects(out.csv);
    assert.equal(row.from_at_utc, '2026-09-25T02:00:00.000Z');
  });

  it('lists join on a semicolon and an empty list stays empty', () => {
    assert.equal(listOrBlank(['a', 'b']), 'a; b');
    assert.equal(listOrBlank([]), '');
    assert.equal(listOrBlank(null), '');
    assert.equal(deviceRefs([{ deviceId: 'id-only', deviceName: null }]), 'id-only');
    assert.equal(deviceRefs([]), '');
    assert.equal(countryTimeline([]), '');
  });
});

describe('⛔ CSV escaping — the values here are attacker-chosen', () => {
  // A username arrives from whoever sent the authentication attempt. It is the
  // single most attacker-controlled string in this file.
  const hostile = '=cmd|\' /C calc\'!A0,"quoted",user';

  it('a username with a comma, a quote and a leading = survives and cannot execute', () => {
    const out = renderDetectionCsv(detection('brute_force', {
      findings: [{ ...bruteFinding, username: hostile }],
    }));
    const [row] = asObjects(out.csv);
    // ⛔ NEUTRALISED: the leading apostrophe is what stops Excel evaluating it.
    assert.equal(row.username, `'${hostile}`);
    // ⛔ AND THE ROW DID NOT SHIFT. The comma inside the value must not have
    // become a column boundary — a shifted row silently mislabels every
    // column after it, which on an evidence export means attributing one
    // person's activity to another's field.
    assert.equal(row.src_ip, '198.51.100.7');
    assert.equal(row.attempts_floor, '57');
    assert.equal(parseCsv(out.csv)[1].length, headerOf(out.csv).length);
  });

  it('every formula lead character is neutralised, including behind whitespace', () => {
    for (const lead of ['=', '+', '-', '@', ' \t=', '  @']) {
      const out = renderDetectionCsv(detection('account_targeted', {
        findings: [{ ...targetedFinding, username: `${lead}SUM(A1)` }],
      }));
      const [row] = asObjects(out.csv);
      assert.equal(row.username.startsWith("'"), true, `not neutralised: ${JSON.stringify(lead)}`);
    }
  });

  it('a newline inside a value cannot break the record into two', () => {
    const out = renderDetectionCsv(detection('credential_spray', {
      findings: [{ ...sprayFinding, evidence: 'line one\nline two\r\nline three' }],
    }));
    assert.equal(asObjects(out.csv).length, 1, 'one finding must stay one record');
    assert.equal(asObjects(out.csv)[0].evidence, 'line one line two line three');
  });

  it('a hostile value in an ARRAY field is escaped too', () => {
    const out = renderDetectionCsv(detection('new_country_for_user', {
      findings: [{ ...newCountryFinding, devices: ['=HYPERLINK("x")', 'HQ-PA'] }],
    }));
    const [row] = asObjects(out.csv);
    assert.equal(row.devices, '\'=HYPERLINK("x"); HQ-PA');
  });

  it('the document is CRLF-terminated and carries a BOM by default', () => {
    // Excel ignores charset=utf-8 on a downloaded file, and these rows carry
    // Thai usernames — mojibake in an identifier is corruption, not cosmetics.
    const out = renderDetectionCsv(detection('off_hours_success', {
      findings: [{ ...offHoursFinding, username: 'สมชาย' }],
    }));
    assert.equal(out.csv.charCodeAt(0), 0xfeff);
    assert.ok(out.csv.includes('\r\n'));
    assert.ok(out.csv.includes('สมชาย'));
    const plain = renderDetectionCsv(detection('off_hours_success', { findings: [offHoursFinding] }), { bom: false });
    assert.notEqual(plain.csv.charCodeAt(0), 0xfeff);
  });
});

describe('the filename says which detection and which window', () => {
  it('carries the id, the window and a UTC stamp', () => {
    const name = exportFilename({
      detectionId: 'credential_spray',
      windowHours: 24,
      generatedAt: '2026-09-25T06:07:08.000Z',
    });
    assert.equal(name, 'secvault-vpn-detection-credential_spray-24h-20260925-0607Z.csv');
  });

  it('a hostile detection id cannot escape the filename', () => {
    const name = exportFilename({ detectionId: '../../etc/passwd', windowHours: 24 });
    assert.equal(/[\\/]/.test(name), false);
    assert.ok(name.endsWith('.csv'));
  });

  it('an absent window is omitted rather than guessed at', () => {
    const name = exportFilename({ detectionId: 'brute_force', generatedAt: '2026-09-25T00:00:00.000Z' });
    assert.equal(name, 'secvault-vpn-detection-brute_force-20260925-0000Z.csv');
  });
});

describe('the summary the route audits and headers from', () => {
  it('rowCount counts data rows including notes, never the header', () => {
    const out = renderDetectionCsv(
      detection('off_hours_success', {
        findings: [],
        unverifiable: [{ ...offHoursFinding, reason: 'no-hour-profile' }],
        unverifiableTotal: 393,
        status: STATUS.INSUFFICIENT,
      })
    );
    // 1 unverifiable + 2 notes (did-not-run, sampled)
    assert.equal(out.rowCount, 3);
    assert.equal(parseCsv(out.csv).length, out.rowCount + 1);
    assert.equal(out.notes.length, 2);
  });

  it('reports the columns it actually wrote', () => {
    const out = renderDetectionCsv(detection('account_targeted', { findings: [targetedFinding] }));
    assert.deepEqual(out.columns, headerOf(out.csv));
  });

  it('a non-array findings or unverifiable value is tolerated, not trusted', () => {
    const out = renderDetectionCsv({
      id: 'brute_force', status: STATUS.MEASURED, findings: null, unverifiable: undefined,
    });
    assert.equal(out.ok, true);
    assert.equal(out.findingCount, 0);
    assert.equal(out.unverifiableListed, 0);
    assert.ok(headerOf(out.csv).includes('attempts_floor'));
  });
});
