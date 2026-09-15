'use strict';
// Pins lib/reports/changeAudit.js — the R8 "Configuration Change Audit" PDF.
//
// ⛔ WHAT THESE TESTS ARE ACTUALLY FOR.
//
// This document is handed to auditors, emailed and archived, and it reports on
// the one table in this product that is guaranteed to contain credentials: a
// firewall configuration. Two things can go wrong, both silently, and both
// produce a page that looks perfectly correct.
//
//   1. A SECRET REACHES THE PAGE. `config_diffs` rows are supposed to arrive
//      already redacted, and on the live fleet they do. That is not a reason to
//      print a value — it is a reason not to READ one. The guarantee here is
//      structural: changedKeysOf() touches `path` and nothing else, so the
//      assembled data object contains no diff value for any renderer to print.
//      The test below feeds an obviously-secret value through the whole pipeline
//      and asserts it appears neither in the data nor in the rendered bytes.
//      It is the most important test in this file.
//
//   2. SILENCE IS REPORTED AS CALM. A firewall whose config collection is
//      failing produces no change records, and on a naive change report becomes
//      the most stable device on the estate. "No diffs recorded" is not "nothing
//      changed", and the failure mode is that nobody notices, because the wrong
//      answer is a reassuring number rather than a crash.
//
// Every other test here is a variant of one of those two.
//
// No database. The stub pool returns canned rows and records every statement it
// was handed, so the window bound and the separation of the (capped) listing
// query from the (uncapped) counting query are asserted as text.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { contentStreams } = require('../lib/reports/pdfCompare');
const {
  NOT_MEASURED_MARK,
  COVERAGE,
  isSecretShapedKey,
  safeFreeText,
  countCell,
  clampDays,
  truncationNote,
  changedKeysOf,
  safeKeyPath,
  UNREADABLE_KEY_MARK,
  detectBulkAcknowledgements,
  reviewLatency,
  coverageStateOf,
  deviceCoverageNote,
  headlineSentence,
  buildChangeAuditData,
  generateChangeAuditPdf,
} = require('../lib/reports/changeAudit');

// ── reading the PDF back ──────────────────────────────────────────────────

/**
 * pdfkit writes every glyph run as a HEX STRING inside a TJ array, so the words
 * are not visible as ASCII anywhere in the file — a naive `buf.includes(secret)`
 * would pass on a document that prints the secret in 40pt on the cover.
 *
 * ⛔ Concatenated with no separator ON PURPOSE. Kerning splits a single word
 * across several tokens; inserting a space would break every phrase assertion
 * below into unmatchable fragments — and, for the redaction test, would let a
 * kerned secret slip past the assertion.
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
// Shaped after the live reference fleet, which genuinely contains all three
// coverage states: firewalls collected from twice a day, one whose most recent
// configuration snapshot is forty days old, and one added today with a single
// snapshot and therefore no comparison at all.

const DEV_BUSY = '11111111-1111-1111-1111-111111111111';
const DEV_QUIET = '22222222-2222-2222-2222-222222222222';
const DEV_STALE = '33333333-3333-3333-3333-333333333333';
const DEV_NEW = '44444444-4444-4444-4444-444444444444';

const NOW = new Date('2026-09-15T00:00:00Z');

// ⛔ The value that must never reach the page. Deliberately shaped like a real
// PAN-OS pre-shared key so that a partial leak (a prefix, a kerned fragment)
// still fails the assertion.
const SECRET_VALUE = 'S3cr3tPreSharedKey-DoNotPrint-9f2b41';
const SECRET_HASH = '$1$abcdefgh$cLEARtextPasswordHashLeak';

function fixture(overrides = {}) {
  return Object.assign({
    devices: [
      { id: DEV_BUSY, name: 'IDC FW', vendor: 'paloalto', mgmt_method: 'api', mgmt_ip: '10.0.0.1', site: 'IDC', active: true, last_collected_at: new Date('2026-09-15T01:50:42Z'), last_rules_collected_at: new Date('2026-09-15T01:50:36Z') },
      { id: DEV_QUIET, name: 'TFM-RN', vendor: 'fortinet', mgmt_method: 'ssh', mgmt_ip: '10.0.0.2', site: 'TFM', active: true, last_collected_at: new Date('2026-09-15T01:53:45Z'), last_rules_collected_at: new Date('2026-09-15T01:53:40Z') },
      // ⛔ THE ROW THIS WHOLE FILE EXISTS FOR. Collection stopped 40 days ago.
      // It has zero change records, and a naive report calls that stable.
      { id: DEV_STALE, name: 'TSR_EKC', vendor: 'fortinet', mgmt_method: 'ssh', mgmt_ip: '10.0.0.3', site: 'TSR', active: true, last_collected_at: new Date('2026-08-25T04:41:43Z'), last_rules_collected_at: null },
      // Added today: one snapshot, nothing to compare it against.
      { id: DEV_NEW, name: 'OKF(F2)', vendor: 'fortinet', mgmt_method: 'ssh', mgmt_ip: '10.0.0.4', site: 'OKF', active: true, last_collected_at: new Date('2026-09-15T01:53:26Z'), last_rules_collected_at: new Date('2026-09-15T01:52:38Z') },
    ],
    snapshots: [
      { device_id: DEV_BUSY, snapshots_total: 186, snapshots_in_window: 60, snapshots_before_window: 126, baselines: 1, oldest_snapshot_at: new Date('2026-07-17T02:36:44Z'), newest_snapshot_at: new Date('2026-09-15T01:50:40Z'), baseline_at: new Date('2026-08-01T00:00:00Z') },
      { device_id: DEV_QUIET, snapshots_total: 143, snapshots_in_window: 58, snapshots_before_window: 85, baselines: 0, oldest_snapshot_at: new Date('2026-07-21T03:53:08Z'), newest_snapshot_at: new Date('2026-09-15T01:53:42Z'), baseline_at: null },
      // Nothing at all inside the window.
      { device_id: DEV_STALE, snapshots_total: 74, snapshots_in_window: 0, snapshots_before_window: 74, baselines: 0, oldest_snapshot_at: new Date('2026-07-21T03:51:24Z'), newest_snapshot_at: new Date('2026-08-06T17:10:33Z'), baseline_at: null },
      // Exactly one snapshot, and none before the window: no comparison exists.
      { device_id: DEV_NEW, snapshots_total: 1, snapshots_in_window: 1, snapshots_before_window: 0, baselines: 0, oldest_snapshot_at: new Date('2026-09-15T01:53:12Z'), newest_snapshot_at: new Date('2026-09-15T01:53:12Z'), baseline_at: null },
    ],
    changeCounts: [
      { device_id: DEV_BUSY, changes: 5, unacknowledged: 2, first_change_at: new Date('2026-09-01T00:00:00Z'), last_change_at: new Date('2026-09-14T07:43:16Z') },
      // DEV_QUIET, DEV_STALE and DEV_NEW deliberately absent.
    ],
    diffs: [
      // ⛔ A CREDENTIAL ROTATION. The path is secret-shaped and the value is a
      // plausible pre-shared key. The report must print the KEY and never the
      // value — including when the stored payload was NOT redacted, which is
      // the case this fixture deliberately constructs.
      {
        id: 'aaaaaaaa-0000-0000-0000-000000000001',
        device_id: DEV_BUSY,
        detected_at: new Date('2026-09-14T07:43:16Z'),
        acknowledged_at: null,
        acknowledged_by: null,
        acknowledged_note: null,
        diff: {
          added: [],
          removed: [],
          modified: [
            { path: 'devices.entry.network.ike.gateway.entry[4].authentication.pre-shared-key.key', old: 'old-key-value', new: SECRET_VALUE },
            { path: 'mgt-config.users.admin.phash', old: 'x', new: SECRET_HASH },
          ],
        },
      },
      // A routine, reviewed change.
      {
        id: 'aaaaaaaa-0000-0000-0000-000000000002',
        device_id: DEV_BUSY,
        detected_at: new Date('2026-09-13T17:10:39Z'),
        acknowledged_at: new Date('2026-09-14T02:25:57Z'),
        acknowledged_by: 'admin',
        acknowledged_note: 'Approved under CR-2291',
        diff: {
          added: [
            { path: 'devices.entry.network.virtual-router.entry[0].routing-table.ip.static-route.entry[7]', value: { nexthop: '10.1.1.1' } },
          ],
          removed: [],
          modified: [],
        },
      },
      // ⛔ AN OLD CHANGE WHOSE SOURCE SNAPSHOTS HAVE BEEN AGED OUT. The change
      // record is append-only and survives; the configurations do not.
      {
        id: 'aaaaaaaa-0000-0000-0000-000000000003',
        device_id: DEV_BUSY,
        detected_at: new Date('2026-08-20T09:00:00Z'),
        acknowledged_at: new Date('2026-08-20T10:00:00Z'),
        acknowledged_by: 'admin',
        acknowledged_note: null,
        diff: { added: [{ path: 'shared.address.WEB-SRV', value: { ip: '1.2.3.4' } }], removed: [], modified: [] },
      },
      // A second unreviewed change, so the unreviewed section has two rows.
      {
        id: 'aaaaaaaa-0000-0000-0000-000000000004',
        device_id: DEV_BUSY,
        detected_at: new Date('2026-09-12T09:00:00Z'),
        acknowledged_at: null,
        acknowledged_by: null,
        acknowledged_note: null,
        diff: { added: [], removed: [{ path: 'shared.service.LEGACY-FTP' }], modified: [] },
      },
      // ⛔ A RECORD CAPPED AT WRITE TIME. diffConfigs() pushes this sentinel in
      // place of the entries it dropped; a capped record is a PARTIAL account of
      // a real change, not a small change.
      {
        id: 'aaaaaaaa-0000-0000-0000-000000000005',
        device_id: DEV_BUSY,
        detected_at: new Date('2026-09-10T09:00:00Z'),
        acknowledged_at: new Date('2026-09-10T09:30:00Z'),
        acknowledged_by: 'admin',
        acknowledged_note: null,
        diff: {
          added: [
            { path: 'shared.address.A1', value: {} },
            { path: '(truncated)', value: 'diff exceeded 500 entries' },
          ],
          removed: [],
          modified: [],
        },
      },
    ],
    // Only the first four listed diffs still have both source snapshots; the
    // August one has none.
    retained: [
      { diff_id: 'aaaaaaaa-0000-0000-0000-000000000001', snapshots_retained: 2 },
      { diff_id: 'aaaaaaaa-0000-0000-0000-000000000002', snapshots_retained: 2 },
      { diff_id: 'aaaaaaaa-0000-0000-0000-000000000003', snapshots_retained: 0 },
      { diff_id: 'aaaaaaaa-0000-0000-0000-000000000004', snapshots_retained: 2 },
      { diff_id: 'aaaaaaaa-0000-0000-0000-000000000005', snapshots_retained: 1 },
    ],
    activity: [
      { actor: 'admin', action: 'acknowledge_config_diff', device_id: DEV_BUSY, detail: 'Config diff aaaaaaaa-0000-0000-0000-000000000002 acknowledged', occurred_at: new Date('2026-09-14T02:25:57Z') },
      // ⛔ An operator note that mentions a credential-shaped word. Withheld
      // fail-closed: SecVault cannot know whether the sentence ends in a value.
      { actor: 'admin', action: 'run_analysis', device_id: DEV_BUSY, detail: `Rotated the IPsec psk to ${SECRET_VALUE}`, occurred_at: new Date('2026-09-13T02:00:00Z') },
    ],
    retainedThrows: null,
    activityThrows: null,
  }, overrides);
}

/**
 * The stub pool. Matches on the statement text and records everything it saw.
 *
 * ⛔ Branch order matters: two statements read `config_diffs` and two read
 * `device_configs`, and the retention check reads BOTH in one statement.
 */
function makePool(f) {
  const seen = [];
  return {
    seen,
    async query(text, params) {
      seen.push({ text, params });
      // The retention check joins both tables — must be matched before either
      // of the single-table branches below.
      if (/LEFT JOIN device_configs/.test(text)) {
        if (f.retainedThrows) throw new Error(f.retainedThrows);
        return { rows: f.retained };
      }
      if (/FROM activity_log/.test(text)) {
        if (f.activityThrows) throw new Error(f.activityThrows);
        return { rows: f.activity };
      }
      if (/FROM device_configs/.test(text)) return { rows: f.snapshots };
      if (/FROM config_diffs/.test(text) && /FILTER/.test(text)) return { rows: f.changeCounts };
      if (/FROM config_diffs/.test(text)) {
        // ⛔ The stub HONOURS the LIMIT, because the whole point of the capping
        // test is that the report keeps its uncapped count when the listing is
        // shortened. A stub that quietly returned every row would make that
        // test pass whatever the code did.
        const limit = params && params[3];
        return { rows: limit ? f.diffs.slice(0, limit) : f.diffs };
      }
      if (/FROM devices/.test(text)) {
        if (params && params[0] && !Array.isArray(params[0])) {
          return { rows: f.devices.filter((d) => d.id === params[0]) };
        }
        return { rows: f.devices };
      }
      throw new Error(`stub pool: unexpected statement\n${text}`);
    },
  };
}

// ══ 1. REDACTION — the most important test in this file ═══════════════════

describe('a secret in a stored change record never reaches the page', () => {
  it('⛔ changedKeysOf() returns the KEY and does not carry the value at all', () => {
    const out = changedKeysOf({
      added: [], removed: [],
      modified: [{ path: 'vpn.ipsec.phase1.psk', old: 'old', new: SECRET_VALUE }],
    }, 6);
    assert.equal(out.modified, 1);
    assert.equal(out.keys[0].path, 'vpn.ipsec.phase1.psk');
    assert.equal(out.keys[0].secretShaped, true);
    // The returned object is searched WHOLE. A `{...entry}` spread anywhere in
    // that function — the easy, natural refactor — fails right here.
    assert.ok(!JSON.stringify(out).includes(SECRET_VALUE));
    assert.ok(!JSON.stringify(out).includes('old'));
  });

  it('⛔ the assembled report data contains no diff value anywhere', async () => {
    const data = await buildChangeAuditData(makePool(fixture()), { now: NOW });
    const serialised = JSON.stringify(data);
    assert.ok(!serialised.includes(SECRET_VALUE), 'a pre-shared key reached the report data');
    assert.ok(!serialised.includes(SECRET_HASH), 'a password hash reached the report data');
  });

  it('⛔ THE RENDERED PDF DOES NOT CONTAIN THE SECRET, but does name the key', async () => {
    const buf = await generateChangeAuditPdf(makePool(fixture()), { now: NOW });
    const text = pdfText(buf);
    // Both the whole value and a leading fragment of it — a kerned leak would
    // still trip the second assertion.
    assert.ok(!says(text, SECRET_VALUE), 'the pre-shared key was printed into the PDF');
    assert.ok(!says(text, 'S3cr3tPreSharedKey'), 'part of the pre-shared key was printed');
    assert.ok(!says(text, SECRET_HASH), 'a password hash was printed into the PDF');
    // ⛔ And the raw bytes, not only the decoded glyph runs — a value drawn via
    // some other pdfkit path would still land in the file.
    assert.ok(!buf.toString('latin1').includes(SECRET_VALUE));

    // The KEY must still be there: withholding the value is worthless if the
    // reader cannot tell that a credential field was touched.
    assert.ok(says(text, 'pre-shared-key'), 'the changed key itself must be named');
    assert.ok(says(text, 'credential field - value never shown'));
    assert.ok(says(text, 'Values are never printed, and that is not an omission'));
  });

  it('⛔ A CORRUPTED "KEY" IS RAW CONFIG TEXT AND IS NEVER EXCERPTED', () => {
    // Found live on the reference fleet while verifying this report: one PAN-OS
    // address-object diff path is ~10 KB of brace-grammar configuration, listing
    // the estate's internal address book, with `phash <redacted>` lines in it.
    // "We only print keys, therefore we are safe" is false on its own.
    const blob = 'tree.address.MGNT-AD-192.168.5.24. {\n    ip-netmask 10.250.8.41/32;\n  }\n'
      + '  SECRET-SUBNET-10.9.9.9 {\n    ip-netmask 10.9.9.9/32;\n  }\n  phash <redacted>\n';
    const out = changedKeysOf({ added: [{ path: blob, value: {} }], removed: [], modified: [] }, 6);

    assert.equal(out.corruptedKeys, 1);
    assert.equal(out.keys[0].corrupted, true);
    assert.equal(out.keys[0].path, UNREADABLE_KEY_MARK);
    // ⛔ Not a truncated excerpt — a fragment still reads as a real, oddly
    // formatted field name, AND puts internal topology into an exported file.
    assert.ok(!JSON.stringify(out).includes('ip-netmask'));
    assert.ok(!JSON.stringify(out).includes('10.9.9.9'));
    // ⛔ And it must NOT be labelled a credential field just because the blob
    // happens to contain the word `phash`. That would be a confident false
    // statement about a field that does not exist.
    assert.equal(out.keys[0].secretShaped, false);
    // The change itself is still counted — only its label is unavailable.
    assert.equal(out.added, 1);

    assert.deepEqual(safeKeyPath('shared.address.WEB'), { path: 'shared.address.WEB', corrupted: false });
    assert.equal(safeKeyPath('a.b { c }').corrupted, true);
    // A merely LONG but well-shaped path is shortened, not placeholder'd.
    const long = safeKeyPath(`devices.entry.${'x'.repeat(300)}.ip`);
    assert.equal(long.corrupted, false);
    assert.ok(long.path.length <= 80);
  });

  it('⛔ an operator note mentioning a credential word is withheld, not dropped', async () => {
    const data = await buildChangeAuditData(makePool(fixture()), { now: NOW });
    const row = data.activity.find((a) => a.action === 'run_analysis');
    assert.ok(row, 'the row itself must survive - only the note is withheld');
    assert.ok(!row.detail.includes(SECRET_VALUE));
    assert.match(row.detail, /note withheld/);
    // Fail-closed and deliberately over-broad: any credential-shaped word.
    assert.match(safeFreeText('the snmp community was changed'), /note withheld/);
    assert.equal(safeFreeText('Approved under CR-2291'), 'Approved under CR-2291');
    // `password_policy` is a real config section, not a credential.
    assert.equal(isSecretShapedKey('system.password_policy'), false);
    assert.equal(isSecretShapedKey('mgt-config.users.admin.phash'), true);
  });
});

// ══ 2. "we could not measure this" ════════════════════════════════════════

describe('a firewall nobody collected from is UNKNOWN, never "no changes"', () => {
  it('⛔ a firewall with no snapshot in the window is not observed and is counted', async () => {
    const data = await buildChangeAuditData(makePool(fixture()), { now: NOW });
    const stale = data.devices.find((d) => d.name === 'TSR_EKC');
    assert.equal(stale.coverage, COVERAGE.NOTHING_IN_WINDOW);
    assert.equal(stale.observed, false);
    assert.equal(stale.comparisons, 0);
    // It has 0 change ROWS in the database. That must not become a result.
    assert.equal(data.totals.devicesUnobserved, 2);
    assert.equal(data.totals.devicesStale, 1);
    assert.equal(data.totals.devicesFirstSnapshotOnly, 1);
    // ⛔ And it is NOT in the "measured quiet" population, which is the number a
    // reader would otherwise take as a clean bill of health.
    assert.equal(data.totals.devicesQuietConfirmed, 1); // only TFM-RN
    assert.match(stale.note, /NOT OBSERVED, not none/);
  });

  it('⛔ one snapshot is not a comparison', () => {
    // The device was added today. There is a configuration on file, which is
    // exactly what makes this seductive: it LOOKS collected.
    assert.equal(
      coverageStateOf({ snapshotsTotal: 1, snapshotsInWindow: 1, snapshotsBeforeWindow: 0 }),
      COVERAGE.FIRST_SNAPSHOT_ONLY
    );
    // One in-window snapshot WITH a prior one outside the window IS a comparison.
    assert.equal(
      coverageStateOf({ snapshotsTotal: 2, snapshotsInWindow: 1, snapshotsBeforeWindow: 1 }),
      COVERAGE.OBSERVED
    );
    assert.equal(
      coverageStateOf({ snapshotsTotal: 0, snapshotsInWindow: 0, snapshotsBeforeWindow: 0 }),
      COVERAGE.NEVER_COLLECTED
    );
  });

  it('⛔ an unobserved firewall renders a dash, never a zero', async () => {
    const buf = await generateChangeAuditPdf(makePool(fixture()), { now: NOW });
    const text = pdfText(buf);
    assert.ok(says(text, 'Firewalls SecVault could not confirm anything about (2)'));
    assert.ok(says(text, 'THEY ARE NOT QUIET FIREWALLS'));
    assert.ok(says(text, 'Firewalls with NO comparison run'));
    // A firewall with no comparison has not had zero changes.
    assert.equal(countCell(0, false), NOT_MEASURED_MARK);
    assert.equal(countCell(0, true), '0');
  });

  it('⛔ AN ALL-CLEAR IS FORBIDDEN WHILE COVERAGE IS INCOMPLETE', () => {
    const incomplete = headlineSentence({
      windowDays: 30, devices: 16, devicesUnobserved: 2, devicesWithoutBaseline: 0,
      changes: 0, unacknowledged: 0, devicesWithChanges: 0,
    });
    assert.ok(!/would have been detected/.test(incomplete));
    assert.match(incomplete, /This is not a complete picture/);
    assert.match(incomplete, /cannot say whether/);

    // The ONLY route to an unqualified sentence: every gap genuinely zero.
    const clean = headlineSentence({
      windowDays: 30, devices: 16, devicesUnobserved: 0, devicesWithoutBaseline: 0,
      changes: 0, unacknowledged: 0, devicesWithChanges: 0,
    });
    assert.match(clean, /a change would have been detected/);
  });

  it('⛔ the page repeats the caveat where an empty change log is printed', async () => {
    const f = fixture({ changeCounts: [], diffs: [], retained: [] });
    const buf = await generateChangeAuditPdf(makePool(f), { now: NOW });
    const text = pdfText(buf);
    assert.ok(says(text, 'this is not a statement that the estate was stable'));
    assert.ok(!says(text, 'no issues'));
  });
});

// ══ 3. review evidence ════════════════════════════════════════════════════

describe('an unreviewed change is the finding, and a reviewed one is distinguishable', () => {
  it('surfaces unreviewed changes and separates them from acknowledged ones', async () => {
    const data = await buildChangeAuditData(makePool(fixture()), { now: NOW });
    assert.equal(data.totals.unacknowledged, 2);
    assert.equal(data.unreviewed.length, 2);
    assert.ok(data.unreviewed.every((c) => c.acknowledgedAt === null));

    const reviewed = data.changes.find((c) => c.id.endsWith('002'));
    assert.equal(reviewed.acknowledgedBy, 'admin');
    assert.equal(reviewed.acknowledgedNote, 'Approved under CR-2291');
  });

  it('⛔ the page marks an unreviewed change as NOT REVIEWED in as many words', async () => {
    const buf = await generateChangeAuditPdf(makePool(fixture()), { now: NOW });
    const text = pdfText(buf);
    assert.ok(says(text, 'NOT REVIEWED'));
    assert.ok(says(text, 'Changes nobody has reviewed (2)'));
    assert.ok(says(text, 'on a change-control audit THIS is the finding')
      || says(text, 'On a change-control audit THIS is the finding'));
    // The acknowledged one is identifiable by its actor and its note.
    assert.ok(says(text, 'Approved under CR-2291'));
    assert.ok(says(text, 'An acknowledgement proves a box was ticked'));
  });

  it('⛔ an unreviewed change is never folded into the review-time average', () => {
    const l = reviewLatency([
      { detectedAt: '2026-09-01T00:00:00Z', acknowledgedAt: '2026-09-01T02:00:00Z' },
      { detectedAt: '2026-09-02T00:00:00Z', acknowledgedAt: '2026-09-02T04:00:00Z' },
      { detectedAt: '2026-09-03T00:00:00Z', acknowledgedAt: null },
      // ⛔ Acknowledged BEFORE detected: a clock disagreement, not a fast review.
      { detectedAt: '2026-09-04T00:00:00Z', acknowledgedAt: '2026-09-03T00:00:00Z' },
    ]);
    assert.equal(l.reviewed, 2);
    assert.equal(l.unreviewed, 1);
    assert.equal(l.clockMismatch, 1);
    assert.equal(l.medianHours, 3);
    // ⛔ null, not 0, when nothing was reviewed: an absent measurement, not a
    // fast one.
    assert.equal(reviewLatency([{ detectedAt: '2026-09-01T00:00:00Z', acknowledgedAt: null }]).medianHours, null);
  });

  it('reports bulk acknowledgements as a timing observation, per actor', () => {
    const base = Date.parse('2026-09-14T02:25:00Z');
    const rows = [];
    for (let i = 0; i < 6; i += 1) {
      rows.push({ acknowledgedBy: 'admin', acknowledgedAt: new Date(base + i * 5000) });
    }
    // A different actor, and far apart: must not join the burst.
    rows.push({ acknowledgedBy: 'alice', acknowledgedAt: new Date(base + 10 * 3600000) });
    const bulk = detectBulkAcknowledgements(rows);
    assert.equal(bulk.bursts, 1);
    assert.equal(bulk.inBursts, 6);
    assert.equal(bulk.largest, 6);
    // Four acknowledgements spread over days are not a burst.
    assert.equal(detectBulkAcknowledgements([
      { acknowledgedBy: 'admin', acknowledgedAt: new Date(base) },
      { acknowledgedBy: 'admin', acknowledgedAt: new Date(base + 86400000) },
    ]).inBursts, 0);
  });
});

// ══ 4. a change record outlives its snapshots ═════════════════════════════

describe('an aged-out snapshot is not an empty diff', () => {
  it('⛔ says "snapshot no longer retained" rather than showing nothing', async () => {
    const data = await buildChangeAuditData(makePool(fixture()), { now: NOW });
    const old = data.changes.find((c) => c.id.endsWith('003'));
    assert.equal(old.snapshotsRetained, 0);
    // The change record itself is intact — that is the whole point.
    assert.equal(old.added, 1);
    assert.equal(data.totals.changesWithLostSnapshots, 1);
    assert.equal(data.totals.changesPartiallyRetained, 1);

    const buf = await generateChangeAuditPdf(makePool(fixture()), { now: NOW });
    const text = pdfText(buf);
    assert.ok(says(text, 'Snapshot no longer retained'));
    assert.ok(says(text, 'A change record outlives the configurations it came from'));
  });

  it('⛔ a failed retention check reports UNKNOWN, never "the snapshots are gone"', async () => {
    const f = fixture({ retainedThrows: 'connection reset' });
    const data = await buildChangeAuditData(makePool(f), { now: NOW });
    assert.ok(data.changes.every((c) => c.snapshotsRetained === null));
    assert.equal(data.totals.changesWithLostSnapshots, 0, 'unknown must not be counted as gone');
    const err = data.sectionErrors.find((e) => e.section === 'Source-snapshot retention');
    assert.ok(err, 'the failure must be a named row in the document, not a log line');
    assert.match(err.message, /NOT claiming/);
  });

  it('⛔ a write-time capped record is marked as PARTIAL, not as a small change', async () => {
    const data = await buildChangeAuditData(makePool(fixture()), { now: NOW });
    const capped = data.changes.find((c) => c.id.endsWith('005'));
    assert.equal(capped.payloadTruncated, true);
    // The sentinel must not be counted as a real changed key.
    assert.equal(capped.added, 1);
    assert.ok(!capped.keys.some((k) => k.path === '(truncated)'));
    assert.equal(data.totals.changesTruncatedPayload, 1);
  });

  it('⛔ an unreadable payload is UNREADABLE, not empty', () => {
    // No added/removed/modified arrays at all.
    const out = changedKeysOf({ something: 'else' }, 6);
    assert.equal(out.payloadUnreadable, true);
    assert.equal(out.total, 0);
    // A payload with the arrays present but empty is genuinely empty, and that
    // is a different claim.
    const real = changedKeysOf({ added: [], removed: [], modified: [] }, 6);
    assert.equal(real.payloadUnreadable, false);
    assert.equal(changedKeysOf(null, 6).payloadUnreadable, true);
    assert.equal(changedKeysOf('oops', 6).payloadUnreadable, true);
  });
});

// ══ 5. baseline drift is a different question ═════════════════════════════

describe('baseline drift is not conflated with consecutive-pull changes', () => {
  it('counts firewalls with no baseline and says what that means', async () => {
    const data = await buildChangeAuditData(makePool(fixture()), { now: NOW });
    assert.equal(data.totals.devicesWithoutBaseline, 3);
    const busy = data.devices.find((d) => d.name === 'IDC FW');
    assert.equal(busy.hasBaseline, true);

    const buf = await generateChangeAuditPdf(makePool(fixture()), { now: NOW });
    const text = pdfText(buf);
    assert.ok(says(text, 'Drift from a baseline is NOT what this report measures'));
    assert.ok(says(text, 'whose comparison target may itself already be drifted'));
  });

  it('a device with no baseline carries the caveat on its own row', () => {
    const note = deviceCoverageNote({
      coverage: COVERAGE.OBSERVED, comparisons: 5, snapshotsInWindow: 6,
      changes: 0, unacknowledged: 0, hasBaseline: false,
    });
    assert.match(note, /measured result, not an absence of data/);
    assert.match(note, /No baseline configuration is designated/);
  });
});

// ══ 6. the queries themselves ═════════════════════════════════════════════

describe('the statements the report issues', () => {
  it('⛔ counts changes with an UNCAPPED query, separate from the capped listing', async () => {
    const pool = makePool(fixture());
    await buildChangeAuditData(pool, { now: NOW, maxChangeRows: 2 });
    const counting = pool.seen.find((s) => /FROM config_diffs/.test(s.text) && /FILTER/.test(s.text));
    const listing = pool.seen.find((s) => /FROM config_diffs/.test(s.text) && /LIMIT/.test(s.text));
    assert.ok(counting && !/LIMIT/.test(counting.text),
      'the headline count must not come from a capped query - a truncated list would deflate it');
    assert.ok(listing && /LIMIT \$4/.test(listing.text));
    // Both bounded by the window, explicitly cast.
    assert.match(counting.text, /detected_at >= \$2::timestamptz/);
    assert.match(listing.text, /detected_at >= \$2::timestamptz/);
  });

  it('⛔ discloses a capped list rather than silently shortening it', async () => {
    const data = await buildChangeAuditData(makePool(fixture()), { now: NOW, maxChangeRows: 2 });
    assert.equal(data.changes.length, 2);
    // The uncapped count is unchanged: 5 real changes exist.
    assert.equal(data.totals.changes, 5);
    assert.match(truncationNote(2, 5, 'changes'), /Showing 2 of 5 changes/);
    assert.equal(truncationNote(5, 5, 'changes'), null);

    const buf = await generateChangeAuditPdf(makePool(fixture()), { now: NOW, maxChangeRows: 2 });
    assert.ok(says(pdfText(buf), 'Showing 2 of 5 changes'));
  });

  it('⛔ a failed review-trail read is reported, never presented as no activity', async () => {
    const f = fixture({ activityThrows: 'permission denied' });
    const data = await buildChangeAuditData(makePool(f), { now: NOW });
    assert.equal(data.activity.length, 0);
    const err = data.sectionErrors.find((e) => e.section === 'Operator review trail');
    assert.ok(err);
    const buf = await generateChangeAuditPdf(makePool(fixture({ activityThrows: 'permission denied' })), { now: NOW });
    assert.ok(says(pdfText(buf), 'Parts of this report could not be gathered'));
  });

  it('clamps the window and the caps, and never to zero', () => {
    assert.equal(clampDays(0, 30), 1);
    assert.equal(clampDays(-9, 30), 1);
    assert.equal(clampDays('nonsense', 30), 30);
    assert.equal(clampDays(90, 30), 90);
  });
});

// ══ 7. the document itself ════════════════════════════════════════════════

describe('the generated document', () => {
  it('⛔ returns a real PDF buffer with more than one page', async () => {
    const buf = await generateChangeAuditPdf(makePool(fixture()), { now: NOW });
    assert.ok(Buffer.isBuffer(buf));
    assert.equal(buf.subarray(0, 4).toString(), '%PDF');
    const pages = (buf.toString('latin1').match(/\/Type\s*\/Page[^s]/g) || []).length;
    assert.ok(pages >= 2, `expected a multi-page document, got ${pages}`);
  });

  it('⛔ does not throw on an empty window, and does not call it clean', async () => {
    const f = fixture({ changeCounts: [], diffs: [], retained: [], activity: [] });
    const buf = await generateChangeAuditPdf(makePool(f), { now: NOW });
    assert.equal(buf.subarray(0, 4).toString(), '%PDF');
    const text = pdfText(buf);
    assert.ok(says(text, 'No operator action was recorded against these firewalls in this window'));
    assert.ok(says(text, 'that is itself a finding'));
  });

  it('⛔ returns null only when a NAMED device does not exist', async () => {
    const missing = await generateChangeAuditPdf(
      makePool(fixture({ devices: [] })),
      { now: NOW, deviceId: '99999999-9999-9999-9999-999999999999' }
    );
    assert.equal(missing, null);
    // A fleet report over an empty inventory is an honest document, not an error.
    const empty = await generateChangeAuditPdf(
      makePool(fixture({ devices: [], snapshots: [], changeCounts: [], diffs: [], retained: [], activity: [] })),
      { now: NOW }
    );
    assert.ok(Buffer.isBuffer(empty));
  });

  it('device scope narrows to one firewall and keeps its own caveats', async () => {
    const data = await buildChangeAuditData(makePool(fixture({ devices: [fixture().devices[2]] })), {
      now: NOW, deviceId: DEV_STALE,
    });
    assert.equal(data.scope, 'device');
    assert.equal(data.device.name, 'TSR_EKC');
    assert.equal(data.totals.devicesUnobserved, 1);
    assert.match(data.headline, /This is not a complete picture/);
  });
});
