'use strict';
// tests/alertTypeRegistry.test.js
//
// ⛔ THREE LISTS DEFINE THE ALERT VOCABULARY AND NOTHING KEPT THEM IN STEP.
//
//   lib/engines/notificationDispatch.js  what the job actually dispatches
//   lib/notificationChannels.js          what the API will accept and persist
//   components/settings/NotificationsPanel.js  what the UI offers
//
// They disagreed in both directions. `ingest_drop` was implemented in the
// engine and offered in the UI but missing from the API's list — so saving a
// channel subscribed to it returned 400 and the alert was structurally
// undeliverable, by anyone, for ever. Fully built, visibly advertised, dead.
// `compliance_report` is the mirror image: accepted and offered, and correctly
// absent from the dispatch loop because it is schedule-driven.
//
// ⛔ THE RELATIONSHIP IS NOT EQUALITY, so this file pins the actual rules
// rather than asserting three identical arrays — an equality test would have
// forced compliance_report into the dispatch loop, where it would be skipped
// for ever with nothing surfaced.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { ALERT_TYPES: API_TYPES } = require('../lib/notificationChannels');
const { ALERT_TYPES: DISPATCH_TYPES } = require('../lib/engines/notificationDispatch');

// The panel is a client component (JSX), so it is read as text rather than
// required — the same approach tests/segmentation.test.js takes.
function panelTypes() {
  const src = fs.readFileSync(
    path.join(__dirname, '..', 'components', 'settings', 'NotificationsPanel.js'),
    'utf8'
  ).replace(/\r\n/g, '\n');
  const m = /const ALERT_TYPES = \[([\s\S]*?)\]/.exec(src);
  assert.ok(m, 'NotificationsPanel must declare an ALERT_TYPES array');
  return [...m[1].matchAll(/'([a-z_]+)'/g)].map((x) => x[1]);
}

describe('the alert-type registries agree where they must', () => {
  const UI = panelTypes();

  it('found all three lists, non-empty', () => {
    // A test whose inputs silently became empty would pass every assertion
    // below while proving nothing.
    assert.ok(API_TYPES.length >= 4, `api list: ${API_TYPES.length}`);
    assert.ok(DISPATCH_TYPES.length >= 4, `dispatch list: ${DISPATCH_TYPES.length}`);
    assert.ok(UI.length >= 4, `ui list: ${UI.length}`);
  });

  it('⛔ every DISPATCHABLE type can be persisted by the API', () => {
    // This is the rule ingest_drop broke. The engine will happily build the
    // alert; if the API refuses to store a subscription to it, no channel can
    // ever receive it and nothing anywhere reports that.
    const undeliverable = DISPATCH_TYPES.filter((t) => !API_TYPES.includes(t));
    assert.deepEqual(
      undeliverable,
      [],
      'dispatched but not persistable — the alert is built and cannot reach a channel'
    );
  });

  it('⛔ every DISPATCHABLE type is offered in the UI', () => {
    const hidden = DISPATCH_TYPES.filter((t) => !UI.includes(t));
    assert.deepEqual(hidden, [], 'dispatched but never offered — nobody can subscribe');
  });

  it('every type the UI offers is one the API accepts', () => {
    // The reverse of the ingest_drop bug: a checkbox whose save returns 400.
    const rejected = UI.filter((t) => !API_TYPES.includes(t));
    assert.deepEqual(rejected, [], 'offered in Settings but rejected on save');
  });

  it('a type the API accepts but does NOT dispatch must be schedule-driven', () => {
    // compliance_report is the only legitimate member of this set: it is
    // delivered by complianceReport.js on a monthly job, not by the dispatch
    // loop. Anything else here is an alert nobody will ever send.
    const notDispatched = API_TYPES.filter((t) => !DISPATCH_TYPES.includes(t));
    assert.deepEqual(
      notDispatched,
      ['compliance_report'],
      'accepted but never dispatched — either wire it up or stop offering it'
    );
  });

  it('⛔ ingest_drop specifically is now deliverable end to end', () => {
    // The regression this file was written for. Named explicitly so a future
    // edit that drops it from one list fails with the reason, not just a diff.
    for (const [where, list] of [['api', API_TYPES], ['dispatch', DISPATCH_TYPES], ['ui', UI]]) {
      assert.ok(list.includes('ingest_drop'), `ingest_drop missing from the ${where} list`);
    }
  });
});

describe('⛔ a deviceless alert can actually be logged', () => {
  const schema = fs.readFileSync(path.join(__dirname, '..', 'lib', 'schema.sql'), 'utf8')
    .replace(/\r\n/g, '\n');

  it('notification_dispatch_log.device_id is nullable', () => {
    // fetchOpenIngestDrop returns deviceId: null on purpose — a full buffer has
    // no culprit device. Against NOT NULL the claim INSERT throws.
    const block = schema.slice(
      schema.indexOf('CREATE TABLE IF NOT EXISTS notification_dispatch_log'),
      schema.indexOf('UNIQUE (alert_type, natural_key)')
    );
    assert.ok(block.length > 50, 'the table definition must be locatable');
    assert.doesNotMatch(block, /device_id UUID NOT NULL/);
  });

  it('and already-deployed servers get the ALTER, not just fresh installs', () => {
    // CREATE TABLE IF NOT EXISTS guards creation only — CLAUDE.md's rule. On
    // every existing server the old NOT NULL survives without this line, so the
    // alert works on a new install and crashes the job on the fleet.
    assert.match(
      schema,
      /ALTER TABLE notification_dispatch_log ALTER COLUMN device_id DROP NOT NULL;/
    );
  });
});

describe('⛔ syslog_ingest_stats is bounded', () => {
  const { trimIngestStats, INGEST_STATS_MIN_DAYS } = require('../lib/syslog/rollups');

  it('the floor covers the window the alert actually reads', () => {
    // fetchOpenIngestDrop looks back 48h; getIngestHealth accepts up to 24h.
    // Trim below that and the alert cannot see the incident it reports on.
    assert.ok(INGEST_STATS_MIN_DAYS >= 3, `floor is ${INGEST_STATS_MIN_DAYS} days`);
  });

  it('a shorter configured retention cannot breach the floor', async () => {
    const seen = [];
    const pool = { query: async (sql, params) => { seen.push({ sql, params }); return { rowCount: 0 }; } };
    const r = await trimIngestStats(pool, 1);
    assert.equal(r.keepDays, INGEST_STATS_MIN_DAYS, 'the floor must win over the config');
    assert.equal(seen[0].params[0], INGEST_STATS_MIN_DAYS);
    assert.match(seen[0].sql, /recorded_at </, 'this table keys on recorded_at, not bucket_hour');
  });

  it('never throws — housekeeping must not fail the maintenance pass', async () => {
    const pool = { query: async () => { throw new Error('boom'); } };
    const r = await trimIngestStats(pool, 30);
    assert.equal(r.deleted, null, 'a failed delete is null, never a fabricated 0');
    assert.match(r.error, /boom/);
  });
});
