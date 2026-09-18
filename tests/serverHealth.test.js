// tests/serverHealth.test.js
//
// ⛔ THE RULE THIS FILE EXISTS FOR: on a server-health page, "0 GB free" is an
// emergency and "we could not read the volume" is a gap in our own
// instrumentation. If a failed read is allowed to become a zero, the two render
// identically and the more alarming one wins. Every case below is a
// could-not-measure case.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const {
  diskState, getDatabaseSize, getSyslogRetention, getIngestHealth,
  getServiceLiveness, volumeFor, BYTES_IN_GB,
} = require('../lib/serverHealth');

const GB = BYTES_IN_GB;

// ── diskState ───────────────────────────────────────────────────────────────

test('diskState returns null when free space is unknown — never ok', () => {
  assert.equal(diskState(null), null);
  assert.equal(diskState({}), null);
  assert.equal(diskState({ freeBytes: null }), null);
  assert.equal(diskState({ freeBytes: undefined }), null);
});

test('diskState thresholds on FREE SPACE, not on percent used', () => {
  // ⛔ A 2 TB volume at 90% still has 200 GB; a 100 GB volume at 90% has 10, and
  // this product writes ~31 GB/day of raw syslog. Percentage alone would call
  // the dangerous one healthy.
  const bigNearlyFull = { totalBytes: 2000 * GB, freeBytes: 200 * GB, usedPct: 90 };
  const smallNearlyFull = { totalBytes: 100 * GB, freeBytes: 10 * GB, usedPct: 90 };
  assert.equal(diskState(bigNearlyFull), 'ok', 'same percentage, plenty of room');
  assert.equal(diskState(smallNearlyFull), 'critical', 'same percentage, days from full');
});

test('diskState bands', () => {
  assert.equal(diskState({ freeBytes: 500 * GB }), 'ok');
  assert.equal(diskState({ freeBytes: 99 * GB }), 'warning');
  assert.equal(diskState({ freeBytes: 19 * GB }), 'critical');
  assert.equal(diskState({ freeBytes: 0 }), 'critical', 'a MEASURED zero is critical, not unknown');
});

// ── volumeFor ───────────────────────────────────────────────────────────────

test('volumeFor reports nulls and a reason for an unreadable path, never zeros', async () => {
  const v = await volumeFor('Z:/definitely/not/a/real/path/on/this/box');
  assert.equal(v.totalBytes, null);
  assert.equal(v.freeBytes, null);
  assert.ok(v.error, 'the reason travels with the failure');
  assert.equal(diskState(v), null, 'and it must not resolve to a state');
});

test('volumeFor returns null for a missing path argument', async () => {
  assert.equal(await volumeFor(''), null);
  assert.equal(await volumeFor(null), null);
});

// ── database / retention / ingest, against stubs ────────────────────────────

const failPool = { query: async () => { throw new Error('connection refused'); } };

test('getDatabaseSize reports null and the error, not 0 bytes', async () => {
  const r = await getDatabaseSize(failPool);
  assert.equal(r.totalBytes, null);
  assert.match(r.error, /connection refused/);
  assert.deepEqual(r.tables, []);
});

test('getSyslogRetention reports nulls when the catalogue cannot be read', async () => {
  const r = await getSyslogRetention(failPool);
  assert.equal(r.partitions, null);
  assert.equal(r.oldestDay, null);
  assert.ok(r.error);
});

test('⛔ getIngestHealth: NO FLUSHES is not ZERO DROPS', async () => {
  // An absent collector would otherwise render as a clean ingest — the most
  // reassuring possible way to show that nothing is being collected at all.
  const emptyPool = {
    query: async () => ({
      rows: [{ received: null, stored: null, dropped: null, backlog: null, last_flush: null, flushes: 0 }],
    }),
  };
  const r = await getIngestHealth(emptyPool, 15);
  assert.equal(r.received, null, 'not 0');
  assert.equal(r.dropped, null, 'not 0 — this is the dangerous one');
  assert.equal(r.eventsPerSec, null);
  assert.equal(r.flushes, 0, 'the flush COUNT is a real measured zero and stays 0');
});

test('getIngestHealth computes a rate only from a real count', async () => {
  const pool = {
    query: async () => ({
      rows: [{ received: '900', stored: '900', dropped: '0', backlog: 0, last_flush: new Date(), flushes: 30 }],
    }),
  };
  const r = await getIngestHealth(pool, 15);
  assert.equal(r.received, 900);
  assert.equal(r.dropped, 0, 'a MEASURED zero is 0, not null');
  assert.equal(r.eventsPerSec, 1, '900 events over 15 minutes');
});

test('getIngestHealth clamps the window rather than trusting the caller', async () => {
  const seen = [];
  const pool = { query: async (_sql, params) => { seen.push(params[0]); return { rows: [{}] }; } };
  await getIngestHealth(pool, 99999);
  await getIngestHealth(pool, -5);
  await getIngestHealth(pool, 'nonsense');
  assert.deepEqual(seen, [1440, 1, 15]);
});

test('⛔ getServiceLiveness: never-run and broken are different answers', async () => {
  const neverPool = { query: async () => ({ rows: [{ at: null }] }) };
  const [engine] = await getServiceLiveness(neverPool);
  assert.equal(engine.lastSeen, null);
  assert.equal(engine.ageSeconds, null);
  assert.ok(!engine.error, 'a fresh install has never run a feed sync; that is not a fault');

  const [broken] = await getServiceLiveness(failPool);
  assert.equal(broken.ageSeconds, null);
  assert.ok(broken.error, 'an unreadable table IS reported as an error');
});

test('getServiceLiveness converts a timestamp into an age', async () => {
  const at = new Date(Date.now() - 120000);
  const pool = { query: async () => ({ rows: [{ at }] }) };
  const [s] = await getServiceLiveness(pool);
  assert.ok(s.ageSeconds >= 119 && s.ageSeconds <= 121, `expected ~120s, got ${s.ageSeconds}`);
});

// ── source-shape guards ─────────────────────────────────────────────────────

/**
 * Source with COMMENTS REMOVED.
 *
 * ⛔ WITHOUT THIS, BOTH GUARDS BELOW FAILED ON THE PROSE THAT WARNS AGAINST THE
 * VERY THING THEY FORBID. serverHealth.js explains why it does not run a
 * count(*) over syslog_events and why it does not spawn a process, and a naive
 * scan matched those explanations. A source-shape test that cannot tell code
 * from a comment punishes documentation.
 *
 * ⛔ LINE ENDINGS ARE NORMALISED FIRST — the trap tests/backupScripts.test.js
 * already records: "." does not match a carriage return, so on a CRLF checkout
 * the stripper silently does nothing and the guard passes for the wrong reason.
 */
function codeOnly(src) {
  return src
    .replace(/\r\n/g, '\n')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .map((line) => line.replace(/\/\/.*$/, ''))
    .join('\n');
}

function healthSource() {
  const fs = require('node:fs');
  const path = require('node:path');
  return codeOnly(fs.readFileSync(path.join(__dirname, '..', 'lib', 'serverHealth.js'), 'utf8'));
}

test('the comment stripper actually strips — otherwise both guards pass for free', () => {
  // A guard that cannot fail is worse than no guard.
  assert.equal(codeOnly('a\n// count(*) FROM syslog_events\nb').includes('count(*)'), false);
  assert.equal(codeOnly('a\r\n// spawn\r\nb').includes('spawn'), false, 'CRLF must be handled');
  assert.equal(codeOnly('/* spawn */\nreal()').includes('spawn'), false, 'block comments too');
  assert.ok(codeOnly('const spawn = 1; // note').includes('spawn'), 'real code survives');
});

test('⛔ server health never counts rows in syslog_events', () => {
  // Retention comes from the partition CATALOGUE: count(*) over that table is a
  // full scan of ~28M rows per day of retention, on a page that renders often.
  const src = healthSource();
  assert.doesNotMatch(src, /count\(\*\)[\s\S]{0,40}FROM\s+syslog_events\b/i);
  assert.match(src, /pg_tables/, 'partitions come from the catalogue');
});

test('⛔ server health never shells out to read service state', () => {
  const src = healthSource();
  for (const forbidden of ['child_process', 'execSync', 'spawn', 'sc.exe', 'Get-Service']) {
    assert.ok(
      !src.includes(forbidden),
      `must not use ${forbidden} — NSSM reports a crash-looping process as Running anyway, so the service state would be LESS truthful than the evidence each service writes`
    );
  }
});
