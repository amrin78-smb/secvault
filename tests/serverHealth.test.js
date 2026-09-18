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
  getServiceLiveness, volumeFor, volumeKey, BYTES_IN_GB,
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

test('getDatabaseSize reports null and the error, not 0 bytes or an empty list', async () => {
  const r = await getDatabaseSize(failPool);
  assert.equal(r.totalBytes, null);
  assert.match(r.error, /connection refused/);
  // THIS ASSERTION USED TO READ deepEqual(r.tables, []) AND PINNED THE BUG.
  // An empty array renders exactly like "nothing qualified" — the dead-tuple
  // block is drawn only when the array is non-empty — so a failed read was a
  // clean bill of health. The test enforced it.
  assert.equal(r.tables, null, 'a failed read is not an empty list');
  assert.equal(r.deadTuples, null, 'and absence of dead tuples is not an all-clear');
  assert.match(r.tablesError, /connection refused/);
  assert.match(r.deadTuplesError, /connection refused/);
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
  // null / false / '' / [] all convert to 0, which IS finite — so a bare
  // Number.isFinite guard clamped them to 1 MINUTE instead of the 15-minute
  // fallback. The original test covered 99999, -5 and 'nonsense' and omitted
  // precisely the inputs the guard got wrong.
  await getIngestHealth(pool, null);
  await getIngestHealth(pool, '');
  await getIngestHealth(pool, false);
  assert.deepEqual(seen, [1440, 1, 15, 15, 15, 15]);
});

test('getIngestHealth: a row missing keys yields null, never NaN', async () => {
  // The published contract is "null means not measured"; NaN !== null, so a
  // consumer testing `dropped === null` would treat NaN as a measured value.
  const pool = { query: async () => ({ rows: [{}] }) };
  const r = await getIngestHealth(pool, 15);
  assert.equal(r.received, null);
  assert.equal(r.dropped, null);
  assert.equal(r.stored, null);
  assert.equal(r.eventsPerSec, null);
});

test('⛔ the ingest ERROR shape keeps every key the renderer reads', async () => {
  // `flushes` was omitted, and the widget's "collector recorded no flushes"
  // banner is gated on `flushes === 0` — undefined === 0 is false, so a DATABASE
  // failure suppressed the one banner that says ingest is broken.
  const r = await getIngestHealth(failPool, 15);
  assert.equal(r.flushes, 0, 'the banner gate must still fire');
  assert.equal(r.received, null);
  assert.equal(r.dropped, null);
  assert.equal(r.eventsPerSec, null);
  assert.ok(r.error, 'and the reason is carried');
});

test('diskState refuses a non-finite figure', () => {
  // NaN < 20 and NaN < 100 are both FALSE, so a guard testing only null and
  // undefined fell through and returned 'ok' — a GREEN bar for an unmeasured
  // volume, the exact inversion this module exists to prevent.
  assert.equal(diskState({ freeBytes: NaN }), null);
  assert.equal(diskState({ freeBytes: 'abc' }), null);
  assert.equal(diskState({ freeBytes: Infinity }), null);
});

test('volumeKey treats E: and e: as one volume', () => {
  // path.resolve does not normalise a Windows drive letter, so a lowercase
  // drive in .env.local split one volume into two identical rows.
  assert.equal(volumeKey('E:/SecVaultArchive'), volumeKey('e:/SecVaultSpool'));
});

test('getSyslogRetention keeps retentionDays through a database failure', async () => {
  // It is a process.env read with no dependency on the database; dropping it
  // made the page claim it did not know its own configuration during a blip.
  process.env.SYSLOG_RETENTION_DAYS = '30';
  const r = await getSyslogRetention(failPool);
  assert.equal(r.partitions, null);
  assert.equal(r.retentionDays, 30);
  delete process.env.SYSLOG_RETENTION_DAYS;
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
  // ⛔ THE WINDOW WAS 40 CHARACTERS AND THE THING IT FORBIDS IS ROUTINELY
  // LONGER THAN THAT. `count(*)::bigint AS events, max(received_at) AS last`
  // then a newline and FROM is already past it -- so the guard would have
  // watched the exact shape a real regression takes go by. A guard whose reach
  // is shorter than the pattern it bans is a guard that cannot fire.
  assert.doesNotMatch(src, /count\(\s*\*\s*\)[\s\S]{0,600}?FROM\s+syslog_events\b/i);
  // And the window itself is pinned, so a later edit cannot quietly shrink it
  // back: this sample MUST be caught.
  const wouldBeCaught = `SELECT count(*)::bigint AS events,
            max(received_at) AS last_event,
            min(received_at) AS first_event
       FROM syslog_events
      WHERE received_at > now() - interval '1 day'`;
  assert.match(wouldBeCaught, /count\(\s*\*\s*\)[\s\S]{0,600}?FROM\s+syslog_events\b/i);
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

// ── the two functions nothing covered ─────────────────────────────────────

const path = require('node:path');
const { getDiskUsage, getServerHealth } = require('../lib/serverHealth');

test('getDiskUsage reports one row per VOLUME, with every role that uses it', async () => {
  // Two paths on the same drive were two rows with identical byte figures and
  // different role labels, and statfs ran twice on the same volume. React keys
  // stayed distinct so nothing warned.
  const prevSpool = process.env.SYSLOG_SPOOL_DIR;
  const prevArchive = process.env.SYSLOG_ARCHIVE_DIR;
  try {
    process.env.SYSLOG_SPOOL_DIR = path.join(__dirname, '..', 'spool-nonexistent');
    process.env.SYSLOG_ARCHIVE_DIR = path.join(__dirname, '..', 'archive-nonexistent');
    const rows = await getDiskUsage({ installDir: path.join(__dirname, '..') });
    assert.ok(Array.isArray(rows) && rows.length >= 1);
    const volumes = rows.map((r) => r.volume);
    assert.equal(new Set(volumes).size, volumes.length, 'one row per volume');
    const roles = rows.flatMap((r) => r.roles);
    for (const r of ['install', 'syslog spool', 'syslog archive']) {
      assert.ok(roles.includes(r), `${r} must be accounted for somewhere`);
    }
    for (const row of rows) {
      // Either a real figure or an explicit null -- never a fabricated zero.
      assert.ok(row.totalBytes === null || Number.isFinite(row.totalBytes));
      assert.ok(row.freeBytes === null || Number.isFinite(row.freeBytes));
    }
  } finally {
    if (prevSpool === undefined) delete process.env.SYSLOG_SPOOL_DIR; else process.env.SYSLOG_SPOOL_DIR = prevSpool;
    if (prevArchive === undefined) delete process.env.SYSLOG_ARCHIVE_DIR; else process.env.SYSLOG_ARCHIVE_DIR = prevArchive;
  }
});

test('⛔ getServerHealth still answers when the database is unreachable', async () => {
  // The Server tab is the page an operator opens BECAUSE something is wrong. If
  // one failing source could reject the whole thing, the tab would go blank at
  // exactly the moment it is needed -- and a blank page reports nothing at all,
  // which is strictly worse than reporting the failure.
  const pool = { query: async () => { throw new Error('ECONNREFUSED'); } };
  const health = await getServerHealth(pool, { installDir: path.join(__dirname, '..') });
  for (const key of ['disks', 'database', 'retention', 'ingest', 'services', 'process']) {
    assert.ok(key in health, `${key} must still be present`);
  }
  assert.equal(health.database.totalBytes, null, 'never a fabricated 0 bytes');
  assert.match(health.database.error, /ECONNREFUSED/);
  assert.equal(health.retention.partitions, null);
  // The one figure that survives a database failure, because it never needed it.
  assert.ok('retentionDays' in health.retention);
  assert.equal(health.ingest.received, null, 'no events received is not the same as no answer');
  assert.equal(health.ingest.flushes, 0, 'the "collector recorded no flushes" banner is gated on this');
  assert.ok(Array.isArray(health.services));
  for (const svc of health.services) {
    assert.equal(svc.lastSeen, null);
    assert.match(svc.error, /ECONNREFUSED/);
  }
  assert.ok(Number.isFinite(health.process.uptimeSeconds));
});
