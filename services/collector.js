// services/collector.js
// SecVault-Collector — syslog listener (Phase 8a, added 2026-09-08).
//
// CommonJS ONLY — NSSM launches this as plain `node services\collector.js`,
// not through Next.js's bundler.
//
// Replaces ManageEngine Firewall Analyzer on this same host. Measured live
// load before FWA was removed: ~1,083 datagrams/sec sustained (~93M/day) from
// 27 devices.
//
// ── DURABILITY: spool to disk BEFORE the database ─────────────────────────
// CLAUDE.md's Reliability Rules require "durable write-to-disk before DB
// insert, replay on restart" for exactly this component. The cycle is:
//
//   datagram -> in-memory buffer
//   every FLUSH_MS: buffer -> spool file (fsync'd, .ready) -> parse ->
//                   batch INSERT -> only then delete the spool file
//   on startup:     any leftover .ready files are replayed first
//
// The spool file is deleted ONLY after a successful insert. A crash between
// write and insert costs a duplicate replay, never a lost event — and for
// firewall logs, losing evidence is far worse than storing it twice.
//
// ⛔ WHAT THIS SERVICE MUST NEVER DO: pretend it kept up. If the buffer
// overflows, `dropped` is counted and reported, because a collector that
// silently loses datagrams under load looks exactly like a quiet network.
// That is the same failed-read-as-a-fact rule as hit_count, applied to
// ingest.

'use strict';

const dgram = require('dgram');
const net = require('net');
const fs = require('fs');
const path = require('path');

// --- .env.local loader (same reasoning as engine-worker.js) ----------------
function loadEnvLocal() {
  const envPath = path.join(__dirname, '..', '.env.local');
  try {
    const content = fs.readFileSync(envPath, 'utf8');
    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      const eq = line.indexOf('=');
      if (eq === -1) continue;
      const key = line.slice(0, eq).trim();
      let value = line.slice(eq + 1).trim();
      if ((value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      } else {
        // ⛔ Strip an UNQUOTED trailing comment. .env.local.example documents
        // most settings on their own line, but one used an inline '# ...' and
        // the whole comment was read AS the value: SYSLOG_ARCHIVE_DIR became
        // '# blank = <install dir>\\archive', which is truthy, so the sane
        // default never engaged and every archive write failed with ENOENT --
        // silently, every 2 seconds, while ~89% of raw lines exist NOWHERE
        // else because SYSLOG_RAW_MESSAGE=security drops them from the DB.
        // Fixing only the one line would leave the trap armed for the next
        // setting someone documents inline.
        const hash = value.indexOf('#');
        if (hash !== -1) value = value.slice(0, hash).trim();
      }
      if (!(key in process.env)) process.env[key] = value;
    }
  } catch (err) {
    if (err.code !== 'ENOENT') {
      console.error(`[collector] could not read .env.local: ${err.message}`);
    }
  }
}
loadEnvLocal();

const { pool } = require('../lib/db');
const { parseSyslogLine } = require('../lib/syslog/syslogParser');
const { parseVendorPayload } = require('../lib/syslog/vendorParsers');
const { buildEvent } = require('../lib/syslog/eventShape');
const archive = require('../lib/syslog/archive');
const store = require('../lib/syslog/eventStore');
const { parsePortList } = require('../lib/syslog/collectorConfig');
const { runRollupMaintenance, trimDetailRollups, refreshThreatRollup } = require('../lib/syslog/rollups');

// --- configuration ---------------------------------------------------------
function intEnv(name, def, min, max) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  const n = Number(raw);
  if (!Number.isFinite(n)) {
    console.warn(`[collector] ${name}="${raw}" is not a number - using ${def}`);
    return def;
  }
  const t = Math.trunc(n);
  if ((min !== undefined && t < min) || (max !== undefined && t > max)) {
    console.warn(`[collector] ${name}=${t} out of range - using ${def}`);
    return def;
  }
  return t;
}

// A LIST, not a single port. Firewall Analyzer listened on 514 AND 1514 and
// most of this fleet was configured to 1514; binding only 514 left the
// collector receiving ~7.5/sec where FWA had seen ~1,373/sec, with no error
// anywhere -- the OS discards datagrams sent to an unbound UDP port silently.
const UDP_PORTS = parsePortList(process.env.SYSLOG_UDP_PORT, [514, 1514]);
const TCP_PORTS = parsePortList(process.env.SYSLOG_TCP_PORT, [514, 1514]);
const FLUSH_MS      = intEnv('SYSLOG_FLUSH_MS', 2000, 250, 60000);
const MAX_BUFFER    = intEnv('SYSLOG_MAX_BUFFER', 200000, 1000, 5000000);
// 30, not 7. Dropping the raw line for ordinary allowed traffic (see
// SYSLOG_RAW_MESSAGE below) took the row from 1,122 bytes to 367, which is
// what makes a 30-day window affordable: ~37 GB/day, ~1.1 TB for 30 days.
const RETENTION_DAYS = intEnv('SYSLOG_RETENTION_DAYS', 30, 1, 3650);
// The DETAIL rollups (per-host / per-application / blocked-destination) are
// keyed on high-cardinality values, so unlike the two PERMANENT rollups they
// are bounded by time. Deliberately LONGER than the raw retention: the whole
// point of a rollup is to still answer "who was the top talker last month"
// after the raw events behind it have been dropped.
const DETAIL_RETENTION_DAYS = intEnv('SYSLOG_DETAIL_RETENTION_DAYS', 30, 1, 3650);

// Compressed raw-log archive -- the storage model Firewall Analyzer used.
// Measured on this fleet: the raw text compresses 10.8x, so the 90 GB/day of
// `message` the database stores UNCOMPRESSED becomes ~8.4 GB/day here.
// ⛔ Default ON. An archive nobody enabled is not an archive.
const ARCHIVE_ENABLED = String(process.env.SYSLOG_ARCHIVE_ENABLED || 'true').toLowerCase() !== 'false';
const ARCHIVE_DIR = process.env.SYSLOG_ARCHIVE_DIR || path.join(__dirname, '..', 'archive');
const ARCHIVE_RETENTION_DAYS = intEnv('SYSLOG_ARCHIVE_RETENTION_DAYS', 60, 1, 3650);
// Log the archive ratio roughly every GB of raw text, not every flush.
const ARCHIVE_LOG_EVERY_BYTES = 1e9;

// How much of the raw line the DATABASE keeps. The archive above keeps every
// line regardless; this only decides what stays searchable in SQL.
//   all | security (default) | none  -- see shouldKeepRawMessage().
// ⛔ Only meaningful while the archive is running. With the archive disabled
// AND this set to none, a line nothing could parse would exist nowhere.
const RAW_MESSAGE_MODE = String(process.env.SYSLOG_RAW_MESSAGE || 'security').toLowerCase();
const SPOOL_DIR     = process.env.SYSLOG_SPOOL_DIR || path.join(__dirname, '..', 'spool');

// Rollup tiers. See lib/syslog/rollups.js for why this is tiered rather than
// LogVault's single 24h-every-5-minutes window: at ~1,400 events/sec that
// design would re-aggregate ~93M rows 288 times a day.
// ⛔ 1, not 3. sweepWindow() adds an hour, so this is already a 2-hour pass
// every SYSLOG_ROLLUP_INTERVAL_MINUTES. At 3 it was a 4-hour pass taking
// 233-262s against a 300s cycle on the live fleet -- about to overrun it.
//
// This is NOT the same trade-off as shrinking the wide lookback, which would
// lose late events permanently. The RECENT tier's only job is keeping the
// newest buckets fresh for the dashboards; every hour is still rebuilt by the
// sliced wide sweep, so nothing is dropped by narrowing this one.
const ROLLUP_RECENT_HOURS   = intEnv('SYSLOG_ROLLUP_RECENT_HOURS', 1, 1, 48);
const ROLLUP_LOOKBACK_HOURS = intEnv('SYSLOG_ROLLUP_LOOKBACK_HOURS', 24, 2, 168);
const ROLLUP_INTERVAL_MIN   = intEnv('SYSLOG_ROLLUP_INTERVAL_MINUTES', 5, 1, 60);

// --- state -----------------------------------------------------------------
let buffer = [];
let dropped = 0;          // datagrams refused because the buffer was full
let received = 0;
let flushing = false;
let shuttingDown = false;
let deviceByIp = new Map();   // source_ip -> device_id, refreshed periodically
let spoolCorrupt = 0;     // spool records skipped for an unreadable timestamp

function log(msg) {
  console.log(`[${new Date().toISOString()}] [collector] ${msg}`);
}

// --- device resolution -----------------------------------------------------
// ⛔ An unmatched sender stores device_id NULL. It is NOT dropped and NOT
// guessed: a firewall we do not manage still produces evidence, and silently
// discarding it would make the fleet look quieter than it is.
async function refreshDeviceMap() {
  try {
    // ⛔ BOTH queries, or NEITHER. A partial refresh — one succeeding, one
    // failing — would install a half-map, and every address in the missing half
    // would start filing its events as unattributed. That is worse than keeping
    // a slightly stale complete map, which is the failure mode this function
    // was already written to prefer.
    const [devices, aliases] = await Promise.all([
      pool.query('SELECT id, mgmt_ip, snmp_host FROM devices WHERE active = true'),
      // Additional syslog source addresses for a managed device — HA passive
      // peers, mainly. See lib/engines/deviceDiscovery.js: on this fleet 5 of 8
      // unmatched senders were peers of devices SecVault already had.
      pool.query(
        `SELECT s.device_id AS id, host(s.source_ip) AS ip
           FROM device_syslog_sources s
           JOIN devices d ON d.id = s.device_id AND d.active = true`
      ),
    ]);
    const map = new Map();
    for (const r of devices.rows) {
      if (r.mgmt_ip) map.set(String(r.mgmt_ip), r.id);
      if (r.snmp_host) map.set(String(r.snmp_host), r.id);
    }
    for (const r of aliases.rows) {
      if (r.ip) map.set(String(r.ip), r.id);
    }
    deviceByIp = map;
  } catch (err) {
    // Keep the previous map rather than blanking it: a transient DB blip must
    // not turn every event into an unattributed one.
    log(`WARN device map refresh failed, keeping previous (${deviceByIp.size} entries): ${err.message}`);
  }
}

// --- ingest ----------------------------------------------------------------
function accept(line, sourceIp) {
  received += 1;
  if (buffer.length >= MAX_BUFFER) {
    dropped += 1;
    return;
  }
  buffer.push({ line, sourceIp, receivedAt: new Date() });
}

// ⛔ The parsed-line -> stored-event mapping lives in lib/syslog/eventShape.js,
// NOT here. It used to be inline, and because this file starts listeners on
// require it could not be unit-tested -- so when eight new fields were added
// on 2026-09-08 the parser and the store were both updated and this hop was
// not. 360,025 events were stored with every new column silently NULL, which
// is indistinguishable from "the devices never sent it". Keep it importable.
function toEvent(raw) {
  const frame = parseSyslogLine(raw.line, raw.receivedAt);
  const payload = parseVendorPayload(frame.message);
  return buildEvent(raw, frame, payload, deviceByIp.get(raw.sourceIp) || null, RAW_MESSAGE_MODE);
}

// --- spool -----------------------------------------------------------------
function ensureSpoolDir() {
  fs.mkdirSync(SPOOL_DIR, { recursive: true });
}

// Written as .tmp then renamed to .ready, so a crash mid-write can never leave
// a half-line that the replay would treat as a real event. rename() is atomic.
function writeSpool(records) {
  // Self-heal a spool directory that vanished after startup (a removed or
  // remounted volume); without this every subsequent flush fails identically.
  ensureSpoolDir();
  const stamp = `${Date.now()}_${process.pid}_${Math.floor(Math.random() * 1e6)}`;
  const tmp = path.join(SPOOL_DIR, `${stamp}.tmp`);
  const ready = path.join(SPOOL_DIR, `${stamp}.ready`);
  const payload = records
    .map((r) => JSON.stringify({ l: r.line, s: r.sourceIp, t: r.receivedAt.toISOString() }))
    .join('\n');
  const fd = fs.openSync(tmp, 'w');
  try {
    fs.writeFileSync(fd, payload);
    fs.fsyncSync(fd);            // the whole point: on disk before the DB
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, ready);
  return ready;
}

function readSpool(file) {
  const out = [];
  const text = fs.readFileSync(file, 'utf8');
  for (const line of text.split('\n')) {
    if (!line) continue;
    try {
      const o = JSON.parse(line);
      const t = new Date(o.t);
      // ⛔ Do NOT substitute `new Date()`. received_at is the partition key and
      // is documented as "when WE observed it"; stamping a replayed record
      // with the restart time silently moves it into the wrong daily partition
      // and misdates every "last N hours" query. A record whose own timestamp
      // is unreadable is skipped and counted, not invented -- the same rule as
      // never defaulting a missing timestamp to now at parse time.
      if (Number.isNaN(t.getTime())) {
        spoolCorrupt++;
        continue;
      }
      out.push({ line: o.l, sourceIp: o.s, receivedAt: t });
    } catch (_e) {
      // A single unparseable spool line is skipped, not allowed to poison the
      // whole file — the rest of the batch is still real evidence.
    }
  }
  return out;
}

async function processSpoolFile(file) {
  const records = readSpool(file);
  if (records.length === 0) { fs.unlinkSync(file); return { stored: 0, parsed: 0 }; }

  // ⛔ Archive BEFORE the insert, and never let it block the insert. The
  // spool file is still on disk at this point, so a crash here costs a
  // replay (and at worst a duplicated archive member), never a lost line.
  // ⛔ An archive failure is a WARNING, not an abort: the database is the
  // primary store and ingest must survive a full disk on the archive volume.
  if (ARCHIVE_ENABLED) {
    const a = archive.appendBatch(ARCHIVE_DIR, records.map((r) => r.line), new Date());
    if (!a.ok) {
      archiveFailures += 1;
      log(`WARN archive append failed (${archiveFailures} so far): ${a.error}`);
    } else {
      archiveRaw += a.bytesRaw;
      archiveGz += a.bytesCompressed;
    }
  }

  const events = records.map(toEvent);
  const { stored, failedChunks } = await store.insertEvents(pool, events);

  if (failedChunks === 0) {
    fs.unlinkSync(file);          // ONLY on full success
  } else {
    log(`WARN ${path.basename(file)} kept for replay - ${failedChunks} chunk(s) failed`);
  }
  return {
    stored,
    parsed: events.filter((e) => e.vendor !== null).length,
    unknownVendor: events.filter((e) => e.vendor === null).length,
    unknownSource: events.filter((e) => e.deviceId === null).length,
  };
}

async function replayBacklog() {
  ensureSpoolDir();
  const files = fs.readdirSync(SPOOL_DIR).filter((f) => f.endsWith('.ready')).sort();
  if (files.length === 0) return;
  log(`replaying ${files.length} spool file(s) left over from a previous run`);
  for (const f of files) {
    try {
      const r = await processSpoolFile(path.join(SPOOL_DIR, f));
      log(`  replayed ${f}: stored ${r.stored}`);
    } catch (err) {
      log(`  ERROR replaying ${f}: ${err.message}`);
    }
  }
}

// --- flush cycle -----------------------------------------------------------
// ⛔ Returns the IN-FLIGHT promise rather than undefined when a flush is
// already running. shutdown() awaits flush() to drain memory before exit; with
// a bare `return` that await resolved instantly while a flush was mid-insert,
// and everything accepted since that flush started was discarded at exit.
// Update-SecVault.ps1 stops this service on every deploy, so that was the
// normal path, not an exceptional one.
let flushInFlight = null;

async function flush() {
  if (flushing) return flushInFlight;
  const p = doFlush();
  flushInFlight = p;
  try {
    return await p;
  } finally {
    flushInFlight = null;
  }
}

async function doFlush() {
  if (flushing) return;
  flushing = true;
  const started = Date.now();
  const batch = buffer;
  buffer = [];
  const droppedThisCycle = dropped;
  const receivedThisCycle = received;
  dropped = 0;
  received = 0;

  // ⛔ Set only once the batch is safely on disk. Until then a failure must put
  // the events BACK, because at this point they exist nowhere else: `buffer`
  // was already emptied above, so an exception here would drop them silently
  // -- the exact opposite of this file's durability contract, and invisible to
  // every DB-side health signal.
  let spooled = false;

  try {
    if (batch.length > 0) {
      const file = writeSpool(batch);           // durable first
      spooled = true;
      const r = await processSpoolFile(file);   // then the DB
      // Retry anything a previous cycle could not insert. Bounded per cycle so
      // a large backlog cannot starve live ingest.
      await drainBacklog(file);
      const backlog = countReadyFiles();
      await recordStats({
        received: receivedThisCycle,
        parsed: r.parsed,
        stored: r.stored,
        dropped: droppedThisCycle,
        unknownVendor: r.unknownVendor,
        unknownSource: r.unknownSource,
        backlog,
        ms: Date.now() - started,
      });
      if (droppedThisCycle > 0) {
        log(`WARN dropped ${droppedThisCycle} datagram(s) - buffer hit ${MAX_BUFFER}`);
      }
      // Report the archive's REAL ratio periodically rather than trusting the
      // measured 10.8x forever — it moves with the traffic mix, and this is the
      // number the retention sizing depends on.
      if (ARCHIVE_ENABLED && archiveRaw > ARCHIVE_LOG_EVERY_BYTES) {
        log(
          `archive   : ${(archiveRaw / 1e9).toFixed(2)} GB raw -> ` +
          `${(archiveGz / 1e9).toFixed(3)} GB stored (${(archiveRaw / archiveGz).toFixed(1)}x)` +
          (archiveFailures > 0 ? `, ${archiveFailures} failure(s)` : '')
        );
        archiveRaw = 0;
        archiveGz = 0;
      }
    } else if (droppedThisCycle > 0) {
      // ⛔ Still persist it. `dropped` is the one number an operator cannot
      // reconstruct from anywhere else, and a stdout line is not a record.
      log(`WARN dropped ${droppedThisCycle} datagram(s) with an empty batch`);
      await recordStats({
        received: receivedThisCycle,
        parsed: 0,
        stored: 0,
        dropped: droppedThisCycle,
        unknownVendor: 0,
        unknownSource: 0,
        backlog: countReadyFiles(),
        ms: Date.now() - started,
      });
    }
  } catch (err) {
    log(`ERROR flush failed: ${err.stack || err.message}`);

    // ⛔ The spool write is the durability boundary. If we never crossed it,
    // these events are ONLY in `batch` and dropping them here is silent data
    // loss on every subsequent cycle too (a full or missing spool volume fails
    // identically every time). Put them back; if the buffer has since filled,
    // count the remainder as dropped so the loss is REPORTED, never hidden.
    if (!spooled && batch.length > 0) {
      const room = Math.max(0, MAX_BUFFER - buffer.length);
      const keep = Math.min(room, batch.length);
      if (keep > 0) buffer = batch.slice(batch.length - keep).concat(buffer);
      const lost = batch.length - keep;
      if (lost > 0) {
        dropped += lost;
        log(`ERROR spool failed and buffer is full - ${lost} event(s) counted as dropped`);
      } else {
        log(`WARN spool failed - ${keep} event(s) returned to the buffer for retry`);
      }
    }

    // Counters must survive the failure, or the ingest-health view shows a gap
    // where it should show a problem.
    try {
      await recordStats({
        received: receivedThisCycle,
        parsed: 0,
        stored: 0,
        dropped: droppedThisCycle,
        unknownVendor: 0,
        unknownSource: 0,
        backlog: countReadyFiles(),
        ms: Date.now() - started,
      });
    } catch (_e) {
      // recordStats already swallows its own errors; this guards the
      // countReadyFiles() call on a broken spool volume.
    }
  } finally {
    flushing = false;
  }
}

// Cheap and failure-tolerant: a broken spool directory must not turn a flush
// error into a second, masking error.
function countReadyFiles() {
  try {
    return fs.readdirSync(SPOOL_DIR).filter((f) => f.endsWith('.ready')).length;
  } catch (_e) {
    return 0;
  }
}

// How many stranded spool files to retry per flush cycle, and how many times
// to retry one before quarantining it.
const BACKLOG_DRAIN_PER_CYCLE = 5;
const MAX_SPOOL_ATTEMPTS = 5;
const spoolAttempts = new Map();   // filename -> attempts

/**
 * Retry spool files that a previous cycle could not insert.
 *
 * ⛔ WHY THIS EXISTS: processSpoolFile() deliberately KEEPS a file whose insert
 * failed, but nothing ever picked it back up -- it was only ever called on a
 * freshly written file, or once at startup. So a database outage stranded every
 * file it produced until someone restarted the service: at ~2,000 events per
 * 2s flush, a one-hour outage leaves ~1,800 files holding ~3.6M events that are
 * invisible in SQL while ingest happily continues. "Kept for retry" with no
 * retry is just a slower kind of loss.
 *
 * Bounded per cycle so draining a large backlog cannot starve live ingest.
 */
async function drainBacklog(currentFile) {
  let files;
  try {
    files = fs.readdirSync(SPOOL_DIR).filter((f) => f.endsWith('.ready')).sort();
  } catch (_e) {
    return;
  }
  const current = currentFile ? path.basename(currentFile) : null;
  let done = 0;
  for (const name of files) {
    if (done >= BACKLOG_DRAIN_PER_CYCLE) break;
    if (name === current) continue;
    const full = path.join(SPOOL_DIR, name);
    const attempts = (spoolAttempts.get(name) || 0) + 1;
    spoolAttempts.set(name, attempts);
    try {
      const r = await processSpoolFile(full);
      if (!fs.existsSync(full)) {
        spoolAttempts.delete(name);
        log(`drained spool ${name}: stored ${r.stored}`);
      } else if (attempts >= MAX_SPOOL_ATTEMPTS) {
        // ⛔ Quarantine, never delete. A file we cannot insert is still
        // evidence; renaming keeps it for inspection and stops it blocking
        // the queue forever, and the rename is LOUD.
        fs.renameSync(full, full.replace(/\.ready$/, '.failed'));
        spoolAttempts.delete(name);
        log(`ERROR spool ${name} failed ${attempts}x - quarantined as .failed (NOT deleted)`);
      }
    } catch (err) {
      log(`ERROR draining spool ${name}: ${err.message}`);
    }
    done++;
  }
}

async function recordStats(s) {
  try {
    await pool.query(
      `INSERT INTO syslog_ingest_stats
         (received, parsed, stored, dropped, unknown_vendor, unknown_source, spool_backlog, batch_ms)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [s.received, s.parsed, s.stored, s.dropped, s.unknownVendor, s.unknownSource, s.backlog, s.ms]
    );
  } catch (err) {
    log(`WARN could not record ingest stats: ${err.message}`);
  }
}

// --- maintenance -----------------------------------------------------------
async function maintenance() {
  try {
    await store.ensurePartitions(pool, new Date());
    const dropped2 = await store.dropOldPartitions(pool, RETENTION_DAYS, new Date());
    if (dropped2.length > 0) log(`retention: dropped partition(s) ${dropped2.join(', ')}`);

    const trimmed = await trimDetailRollups(pool, DETAIL_RETENTION_DAYS);
    const trimTotal = Object.values(trimmed.deleted).reduce((a, b) => a + b, 0);
    if (trimTotal > 0) {
      log(`retention: trimmed ${trimTotal} detail rollup row(s) older than ${trimmed.days}d`);
    }
    // trimDetailRollups never throws, so without this the failure would be
    // SILENT -- and an un-trimmed high-cardinality table is exactly how a
    // disk fills up with every health signal still reporting green.
    if (trimmed.error) log(`WARN detail rollup trim: ${trimmed.error}`);

    if (ARCHIVE_ENABLED) {
      const pruned = archive.pruneArchive(ARCHIVE_DIR, ARCHIVE_RETENTION_DAYS, new Date());
      if (pruned.removed.length > 0) {
        log(`archive: removed ${pruned.removed.length} file(s) older than ${ARCHIVE_RETENTION_DAYS}d`);
      }
      if (pruned.error) log(`WARN archive prune: ${pruned.error}`);
    }
  } catch (err) {
    log(`ERROR maintenance failed: ${err.stack || err.message}`);
  }
}

// --- rollups ---------------------------------------------------------------
// Archive counters, reported in the flush log so the ratio is visible rather
// than assumed. Reset each time they are logged.
let archiveRaw = 0;
let archiveGz = 0;
let archiveFailures = 0;

let rollupRunning = false;

// `wide` sweeps further back to pick up events that landed LATE. Skipping it
// would leave those buckets permanently under-counted with no error anywhere
// -- see lib/syslog/rollups.js's header for the LogVault incident this
// prevents. Never overlap two sweeps: they would fight over the same buckets.
async function rollupCycle(wide) {
  if (rollupRunning) { log('rollup skipped - previous sweep still running'); return; }
  rollupRunning = true;
  // ⛔ This function is invoked from bare setInterval callbacks whose promises
  // nobody awaits, so a throw here becomes an unhandled rejection — which under
  // Node's default --unhandled-rejections=throw TERMINATES the collector.
  // Every sibling timer in this file (flush, maintenance, refreshDeviceMap)
  // already has its own catch; this one did not, and ingest is the last thing
  // that should die for a rollup bug.
  try {
    const r = await runRollupMaintenance(pool, {
      wide,
      recentHours: ROLLUP_RECENT_HOURS,
      lookbackHours: ROLLUP_LOOKBACK_HOURS,
    });
    if (r.ok) {
      // ⛔ Report EVERY rollup, derived from the result object rather than a
      // hand-written list. The old line named five of nine, so inboundRows,
      // countryRows, userRows and urlCatRows were invisible: a rollup that
      // silently returns zero rows (an empty address set, a column that stops
      // parsing) would commit, log "success", and flatline unnoticed. Deriving
      // the list means a tenth rollup cannot be added without appearing here.
      //
      // ⛔ AND ITS DURATION, from the same derivation, for the same reason in
      // the other axis. A sweep that slows from 130s to 900s still commits and
      // still reports honest counts; its only symptom was "rollup skipped -
      // previous sweep still running", which names no pass and left the 2026-09
      // investigation guessing between the window scan and ten aggregations.
      // The answer turned out to be the scan (`build`), which no line reported
      // at all — so build/analyze/deletes are named explicitly and every pass
      // carries its own ms.
      const t = r.timings || {};
      const counts = Object.keys(r)
        .filter((k) => k.endsWith('Rows'))
        .map((k) => {
          const name = k.slice(0, -4);
          const ms = t[name];
          return `${r[k]} ${name}${ms === undefined ? '' : `/${ms}ms`}`;
        })
        .join(' + ');
      const prologue = ['build', 'analyze', 'deletes']
        .filter((k) => t[k] !== undefined)
        .map((k) => `${k} ${t[k]}ms`)
        .join(', ');
      log(
        `rollup ${r.tier} (${r.hours}h` +
        (r.sliceIndex === null || r.sliceIndex === undefined
          ? ''
          : `, slice ${r.sliceIndex}/${r.sliceHours}h`) +
        `): ${counts} row(s) in ${r.ms}ms` +
        (prologue ? ` [${prologue}]` : '')
      );
    } else {
      log(`ERROR rollup ${r.tier} failed after ${r.ms}ms: ${r.error}`);
    }
  } catch (err) {
    log(`ERROR rollup threw: ${err.stack || err.message}`);
  } finally {
    rollupRunning = false;
  }
}

// --- listeners -------------------------------------------------------------
function startUdp(port) {
  const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  sock.on('message', (msg, rinfo) => {
    // Firewalls can pack several lines into one datagram.
    const text = msg.toString('utf8');
    for (const line of text.split('\n')) {
      if (line.trim().length > 0) accept(line, rinfo.address);
    }
  });
  // !! A bind failure on ONE port must not take the others down. Report it
  // loudly and keep the rest listening.
  sock.on('error', (err) => log(`ERROR udp/${port}: ${err.message}`));
  sock.bind(port, () => log(`listening udp/${port}`));
  return sock;
}

// A syslog line far longer than this is a framing failure, not a log line.
// Bounding it matters because `partial` is per-connection and otherwise grows
// without limit.
const MAX_TCP_LINE = 65536;
const TCP_IDLE_MS = 300000;

function startTcp(port) {
  const server = net.createServer((socket) => {
    // ⛔ No 'unknown' sentinel. source_ip is INET NOT NULL, so a sentinel
    // coerces to NULL and fails the INSERT for the entire 500-row chunk it
    // lands in -- which then strands the spool file. remoteAddress is
    // genuinely undefined for a socket the peer destroyed before this handler
    // ran, which is routine on a public listener. Refuse the connection
    // instead of manufacturing an address we cannot store.
    if (!socket.remoteAddress) {
      socket.destroy();
      return;
    }
    const peer = socket.remoteAddress.replace(/^::ffff:/, '');
    let partial = '';

    socket.setTimeout(TCP_IDLE_MS, () => socket.destroy());

    socket.on('data', (chunk) => {
      partial += chunk.toString('utf8');
      const lines = partial.split('\n');
      partial = lines.pop();   // keep the incomplete tail for the next chunk
      for (const line of lines) {
        if (line.trim().length > 0) accept(line, peer);
      }
      // A sender that never emits a newline would otherwise grow this string
      // until the process dies. Emit what we have, count it, and reset.
      if (partial.length > MAX_TCP_LINE) {
        log(`WARN tcp/${port} ${peer}: line exceeded ${MAX_TCP_LINE} bytes - truncating`);
        accept(partial.slice(0, MAX_TCP_LINE), peer);
        partial = '';
      }
    });
    socket.on('error', () => {});
    socket.on('close', () => {
      if (partial.trim().length > 0) accept(partial.slice(0, MAX_TCP_LINE), peer);
      partial = '';
    });
  });
  // Bounded so a connection flood cannot exhaust file descriptors.
  server.maxConnections = 2048;
  server.on('error', (err) => log(`ERROR tcp/${port}: ${err.message}`));
  server.listen(port, () => log(`listening tcp/${port}`));
  return server;
}

// --- lifecycle -------------------------------------------------------------
async function main() {
  log('SecVault-Collector starting.');
  log(`spool dir : ${SPOOL_DIR}`);
  log(`raw line  : ${RAW_MESSAGE_MODE} in the database (the archive keeps every line regardless)`);
  // ⛔ The one combination that can lose a line nothing understood.
  if (!ARCHIVE_ENABLED && RAW_MESSAGE_MODE === 'none') {
    log('WARN archive is DISABLED and raw lines are not stored - unparsed lines will exist nowhere');
  }
  log(
    `retention : ${RETENTION_DAYS} day(s) of raw events, ` +
    `${DETAIL_RETENTION_DAYS} day(s) of detail rollups`
  );
  if (ARCHIVE_ENABLED) {
    const st = archive.archiveStats(ARCHIVE_DIR);
    log(
      `archive   : ${ARCHIVE_DIR} (${ARCHIVE_RETENTION_DAYS}d) - ` +
      `${st.files} file(s), ${(st.bytes / 1e9).toFixed(1)} GB` +
      (st.oldest ? ` covering ${st.oldest}..${st.newest}` : '')
    );
  } else {
    log('archive   : DISABLED');
  }
  log(`rollups   : recent ${ROLLUP_RECENT_HOURS}h every ${ROLLUP_INTERVAL_MIN}min, wide ${ROLLUP_LOOKBACK_HOURS}h hourly`);
  log(`threat    : ${ROLLUP_LOOKBACK_HOURS}h now, then ${ROLLUP_RECENT_HOURS + 1}h every ${ROLLUP_INTERVAL_MIN}min (separate from the sweep)`);

  ensureSpoolDir();
  await pool.query('SELECT 1');
  log('database connectivity verified.');

  await maintenance();
  await refreshDeviceMap();
  log(`device map: ${deviceByIp.size} source address(es) resolvable`);
  for (const p of UDP_PORTS.rejected) log(`WARN ignoring invalid SYSLOG_UDP_PORT entry '${p}'`);
  for (const p of TCP_PORTS.rejected) log(`WARN ignoring invalid SYSLOG_TCP_PORT entry '${p}'`);
  // ⛔ BIND FIRST, replay second. replayBacklog() used to run to completion
  // before any socket existed, so a large backlog left the collector DEAF for
  // its whole duration — and datagrams sent to an unbound UDP port are
  // discarded by the OS with no counter anywhere, the one failure mode you
  // cannot see from inside the process. A one-hour DB outage can strand ~1,800
  // spool files; replaying those serially is minutes of silence. The replay is
  // now started after the listeners are up and shares the flush cycle's
  // `flushing` mutex, so the two cannot collide.
  const udpSockets = UDP_PORTS.ports.map((p) => startUdp(p));
  const tcpServers = TCP_PORTS.ports.map((p) => startTcp(p));

  replayBacklog().catch((err) => log(`ERROR replaying backlog: ${err.stack || err.message}`));

  // ⛔ THREAT ROLLUP RUNS SEPARATELY AND EAGERLY, on purpose.
  //
  // It used to be one of the eleven passes inside the heavy sweep, and the
  // Security tab was consequently HOURS behind: that sweep builds a ~10M-row
  // temp table for the traffic rollups, its wide tier fires once an hour and
  // covers a 6-hour slice per run, so a 24-hour backfill took four hourly
  // passes. An operator opening a SECURITY view expects what the firewalls
  // just reported, not what they reported before lunch.
  //
  // This pass reads syslog_events through the partial log_class index, where
  // an hour of threat events is ~59k rows and ~256ms, so a full 24h rebuild
  // is seconds. Running it immediately at startup means the tab is populated
  // by the time anyone can click it, and re-running the recent window every
  // cycle keeps it current.
  //
  // ⛔ Awaited nowhere: like every sibling timer here it must not let a
  // rejection escape, or an unhandled rejection kills ingest. refreshThreatRollup
  // never throws, and this catch is the second line of that defence.
  async function threatRollupCycle(hours) {
    try {
      const r = await refreshThreatRollup(pool, hours);
      if (r.ok) {
        log(`threat rollup (${r.hours}h): ${r.rows} row(s) over ${r.buckets} bucket(s) in ${r.ms}ms`);
      } else {
        log(`ERROR threat rollup (${r.hours}h) failed after ${r.ms}ms: ${r.error}`);
      }
    } catch (err) {
      log(`ERROR threat rollup threw: ${err && err.message ? err.message : err}`);
    }
  }

  // Full window once, now, so the Security tab is not empty for a moment
  // longer than it has to be after a restart.
  threatRollupCycle(ROLLUP_LOOKBACK_HOURS);

  const flushTimer = setInterval(() => { flush(); }, FLUSH_MS);
  // Only the recent window on the frequent tick — rebuilding 24h every few
  // minutes would be wasted work, since older buckets cannot change.
  const threatTimer = setInterval(
    () => { threatRollupCycle(ROLLUP_RECENT_HOURS + 1); },
    ROLLUP_INTERVAL_MIN * 60 * 1000,
  );
  const mapTimer = setInterval(() => { refreshDeviceMap(); }, 5 * 60 * 1000);
  const maintTimer = setInterval(() => { maintenance(); }, 60 * 60 * 1000);
  const rollupTimer = setInterval(() => { rollupCycle(false); }, ROLLUP_INTERVAL_MIN * 60 * 1000);
  const rollupWideTimer = setInterval(() => { rollupCycle(true); }, 60 * 60 * 1000);
  // Seed the rollups immediately so a restart does not leave a visible gap
  // until the first timer fires.
  rollupCycle(true);

  async function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    log(`${signal} received - draining.`);
    clearInterval(flushTimer);
    clearInterval(mapTimer);
    clearInterval(maintTimer);
    clearInterval(threatTimer);
    clearInterval(rollupTimer);
    clearInterval(rollupWideTimer);
    for (const s of udpSockets) { try { s.close(); } catch (_e) {} }
    for (const s of tcpServers) { try { s.close(); } catch (_e) {} }
    // Drain what is in memory so a restart does not lose the current window.
    // Two calls on purpose: the first awaits any in-flight flush (which does
    // NOT touch the current buffer), the second spools whatever arrived while
    // that one was running.
    await flush();
    await flush();
    try { await pool.end(); } catch (_e) {}
    log('stopped cleanly.');
    process.exit(0);
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  log('collector ready.');
}

main().catch((err) => {
  console.error(`[collector] fatal: ${err.stack || err.message}`);
  process.exit(1);
});
