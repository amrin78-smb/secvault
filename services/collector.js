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
const store = require('../lib/syslog/eventStore');
const { parsePortList } = require('../lib/syslog/collectorConfig');
const { runRollupMaintenance, trimDetailRollups } = require('../lib/syslog/rollups');

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
const RETENTION_DAYS = intEnv('SYSLOG_RETENTION_DAYS', 7, 1, 3650);
// The DETAIL rollups (per-host / per-application / blocked-destination) are
// keyed on high-cardinality values, so unlike the two PERMANENT rollups they
// are bounded by time. Deliberately LONGER than the raw retention: the whole
// point of a rollup is to still answer "who was the top talker last month"
// after the raw events behind it have been dropped.
const DETAIL_RETENTION_DAYS = intEnv('SYSLOG_DETAIL_RETENTION_DAYS', 30, 1, 3650);
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

function log(msg) {
  console.log(`[${new Date().toISOString()}] [collector] ${msg}`);
}

// --- device resolution -----------------------------------------------------
// ⛔ An unmatched sender stores device_id NULL. It is NOT dropped and NOT
// guessed: a firewall we do not manage still produces evidence, and silently
// discarding it would make the fleet look quieter than it is.
async function refreshDeviceMap() {
  try {
    const { rows } = await pool.query(
      'SELECT id, mgmt_ip, snmp_host FROM devices WHERE active = true'
    );
    const map = new Map();
    for (const r of rows) {
      if (r.mgmt_ip) map.set(String(r.mgmt_ip), r.id);
      if (r.snmp_host) map.set(String(r.snmp_host), r.id);
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
  return buildEvent(raw, frame, payload, deviceByIp.get(raw.sourceIp) || null);
}

// --- spool -----------------------------------------------------------------
function ensureSpoolDir() {
  fs.mkdirSync(SPOOL_DIR, { recursive: true });
}

// Written as .tmp then renamed to .ready, so a crash mid-write can never leave
// a half-line that the replay would treat as a real event. rename() is atomic.
function writeSpool(records) {
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
      out.push({ line: o.l, sourceIp: o.s, receivedAt: Number.isNaN(t.getTime()) ? new Date() : t });
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
async function flush() {
  if (flushing) return;
  flushing = true;
  const started = Date.now();
  const batch = buffer;
  buffer = [];
  const droppedThisCycle = dropped;
  const receivedThisCycle = received;
  dropped = 0;
  received = 0;

  try {
    if (batch.length > 0) {
      const file = writeSpool(batch);           // durable first
      const r = await processSpoolFile(file);   // then the DB
      const backlog = fs.readdirSync(SPOOL_DIR).filter((f) => f.endsWith('.ready')).length;
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
    } else if (droppedThisCycle > 0) {
      log(`WARN dropped ${droppedThisCycle} datagram(s) with an empty batch`);
    }
  } catch (err) {
    log(`ERROR flush failed: ${err.stack || err.message}`);
  } finally {
    flushing = false;
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
  } catch (err) {
    log(`ERROR maintenance failed: ${err.stack || err.message}`);
  }
}

// --- rollups ---------------------------------------------------------------
let rollupRunning = false;

// `wide` sweeps further back to pick up events that landed LATE. Skipping it
// would leave those buckets permanently under-counted with no error anywhere
// -- see lib/syslog/rollups.js's header for the LogVault incident this
// prevents. Never overlap two sweeps: they would fight over the same buckets.
async function rollupCycle(wide) {
  if (rollupRunning) { log('rollup skipped - previous sweep still running'); return; }
  rollupRunning = true;
  try {
    const r = await runRollupMaintenance(pool, {
      wide,
      recentHours: ROLLUP_RECENT_HOURS,
      lookbackHours: ROLLUP_LOOKBACK_HOURS,
    });
    if (r.ok) {
      log(
        `rollup ${r.tier} (${r.hours}h` +
        (r.sliceIndex === null || r.sliceIndex === undefined
          ? ''
          : `, slice ${r.sliceIndex}/${r.sliceHours}h`) +
        `): ${r.hourlyRows} hourly + ${r.ruleRows} rule + ` +
        `${r.talkerRows} host + ${r.appRows} app + ${r.blockedRows} blocked-dst row(s) in ${r.ms}ms`
      );
    } else {
      log(`ERROR rollup ${r.tier} failed after ${r.ms}ms: ${r.error}`);
    }
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

function startTcp(port) {
  const server = net.createServer((socket) => {
    const peer = socket.remoteAddress ? socket.remoteAddress.replace(/^::ffff:/, '') : 'unknown';
    let partial = '';
    socket.on('data', (chunk) => {
      partial += chunk.toString('utf8');
      const lines = partial.split('\n');
      partial = lines.pop();   // keep the incomplete tail for the next chunk
      for (const line of lines) {
        if (line.trim().length > 0) accept(line, peer);
      }
    });
    socket.on('error', () => {});
    socket.on('close', () => {
      if (partial.trim().length > 0) accept(partial, peer);
    });
  });
  server.on('error', (err) => log(`ERROR tcp/${port}: ${err.message}`));
  server.listen(port, () => log(`listening tcp/${port}`));
  return server;
}

// --- lifecycle -------------------------------------------------------------
async function main() {
  log('SecVault-Collector starting.');
  log(`spool dir : ${SPOOL_DIR}`);
  log(
    `retention : ${RETENTION_DAYS} day(s) of raw events, ` +
    `${DETAIL_RETENTION_DAYS} day(s) of detail rollups`
  );
  log(`rollups   : recent ${ROLLUP_RECENT_HOURS}h every ${ROLLUP_INTERVAL_MIN}min, wide ${ROLLUP_LOOKBACK_HOURS}h hourly`);

  ensureSpoolDir();
  await pool.query('SELECT 1');
  log('database connectivity verified.');

  await maintenance();
  await refreshDeviceMap();
  log(`device map: ${deviceByIp.size} source address(es) resolvable`);
  await replayBacklog();

  for (const p of UDP_PORTS.rejected) log(`WARN ignoring invalid SYSLOG_UDP_PORT entry '${p}'`);
  for (const p of TCP_PORTS.rejected) log(`WARN ignoring invalid SYSLOG_TCP_PORT entry '${p}'`);
  const udpSockets = UDP_PORTS.ports.map((p) => startUdp(p));
  const tcpServers = TCP_PORTS.ports.map((p) => startTcp(p));

  const flushTimer = setInterval(() => { flush(); }, FLUSH_MS);
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
    clearInterval(rollupTimer);
    clearInterval(rollupWideTimer);
    for (const s of udpSockets) { try { s.close(); } catch (_e) {} }
    for (const s of tcpServers) { try { s.close(); } catch (_e) {} }
    // Drain what is in memory so a restart does not lose the current window.
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
