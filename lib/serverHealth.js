// lib/serverHealth.js
//
// The health of the SERVER SecVault runs on — disk, database, retention,
// ingest, and whether the three services are actually doing anything.
//
// ⛔ NOT TO BE CONFUSED WITH FLEET HEALTH. `FleetSystemHealth` and
// `deviceHealth.js` are about the FIREWALLS' CPU, memory and licences. This is
// about the box. The dashboard's `fleet` tab description even says "system
// health" meaning the devices, which is exactly why this one is labelled
// Server: one word apart is how a session reads the wrong number.
//
// ⛔ A FAILED READ IS NULL, NEVER ZERO — and on this page that rule has teeth.
// "0 GB free" and "we could not read the volume" render identically if the
// second is allowed to become the first, and the first is an emergency. Every
// figure here is nullable and every caller must render null as not-measured.
//
// ⛔ NOTHING HERE SHELLS OUT. Service liveness is inferred from the evidence
// each service leaves in the database — the engine's feed_sync_log rows, the
// collector's syslog_ingest_stats rows — rather than by spawning sc.exe from a
// web request. This codebase already has a rule against PowerShell service
// cmdlets hanging things, and a dashboard that can hang the app server is worse
// than one that reports a little less.

'use strict';

const fsp = require('node:fs/promises');
const path = require('node:path');

const BYTES_IN_GB = 1024 ** 3;

/**
 * Free/total for the volume containing `p`.
 *
 * ⛔ RETURNS NULLS ON FAILURE, NOT ZEROS. A path that does not exist, a volume
 * that is not mounted, or a permissions error all mean WE DO NOT KNOW — and a
 * zero here would render as a full disk, which is the loudest possible wrong
 * answer.
 */
async function volumeFor(p) {
  if (!p) return null;
  try {
    const s = await fsp.statfs(p);
    const total = Number(s.blocks) * Number(s.bsize);
    // bavail is space available to an UNPRIVILEGED user, which is what actually
    // constrains the services; bfree includes root-reserved blocks.
    const free = Number(s.bavail) * Number(s.bsize);
    if (!Number.isFinite(total) || !Number.isFinite(free) || total <= 0) {
      return { path: p, totalBytes: null, freeBytes: null, error: 'statfs returned no usable figures' };
    }
    return {
      path: p,
      totalBytes: total,
      freeBytes: free,
      usedBytes: total - free,
      usedPct: Math.round(((total - free) / total) * 100),
    };
  } catch (err) {
    return { path: p, totalBytes: null, freeBytes: null, error: err.message };
  }
}

/** The volume root a path sits on, so two paths on E: are reported once. */
function volumeKey(p) {
  try {
    const parsed = path.parse(path.resolve(p));
    // UPPER-CASED, because path.resolve does not normalise a Windows drive
    // letter: an operator writing e:\SecVaultArchive in .env.local while the
    // installer wrote E:\SecVaultSpool produced TWO "E:" rows with identical
    // byte figures, each claiming different roles, and statfs ran twice on the
    // same volume. React keys stayed distinct so nothing warned.
    return (parsed.root || p).toUpperCase();
  } catch {
    return p;
  }
}

/**
 * Disk for every directory this product writes to.
 *
 * ⛔ THE POSTGRES DATA DIRECTORY CANNOT BE DISCOVERED FROM SQL by the
 * application's role — `SHOW data_directory` is superuser-only and answers
 * "permission denied to examine data_directory". It is therefore NOT guessed.
 * On the reference deployment the archive lives on the same volume as the
 * database (both on E:), so that volume is still measured — but the label says
 * which path was measured, never "the database volume", because we cannot
 * prove that.
 */
async function getDiskUsage(opts = {}) {
  const installDir = opts.installDir || process.cwd();
  const candidates = [
    { path: installDir, role: 'install' },
    { path: process.env.SYSLOG_SPOOL_DIR || path.join(installDir, 'spool'), role: 'syslog spool' },
    { path: process.env.SYSLOG_ARCHIVE_DIR || path.join(installDir, 'archive'), role: 'syslog archive' },
  ];

  const seen = new Map();
  for (const c of candidates) {
    const key = volumeKey(c.path);
    if (!seen.has(key)) seen.set(key, { volume: key, roles: [], paths: [] });
    seen.get(key).roles.push(c.role);
    seen.get(key).paths.push(c.path);
  }

  const out = [];
  for (const entry of seen.values()) {
    // Measure the volume once, via the first path on it that resolves.
    let measured = null;
    for (const p of entry.paths) {
      const v = await volumeFor(p);
      if (v && v.totalBytes !== null) { measured = v; break; }
      if (!measured) measured = v;
    }
    out.push({ ...entry, ...(measured || { totalBytes: null, freeBytes: null, error: 'not measured' }) });
  }
  return out;
}

/** Database size, the biggest relations, and dead-tuple pressure. */
async function getDatabaseSize(pool) {
  // tables/deadTuples START AS NULL, NOT []. An empty array renders identically
  // to "nothing qualified": the dead-tuple section is drawn only when the array
  // is non-empty, so a failed or permission-denied read was pixel-identical to a
  // clean bill of health drawn from a read that never happened.
  const out = { totalBytes: null, tables: null, deadTuples: null, error: null, tablesError: null, deadTuplesError: null };
  try {
    const { rows } = await pool.query(
      'SELECT pg_database_size(current_database())::bigint AS bytes'
    );
    out.totalBytes = rows[0] ? Number(rows[0].bytes) : null;
  } catch (err) {
    out.error = err.message;
  }
  try {
    const { rows } = await pool.query(
      // PARTITIONS ROLL UP TO THEIR PARENT, AND CHILDREN ARE EXCLUDED.
      // pg_total_relation_size does not recurse into a partitioned table, so
      // syslog_events (relkind 'p', no storage of its own) reported ~0 while its
      // ~30 daily children each reported tens of GB and filled the whole list.
      // Measured live: the operator saw five syslog_events_YYYYMMDD rows and
      // NEVER saw syslog_events itself -- 263.1 GB of a 265 GB database.
      //
      // ⛔ AND THE FIX FOR THAT BROKE EVERY ORDINARY TABLE. pg_partition_tree()
      // returns NO ROWS for a relation that is neither partitioned nor a
      // partition, so `coalesce(sum(...), 0)` evaluated to 0 for all 100-odd
      // regular tables. Measured live 2026-10-19: syslog_talker_hourly (1,926
      // MB), syslog_threat_hourly (1,340 MB) and device_configs (776 MB) all
      // computed as 0 bytes, and ORDER BY 2 DESC then tie-broke arbitrarily
      // among them -- so the operator saw syslog_events followed by whichever
      // three sub-megabyte tables sorted first, never the ~6.9 GB of detail
      // rollups that are the second-largest thing in the database.
      //
      // ⛔ IT RENDERED AS A PLAUSIBLE NUMBER, NOT AS A GAP, WHICH IS WHY IT
      // SURVIVED. ServerHealthWidgets floors a sub-gigabyte value at "1 MB"
      // (0.0 GB being indistinguishable from nothing at all), so four tables
      // reporting ZERO displayed as "1 MB" -- a failed read presented as a
      // measurement, the bug class this file exists to report on. The tell was
      // on screen the whole time: the panel showed 717 GB total against a
      // 706 GB largest relation and nothing else above 1 MB.
      //
      // GREATEST of the two, so each relkind is measured the way that is
      // correct for it and neither can zero the other out.
      `SELECT c.relname,
              GREATEST(
                pg_total_relation_size(c.oid),
                (SELECT coalesce(sum(pg_total_relation_size(pt.relid)), 0)
                   FROM pg_partition_tree(c.oid) pt)
              )::bigint AS bytes
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p')
          AND NOT c.relispartition
        ORDER BY 2 DESC
        LIMIT 8`
    );
    out.tables = rows.map((r) => ({ name: r.relname, bytes: Number(r.bytes) }));
  } catch (err) {
    out.tablesError = err.message;
  }
  try {
    // ⛔ Dead tuples are a real operational signal here: this codebase has
    // already shipped a backfill that rewrote 302 rows to identical values on
    // every deploy and left `advisories` at 18.6% dead.
    const { rows } = await pool.query(
      `SELECT relname, n_dead_tup::bigint AS dead, n_live_tup::bigint AS live
         FROM pg_stat_user_tables
        WHERE schemaname = 'public'
          AND n_dead_tup > 10000
        ORDER BY n_dead_tup DESC
        LIMIT 5`
    );
    out.deadTuples = rows.map((r) => ({
      name: r.relname,
      dead: Number(r.dead),
      live: Number(r.live),
      pct: Number(r.live) + Number(r.dead) > 0
        ? Math.round((Number(r.dead) / (Number(r.live) + Number(r.dead))) * 100)
        : null,
    }));
  } catch (err) {
    out.deadTuplesError = err.message;
  }
  return out;
}

/**
 * Raw syslog retention, from the partitions themselves.
 *
 * ⛔ COUNTS PARTITIONS, NEVER ROWS. `SELECT count(*) FROM syslog_events` is a
 * full scan of ~28M rows per day of retention, and this is a dashboard.
 */
async function getSyslogRetention(pool) {
  try {
    const { rows } = await pool.query(
      `SELECT count(*)::int          AS partitions,
              min(tablename)         AS oldest,
              max(tablename)         AS newest,
              sum(pg_total_relation_size(('public.' || quote_ident(tablename))::regclass))::bigint AS bytes
         FROM pg_tables
        WHERE schemaname = 'public'
          AND tablename ~ '^syslog_events_[0-9]{8}$'`
    );
    const r = rows[0] || {};
    const dayOf = (t) => (t ? String(t).slice(-8) : null);
    return {
      partitions: r.partitions === null ? null : Number(r.partitions),
      oldestDay: dayOf(r.oldest),
      newestDay: dayOf(r.newest),
      bytes: r.bytes === null ? null : Number(r.bytes),
      retentionDays: Number(process.env.SYSLOG_RETENTION_DAYS) || null,
    };
  } catch (err) {
    // retentionDays SURVIVES A DATABASE FAILURE because it is a process.env
    // read with no dependency on the database. Dropping it made the page claim
    // it did not know its own configuration during a DB blip.
    return {
      partitions: null, oldestDay: null, newestDay: null, bytes: null,
      retentionDays: Number(process.env.SYSLOG_RETENTION_DAYS) || null,
      error: err.message,
    };
  }
}

/**
 * Collector throughput and, crucially, whether it is DROPPING.
 *
 * ⛔ `dropped` IS THE POINT. The collector counts overflow rather than hiding
 * it, precisely so it can be surfaced — a collector silently losing datagrams
 * is indistinguishable from a quiet network.
 */

/**
 * The most recent window in which nothing was listening on the syslog ports.
 *
 * ⛔ THIS IS THE LOSS `dropped` CANNOT SEE. That counter is honest about buffer
 * overflow, but it can only count datagrams that REACHED the process. While
 * SecVault-Collector is stopped the OS discards each one before any socket
 * sees it, UDP does not retry, and nothing anywhere records that it happened —
 * a loss indistinguishable from a quiet network, which is the one thing this
 * product refuses to let a number do.
 *
 * ⛔ IT REPORTS A WINDOW, NEVER AN EVENT COUNT. What arrived while nothing
 * listened is unknowable; scaling a neighbouring rate by the gap would invent
 * a measurement out of an absence.
 *
 * ⛔ ITS OWN try/catch, DELIBERATELY. An installation that has not yet run the
 * migration adding `syslog_ingest_gaps` would otherwise fail the whole ingest
 * read and blank a panel that was working — a new diagnostic must never be
 * able to take out the diagnostics beside it. Unreadable returns null, which
 * renders as not-measured rather than as "no gap".
 */
async function getLastIngestGap(pool) {
  try {
    const { rows } = await pool.query(
      `SELECT detected_at, last_stat_at, gap_seconds, reason
         FROM syslog_ingest_gaps
        ORDER BY detected_at DESC
        LIMIT 1`
    );
    if (rows.length === 0) return null;
    const r = rows[0];
    return {
      detectedAt: r.detected_at || null,
      lastStatAt: r.last_stat_at || null,
      // ⛔ NULL stays NULL. `reason` distinguishes first_start / unreadable /
      // clock_mismatch from a real measurement; none of them is a zero gap.
      gapSeconds: r.gap_seconds === null || r.gap_seconds === undefined
        ? null : Number(r.gap_seconds),
      reason: r.reason || null,
    };
  } catch {
    return null;
  }
}

async function getIngestHealth(pool, minutes = 15) {
  // Number(null), Number(false), Number('') and Number([]) are all 0, which IS
  // finite -- so a bare Number.isFinite guard clamped them to 1 MINUTE instead
  // of falling back to 15. typeof-checking first is what makes the fallback real.
  const raw = typeof minutes === 'number' || (typeof minutes === 'string' && minutes.trim() !== '')
    ? Number(minutes) : NaN;
  const m = Number.isFinite(raw) ? Math.min(Math.max(raw, 1), 1440) : 15;
  try {
    const { rows } = await pool.query(
      `SELECT sum(received)::bigint  AS received,
              sum(stored)::bigint    AS stored,
              sum(dropped)::bigint   AS dropped,
              max(spool_backlog)     AS backlog,
              max(recorded_at)       AS last_flush,
              count(*)::int          AS flushes
         FROM syslog_ingest_stats
        WHERE recorded_at > now() - ($1::int * interval '1 minute')`,
      [m]
    );
    const r = rows[0] || {};
    const received = r.received === null || r.received === undefined ? null : Number(r.received);
    return {
      windowMinutes: m,
      received,
      stored: r.stored === null || r.stored === undefined ? null : Number(r.stored),
      // ⛔ NULL when nothing was recorded at all — "no flushes in the window"
      // is not "zero drops", and reporting 0 there would be an all-clear drawn
      // from an absent collector.
      dropped: r.dropped === null || r.dropped === undefined ? null : Number(r.dropped),
      backlog: r.backlog === null || r.backlog === undefined ? null : Number(r.backlog),
      lastFlush: r.last_flush || null,
      flushes: Number(r.flushes || 0),
      eventsPerSec: received === null ? null : Math.round(received / (m * 60)),
      lastGap: await getLastIngestGap(pool),
    };
  } catch (err) {
    // THE ERROR SHAPE MUST CARRY EVERY KEY THE RENDERER READS. It omitted
    // `flushes`, and the widget's "the collector recorded no flushes" banner is
    // gated on `flushes === 0` -- `undefined === 0` is false, so a DATABASE
    // failure SUPPRESSED the very banner that says ingest is broken, and the
    // panel rendered five em-dashes with no explanation at all.
    return {
      windowMinutes: m,
      received: null, stored: null, dropped: null, backlog: null,
      lastFlush: null, flushes: 0, eventsPerSec: null,
      // ⛔ Present and null, never absent — see the note above: a key the
      // renderer reads must exist on the error shape too.
      lastGap: null,
      error: err.message,
    };
  }
}

/**
 * Are the Engine and Collector alive?
 *
 * ⛔ INFERRED FROM WHAT THEY WRITE, NOT FROM sc.exe. Each service leaves dated
 * evidence in the database; asking Windows would mean spawning a process from a
 * web request, and NSSM reports a crash-looping process as Running anyway — so
 * the service state would be less truthful than the evidence.
 *
 * ⛔ `lastSeen: null` MEANS NEVER, NOT BROKEN, and the two are reported apart:
 * a fresh install has never run a feed sync and that is not a fault.
 */
async function getServiceLiveness(pool) {
  const svc = async (name, sql) => {
    try {
      const { rows } = await pool.query(sql);
      const at = rows[0] && rows[0].at ? new Date(rows[0].at) : null;
      return { name, lastSeen: at, ageSeconds: at ? Math.round((Date.now() - at.getTime()) / 1000) : null };
    } catch (err) {
      return { name, lastSeen: null, ageSeconds: null, error: err.message };
    }
  };
  return Promise.all([
    svc('Engine (feeds, matching, retention)', 'SELECT max(started_at) AS at FROM feed_sync_log'),
    svc('Collector (syslog ingest)', 'SELECT max(recorded_at) AS at FROM syslog_ingest_stats'),
  ]);
}

/** The App process itself — the one thing we can observe directly. */
function getProcessInfo() {
  const mem = process.memoryUsage();
  return {
    nodeVersion: process.version,
    uptimeSeconds: Math.round(process.uptime()),
    rssBytes: mem.rss,
    heapUsedBytes: mem.heapUsed,
    heapTotalBytes: mem.heapTotal,
    pid: process.pid,
  };
}

async function getServerHealth(pool, opts = {}) {
  const [disks, database, retention, ingest, services] = await Promise.all([
    getDiskUsage(opts),
    getDatabaseSize(pool),
    getSyslogRetention(pool),
    getIngestHealth(pool, opts.ingestMinutes || 15),
    getServiceLiveness(pool),
  ]);
  return { disks, database, retention, ingest, services, process: getProcessInfo() };
}

/**
 * ⛔ THRESHOLDS ON FREE SPACE, NOT ON PERCENT USED. A 2 TB volume at 90% still
 * has 200 GB; a 100 GB volume at 90% has 10 and this product writes ~31 GB a
 * day of raw syslog. Percentage alone would call the dangerous one healthy.
 * Returns null — not 'ok' — when the figure is unknown.
 */
function diskState(vol) {
  // NOT-A-NUMBER IS UNKNOWN, NOT HEALTHY. The guard tested only null and
  // undefined, so NaN and a numeric string sailed past it -- and because
  // NaN < 20 and NaN < 100 are both FALSE, it fell through and returned 'ok',
  // painting a GREEN bar for a value nobody measured. That is the exact
  // inversion this file exists to prevent, in the one function whose docblock
  // promises it returns null when the figure is unknown.
  if (!vol || !Number.isFinite(vol.freeBytes)) return null;
  const freeGb = vol.freeBytes / BYTES_IN_GB;
  if (freeGb < 20) return 'critical';
  if (freeGb < 100) return 'warning';
  return 'ok';
}

/**
 * Render a byte count for the Server tab.
 *
 * ⛔ PURE, AND IN THE LIB RATHER THAN THE COMPONENT, BECAUSE THE DECISION IT
 * MAKES IS NOT A RENDERING DETAIL. It decides when a number is a MEASUREMENT
 * and when it is an ABSENCE, which is the distinction this whole tab exists to
 * keep -- and a decision living inside a JSX file cannot be unit-tested at all
 * here: the repo carries no devDependencies and therefore no JSX transform, so
 * anything in a component is reachable only by a source-text scan.
 *
 * ⛔ IT USED TO FABRICATE A MEGABYTE. The component floored the sub-gigabyte
 * branch at `Math.max(1, ...)` so that a small table would not read "0 MB" and
 * look like nothing at all. The intent was right and the effect was the bug
 * this file's own header forbids: a relation measured at ZERO displayed as
 * "1 MB", a failed read wearing a plausible number. It masked a live defect for
 * as long as it existed -- pg_partition_tree() returns no rows for an ordinary
 * table, so every non-partitioned relation computed as 0 and the four largest
 * tables after syslog_events each rendered "1 MB" while really holding between
 * 326 MB and 1,926 MB (measured 2026-10-19).
 *
 * So: zero is reported AS zero, a real sub-megabyte value as "<1 MB", and only
 * a genuinely unreadable figure as unmeasured.
 *
 * @param {number|null|undefined} bytes
 * @returns {{text: string, unmeasured: boolean}} `unmeasured` true means the
 *   caller must render the hueless em-dash state, never a number.
 */
function formatBytes(bytes) {
  if (bytes === null || bytes === undefined || !Number.isFinite(Number(bytes))) {
    return { text: '—', unmeasured: true };
  }
  const n = Number(bytes);
  if (n < 0) return { text: '—', unmeasured: true };
  if (n === 0) return { text: '0 bytes', unmeasured: false };
  const gbv = n / BYTES_IN_GB;
  if (gbv < 1) {
    const mb = n / (1024 ** 2);
    // ⛔ Never Math.max(1, ...) here -- see the note above.
    return { text: mb < 1 ? '<1 MB' : `${Math.round(mb)} MB`, unmeasured: false };
  }
  return { text: `${gbv >= 100 ? gbv.toFixed(0) : gbv.toFixed(1)} GB`, unmeasured: false };
}

module.exports = {
  getServerHealth,
  getDiskUsage,
  getDatabaseSize,
  getSyslogRetention,
  getIngestHealth,
  getServiceLiveness,
  getProcessInfo,
  diskState,
  volumeFor,
  volumeKey,
  BYTES_IN_GB,
  formatBytes,
  getLastIngestGap,
};
