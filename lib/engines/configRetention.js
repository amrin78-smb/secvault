// lib/engines/configRetention.js
//
// Retention for the two config-snapshot tables, `device_configs` and
// `config_backups`.
//
// Why this exists: measured on the live fleet 2026-08-25, `device_configs` was
// 447 MB of a 529 MB database (84%) after 41 days of collection — ~9.5 MB/day,
// ~3.4 GB/year, with no retention of any kind. Almost all of that is TOASTed
// `config_raw`/`config_parsed` (heap is 200 kB); a single Palo Alto snapshot
// averages 250-515 kB and the fleet stores one per device per day whether or
// not anything changed.
//
// What is deliberately NOT deleted (and why it is safe to delete the rest):
//   - the CHANGE record lives in `config_diffs` (append-only, its own stored
//     JSONB payload, no reference to any `device_configs` row) — it is not
//     touched by this engine at all, so "what changed and when" survives any
//     retention window;
//   - a full copy of the config AT each detected change lives in
//     `config_backups` (written by configDiff.js's createBackup() only when a
//     diff was detected), which gets its own much longer window here;
//   - so what retention actually removes from `device_configs` is the long
//     tail of snapshots that were identical to their predecessor.
//
// ⛔ FOUR PROTECTIONS, none of them optional. Each is expressed twice (once in
// the classification query, once in the DELETE predicate) on purpose — this
// file deletes real customer data and a single mis-edited clause must not be
// the only thing standing between a retention run and a data-loss incident:
//   1. `device_configs.is_baseline = true` is NEVER deleted, at any age. It is
//      an operator-designated known-good snapshot and the comparison target
//      for baseline drift (see CLAUDE.md "Baseline config drift"). The partial
//      unique index guarantees at most one per device; losing it silently
//      turns drift detection into "no drift", the most dangerous wrong answer.
//   2. The NEWEST row per device is NEVER deleted, at any age. A device that
//      stopped being collected two years ago must still show its last known
//      config. "Retention deleted the only copy" is strictly worse than a
//      large database.
//   3. A minimum COUNT per device is kept regardless of age (MIN_KEEP_*), so
//      age alone can never empty a device's history.
//   4. `config_backups` rows whose `label` is not 'auto' (i.e. 'manual' /
//      'pre-change', operator-created) are NEVER deleted, at any age — same
//      reasoning as is_baseline: operator intent outranks a size budget.
//
// Nothing in the schema references either table by id (verified empirically
// against the live DB: the only FK on/into `device_configs`/`config_backups`
// is their own `device_id -> devices(id)`; `config_diffs` stores no config id),
// so a retention delete can never orphan a row in another table.
//
// CommonJS — services/engine-worker.js require()s this under plain node.

'use strict';

// Defaults. Exported so services/engine-worker.js, .env.local.example and
// CLAUDE.md's env list can't drift from each other — the worker imports these
// as its env-parsing fallbacks rather than hardcoding its own copy.
//
// CONFIG_RETENTION_DAYS = 60: bounds `device_configs` at roughly 60 x the
// fleet's daily config volume (~570 MB at the measured 9.5 MB/day) instead of
// growing without limit, while staying longer than any diff/compare window the
// UI offers and longer than a monthly audit cycle. It is also, deliberately,
// longer than the oldest row that existed when retention shipped (41 days) —
// the first production run of a destructive job being a provable no-op is a
// feature. An operator who wants space back now sets 30 (frees ~150 MB on the
// measured fleet, steady state ~285 MB).
const DEFAULT_CONFIG_RETENTION_DAYS = 60;

// CONFIG_BACKUP_RETENTION_DAYS = 365, deliberately much longer than the above:
// `config_backups` is only written when a diff was actually detected, so each
// row is a distinct moment of real change (162 rows / 25 MB on the measured
// fleet, ~1.5% of `device_configs`' volume). Applying the shorter window here
// would destroy the long-term change record to save almost nothing.
const DEFAULT_BACKUP_RETENTION_DAYS = 365;

// Minimum rows kept per device regardless of age. Constants, not env vars, on
// purpose: these are safety floors, not tuning knobs — exposing them invites
// setting them to 0, which removes protection 3 entirely. Both are clamped to
// >= 1 below so protection 2 (newest per device) holds even if a future edit
// passes 0.
const MIN_KEEP_CONFIGS = 10;
const MIN_KEEP_BACKUPS = 5;

// Ceiling on rows removed per table per run. Retention runs at every service
// start AND daily, so a large backlog drains over a few runs instead of one
// multi-gigabyte transaction with its matching WAL burst. When the cap bites,
// the summary says so (`capped: true`) rather than silently reporting a small
// number as if it were the whole job.
const DEFAULT_MAX_ROWS_PER_RUN = 5000;

// The only auto-generated backup label; everything else means a human made it.
const AUTO_BACKUP_LABEL = 'auto';

function clampPositiveInt(value, fallback, min) {
  const n = parseInt(value, 10);
  if (Number.isInteger(n) && n >= min) return n;
  return fallback;
}

function emptyTableSummary(retentionDays, minKeepPerDevice) {
  return {
    retentionDays,
    minKeepPerDevice,
    totalRows: 0,
    devices: 0,
    deleted: 0,
    wouldDelete: 0,
    capped: false,
    kept: { baseline: 0, newestPerDevice: 0, minKeep: 0, withinWindow: 0, total: 0 },
    perDevice: [],
    error: null,
  };
}

// ---------------------------------------------------------------------------
// SQL. Written out per table rather than generated from a table-name template
// so every predicate that protects a row is readable in place, and so every
// value is a real bind parameter (CLAUDE.md: parameterized queries only, no
// interpolation).
//
// The CLASSIFY queries sort every row into exactly one mutually-exclusive
// bucket, in protection order, using the SAME window function and cutoff as
// the matching DELETE — so the "kept" numbers reported to the operator are
// derived from the delete's own logic, not a separate approximation that could
// drift from it. Their `deletable` bucket is precisely the DELETE's target set.
//
// The DELETE queries are deliberately redundant:
//   - `rn > $2` already implies `rn > 1` (minKeep is clamped to >= 1), and
//     `rn > 1` is restated anyway so "never delete the newest row for a
//     device" does not depend on the value of a variable;
//   - the protected-row test is applied inside `victims` AND again on the
//     outer DELETE, so a row can only be removed if it fails that test twice.
// Ordering is oldest-first so the LIMIT cap (when it bites) always removes the
// oldest rows; `id` breaks timestamp ties so repeat runs are deterministic.
// ---------------------------------------------------------------------------

// $1 = retention days, $2 = min keep per device
const CLASSIFY_DEVICE_CONFIGS_SQL = `
  WITH ranked AS (
    SELECT
      collected_at AS ts,
      (is_baseline IS NOT FALSE) AS is_protected,
      row_number() OVER (PARTITION BY device_id ORDER BY collected_at DESC, id DESC) AS rn
    FROM device_configs
  )
  SELECT
    CASE
      WHEN is_protected THEN 'protected'
      WHEN rn = 1 THEN 'newest'
      WHEN rn <= $2 THEN 'min_keep'
      WHEN ts >= now() - ($1 || ' days')::interval THEN 'within_window'
      ELSE 'deletable'
    END AS bucket,
    count(*)::int AS rows
  FROM ranked
  GROUP BY 1`;

// $1 = retention days, $2 = min keep per device, $3 = max rows this run
const DELETE_DEVICE_CONFIGS_SQL = `
  WITH ranked AS (
    SELECT
      id,
      collected_at AS ts,
      (is_baseline IS NOT FALSE) AS is_protected,
      row_number() OVER (PARTITION BY device_id ORDER BY collected_at DESC, id DESC) AS rn
    FROM device_configs
  ),
  victims AS (
    SELECT id
    FROM ranked
    WHERE rn > $2
      AND rn > 1
      AND is_protected = false
      AND ts < now() - ($1 || ' days')::interval
    ORDER BY ts ASC, id ASC
    LIMIT $3
  )
  DELETE FROM device_configs t
  USING victims v
  WHERE t.id = v.id
    AND t.is_baseline IS FALSE
  RETURNING t.device_id`;

// $1 = retention days, $2 = min keep per device, $3 = the 'auto' label
const CLASSIFY_CONFIG_BACKUPS_SQL = `
  WITH ranked AS (
    SELECT
      backed_up_at AS ts,
      (label IS DISTINCT FROM $3) AS is_protected,
      row_number() OVER (PARTITION BY device_id ORDER BY backed_up_at DESC, id DESC) AS rn
    FROM config_backups
  )
  SELECT
    CASE
      WHEN is_protected THEN 'protected'
      WHEN rn = 1 THEN 'newest'
      WHEN rn <= $2 THEN 'min_keep'
      WHEN ts >= now() - ($1 || ' days')::interval THEN 'within_window'
      ELSE 'deletable'
    END AS bucket,
    count(*)::int AS rows
  FROM ranked
  GROUP BY 1`;

// $1 = retention days, $2 = min keep, $3 = max rows this run, $4 = 'auto' label
const DELETE_CONFIG_BACKUPS_SQL = `
  WITH ranked AS (
    SELECT
      id,
      backed_up_at AS ts,
      (label IS DISTINCT FROM $4) AS is_protected,
      row_number() OVER (PARTITION BY device_id ORDER BY backed_up_at DESC, id DESC) AS rn
    FROM config_backups
  ),
  victims AS (
    SELECT id
    FROM ranked
    WHERE rn > $2
      AND rn > 1
      AND is_protected = false
      AND ts < now() - ($1 || ' days')::interval
    ORDER BY ts ASC, id ASC
    LIMIT $3
  )
  DELETE FROM config_backups t
  USING victims v
  WHERE t.id = v.id
    AND t.label IS NOT DISTINCT FROM $4
  RETURNING t.device_id`;

async function retainTable(pool, opts) {
  const { classifySql, classifyParams, deleteSql, deleteParams, retentionDays, minKeep, maxRows, dryRun } = opts;
  const summary = emptyTableSummary(retentionDays, minKeep);
  try {
    const classified = await pool.query(classifySql, classifyParams);
    for (const row of classified.rows) {
      const n = row.rows || 0;
      summary.totalRows += n;
      if (row.bucket === 'protected') summary.kept.baseline += n;
      else if (row.bucket === 'newest') summary.kept.newestPerDevice += n;
      else if (row.bucket === 'min_keep') summary.kept.minKeep += n;
      else if (row.bucket === 'within_window') summary.kept.withinWindow += n;
      else if (row.bucket === 'deletable') summary.wouldDelete += n;
    }
    summary.kept.total =
      summary.kept.baseline + summary.kept.newestPerDevice + summary.kept.minKeep + summary.kept.withinWindow;

    if (dryRun) {
      summary.capped = summary.wouldDelete > maxRows;
      return summary;
    }

    const deleted = await pool.query(deleteSql, deleteParams);
    summary.deleted = deleted.rowCount || 0;
    summary.capped = summary.deleted >= maxRows && summary.wouldDelete > maxRows;

    const byDevice = new Map();
    for (const row of deleted.rows) {
      byDevice.set(row.device_id, (byDevice.get(row.device_id) || 0) + 1);
    }
    summary.devices = byDevice.size;
    if (byDevice.size > 0) {
      // Names are looked up after the fact rather than joined into the DELETE:
      // a device row could theoretically vanish between the two statements, and
      // a missing name must degrade to the id, never fail the retention run.
      let names = new Map();
      try {
        const nameRows = await pool.query('SELECT id, name FROM devices WHERE id = ANY($1::uuid[])', [
          [...byDevice.keys()],
        ]);
        names = new Map(nameRows.rows.map((r) => [r.id, r.name]));
      } catch (_err) {
        /* names are cosmetic — fall through to ids */
      }
      summary.perDevice = [...byDevice.entries()]
        .map(([deviceId, count]) => ({ deviceId, name: names.get(deviceId) || deviceId, deleted: count }))
        .sort((a, b) => b.deleted - a.deleted);
    }
  } catch (err) {
    // Never rethrown: the caller is a scheduled job and one table's failure
    // must neither crash the engine service nor skip the other table.
    summary.error = err && err.message ? err.message : String(err);
  }
  return summary;
}

/**
 * Run retention over `device_configs` + `config_backups`.
 *
 * Idempotent and safe to re-run: it deletes only rows that are simultaneously
 * older than the window, outside the per-device minimum-keep set, not the
 * newest for their device, and not protected (baseline / non-'auto' label). A
 * second run immediately after the first deletes nothing.
 *
 * ⛔ NEVER THROWS. Returns a summary describing what it deleted AND what it
 * deliberately kept, so an operator reading engine.log can tell retention from
 * data loss.
 *
 * @param {import('pg').Pool} pool
 * @param {{configRetentionDays?:number, backupRetentionDays?:number,
 *          minKeepConfigs?:number, minKeepBackups?:number,
 *          maxRowsPerRun?:number, dryRun?:boolean}} [options]
 * @returns {Promise<object>} summary
 */
async function runConfigRetention(pool, options = {}) {
  const start = Date.now();
  const opts = options || {};
  const dryRun = opts.dryRun === true;
  const configRetentionDays = clampPositiveInt(opts.configRetentionDays, DEFAULT_CONFIG_RETENTION_DAYS, 1);
  const backupRetentionDays = clampPositiveInt(opts.backupRetentionDays, DEFAULT_BACKUP_RETENTION_DAYS, 1);
  // Clamped to >= 1: protection 2 (newest per device) must hold even if a
  // caller passes 0 or a negative.
  const minKeepConfigs = clampPositiveInt(opts.minKeepConfigs, MIN_KEEP_CONFIGS, 1);
  const minKeepBackups = clampPositiveInt(opts.minKeepBackups, MIN_KEEP_BACKUPS, 1);
  const maxRowsPerRun = clampPositiveInt(opts.maxRowsPerRun, DEFAULT_MAX_ROWS_PER_RUN, 1);

  if (!pool) {
    return {
      dryRun,
      durationMs: 0,
      deviceConfigs: { ...emptyTableSummary(configRetentionDays, minKeepConfigs), error: 'no pool supplied' },
      configBackups: { ...emptyTableSummary(backupRetentionDays, minKeepBackups), error: 'no pool supplied' },
    };
  }

  // `is_baseline IS NOT FALSE` (rather than `= true`): a NULL is_baseline —
  // impossible under the current NOT NULL column, but free to guard — counts
  // as PROTECTED, never as deletable.
  const deviceConfigs = await retainTable(pool, {
    classifySql: CLASSIFY_DEVICE_CONFIGS_SQL,
    classifyParams: [String(configRetentionDays), minKeepConfigs],
    deleteSql: DELETE_DEVICE_CONFIGS_SQL,
    deleteParams: [String(configRetentionDays), minKeepConfigs, maxRowsPerRun],
    retentionDays: configRetentionDays,
    minKeep: minKeepConfigs,
    maxRows: maxRowsPerRun,
    dryRun,
  });

  // Anything whose label is not exactly 'auto' — including NULL — was created
  // by an operator and is permanently protected.
  const configBackups = await retainTable(pool, {
    classifySql: CLASSIFY_CONFIG_BACKUPS_SQL,
    classifyParams: [String(backupRetentionDays), minKeepBackups, AUTO_BACKUP_LABEL],
    deleteSql: DELETE_CONFIG_BACKUPS_SQL,
    deleteParams: [String(backupRetentionDays), minKeepBackups, maxRowsPerRun, AUTO_BACKUP_LABEL],
    retentionDays: backupRetentionDays,
    minKeep: minKeepBackups,
    maxRows: maxRowsPerRun,
    dryRun,
  });

  return { dryRun, durationMs: Date.now() - start, deviceConfigs, configBackups };
}

/**
 * One-line-per-table human summary for engine.log. Says what was deleted AND
 * what was kept, broken down by which protection kept it.
 *
 * @param {object} summary - the object returned by runConfigRetention()
 * @returns {string[]} lines
 */
function formatRetentionSummary(summary) {
  if (!summary) return ['config retention produced no summary.'];
  const lines = [];
  const describe = (label, t, protectedLabel) => {
    if (!t) return;
    if (t.error) {
      lines.push(`${label}: FAILED — ${t.error} (nothing deleted from this table).`);
      return;
    }
    const action = summary.dryRun
      ? `would delete ${t.wouldDelete} row(s)`
      : `deleted ${t.deleted} row(s) across ${t.devices} device(s)`;
    const capped = t.capped ? ` [capped at ${t.wouldDelete} eligible — remainder next run]` : '';
    lines.push(
      `${label}: ${action}${capped}; kept ${t.kept.total} of ${t.totalRows} ` +
        `(${t.kept.baseline} ${protectedLabel}, ${t.kept.newestPerDevice} newest-per-device, ` +
        `${t.kept.minKeep} within min-keep ${t.minKeepPerDevice}, ${t.kept.withinWindow} within ${t.retentionDays}d window).`
    );
    if (t.perDevice && t.perDevice.length > 0) {
      const shown = t.perDevice.slice(0, 20).map((d) => `${d.name}=${d.deleted}`);
      const more = t.perDevice.length > shown.length ? `, +${t.perDevice.length - shown.length} more` : '';
      lines.push(`${label} per device: ${shown.join(', ')}${more}.`);
    }
  };
  describe('device_configs', summary.deviceConfigs, 'baseline');
  describe('config_backups', summary.configBackups, 'operator-labelled');
  return lines;
}

module.exports = {
  runConfigRetention,
  formatRetentionSummary,
  DEFAULT_CONFIG_RETENTION_DAYS,
  DEFAULT_BACKUP_RETENTION_DAYS,
  MIN_KEEP_CONFIGS,
  MIN_KEEP_BACKUPS,
  DEFAULT_MAX_ROWS_PER_RUN,
  AUTO_BACKUP_LABEL,
};
