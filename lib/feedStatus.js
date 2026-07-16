// lib/feedStatus.js
// Shared feed_sync_log status helper. Previously this exact query lived
// inline in app/(dashboard)/advisories/page.js's getLastSyncs() — pulled out
// here so the header's sync-status pill and the Advisories page read from
// the same source instead of maintaining two copies of the same SQL.

'use strict';

/**
 * @param {import('pg').Pool} pool
 * @returns {Promise<object[]>} up to 10 most recent feed_sync_log rows
 */
async function getLastSyncs(pool) {
  const result = await pool.query(
    `SELECT feed_name, status, started_at, finished_at
     FROM feed_sync_log
     ORDER BY started_at DESC
     LIMIT 10`
  );
  return result.rows;
}

/**
 * Condensed status for the header pill: ok when the most recent run of every
 * known feed succeeded, degraded on any partial/error, unknown with no data.
 * @param {import('pg').Pool} pool
 * @returns {Promise<{ok: boolean, label: string, lastSyncs: object[]}>}
 */
async function getSyncPillStatus(pool) {
  const lastSyncs = await getLastSyncs(pool);
  const lastNvd = lastSyncs.find((s) => s.feed_name === 'nvd');
  const lastKev = lastSyncs.find((s) => s.feed_name === 'kev');

  if (!lastNvd && !lastKev) {
    return { ok: false, label: 'NO SYNC YET', lastSyncs };
  }

  const anyError = [lastNvd, lastKev].some((s) => s && s.status === 'error');
  const ok = !anyError;

  return { ok, label: ok ? 'FEEDS OK' : 'FEED ERROR', lastSyncs };
}

module.exports = { getLastSyncs, getSyncPillStatus };
