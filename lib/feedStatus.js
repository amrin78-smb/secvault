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
  // paloalto_psirt/fortinet_psirt added alongside nvd/kev when those feeds
  // shipped -- a feed that has genuinely never run yet (e.g. right after a
  // fresh deploy, before the engine's first scheduled sync) is intentionally
  // NOT treated as an error here, only a feed that ran and failed is.
  const known = ['nvd', 'paloalto_psirt', 'fortinet_psirt', 'kev'];
  const latestPerFeed = known.map((name) => lastSyncs.find((s) => s.feed_name === name));

  if (latestPerFeed.every((s) => !s)) {
    return { ok: false, label: 'NO SYNC YET', lastSyncs };
  }

  const anyError = latestPerFeed.some((s) => s && s.status === 'error');
  const ok = !anyError;

  return { ok, label: ok ? 'FEEDS OK' : 'FEED ERROR', lastSyncs };
}

module.exports = { getLastSyncs, getSyncPillStatus };
