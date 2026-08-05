// lib/engines/connectivityHistory.js
//
// Append-only fleet reachability log. See device_connectivity_history in
// lib/schema.sql for why it exists (devices.last_connectivity_ok is a single
// overwritten value, written only by the manual test button).
//
// CommonJS — called from API routes AND from services/engine-worker.js /
// lib/adapters/index.js under plain node.

'use strict';

const VALID_SOURCES = new Set(['test', 'collect', 'metrics']);

/**
 * Record one reachability observation.
 *
 * ⛔ NEVER THROWS. Every caller is doing something more important than logging
 * (running a connectivity test, collecting a config, polling metrics) and must
 * not fail because this insert did. A lost history row is a cosmetic gap in a
 * chart; a thrown error here would break a collect.
 *
 * @param {import('pg').Pool} pool
 * @param {string} deviceId
 * @param {{reachable:boolean, latencyMs?:number|null, source:string, message?:string|null}} obs
 */
async function recordConnectivity(pool, deviceId, obs) {
  try {
    if (!pool || !deviceId || !obs) return;
    const source = VALID_SOURCES.has(obs.source) ? obs.source : 'collect';
    const latency = Number.isFinite(obs.latencyMs) ? Math.round(obs.latencyMs) : null;
    await pool.query(
      `INSERT INTO device_connectivity_history (device_id, reachable, latency_ms, source, message)
       VALUES ($1, $2, $3, $4, $5)`,
      [deviceId, obs.reachable === true, latency, source, obs.message || null]
    );
  } catch (_err) {
    // Deliberately swallowed — see the never-throws note above.
  }
}

/**
 * Fleet reachability over a window, bucketed for a sparkline.
 *
 * ⛔ Returns the REAL sample density, not a fixed-width series. Buckets with no
 * observation are omitted entirely rather than emitted as zero — a gap in
 * sampling is not the same fact as "nothing was reachable", and drawing it as
 * a line to zero would invent an outage. The caller renders what it gets and
 * states the window.
 */
async function getFleetConnectivityTrend(pool, hours = 24, bucketMinutes = 60) {
  const { rows } = await pool.query(
    `SELECT
       to_timestamp(floor(extract(epoch FROM dch.checked_at) / ($2 * 60)) * ($2 * 60)) AS bucket,
       COUNT(DISTINCT dch.device_id) FILTER (WHERE dch.reachable)::int AS reachable,
       COUNT(DISTINCT dch.device_id)::int AS checked
     FROM device_connectivity_history dch
     JOIN devices d ON d.id = dch.device_id
     WHERE d.active = true
       AND dch.checked_at > now() - ($1 || ' hours')::interval
     GROUP BY bucket
     ORDER BY bucket`,
    [String(hours), bucketMinutes]
  );
  return rows.map((r) => ({
    bucket: r.bucket,
    reachable: r.reachable,
    checked: r.checked,
  }));
}

/**
 * Current reachability split, from the LATEST observation per device.
 * A device with no observation at all is 'never checked' — distinct from
 * 'unreachable', which is a measured failure.
 */
async function getFleetConnectivityNow(pool) {
  const { rows } = await pool.query(
    `WITH latest AS (
       SELECT DISTINCT ON (dch.device_id) dch.device_id, dch.reachable
         FROM device_connectivity_history dch
         JOIN devices d ON d.id = dch.device_id
        WHERE d.active = true
        ORDER BY dch.device_id, dch.checked_at DESC
     )
     SELECT
       (SELECT COUNT(*)::int FROM devices WHERE active = true) AS total,
       COUNT(*) FILTER (WHERE latest.reachable)::int AS reachable,
       COUNT(*) FILTER (WHERE NOT latest.reachable)::int AS unreachable
     FROM latest`
  );
  const r = rows[0] || { total: 0, reachable: 0, unreachable: 0 };
  return {
    total: r.total,
    reachable: r.reachable,
    unreachable: r.unreachable,
    neverChecked: Math.max(0, r.total - r.reachable - r.unreachable),
  };
}

module.exports = {
  recordConnectivity,
  getFleetConnectivityTrend,
  getFleetConnectivityNow,
  VALID_SOURCES,
};
