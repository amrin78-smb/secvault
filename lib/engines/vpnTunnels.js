// lib/engines/vpnTunnels.js
//
// Storage + retrieval for the LIVE IPSec site-to-site tunnel snapshot
// (vpn_ipsec_tunnels). Same live-snapshot discipline as vpnSessions.js:
// storeVpnTunnels() is DELETE+reinsert in ONE transaction, called by the
// engine-worker only after a SUCCESSFUL poll, so a failed pull never wipes the
// last-known set and an empty array legitimately clears the device's tunnels
// (none configured/up). Fed by the adapters' optional getVpnTunnels().
//
// Takes `pool` per CLAUDE.md. Tunnel objects are the vendor-agnostic shape:
//   { name, peer, status, ike_version, bytes_in, bytes_out, raw }
// Any field may be null.

'use strict';

function numericOrNull(v) {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

function textOrNull(v) {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

/**
 * Replace a device's IPSec tunnel rows with `tunnels` in one transaction.
 * @param {string} deviceId
 * @param {object[]} tunnels
 * @param {import('pg').Pool} pool
 * @returns {Promise<{count: number}>}
 */
async function storeVpnTunnels(deviceId, tunnels, pool) {
  const list = Array.isArray(tunnels) ? tunnels : [];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM vpn_ipsec_tunnels WHERE device_id = $1', [deviceId]);
    for (const t of list) {
      const rec = t && typeof t === 'object' ? t : {};
      await client.query(
        `INSERT INTO vpn_ipsec_tunnels
           (device_id, name, peer, status, ike_version, bytes_in, bytes_out, raw)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
        [
          deviceId,
          textOrNull(rec.name),
          textOrNull(rec.peer),
          textOrNull(rec.status),
          textOrNull(rec.ike_version),
          numericOrNull(rec.bytes_in),
          numericOrNull(rec.bytes_out),
          JSON.stringify(rec.raw == null ? null : rec.raw),
        ]
      );
    }
    await client.query('COMMIT');
    return { count: list.length };
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (_rollbackErr) {
      /* ignore rollback failure — surface the original error */
    }
    throw err;
  } finally {
    client.release();
  }
}

/**
 * The current IPSec tunnel rows for a device.
 * @param {string} deviceId
 * @param {import('pg').Pool} pool
 * @returns {Promise<object[]>}
 */
async function getVpnTunnels(deviceId, pool) {
  const { rows } = await pool.query(
    `SELECT name, peer, status, ike_version, bytes_in, bytes_out, collected_at
     FROM vpn_ipsec_tunnels
     WHERE device_id = $1
     ORDER BY name ASC NULLS LAST`,
    [deviceId]
  );
  return rows;
}

module.exports = { storeVpnTunnels, getVpnTunnels };
