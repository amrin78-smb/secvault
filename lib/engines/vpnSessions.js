// lib/engines/vpnSessions.js
//
// Storage + retrieval for the LIVE per-user VPN active-session snapshot
// (vpn_active_sessions). This is the detail behind the coarse
// active_session_count in vpn_session_snapshots — the per-user rows the
// management-plane commands SecVault already runs return (see each adapter's
// getVpnSessionSummary()), NOT syslog data.
//
// storeVpnSessions() is DELETE+reinsert in ONE transaction: the table always
// holds exactly the CURRENT connected set for a device, never history. The
// engine-worker only ever calls this after a SUCCESSFUL poll, so a failed pull
// never wipes the last-known set; an empty array from a successful poll
// legitimately clears the device's rows (nobody is connected right now).
//
// Takes `pool` as a parameter per CLAUDE.md (never omit pool from a DB
// function). Session objects are the vendor-agnostic normalized shape produced
// by the adapters:
//   { username, tunnel_type, source_ip, assigned_ip, login_time,
//     duration_seconds, bytes_in, bytes_out, client, gateway, raw }
// Any field may be null/absent — different vendors report different subsets.

'use strict';

function numericOrNull(v) {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

function textOrNull(v) {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

/**
 * Replace a device's active-session rows with `sessions` in one transaction.
 * @param {string} deviceId
 * @param {object[]} sessions - normalized session objects (see file header)
 * @param {import('pg').Pool} pool
 * @returns {Promise<{count: number}>}
 */
async function storeVpnSessions(deviceId, sessions, pool) {
  const list = Array.isArray(sessions) ? sessions : [];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM vpn_active_sessions WHERE device_id = $1', [deviceId]);
    for (const s of list) {
      const rec = s && typeof s === 'object' ? s : {};
      await client.query(
        `INSERT INTO vpn_active_sessions
           (device_id, username, tunnel_type, source_ip, assigned_ip, login_time,
            duration_seconds, bytes_in, bytes_out, client, gateway, raw)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb)`,
        [
          deviceId,
          textOrNull(rec.username),
          textOrNull(rec.tunnel_type),
          textOrNull(rec.source_ip),
          textOrNull(rec.assigned_ip),
          textOrNull(rec.login_time),
          numericOrNull(rec.duration_seconds),
          numericOrNull(rec.bytes_in),
          numericOrNull(rec.bytes_out),
          textOrNull(rec.client),
          textOrNull(rec.gateway),
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
 * The current active-session rows for a device, ordered by username.
 * @param {string} deviceId
 * @param {import('pg').Pool} pool
 * @returns {Promise<object[]>}
 */
async function getVpnSessions(deviceId, pool) {
  const { rows } = await pool.query(
    `SELECT username, tunnel_type, source_ip, assigned_ip, login_time,
            duration_seconds, bytes_in, bytes_out, client, gateway, collected_at
     FROM vpn_active_sessions
     WHERE device_id = $1
     ORDER BY username ASC NULLS LAST`,
    [deviceId]
  );
  return rows;
}

module.exports = { storeVpnSessions, getVpnSessions };
