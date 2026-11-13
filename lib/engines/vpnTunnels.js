// lib/engines/vpnTunnels.js
//
// Storage + retrieval for the LIVE IPSec site-to-site tunnel snapshot
// (vpn_ipsec_tunnels). Same live-snapshot discipline as vpnSessions.js:
// storeVpnTunnels() is DELETE+reinsert in ONE transaction, called by the
// engine-worker only after a SUCCESSFUL poll, so a failed pull never wipes the
// last-known set and an empty array legitimately clears the device's tunnels
// (none configured/up). Fed by the adapters' optional getVpnTunnels().
//
// ⛔ THE ANSWER IS TRI-STATE, AND `[]` IS ONLY ONE OF THE THREE (2026-11-13).
// An ARRAY is a measurement: `[]` means this device genuinely has no tunnels
// up, and clearing its rows is correct. `null`/`undefined` means NOT MEASURED
// — the pull ran but its answer could not be read — and the DELETE is SKIPPED,
// leaving the last-known rows with their own older `collected_at`.
//
// ⛔ IT WAS `Array.isArray(tunnels) ? tunnels : []`, WHICH TURNED EVERY
// UNREADABLE ANSWER INTO A WIPE. All FIVE implementations degraded a PARSE failure to
// an empty list (a vendor shape the normalizer did not expect), and
// `undefined` is what any method that falls off its own end returns — so a
// parse surprise on one tunnel deleted the device's whole tunnel set and
// `topology.js`'s `buildVpnEdges()` then drew the firewall with no tunnels at
// all. A confident wrong answer, not a gap, which is this codebase's signature
// bug; `vpnTunnelHealth.js` says the same thing about its own
// `no_rows_polled` state — "a poll that failed on a reachable device is
// indistinguishable here from a device with no tunnels".
//
// ⛔ THE HONEST OUTCOME WAS ALREADY BUILT AND WAS BEING BYPASSED. Keeping the
// rows lets `vpnTunnelHealth.classifyFreshness()` report the snapshot `stale`
// once it passes `staleAfterMinutes` (120) and collapse every status to
// `unmeasured`. That is also what ALREADY happens when the poll THROWS, so
// after this a parse failure and a transport failure behave alike — the
// inconsistency was the whole defect.
//
// ⛔ A NON-ARRAY, NON-NULL ANSWER THROWS rather than being coerced. A string
// or an object is a shape nobody intended, and guessing which of the other two
// states it meant is how the `: []` fallback got there in the first place.
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
 *
 * `tunnels` is TRI-STATE: an array is a measurement (`[]` = genuinely none),
 * `null`/`undefined` means the pull could not be read and the device's
 * existing rows are LEFT ALONE. Any other shape throws. See the header.
 *
 * @param {string} deviceId
 * @param {object[]|null|undefined} tunnels
 * @param {import('pg').Pool} pool
 * @returns {Promise<{count: number|null, measured: boolean}>}
 */
async function storeVpnTunnels(deviceId, tunnels, pool) {
  // ⛔ NOT MEASURED — RETURN BEFORE THE TRANSACTION OPENS, so there is no path
  // on which the DELETE has run and the reinsert has not.
  if (tunnels == null) {
    return { count: null, measured: false };
  }
  if (!Array.isArray(tunnels)) {
    throw new TypeError(
      `storeVpnTunnels: device ${deviceId} supplied a ${typeof tunnels} rather than an array of `
      + 'tunnels or null. An array means measured, null means not measured; a third shape is '
      + 'refused rather than guessed at, because coercing it is what silently wiped tunnel sets.'
    );
  }
  const list = tunnels;
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
    return { count: list.length, measured: true };
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
