// lib/syslog/deviceMap.js
//
// The source-address -> device resolution the collector uses to attribute an
// incoming datagram.
//
// ── WHY THIS IS NOT INLINE IN services/collector.js ──────────────────────
// That file starts listeners on require, so nothing in it can be unit-tested —
// the same reason lib/syslog/eventShape.js was pulled out of it. The decision
// this module makes is a correctness decision about ATTRIBUTION, which is
// exactly the kind that must be testable by behaviour rather than by a regex
// over the source.
//
// ⛔ AN ADDRESS CLAIMED BY MORE THAN ONE DEVICE ATTRIBUTES TO NEITHER.
// One Forcepoint SMC manages many engines, so `smc_host` is routinely shared
// between devices. A last-writer-wins map would file every one of those
// devices' events under whichever row the query happened to return last — a
// FABRICATED ATTRIBUTION, indistinguishable from a real one once stored, and
// strictly worse than leaving the event unattributed, which this product
// already handles honestly ("an unmatched sender is still evidence").
// The same hazard exists for a shared `snmp_host`; it was simply never
// exercised by a fleet containing only two vendors.
//
// ⛔ `smc_host` MUST BE CONSULTED AT ALL. A Forcepoint device has NO `mgmt_ip`
// — it is reached through the SMC — so without it such a device's syslog can
// never be attributed. Measured on the six-vendor mock fleet before this
// existed: 637 Forcepoint events, every one stored with `device_id NULL`.
//
// ⛔ AN EXPLICIT ALIAS OVERRIDES AN AMBIGUITY. A `device_syslog_sources` row is
// an operator's deliberate statement about who sends from an address, and it
// outranks anything inferred from the inventory. That is also the documented
// way to RESOLVE a collision, which is why the ambiguity is reported rather
// than merely dropped.
//
// Pure: no DB, no clock, no I/O. Never throws.

'use strict';

/**
 * @param {Array<{id:string, mgmt_ip?:string, snmp_host?:string, smc_host?:string}>} deviceRows
 * @param {Array<{id:string, ip:string}>} aliasRows  device_syslog_sources
 * @returns {{map: Map<string,string>, ambiguous: Array<{ip:string, deviceIds:string[]}>}}
 *          `map` is safe to use directly; `ambiguous` is for reporting, and
 *          those addresses are deliberately ABSENT from the map.
 */
function buildDeviceMap(deviceRows, aliasRows) {
  const claims = new Map();           // ip -> Set<deviceId>

  const claim = (ip, id) => {
    if (ip === null || ip === undefined || id === null || id === undefined) return;
    const key = String(ip).trim();
    // An empty or whitespace-only column is absent information, not an address.
    if (key === '') return;
    if (!claims.has(key)) claims.set(key, new Set());
    claims.get(key).add(String(id));
  };

  for (const r of Array.isArray(deviceRows) ? deviceRows : []) {
    if (!r) continue;
    claim(r.mgmt_ip, r.id);
    claim(r.snmp_host, r.id);
    claim(r.smc_host, r.id);
  }

  const map = new Map();
  const ambiguous = [];
  for (const [ip, ids] of claims) {
    if (ids.size === 1) map.set(ip, [...ids][0]);
    else ambiguous.push({ ip, deviceIds: [...ids].sort() });
  }

  // Applied AFTER, so an explicit alias both adds an address and resolves an
  // ambiguous one.
  for (const r of Array.isArray(aliasRows) ? aliasRows : []) {
    if (!r || r.ip === null || r.ip === undefined) continue;
    const key = String(r.ip).trim();
    if (key === '' || r.id === null || r.id === undefined) continue;
    map.set(key, String(r.id));
  }

  // An address an alias resolved is no longer ambiguous.
  const stillAmbiguous = ambiguous.filter((a) => !map.has(a.ip));
  return { map, ambiguous: stillAmbiguous };
}

module.exports = { buildDeviceMap };
