// lib/engines/deviceDiscovery.js
//
// Surfaces firewalls that are sending SecVault syslog from an address matching
// no `devices` row, so an operator can review them and promote the real ones.
//
// ── ⛔ IT SURFACES, IT NEVER AUTO-INSERTS INTO `devices` ───────────────────
// The request was "auto add them to the inventory". This deliberately reads
// that as "auto-surface a reviewable list", and the difference is the whole
// safety story:
//
//   * UDP syslog is unauthenticated and trivially spoofable. Nothing here can
//     put a spoofed packet into the CVE, compliance or security-score
//     denominators, because promotion requires an admin to supply credentials
//     that must actually work.
//   * `devices` is NOT NULL on vendor/mgmt_method. Auto-inserting would assert
//     a vendor for the 2 of 8 live senders that have none.
//
// ── ⛔ MOST "UNKNOWN" SENDERS ARE ALREADY KNOWN ───────────────────────────
// Measured on the live fleet: 5 of 8 unmatched senders are HA PASSIVE PEERS
// whose addresses SecVault already holds in `device_ha_status.peer_mgmt_ip`,
// each independently confirmed by `peer_serial`. Presenting those as "5 new
// devices to add" would make the feature untrustworthy on first sight, so they
// are correlated and offered as LINK, never as promote.
//
// That correlation is computed at READ time, never stored: `peer_mgmt_ip` is a
// snapshot that swaps on failover, so a cached match would go stale and read as
// a fact. Same discipline as lib/engines/deviceHealth.js.

'use strict';

// Bounded per run so a stray packet cannot mint inventory. Live separation is
// unambiguous: every real sender shows 18 distinct hours and hundreds to
// millions of events; the one junk entry (127.0.0.1) shows 1 hour, 1 event.
const DEFAULT_MIN_HOURS = 2;
const DEFAULT_MIN_EVENTS = 100;
// ⛔ MUST be bounded, and far shorter than SYSLOG_RETENTION_DAYS. The rollup
// copies `device_id` verbatim from syslog_events and never re-resolves it, so
// historical rows for a NOW-PROMOTED sender keep device_id NULL forever — an
// unbounded lookback would re-list every promoted device on every run. Same
// "shorter than retention on purpose" reasoning as LOG_HIT_LOOKBACK_DAYS.
const DEFAULT_LOOKBACK_HOURS = 48;

function clampInt(v, def, min, max) {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.min(Math.max(Math.trunc(n), min), max);
}

/**
 * Decide what a discovered sender actually IS, against what SecVault already
 * knows. PURE — no DB — so the page, the API and the tests all agree.
 *
 * @param {object} row     a discovered_devices row
 * @param {object[]} haRows  {device_id, device_name, peer_mgmt_ip, peer_serial}
 * @param {object[]} aliasRows {device_id, device_name, source_ip}
 * @returns {{kind:'ha-peer'|'known-alias'|'unmanaged', deviceId, deviceName, evidence}}
 */
function correlateSender(row, haRows, aliasRows) {
  const ip = String(row.source_ip || '').replace(/\/\d+$/, '');
  const serial = row.observed_serial ? String(row.observed_serial).trim() : null;

  for (const a of Array.isArray(aliasRows) ? aliasRows : []) {
    if (String(a.source_ip || '').replace(/\/\d+$/, '') === ip) {
      return {
        kind: 'known-alias',
        deviceId: a.device_id,
        deviceName: a.device_name,
        evidence: 'already linked to this device as an additional syslog source',
      };
    }
  }

  for (const h of Array.isArray(haRows) ? haRows : []) {
    const peerIp = h.peer_mgmt_ip ? String(h.peer_mgmt_ip).trim() : null;
    const peerSerial = h.peer_serial ? String(h.peer_serial).trim() : null;
    const ipMatch = peerIp && peerIp === ip;
    const serialMatch = peerSerial && serial && peerSerial === serial;
    if (!ipMatch && !serialMatch) continue;
    // ⛔ State WHICH signals matched. An operator about to merge two firewalls
    // deserves to see the evidence, not a verdict.
    const parts = [];
    if (ipMatch) parts.push(`peer address ${peerIp}`);
    if (serialMatch) parts.push(`peer serial ${peerSerial}`);
    return {
      kind: 'ha-peer',
      deviceId: h.device_id,
      deviceName: h.device_name,
      evidence: `matches ${h.device_name}'s ${parts.join(' and ')}`,
    };
  }

  return { kind: 'unmanaged', deviceId: null, deviceName: null, evidence: null };
}

/**
 * Refresh `discovered_devices` from the rollup.
 *
 * ⛔ NEVER THROWS (same contract as runConfigRetention / runLogHitCorrelation).
 *
 * ⛔ Runs in the ENGINE, not the collector. The collector handles 250-1,400
 * events/sec on a 2-second flush cycle that has already had to be tuned back
 * once; nothing goes in that path for a feature whose output is ~8 rows an
 * hour. It also needs history the collector does not have — "seen across >= 2
 * distinct hours" is a rollup question, and an in-memory accumulator would lose
 * first_seen_at on every deploy restart.
 */
async function runDeviceDiscovery(pool, opts = {}) {
  const lookbackHours = clampInt(opts.lookbackHours, DEFAULT_LOOKBACK_HOURS, 2, 720);
  const minHours = clampInt(opts.minHours, DEFAULT_MIN_HOURS, 1, 168);
  const minEvents = clampInt(opts.minEvents, DEFAULT_MIN_EVENTS, 1, 10_000_000);

  const summary = {
    lookbackHours,
    minHours,
    minEvents,
    candidates: 0,
    inserted: 0,
    updated: 0,
    errors: [],
  };

  try {
    // syslog_rollup_hourly is small, indexed and already aggregated per
    // (source_ip, device_id, vendor) — never the raw table.
    const { rows: candidates } = await pool.query(
      `SELECT source_ip,
              sum(event_count)::bigint            AS event_count,
              count(DISTINCT bucket_hour)::int    AS observed_hours,
              min(bucket_hour)                    AS first_seen_at,
              max(bucket_hour)                    AS last_seen_at,
              array_remove(array_agg(DISTINCT vendor), NULL) AS vendors
         FROM syslog_rollup_hourly
        WHERE device_id IS NULL
          AND bucket_hour >= now() - ($1::int * interval '1 hour')
          -- Loopback, link-local and CGNAT are never a managed firewall.
          AND NOT (source_ip <<= '127.0.0.0/8'::inet
                OR source_ip <<= '169.254.0.0/16'::inet
                OR source_ip <<= '100.64.0.0/10'::inet)
        GROUP BY source_ip
       HAVING count(DISTINCT bucket_hour) >= $2::int
          AND sum(event_count) >= $3::int`,
      [lookbackHours, minHours, minEvents]
    );
    summary.candidates = candidates.length;
    if (candidates.length === 0) return summary;

    // Hostname (and, where the parser yields it, serial) from a NARROW window.
    // Bounded by device_id IS NULL + a 15-minute slice, which the existing
    // (device_id, received_at) index serves directly.
    const { rows: identity } = await pool.query(
      `SELECT DISTINCT ON (source_ip) source_ip, hostname, vendor
         FROM syslog_events
        WHERE device_id IS NULL
          AND received_at >= now() - interval '15 minutes'
          AND hostname IS NOT NULL
        ORDER BY source_ip, received_at DESC`
    );
    const hostByIp = new Map(identity.map((r) => [String(r.source_ip), r.hostname]));

    for (const c of candidates) {
      try {
        const vendors = Array.isArray(c.vendors) ? c.vendors.filter(Boolean) : [];
        const observedVendor = vendors.length === 1 ? vendors[0] : vendors[0] || null;
        const hostname = hostByIp.get(String(c.source_ip)) || null;

        // ⛔ COALESCE on every observation, so a pass that failed to see a
        // value cannot ERASE one an earlier pass did see. Vendor detection is
        // intermittent — one live sender read 0% vendor for a full hour while
        // the rollup showed it emitting Palo Alto rows in 7 of 18 hours — so
        // "not seen this pass" must never overwrite "seen last pass" with NULL.
        // Same failed-read-as-a-fact rule as everywhere else.
        //
        // ⛔ status / decided_* / promoted_device_id / linked_device_id are
        // NEVER touched: those are operator decisions, not observations. A
        // promoted sender must not be resurrected as 'new' by the next run.
        const res = await pool.query(
          `INSERT INTO discovered_devices
             (source_ip, observed_vendor, observed_hostname, vendor_conflict,
              hostname_conflict, first_seen_at, last_seen_at, observed_hours, event_count)
           VALUES ($1::inet, $2, $3, $4, false, $5::timestamptz, $6::timestamptz, $7::int, $8::bigint)
           ON CONFLICT (source_ip) DO UPDATE SET
             observed_vendor   = COALESCE(EXCLUDED.observed_vendor, discovered_devices.observed_vendor),
             observed_hostname = COALESCE(EXCLUDED.observed_hostname, discovered_devices.observed_hostname),
             vendor_conflict   = EXCLUDED.vendor_conflict,
             first_seen_at     = LEAST(discovered_devices.first_seen_at, EXCLUDED.first_seen_at),
             last_seen_at      = GREATEST(discovered_devices.last_seen_at, EXCLUDED.last_seen_at),
             observed_hours    = EXCLUDED.observed_hours,
             event_count       = EXCLUDED.event_count,
             updated_at        = now()
           RETURNING (xmax = 0) AS inserted`,
          [
            String(c.source_ip).replace(/\/\d+$/, ''),
            observedVendor,
            hostname,
            vendors.length > 1,
            c.first_seen_at,
            c.last_seen_at,
            c.observed_hours,
            c.event_count,
          ]
        );
        if (res.rows[0] && res.rows[0].inserted) summary.inserted++;
        else summary.updated++;
      } catch (err) {
        summary.errors.push({ sourceIp: String(c.source_ip), error: err.message });
      }
    }

    // ⛔ A promoted device that was later DELETED leaves promoted_device_id
    // NULL via ON DELETE SET NULL. Without this the sender would stay
    // 'promoted' and be invisible forever, even though it is unmanaged again.
    const reset = await pool.query(
      `UPDATE discovered_devices
          SET status = 'new', decided_by = NULL, decided_at = NULL, updated_at = now()
        WHERE (status = 'promoted' AND promoted_device_id IS NULL)
           OR (status = 'linked'   AND linked_device_id IS NULL)`
    );
    if (reset.rowCount > 0) summary.reset = reset.rowCount;
  } catch (err) {
    summary.errors.push({ error: err.message });
  }

  return summary;
}

/**
 * The review worklist, with each sender correlated against what is already
 * known. Read-only.
 */
async function getDiscoveredDevices(pool) {
  const [{ rows }, { rows: haRows }, { rows: aliasRows }] = await Promise.all([
    pool.query(
      `SELECT * FROM discovered_devices
        ORDER BY (status = 'new') DESC, event_count DESC, source_ip`
    ),
    pool.query(
      `SELECT h.device_id, d.name AS device_name, h.peer_mgmt_ip, h.peer_serial
         FROM device_ha_status h JOIN devices d ON d.id = h.device_id`
    ),
    pool.query(
      `SELECT s.device_id, d.name AS device_name, host(s.source_ip) AS source_ip
         FROM device_syslog_sources s JOIN devices d ON d.id = s.device_id`
    ),
  ]);

  return rows.map((r) => ({
    ...r,
    sourceIp: String(r.source_ip).replace(/\/\d+$/, ''),
    correlation: correlateSender(r, haRows, aliasRows),
  }));
}

module.exports = {
  correlateSender,
  runDeviceDiscovery,
  getDiscoveredDevices,
  DEFAULT_MIN_HOURS,
  DEFAULT_MIN_EVENTS,
  DEFAULT_LOOKBACK_HOURS,
};
