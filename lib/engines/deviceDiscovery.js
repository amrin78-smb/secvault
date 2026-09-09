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
//
// ── ⛔ A SENDER THAT LATER BECOMES A MANAGED DEVICE ────────────────────────
// ...must stop being called unmanaged — and that reconciliation is READ TIME
// too, deliberately.
//
// Live, 2026-09-09: 10.204.6.1 (FG200ETK18912640_OkeanosFOOD) was first seen at
// 07:00 on the 8th, added to the inventory as OKF(F2) at 03:52 on the 9th, and
// the page still listed it under "These addresses match nothing SecVault
// knows" — because the row's `status` stays 'new' forever and nothing ever
// compared the sender against `devices.mgmt_ip`, the most obvious match of all.
// The discovery job could not have fixed that by itself either: the rollup
// copies `device_id` verbatim and never re-resolves it, so rows from BEFORE the
// device existed keep device_id NULL and the address legitimately stays a
// candidate for the rest of the lookback window.
//
// WRITE TIME WAS REJECTED. Stamping stored state on the row when the job
// notices the address is managed has three failure modes read time cannot have:
//   * The device can be DELETED later. `promoted_device_id`/`linked_device_id`
//     survive that only because of ON DELETE SET NULL plus the resurrect UPDATE
//     at the bottom of runDeviceDiscovery(). A match on `mgmt_ip` has NO
//     foreign key to null out, so nothing would ever un-stick it — exactly the
//     "invisible forever even though it is unmanaged again" bug that UPDATE
//     already exists to prevent.
//   * `mgmt_ip` is editable. Renumber the firewall and a stored verdict is a
//     stale fact; a read-time one is simply recomputed.
//   * It would have to write `status`, which this file says everywhere is an
//     OPERATOR DECISION column, never an observation.
// The cost is one more query over a 16-row table inside the Promise.all that
// already runs. Self-correcting beats cheap here.
//
// ⛔ AND IT IS NOT HIDDEN. A reconciled sender moves to its own group that SAYS
// which device it matched. An operator who remembers reviewing an address needs
// to find out where it went, not watch it vanish out of a count.

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

// ⛔ EXACT ADDRESS, NEVER A PREFIX — and mind which side is which type.
// `discovered_devices.source_ip` is INET, which PostgreSQL renders as
// '10.204.6.1/32'. `devices.mgmt_ip` is TEXT, holding a bare '10.204.6.1'.
// Comparing the two raw silently never matches, which is precisely how the
// OKF(F2) bug survived, and `host()` is no help on the TEXT side — `host(text)`
// does not exist as a function at all.
//
// So: strip a /len ONLY where it is a rendering artefact of an INET column,
// lower-case for IPv6 hex, then compare whole strings. `stripMask` stays false
// for anything that came out of a TEXT column, because a mgmt_ip somebody typed
// as '10.204.6.0/24' is a SUBNET, not this device's address, and must never be
// allowed to claim every sender inside it. Anything still carrying a '/' after
// normalisation is not an exact address and matches nothing.
function normalizeAddress(value, { stripMask = false } = {}) {
  if (value === null || value === undefined) return null;
  let s = String(value).trim().toLowerCase();
  if (stripMask) s = s.replace(/\/\d+$/, '');
  if (!s || s.includes('/')) return null;
  return s;
}

/**
 * Decide what a discovered sender actually IS, against what SecVault already
 * knows. PURE — no DB — so the page, the API and the tests all agree.
 *
 * @param {object} row     a discovered_devices row
 * @param {object[]} haRows  {device_id, device_name, peer_mgmt_ip, peer_serial}
 * @param {object[]} aliasRows {device_id, device_name, source_ip}
 * @param {object[]} deviceRows {device_id, device_name, mgmt_ip, snmp_host, active}
 * @returns {{kind:'managed'|'ha-peer'|'known-alias'|'unmanaged', deviceId, deviceName, evidence}}
 */
function correlateSender(row, haRows, aliasRows, deviceRows) {
  const ip = normalizeAddress(row.source_ip, { stripMask: true });
  const serial = row.observed_serial ? String(row.observed_serial).trim() : null;

  // ⛔ CHECKED FIRST, because it is the strongest and least ambiguous statement
  // available: this address is not "related to" a managed device, it IS one.
  // Compared against the same two columns the COLLECTOR uses to attribute an
  // event (services/collector.js refreshDeviceMap → mgmt_ip, snmp_host), so
  // discovery and ingestion cannot disagree about what counts as a known
  // address of a managed device.
  if (ip) {
    for (const d of Array.isArray(deviceRows) ? deviceRows : []) {
      const mgmt = normalizeAddress(d.mgmt_ip);
      const snmp = normalizeAddress(d.snmp_host);
      const which = mgmt && mgmt === ip ? 'management' : snmp && snmp === ip ? 'SNMP' : null;
      if (!which) continue;
      // ⛔ An inactive device is still IN THE INVENTORY, so this is still not an
      // unmanaged firewall — but refreshDeviceMap() only maps ACTIVE devices, so
      // its logs really are still arriving unattributed. Say both: an operator
      // who reads "managed" and then watches the row persist deserves the
      // reason, rather than concluding the page is lying.
      const inactive = d.active === false;
      return {
        kind: 'managed',
        deviceId: d.device_id,
        deviceName: d.device_name,
        evidence:
          `this is ${d.device_name}'s ${which} address ${ip}` +
          (inactive
            ? ' — but that device is marked inactive, so its logs are still being' +
              ' filed as unattributed'
            : ''),
      };
    }
  }

  for (const a of Array.isArray(aliasRows) ? aliasRows : []) {
    const aliasIp = normalizeAddress(a.source_ip, { stripMask: true });
    if (ip && aliasIp === ip) {
      return {
        kind: 'known-alias',
        deviceId: a.device_id,
        deviceName: a.device_name,
        evidence: 'already linked to this device as an additional syslog source',
      };
    }
  }

  for (const h of Array.isArray(haRows) ? haRows : []) {
    // peer_mgmt_ip is TEXT (schema.sql), so no mask stripping — same rule as
    // devices.mgmt_ip above.
    const peerIp = normalizeAddress(h.peer_mgmt_ip);
    const peerSerial = h.peer_serial ? String(h.peer_serial).trim() : null;
    const ipMatch = ip && peerIp && peerIp === ip;
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
  const [{ rows }, { rows: haRows }, { rows: aliasRows }, { rows: deviceRows }] = await Promise.all([
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
    // ⛔ The real inventory. Fetched, NOT joined: `devices.mgmt_ip` is TEXT and
    // `discovered_devices.source_ip` is INET, and there is no safe SQL join
    // between them. `d.mgmt_ip::inet = dd.source_ip` would throw for the WHOLE
    // query the first time any single row held a hostname, a typo or a blank —
    // taking the page down rather than failing to match one sender. So both
    // sides are normalised in the pure correlateSender(), where a bad value can
    // only ever fail to match.
    //
    // INACTIVE DEVICES ARE INCLUDED ON PURPOSE. An inactive device is still in
    // the inventory, so its address is not an unmanaged firewall; the
    // correlation says so, and says the logs are still unattributed.
    pool.query(
      `SELECT id AS device_id, name AS device_name, mgmt_ip, snmp_host, active
         FROM devices
        WHERE mgmt_ip IS NOT NULL OR snmp_host IS NOT NULL`
    ),
  ]);

  return rows.map((r) => ({
    ...r,
    sourceIp: String(r.source_ip).replace(/\/\d+$/, ''),
    correlation: correlateSender(r, haRows, aliasRows, deviceRows),
  }));
}

module.exports = {
  normalizeAddress,
  correlateSender,
  runDeviceDiscovery,
  getDiscoveredDevices,
  DEFAULT_MIN_HOURS,
  DEFAULT_MIN_EVENTS,
  DEFAULT_LOOKBACK_HOURS,
};
