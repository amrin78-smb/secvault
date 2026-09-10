// lib/engines/vpnTunnelHealth.js
//
// Site-to-site IPsec TUNNEL HEALTH, fleet-wide — "which tunnels are down, and
// how much of the fleet can SecVault actually answer that for?"
//
// Until this file existed, `vpn_ipsec_tunnels` was collected on every VPN poll
// (lib/engines/vpnTunnels.js) and used for exactly two things: a per-device
// table on /devices/[id]/vpn, and dashed VPN edges on the fleet map. Nobody
// could ask the fleet-level question.
//
// ⛔ READ-TIME ONLY. No new table, no migration, no cron job, no env var —
// exactly the precedent lib/engines/deviceHealth.js set for the lifecycle data:
// the RAW FACTS are what gets persisted, and "is that up / stale / uncovered"
// is a pure function of those facts plus the current time. Storing the verdict
// would only create a second thing that can go stale.
//
// Everything below the DB read is PURE and takes an explicit `now`, so every
// branch is fixture-testable without Postgres (same convention as
// deviceHealth.js / riskScore.js). CommonJS, like every other lib/engines file.
//
// ── ⛔ THE FOUR THINGS THIS FILE REFUSES TO SAY ───────────────────────────
// This codebase's dominant bug is a failed read recorded as an affirmative
// value (hit_count's old DEFAULT 0, getRules() returning [], an unanswerable
// compliance check scored as a warning). Tunnel health is unusually easy to get
// wrong in exactly that way, so:
//
//   1. "No tunnel rows" is NEVER "no tunnels." Three different situations
//      produce zero rows — the vendor/transport cannot report tunnels at all,
//      the pull has never succeeded, or the device genuinely has none — and
//      this engine keeps them apart (`coverage`, below) instead of drawing a
//      reassuring 0.
//   2. An unrecognised status verb is UNKNOWN, never down. Mapping a vendor
//      word we do not know onto a definite state is how `tunnel-up` once got
//      read as a user login. The recognised set is enumerated from what
//      SecVault's OWN adapters write, and anything else is surfaced verbatim
//      in `unrecognisedStatuses` so the enumeration can be widened on evidence
//      rather than guessed at.
//   3. Staleness is a fact about SECVAULT, not about the tunnel. A tunnel last
//      seen "up" 34 days ago is not up; it is UNMEASURED since then. Live on
//      this fleet, TSR_EKC is precisely that: one tunnel row from 2026-08-07
//      whose device has never had a successful VPN poll recorded. Rendering it
//      as "1 up" would be a fabricated present-tense claim.
//   4. "DOWN SINCE" IS NOT DERIVABLE AND IS NOT REPORTED. `vpn_ipsec_tunnels`
//      is a LATEST-SNAPSHOT table — storeVpnTunnels() DELETEs the device's rows
//      and reinserts on every poll, same lifecycle as network_objects — so
//      there is exactly one `collected_at` per device and no history whatever.
//      A duration would require either a history/state-change table (a schema
//      decision, deliberately not taken here) or correlating FortiOS's
//      `action="tunnel-down"` syslog events, which carry the phase-1 name only
//      inside the raw `message` text and exist for one vendor. `downSince` is
//      therefore absent from every return value, and `notes.downSince` says
//      what it would take.

'use strict';

const { parseCidrOrIp } = require('./cidrUtils');

// ── Staleness ─────────────────────────────────────────────────────────────
// The VPN poll (services/engine-worker.js's `vpn-session-poll`) runs every
// VPN_POLL_INTERVAL_MINUTES, clamped 5..59, default 30. 120 minutes is
// therefore at least two and usually four consecutive polls that did not write
// a snapshot — comfortably past normal jitter, well short of "nobody noticed
// for a day". NOT an env var: it is a reading threshold, not deployment
// tuning, and it is overridable per call for tests.
const DEFAULT_STALE_AFTER_MINUTES = 120;

// How far back to look for evidence that the VPN poll reached a device at all.
// Only used to narrow the "zero rows" ambiguity (below) — never to decide
// whether a tunnel is up.
const DEFAULT_POLL_EVIDENCE_LOOKBACK_DAYS = 7;

const MS_PER_MINUTE = 60 * 1000;

// ── ⛔ The status enumeration ─────────────────────────────────────────────
// These are the values SecVault's own adapters WRITE, established by reading
// every producer rather than by guessing:
//
//   fortinet  cliParser.js  → 'up' | 'down' | null   (explicit `status=`, else
//                                                     derived from `sa=<n>`)
//   paloalto  parser.js     → 'up' | 'down' | <the device's own word, verbatim>
//   cisco_asa parser.js     → 'up'                   (only established L2L
//                                                     tunnels appear at all)
//
// Live on the reference fleet, 151 rows carry exactly two distinct values: 149
// 'up' and 2 'down', and none is NULL. So {'up'} / {'down'} is the COMPLETE
// enumeration of what this system produces, and any other value arrived
// verbatim from a device.
//
// ⛔ DO NOT widen these sets speculatively ("active", "established", "mature"
// look safe). A verb we have not seen is a verb we cannot map, and the safe
// direction is 'unknown' — which never escalates and never reassures. Widen
// them only from `unrecognisedStatuses` on real data.
const UP_STATUSES = new Set(['up']);
const DOWN_STATUSES = new Set(['down']);

// ── ⛔ Vendor coverage — stated, never hidden ─────────────────────────────
// getVpnTunnels() is an OPTIONAL adapter capability (lib/adapters/interface.js).
// Three of the six Tier-1 vendors do not implement it on any transport, so a
// fleet view that quietly listed only the vendors that answer would read as
// "all tunnels healthy" while a third of the fleet was never asked.
//
// Established by reading the adapters, not the docs:
//   lib/adapters/fortinet/index.js  (api) · fortinet/ssh.js   (ssh)  → yes
//   lib/adapters/paloalto/index.js  (api) · paloalto/ssh.js   (ssh)  → yes
//   lib/adapters/cisco_asa/index.js (ssh)                            → yes
//   forcepoint / checkpoint / sangfor — no getVpnTunnels() anywhere   → no
//
// ⛔ KEEP THIS IN STEP with ADAPTERS in lib/adapters/index.js — the same
// cross-registry duplication CLAUDE.md already documents for DEFAULT_METHOD
// (an ES-module/CommonJS split makes importing it here the wrong trade). The
// vendor slugs are the canonical ones and must not be re-spelled.
// tests/vpnTunnelHealth.test.js greps the adapter sources and fails if this
// map and the code disagree.
// ⛔ CAN THIS (vendor, transport) EVER REPORT A TUNNEL AS *DOWN*?
//
// Reporting tunnels and reporting DOWN tunnels are different capabilities, and
// conflating them turns a blind spot into good news. Palo Alto’s
// `show vpn ipsec-sa` lists ESTABLISHED Phase-2 SAs only, so a down tunnel is
// simply ABSENT — never a row with status "down". Same for cisco_asa’s
// `show vpn-sessiondb l2l`. FortiOS reports a real per-tunnel status and does
// emit "down" (measured live: 8 up, 2 down).
//
// So for a non-observable vendor the tunnel list is CURRENTLY-ESTABLISHED
// tunnels, not CONFIGURED ones, and a tunnel that is down is INVISIBLE — not
// counted down, not counted up, just missing. Rendering "0 down" for those
// devices without saying so is the failed-read-as-a-fact rule with extra steps.
const VENDOR_DOWN_OBSERVABLE = {
  fortinet: { api: true, ssh: true },
  paloalto: { api: false, ssh: false },
  cisco_asa: { ssh: false },
};

/** @returns {boolean|null} null = unknown vendor/transport, never flattened to false. */
function downObservable(vendor, mgmtMethod) {
  const byMethod = VENDOR_DOWN_OBSERVABLE[vendor];
  if (!byMethod) return null;
  if (mgmtMethod && Object.prototype.hasOwnProperty.call(byMethod, mgmtMethod)) {
    return byMethod[mgmtMethod];
  }
  const values = Object.values(byMethod);
  return values.every((v) => v === values[0]) ? values[0] : null;
}

const VENDOR_TUNNEL_SUPPORT = {
  forcepoint: { smc: false },
  fortinet: { api: true, ssh: true },
  paloalto: { api: true, ssh: true },
  checkpoint: { api: false },
  cisco_asa: { ssh: true },
  sangfor: { ssh: false },
};

/**
 * Does this (vendor, mgmt_method) pair have a getVpnTunnels() implementation?
 *
 * @returns {boolean|null} TRI-STATE. `null` means "we do not know" — an
 *   unrecognised vendor, or a known vendor asked about a transport that is not
 *   in the map. ⛔ `null` must never be flattened to `false`: "this vendor
 *   cannot report tunnels" is a claim about the product, and making it about a
 *   vendor we simply do not recognise is the same class of error as recording
 *   a failed read as a fact.
 */
function tunnelSupport(vendor, mgmtMethod) {
  const byMethod = VENDOR_TUNNEL_SUPPORT[vendor];
  if (!byMethod) return null;
  if (mgmtMethod && Object.prototype.hasOwnProperty.call(byMethod, mgmtMethod)) {
    return byMethod[mgmtMethod];
  }
  // The device's mgmt_method is null or not one this vendor declares, so
  // lib/adapters/index.js would fall back to DEFAULT_METHOD. Rather than
  // duplicate that table here (a second thing to drift), answer only when
  // every transport of this vendor agrees: all-false is a safe definite `false`
  // because no transport could report tunnels; a mixed/true vendor is `null`,
  // because which adapter would actually be dispatched is not knowable here.
  const values = Object.values(byMethod);
  if (values.length > 0 && values.every((v) => v === false)) return false;
  return null;
}

/**
 * The device's last reported status for one tunnel, classified.
 *
 * @param {string|null|undefined} raw
 * @returns {'up'|'down'|'unknown'} ⛔ Three states. An unrecognised verb and a
 *   missing status are BOTH 'unknown' — neither may become 'down' (a fault
 *   nobody reported) nor 'up' (a fault hidden).
 */
function classifyTunnelStatus(raw) {
  if (typeof raw !== 'string') return 'unknown';
  const s = raw.trim().toLowerCase();
  if (s.length === 0) return 'unknown';
  if (UP_STATUSES.has(s)) return 'up';
  if (DOWN_STATUSES.has(s)) return 'down';
  return 'unknown';
}

function toDate(value) {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value !== 'string' || value.trim() === '') return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * How current is a snapshot taken at `collectedAt`?
 *
 * @returns {{freshness:'fresh'|'stale'|'unknown', ageMinutes:number|null}}
 *   'unknown' = no usable timestamp at all, which is not the same as old.
 */
function classifyFreshness(collectedAt, now, staleAfterMinutes = DEFAULT_STALE_AFTER_MINUTES) {
  const at = now instanceof Date ? now : new Date();
  const taken = toDate(collectedAt);
  if (!taken) return { freshness: 'unknown', ageMinutes: null };
  const ageMinutes = Math.floor((at.getTime() - taken.getTime()) / MS_PER_MINUTE);
  // A snapshot stamped in the future is clock skew, not freshness evidence —
  // clamp the age at 0 rather than letting a negative number read as "very
  // fresh" in a sort.
  const age = ageMinutes < 0 ? 0 : ageMinutes;
  return { freshness: age > staleAfterMinutes ? 'stale' : 'fresh', ageMinutes: age };
}

/**
 * The peer address a vendor reported, reduced to a bare IP.
 *
 * Palo Alto writes `180.183.195.2:4500` (confirmed live) while FortiOS strips
 * the port itself, so one transport-port suffix is removed here. A bare IPv6
 * literal (several colons, no brackets) is left alone.
 *
 * @returns {string|null} null when there is nothing parseable to compare.
 */
function normalizePeer(raw) {
  if (typeof raw !== 'string') return null;
  const s = raw.trim();
  if (s.length === 0) return null;
  // [2001:db8::1]:4500 — bracketed IPv6 with a port.
  const bracketed = s.match(/^\[(.+)\](?::\d+)?$/);
  if (bracketed) return bracketed[1];
  const colonCount = (s.match(/:/g) || []).length;
  if (colonCount === 1) {
    const m = s.match(/^(.+):(\d+)$/);
    if (m) return m[1];
  }
  return s;
}

/**
 * Classify a tunnel's peer against the fleet's own collected interface
 * addresses.
 *
 * @param {string|null} peerRaw
 * @param {string} deviceId - the device the tunnel belongs to
 * @param {Map<string, string[]>} ifaceOwners - bare interface IP -> deviceIds
 * @returns {{peerIp:string|null, peerKind:'managed_device'|'unmatched'|'dialup'|'self'|'unreadable', peerDeviceIds:string[]}}
 *
 * ⛔ 'unmatched' means "not matched to a device SecVault manages", NOT
 * "external site". Matching depends entirely on device_interfaces coverage,
 * which is itself partial — live, one device (TSR_EKC) has zero interface rows,
 * so every tunnel pointing at it is unmatchable no matter how well known it is.
 * The fleet summary reports that coverage alongside the counts so the number
 * cannot be read as a claim about the internet.
 */
function classifyPeer(peerRaw, deviceId, ifaceOwners) {
  const peerIp = normalizePeer(peerRaw);
  if (!peerIp) return { peerIp: null, peerKind: 'unreadable', peerDeviceIds: [] };
  // '0.0.0.0' is a real, recurring value for dial-up / unnumbered-gateway
  // tunnels (FortiOS's `ipsec-client`, confirmed live) — it is a valid address
  // literal but not a site, and calling it "unmatched" would imply we looked
  // for a peer that could have existed.
  if (peerIp === '0.0.0.0') return { peerIp, peerKind: 'dialup', peerDeviceIds: [] };
  if (parseCidrOrIp(peerIp) === null) {
    // An FQDN peer, or something we cannot parse. Not a failure worth throwing
    // over, and definitely not "external".
    return { peerIp, peerKind: 'unreadable', peerDeviceIds: [] };
  }
  const owners = ifaceOwners.get(peerIp) || [];
  const others = owners.filter((id) => id !== deviceId);
  if (others.length > 0) return { peerIp, peerKind: 'managed_device', peerDeviceIds: others };
  if (owners.length > 0) return { peerIp, peerKind: 'self', peerDeviceIds: [deviceId] };
  return { peerIp, peerKind: 'unmatched', peerDeviceIds: [] };
}

// ── Coverage: what can be claimed about a device at all ───────────────────
//
// ⛔ THE CENTRAL DISTINCTION IN THIS FILE. Four values, and only one of them
// permits a statement about tunnels:
//
//   'reporting'      >=1 tunnel row. Its freshness decides whether the states
//                    are current or merely last-known.
//   'no_rows_polled' the vendor CAN report tunnels, zero rows are stored, and
//                    the VPN poll demonstrably reached this device recently.
//                    The strongest available reading of "probably has none" —
//                    and still not a confident one, because the tunnel pull
//                    sits in its own try/catch in the engine worker that logs a
//                    warning and writes NOTHING to the database, so a command
//                    that failed on a reachable device is indistinguishable
//                    here from a device with no tunnels.
//   'no_rows_unconfirmed'
//                    the vendor CAN report tunnels, zero rows are stored, and
//                    there is no evidence the VPN poll succeeded in the
//                    lookback window. Nothing may be claimed at all.
//   'unsupported'    no getVpnTunnels() for this vendor/transport. SecVault has
//                    never asked and cannot ask. ⛔ This is a fact about
//                    SecVault, the same category as compliance's `na`, and it
//                    must be excluded from any "% healthy" denominator rather
//                    than counted as zero problems.
//   'support_unknown'
//                    unrecognised vendor, or a transport not in the support
//                    map. Also unclaimable.
function classifyCoverage(device, tunnelCount, pollEvidence) {
  if (tunnelCount > 0) return 'reporting';
  // Accepts either the raw DB row shape or the camelCase one assembled below —
  // same dual-naming tolerance deviceHealth.js uses, so a caller cannot get a
  // silently wrong answer by handing over the object it happens to have.
  const method = device.mgmt_method !== undefined ? device.mgmt_method : device.mgmtMethod;
  const supported = tunnelSupport(device.vendor, method);
  if (supported === false) return 'unsupported';
  if (supported === null) return 'support_unknown';
  return pollEvidence && pollEvidence.lastOkAt ? 'no_rows_polled' : 'no_rows_unconfirmed';
}

/**
 * Fleet-wide site-to-site IPsec tunnel health.
 *
 * ⛔ Read-only. Four SELECTs, no writes, no persistence — safe to call from a
 * server component on every render (the reference fleet's whole tunnel set is
 * 151 rows).
 *
 * @param {import('pg').Pool} pool
 * @param {object}  [options]
 * @param {Date}    [options.now]                  injectable clock, for tests
 * @param {number}  [options.staleAfterMinutes]
 * @param {number}  [options.pollEvidenceLookbackDays]
 * @param {string}  [options.deviceId]             restrict to one device
 * @returns {Promise<object>} see the shape assembled at the bottom of this file
 */
async function getVpnTunnelHealth(pool, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date();
  const staleAfterMinutes = Number.isFinite(options.staleAfterMinutes) && options.staleAfterMinutes > 0
    ? Math.floor(options.staleAfterMinutes)
    : DEFAULT_STALE_AFTER_MINUTES;
  const lookbackDays = Number.isFinite(options.pollEvidenceLookbackDays) && options.pollEvidenceLookbackDays > 0
    ? Math.floor(options.pollEvidenceLookbackDays)
    : DEFAULT_POLL_EVIDENCE_LOOKBACK_DAYS;
  const deviceId = typeof options.deviceId === 'string' && options.deviceId.length > 0
    ? options.deviceId
    : null;

  // 1. Every ACTIVE device, whether or not it has tunnel rows. ⛔ A LEFT JOIN,
  //    not an inner one: the devices with nothing to show are the whole point
  //    of rule 5 — an inner join is how a fleet view silently becomes "the
  //    vendors that answer".
  const { rows: deviceRows } = await pool.query(
    `SELECT d.id, d.name, d.vendor, d.mgmt_method, d.site, d.asset_criticality,
            t.id           AS tunnel_id,
            t.name         AS tunnel_name,
            t.peer         AS tunnel_peer,
            t.status       AS tunnel_status,
            t.ike_version  AS tunnel_ike_version,
            t.bytes_in     AS tunnel_bytes_in,
            t.bytes_out    AS tunnel_bytes_out,
            t.collected_at AS tunnel_collected_at
     FROM devices d
     LEFT JOIN vpn_ipsec_tunnels t ON t.device_id = d.id
     WHERE d.active = true
       AND ($1::uuid IS NULL OR d.id = $1::uuid)
     ORDER BY d.name ASC, t.name ASC NULLS LAST`,
    [deviceId]
  );

  // 2. Every collected interface address in the fleet, for peer resolution.
  //    ⛔ NOT restricted to `deviceId` even when one is given: the question
  //    "does this tunnel's peer belong to a firewall we manage" is fleet-wide
  //    by nature. Disabled interfaces are excluded, matching
  //    topology.js:buildVpnEdges() — a peer resolving to a shut-down interface
  //    is not a live link.
  const { rows: ifaceRows } = await pool.query(
    `SELECT i.device_id, i.ip_address, d.name AS device_name
     FROM device_interfaces i
     JOIN devices d ON d.id = i.device_id
     WHERE i.ip_address IS NOT NULL
       AND i.enabled = true`
  );

  // 3. Evidence the VPN poll actually reached each device. This is the ONLY
  //    thing that narrows the "zero rows" ambiguity, and it is deliberately
  //    read from device_connectivity_history's `vpn` source rather than from
  //    devices.last_rules_collected_at — that column is stamped by a DIFFERENT
  //    job (the daily rule/config pull), so using it here would answer a
  //    question nobody asked.
  const { rows: pollRows } = await pool.query(
    `SELECT h.device_id,
            max(h.checked_at) FILTER (WHERE h.reachable) AS last_ok_at,
            max(h.checked_at)                            AS last_attempt_at
     FROM device_connectivity_history h
     WHERE h.source = 'vpn'
       AND h.checked_at > $1::timestamptz
     GROUP BY h.device_id`,
    [new Date(now.getTime() - lookbackDays * 24 * 60 * MS_PER_MINUTE).toISOString()]
  );

  return assembleTunnelHealth({
    deviceRows,
    ifaceRows,
    pollRows,
    now,
    staleAfterMinutes,
    lookbackDays,
  });
}

/**
 * PURE. Everything above only fetches; every judgement is made here, so tests
 * drive this directly with fixtures and no stub pool at all.
 */
function assembleTunnelHealth({ deviceRows, ifaceRows, pollRows, now, staleAfterMinutes, lookbackDays }) {
  // bare interface IP -> deviceIds, plus deviceId -> name for labelling.
  const ifaceOwners = new Map();
  const deviceNames = new Map();
  const devicesWithInterfaceData = new Set();
  for (const r of Array.isArray(ifaceRows) ? ifaceRows : []) {
    if (r.device_name) deviceNames.set(r.device_id, r.device_name);
    const bare = String(r.ip_address).split('/')[0].trim();
    if (bare.length === 0) continue;
    if (parseCidrOrIp(bare) === null) continue; // unparseable — skip, never throw
    devicesWithInterfaceData.add(r.device_id);
    const list = ifaceOwners.get(bare) || [];
    if (!list.includes(r.device_id)) list.push(r.device_id);
    ifaceOwners.set(bare, list);
  }

  const pollByDevice = new Map();
  for (const r of Array.isArray(pollRows) ? pollRows : []) {
    pollByDevice.set(r.device_id, {
      lastOkAt: r.last_ok_at ? new Date(r.last_ok_at).toISOString() : null,
      lastAttemptAt: r.last_attempt_at ? new Date(r.last_attempt_at).toISOString() : null,
    });
  }

  // Group the LEFT JOIN back into devices.
  const byDevice = new Map();
  for (const r of Array.isArray(deviceRows) ? deviceRows : []) {
    let d = byDevice.get(r.id);
    if (!d) {
      d = {
        deviceId: r.id,
        name: r.name,
        vendor: r.vendor,
        mgmtMethod: r.mgmt_method,
        site: r.site || null,
        assetCriticality: r.asset_criticality || null,
        rawTunnels: [],
      };
      byDevice.set(r.id, d);
      if (r.name) deviceNames.set(r.id, r.name);
    }
    if (r.tunnel_id) d.rawTunnels.push(r);
  }

  const unrecognised = new Map(); // lowercased verb -> {value, count, deviceIds}
  const devices = [];
  const down = [];
  const fleetTunnels = { total: 0, up: 0, down: 0, unknownStatus: 0, unmeasured: 0 };
  const peering = { managedDevice: 0, unmatched: 0, dialup: 0, self: 0, unreadable: 0 };
  const coverageCounts = {
    reporting: 0,
    reportingFresh: 0,
    reportingStale: 0,
    reportingUnknownAge: 0,
    no_rows_polled: 0,
    no_rows_unconfirmed: 0,
    unsupported: 0,
    support_unknown: 0,
  };

  for (const d of byDevice.values()) {
    const pollEvidence = pollByDevice.get(d.deviceId) || null;
    const coverage = classifyCoverage(d, d.rawTunnels.length, pollEvidence);

    // Every row of a device shares one collected_at (storeVpnTunnels writes the
    // whole set in one transaction), but read the newest defensively rather
    // than assume it.
    let collectedAt = null;
    for (const r of d.rawTunnels) {
      const t = toDate(r.tunnel_collected_at);
      if (t && (collectedAt === null || t > collectedAt)) collectedAt = t;
    }
    const { freshness, ageMinutes } = classifyFreshness(collectedAt, now, staleAfterMinutes);
    // ⛔ A device with no rows has no snapshot, so it has no freshness either.
    // Reporting 'fresh' there would be a statement about data that does not
    // exist.
    const snapshotFreshness = d.rawTunnels.length > 0 ? freshness : 'none';

    const counts = { up: 0, down: 0, unknown: 0, unmeasured: 0 };
    const tunnels = [];
    for (const r of d.rawTunnels) {
      const status = classifyTunnelStatus(r.tunnel_status);
      if (status === 'unknown' && typeof r.tunnel_status === 'string' && r.tunnel_status.trim() !== '') {
        const key = r.tunnel_status.trim().toLowerCase();
        const seen = unrecognised.get(key) || { value: r.tunnel_status.trim(), count: 0, deviceIds: [] };
        seen.count += 1;
        if (!seen.deviceIds.includes(d.deviceId)) seen.deviceIds.push(d.deviceId);
        unrecognised.set(key, seen);
      }

      // ⛔ TWO ORTHOGONAL FACTS, kept apart on purpose:
      //   `lastKnownStatus` — what the device said, last time we asked.
      //   `health`          — what may be claimed about it NOW.
      // A stale snapshot collapses every status into 'unmeasured', because the
      // age of the reading, not its value, is the operative fact. Folding these
      // into one field is how "up 34 days ago" becomes "up".
      const health = snapshotFreshness === 'fresh' ? status : 'unmeasured';

      const peer = classifyPeer(r.tunnel_peer, d.deviceId, ifaceOwners);
      peering[peer.peerKind === 'managed_device' ? 'managedDevice' : peer.peerKind] += 1;

      const tunnel = {
        tunnelId: r.tunnel_id,
        name: r.tunnel_name || null,
        deviceId: d.deviceId,
        deviceName: d.name,
        vendor: d.vendor,
        mgmtMethod: d.mgmtMethod,
        site: d.site,
        peerRaw: r.tunnel_peer || null,
        peerIp: peer.peerIp,
        peerKind: peer.peerKind,
        peerDeviceIds: peer.peerDeviceIds,
        peerDeviceNames: peer.peerDeviceIds.map((id) => deviceNames.get(id) || id),
        lastKnownStatus: status,
        rawStatus: r.tunnel_status || null,
        health,
        ikeVersion: r.tunnel_ike_version || null,
        // ⛔ Left NULL when the vendor reports no counter. 0 would say "no
        // traffic crossed this tunnel", which is a different claim.
        bytesIn: r.tunnel_bytes_in === null || r.tunnel_bytes_in === undefined ? null : Number(r.tunnel_bytes_in),
        bytesOut: r.tunnel_bytes_out === null || r.tunnel_bytes_out === undefined ? null : Number(r.tunnel_bytes_out),
        collectedAt: collectedAt ? collectedAt.toISOString() : null,
        ageMinutes,
        snapshotFreshness,
        // ⛔ Explicitly present and explicitly null. A consumer reaching for a
        // duration finds the field, finds nothing in it, and finds out why —
        // rather than inventing one from collectedAt, which measures when WE
        // looked and not when the tunnel dropped.
        downSince: null,
        downSinceReason:
          'Not derivable. vpn_ipsec_tunnels keeps only the latest snapshot per device '
          + '(DELETE + reinsert on every poll), so no state-change history exists.',
      };
      tunnels.push(tunnel);

      counts[health === 'unmeasured' ? 'unmeasured' : health] += 1;
      fleetTunnels.total += 1;
      if (health === 'up') fleetTunnels.up += 1;
      else if (health === 'down') fleetTunnels.down += 1;
      else if (health === 'unknown') fleetTunnels.unknownStatus += 1;
      else fleetTunnels.unmeasured += 1;

      if (health === 'down') down.push(tunnel);
    }

    // Down first, then unknown, then unmeasured, then up — the operator's
    // reading order. Within a band, by name with nulls last.
    const HEALTH_ORDER = { down: 0, unknown: 1, unmeasured: 2, up: 3 };
    tunnels.sort((a, b) => {
      const h = HEALTH_ORDER[a.health] - HEALTH_ORDER[b.health];
      if (h !== 0) return h;
      if (a.name === null && b.name !== null) return 1;
      if (b.name === null && a.name !== null) return -1;
      return String(a.name || '').localeCompare(String(b.name || ''));
    });

    coverageCounts[coverage] = (coverageCounts[coverage] || 0) + 1;
    if (coverage === 'reporting') {
      if (snapshotFreshness === 'fresh') coverageCounts.reportingFresh += 1;
      else if (snapshotFreshness === 'stale') coverageCounts.reportingStale += 1;
      else coverageCounts.reportingUnknownAge += 1;
    }

    devices.push({
      deviceId: d.deviceId,
      name: d.name,
      vendor: d.vendor,
      mgmtMethod: d.mgmtMethod,
      site: d.site,
      assetCriticality: d.assetCriticality,
      supportsTunnelCollection: tunnelSupport(d.vendor, d.mgmtMethod),
      coverage,
      coverageReason: COVERAGE_REASON[coverage],
      collectedAt: collectedAt ? collectedAt.toISOString() : null,
      ageMinutes,
      snapshotFreshness,
      lastVpnPollOkAt: pollEvidence ? pollEvidence.lastOkAt : null,
      lastVpnPollAttemptAt: pollEvidence ? pollEvidence.lastAttemptAt : null,
      tunnelCount: tunnels.length,
      counts,
      tunnels,
    });
  }

  devices.sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));
  down.sort((a, b) => {
    const n = String(a.deviceName || '').localeCompare(String(b.deviceName || ''));
    if (n !== 0) return n;
    return String(a.name || '').localeCompare(String(b.name || ''));
  });

  const staleDevices = devices.filter((d) => d.snapshotFreshness === 'stale' || d.snapshotFreshness === 'unknown');

  // ⛔ The denominator, stated. `claimable` is the only population any
  // percentage on screen may be computed over: devices SecVault both can ask
  // and has a current answer from. Everything else is a coverage gap, and
  // dividing by the whole fleet would quietly turn those gaps into good news.
  const totalDevices = devices.length;
  const claimable = coverageCounts.reportingFresh;

  return {
    generatedAt: now.toISOString(),
    staleAfterMinutes,
    pollEvidenceLookbackDays: lookbackDays,
    fleet: {
      devices: {
        total: totalDevices,
        reporting: coverageCounts.reporting,
        reportingFresh: coverageCounts.reportingFresh,
        reportingStale: coverageCounts.reportingStale,
        reportingUnknownAge: coverageCounts.reportingUnknownAge,
        noRowsPolled: coverageCounts.no_rows_polled,
        noRowsUnconfirmed: coverageCounts.no_rows_unconfirmed,
        unsupported: coverageCounts.unsupported,
        supportUnknown: coverageCounts.support_unknown,
        claimable,
      },
      tunnels: { ...fleetTunnels },
      // ⛔ Which devices CANNOT report a down tunnel at all, so the caller can say
      // so rather than presenting their 0-down as a clean result.
      downObservability: (() => {
        const blind = devices.filter((d) => downObservable(d.vendor, d.mgmtMethod) === false);
        const unknown = devices.filter((d) => downObservable(d.vendor, d.mgmtMethod) === null);
        return {
          blindDevices: blind.length,
          blindTunnels: blind.reduce((a, d) => a + (d.tunnels ? d.tunnels.length : 0), 0),
          unknownDevices: unknown.length,
          blindVendors: [...new Set(blind.map((d) => d.vendor))].sort(),
        };
      })(),
      peering: {
        ...peering,
        devicesWithInterfaceData: devicesWithInterfaceData.size,
        devicesTotal: totalDevices,
      },
    },
    devices,
    down,
    staleDevices,
    // Sorted by frequency so the verb worth adding to the enumeration is first.
    unrecognisedStatuses: [...unrecognised.values()].sort((a, b) => b.count - a.count),
    notes: NOTES,
  };
}

const COVERAGE_REASON = {
  reporting: 'Tunnel rows were collected from this device.',
  no_rows_polled:
    'This vendor can report tunnels and the VPN poll reached this device recently, but no tunnel '
    + 'rows are stored. Most likely it has none configured — though a tunnel command that failed on '
    + 'a reachable device would look identical here, because that failure is only logged, never '
    + 'recorded in the database.',
  no_rows_unconfirmed:
    'This vendor can report tunnels, but no rows are stored and no successful VPN poll was recorded '
    + 'in the lookback window. Nothing can be concluded about this device’s tunnels.',
  unsupported:
    'SecVault has no tunnel-collection support for this vendor and access method, so it has never '
    + 'asked. This is a limitation of SecVault, not a statement about the device.',
  support_unknown:
    'This vendor or access method is not in the tunnel-support map, so whether tunnels can be '
    + 'collected at all is unknown.',
};

const NOTES = {
  scope:
    'Site-to-site IPsec tunnels, from the device’s own management API/CLI (Palo Alto '
    + '`show vpn ipsec-sa`, FortiOS `diagnose vpn tunnel list`, ASA `show vpn-sessiondb l2l`) — '
    + 'not from syslog.',
  vendorCoverage:
    'Tunnel collection is implemented for Palo Alto (API and SSH), Fortinet (API and SSH) and '
    + 'Cisco ASA (SSH). Forcepoint, Check Point and Sangfor have no tunnel collection at all and '
    + 'are counted as uncovered rather than as healthy.',
  staleness:
    'A snapshot older than the staleness window is reported as UNMEASURED, not as its last known '
    + 'state. A tunnel that was up when we last looked is not evidence that it is up now.',
  downSince:
    'How long a tunnel has been down is NOT derivable today: vpn_ipsec_tunnels holds only the '
    + 'latest snapshot per device, so there is no state history to measure against. Answering it '
    + 'would take either an append-only tunnel state-change table written at poll time, or '
    + 'correlation with FortiOS `action="tunnel-down"` syslog events — which carry the phase-1 '
    + 'tunnel name only inside the raw message text, and which no other vendor in this fleet emits.',
  unknownStatus:
    'A status value SecVault does not recognise is reported as unknown, never as down. An '
    + 'unrecognised vendor word must not be able to raise an alarm no device raised.',
  peering:
    'A peer is matched to a managed firewall by comparing it against collected device_interfaces '
    + 'addresses. That data is itself partial, so “not matched” means SecVault could not match it — '
    + 'not that the far end is outside the fleet.',
};

module.exports = {
  downObservable,
  VENDOR_DOWN_OBSERVABLE,
  getVpnTunnelHealth,
  assembleTunnelHealth,
  classifyTunnelStatus,
  classifyFreshness,
  classifyPeer,
  classifyCoverage,
  normalizePeer,
  tunnelSupport,
  VENDOR_TUNNEL_SUPPORT,
  UP_STATUSES,
  DOWN_STATUSES,
  COVERAGE_REASON,
  NOTES,
  DEFAULT_STALE_AFTER_MINUTES,
  DEFAULT_POLL_EVIDENCE_LOOKBACK_DAYS,
};
