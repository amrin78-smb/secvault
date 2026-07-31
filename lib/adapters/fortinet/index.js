// lib/adapters/fortinet/index.js
// CommonJS ONLY — services/engine-worker.js (plain node) requires adapter modules.
//
// Fortinet FortiGate adapters. Two transports, dispatched by devices.mgmt_method in
// lib/adapters/index.js:
//   - FortinetAdapter    (mgmt_method 'api') — FortiOS REST API, this file
//   - FortinetSshAdapter (mgmt_method 'ssh') — FortiOS CLI over SSH, ./ssh.js
// Both names are imported by the frozen dispatcher; do not rename either.
//
// This file is the REST transport: https://<mgmt_ip>:<mgmt_port||443>, authenticating
// EITHER with a REST API access token (`Authorization: Bearer <token>`) OR with an
// admin username + password via a FortiOS session login. Which one is used depends on
// the stored credential's shape — see _getConn().
//
// See CLAUDE.md "External API Integrations" and the Pool Warning: testConnectivity()
// and any function touching credStore/DB must always receive and use `this.pool`,
// even though it looks like a pure connectivity check.
//
// ⚠️ No live FortiGate was available during this build. All monitor/cmdb field names
// are the documented FortiOS 7.x shapes and MUST be verified against a real device on
// first connect — raw responses are logged once via '[Fortinet Debug]' below for
// exactly that purpose. parser.js is defensive on every field.

const { FirewallAdapter } = require('../interface');
const credStore = require('../../credStore');
const { parseApiCredential } = require('../credentials');
const api = require('./api');
const parser = require('./parser');
const cliParser = require('./cliParser');
const { FortinetSshAdapter } = require('./ssh');
const { createSession, getMetrics, closeSession } = require('../../snmpClient');
const { parseSnmpCredential } = require('../snmpCredential');

let loggedFirstVersionResponses = false;
let loggedFirstPolicyEntry = false;
let loggedFirstVdomResponse = false;
let loggedFirstSnmpResponse = false;
let loggedFirstIpsecResponse = false;

// SNMP OIDs for getSnmpMetrics() — doc-derived from the FORTINET-FORTIGATE-MIB
// (fgSystemInfo subtree), NOT yet confirmed against a real SecVault-connected
// FortiGate (see CLAUDE.md's Live Validation Status discipline — log-and-confirm
// on first live poll, via '[Fortinet SNMP Debug]' below). Verified against
// oidref.com / mibs.observium.org during this feature's build (not assumed from
// memory) — all four resolved exactly as documented, with no surprises:
//
// - sysUpTime.0 (MIB-II, RFC 1213) — universal, no vendor-specific doc needed.
// - fgSysCpuUsage.0 (FORTINET-FORTIGATE-MIB, fgSystemInfo) — Gauge32 0..100,
//   already a percentage, no derivation needed.
// - fgSysMemUsage.0 (FORTINET-FORTIGATE-MIB, fgSystemInfo) — Gauge32 0..100,
//   already a percentage, no derivation needed.
// - fgSysSesCount.0 (FORTINET-FORTIGATE-MIB, fgSystemInfo) — Gauge32, raw
//   active-session count, no derivation needed.
//
// All four are true scalars (unlike e.g. Cisco ASA's CPU/memory OIDs, which
// are indexed table columns needing a walk) — one getMetrics() GET call is
// enough. lowConfidence stays false: FortiGate ships a well-documented, stable
// vendor MIB, same confidence tier as Cisco ASA's getSnmpMetrics().
const SNMP_OID = {
  sysUpTime: '1.3.6.1.2.1.1.3.0',
  fgSysCpuUsage: '1.3.6.1.4.1.12356.101.4.1.3.0',
  fgSysMemUsage: '1.3.6.1.4.1.12356.101.4.1.4.0',
  fgSysSesCount: '1.3.6.1.4.1.12356.101.4.1.8.0',
};

// --- getObjects() mapping helpers (REST transport) ----------------------------------
// Pure mapping from FortiOS cmdb JSON shapes to the FirewallAdapter getObjects()
// contract (lib/adapters/interface.js). Field names (name/subnet/type/fqdn/start-ip/
// end-ip/member/protocol/tcp-portrange/udp-portrange) are DOC-DERIVED, not yet
// live-verified — same standing caveat as the rest of this file (CLAUDE.md Live
// Validation Status). `cliParser.ipMaskToPrefixLength` is reused rather than
// reimplemented so the REST and SSH transports normalize a dotted-decimal netmask
// identically.

function restAddressToNamedAddress(entry) {
  if (!entry || !entry.name) return null;
  const type = entry.type ? String(entry.type).toLowerCase() : null;
  let value = null;

  if (type === 'fqdn' && entry.fqdn) {
    value = String(entry.fqdn);
  } else if (type === 'iprange') {
    const start = entry['start-ip'];
    const end = entry['end-ip'];
    if (start && end) value = `${start}-${end}`;
  } else if (typeof entry.subnet === 'string' && entry.subnet.trim().length > 0) {
    // `ipmask` (the default type) typically returns "x.x.x.x y.y.y.y" — IP + dotted
    // netmask, space-separated — but some firmware/serializer combinations may
    // already return CIDR. Normalize to CIDR when a clean prefix length can be
    // derived; otherwise pass the raw subnet string through rather than guess.
    const subnet = entry.subnet.trim();
    if (subnet.includes('/')) {
      value = subnet;
    } else {
      const parts = subnet.split(/\s+/);
      if (parts.length === 2) {
        const prefix = cliParser.ipMaskToPrefixLength(parts[1]);
        value = prefix !== null ? `${parts[0]}/${prefix}` : subnet;
      } else {
        value = subnet;
      }
    }
  } else if (!type && entry.fqdn) {
    value = String(entry.fqdn);
  }

  return { name: String(entry.name), type: type || undefined, value };
}

function restGroupToNamedGroup(entry) {
  if (!entry || !entry.name) return null;
  // ⛔ BUG FIXED 2026-07-18, found in a bug-sweep pass: `entry.member` was
  // only ever read as an array — a FortiOS REST response returning a
  // single-item table field as a bare object instead of a 1-element array
  // (the same single-item-collapse class of issue CLAUDE.md already
  // documents for Palo Alto's XML parser) silently fell to `[]`, dropping
  // the group's one real member with no warning. The SSH-transport sibling
  // (cliParser.js's groupEntryToNamedGroup) already handled this shape;
  // this REST version didn't. Fixed to accept either shape, matching it.
  const raw = Array.isArray(entry.member) ? entry.member : entry.member ? [entry.member] : [];
  const members = raw
    .map((m) => (m && m.name !== undefined && m.name !== null ? String(m.name) : null))
    .filter((name) => name !== null);
  return { name: String(entry.name), members };
}

// Normalizes one /api/v2/monitor/vpn/ssl `results` entry into the vendor-agnostic
// active-session shape stored in vpn_active_sessions (see lib/engines/vpnSessions.js).
// BEST-EFFORT and ADDITIVE: getVpnSessionSummary()'s active_session_count is the
// authoritative, already-shipped signal (results.length) — normalizing entries must
// never disturb it, so the caller wraps this in try/catch and every field degrades to
// null rather than throwing.
//
// ⚠️ Field names are DOC-DERIVED and NOT live-verified — the /api/v2/monitor/vpn/ssl
// per-session shape is explicitly unconfirmed (see api.js's getSslVpnMonitor() and
// CLAUDE.md Live Validation Status). Every field is therefore picked from a small
// candidate list and missing fields fall to null; the raw entry is preserved under
// `raw` so the [Fortinet Debug] logged response can be used to correct these names on
// first live use. Never throws.
function restSslVpnSessionToNormalized(entry) {
  if (!entry || typeof entry !== 'object') return null;

  const pick = (keys) => {
    for (const k of keys) {
      const v = entry[k];
      if (v !== undefined && v !== null && v !== '') return v;
    }
    return null;
  };
  const str = (v) => (v === null || v === undefined ? null : String(v));
  const intOrNull = (v) => {
    if (v === null || v === undefined || v === '') return null;
    const n = parseInt(String(v), 10);
    return Number.isFinite(n) ? n : null;
  };

  return {
    username: str(pick(['user_name', 'user', 'username', 'login'])),
    tunnel_type: 'SSL-VPN',
    source_ip: str(pick(['remote_host', 'source_ip', 'src_ip', 'remote_ip', 'client_ip'])),
    assigned_ip: str(pick(['tunnel_ip', 'assigned_ip', 'virtual_ip', 'ip'])),
    login_time: str(pick(['last_login_time', 'login_time', 'logintime'])),
    duration_seconds: intOrNull(pick(['duration', 'duration_seconds', 'session_duration'])),
    bytes_in: intOrNull(pick(['bytes_in', 'in_bytes', 'rx_bytes'])),
    bytes_out: intOrNull(pick(['bytes_out', 'out_bytes', 'tx_bytes'])),
    client: str(pick(['host', 'client', 'hostname', 'computer'])),
    gateway: str(pick(['realm', 'portal', 'gateway'])),
    raw: entry,
  };
}

// Normalizes one /api/v2/monitor/vpn/ipsec `results` entry (a phase1 IPSec tunnel)
// into the vendor-agnostic getVpnTunnels() shape:
//   { name, peer, status, ike_version, bytes_in, bytes_out, raw }
// (any field may be null). SEPARATE from restSslVpnSessionToNormalized() above —
// that models SSL-VPN user sessions; this models IPSec SITE-TO-SITE tunnels.
//
// ⚠️ Field names are DOC-DERIVED and NOT live-verified (see CLAUDE.md Live Validation
// Status). A FortiOS ipsec monitor result typically carries a tunnel-level `name` /
// `rgwy` plus a `proxyid` array of phase2 selectors, each with `p2name` / `status` /
// `incoming_bytes` / `outgoing_bytes`. Every field is picked defensively and missing
// fields fall to null; the raw entry is preserved under `raw` so the [Fortinet Debug]
// logged response can correct these names on first live use. Pure; NEVER throws.
function restIpsecTunnelToNormalized(entry) {
  if (!entry || typeof entry !== 'object') return null;

  const str = (v) => (v === null || v === undefined || v === '' ? null : String(v));
  const intOrNull = (v) => {
    if (v === null || v === undefined || v === '') return null;
    const n = parseInt(String(v), 10);
    return Number.isFinite(n) ? n : null;
  };

  // proxyid holds the phase2 selectors. A single-item table field can arrive as a bare
  // object instead of a 1-element array (the same single-item-collapse class of issue
  // restGroupToNamedGroup() above already guards against) — accept either shape.
  const proxyids = Array.isArray(entry.proxyid)
    ? entry.proxyid
    : entry.proxyid && typeof entry.proxyid === 'object'
      ? [entry.proxyid]
      : [];

  const name = str(entry.name) || (proxyids.length > 0 ? str(proxyids[0].p2name) : null) || null;
  const peer = str(entry.rgwy) || str(entry.rgwy_ip) || null;

  // IKE version — not always present at the tunnel level; map defensively.
  let ike_version = null;
  const verRaw = entry.ike_version !== undefined ? entry.ike_version : entry.version;
  if (verRaw !== undefined && verRaw !== null && verRaw !== '') {
    const v = String(verRaw).trim();
    if (v === '1' || /ikev1/i.test(v)) ike_version = 'IKEv1';
    else if (v === '2' || /ikev2/i.test(v)) ike_version = 'IKEv2';
  }

  // status: a tunnel-level `status` when present (mapped to 'up'/'down'); otherwise
  // "up" if ANY phase2 SA reports up, else "down". null when nothing is readable.
  let status = null;
  const tunnelStatus = str(entry.status);
  if (tunnelStatus) {
    status = /up/i.test(tunnelStatus) ? 'up' : /down/i.test(tunnelStatus) ? 'down' : tunnelStatus.toLowerCase();
  } else if (proxyids.length > 0) {
    const anyUp = proxyids.some((p) => p && /up/i.test(String(p.status || '')));
    status = anyUp ? 'up' : 'down';
  }

  // bytes: tunnel-level counters when present, else summed across the phase2 selectors.
  const sumProxyBytes = (key) => {
    let sum = 0;
    let seen = false;
    for (const p of proxyids) {
      const n = intOrNull(p && p[key]);
      if (n !== null) {
        sum += n;
        seen = true;
      }
    }
    return seen ? sum : null;
  };
  let bytes_in = intOrNull(entry.incoming_bytes);
  if (bytes_in === null) bytes_in = sumProxyBytes('incoming_bytes');
  let bytes_out = intOrNull(entry.outgoing_bytes);
  if (bytes_out === null) bytes_out = sumProxyBytes('outgoing_bytes');

  return { name, peer, status, ike_version, bytes_in, bytes_out, raw: entry };
}

function restServiceToNamedService(entry) {
  if (!entry || !entry.name) return null;
  const tcpRange = entry['tcp-portrange'];
  const udpRange = entry['udp-portrange'];
  const parts = [];
  if (tcpRange) parts.push(`tcp/${tcpRange}`);
  if (udpRange) parts.push(`udp/${udpRange}`);

  let value = null;
  if (parts.length > 0) value = parts.join(',');
  else if (entry.protocol) value = String(entry.protocol).toLowerCase();

  return { name: String(entry.name), value };
}

class FortinetAdapter extends FirewallAdapter {
  constructor({ device, pool }) {
    super({ device, pool });
  }

  // Builds the FortiOS connection descriptor, decrypting the stored credential via
  // credStore. Always uses this.pool — never omit it (CLAUDE.md Pool Warning).
  //
  // parseApiCredential handles all three stored forms (see lib/adapters/credentials.js):
  //   {"api_key":"..."}                      → token auth
  //   {"username":"...","password":"..."}    → session auth
  //   a bare non-JSON string                 → token auth (LEGACY raw token; devices
  //                                            added before access-method selection
  //                                            existed must keep working untouched)
  async _getConn() {
    const plaintext = await credStore.getCredential(this.device.id, 'rest_api', this.pool);
    if (!plaintext) {
      throw new Error(
        `No REST API credential found for device ${this.device.id} — save credentials before connecting.`
      );
    }

    // Throws a secret-free, actionable error when the stored credential is unusable.
    const { apiKey, username, password } = parseApiCredential(plaintext, 'FortiGate');

    return {
      host: this.device.mgmt_ip,
      port: this.device.mgmt_port || 443,
      token: apiKey,
      username,
      password,
      session: null,
      authMode: apiKey ? 'token' : 'session',
      allowSelfSignedSsl: this.device.allow_self_signed_ssl !== false,
    };
  }

  /**
   * Runs `fn(conn)` with a usable, authenticated conn.
   *
   * Token auth: passes the conn straight through — the original stateless path,
   * unchanged.
   *
   * Session auth: logs in first, and ALWAYS logs out afterwards via try/finally,
   * including on every error path. This is not tidiness — a FortiGate caps concurrent
   * admin sessions, so one session leaked per collect cycle eventually locks real
   * admins out of the appliance. A logout failure is logged but never masks the real
   * error from `fn`.
   */
  async _withSession(fn) {
    const conn = await this._getConn();

    if (conn.authMode === 'token') {
      return fn(conn);
    }

    const session = await api.loginSession(conn);
    const sessionConn = { ...conn, session };

    try {
      return await fn(sessionConn);
    } finally {
      try {
        await api.logoutSession(sessionConn);
      } catch (err) {
        // Never rethrow from finally: that would replace the real failure with a
        // logout error. The session lingers until FortiOS times it out.
        console.warn(
          `[Fortinet] Session logout failed for device ${this.device.id} — the admin session ` +
            `will linger until it times out: ${err.message}`
        );
      }
    }
  }

  // → { ok: bool, latency_ms, message } — must never throw.
  async testConnectivity() {
    const startedAt = Date.now();
    try {
      await this._withSession(async (conn) => api.getSystemStatus(conn));
      return { ok: true, latency_ms: Date.now() - startedAt, message: 'Connected' };
    } catch (err) {
      // err.message is credential-safe by construction: api.js and credentials.js
      // never put the token, password or session cookie into an error. This message
      // is returned in the /api/devices/[id]/test HTTP response body.
      return { ok: false, latency_ms: null, message: err.message };
    }
  }

  // → { version_string, version_tuple, build, model }
  // Primary source: /api/v2/monitor/system/firmware (results.current.version/.build).
  // Fallback: /api/v2/monitor/system/status (version, serial, hostname, model fields).
  async getVersion() {
    return this._withSession(async (conn) => {
      let firmwareBody = null;
      try {
        firmwareBody = await api.getFirmware(conn);
      } catch (err) {
        console.warn(
          `[Fortinet] firmware endpoint failed for device ${this.device.id} — falling back to system status: ${err.message}`
        );
      }

      let statusBody = null;
      try {
        statusBody = await api.getSystemStatus(conn);
      } catch (err) {
        console.warn(
          `[Fortinet] system status endpoint failed for device ${this.device.id}: ${err.message}`
        );
      }

      if (!firmwareBody && !statusBody) {
        throw new Error(
          'Unable to determine FortiGate version — both /monitor/system/firmware and /monitor/system/status failed'
        );
      }

      if (!loggedFirstVersionResponses) {
        // Per CLAUDE.md: never assume vendor field names from documentation. Log the full
        // raw responses the first time so parser.js field mappings can be verified and
        // adjusted against the live system.
        console.log('[Fortinet Debug] Raw firmware response:', JSON.stringify(firmwareBody, null, 2));
        console.log('[Fortinet Debug] Raw system status response:', JSON.stringify(statusBody, null, 2));
        loggedFirstVersionResponses = true;
      }

      return parser.parseVersionInfo(firmwareBody, statusBody);
    });
  }

  /**
   * Lists the device's VDOMs.
   *
   * @returns {Promise<string[]|null>} VDOM names, or NULL meaning "could not
   *   enumerate — assume a single implicit VDOM". NULL is the safe, pre-existing
   *   behaviour and must never be treated as "this box has no VDOMs".
   */
  async _discoverVdoms(conn) {
    try {
      const body = await api.getVdoms(conn);

      if (!loggedFirstVdomResponse) {
        console.log('[Fortinet Debug] Raw cmdb/system/vdom response:', JSON.stringify(body, null, 2));
        loggedFirstVdomResponse = true;
      }

      return parser.parseVdomNames(body);
    } catch (err) {
      // Older firmware, a VDOM-scoped admin profile, or VDOMs simply not enabled.
      // Fall back to the single implicit VDOM rather than hard-failing a box that
      // has always worked.
      console.warn(
        `[Fortinet] VDOM enumeration failed for device ${this.device.id} — assuming a single ` +
          `implicit VDOM (the pre-VDOM behaviour): ${err.message}`
      );
      return null;
    }
  }

  // Pulls one VDOM's policy table (vdom = null → the admin's default/implicit VDOM).
  // THROWS on anything that is not a usable policy table — see getRules().
  async _getRulesForVdom(conn, vdom, sequenceStart, prefixRuleName) {
    const where = vdom ? ` for VDOM "${vdom}"` : '';

    const policyBody = await api.getFirewallPolicies(conn, vdom);
    const policies = parser.extractResults(policyBody);

    if (!Array.isArray(policies)) {
      // Previously this returned [] — a false success. collectAndStore would then
      // DELETE every stored rule for the device and report rulesCount: 0.
      throw new Error(
        `FortiGate cmdb firewall/policy response${where} had no results array — field names may ` +
          'differ on this firmware. Raw keys: ' +
          JSON.stringify(
            policyBody && typeof policyBody === 'object' ? Object.keys(policyBody) : null
          ) +
          '. Not treating this as "zero rules" — existing rules are left untouched. Check the ' +
          '[Fortinet Debug] logs and adjust lib/adapters/fortinet/parser.js.'
      );
    }

    if (!loggedFirstPolicyEntry && policies.length > 0) {
      console.log('[Fortinet Debug] Raw first policy entry:', JSON.stringify(policies[0], null, 2));
      loggedFirstPolicyEntry = true;
    }

    // Hit counts are best-effort enrichment: FortiGate is one of the few vendors that
    // exposes genuine per-policy counters, but a monitor failure must never break the
    // rule pull — hit counts just default to 0.
    //
    // Fetched PER VDOM and kept with that VDOM's policies: FortiOS policyid is only
    // unique within a VDOM, so merging every VDOM's stats into one index would
    // attribute one VDOM's traffic to another VDOM's policy of the same id.
    let statsResults = [];
    try {
      const statsBody = await api.getPolicyStats(conn, vdom);
      const extracted = parser.extractResults(statsBody);
      statsResults = Array.isArray(extracted) ? extracted : [];
    } catch (err) {
      console.warn(
        `[Fortinet] policy hit-count monitor call${where} failed for device ${this.device.id} — hit counts default to 0: ${err.message}`
      );
      statsResults = [];
    }

    return parser.parsePolicies(policies, statsResults, { vdom, prefixRuleName, sequenceStart });
  }

  // → NormalizedRule[]
  //
  // VDOM completeness: without a `vdom` query param FortiOS returns ONLY the admin's
  // default VDOM, so on a multi-VDOM box this used to hand the rule-analysis engine a
  // partial ruleset that it treated as complete (producing wrong "unused rule"
  // findings). Rules are now collected from EVERY VDOM.
  //
  // ⛔ If one VDOM's rules cannot be fetched, the WHOLE call throws — it does not
  // return the other VDOMs' rules. collectAndStore() (lib/adapters/index.js) awaits
  // getRules() and only THEN opens a transaction that DELETEs every firewall_rules row
  // for this device before reinserting. So:
  //   throw  → the DELETE never runs; the previous complete ruleset survives and the
  //            error is surfaced in engine.log and the /test response.
  //   partial→ the real rules of the failed VDOM are deleted and never reinserted, the
  //            Phase 5 findings are rewritten from the partial set, and the whole thing
  //            reports success. That is strictly worse than a visible failure, and is
  //            exactly the bug this change exists to fix.
  async getRules() {
    return this._withSession(async (conn) => {
      const vdoms = await this._discoverVdoms(conn);

      // No VDOM info, or exactly one VDOM → keep the original implicit-VDOM request
      // (no `vdom` param). With a single VDOM the admin's default VDOM IS that VDOM,
      // so the implicit result is already complete — and this keeps single-VDOM and
      // legacy boxes on the exact code path that already works. No hard fail.
      if (!vdoms || vdoms.length <= 1) {
        return this._getRulesForVdom(conn, null, 0, false);
      }

      console.log(
        `[Fortinet] Device ${this.device.id} has ${vdoms.length} VDOMs; collecting rules from all ` +
          `of them: ${vdoms.join(', ')}`
      );

      const allRules = [];
      for (const vdom of vdoms) {
        // No try/catch on purpose — a failure here must fail getRules() entirely.
        const rules = await this._getRulesForVdom(
          conn,
          vdom,
          allRules.length,
          // Multi-VDOM only: the VDOM goes in firewall_rules.vdom (real column, added
          // 2026-07-30 — see ruleAnalysis.js's isStrictlyEarlier()), in raw_rule
          // (durable, machine-readable), AND as a "[vdom] " rule_name prefix
          // (human-facing, kept for UI tables that don't render a VDOM column yet).
          true
        );
        allRules.push(...rules);
      }

      return allRules;
    });
  }

  // → { raw: string, parsed: object }
  // raw: full text config from /monitor/system/config/backup?scope=global, REDACTED
  // (may 403 on tokens without backup permission — falls back to the JSON of `parsed`).
  // parsed: flat, predictably-keyed object assembled from cmdb endpoints — these keys
  // ({global, interfaces, ssl_vpn, snmp, admins, ntp, dns, log_syslogd, password_policy,
  // fortiguard, autoupdate_schedule}) feed the Phase 6 applicability predicate engine's
  // dot-path lookups, and the Phase 7 compliance engine's audit_checks predicates — the
  // 6 newest keys were added 2026-07-19 specifically so 5 of the 7 Fortinet checks that
  // were seeded as `not_evaluable_from_config` in lib/auditChecksSeed.js could be
  // upgraded to real predicates (already done, same change). The other 2
  // (fortinet-ips-internet-facing-policies, fortinet-unused-interfaces-shutdown) remain
  // not_evaluable_from_config for structural reasons this section extension does not
  // fix — see lib/auditChecksSeed.js's header comment and CLAUDE.md "Compliance Engine
  // (Phase 7)". Keep the structure
  // flat and predictable. `parsed.collected_via` is always 'api' for this transport
  // (matches devices.mgmt_method's REST-access value — see VENDOR_META in
  // components/devices/vendorMeta.js) — the SSH transport's parseFullConfiguration()
  // sets 'ssh'; both transports must always set this key so config_parsed's shape
  // doesn't silently differ between them.
  async getConfig() {
    return this._withSession(async (conn) => {
      const sections = [
        ['global', api.getSystemGlobal],
        ['interfaces', api.getInterfaces],
        ['ssl_vpn', api.getSslVpnSettings],
        ['snmp', api.getSnmpSysinfo],
        ['admins', api.getAdmins],
        ['ntp', api.getNtp],
        ['dns', api.getDns],
        ['log_syslogd', api.getLogSyslogdSetting],
        ['password_policy', api.getPasswordPolicy],
        ['fortiguard', api.getFortiguard],
        ['autoupdate_schedule', api.getAutoupdateSchedule],
      ];

      const parsed = {};
      for (const [key, fetchFn] of sections) {
        try {
          // redactSecretFields: defence in depth. `parsed` lands in
          // device_configs.config_parsed, which is readable by the claude_readonly /
          // nocvault_readonly roles, and it is NOT verified whether FortiOS blanks
          // secret fields on a cmdb GET (system/admin in particular). Fail closed.
          parsed[key] = parser.redactSecretFields(parser.extractResults(await fetchFn(conn)));
        } catch (err) {
          console.warn(
            `[Fortinet] config section '${key}' fetch failed for device ${this.device.id}: ${err.message}`
          );
          parsed[key] = null;
        }
      }

      // Fix: this REST transport never set collected_via at all (parsed[key] entries
      // only), while the SSH transport's parseFullConfiguration() always sets
      // collected_via: 'ssh' — a real shape asymmetry between the two config_parsed
      // producers, confirmed by direct read of both files. 'api' matches this vendor's
      // mgmt_method value for the REST access method (VENDOR_META in
      // components/devices/vendorMeta.js / ADAPTERS dispatch key) — not 'rest'.
      parsed.collected_via = 'api';

      let raw = null;
      try {
        raw = await api.getConfigBackup(conn);
      } catch (err) {
        console.warn(
          `[Fortinet] config backup fetch failed for device ${this.device.id} (token may lack backup permission) — using parsed JSON as raw: ${err.message}`
        );
        raw = null;
      }

      if (typeof raw !== 'string' || raw.length === 0) {
        raw = JSON.stringify(parsed);
      } else {
        // SECURITY: /monitor/system/config/backup returns a FortiOS full configuration
        // — admin password hashes (`set passwd ENC ...`), `set psksecret`, PEM private
        // keys, SNMP communities. It is persisted verbatim into
        // device_configs.config_raw, copied into config_backups, served by the backup
        // download route, and BOTH tables are GRANT SELECT'd to claude_readonly /
        // nocvault_readonly — the roles CLAUDE.md bars from device_credentials.
        // Nothing downstream redacts, so redact here before it leaves the adapter.
        // (CLAUDE.md "Stored configs are REDACTED" / "Any NEW adapter that returns a
        // raw text config MUST redact before returning it from getConfig()".)
        raw = cliParser.redactConfig(raw);
      }

      return { raw, parsed };
    });
  }

  // → { active_session_count, raw } — an OPTIONAL adapter capability, not
  // part of the FirewallAdapter base interface. See
  // FortinetSshAdapter.getVpnSessionSummary() (ssh.js) for the full
  // doc-derived/optional-capability explanation this mirrors. Counts
  // entries in the /monitor/vpn/ssl response's `results` array rather than
  // parsing individual session fields — narrower, lower-risk surface than
  // fully modeling per-session shape, and all that this feature needs.
  //
  // ⛔ Bug fixed 2026-07-19: now VDOM-aware, mirroring getRules()'s existing
  // _discoverVdoms()/per-VDOM loop — omitting `vdom` silently returns only
  // the admin token's default VDOM's sessions on a multi-VDOM box, the same
  // class of bug CLAUDE.md's VDOM rule already covers for getRules(). Unlike
  // getRules(), a single VDOM's monitor-endpoint failure here does NOT abort
  // the whole poll (see the try/catch below) — VDOM enumeration failing
  // entirely still throws (nothing to sum), but one VDOM erroring out of
  // several degrades to a partial (documented as such via `raw.partial`)
  // rather than losing the whole session count, since this is a coarse
  // trend signal, not an authoritative ruleset the way getRules() is.
  async getVpnSessionSummary() {
    return this._withSession(async (conn) => {
      const vdoms = await this._discoverVdoms(conn);

      if (!vdoms || vdoms.length <= 1) {
        const response = await api.getSslVpnMonitor(conn);
        const results = parser.extractResults(response);
        if (!Array.isArray(results)) {
          throw new Error(
            `FortiGate GET /api/v2/monitor/vpn/ssl on device ${this.device.id} did not return an ` +
              "array of sessions under the expected 'results' key — refusing to guess a session count."
          );
        }
        // Per-user detail is ADDITIVE and best-effort — normalizing the counted
        // entries must never disturb the authoritative count (results.length) above.
        let sessions = [];
        try {
          sessions = results.map(restSslVpnSessionToNormalized).filter(Boolean);
        } catch (_err) {
          sessions = [];
        }

        return {
          active_session_count: results.length,
          sessions,
          raw: { source_endpoint: '/api/v2/monitor/vpn/ssl', count: results.length },
        };
      }

      let total = 0;
      let anySucceeded = false;
      const perVdom = {};
      // ADDITIVE per-user detail, aggregated across VDOMs — kept in its own
      // accumulator so it can never interfere with the count.
      const allSessions = [];
      for (const vdom of vdoms) {
        try {
          const response = await api.getSslVpnMonitor(conn, vdom);
          const results = parser.extractResults(response);
          if (!Array.isArray(results)) {
            throw new Error(`no 'results' array for VDOM "${vdom}"`);
          }
          total += results.length;
          perVdom[vdom] = results.length;
          anySucceeded = true;

          // Best-effort, AFTER the count is recorded: a normalization failure must
          // never undo this VDOM's counted total. Tag each row's gateway with the
          // VDOM name when the entry itself carried no portal/realm.
          try {
            for (const e of results) {
              const s = restSslVpnSessionToNormalized(e);
              if (s) allSessions.push({ ...s, gateway: s.gateway || vdom });
            }
          } catch (_err) {
            // Detail unavailable for this VDOM — count already recorded, ignore.
          }
        } catch (err) {
          console.warn(
            `[Fortinet] VPN session monitor failed for VDOM "${vdom}" on device ${this.device.id}: ${err.message}`
          );
          perVdom[vdom] = null;
        }
      }

      if (!anySucceeded) {
        throw new Error(
          `FortiGate GET /api/v2/monitor/vpn/ssl failed for every VDOM on device ${this.device.id} — ` +
            'refusing to guess a session count.'
        );
      }

      return {
        active_session_count: total,
        sessions: allSessions,
        raw: { source_endpoint: '/api/v2/monitor/vpn/ssl', per_vdom: perVdom, partial: Object.values(perVdom).some((v) => v === null) },
      };
    });
  }

  // → NormalizedIpsecTunnel[] — an OPTIONAL adapter capability, NOT part of the
  // FirewallAdapter base interface, and SEPARATE from getVpnSessionSummary() above
  // (that counts SSL-VPN user sessions; this reports IPSec SITE-TO-SITE tunnel
  // state). Each element is { name, peer, status, ike_version, bytes_in, bytes_out,
  // raw } (any field may be null). Returns [] when the device has no IPSec tunnels
  // — a legitimate empty state, NOT an error. MAY throw when the endpoint itself
  // errors (the engine-worker catches and logs per-device).
  //
  // VDOM-aware, mirroring getVpnSessionSummary()/getRules()'s _discoverVdoms() +
  // per-VDOM loop: omitting `vdom` would return only the admin token's default
  // VDOM's tunnels on a multi-VDOM box (the silent-under-report class CLAUDE.md's
  // VDOM rule covers). A single VDOM's endpoint failure degrades to a partial (that
  // VDOM is skipped) rather than losing the whole set; only a total failure of every
  // VDOM throws. Per-VDOM rows are tagged with their source VDOM under `raw.vdom` so
  // the normalized top-level shape stays exactly the 7 contract fields.
  async getVpnTunnels() {
    return this._withSession(async (conn) => {
      const vdoms = await this._discoverVdoms(conn);

      if (!vdoms || vdoms.length <= 1) {
        const response = await api.getIpsecTunnels(conn);
        const results = parser.extractResults(response);
        if (!Array.isArray(results)) {
          throw new Error(
            `FortiGate GET /api/v2/monitor/vpn/ipsec on device ${this.device.id} did not return an ` +
              "array of tunnels under the expected 'results' key — refusing to guess."
          );
        }
        if (!loggedFirstIpsecResponse) {
          console.log(
            '[Fortinet Debug] Raw /monitor/vpn/ipsec first entry:',
            JSON.stringify(results[0] || null, null, 2)
          );
          loggedFirstIpsecResponse = true;
        }
        // parseIpsecTunnelList's REST sibling normalizer never throws; the try/catch
        // is belt-and-suspenders so a normalization surprise degrades to [] rather
        // than propagating.
        let tunnels = [];
        try {
          tunnels = results.map(restIpsecTunnelToNormalized).filter(Boolean);
        } catch (_err) {
          tunnels = [];
        }
        return tunnels;
      }

      const allTunnels = [];
      let anySucceeded = false;
      for (const vdom of vdoms) {
        try {
          const response = await api.getIpsecTunnels(conn, vdom);
          const results = parser.extractResults(response);
          if (!Array.isArray(results)) {
            throw new Error(`no 'results' array for VDOM "${vdom}"`);
          }
          if (!loggedFirstIpsecResponse) {
            console.log(
              '[Fortinet Debug] Raw /monitor/vpn/ipsec first entry:',
              JSON.stringify(results[0] || null, null, 2)
            );
            loggedFirstIpsecResponse = true;
          }
          for (const e of results) {
            const t = restIpsecTunnelToNormalized(e);
            if (t) {
              const rawWithVdom = { ...(t.raw && typeof t.raw === 'object' ? t.raw : {}), vdom };
              allTunnels.push({ ...t, raw: rawWithVdom });
            }
          }
          anySucceeded = true;
        } catch (err) {
          console.warn(
            `[Fortinet] IPSec tunnel monitor failed for VDOM "${vdom}" on device ${this.device.id}: ${err.message}`
          );
        }
      }

      if (!anySucceeded) {
        throw new Error(
          `FortiGate GET /api/v2/monitor/vpn/ipsec failed for every VDOM on device ${this.device.id} — ` +
            'refusing to report an IPSec tunnel list.'
        );
      }

      return allTunnels;
    });
  }

  // → { addresses, addressGroups, services, serviceGroups } — an OPTIONAL adapter
  // capability, not part of the FirewallAdapter base interface. See
  // lib/adapters/interface.js's getObjects() contract comment. Collects the
  // device's named address/service OBJECT CATALOG (the objects/groups DEFINED on
  // the device) — distinct from getFirewallPolicies()'s already-collected RESOLVED
  // rule field values — for lib/engines/objectUsage.js's unused/duplicate-object
  // detection.
  //
  // Endpoints: GET .../cmdb/firewall/address, .../firewall/addrgrp,
  // .../firewall.service/custom, .../firewall.service/group — real, documented
  // FortiOS cmdb endpoints (same `?vdom=` param convention as
  // getFirewallPolicies() above), collected once per VDOM discovered via the same
  // `_discoverVdoms()` this class already uses for getRules()/
  // getVpnSessionSummary(). Field names are DOC-DERIVED, not yet live-verified —
  // see the mapping helpers above this class and CLAUDE.md's Live Validation
  // Status.
  //
  // Unlike getRules()/getConfig(), this method must NEVER throw: each of the 4
  // sub-categories is independently try/caught here AND internally degrades a
  // single VDOM's failure to "skip that VDOM, keep the rest" (see
  // _collectObjectCategory()) — a partial object catalog is still useful data,
  // with none of getRules()'s destructive DELETE-then-nothing risk (CLAUDE.md).
  //
  // `network_objects` (the DB table this feeds) has no vdom column — an
  // identically-named object collected from two different VDOMs on the same
  // device silently collapses to whichever was inserted last. Accepted, documented
  // simplification, not something this method needs to solve.
  async getObjects() {
    return this._withSession(async (conn) => {
      const vdoms = await this._discoverVdoms(conn);
      const vdomList = vdoms && vdoms.length > 0 ? vdoms : [null];

      let addresses = [];
      try {
        addresses = await this._collectObjectCategory(
          conn,
          vdomList,
          api.getFirewallAddresses,
          'addresses',
          restAddressToNamedAddress
        );
      } catch (err) {
        console.warn(
          `[Fortinet] getObjects(): addresses collection failed entirely for device ${this.device.id}: ${err.message}`
        );
      }

      let addressGroups = [];
      try {
        addressGroups = await this._collectObjectCategory(
          conn,
          vdomList,
          api.getFirewallAddrgrp,
          'addressGroups',
          restGroupToNamedGroup
        );
      } catch (err) {
        console.warn(
          `[Fortinet] getObjects(): addressGroups collection failed entirely for device ${this.device.id}: ${err.message}`
        );
      }

      let services = [];
      try {
        services = await this._collectObjectCategory(
          conn,
          vdomList,
          api.getFirewallServiceCustom,
          'services',
          restServiceToNamedService
        );
      } catch (err) {
        console.warn(
          `[Fortinet] getObjects(): services collection failed entirely for device ${this.device.id}: ${err.message}`
        );
      }

      let serviceGroups = [];
      try {
        serviceGroups = await this._collectObjectCategory(
          conn,
          vdomList,
          api.getFirewallServiceGroup,
          'serviceGroups',
          restGroupToNamedGroup
        );
      } catch (err) {
        console.warn(
          `[Fortinet] getObjects(): serviceGroups collection failed entirely for device ${this.device.id}: ${err.message}`
        );
      }

      return { addresses, addressGroups, services, serviceGroups };
    });
  }

  // Runs `fetchFn(conn, vdom)` once per VDOM in `vdomList`, maps every returned
  // result via `mapFn`, and never throws — a single VDOM's failure (or a
  // non-array response) is logged and skipped, keeping whatever the other VDOMs
  // already produced. Mirrors getRules()'s per-VDOM loop shape but with
  // getObjects()'s required graceful degradation instead of getRules()'s
  // fail-loud one (see the class-level getObjects() doc comment above).
  async _collectObjectCategory(conn, vdomList, fetchFn, label, mapFn) {
    const out = [];
    for (const vdom of vdomList) {
      const where = vdom ? ` for VDOM "${vdom}"` : '';
      try {
        const body = await fetchFn(conn, vdom);
        const results = parser.extractResults(body);
        if (!Array.isArray(results)) {
          console.warn(
            `[Fortinet] getObjects(): ${label} response${where} on device ${this.device.id} had ` +
              'no results array — skipping.'
          );
          continue;
        }
        for (const entry of results) {
          try {
            const mapped = mapFn(entry);
            if (mapped) out.push(mapped);
          } catch (err) {
            console.warn(
              `[Fortinet] getObjects(): failed to map one ${label} entry${where} on device ` +
                `${this.device.id} — skipping it: ${err.message}`
            );
          }
        }
      } catch (err) {
        console.warn(
          `[Fortinet] getObjects(): ${label} fetch failed${where} on device ${this.device.id}: ${err.message}`
        );
      }
    }
    return out;
  }

  // → { cpuPercent, memoryPercent, sessionCount, uptimeSeconds, raw,
  //     lowConfidence, targetHost } — an OPTIONAL adapter capability, not
  // part of the FirewallAdapter base interface. See
  // lib/adapters/interface.js's getSnmpMetrics() contract comment. Uses a
  // SEPARATE credential (credential_type='snmp') from this adapter's own
  // REST/session credential — never gated on or mixed with
  // testConnectivity()/getRules()'s auth. All four OIDs are true scalars
  // (see SNMP_OID above), so a single getMetrics() GET is all that's needed
  // — no walkSubtree() required, unlike Cisco ASA's equivalent. MAY throw
  // (missing credential, timeout, auth failure) — engine-worker's
  // snmp-poll job already treats that exactly like any other per-device
  // polling failure (logged and skipped, never fatal).
  async getSnmpMetrics() {
    const plaintext = await credStore.getCredential(this.device.id, 'snmp', this.pool);
    if (!plaintext) {
      throw new Error(
        `No SNMP credential found for device ${this.device.id} — configure one under the device SNMP tab before polling.`
      );
    }
    const credential = parseSnmpCredential(plaintext);

    const targetHost = this.device.snmp_host || this.device.mgmt_ip;
    if (!targetHost) {
      throw new Error(`Device ${this.device.id} has no snmp_host or mgmt_ip to poll for SNMP metrics.`);
    }
    const targetPort = this.device.snmp_port || 161;

    const session = createSession(credential, targetHost, targetPort);
    try {
      const result = await getMetrics(session, SNMP_OID, undefined, targetHost);

      if (!loggedFirstSnmpResponse) {
        loggedFirstSnmpResponse = true;
        // CLAUDE.md live-verification rule: log the raw OID responses once so the
        // first real connection can be used to confirm/correct SNMP_OID above.
        console.log('[Fortinet SNMP Debug] raw responses:', JSON.stringify(result));
      }

      const uptimeTicks = result.sysUpTime;
      const uptimeSeconds =
        uptimeTicks !== null && uptimeTicks !== undefined && !Number.isNaN(Number(uptimeTicks))
          ? Math.round(Number(uptimeTicks) / 100)
          : null;

      const cpuPercent =
        result.fgSysCpuUsage !== null && result.fgSysCpuUsage !== undefined && !Number.isNaN(Number(result.fgSysCpuUsage))
          ? Number(result.fgSysCpuUsage)
          : null;

      const memoryPercent =
        result.fgSysMemUsage !== null && result.fgSysMemUsage !== undefined && !Number.isNaN(Number(result.fgSysMemUsage))
          ? Number(result.fgSysMemUsage)
          : null;

      const sessionCount =
        result.fgSysSesCount !== null && result.fgSysSesCount !== undefined && !Number.isNaN(Number(result.fgSysSesCount))
          ? Number(result.fgSysSesCount)
          : null;

      return {
        cpuPercent,
        memoryPercent,
        sessionCount,
        uptimeSeconds,
        raw: result,
        lowConfidence: false,
        targetHost,
      };
    } finally {
      closeSession(session);
    }
  }
}

module.exports = { FortinetAdapter, FortinetSshAdapter };
