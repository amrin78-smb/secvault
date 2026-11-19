// lib/adapters/sophos/index.js
// CommonJS ONLY — required by lib/adapters/index.js, which services/
// engine-worker.js require()s under plain node.
//
// Sophos SFOS adapter. TWO TRANSPORTS IN ONE ADAPTER, which is unusual here and
// is forced by the device rather than chosen:
//
//   XML API  (:4444)  rules, config, objects, interfaces, zones
//   SSH console (:22) version, HA, disk, memory
//
// ⛔ THE SPLIT IS NOT A PREFERENCE. The XML API has no version surface at all —
// nine candidate entity names return `code 529, Input request module is
// Invalid`, and `APIVersion="2200.1"` does not track the firmware patch level,
// so it cannot drive CVE matching. Conversely the SSH console has no command
// that dumps the rulebase. Neither transport can do the other's job.
//
// ⛔ A DEVICE WITH NO SSH CREDENTIAL STILL COLLECTS. getVersion() throws a
// named, actionable error; collectAndStore() isolates that into result.errors
// and carries on with rules and config. The cost is stated rather than hidden:
// with no version there is no CVE assessment, and v2.230.0's guard means such a
// firewall is reported as NOT ASSESSED rather than silently not-affected.
//
// ⛔ getLicenses() IS DELIBERATELY ABSENT, not stubbed. Measured on BOTH
// transports: nine XML entity names return 529, `system license show` and
// `system diagnostics show subscription-info` both return `Unknown Parameter`,
// and the full `system diagnostics show` command list contains nothing
// licence-shaped. The optional-capability contract in ../interface.js says an
// absent method is how an adapter declares a capability it does not have, so
// /lifecycle shows Sophos as not collectable rather than as "no renewals due" —
// which would make the one vendor we cannot read look like the healthiest.
//
// Every shape here was verified against a live SFOS 22.0.3 MR-3-Build576
// appliance on 2026-11-19. Evidence: secvault-lab/findings/.

'use strict';

const { FirewallAdapter, CapabilityUnavailableError } = require('../interface');
const credStore = require('../../credStore');
const { parseApiCredential } = require('../credentials');
const { parseJsonCredential } = require('../sshClient');
const api = require('./api');
const parser = require('./parser');
const consoleClient = require('./console');

// ⛔ The config snapshot is a BOUNDED set of entities, deliberately.
// `ApplicationFilterPolicy` measured 305 KB and `WebFilterPolicy` 40 KB on an
// appliance with NOTHING configured — on a real one they are far larger, and
// `device_configs` stores one row per pull whether or not anything changed.
// CLAUDE.md records that table reaching 449 MB of a 529 MB database. These
// entities are the ones a compliance check or a config diff actually reads;
// the vendor's own signature catalogues are not configuration.
const CONFIG_ENTITIES = [
  'AdminSettings',      // password policy, login security — directly gradeable
  'SystemServices',     // per-service state
  'Zone',               // per-zone appliance access
  'Interface',
  'DNS',
  'Time',
  'Notification',
  'SyslogServers',
  'AuthenticationServer',
  'SSLTLSInspectionRule',
  'VPNIPSecConnection',
  'Certificate',
];

let loggedFirstRules = false;
let loggedFirstVersion = false;

class SophosAdapter extends FirewallAdapter {
  constructor({ device, pool }) {
    super({ device, pool });
    this._apiConn = null;
    this._sshConn = null;
  }

  // Always passes this.pool — never omit it (CLAUDE.md Pool Warning).
  async _getApiConn() {
    if (this._apiConn) return this._apiConn;
    const plaintext = await credStore.getCredential(this.device.id, 'rest_api', this.pool);
    if (!plaintext) {
      throw new Error(
        `No SFOS API credential found for device ${this.device.id} — save credentials before connecting.`
      );
    }
    // Never surfaces the plaintext in its errors — see ../credentials.js.
    const { username, password } = parseApiCredential(plaintext, 'Sophos device');
    if (!username || !password) {
      // ⛔ SFOS has no API-key auth mode: the XML API authenticates with a
      // username and password inside every request body. A credential stored
      // as a bare api-key string cannot work here, and saying so is better
      // than a 401 the operator has to interpret.
      throw new Error(
        'The SFOS XML API authenticates with a username and password; '
        + 'this device has no username/password credential stored.'
      );
    }
    this._apiConn = {
      host: this.device.mgmt_ip,
      port: this.device.mgmt_port || api.DEFAULT_PORT,
      username,
      password,
      allowSelfSignedSsl: this.device.allow_self_signed_ssl !== false,
    };
    return this._apiConn;
  }

  /**
   * ⛔ Falls back to the API credential when no separate `ssh` credential is
   * stored. It is the SAME ADMIN ACCOUNT on the SAME APPLIANCE — SFOS does not
   * have separate API and CLI identities — so demanding the operator save the
   * same password twice buys nothing and loses getVersion() whenever they do
   * not. An explicit `ssh` credential still wins, for an installation that has
   * given the console its own account.
   */
  async _getSshConn() {
    if (this._sshConn) return this._sshConn;
    let username = null;
    let password = null;

    const sshPlain = await credStore.getCredential(this.device.id, 'ssh', this.pool);
    if (sshPlain) {
      const parsed = parseJsonCredential(sshPlain);
      username = parsed.username;
      password = parsed.password;
    } else {
      const apiConn = await this._getApiConn();
      username = apiConn.username;
      password = apiConn.password;
    }

    this._sshConn = { host: this.device.mgmt_ip, port: 22, username, password };
    return this._sshConn;
  }

  // → { ok, latency_ms, message } — must never throw.
  async testConnectivity() {
    const startedAt = Date.now();
    try {
      const conn = await this._getApiConn();
      // Zone is tiny, always present and needs no feature to be configured.
      await api.getEntity(conn, 'Zone');
      return { ok: true, latency_ms: Date.now() - startedAt, message: 'Connected' };
    } catch (err) {
      // api.js has already redacted; this is belt-and-braces for a credential
      // error thrown before the request was built.
      return { ok: false, latency_ms: null, message: api.redactSecrets(err.message, []) };
    }
  }

  // → { version_string, version_tuple, build, model, serial, contentVersions }
  async getVersion() {
    const conn = await this._getSshConn();
    const out = await consoleClient.run(conn, [consoleClient.CMD_VERSION]);
    const text = out[consoleClient.CMD_VERSION];

    if (!loggedFirstVersion) {
      // First-connect verification aid, same convention as every other adapter
      // here: field names are checked against the live device before the
      // mappings are trusted (CLAUDE.md: documentation lies).
      console.log('[Sophos Debug] version-info output:', JSON.stringify(text));
      loggedFirstVersion = true;
    }

    const parsed = consoleClient.parseVersionInfo(text);
    if (!parsed.version_string || !parsed.version_tuple) {
      // ⛔ Reached the device, got output, could not read a version from it.
      // NOT a connectivity failure — conflating the two is what
      // CapabilityUnavailableError exists to stop, and it would mark a
      // perfectly reachable firewall as down.
      throw new CapabilityUnavailableError(
        'SFOS returned no readable firmware version from `system diagnostics show version-info`.',
        { capability: 'getVersion' }
      );
    }
    return parsed;
  }

  // → NormalizedRule[]. ⛔ THROWS on a retrieval failure, never returns [].
  async getRules() {
    const conn = await this._getApiConn();
    const { records, empty } = await api.getEntity(conn, 'FirewallRule');

    if (!loggedFirstRules) {
      console.log('[Sophos Debug] FirewallRule record[0]:', JSON.stringify(records[0] || null));
      loggedFirstRules = true;
    }

    // ⛔ `empty` here is the DEVICE saying `No. of records Zero.` — a
    // measurement that this firewall genuinely has no rules, which is a real
    // state on a newly provisioned appliance. It is NOT the same as a failed
    // read, which api.getEntity() throws for. Returning [] is correct ONLY on
    // this branch.
    if (empty) return [];

    // parser.parseFirewallRules throws rather than returning a mis-ordered
    // rulebase — SFOS expresses order as a linked list with no sequence number.
    return parser.parseFirewallRules(records);
  }

  // → { raw, parsed }
  async getConfig() {
    const conn = await this._getApiConn();
    const parsed = {};
    const rawParts = [];
    const failures = [];

    for (const entity of CONFIG_ENTITIES) {
      try {
        const { records, empty } = await api.getEntity(conn, entity, {
          timeoutMs: api.CONFIG_REQUEST_TIMEOUT_MS,
        });
        parsed[entity] = empty ? [] : records;
        rawParts.push(`<!-- ${entity} -->\n${JSON.stringify(records, null, 2)}`);
      } catch (err) {
        // ⛔ A per-entity failure is RECORDED, not swallowed and not fatal. A
        // config snapshot missing one section is still a useful diff baseline;
        // a snapshot that silently lost a section would show up as that
        // section being DELETED from the device — which is exactly the
        // whole-config read failure v2.226.0 records as having told an
        // operator somebody wiped five subsystems of a firewall.
        failures.push(`${entity}: ${api.redactSecrets(err.message, [])}`);
      }
    }

    if (Object.keys(parsed).length === 0) {
      throw new Error(
        `SFOS config collection failed for every entity: ${failures.join('; ')}`
      );
    }
    if (failures.length) parsed.$collectionErrors = failures;

    // ⛔ REDACT BEFORE IT LEAVES THE ADAPTER. device_configs and config_backups
    // are GRANT SELECT'd to claude_readonly / nocvault_readonly, which are
    // barred from device_credentials — a secret reaching a config row defeats
    // that separation. Nothing downstream redacts. The PARSED tree is redacted
    // through the same function (defence in depth), so the two cannot disagree.
    const raw = parser.redactConfigXml(rawParts.join('\n\n'));
    return { raw, parsed: JSON.parse(parser.redactConfigXml(JSON.stringify(parsed))) };
  }

  // OPTIONAL — see ../interface.js. Degrades per sub-category rather than
  // throwing whole: a partial object catalogue is useful data with no
  // destructive-empty consequence, unlike getRules().
  async getObjects() {
    const conn = await this._getApiConn();
    const fetch = async (entity) => {
      try {
        const { records, empty } = await api.getEntity(conn, entity);
        return empty ? [] : records;
      } catch (err) {
        console.warn(`[Sophos] ${entity} fetch failed for ${this.device.id}: ${err.message}`);
        return [];
      }
    };
    const [hosts, hostGroups, services, serviceGroups] = await Promise.all([
      fetch('IPHost'), fetch('IPHostGroup'), fetch('Services'), fetch('ServiceGroup'),
    ]);
    return parser.parseObjects({ hosts, hostGroups, services, serviceGroups });
  }

  // OPTIONAL — topology collection.
  async getInterfaces() {
    const conn = await this._getApiConn();
    const { records, empty } = await api.getEntity(conn, 'Interface');
    return { interfaces: empty ? [] : parser.parseInterfaces(records) };
  }

  /**
   * OPTIONAL — routing.
   * ⛔ `UnicastRoute` returns STATIC routes only. The DHCP-learned default
   * route is NOT in it (verified: the lab appliance had a working default route
   * via DHCP and this entity reported zero records). So this is a partial
   * table, and it is reported as what it is rather than presented as the FIB.
   */
  async getRoutingTable() {
    const conn = await this._getApiConn();
    const { records, empty } = await api.getEntity(conn, 'UnicastRoute');
    if (empty) return { routes: [] };
    return {
      routes: records
        .filter((r) => r && r.DestinationIP)
        .map((r) => ({
          destinationCidr: parser.cidrFromMask(String(r.DestinationIP), String(r.Netmask || '')),
          nextHopIp: r.Gateway ? String(r.Gateway) : null,
          interfaceName: r.Interface ? String(r.Interface) : null,
          protocol: 'static',
          metric: null,
          vdom: null,
        }))
        .filter((r) => r.destinationCidr !== null),
    };
  }

  // OPTIONAL — lifecycle.
  async getHaStatus() {
    const conn = await this._getSshConn();
    const out = await consoleClient.run(conn, [consoleClient.CMD_HA]);
    // null here means COULD NOT DETERMINE and the caller stores nothing,
    // leaving the previous row intact — see parseHaStatus for why only the
    // disabled case is parsed.
    return consoleClient.parseHaStatus(out[consoleClient.CMD_HA]);
  }

  async getDiskUsage() {
    const conn = await this._getSshConn();
    const out = await consoleClient.run(conn, [consoleClient.CMD_DISK]);
    const parsedDisk = consoleClient.parseDiskUsage(out[consoleClient.CMD_DISK]);
    if (parsedDisk.filesystems.length === 0) {
      throw new CapabilityUnavailableError(
        'SFOS returned no readable partition usage from `system diagnostics show disk`.',
        { capability: 'getDiskUsage' }
      );
    }
    return parsedDisk;
  }

  /**
   * OPTIONAL — performance metrics.
   * ⛔ `cpuPercent` IS ALWAYS NULL FROM THIS TRANSPORT, and that is a finding
   * rather than an omission: `system diagnostics show cpu` returns
   * /proc/cpuinfo — a processor model name and core count, with no load figure
   * anywhere. Reporting it as a CPU metric would put hardware identity where a
   * percentage belongs. CPU utilisation for Sophos arrives in the syslog
   * System Health class instead.
   */
  async getPerformanceMetrics() {
    const conn = await this._getSshConn();
    const out = await consoleClient.run(conn, [consoleClient.CMD_MEMORY]);
    const mem = consoleClient.parseMemory(out[consoleClient.CMD_MEMORY]);
    return {
      cpuPercent: null,
      memoryPercent: mem.memoryPercent,
      sessionCount: null,
      uptimeSeconds: null,
      raw: { source: consoleClient.CMD_MEMORY, ...mem.raw },
    };
  }
}

module.exports = SophosAdapter;
module.exports.SophosAdapter = SophosAdapter;
module.exports.CONFIG_ENTITIES = CONFIG_ENTITIES;
