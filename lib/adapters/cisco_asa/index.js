// lib/adapters/cisco_asa/index.js
// Cisco ASA adapter — SSH/CLI based (no management-plane API assumed).
// CommonJS ONLY — required (indirectly) by services/engine-worker.js.
//
// See CLAUDE.md — in particular the Pool Warning: testConnectivity() and any
// function touching credStore/DB must always receive and use `this.pool`,
// even though it looks like a pure connectivity check. Removing pool builds
// clean and silently breaks credential decryption at runtime.

'use strict';

const { FirewallAdapter } = require('../interface');
const credStore = require('../../credStore');
const { runCommands, parseJsonCredential } = require('../sshClient');
const parser = require('./parser');
const { parseVersion } = require('../../engines/versionComparator');
const { createSession, getMetrics, walkSubtree, closeSession } = require('../../snmpClient');
const { parseSnmpCredential } = require('../snmpCredential');

// ASA prompts: "hostname>" (user EXEC) / "hostname#" (privileged EXEC).
// NO `m` flag — see the DEFAULT_PROMPT_REGEX comment in ../sshClient.js. With
// `m`, `banner motd ####` (# is ASA's conventional banner delimiter) matches
// mid-config and silently truncates `show running-config`.
const ASA_PROMPT_REGEX = /[>#]\s*$/;

// SNMP OIDs for getSnmpMetrics() — doc-derived, NOT yet live-verified against
// a real SecVault-connected ASA (see CLAUDE.md's "Live Validation Status"
// discipline: log-and-confirm on first live poll). All four are drawn from
// standard, well-documented Cisco MIBs (confirmed against Cisco's own MIB
// reference + oidref.com during this feature's build), which is why
// lowConfidence stays false for this vendor — see the getSnmpMetrics() method
// comment below for what that flag actually means here.
//
// - sysUpTime.0 (MIB-II, RFC 1213) — universal, no vendor-specific doc needed.
// - cfwConnectionStatValue (CISCO-FIREWALL-MIB), the specific verified
//   instance for "current global connections in use":
//   1.3.6.1.4.1.9.9.147.1.2.2.2.1.5.40.6 (table root
//   1.3.6.1.4.1.9.9.147.1.2.2.2.1, suffix .5.40.6 selects that stat). Source:
//   Cisco's "SNMP MIBs and Traps on the ASA" community doc + the Cisco Secure
//   Firewall MIB Reference Guide.
// - cpmCPUTotal5minRev (CISCO-PROCESS-MIB), table root
//   1.3.6.1.4.1.9.9.109.1.1.1.1.8 — walked (per-CPU table; an ASA typically
//   has one row), value is already a 0-100 percentage. Confirmed via
//   oidref.com / Cisco's "Collect CPU Utilization on Cisco IOS Devices with
//   SNMP" doc.
// - ciscoMemoryPoolUsed / ciscoMemoryPoolFree (CISCO-MEMORY-POOL-MIB), table
//   roots 1.3.6.1.4.1.9.9.48.1.1.1.5 / .6 — sibling columns in the same
//   table; sum of used+free is the pool total (confirmed live via
//   oidref.com's own OID description text during this feature's build, not
//   assumed).
const SNMP_OID = {
  sysUpTime: '1.3.6.1.2.1.1.3.0',
  cfwConnectionCurrentInUse: '1.3.6.1.4.1.9.9.147.1.2.2.2.1.5.40.6',
};
const SNMP_CPU_TABLE_BASE = '1.3.6.1.4.1.9.9.109.1.1.1.1.8'; // cpmCPUTotal5minRev
const SNMP_MEM_USED_TABLE_BASE = '1.3.6.1.4.1.9.9.48.1.1.1.5'; // ciscoMemoryPoolUsed
const SNMP_MEM_FREE_TABLE_BASE = '1.3.6.1.4.1.9.9.48.1.1.1.6'; // ciscoMemoryPoolFree

let snmpDebugLogged = false;

class CiscoAsaAdapter extends FirewallAdapter {
  constructor({ device, pool }) {
    super({ device, pool });
  }

  // Builds the SSH connection descriptor + shell options, decrypting the
  // stored credential via credStore. ALWAYS uses this.pool (CLAUDE.md Pool
  // Warning — never omit it).
  // Credential plaintext is JSON: {"username":"...","password":"...","enable_password":"..."}
  // (enable_password optional).
  async _getSession() {
    const plaintext = await credStore.getCredential(this.device.id, 'ssh', this.pool);
    if (!plaintext) {
      throw new Error(
        `No SSH credential found for device ${this.device.id} — save credentials before connecting.`
      );
    }

    const cred = parseJsonCredential(plaintext);

    return {
      conn: {
        host: this.device.mgmt_ip,
        port: this.device.mgmt_port || 22,
        username: cred.username,
        password: cred.password,
      },
      options: {
        promptRegex: ASA_PROMPT_REGEX,
        initCommands: ['terminal pager 0'],
        enablePassword: cred.enable_password || null,
      },
    };
  }

  // Runs commands in one SSH shell session against this device.
  async _run(commands) {
    const { conn, options } = await this._getSession();
    return runCommands(conn, commands, options);
  }

  // → { ok, latency_ms, message } — must never throw.
  async testConnectivity() {
    const startedAt = Date.now();
    try {
      try {
        const results = await this._run(['show version | include Version']);
        const output = results[0] ? results[0].output : '';
        // ASA supports `| include`, but be defensive: if the pipe errored
        // ("ERROR: % Invalid input ...") or filtered everything away, fall
        // back to a plain `show version`.
        if (/%\s*(invalid|error)/i.test(output) || !/version/i.test(output)) {
          throw new Error('pipe filter not supported or returned no output');
        }
      } catch (pipeErr) {
        await this._run(['show version']);
      }
      return { ok: true, latency_ms: Date.now() - startedAt, message: 'Connected' };
    } catch (err) {
      return { ok: false, latency_ms: null, message: err.message };
    }
  }

  // → { version_string, version_tuple, build, model }
  async getVersion() {
    const results = await this._run(['show version']);
    const raw = results[0] ? results[0].output : '';

    // First-integration debug logging (same pattern as the Forcepoint SMC
    // adapter — no live device was available during this build, so the raw
    // output is logged to verify/adjust parser patterns on first real connect).
    console.log('[CiscoASA Debug] show version raw output:', raw);

    const info = parser.parseShowVersion(raw);
    return {
      version_string: info.version_string,
      version_tuple: parseVersion('cisco_asa', info.version_string),
      build: info.build,
      model: info.model,
    };
  }

  // → NormalizedRule[]
  async getRules() {
    const results = await this._run(['show running-config access-list']);
    const aclOutput = results[0] ? results[0].output : '';

    // `show running-config ...` requires privileged EXEC. Without it the ASA
    // answers with a rejection, which parseAccessListConfig would happily read
    // as "zero ACEs" — and collectAndStore would then DELETE every previously
    // collected rule for this device and report success (rulesCount: 0).
    // A wrong/absent enable password must fail loudly, not silently wipe rules.
    if (parser.looksLikeCliError(aclOutput)) {
      throw new Error(this._privilegeErrorMessage('show running-config access-list'));
    }

    const rules = parser.parseAccessListConfig(aclOutput);

    // Hit counts are best-effort enrichment: fetched in a separate session
    // and wrapped in their own try/catch so a `show access-list` failure (or
    // any parse problem) never breaks the rule pull itself — rules keep
    // their default hit_count of 0.
    try {
      const hitResults = await this._run(['show access-list']);
      const counts = parser.parseHitCounts(hitResults[0] ? hitResults[0].output : '');
      for (const rule of rules) {
        const key = parser.normalizeAceForMatch(rule.rule_id_vendor);
        if (key in counts) rule.hit_count = counts[key];
      }
    } catch (err) {
      console.warn(
        `[CiscoASA] Hit count collection failed for device ${this.device.id} (rules kept with hit_count=0): ${err.message}`
      );
    }

    return rules;
  }

  // Shared, credential-safe message for "the CLI rejected a privileged command".
  // Never echoes the device output — a partial config dump could contain secrets.
  _privilegeErrorMessage(command) {
    return (
      `Cisco ASA rejected \`${command}\` on device ${this.device.id}. This almost always means ` +
      'the SSH session never reached privileged EXEC mode: set or correct "enable_password" in ' +
      'the device credential JSON ({"username","password","enable_password"}), or give the SSH ' +
      'user privilege 15. Refusing to store a partial/empty result.'
    );
  }

  // → { raw: string, parsed: object }
  async getConfig() {
    const results = await this._run(['show running-config']);
    const rawOutput = results[0] ? results[0].output : '';

    // Guard BEFORE storing: in user EXEC mode the ASA rejects this command, and
    // storing the rejection text as a config snapshot would silently overwrite
    // real config history with an empty parse (and trigger a bogus config-change
    // diff + backup). Fail with an actionable error instead.
    if (parser.looksLikeCliError(rawOutput) || !parser.looksLikeRunningConfig(rawOutput)) {
      throw new Error(this._privilegeErrorMessage('show running-config'));
    }

    // SECURITY: a running-config contains password hashes, VPN pre-shared keys,
    // SNMP communities and AAA secrets. `raw` is persisted verbatim into
    // device_configs.config_raw, copied into config_backups, served by the
    // backup download route, and readable by the claude_readonly /
    // nocvault_readonly roles — so redact here, before it leaves the adapter.
    // Nothing downstream redacts. Parse the redacted text too (defence in
    // depth: a future parsed field can then never capture a live secret).
    const raw = parser.redactConfig(rawOutput);
    return {
      raw,
      parsed: parser.parseRunningConfig(raw),
    };
  }

  // → { addresses, addressGroups, services, serviceGroups } — OPTIONAL, see
  // lib/adapters/interface.js's getObjects() contract comment. Unlike
  // getRules()/getConfig(), this method must NEVER throw — a partial or empty
  // object catalog is acceptable data, not a "silently wrong" risk (there is
  // no destructive DELETE-then-nothing consequence downstream for this one).
  // Object/object-group definitions carry no secrets, so the UNREDACTED
  // `show running-config` output is parsed directly — same convention as
  // parseRunningConfig()'s other non-secret fields.
  async getObjects() {
    const empty = { addresses: [], addressGroups: [], services: [], serviceGroups: [] };
    try {
      const results = await this._run(['show running-config']);
      const rawOutput = results[0] ? results[0].output : '';

      if (parser.looksLikeCliError(rawOutput) || !parser.looksLikeRunningConfig(rawOutput)) {
        console.warn(
          `[CiscoASA] getObjects(): CLI did not return a usable running-config for device ${this.device.id} — returning empty object catalog`
        );
        return empty;
      }

      try {
        return parser.parseObjects(rawOutput);
      } catch (err) {
        console.warn(`[CiscoASA] getObjects(): parse failure for device ${this.device.id}: ${err.message}`);
        return empty;
      }
    } catch (err) {
      console.warn(`[CiscoASA] getObjects(): failed to collect for device ${this.device.id}: ${err.message}`);
      return empty;
    }
  }

  // → { cpuPercent, memoryPercent, sessionCount, uptimeSeconds, raw,
  //     lowConfidence, targetHost } — OPTIONAL, see lib/adapters/interface.js's
  // getSnmpMetrics() contract comment. Uses a SEPARATE credential
  // (credential_type='snmp') from this adapter's own SSH credential — never
  // gated on / mixed with testConnectivity()/getRules()'s auth. MAY throw
  // (missing credential, timeout, auth failure) — engine-worker's snmp-poll
  // job already treats that like any other per-device polling failure.
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
      const scalarResult = await getMetrics(session, SNMP_OID, undefined, targetHost);
      const cpuRows = await walkSubtree(session, SNMP_CPU_TABLE_BASE, undefined, targetHost);
      const memUsedRows = await walkSubtree(session, SNMP_MEM_USED_TABLE_BASE, undefined, targetHost);
      const memFreeRows = await walkSubtree(session, SNMP_MEM_FREE_TABLE_BASE, undefined, targetHost);

      if (!snmpDebugLogged) {
        snmpDebugLogged = true;
        console.log(
          '[CiscoASA SNMP Debug] raw responses:',
          JSON.stringify({ scalarResult, cpuRows, memUsedRows, memFreeRows })
        );
      }

      const uptimeTicks = scalarResult.sysUpTime;
      const uptimeSeconds =
        uptimeTicks !== null && uptimeTicks !== undefined && !Number.isNaN(Number(uptimeTicks))
          ? Math.round(Number(uptimeTicks) / 100)
          : null;

      const sessionRaw = scalarResult.cfwConnectionCurrentInUse;
      const sessionCount =
        sessionRaw !== null && sessionRaw !== undefined && !Number.isNaN(Number(sessionRaw))
          ? Number(sessionRaw)
          : null;

      const cpuPercent =
        cpuRows.length > 0 && cpuRows[0].value !== null && cpuRows[0].value !== undefined && !Number.isNaN(Number(cpuRows[0].value))
          ? Number(cpuRows[0].value)
          : null;

      const memUsedBytes =
        memUsedRows.length > 0 && !Number.isNaN(Number(memUsedRows[0].value)) ? Number(memUsedRows[0].value) : null;
      const memFreeBytes =
        memFreeRows.length > 0 && !Number.isNaN(Number(memFreeRows[0].value)) ? Number(memFreeRows[0].value) : null;

      let memoryPercent = null;
      if (memUsedBytes !== null && memFreeBytes !== null && memUsedBytes + memFreeBytes > 0) {
        memoryPercent = Math.round((memUsedBytes / (memUsedBytes + memFreeBytes)) * 10000) / 100;
      }

      return {
        cpuPercent,
        memoryPercent,
        sessionCount,
        uptimeSeconds,
        raw: { scalarResult, cpuRows, memUsedRows, memFreeRows },
        lowConfidence: false,
        targetHost,
      };
    } finally {
      closeSession(session);
    }
  }
}

module.exports = { CiscoAsaAdapter };
