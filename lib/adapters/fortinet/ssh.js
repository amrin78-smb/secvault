// lib/adapters/fortinet/ssh.js
// Fortinet FortiGate adapter — SSH/CLI transport (the REST API transport lives in
// ./index.js as FortinetAdapter). CommonJS ONLY — required (indirectly) by
// services/engine-worker.js.
//
// Selected when devices.mgmt_method = 'ssh' (see ADAPTERS in lib/adapters/index.js
// and VENDOR_META.fortinet.accessMethods.ssh in components/devices/vendorMeta.js).
// Credential: credential_type 'ssh', plaintext JSON {"username","password"}.
// FortiOS has no enable/privileged mode — an admin's profile decides what it can
// read, so there is no enablePassword here (unlike the Cisco ASA adapter).
//
// See CLAUDE.md Pool Warning: testConnectivity() and every path that touches
// credStore MUST use this.pool. Never omit it — builds clean, breaks silently.
//
// ⚠️ No live FortiGate was available during this build. The CLI commands below are
// the documented/standard FortiOS forms; raw output is logged once per process under
// '[Fortinet Debug]' so the parsers in ./cliParser.js can be corrected against real
// hardware on first connect (CLAUDE.md: "Documentation lies").

'use strict';

const { FirewallAdapter } = require('../interface');
const credStore = require('../../credStore');
const { runCommands, parseJsonCredential } = require('../sshClient');
const parser = require('./parser');
const cliParser = require('./cliParser');
const { parseVersion } = require('../../engines/versionComparator');
const { createSession, getMetrics, closeSession } = require('../../snmpClient');
const { parseSnmpCredential } = require('../snmpCredential');

// FortiOS prompts are always '#': "FGT60F # ", "FGT60F (global) # ",
// "FGT60F (policy) # ". Narrower than sshClient's default /[>#$%]\s*$/ — FortiOS
// never presents '>', '$' or '%', so accepting them only widens the window for a
// config line to be mistaken for a prompt.
// NO `m` flag — see the DEFAULT_PROMPT_REGEX comment in ../sshClient.js.
const FORTIOS_PROMPT_REGEX = /#\s*$/;

// FortiOS pager off. Without it, long output paginates with '--More--' and the
// capture is truncated//polluted. (sshClient has a defensive --More-- handler as a
// backstop, which is what keeps this working if these commands are rejected — e.g.
// `config system console` is global-scope, so a VDOM-scoped admin cannot run it.)
const PAGER_OFF_COMMANDS = ['config system console', 'set output standard', 'end'];

// `show full-configuration` prints every field including defaults — tens of thousands
// of lines on a real box. The sshClient's default 20s per-command timeout is not
// enough for that on a slow link.
const CONFIG_COMMAND_TIMEOUT_MS = 120000;

let loggedFirstStatus = false;
let loggedFirstPolicyOutput = false;
let loggedFirstConfigPreview = false;
let loggedFirstVdomEditOutput = false;
let loggedFirstVpnMonitorOutput = false;
let loggedFirstVpnTunnelOutput = false;
let loggedFirstSnmpResponse = false;
let loggedFirstInterfaces = false;
let loggedFirstRoutingTable = false;
let loggedFirstNatOutput = false;
let loggedFirstLicenses = false;
let loggedFirstHaStatus = false;
let loggedFirstPerformance = false;
// One-shot debug log per object-catalog block name (firewall address / addrgrp /
// service custom / service group) — see getObjects() below.
const loggedFirstObjectOutput = new Set();
// One-shot debug log per DEVICE ID for an unrecognized `get vpn ssl monitor`
// output shape — see _getVpnSessionSummarySingleVdom() below for why this can't
// share loggedFirstVpnMonitorOutput's single process-wide flag.
const loggedVpnMonitorParseFailureFor = new Set();

// SNMP OIDs for getSnmpMetrics() — doc-derived from the FORTINET-FORTIGATE-MIB
// (fgSystemInfo subtree), NOT yet confirmed against a real SecVault-connected
// FortiGate (see CLAUDE.md's Live Validation Status discipline — log-and-confirm
// on first live poll, via '[Fortinet SNMP Debug]' below). Verified against
// oidref.com / mibs.observium.org during this feature's build (not assumed from
// memory) — all four resolved exactly as documented, with no surprises. Identical
// to the OID map in ./index.js's REST-transport FortinetAdapter — SNMP is a
// completely separate UDP protocol/connection from both the REST and SSH
// management transports, so this logic is duplicated verbatim rather than shared
// (this codebase's established "duplicate small per-adapter logic rather than
// share a module" convention — see CLAUDE.md).
//
// - sysUpTime.0 (MIB-II, RFC 1213) — universal, no vendor-specific doc needed.
// - fgSysCpuUsage.0 (FORTINET-FORTIGATE-MIB, fgSystemInfo) — Gauge32 0..100,
//   already a percentage, no derivation needed.
// - fgSysMemUsage.0 (FORTINET-FORTIGATE-MIB, fgSystemInfo) — Gauge32 0..100,
//   already a percentage, no derivation needed.
// - fgSysSesCount.0 (FORTINET-FORTIGATE-MIB, fgSystemInfo) — Gauge32, raw
//   active-session count, no derivation needed.
//
// All four are true scalars, so a single getMetrics() GET is enough — no
// walkSubtree() required. lowConfidence stays false: FortiGate ships a
// well-documented, stable vendor MIB, same confidence tier as Cisco ASA's
// getSnmpMetrics().
const SNMP_OID = {
  sysUpTime: '1.3.6.1.2.1.1.3.0',
  fgSysCpuUsage: '1.3.6.1.4.1.12356.101.4.1.3.0',
  fgSysMemUsage: '1.3.6.1.4.1.12356.101.4.1.4.0',
  fgSysSesCount: '1.3.6.1.4.1.12356.101.4.1.8.0',
};

class FortinetSshAdapter extends FirewallAdapter {
  constructor({ device, pool }) {
    super({ device, pool });
    // Per-instance cache so getRules() and getConfig() in one collect cycle don't
    // dump the configuration over SSH twice. Holds UNREDACTED text on purpose —
    // redaction is keyword-based and would mangle real object names needed for
    // parsing. Redaction is applied at every EGRESS point instead (the debug log
    // below, and getConfig()'s `raw`), exactly as the Sangfor adapter does.
    this._configText = null;
  }

  // Builds the SSH connection descriptor + shell options, decrypting the stored SSH
  // credential via credStore. ALWAYS uses this.pool (CLAUDE.md Pool Warning).
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
        promptRegex: FORTIOS_PROMPT_REGEX,
        initCommands: PAGER_OFF_COMMANDS,
      },
    };
  }

  // Runs commands in ONE SSH shell session against this device.
  async _run(commands, extraOptions = {}) {
    const { conn, options } = await this._getSession();
    return runCommands(conn, commands, { ...options, ...extraOptions });
  }

  static _outputAt(results, index) {
    const entry = Array.isArray(results) ? results[index] : null;
    return entry && typeof entry.output === 'string' ? entry.output : '';
  }

  // → { ok, latency_ms, message } — must NEVER throw.
  async testConnectivity() {
    const startedAt = Date.now();
    try {
      const results = await this._run(['get system status']);
      const output = FortinetSshAdapter._outputAt(results, 0);

      if (cliParser.looksLikeCliError(output) || !/version/i.test(output)) {
        // SSH itself worked — surface that, but do not claim a healthy device.
        return {
          ok: false,
          latency_ms: null,
          message:
            'SSH connected but `get system status` was rejected or returned no version line — ' +
            "check the admin account's access profile permissions.",
        };
      }

      return { ok: true, latency_ms: Date.now() - startedAt, message: 'Connected' };
    } catch (err) {
      return { ok: false, latency_ms: null, message: err.message };
    }
  }

  // Runs `get system status` and parses it. Used by getVersion() and by getRules()
  // to decide whether this box is multi-VDOM.
  async _getSystemStatus() {
    const results = await this._run(['get system status']);
    const raw = FortinetSshAdapter._outputAt(results, 0);

    if (!loggedFirstStatus) {
      // CLAUDE.md live-verification rule: log the raw output once so the first real
      // connection can be used to correct cliParser.parseSystemStatus().
      // `get system status` carries no secrets (version/serial/licence state only).
      console.log('[Fortinet Debug] SSH `get system status` raw output:\n' + raw);
      loggedFirstStatus = true;
    }

    if (cliParser.looksLikeCliError(raw)) {
      throw new Error(
        `FortiGate rejected \`get system status\` on device ${this.device.id} — ` +
          "the SSH admin account's access profile likely lacks read permission. " +
          'Refusing to continue with an unusable result.'
      );
    }

    return cliParser.parseSystemStatus(raw);
  }

  // → { version_string, version_tuple, build, model, serial }
  async getVersion() {
    const info = await this._getSystemStatus();

    if (!info.version_string) {
      throw new Error(
        'FortiGate version detection failed: `get system status` produced output but no ' +
          '"Version:" line was found. Check the [Fortinet Debug] raw output in the logs and ' +
          'update lib/adapters/fortinet/cliParser.js parseSystemStatus() for this firmware.'
      );
    }

    return {
      version_string: info.version_string,
      version_tuple: parseVersion('fortinet', info.version_string),
      build: info.build,
      model: info.model || 'unknown',
      // ⛔ Bug fixed 2026-07-19: parseSystemStatus() already parses `serial`
      // (the `Serial-Number:` line) — it was simply never included in this
      // return object, so a real, already-collected value was thrown away
      // before it ever reached collectAndStore()'s INSERT.
      serial: info.serial || null,
      // Same class of gap, fixed 2026-07-23: parseSystemStatus() already
      // parses `hostname` (the `Hostname:` line) — it was likewise never
      // included here.
      hostname: info.hostname || null,
      // Content/signature versions (added 2026-08-04). Unlike PAN-OS — where
      // these ride along on the `show system info` getVersion() already
      // fetches — FortiOS reports them from a DIFFERENT command, so this costs
      // one extra round trip. Wrapped so a failure degrades to no signature
      // data rather than failing version detection, which collectAndStore
      // treats as fatal for the whole device_versions row.
      contentVersions: await this._getContentVersionsSafe(),
    };
  }

  // Best-effort: `diagnose autoupdate versions` carries signature versions and
  // their last-update timestamps. getLicenses() runs the same command for the
  // contract dates; they are deliberately NOT shared because the optional
  // adapter methods are independently callable per interface.js's contract,
  // and assuming call order is exactly the kind of coupling that breaks later.
  async _getContentVersionsSafe() {
    try {
      const results = await this._run(['diagnose autoupdate versions']);
      const out = FortinetSshAdapter._outputAt(results, 0);
      return cliParser.parseFortinetContentVersions(out);
    } catch (err) {
      console.warn(
        `[Fortinet SSH] content versions unavailable for device ${this.device.id}: ${err.message}`
      );
      // ⛔ null, NOT []. This runs its OWN command (diagnose autoupdate
      // versions), so it has an independent failure mode — and [] passes
      // collectAndStore's Array.isArray gate, which then DELETEs every
      // device_content_versions row and reinserts nothing. Same class as
      // the getLicenses/getDiskUsage fix; missed because contentVersions
      // rides inside getVersion()'s return object rather than being its
      // own optional method.
      return null;
    }
  }

  // → { active_session_count, raw } — an OPTIONAL adapter capability, not
  // part of the FirewallAdapter base interface (testConnectivity/getVersion/
  // getRules/getConfig). Checked via `typeof adapter.getVpnSessionSummary ===
  // 'function'` by the poller (services/engine-worker.js's
  // runVpnSessionPoll()) before use, since most adapters/vendors don't
  // implement it. THROWS rather than guessing a count on unrecognized
  // output — see cliParser.countActiveVpnSessions()'s own comment for why a
  // wrong "0 active sessions" would look like a confirmed empty state to a
  // downstream trend chart, not a parse failure.
  //
  // Public entry point — dispatches to the single-VDOM or multi-VDOM path
  // based on the device's actual VDOM mode (mirrors getRules()'s own
  // isMultiVdom() dispatch immediately below in this file).
  async getVpnSessionSummary() {
    const status = await this._getSystemStatus();
    if (!cliParser.isMultiVdom(status)) {
      return this._getVpnSessionSummarySingleVdom();
    }
    return this.getVpnSessionSummaryMultiVdom(status);
  }

  async _getVpnSessionSummarySingleVdom() {
    const results = await this._run(['get vpn ssl monitor']);
    const output = FortinetSshAdapter._outputAt(results, 0);

    if (cliParser.looksLikeCliError(output)) {
      throw new Error(
        `FortiGate \`get vpn ssl monitor\` on device ${this.device.id} was rejected — check ` +
          "the SSH admin account's access profile permissions."
      );
    }

    if (!loggedFirstVpnMonitorOutput) {
      console.log(`[Fortinet Debug] SSH \`get vpn ssl monitor\` raw output:\n${output.slice(0, 4000)}`);
      loggedFirstVpnMonitorOutput = true;
    }

    const count = cliParser.countActiveVpnSessions(output);
    if (count === null) {
      // ⛔ Found live (2026-07-31): loggedFirstVpnMonitorOutput above is a single
      // PROCESS-WIDE flag, not per-device — on a fleet where most devices' output
      // matches but one or two don't (confirmed: TSR_EKC/Vietnam-YCC fail this
      // parse while TSR-TL/TSR_EKM/TUS succeed), whichever device happens to be
      // polled first trips the flag and every subsequent device's raw output —
      // including the ones that actually need debugging — is never logged at all.
      // The device(s) that actually need [Fortinet Debug] output to fix this
      // parser are exactly the ones this flag was silencing. Log unconditionally
      // (per-device, once per process) specifically on this failure path so a
      // format mismatch is always diagnosable, regardless of poll order.
      if (!loggedVpnMonitorParseFailureFor.has(this.device.id)) {
        loggedVpnMonitorParseFailureFor.add(this.device.id);
        console.log(
          `[Fortinet Debug] SSH \`get vpn ssl monitor\` UNRECOGNIZED output for device ` +
            `${this.device.id} (${this.device.name || 'unnamed'}):\n${output.slice(0, 4000)}`
        );
      }
      throw new Error(
        `FortiGate \`get vpn ssl monitor\` on device ${this.device.id} returned output that did ` +
          'not match the expected "SSL-VPN Login Users:" format — see the [Fortinet Debug] log. ' +
          'Refusing to guess a session count.'
      );
    }

    // Per-user detail is ADDITIVE and best-effort — a parse failure here must NEVER
    // disturb the authoritative count above (see cliParser.parseVpnSslMonitorSessions()'s
    // header comment). parseVpnSslMonitorSessions() already returns [] on any doubt;
    // the try/catch is belt-and-suspenders.
    let sessions = [];
    try {
      sessions = cliParser.parseVpnSslMonitorSessions(output);
    } catch (_err) {
      sessions = [];
    }

    return { active_session_count: count, sessions, raw: { source_command: 'get vpn ssl monitor' } };
  }

  // ⛔ Bug fixed 2026-07-19, found in the same bug sweep that shipped
  // getVpnSessionSummary() originally: the version above only ever ran `get
  // vpn ssl monitor` in the admin session's own default VDOM context —
  // identical "silent under-count on a multi-VDOM box" bug CLAUDE.md's VDOM
  // rule already documents for getRules(), reintroduced here. Renamed the
  // original single-shot implementation to _getVpnSessionSummarySingleVdom()
  // (used for non-VDOM boxes) and added a multi-VDOM path mirroring
  // getRules()'s _getRulesMultiVdom() command-batching pattern (config vdom
  // / edit <vdom> / <command> / end, one SSH round-trip for every VDOM).
  //
  // Unlike getRules() (which has NO try/catch per-VDOM — a single VDOM's
  // failure must fail the whole ruleset collection), this degrades
  // gracefully per VDOM: a partial session count is still a meaningful
  // coarse trend signal, whereas getRules() populates the authoritative
  // firewall_rules table where a silent partial result would be far worse
  // than an error. Only throws overall if EVERY VDOM failed (nothing usable
  // at all).
  async getVpnSessionSummaryMultiVdom(status) {
    const vdoms = await this._discoverVdomsForVpnPoll(status);

    // `vdoms === null` means enumeration itself failed (VDOM-scoped admin
    // token, transient rejection) — NOT "no VDOMs". We already KNOW
    // multi-VDOM is enabled (status.vdom_mode said so), so silently falling
    // back to a single implicit-VDOM count here would under-count and look
    // like a real, complete total — the exact bug this whole fix exists to
    // close, just reintroduced via the enumeration-failure path instead of
    // the no-vdom-param path. Throw instead, same as _getRulesMultiVdom()'s
    // identical reasoning for the ruleset case.
    if (vdoms === null) {
      throw new Error(
        `FortiGate device ${this.device.id} reports multi-VDOM mode ("${status.vdom_mode}") but ` +
          'the VDOM list could not be read for the VPN session poll — the SSH admin account ' +
          'probably lacks global/super_admin scope. Refusing to report only the default VDOM\'s ' +
          'session count, which would silently look like the complete total.'
      );
    }
    if (vdoms.length <= 1) {
      return this._getVpnSessionSummarySingleVdom();
    }

    const unsafe = vdoms.filter((name) => !cliParser.isSafeVdomName(name));
    if (unsafe.length > 0) {
      throw new Error(
        `FortiGate device ${this.device.id}: VDOM list contained ${unsafe.length} name(s) with ` +
          'unexpected characters for the VPN session poll — refusing to send them to the CLI.'
      );
    }

    const commands = [];
    const editIndexByVdom = new Map();
    const outputIndexByVdom = new Map();
    for (const vdom of vdoms) {
      commands.push('config vdom');
      commands.push(`edit ${vdom}`);
      editIndexByVdom.set(vdom, commands.length - 1);
      outputIndexByVdom.set(vdom, commands.length);
      commands.push('get vpn ssl monitor');
      commands.push('end');
    }

    const results = await this._run(commands);

    let total = 0;
    let anySucceeded = false;
    const perVdom = {};
    // ADDITIVE per-user detail, aggregated across VDOMs — see the sessions block
    // below. Kept in its own accumulator so it can never interfere with the count.
    const allSessions = [];
    for (const vdom of vdoms) {
      try {
        this._assertVdomEditSucceeded(vdom, FortinetSshAdapter._outputAt(results, editIndexByVdom.get(vdom)));
        const output = FortinetSshAdapter._outputAt(results, outputIndexByVdom.get(vdom));
        if (cliParser.looksLikeCliError(output)) {
          throw new Error(`\`get vpn ssl monitor\` rejected for VDOM "${vdom}"`);
        }
        const count = cliParser.countActiveVpnSessions(output);
        if (count === null) {
          throw new Error(`unrecognized output format for VDOM "${vdom}"`);
        }
        total += count;
        perVdom[vdom] = count;
        anySucceeded = true;

        // Best-effort, and deliberately AFTER the count is already recorded above:
        // a session-detail parse failure must never undo this VDOM's counted total,
        // so it gets its own try/catch. Tag each row's gateway with the VDOM name
        // (the SSH output carries no portal/realm field of its own).
        try {
          const vdomSessions = cliParser.parseVpnSslMonitorSessions(output);
          for (const s of vdomSessions) {
            allSessions.push({ ...s, gateway: s.gateway || vdom });
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
        `FortiGate \`get vpn ssl monitor\` failed for every VDOM on device ${this.device.id} — ` +
          'refusing to guess a session count.'
      );
    }

    return {
      active_session_count: total,
      sessions: allSessions,
      raw: { source_command: 'get vpn ssl monitor', per_vdom: perVdom, partial: Object.values(perVdom).some((v) => v === null) },
    };
  }

  // Mirrors _getRulesMultiVdom()'s own VDOM-listing call exactly — `show
  // system vdom` is global-scope, so it needs the same `config global`
  // wrapper (a VDOM-scoped admin token cannot enter global context; without
  // this wrapper the command can silently return an incomplete or empty
  // list instead of failing loudly). Reuses the `status` the public
  // getVpnSessionSummary() entry point already fetched, avoiding a second
  // `get system status` round-trip.
  async _discoverVdomsForVpnPoll(status) {
    if (!cliParser.isMultiVdom(status)) return null;
    const results = await this._run(['config global', 'show system vdom', 'end']);
    return cliParser.vdomNamesFromConfigText(FortinetSshAdapter._outputAt(results, 1));
  }

  // → NormalizedIpsecTunnel[] — an OPTIONAL adapter capability, NOT part of the
  // FirewallAdapter base interface (testConnectivity/getVersion/getRules/getConfig),
  // and SEPARATE from getVpnSessionSummary() above (that counts SSL-VPN user
  // sessions; this reports IPSec SITE-TO-SITE tunnel state). Checked via `typeof
  // adapter.getVpnTunnels === 'function'` by the poller before use, since most
  // adapters don't implement it. Each element is
  //   { name, peer, status, ike_version, bytes_in, bytes_out, raw }
  // (any field may be null). Returns [] when the device has no IPSec tunnels — a
  // legitimate empty state, NOT an error. MAY throw when the CLI command itself is
  // rejected (the engine-worker catches and logs per-device); a parse that simply
  // finds nothing returns [], and any internal parse error degrades to [] rather
  // than throwing (cliParser.parseIpsecTunnelList() is itself non-throwing, the
  // try/catch here is belt-and-suspenders).
  //
  // Public entry point — dispatches single- vs multi-VDOM exactly like
  // getVpnSessionSummary()/getRules() do above.
  async getVpnTunnels() {
    const status = await this._getSystemStatus();
    if (!cliParser.isMultiVdom(status)) {
      return this._getVpnTunnelsSingleVdom();
    }
    return this._getVpnTunnelsMultiVdom(status);
  }

  async _getVpnTunnelsSingleVdom() {
    const results = await this._run(['diagnose vpn tunnel list']);
    const output = FortinetSshAdapter._outputAt(results, 0);

    if (cliParser.looksLikeCliError(output)) {
      throw new Error(
        `FortiGate \`diagnose vpn tunnel list\` on device ${this.device.id} was rejected — check ` +
          "the SSH admin account's access profile permissions."
      );
    }

    if (!loggedFirstVpnTunnelOutput) {
      // CLAUDE.md live-verification rule: log the raw output once so the first real
      // connection can be used to correct cliParser.parseIpsecTunnelList(). The
      // `diagnose vpn tunnel list` output carries no secrets (tunnel/SA state, IPs,
      // SPIs and byte counters — no key material), same as the SSL-VPN monitor log.
      console.log(`[Fortinet Debug] SSH \`diagnose vpn tunnel list\` raw output:\n${output.slice(0, 4000)}`);
      loggedFirstVpnTunnelOutput = true;
    }

    try {
      return cliParser.parseIpsecTunnelList(output);
    } catch (_err) {
      return [];
    }
  }

  // Multi-VDOM box: enumerate the VDOMs and pull each one's IPSec tunnel list,
  // aggregating into one array. Mirrors getVpnSessionSummaryMultiVdom()'s exact
  // `config vdom` / `edit <vdom>` / `<command>` / `end` batching and its
  // graceful-per-VDOM degradation (a single VDOM's failure is logged and skipped;
  // only a total failure of every VDOM throws). Each aggregated tunnel is tagged
  // with its source VDOM under `raw.vdom` so the normalized top-level shape stays
  // exactly the 7 contract fields.
  async _getVpnTunnelsMultiVdom(status) {
    const vdoms = await this._discoverVdomsForVpnPoll(status);

    // Same reasoning as getVpnSessionSummaryMultiVdom(): we KNOW multi-VDOM is on,
    // so an enumeration failure must not silently fall back to only the default
    // VDOM's tunnels and look like the complete set. Throw instead.
    if (vdoms === null) {
      throw new Error(
        `FortiGate device ${this.device.id} reports multi-VDOM mode ("${status.vdom_mode}") but ` +
          'the VDOM list could not be read for the IPSec tunnel poll — the SSH admin account ' +
          'probably lacks global/super_admin scope. Refusing to report only the default VDOM\'s ' +
          'tunnels, which would silently look like the complete set.'
      );
    }
    if (vdoms.length <= 1) {
      return this._getVpnTunnelsSingleVdom();
    }

    const unsafe = vdoms.filter((name) => !cliParser.isSafeVdomName(name));
    if (unsafe.length > 0) {
      throw new Error(
        `FortiGate device ${this.device.id}: VDOM list contained ${unsafe.length} name(s) with ` +
          'unexpected characters for the IPSec tunnel poll — refusing to send them to the CLI.'
      );
    }

    const commands = [];
    const editIndexByVdom = new Map();
    const outputIndexByVdom = new Map();
    for (const vdom of vdoms) {
      commands.push('config vdom');
      commands.push(`edit ${vdom}`);
      editIndexByVdom.set(vdom, commands.length - 1);
      outputIndexByVdom.set(vdom, commands.length);
      commands.push('diagnose vpn tunnel list');
      commands.push('end');
    }

    const results = await this._run(commands);

    const allTunnels = [];
    let anySucceeded = false;
    for (const vdom of vdoms) {
      try {
        this._assertVdomEditSucceeded(vdom, FortinetSshAdapter._outputAt(results, editIndexByVdom.get(vdom)));
        const output = FortinetSshAdapter._outputAt(results, outputIndexByVdom.get(vdom));
        if (cliParser.looksLikeCliError(output)) {
          throw new Error(`\`diagnose vpn tunnel list\` rejected for VDOM "${vdom}"`);
        }

        if (!loggedFirstVpnTunnelOutput) {
          console.log(
            `[Fortinet Debug] SSH \`diagnose vpn tunnel list\` (VDOM "${vdom}") raw output:\n${output.slice(0, 4000)}`
          );
          loggedFirstVpnTunnelOutput = true;
        }

        let tunnels = [];
        try {
          tunnels = cliParser.parseIpsecTunnelList(output);
        } catch (_err) {
          tunnels = [];
        }
        for (const t of tunnels) {
          const rawWithVdom = { ...(t.raw && typeof t.raw === 'object' ? t.raw : {}), vdom };
          allTunnels.push({ ...t, raw: rawWithVdom });
        }
        anySucceeded = true;
      } catch (err) {
        console.warn(
          `[Fortinet] IPSec tunnel list failed for VDOM "${vdom}" on device ${this.device.id}: ${err.message}`
        );
      }
    }

    if (!anySucceeded) {
      throw new Error(
        `FortiGate \`diagnose vpn tunnel list\` failed for every VDOM on device ${this.device.id} — ` +
          'refusing to report an IPSec tunnel list.'
      );
    }

    return allTunnels;
  }

  // OPTIONAL — FirewallAdapter's getInterfaces() (see interface.js for the
  // exact contract). Phase 1 (2026-08-02): single/root-vdom pull only, no
  // per-VDOM switching (unlike getRules()/getVpnTunnels() above) — see
  // cliParser.js's "Topology parsers" section header comment. Never throws
  // — same "degrade to empty, don't fail the whole collectAndStore pull"
  // treatment every other optional method here uses.
  async getInterfaces() {
    let output;
    try {
      const results = await this._run(['get system interface physical']);
      output = results[0] ? results[0].output : '';
    } catch (err) {
      console.warn(`[Fortinet SSH] getInterfaces() failed for device ${this.device.id}: ${err.message}`);
      // ⛔ RETHROW, never an empty set. Returning [] here made
      // collectAndStore's per-method try/catch unreachable: it would have
      // left this device's rows untouched on a failure, but the adapter
      // reported success, so storeDevice*() ran its DELETE and reinserted
      // nothing. One SSH/API timeout silently wiped the device's
      // interfaces — and topology.js then renders the device as having no
      // links at all, a confident wrong answer rather than a gap.
      throw err instanceof Error ? err : new Error(String(err));
    }

    if (!loggedFirstInterfaces) {
      console.log(`[Fortinet Debug] SSH \`get system interface physical\` raw output:\n${output.slice(0, 4000)}`);
      loggedFirstInterfaces = true;
    }

    try {
      return { interfaces: cliParser.parseFortinetInterfacesOutput(output) };
    } catch (_err) {
      // ⛔ RETHROW, never an empty set. Returning [] here made
      // collectAndStore's per-method try/catch unreachable: it would have
      // left this device's rows untouched on a failure, but the adapter
      // reported success, so storeDevice*() ran its DELETE and reinserted
      // nothing. One SSH/API timeout silently wiped the device's
      // interfaces — and topology.js then renders the device as having no
      // links at all, a confident wrong answer rather than a gap.
      throw err instanceof Error ? err : new Error(String(err));
    }
  }

  // OPTIONAL — FirewallAdapter's getRoutingTable(). Same Phase 1 scope note
  // as getInterfaces() above.
  async getRoutingTable() {
    let output;
    try {
      const results = await this._run(['get router info routing-table all']);
      output = results[0] ? results[0].output : '';
    } catch (err) {
      console.warn(`[Fortinet SSH] getRoutingTable() failed for device ${this.device.id}: ${err.message}`);
      // ⛔ RETHROW, never an empty set. Returning [] here made
      // collectAndStore's per-method try/catch unreachable: it would have
      // left this device's rows untouched on a failure, but the adapter
      // reported success, so storeDevice*() ran its DELETE and reinserted
      // nothing. One SSH/API timeout silently wiped the device's
      // routes — and topology.js then renders the device as having no
      // links at all, a confident wrong answer rather than a gap.
      throw err instanceof Error ? err : new Error(String(err));
    }

    if (!loggedFirstRoutingTable) {
      console.log(`[Fortinet Debug] SSH \`get router info routing-table all\` raw output:\n${output.slice(0, 4000)}`);
      loggedFirstRoutingTable = true;
    }

    try {
      return { routes: cliParser.parseFortinetRoutingTableOutput(output) };
    } catch (_err) {
      // ⛔ RETHROW, never an empty set. Returning [] here made
      // collectAndStore's per-method try/catch unreachable: it would have
      // left this device's rows untouched on a failure, but the adapter
      // reported success, so storeDevice*() ran its DELETE and reinserted
      // nothing. One SSH/API timeout silently wiped the device's
      // routes — and topology.js then renders the device as having no
      // links at all, a confident wrong answer rather than a gap.
      throw err instanceof Error ? err : new Error(String(err));
    }
  }

  // OPTIONAL — FirewallAdapter's getNatRules() (added 2026-08-02, live-verified
  // against TSR-TL). Same Phase 1 scope note as getInterfaces() above
  // (single/root-vdom pull only). Re-fetches interfaces internally (a second
  // small SSH round trip) rather than sharing state with getInterfaces() —
  // the three optional methods are independently callable/failable per
  // interface.js's contract, so this keeps that guarantee real rather than
  // assuming call order. See cliParser.js's parseFortinetNatRulesOutput()
  // header comment for exactly what resolves vs. degrades to unresolved
  // (SD-WAN virtual-interface dstintf, unresolvable ippool reference).
  async getNatRules() {
    let policyOutput;
    let vipOutput;
    let ippoolOutput;
    let interfaceOutput;
    try {
      const results = await this._run([
        'show firewall policy',
        'show firewall vip',
        'show firewall ippool',
        'get system interface physical',
      ]);
      [policyOutput, vipOutput, ippoolOutput, interfaceOutput] = results.map((r) => (r ? r.output : ''));
    } catch (err) {
      console.warn(`[Fortinet SSH] getNatRules() failed for device ${this.device.id}: ${err.message}`);
      // ⛔ RETHROW, never an empty set. Returning [] here made
      // collectAndStore's per-method try/catch unreachable: it would have
      // left this device's rows untouched on a failure, but the adapter
      // reported success, so storeDevice*() ran its DELETE and reinserted
      // nothing. One SSH/API timeout silently wiped the device's
      // rules — and topology.js then renders the device as having no
      // links at all, a confident wrong answer rather than a gap.
      throw err instanceof Error ? err : new Error(String(err));
    }

    if (!loggedFirstNatOutput) {
      console.log(
        `[Fortinet Debug] SSH \`show firewall vip\` raw output:\n${vipOutput.slice(0, 4000)}\n` +
          `[Fortinet Debug] SSH \`show firewall ippool\` raw output:\n${ippoolOutput.slice(0, 2000)}`
      );
      loggedFirstNatOutput = true;
    }

    try {
      const interfaces = cliParser.parseFortinetInterfacesOutput(interfaceOutput);
      const interfaceIpByName = new Map(
        interfaces.map((iface) => [iface.name, iface.ipAddress.split('/')[0]])
      );
      return {
        rules: cliParser.parseFortinetNatRulesOutput(policyOutput, vipOutput, ippoolOutput, interfaceIpByName),
      };
    } catch (_err) {
      // ⛔ RETHROW, never an empty set. Returning [] here made
      // collectAndStore's per-method try/catch unreachable: it would have
      // left this device's rows untouched on a failure, but the adapter
      // reported success, so storeDevice*() ran its DELETE and reinserted
      // nothing. One SSH/API timeout silently wiped the device's
      // rules — and topology.js then renders the device as having no
      // links at all, a confident wrong answer rather than a gap.
      throw err instanceof Error ? err : new Error(String(err));
    }
  }

  // OPTIONAL — FirewallAdapter's getLicenses() (added 2026-08-04).
  // Three commands, each contributing something the others don't:
  //   - `diagnose autoupdate versions`  FortiGuard UPDATE contracts per
  //     component, plus signature versions/dates (Fortinet's own documented
  //     way to view licence info from the CLI).
  //   - `diagnose test update info`     the SUPPORT/HARDWARE contracts
  //     (SPRT/HDWR/ENHN/COMP) — the renewal-planning data, available nowhere
  //     else on the CLI.
  //   - `get system fortiguard`         query-based services (webfilter,
  //     antispam, outbreak prevention) that aren't downloaded databases and so
  //     never appear in autoupdate's list.
  // All live-verified against TSR-TL/TSR_EKC before this parser was written.
  // Never throws — same degrade-to-empty treatment as the topology methods.
  async getLicenses() {
    let autoupdate = '';
    let updateInfo = '';
    let fortiguard = '';
    try {
      const results = await this._run(
        ['diagnose autoupdate versions', 'diagnose test update info', 'get system fortiguard'],
        // `diagnose test update info` emits a large log dump before the
        // contracts block; the default per-command timeout is tight for it.
        { commandTimeoutMs: 60000 }
      );
      [autoupdate, updateInfo, fortiguard] = results.map((r) => (r ? r.output : ''));
    } catch (err) {
      console.warn(`[Fortinet SSH] getLicenses() failed for device ${this.device.id}: ${err.message}`);
      return null; // null = "could not determine", never an empty set — see collectAndStore
    }

    if (!loggedFirstLicenses) {
      // Contract codes and dates only — no key material. `diagnose test update
      // info` is truncated because most of it is an update-daemon log dump.
      console.log(
        `[Fortinet Debug] SSH \`diagnose autoupdate versions\`:\n${autoupdate.slice(0, 3000)}\n` +
          `[Fortinet Debug] SSH \`diagnose test update info\` (contracts region):\n${updateInfo.slice(
            Math.max(0, updateInfo.search(/System contracts:/i)),
            Math.max(0, updateInfo.search(/System contracts:/i)) + 1500
          )}`
      );
      loggedFirstLicenses = true;
    }

    try {
      return cliParser.parseFortinetLicenseOutput(autoupdate, fortiguard, updateInfo);
    } catch (_err) {
      return null; // null = "could not determine", never an empty set — see collectAndStore
    }
  }

  // OPTIONAL — FirewallAdapter's getHaStatus() (added 2026-08-04).
  // `get system ha status` is live-verified across all 5 FortiGates here, every
  // one reporting `Mode: Standalone`. Recording that positively is the point:
  // these devices previously rendered as "Not collected", which wrongly implied
  // SecVault had never asked rather than "this device is not in a pair".
  // Cluster shape is unverified — see parseFortinetHaStatus()'s header.
  async getHaStatus() {
    let output;
    try {
      const results = await this._run(['get system ha status']);
      output = FortinetSshAdapter._outputAt(results, 0);
    } catch (err) {
      console.warn(`[Fortinet SSH] getHaStatus() failed for device ${this.device.id}: ${err.message}`);
      return null;
    }

    if (!loggedFirstHaStatus) {
      console.log(`[Fortinet Debug] SSH \`get system ha status\` raw output:\n${output.slice(0, 3000)}`);
      loggedFirstHaStatus = true;
    }

    try {
      return cliParser.parseFortinetHaStatus(output);
    } catch (_err) {
      return null;
    }
  }

  // OPTIONAL — getPerformanceMetrics() (added 2026-08-04). Same return shape as
  // getSnmpMetrics() so services/engine-worker.js's poll job can use either,
  // but sourced from `get system performance status` over the management SSH
  // session this adapter ALREADY holds. Preferred over SNMP by that job because
  // it needs no separate credential, no snmp_enabled flag, and reports the
  // device's own stated percentages instead of doc-derived OIDs — hence
  // lowConfidence:false, unlike this vendor's SNMP path.
  async getPerformanceMetrics() {
    let output;
    try {
      const results = await this._run(['get system performance status']);
      output = FortinetSshAdapter._outputAt(results, 0);
    } catch (err) {
      throw new Error(`get system performance status failed: ${err.message}`);
    }

    if (!loggedFirstPerformance) {
      console.log(`[Fortinet Debug] SSH \`get system performance status\` raw output:\n${output.slice(0, 2500)}`);
      loggedFirstPerformance = true;
    }

    const m = cliParser.parseFortinetPerformanceStatus(output);
    // A rejected command or an unparsable dialect yields all-nulls. Storing that
    // as a successful poll fabricates a 'polled OK, no data' row every cycle
    // forever with nothing in the log — throw so the job records a real error,
    // matching this adapter's getRules()/countActiveVpnSessions() discipline.
    if (m.cpuPercent === null && m.memoryPercent === null && m.sessionCount === null && m.uptimeSeconds === null) {
      throw new Error(
        'get system performance status returned no parsable metrics (command rejected, or an ' +
          'unrecognized output dialect) — refusing to record an all-empty reading. See [Fortinet Debug].'
      );
    }
    return {
      cpuPercent: m.cpuPercent,
      memoryPercent: m.memoryPercent,
      sessionCount: m.sessionCount,
      uptimeSeconds: m.uptimeSeconds,
      raw: { source: 'get system performance status' },
      lowConfidence: false,
      targetHost: this.device.mgmt_ip,
    };
  }

  // Converts one `show firewall policy` capture into NormalizedRule[].
  // THROWS rather than returning [] whenever the output is not a policy dump — see
  // the getRules() comment for why a false "zero rules" is destructive.
  _rulesFromPolicyOutput(output, { vdom, prefixRuleName, sequenceStart }) {
    const where = vdom ? ` for VDOM "${vdom}"` : '';

    if (!loggedFirstPolicyOutput) {
      // Bounded preview: a real policy dump is thousands of lines. 2000 chars
      // was too tight in practice -- a 31KB dump's first 2000 chars covered
      // only 4-5 policies out of dozens, which cost a full extra round of log
      // collection to diagnose an unrelated parsing question. 8000 chars is
      // still bounded but reaches meaningfully further into a real ruleset.
      console.log(
        `[Fortinet Debug] SSH \`show firewall policy\`${where} (${output.length} chars). First 8000 chars:\n` +
          output.slice(0, 8000)
      );
      loggedFirstPolicyOutput = true;
    }

    if (cliParser.looksLikeCliError(output)) {
      throw new Error(
        `FortiGate rejected \`show firewall policy\`${where} on device ${this.device.id}. ` +
          "Check the SSH admin account's access profile (it needs read access to firewall " +
          'policy in every VDOM). Refusing to store a partial/empty ruleset.'
      );
    }

    const policies = cliParser.policiesFromConfigText(output);
    if (policies === null) {
      throw new Error(
        `FortiGate \`show firewall policy\`${where} on device ${this.device.id} returned output ` +
          'with no `config firewall policy` block. This is NOT being treated as "zero rules" — ' +
          'the previously collected rules are left untouched. Check the [Fortinet Debug] output ' +
          'in the logs and adjust lib/adapters/fortinet/cliParser.js if this firmware differs.'
      );
    }

    // Hit counts are NOT collected over SSH: FortiOS exposes real per-policy counters
    // via the REST monitor API (see the api transport), but the CLI equivalent
    // (`diagnose firewall iprope show ...`) is an undocumented, firmware-specific
    // debug format. Rules therefore carry hit_count 0 — which the Phase 5 engine will
    // read as "unused". Documented limitation of the SSH transport; use the REST API
    // transport if unused-rule findings matter for this device.
    return parser.parsePolicies(policies, [], { vdom, prefixRuleName, sequenceStart });
  }

  // → NormalizedRule[]
  //
  // ⛔ Never return [] on a connection/credential/permission failure — THROW.
  // collectAndStore() (lib/adapters/index.js) awaits getRules() and only THEN opens a
  // transaction that DELETEs every firewall_rules row for this device before
  // reinserting. A throw happens before the DELETE, so the previous ruleset survives
  // and the error is surfaced; a false [] silently wipes the real rules, wipes the
  // Phase 5 findings that cascade from them, and reports rulesCount: 0 as success.
  // (Same bug that was fixed in lib/adapters/sangfor/index.js.)
  //
  // VDOM completeness: on a multi-VDOM box, rules are collected from EVERY VDOM. If
  // any single VDOM's rules cannot be collected, the WHOLE call throws — see
  // _getRulesMultiVdom().
  async getRules() {
    const status = await this._getSystemStatus();

    if (!cliParser.isMultiVdom(status)) {
      return this._getRulesSingleVdom();
    }
    return this._getRulesMultiVdom(status);
  }

  // Non-VDOM box (or firmware that does not report VDOM mode): one implicit VDOM.
  async _getRulesSingleVdom() {
    const results = await this._run(['show firewall policy']);
    return this._rulesFromPolicyOutput(FortinetSshAdapter._outputAt(results, 0), {
      vdom: null,
      // Nothing to disambiguate on a single-VDOM box — prefixing every rule_name
      // would be noise and would churn the names of every already-collected rule.
      prefixRuleName: false,
      sequenceStart: 0,
    });
  }

  // Confirms `edit <vdom>` (under `config vdom`) actually succeeded, using the edit
  // command's own captured output — see the call site comment in
  // _getRulesMultiVdom() for why this is the only signal available in this file. No
  // try/catch here on purpose, matching the rest of this file (e.g. the multi-VDOM
  // loop below): a failed/unconfirmed VDOM switch must fail getRules() entirely
  // rather than silently collect and store the wrong VDOM's policies under this
  // VDOM's label.
  _assertVdomEditSucceeded(vdom, editOutput) {
    if (!loggedFirstVdomEditOutput) {
      // Bounded/short on purpose: `edit <vdom>` carries no secrets and, on success,
      // FortiOS prints nothing at all — logged once so a real rejection string seen
      // on first live connect can be folded into cliParser.CLI_ERROR_REGEX.
      console.log(
        `[Fortinet Debug] SSH \`edit ${vdom}\` (under \`config vdom\`) output: ` +
          JSON.stringify(editOutput.slice(0, 500))
      );
      loggedFirstVdomEditOutput = true;
    }

    if (cliParser.looksLikeCliError(editOutput)) {
      throw new Error(
        `FortiGate device ${this.device.id}: \`edit ${vdom}\` under \`config vdom\` was rejected ` +
          `(output: ${JSON.stringify(editOutput.slice(0, 200))}). Refusing to run ` +
          '`show firewall policy` after an unconfirmed VDOM switch — the shell session may still ' +
          "be in the previous VDOM, which would silently store that VDOM's rules under this " +
          "VDOM's label. Check whether this VDOM still exists and the SSH admin account's VDOM " +
          'scope.'
      );
    }
  }

  // Multi-VDOM box: enumerate the VDOMs, then pull each one's policy table.
  async _getRulesMultiVdom(status) {
    // `show system vdom` is global-scope, hence the `config global` wrapper. A
    // VDOM-scoped admin cannot enter global context — that case is handled below.
    const listResults = await this._run(['config global', 'show system vdom', 'end']);
    const vdomOutput = FortinetSshAdapter._outputAt(listResults, 1);
    const vdoms = cliParser.vdomNamesFromConfigText(vdomOutput);

    if (vdoms === null) {
      // We KNOW multi-VDOM is enabled (get system status said so) but we cannot list
      // the VDOMs. Falling back to an implicit single-VDOM pull here would collect
      // only this admin's default VDOM and hand it to collectAndStore as the complete
      // ruleset — reintroducing the exact bug this code exists to fix, and deleting
      // the other VDOMs' stored rules in the process. Fail instead.
      throw new Error(
        `FortiGate device ${this.device.id} reports multi-VDOM mode ` +
          `("${status.vdom_mode}") but the VDOM list could not be read via ` +
          '`config global` + `show system vdom` — the SSH admin account probably lacks ' +
          'global/super_admin scope. Refusing to collect only the default VDOM, which would ' +
          'silently look like the complete ruleset. Fix: use a super_admin account, or switch ' +
          "this device's access method to the REST API. Check the [Fortinet Debug] logs."
      );
    }

    const unsafe = vdoms.filter((name) => !cliParser.isSafeVdomName(name));
    if (unsafe.length > 0) {
      // A name we will not interpolate into an `edit <name>` CLI command. Either the
      // parse is wrong or something is very odd — either way, do not guess, and do
      // not silently skip the VDOM (that would be a partial result).
      throw new Error(
        `FortiGate device ${this.device.id}: VDOM list contained ${unsafe.length} name(s) with ` +
          'unexpected characters, which will not be sent to the CLI. Refusing to collect a ' +
          'partial ruleset. Check the [Fortinet Debug] `show system vdom` output.'
      );
    }

    console.log(
      `[Fortinet] Device ${this.device.id} is multi-VDOM (${status.vdom_mode}); collecting rules from ` +
        `${vdoms.length} VDOM(s): ${vdoms.join(', ')}`
    );

    // One SSH session for every VDOM. runCommands throws if ANY command in the list
    // fails or times out, which is exactly the behaviour required here: a single
    // VDOM's failure must fail the whole collection, never yield a partial ruleset.
    const commands = [];
    const editIndexByVdom = new Map();
    const outputIndexByVdom = new Map();
    for (const vdom of vdoms) {
      commands.push('config vdom');
      commands.push(`edit ${vdom}`);
      editIndexByVdom.set(vdom, commands.length - 1); // index of `edit <vdom>` itself
      outputIndexByVdom.set(vdom, commands.length); // index of `show firewall policy`
      commands.push('show firewall policy');
      commands.push('end');
    }

    const results = await this._run(commands);

    const allRules = [];
    for (const vdom of vdoms) {
      // `edit <vdom>`'s own output was previously discarded entirely, so a silent
      // failure (VDOM renamed/deleted since the listing above, a VDOM-scoped admin
      // token, a transient CLI rejection) left the shell session in the PREVIOUS
      // VDOM's context — and the following `show firewall policy` would then return
      // THAT vdom's policies, stored under this (wrong) vdom's label with no error.
      // sshClient.js's cleanOutput() strips the resulting prompt line from every
      // captured command (a frozen-contract file, not touched here), so the prompt's
      // "(vdomname)" segment isn't available to check — the edit command's own body
      // text is the only usable signal here. A successful FortiOS `edit` under
      // `config vdom` prints nothing; a failure prints a known rejection string.
      this._assertVdomEditSucceeded(vdom, FortinetSshAdapter._outputAt(results, editIndexByVdom.get(vdom)));

      const output = FortinetSshAdapter._outputAt(results, outputIndexByVdom.get(vdom));
      // Throws on any problem — no try/catch here on purpose. Swallowing one VDOM's
      // error and returning the rest would be indistinguishable from success.
      const rules = this._rulesFromPolicyOutput(output, {
        vdom,
        // Multi-VDOM: the VDOM goes in firewall_rules.vdom (real column, added
        // 2026-07-30 — see ruleAnalysis.js's isStrictlyEarlier()), in raw_rule
        // (durable, machine-readable), AND as a "[vdom] " rule_name prefix
        // (human-facing, kept for UI tables that don't render a VDOM column yet).
        prefixRuleName: true,
        sequenceStart: allRules.length,
      });
      allRules.push(...rules);
    }

    return allRules;
  }

  // Fetches `show full-configuration`, cached per adapter instance.
  // Returns the UNREDACTED text — every caller must redact before letting it out.
  async _getConfigText() {
    if (this._configText !== null) return this._configText;

    const results = await this._run(['show full-configuration'], {
      commandTimeoutMs: CONFIG_COMMAND_TIMEOUT_MS,
    });
    const output = FortinetSshAdapter._outputAt(results, 0);

    if (cliParser.looksLikeCliError(output) || !cliParser.looksLikeConfig(output)) {
      // Storing a CLI rejection as a config snapshot would overwrite real config
      // history with an empty parse AND trigger a bogus config-change diff + backup.
      throw new Error(
        `FortiGate \`show full-configuration\` on device ${this.device.id} did not return a ` +
          "configuration. Check the SSH admin account's access profile permissions. " +
          'Refusing to store the result as a config snapshot.'
      );
    }

    this._configText = output;

    if (!loggedFirstConfigPreview) {
      // SECURITY: redact BEFORE logging. This preview lands in engine.log on disk and
      // a FortiOS config carries admin hashes, psksecrets, private keys and SNMP
      // communities. Bounded preview — a full config is tens of thousands of lines.
      // 8000 chars (was 2000): the smaller cap covered only `config system global`,
      // nowhere near `config firewall policy` on a real 1.7MB dump.
      const preview = cliParser.redactConfig(output).slice(0, 8000);
      console.log(
        `[Fortinet Debug] SSH \`show full-configuration\` (${output.length} chars, secrets redacted). ` +
          `First 8000 chars:\n${preview}`
      );
      loggedFirstConfigPreview = true;
    }

    return this._configText;
  }

  // → { raw: string, parsed: object }
  async getConfig() {
    const text = await this._getConfigText();

    // SECURITY — MANDATORY (CLAUDE.md: "Any NEW adapter that returns a raw text config
    // MUST redact before returning it from getConfig()"). `raw` is persisted verbatim
    // into device_configs.config_raw, copied into config_backups, served by the backup
    // download route, and both tables are readable by claude_readonly /
    // nocvault_readonly — the roles CLAUDE.md bars from device_credentials. Nothing
    // downstream redacts. Parse the REDACTED text too (defence in depth: no parsed
    // field can then ever capture a live secret).
    const raw = cliParser.redactConfig(text);

    // Best-effort system status, merged into the parsed config as system_info
    // (v2.59.0). `_getSystemStatus()` is cached per adapter instance, so on a
    // normal collect this reuses the response getVersion() already fetched and
    // costs no extra command.
    // ⛔ A failure passes undefined, and parseFullConfiguration then OMITS the
    // key rather than writing {} — an empty object is what produced the false
    // "12 removed / 12 added" change alerts on Palo Alto.
    let systemStatus;
    try {
      systemStatus = await this._getSystemStatus();
    } catch (err) {
      console.warn(
        `[Fortinet SSH] Failed to fetch system status for config snapshot on device ${this.device.id}: ${err.message}`
      );
    }

    return {
      raw,
      parsed: cliParser.parseFullConfiguration(raw, systemStatus),
    };
  }

  // → { addresses, addressGroups, services, serviceGroups } — an OPTIONAL adapter
  // capability, not part of the FirewallAdapter base interface (see
  // lib/adapters/interface.js's getObjects() contract comment). Collects the
  // device's named address/service OBJECT CATALOG (the objects/groups DEFINED on
  // the device) — distinct from getRules()'s already-collected RESOLVED rule field
  // values — for lib/engines/objectUsage.js's unused/duplicate-object detection.
  //
  // Commands use the same `show <block>` convention this file already relies on
  // for `show firewall policy` — a `show` at global/VDOM scope prints the
  // matching `config <block> ... end` text directly, with no lasting CLI-context
  // side effects — rather than sending `config firewall address` as a standalone
  // command (which enters config mode and produces no dump on its own). Grounded
  // in this file's existing `show firewall policy`/`show full-configuration`
  // usage, not newly invented.
  //
  // Unlike getRules()/getConfig(), this method must NEVER throw: each of the 4
  // sub-categories is independently try/caught here AND internally degrades a
  // single VDOM's failure to "skip that VDOM, keep the rest" (see
  // _collectObjectCategory()) — a partial object catalog is still useful data,
  // with none of getRules()'s destructive DELETE-then-nothing risk (CLAUDE.md).
  //
  // `network_objects` (the DB table this feeds) has no vdom column — an
  // identically-named object collected from two different VDOMs on the same
  // device silently collapses to whichever was inserted last. Accepted,
  // documented simplification, not something this method needs to solve.
  //
  // ⚠️ DOC-DERIVED, not yet live-verified against a real FortiGate — same standing
  // caveat as the rest of this file (CLAUDE.md Live Validation Status).
  async getObjects() {
    let status = null;
    try {
      status = await this._getSystemStatus();
    } catch (err) {
      console.warn(
        `[Fortinet] getObjects(): could not determine VDOM mode for device ${this.device.id} — ` +
          `assuming a single implicit VDOM: ${err.message}`
      );
    }

    const vdomList = await this._resolveVdomListForObjects(status);

    let addresses = [];
    try {
      addresses = await this._collectObjectCategory(
        vdomList,
        'show firewall address',
        'firewall address',
        'addresses',
        cliParser.addressEntryToNamedAddress
      );
    } catch (err) {
      console.warn(
        `[Fortinet] getObjects(): addresses collection failed entirely for device ${this.device.id}: ${err.message}`
      );
    }

    let addressGroups = [];
    try {
      addressGroups = await this._collectObjectCategory(
        vdomList,
        'show firewall addrgrp',
        'firewall addrgrp',
        'addressGroups',
        cliParser.groupEntryToNamedGroup
      );
    } catch (err) {
      console.warn(
        `[Fortinet] getObjects(): addressGroups collection failed entirely for device ${this.device.id}: ${err.message}`
      );
    }

    let services = [];
    try {
      services = await this._collectObjectCategory(
        vdomList,
        'show firewall service custom',
        'firewall service custom',
        'services',
        cliParser.serviceEntryToNamedService
      );
    } catch (err) {
      console.warn(
        `[Fortinet] getObjects(): services collection failed entirely for device ${this.device.id}: ${err.message}`
      );
    }

    let serviceGroups = [];
    try {
      serviceGroups = await this._collectObjectCategory(
        vdomList,
        'show firewall service group',
        'firewall service group',
        'serviceGroups',
        cliParser.groupEntryToNamedGroup
      );
    } catch (err) {
      console.warn(
        `[Fortinet] getObjects(): serviceGroups collection failed entirely for device ${this.device.id}: ${err.message}`
      );
    }

    return { addresses, addressGroups, services, serviceGroups };
  }

  // Resolves the VDOM list for getObjects(). Mirrors
  // _discoverVdomsForVpnPoll()'s "config global / show system vdom / end"
  // enumeration exactly, but with a softer failure mode: unlike that method (which
  // is allowed to return null and let its caller throw — VPN polling has a
  // "nothing usable at all" hard-fail path), getObjects() must never throw
  // overall, so enumeration failure here falls back to a single default-VDOM
  // attempt (`[null]`) rather than propagating.
  async _resolveVdomListForObjects(status) {
    if (!status || !cliParser.isMultiVdom(status)) return [null];

    let vdoms = null;
    try {
      const results = await this._run(['config global', 'show system vdom', 'end']);
      vdoms = cliParser.vdomNamesFromConfigText(FortinetSshAdapter._outputAt(results, 1));
    } catch (err) {
      console.warn(
        `[Fortinet] getObjects(): VDOM enumeration failed for device ${this.device.id} — falling ` +
          `back to a single default-VDOM object collection attempt: ${err.message}`
      );
    }

    if (!vdoms || vdoms.length === 0) return [null];

    const safe = vdoms.filter((name) => cliParser.isSafeVdomName(name));
    const unsafe = vdoms.length - safe.length;
    if (unsafe > 0) {
      console.warn(
        `[Fortinet] getObjects(): device ${this.device.id} had ${unsafe} VDOM name(s) with ` +
          'unexpected characters for the object catalog pull — skipping them rather than ' +
          'sending them to the CLI.'
      );
    }
    return safe.length > 0 ? safe : [null];
  }

  // Runs `command` (a `show <block>` dump) once per VDOM in `vdomList` — or once,
  // unwrapped, when `vdomList` is `[null]` (a non-VDOM box, mirroring
  // _getRulesSingleVdom()'s equivalent shortcut) — maps every returned entry via
  // `mapFn`, and never throws: every failure (a single VDOM's `edit`/command, or
  // the whole category) is caught, logged, and skipped, per getObjects()'s
  // graceful-degradation contract. On a multi-VDOM box this mirrors
  // _getRulesMultiVdom()'s exact `config vdom` / `edit <vdom>` / `<command>` /
  // `end` batching shape in one SSH session — the one difference from that method
  // is that a single VDOM's failure here is caught and skipped rather than
  // aborting the whole category.
  async _collectObjectCategory(vdomList, command, blockPath, label, mapFn) {
    const out = [];

    if (vdomList.length === 1 && vdomList[0] === null) {
      const results = await this._run([command]);
      this._appendObjectEntries(out, FortinetSshAdapter._outputAt(results, 0), blockPath, null, label, mapFn);
      return out;
    }

    const commands = [];
    const editIndexByVdom = new Map();
    const outputIndexByVdom = new Map();
    for (const vdom of vdomList) {
      commands.push('config vdom');
      commands.push(`edit ${vdom}`);
      editIndexByVdom.set(vdom, commands.length - 1);
      outputIndexByVdom.set(vdom, commands.length);
      commands.push(command);
      commands.push('end');
    }

    const results = await this._run(commands);

    for (const vdom of vdomList) {
      try {
        this._assertVdomEditSucceeded(vdom, FortinetSshAdapter._outputAt(results, editIndexByVdom.get(vdom)));
        this._appendObjectEntries(
          out,
          FortinetSshAdapter._outputAt(results, outputIndexByVdom.get(vdom)),
          blockPath,
          vdom,
          label,
          mapFn
        );
      } catch (err) {
        console.warn(
          `[Fortinet] getObjects(): ${label} collection failed for VDOM "${vdom}" on device ` +
            `${this.device.id}: ${err.message}`
        );
      }
    }

    return out;
  }

  // Parses one command's captured output (for one VDOM, or the implicit default
  // VDOM when `vdom` is null) into NamedAddress/NamedService/NamedGroup entries,
  // appending onto `out`. A CLI rejection or "no such block present" result is
  // logged and skipped, never thrown — see getObjects()'s class-level doc comment.
  _appendObjectEntries(out, output, blockPath, vdom, label, mapFn) {
    const where = vdom ? ` for VDOM "${vdom}"` : '';

    if (!loggedFirstObjectOutput.has(blockPath)) {
      // Bounded preview: an address/service book can run to thousands of lines on
      // a real box. Carries no secrets (object names/subnets/ports only), unlike
      // the full-configuration preview above.
      console.log(
        `[Fortinet Debug] SSH \`show ${blockPath}\`${where} (${output.length} chars). First 4000 chars:\n` +
          output.slice(0, 4000)
      );
      loggedFirstObjectOutput.add(blockPath);
    }

    if (cliParser.looksLikeCliError(output)) {
      console.warn(
        `[Fortinet] getObjects(): \`show ${blockPath}\`${where} was rejected on device ` +
          `${this.device.id} — skipping this ${label} source.`
      );
      return;
    }

    const entries = cliParser.entriesFromConfigText(output, blockPath);
    if (entries === null) {
      // Not an error — this block simply wasn't present in the captured output
      // (e.g. this device/VDOM genuinely has zero custom services). Nothing to
      // append.
      return;
    }

    for (const entry of entries) {
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
  }

  // → { cpuPercent, memoryPercent, sessionCount, uptimeSeconds, raw,
  //     lowConfidence, targetHost } — an OPTIONAL adapter capability, not
  // part of the FirewallAdapter base interface. See
  // lib/adapters/interface.js's getSnmpMetrics() contract comment. SNMP is
  // a completely separate UDP connection from this adapter's own SSH
  // transport — uses a SEPARATE credential (credential_type='snmp') and is
  // never gated on or mixed with testConnectivity()/getRules()'s SSH auth.
  // All four OIDs are true scalars (see SNMP_OID above), so a single
  // getMetrics() GET is all that's needed — no walkSubtree() required,
  // unlike Cisco ASA's equivalent. MAY throw (missing credential, timeout,
  // auth failure) — engine-worker's snmp-poll job already treats that
  // exactly like any other per-device polling failure (logged and
  // skipped, never fatal).
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

module.exports = { FortinetSshAdapter };
