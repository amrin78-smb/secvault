// lib/adapters/sangfor/index.js
// CommonJS ONLY — services/engine-worker.js (plain node) loads adapters via require.
//
// Sangfor NGAF adapter — SSH-based, sparsely documented vendor. This adapter is
// maximally defensive and degrades gracefully: partial data always beats thrown
// errors. Sangfor CLI syntax varies by firmware line (Cisco-flavored on some,
// Huawei-flavored on others), so every command is tried with fallbacks and every
// raw output is logged with a '[Sangfor Debug]' prefix on first-connect paths, per
// CLAUDE.md's live-verification rule ("verify all field names against live
// responses before writing any parser" — there was no live NGAF available during
// this build, so the operator must check the debug logs on first real connect).
//
// See CLAUDE.md Pool Warning: testConnectivity() and every path that touches
// credStore MUST use this.pool. Never remove it — builds clean, breaks silently.

'use strict';

const { FirewallAdapter } = require('../interface');
const credStore = require('../../credStore');
const { runCommands, parseJsonCredential } = require('../sshClient');
const parser = require('./parser');
const { parseVersion } = require('../../engines/versionComparator');
const { createSession, getMetrics, walkSubtree, closeSession } = require('../../snmpClient');
const { parseSnmpCredential } = require('../snmpCredential');

// Version banner: Cisco-flavored first, Huawei-flavored fallback.
const VERSION_COMMANDS = ['show version', 'display version'];

// SNMP OIDs for getSnmpMetrics() — deliberately STANDARD MIB-II /
// HOST-RESOURCES-MIB ONLY. Sangfor is this codebase's least-verified vendor
// (CLAUDE.md's "Live Validation Status": no live NGAF has ever been
// connected, and unlike every other vendor here there is no documentation
// trail to check field names against either — see getObjects() above for
// the identical reasoning already applied to the object catalog). Inventing
// a plausible-sounding Sangfor-proprietary enterprise MIB here would be
// exactly the "guessing ungrounded syntax" CLAUDE.md's live-verification
// rule warns against, so this method uses ONLY OIDs defined by RFC 1213
// (MIB-II) and RFC 2790 (HOST-RESOURCES-MIB) — implemented by essentially
// every SNMP agent regardless of vendor — and unconditionally reports
// lowConfidence: true (per this feature's explicit scope decision), since
// even a standard OID resolving successfully says nothing about whether
// Sangfor's agent maps it the way the MIB intends.
//
// - sysUpTime.0 (MIB-II, RFC 1213) — universal scalar, no vendor mapping
//   needed to interpret (TimeTicks, hundredths of a second).
// - hrProcessorLoad table (HOST-RESOURCES-MIB), root
//   1.3.6.1.2.1.25.3.3.1.2 — one row per CPU, each value already a 0-100
//   percentage; averaged across all returned rows.
// - hrStorage table (HOST-RESOURCES-MIB), root 1.3.6.1.2.1.25.2.3.1 —
//   walked whole (descr/size/used columns), then the row whose descr text
//   indicates physical RAM is used to compute used/size as a percentage.
//   No standard OID reports memory as a single ready-made percentage, and
//   correlating hrStorage's sibling columns by row index is inherently
//   best-effort against an unverified agent — an honest null when no
//   matching row is found is the correct outcome, not a guess.
const SNMP_SCALAR_OID = {
  sysUpTime: '1.3.6.1.2.1.1.3.0',
};
const SNMP_CPU_TABLE_BASE = '1.3.6.1.2.1.25.3.3.1.2'; // hrProcessorLoad
const SNMP_STORAGE_TABLE_BASE = '1.3.6.1.2.1.25.2.3.1'; // hrStorageEntry
const HR_STORAGE_DESCR_COLUMN = '3'; // hrStorageDescr
const HR_STORAGE_SIZE_COLUMN = '5'; // hrStorageSize
const HR_STORAGE_USED_COLUMN = '6'; // hrStorageUsed
const HR_STORAGE_TABLE_BASE_LEN = SNMP_STORAGE_TABLE_BASE.split('.').length;
// Matches the conventional HOST-RESOURCES-MIB descr text for the physical
// RAM row ("Physical memory", "Physical Memory", occasionally "Real
// Memory") without also matching "Virtual memory"/"Swap space"/"Cached
// memory"/mounted-filesystem rows that share the same table.
const PHYSICAL_MEMORY_DESCR_RE = /physical\s*memory|real\s*memory/i;

let snmpDebugLogged = false;

// Full-config dump candidates, in preference order. Sangfor NGAF has no stable
// documented CLI for policy export — these are the common syntaxes across
// firmware lines. Each is tried independently; the first non-empty output wins.
const CONFIG_COMMANDS = [
  'show running-config',
  'display current-configuration',
  'show configuration',
];

class SangforAdapter extends FirewallAdapter {
  constructor({ device, pool }) {
    super({ device, pool });
    // Per-instance config cache so getRules() and getConfig() in the same collect
    // cycle don't dump the running config over SSH twice.
    this._configText = null;
    this._configCommand = null;
  }

  // Builds the SSH connection descriptor + options, decrypting the stored SSH
  // credential via credStore. Always uses this.pool (CLAUDE.md Pool Warning).
  async _getConn() {
    const plaintext = await credStore.getCredential(this.device.id, 'ssh', this.pool);
    if (!plaintext) {
      throw new Error(
        `No SSH credential found for device ${this.device.id} — save credentials before connecting.`
      );
    }

    const cred = parseJsonCredential(plaintext);

    const conn = {
      host: this.device.mgmt_ip,
      port: this.device.mgmt_port || 22,
      username: cred.username,
      password: cred.password,
    };

    const options = {};
    if (cred.enable_password) {
      options.enablePassword = cred.enable_password;
    }

    return { conn, options };
  }

  // Runs a single command over SSH; returns its output string ('' when the device
  // returned nothing). Throws only if the sshClient itself throws (connect/auth/
  // timeout failures) — callers decide whether that is fatal.
  async _runOne(conn, options, command) {
    const results = await runCommands(conn, [command], options);
    const first = Array.isArray(results) ? results[0] : null;
    return first && typeof first.output === 'string' ? first.output : '';
  }

  // Tries `commands` in order, each in its own try/catch. Returns
  // { command, output, connected, lastError }:
  //   command/output — the first command that produced non-empty output (or nulls)
  //   connected      — true if at least one runCommands call completed (SSH worked)
  //   lastError      — the last thrown error, for diagnostics
  async _tryCommands(conn, options, commands) {
    let connected = false;
    let lastError = null;

    for (const command of commands) {
      try {
        const output = await this._runOne(conn, options, command);
        connected = true;
        if (output.trim().length > 0) {
          return { command, output, connected, lastError };
        }
        console.warn(`[Sangfor] \`${command}\` returned empty output on ${conn.host} — trying next fallback.`);
      } catch (err) {
        lastError = err;
        console.warn(`[Sangfor] \`${command}\` failed on ${conn.host}: ${err.message} — trying next fallback.`);
      }
    }

    return { command: null, output: null, connected, lastError };
  }

  // Fetches the raw config text (first non-empty of CONFIG_COMMANDS), cached per
  // adapter instance. Returns { text, command } — text is null if every command
  // failed or returned nothing.
  async _getConfigText() {
    if (this._configText !== null) {
      return { text: this._configText, command: this._configCommand };
    }

    const { conn, options } = await this._getConn();
    const attempt = await this._tryCommands(conn, options, CONFIG_COMMANDS);

    if (attempt.output !== null) {
      // The cache holds the UNREDACTED text on purpose: rule parsing needs the
      // real tokens (redaction is keyword-based and would mangle object names
      // like "community-web"). Redaction is applied at every egress point
      // instead — the debug log below, and getConfig()'s `raw`.
      this._configText = attempt.output;
      this._configCommand = attempt.command;
      // First-connect verification aid: log a bounded preview, not the whole dump
      // (running configs can be tens of thousands of lines).
      // SECURITY: redact BEFORE logging — this preview lands in the engine log
      // on disk, and a config dump can carry admin hashes / PSKs / communities.
      const preview = parser.redactConfig(attempt.output).slice(0, 2000);
      console.log(
        `[Sangfor Debug] Config via \`${attempt.command}\` (${attempt.output.length} chars, secrets redacted). First 2000 chars:\n${preview}`
      );
      return { text: this._configText, command: this._configCommand };
    }

    return { text: null, command: null, lastError: attempt.lastError, connected: attempt.connected };
  }

  // → { ok, latency_ms, message } — must NEVER throw (CLAUDE.md Pool Warning
  // pattern: still goes through credStore with this.pool even though it "looks
  // like" a pure connectivity test).
  async testConnectivity() {
    const startedAt = Date.now();
    try {
      const { conn, options } = await this._getConn();
      const attempt = await this._tryCommands(conn, options, VERSION_COMMANDS);

      if (attempt.output !== null) {
        return {
          ok: true,
          latency_ms: Date.now() - startedAt,
          message: `Connected (\`${attempt.command}\` responded)`,
        };
      }

      if (attempt.connected) {
        // SSH session worked but neither version command produced output — still
        // reachable; flag it so the operator knows the CLI dialect is unusual.
        return {
          ok: true,
          latency_ms: Date.now() - startedAt,
          message:
            'SSH connection succeeded but `show version`/`display version` returned no output — CLI dialect may differ, check [Sangfor Debug] logs on collection.',
        };
      }

      return {
        ok: false,
        latency_ms: null,
        message: attempt.lastError ? attempt.lastError.message : 'SSH connection failed',
      };
    } catch (err) {
      return { ok: false, latency_ms: null, message: err.message };
    }
  }

  // → { version_string, version_tuple, build, model }
  async getVersion() {
    const { conn, options } = await this._getConn();
    const attempt = await this._tryCommands(conn, options, VERSION_COMMANDS);

    if (attempt.output === null) {
      if (!attempt.connected) {
        throw new Error(
          `Sangfor SSH connection failed for device ${this.device.id}: ${
            attempt.lastError ? attempt.lastError.message : 'unknown error'
          }`
        );
      }
      throw new Error(
        'Sangfor version detection failed: `show version` and `display version` both returned no output. ' +
          'Check the [Sangfor Debug] output in the logs and update lib/adapters/sangfor/parser.js for this firmware CLI dialect.'
      );
    }

    // CLAUDE.md live-verification rule: log the full raw output so the first real
    // connection to an NGAF can be used to correct the parser's assumptions.
    console.log(`[Sangfor Debug] \`${attempt.command}\` raw output:\n${attempt.output}`);

    const parsed = parser.parseVersionOutput(attempt.output);

    if (!parsed.version_string) {
      throw new Error(
        `Sangfor version parse failed: \`${attempt.command}\` produced output but no token matching ` +
          'a dotted version number (e.g. "8.0.85") was found. Check the [Sangfor Debug] raw output ' +
          'logged above and update lib/adapters/sangfor/parser.js field extraction for this firmware.'
      );
    }

    return {
      version_string: parsed.version_string,
      version_tuple: parseVersion('sangfor', parsed.version_string),
      build: parsed.build,
      model: parsed.model,
    };
  }

  // → NormalizedRule[]
  //
  // Graceful degradation here means "the config was READ but holds no parseable
  // policy blocks" → []. It does NOT mean "we could not talk to the device".
  //
  // Returning [] on a retrieval failure would be a false success: collectAndStore
  // awaits getRules() and only then DELETEs firewall_rules, so a throw preserves
  // the device's previously collected rules and surfaces a clear error, whereas
  // [] silently wipes them, wipes the Phase 5 findings that cascade from them,
  // and reports rulesCount: 0 as if the device genuinely had no rules.
  async getRules() {
    let result;
    try {
      result = await this._getConfigText();
    } catch (err) {
      throw new Error(
        `Sangfor rule collection failed — could not retrieve config over SSH: ${err.message}`
      );
    }

    if (result.text === null) {
      throw new Error(
        `Sangfor rule collection failed: all of ${CONFIG_COMMANDS.map((c) => `\`${c}\``).join(', ')} ` +
          `failed or returned no output${
            result.lastError ? ` (last error: ${result.lastError.message})` : ''
          }. Check SSH reachability/credentials and the [Sangfor Debug] logs. ` +
          'Not treating this as "zero rules" — existing rules are left untouched.'
      );
    }

    const rules = parser.parseRulesFromConfig(result.text);

    if (rules.length === 0) {
      // Genuine degradation: the device answered with a config, it just has no
      // blocks this parser recognizes. [] is honest here.
      console.warn(
        '[Sangfor] Config retrieved but no rules could be parsed from it — rule extraction for this vendor may require the NGAF web API or a newer firmware CLI; config snapshot is still collected.'
      );
    }

    return rules;
  }

  // → { raw, parsed } — throws a clear error only if every config command failed;
  // if at least one returned text, always succeeds with best-effort parsing.
  async getConfig() {
    const result = await this._getConfigText();

    if (result.text === null) {
      throw new Error(
        `Sangfor config collection failed: all of ${CONFIG_COMMANDS.map((c) => `\`${c}\``).join(', ')} ` +
          `failed or returned no output${
            result.lastError ? ` (last error: ${result.lastError.message})` : ''
          }. Check SSH reachability/credentials and the [Sangfor Debug] logs.`
      );
    }

    // SECURITY: `raw` is persisted verbatim into device_configs.config_raw,
    // copied into config_backups, served by the backup download route, and
    // readable by the claude_readonly / nocvault_readonly roles. Nothing
    // downstream redacts, so redact here before it leaves the adapter.
    //
    // `parsed.sections` is built from the REDACTED text too, not the raw
    // `result.text` — found in a full-app audit (2026-07-16). Not actively
    // exploitable today (parseConfigSections only extracts hostname/version/
    // interface names, none secret-shaped), but building it from unredacted
    // text was the wrong order: a future field added to parseConfigSections
    // could silently leak a secret into config_parsed (also grant-readable)
    // with no test or review signal catching it. Matches the redact-first
    // discipline established this session for Palo Alto SSH's config_parsed.
    const redacted = parser.redactConfig(result.text);
    return {
      raw: redacted,
      parsed: {
        source_command: result.command,
        line_count: result.text.split(/\r?\n/).length,
        sections: parser.parseConfigSections(redacted),
        collected_via: 'ssh',
      },
    };
  }

  // → { addresses, addressGroups, services, serviceGroups } — see
  // lib/adapters/interface.js's FirewallAdapter comment for the exact contract.
  // OPTIONAL per the base interface; lib/adapters/index.js's collectAndStore()
  // checks `typeof adapter.getObjects === 'function'` before calling this, and
  // an all-empty catalog is a normal "nothing available for this device" state,
  // not an error — rendered as an empty state by the UI, never a crash/red flag.
  //
  // Judgment call (2026-07-19), made explicitly rather than guessed: this is
  // deliberately NOT a real parser. Sangfor NGAF is this codebase's
  // least-verified vendor (CLAUDE.md "Live Validation Status" — no live device
  // has ever been connected, and unlike every other vendor here there is no
  // documentation trail to check field names against either). The existing
  // low-confidence precedent in this file, parser.js's `ssl_vpn.enabled`
  // tri-state detection, is a defensible bounded guess: ONE line
  // ("ssl-vpn enable|disable"), a keyword pairing plausible across every
  // Cisco/Huawei-flavored CLI dialect this adapter already tries, with a
  // single boolean outcome and an honest `null` for "undetected."
  //
  // A named address/service OBJECT CATALOG is a different, much higher-risk
  // kind of guess: it needs a block HEADER keyword to even recognize a
  // definition (candidates across firmware dialects might be
  // `ip address-set`, `object-group network`, `address-object`,
  // `service-object`, ... — no two vendors agree, and Sangfor's own NGAF CLI
  // has no captured sample anywhere in this codebase), a value syntax (mask vs.
  // CIDR vs. range vs. wildcard), and separate group-membership syntax. The
  // existing rule-block parser's field keyword sets (SRC_ADDR_KEYS, SVC_KEYS,
  // etc., above in parser.js) describe how a POLICY REFERENCES an object by
  // name inside `_getConfigText()`'s already-captured dump — they say nothing
  // about how that object is DEFINED, so they provide no grounding for this
  // either. Writing regex against invented block syntax here would be exactly
  // the "guessing plausible-sounding-but-ungrounded CLI syntax" this task and
  // CLAUDE.md's "documentation lies, verify against live responses before
  // writing any parser" rule both reject — it would fabricate an unused-object
  // finding as confidently as a real one, with zero way to tell the two apart.
  //
  // An honest empty catalog is the correct, preferred choice per this
  // codebase's own established convention (see CLAUDE.md's acceptance of
  // "not yet built" over fabricated parsing logic for structurally-uncertain
  // Sangfor/Palo-Alto-object-resolution cases elsewhere). Revisit once a live
  // NGAF connection lets a real `[Sangfor Debug]` config dump be inspected for
  // whatever object-definition syntax that firmware actually uses.
  async getObjects() {
    return { addresses: [], addressGroups: [], services: [], serviceGroups: [] };
  }

  // → { cpuPercent, memoryPercent, sessionCount, uptimeSeconds, raw,
  //     lowConfidence, targetHost } — OPTIONAL, see lib/adapters/interface.js's
  // getSnmpMetrics() contract comment. Uses a SEPARATE credential
  // (credential_type='snmp') from this adapter's own SSH credential — never
  // gated on / mixed with testConnectivity()/getRules()'s auth. MAY throw
  // (missing credential, timeout, auth failure) — engine-worker's snmp-poll
  // job already treats that like any other per-device polling failure.
  //
  // lowConfidence is unconditionally true for this vendor (per this
  // feature's explicit scope decision — see the SNMP OID comments above):
  // Sangfor has no known documentation trail and no live device to verify
  // against, so even a clean SNMP response here is a weaker signal than the
  // same response from a vendor whose MIB usage has been confirmed.
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
      const scalarResult = await getMetrics(session, SNMP_SCALAR_OID, undefined, targetHost);
      const cpuRows = await walkSubtree(session, SNMP_CPU_TABLE_BASE, undefined, targetHost);
      const storageRows = await walkSubtree(session, SNMP_STORAGE_TABLE_BASE, undefined, targetHost);

      if (!snmpDebugLogged) {
        snmpDebugLogged = true;
        console.log(
          '[Sangfor SNMP Debug] raw responses:',
          JSON.stringify({ scalarResult, cpuRows, storageRows })
        );
      }

      const uptimeTicks = scalarResult.sysUpTime;
      const uptimeSeconds =
        uptimeTicks !== null && uptimeTicks !== undefined && !Number.isNaN(Number(uptimeTicks))
          ? Math.round(Number(uptimeTicks) / 100)
          : null;

      // hrProcessorLoad: one row per CPU, each already a 0-100 percentage.
      // Zero rows returned (OID not implemented by this agent) → null, never
      // a fabricated 0.
      let cpuPercent = null;
      if (cpuRows.length > 0) {
        const loads = cpuRows.map((r) => Number(r.value)).filter((n) => !Number.isNaN(n));
        if (loads.length > 0) {
          cpuPercent = Math.round((loads.reduce((sum, n) => sum + n, 0) / loads.length) * 100) / 100;
        }
      }

      // hrStorage: sibling columns (descr/size/used) share the same row
      // index as their final OID component — group by that index, then find
      // the row whose descr identifies physical RAM. The used/size ratio is
      // valid regardless of hrStorageAllocationUnits (both columns are in
      // the same units for a given row), so allocation units are not needed.
      const storageRowsByIndex = {};
      for (const row of storageRows) {
        const parts = String(row.oid).split('.');
        if (parts.length !== HR_STORAGE_TABLE_BASE_LEN + 2) continue; // not a well-formed column.row entry
        const column = parts[HR_STORAGE_TABLE_BASE_LEN];
        const rowIndex = parts[HR_STORAGE_TABLE_BASE_LEN + 1];
        if (!storageRowsByIndex[rowIndex]) storageRowsByIndex[rowIndex] = {};
        if (column === HR_STORAGE_DESCR_COLUMN) storageRowsByIndex[rowIndex].descr = row.value;
        else if (column === HR_STORAGE_SIZE_COLUMN) storageRowsByIndex[rowIndex].size = row.value;
        else if (column === HR_STORAGE_USED_COLUMN) storageRowsByIndex[rowIndex].used = row.value;
      }

      let memoryPercent = null;
      const memoryRow = Object.values(storageRowsByIndex).find(
        (r) => typeof r.descr === 'string' && PHYSICAL_MEMORY_DESCR_RE.test(r.descr)
      );
      if (memoryRow) {
        const size = Number(memoryRow.size);
        const used = Number(memoryRow.used);
        if (!Number.isNaN(size) && !Number.isNaN(used) && size > 0) {
          memoryPercent = Math.round((used / size) * 10000) / 100;
        }
      }
      // No matching physical-memory row found (agent doesn't implement
      // hrStorage, or uses different descr text than every dialect this
      // regex covers) → memoryPercent stays null. An honest null is the
      // correct outcome here — see the SNMP OID comment block above.

      return {
        cpuPercent,
        memoryPercent,
        // No MIB-II/HOST-RESOURCES-MIB equivalent exists for a firewall's
        // active session/connection count — that concept has no generic
        // SNMP representation, only vendor-proprietary MIBs (e.g. Cisco's
        // CISCO-FIREWALL-MIB, used by the cisco_asa adapter's own
        // getSnmpMetrics()). Sangfor has no known proprietary MIB either
        // (see this file's getObjects() comment on the total absence of a
        // documentation trail for this vendor), so sessionCount is always
        // null rather than guessed at.
        sessionCount: null,
        uptimeSeconds,
        raw: { scalarResult, cpuRows, storageRows },
        lowConfidence: true,
        targetHost,
      };
    } finally {
      closeSession(session);
    }
  }
}

module.exports = { SangforAdapter };
