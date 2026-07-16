// lib/adapters/paloalto/ssh.js
// Palo Alto PAN-OS adapter — SSH/CLI transport.
// CommonJS ONLY — required by ./index.js, which the adapter registry
// (lib/adapters/index.js) requires from services/engine-worker.js (plain node).
//
// The SIBLING of ./index.js's PaloaltoAdapter (XML API). Dispatch picks between
// them on devices.mgmt_method: 'api' → PaloaltoAdapter, 'ssh' → PaloaltoSshAdapter.
// Credential type is 'ssh', shape 'userpass' → JSON {"username","password"}, per
// VENDOR_META in components/devices/vendorMeta.js.
//
// See CLAUDE.md — in particular the Pool Warning: testConnectivity() and every path
// touching credStore MUST receive and use this.pool, even though a connectivity test
// looks pure. Removing pool builds clean and breaks credential decryption silently.

'use strict';

const { FirewallAdapter } = require('../interface');
const credStore = require('../../credStore');
const { runCommands, parseJsonCredential } = require('../sshClient');
const sshParser = require('./sshParser');
const { parseVersion } = require('../../engines/versionComparator');

// PAN-OS prompt: `admin@PA-VM>` (operational) / `admin@PA-VM#` (configure), with an
// optional HA/vsys qualifier: `admin@PA-3220(active)>`.
//
// STRICTER than the shared DEFAULT_PROMPT_REGEX (/[>#$%]\s*$/) and than the ASA
// adapter's /[>#]\s*$/, deliberately. Read the DEFAULT_PROMPT_REGEX comment in
// ../sshClient.js first: the prompt is matched against the whole accumulated buffer
// on EVERY network chunk, so any buffer that transiently ends in `>` or `#` is read
// as a prompt and the command returns SILENTLY TRUNCATED. The full-tree `show` on
// a real firewall is a multi-MB dump arriving over hundreds of chunks — with a loose
// regex, one chunk boundary landing after a `>`/`#` anywhere in that dump truncates
// the config, and a truncated config is stored as if it were complete. Requiring the
// full `user@host>` shape makes a false match essentially impossible in config text.
//
// The trade-off, stated plainly: if a PAN-OS build presents a prompt that does not
// match this, every command times out with an explicit "Timed out ... waiting for
// output of command" error. That is a LOUD failure and the right side to fail on —
// the alternative is a silently truncated config stored as real history.
const PANOS_PROMPT_REGEX = /[\w.-]+@[\w.-]+(?:\([^\n()]*\))?\s*[>#]\s*$/;

// Pager off FIRST — before any command whose output can exceed a screen.
const PAGER_OFF = 'set cli pager off';

// ⚠️ RESOLVED (2026-07-16, PAN-OS 11.1.13-h5, two independent devices — a
// PA-440 and a PA-3220): this command sequence was originally chosen to chase
// flat `set ...` output (`configure` + `set cli config-output-format set` +
// bare `show` is the standard documented technique for it), but live testing
// on both devices proved the format preference has no effect here — the
// retrieved text is reliably the classic curly-brace tree
// (`rulebase { security { rules { RuleName { from ...; action allow; } } } } }`),
// confirmed by directly inspecting the real rulebase section (see ssh.js's
// targeted "rulebase" debug search, and sshParser.js's brace-tree parser built
// against that captured sample).
//
// The command sequence below is KEPT AS-IS — it reliably retrieves the FULL
// config tree from root (confirmed: 1.2MB, containing the rulebase, versus a
// smaller/unconfirmed result from plain `show config running`) — only the
// PARSER changed, from expecting `set` lines to parsing the brace tree that
// actually comes back. See sshParser.js's "Brace format, not `set` format"
// header for the parser side of this.
//
// `configure` needs no elevated role beyond ordinary CLI config-read access — a
// PAN-OS "superreader" (built-in read-only) account can enter it and run `show`;
// it just cannot commit/edit. If the SSH account genuinely cannot enter
// configuration mode, `configure` itself answers with a rejection that
// looksLikeCliError() catches, and _getConfigText() throws — never silently
// stores a partial/rejected result.
const CONFIGURE_MODE = 'configure';
const SET_FORMAT = 'set cli config-output-format set';

const SYSTEM_INFO_COMMAND = 'show system info';
const RUNNING_CONFIG_COMMAND = 'show';

// A full config dump over a WAN is slow — the shared client's 20s default is a
// version-command budget, not a config-dump budget.
const CONFIG_COMMAND_TIMEOUT_MS = 120000;

let loggedFirstSystemInfo = false;
let loggedFirstConfig = false;

class PaloaltoSshAdapter extends FirewallAdapter {
  constructor({ device, pool }) {
    super({ device, pool });
    // Per-instance cache: collectAndStore() builds ONE adapter per device per
    // collect and calls getVersion/getRules/getConfig on it. getRules() and
    // getConfig() both need the running config — without this they would dump a
    // multi-MB config over SSH twice per collect. Same pattern as the Sangfor
    // adapter. Holds the UNREDACTED text on purpose: rule parsing needs the real
    // tokens, and redaction is applied at every egress point instead (the debug log
    // and getConfig()'s `raw`).
    this._configText = null;
    // Same reasoning for system info: getVersion() and getConfig() both need it, and
    // every _run() is a full TCP + SSH handshake + shell + pager-off round trip. One
    // collect would otherwise open four SSH sessions instead of two.
    // testConnectivity() is unaffected — the /test route builds a fresh adapter, so
    // it never reads a cache populated by an earlier call.
    this._systemInfo = null;
  }

  // Builds the SSH connection descriptor + shell options, decrypting the stored
  // credential via credStore. ALWAYS uses this.pool (CLAUDE.md Pool Warning).
  // Credential plaintext is JSON: {"username":"...","password":"..."}.
  async _getSession(extraInitCommands = []) {
    const plaintext = await credStore.getCredential(this.device.id, 'ssh', this.pool);
    if (!plaintext) {
      throw new Error(
        `No SSH credential found for device ${this.device.id} — save credentials before connecting.`
      );
    }

    // parseJsonCredential's errors name the missing FIELDS only, never the values.
    const cred = parseJsonCredential(plaintext);

    return {
      conn: {
        host: this.device.mgmt_ip,
        port: this.device.mgmt_port || 22,
        username: cred.username,
        password: cred.password,
      },
      options: {
        promptRegex: PANOS_PROMPT_REGEX,
        // Pager off first, then any session-specific init.
        initCommands: [PAGER_OFF, ...extraInitCommands],
        // PAN-OS has NO enable/privileged mode — role is bound to the account, so
        // there is deliberately no enablePassword here. (A read-only "superreader"
        // PAN-OS admin can still enter `configure` and run `show`; it returns the
        // config it can see, just cannot commit/edit.)
        enablePassword: null,
      },
    };
  }

  // Runs commands in one SSH shell session against this device.
  async _run(commands, { extraInitCommands = [], commandTimeoutMs } = {}) {
    const { conn, options } = await this._getSession(extraInitCommands);
    const runOptions = { ...options };
    if (typeof commandTimeoutMs === 'number') runOptions.commandTimeoutMs = commandTimeoutMs;
    return runCommands(conn, commands, runOptions);
  }

  // Fetches `show system info` and parses it, cached per adapter instance.
  // Throws on connection/CLI failure — a failure is never cached.
  async _getSystemInfo() {
    if (this._systemInfo !== null) return this._systemInfo;

    const results = await this._run([SYSTEM_INFO_COMMAND]);
    const output = results[0] ? results[0].output : '';

    if (sshParser.looksLikeCliError(output)) {
      throw new Error(
        `PAN-OS rejected \`${SYSTEM_INFO_COMMAND}\` on device ${this.device.id}. ` +
          'Check that the SSH account has operational-command access. ' +
          'Refusing to store a partial/empty result.'
      );
    }

    if (!loggedFirstSystemInfo) {
      // CLAUDE.md live-verification rule: log the raw output so the first real
      // connection can be used to correct this adapter's field assumptions.
      // `show system info` carries no secrets (hostname/model/versions/serial).
      console.log(`[PaloAlto SSH Debug] \`${SYSTEM_INFO_COMMAND}\` raw output:\n${output}`);
      loggedFirstSystemInfo = true;
    }

    this._systemInfo = sshParser.parseSystemInfoOutput(output);
    return this._systemInfo;
  }

  // Fetches the running config as `set` lines, cached per adapter instance.
  // THROWS on any failure — never returns empty text. See getRules() for why that
  // distinction is load-bearing.
  //
  // Enters configuration mode FIRST — see the CONFIGURE_MODE/SET_FORMAT comment
  // above for why `show config running` (operational mode) cannot be made to
  // emit `set` lines no matter what `cli config-output-format` is set to. If the
  // account cannot enter config mode, `configure` fails silently at the init-
  // command stage (sshClient's init commands discard their output — see
  // ../sshClient.js), but the fallback is still safe: a bare `show` command is
  // invalid in OPERATIONAL mode (PAN-OS requires an argument there), so
  // looksLikeCliError() below still catches it off the REAL captured command
  // output and throws, rather than silently storing brace-format text again.
  async _getConfigText() {
    if (this._configText !== null) return this._configText;

    const results = await this._run([RUNNING_CONFIG_COMMAND], {
      extraInitCommands: [CONFIGURE_MODE, SET_FORMAT],
      commandTimeoutMs: CONFIG_COMMAND_TIMEOUT_MS,
    });
    const output = results[0] ? results[0].output : '';

    if (sshParser.looksLikeCliError(output)) {
      throw new Error(
        `PAN-OS rejected \`${RUNNING_CONFIG_COMMAND}\` (after \`${CONFIGURE_MODE}\`) on device ` +
          `${this.device.id}. This usually means the SSH account could not enter configuration ` +
          'mode — give it a role with configuration-read access (a built-in "superreader" role ' +
          'is sufficient; it does not need commit/edit rights). Refusing to store a partial/empty result.'
      );
    }

    if (!sshParser.looksLikePanosConfig(output)) {
      // Storing this would silently overwrite real config history with an empty
      // parse and trigger a bogus config-change diff + backup. Device output is
      // NOT echoed — a partial config dump can contain secrets.
      throw new Error(
        `\`${RUNNING_CONFIG_COMMAND}\` on device ${this.device.id} returned ${output.length} ` +
          'bytes that do not look like a PAN-OS configuration. Check SSH reachability, the ' +
          'account\'s permissions, and the [PaloAlto SSH Debug] logs. Refusing to store it.'
      );
    }

    this._configText = output;

    if (!loggedFirstConfig) {
      // SECURITY: redact BEFORE logging — this preview lands in engine.log on disk,
      // and a PAN-OS config carries phash, pre-shared keys and SNMP communities.
      //
      // ⚠️ NOT CONFIRMED to be `set` format -- say so plainly rather than assert it.
      // Live evidence (2026-07-16, two independent devices: a PA-440 and a PA-3220,
      // both PAN-OS 11.1.13-h5) shows `configure` + `set cli config-output-format set`
      // + bare `show` STILL returns the curly-brace tree (`deviceconfig { system {
      // ... } }`), not flat `set ...` lines, despite that being the standard
      // documented technique. Something about this firmware's handling of the
      // preference command is still not understood -- guessing a third command
      // sequence without seeing the actual rulebase text first would repeat the
      // exact mistake that produced this bug in the first place.
      //
      // Two previews, not one: the head preview alone proved insufficient TWICE
      // now (both times it landed in deviceconfig/mgt-config, never reaching the
      // rulebase on a 90KB-1.2MB dump) -- so this also searches for the literal
      // string "rulebase" and logs a window there directly, regardless of overall
      // file size. This is what should finally show the real rule syntax so a
      // parser (brace-tree, if that's what this firmware genuinely always returns)
      // can be written against real evidence instead of another guess.
      const redacted = sshParser.redactConfig(output);
      const headPreview = redacted.slice(0, 8000);
      console.log(
        `[PaloAlto SSH Debug] Config via \`${RUNNING_CONFIG_COMMAND}\` (${output.length} chars, ` +
          `secrets redacted, format NOT confirmed). First 8000 chars:\n${headPreview}`
      );

      const rulebaseIdx = redacted.search(/rulebase/i);
      if (rulebaseIdx === -1) {
        console.log(
          '[PaloAlto SSH Debug] No "rulebase" substring found anywhere in the retrieved config -- ' +
            'the security rulebase may be under a different key on this firmware, or the dump was ' +
            'truncated before reaching it.'
        );
      } else {
        const windowStart = Math.max(0, rulebaseIdx - 200);
        const rulebasePreview = redacted.slice(windowStart, windowStart + 8000);
        console.log(
          `[PaloAlto SSH Debug] First "rulebase" match at char ${rulebaseIdx} of ${redacted.length}. ` +
            `Window from char ${windowStart}:\n${rulebasePreview}`
        );
      }
      loggedFirstConfig = true;
    }

    return this._configText;
  }

  // → { ok, latency_ms, message } — must NEVER throw.
  async testConnectivity() {
    const startedAt = Date.now();
    try {
      await this._getSystemInfo();
      return { ok: true, latency_ms: Date.now() - startedAt, message: 'Connected' };
    } catch (err) {
      return { ok: false, latency_ms: null, message: err.message };
    }
  }

  // → { version_string, version_tuple, build, model }
  async getVersion() {
    const info = await this._getSystemInfo();

    if (!info.version_string) {
      throw new Error(
        `PAN-OS version detection failed on device ${this.device.id}: \`${SYSTEM_INFO_COMMAND}\` ` +
          'produced output but no "sw-version:" line. Check the [PaloAlto SSH Debug] raw output ' +
          'and update lib/adapters/paloalto/sshParser.js for this firmware.'
      );
    }

    return {
      version_string: info.version_string,
      // parseVersion('paloalto', ...) handles the -h hotfix suffix: 11.1.2-h3 → [11,1,2,3].
      version_tuple: parseVersion('paloalto', info.version_string),
      build: info.build,
      model: info.model,
    };
  }

  // → NormalizedRule[]
  //
  // ⛔ NEVER return [] on a connection/credential/CLI failure — THROW.
  // collectAndStore() awaits getRules() and only then DELETEs every firewall_rules
  // row for this device before reinserting. A throw preserves the previously
  // collected ruleset and surfaces a clear error; [] silently wipes it, wipes the
  // Phase 5 findings that cascade from it, and reports rulesCount: 0 as if the
  // device genuinely had no rules. This exact bug was just fixed in the Sangfor
  // adapter — _getConfigText() above throws rather than returning empty text, which
  // is what makes this guarantee hold.
  //
  // [] is returned ONLY for the honest case: a real config was read and it contains
  // no security rules.
  async getRules() {
    let configText;
    try {
      configText = await this._getConfigText();
    } catch (err) {
      throw new Error(
        `PAN-OS rule collection failed — could not retrieve the running config over SSH: ${err.message}`
      );
    }

    const rules = sshParser.parseSecurityRules(configText);

    if (rules.length === 0) {
      // The device answered with a real config that simply has no rulebase this
      // parser recognizes. [] is honest here — but say so loudly, because the other
      // possibility is that this firmware's brace-tree shape differs from the one
      // sshParser.js's findSecurityRulesContainers() was built against (verified on
      // a PA-440 and a PA-3220, both PAN-OS 11.1.13-h5 — an older/newer release may
      // structure the tree differently).
      console.warn(
        `[PaloAlto SSH] Config retrieved for device ${this.device.id} but no security rules were ` +
          'parsed from it. Either the rulebase is genuinely empty, or this firmware structures ' +
          'the config tree differently — check the [PaloAlto SSH Debug] "rulebase" window and ' +
          'lib/adapters/paloalto/sshParser.js.'
      );
    }

    return rules;
  }

  // → { raw: string, parsed: object }
  async getConfig() {
    const configText = await this._getConfigText();

    // Best-effort: the config snapshot is still useful without system info, so a
    // failed info call is logged, not fatal (mirrors the XML adapter).
    let systemInfo = null;
    try {
      systemInfo = await this._getSystemInfo();
    } catch (err) {
      console.warn(
        `[PaloAlto SSH] Failed to fetch system info for config snapshot on device ${this.device.id}: ${err.message}`
      );
    }

    // ⛔ SECURITY — CLAUDE.md: "Any NEW adapter that returns a raw text config MUST
    // redact before returning it from getConfig()." A PAN-OS config carries phash
    // admin hashes, IKE pre-shared keys and SNMP communities. `raw` is persisted
    // verbatim into device_configs.config_raw, copied into config_backups, served by
    // the backup download route, and both tables are readable by the
    // claude_readonly / nocvault_readonly roles. NOTHING downstream redacts.
    //
    // Redact FIRST, then parse the REDACTED text into `parsed.tree` — parseConfig()
    // includes the full parsed tree for the Phase 6 predicate engine, so building it
    // from unredacted text would put live secrets in device_configs.config_parsed,
    // which is granted to the same readonly roles device_credentials is barred from.
    const redacted = sshParser.redactConfig(configText);
    return {
      raw: redacted,
      parsed: sshParser.parseConfig(redacted, systemInfo),
    };
  }
}

module.exports = { PaloaltoSshAdapter };
