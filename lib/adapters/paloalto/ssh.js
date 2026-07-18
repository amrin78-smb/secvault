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
const { getLatestConfigParsed } = require('../../engines/applicability');

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
let loggedFirstHitCount = false;

// Builds the CLI command for `show rule-hit-count vsys <vsys-name> ...`.
// See sshParser.js's parseRuleHitCountOutput() for the output-shape caveat —
// doc-derived, not yet live-verified.
function buildRuleHitCountCommand(vsysName) {
  return `show rule-hit-count vsys ${vsysName} rule-base security rules all`;
}

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

  // → { version_string, version_tuple, build, model, serial }
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
      // ⛔ Bug fixed 2026-07-19: parseSystemInfo() (sshParser.js) already
      // parses `serial` — it was simply never included in this return
      // object, so a real, already-collected value was thrown away before
      // it ever reached collectAndStore()'s INSERT.
      serial: info.serial || null,
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

    const { rules, containersFound } = sshParser.parseSecurityRules(configText);

    if (containersFound === 0) {
      // No `rulebase.security.rules` container was found ANYWHERE in the parsed
      // tree — this is a structural retrieval failure (wrong firmware shape, or
      // a truncated/corrupted parse), not an honest empty ruleset. Per CLAUDE.md
      // ("getRules() must THROW on a retrieval failure — never return []"),
      // collectAndStore() DELETEs the device's stored firewall_rules before
      // reinserting whatever getRules() returns — silently returning [] here
      // would wipe a real, previously-collected ruleset. Throw instead.
      throw new Error(
        `PAN-OS rule collection failed on device ${this.device.id}: no ` +
          '`rulebase.security.rules` container was found anywhere in the parsed config tree. ' +
          'Either this firmware structures the config tree differently, or the retrieved config ' +
          'was truncated/corrupted before reaching the rulebase — check the [PaloAlto SSH Debug] ' +
          '"rulebase" window and lib/adapters/paloalto/sshParser.js. Refusing to overwrite the ' +
          'existing stored ruleset with an empty result.'
      );
    }

    if (rules.length === 0) {
      // A container WAS found (containersFound > 0) but it genuinely contains
      // zero rules — an honest [], not a failure. Say so loudly anyway, since
      // an empty rulebase is unusual on a device in production use.
      console.warn(
        `[PaloAlto SSH] Config retrieved for device ${this.device.id}: ${containersFound} ` +
          'rulebase container(s) found, but no security rules were parsed from ' +
          `${containersFound === 1 ? 'it' : 'them'}. The rulebase appears to be genuinely empty.`
      );
    } else {
      // Hit-count enrichment (ADDITIVE, best-effort) — runs AFTER the real
      // ruleset is already built, so any failure here can never affect what
      // getRules() returns for the rules themselves. See _enrichHitCounts()'s
      // own header comment for the full failure contract.
      try {
        const tree = sshParser.parseBraceConfig(configText);
        await this._enrichHitCounts(tree, rules);
      } catch (err) {
        console.warn(
          `[PaloAlto SSH] Hit-count enrichment failed unexpectedly for device ${this.device.id} — ` +
            `hit_count left at 0 for all rules: ${err.message}`
        );
      }
    }

    return rules;
  }

  // Fetches `show rule-hit-count` and merges the resulting ruleName →
  // hitCount map into `rules` (matched by rule_name) IN PLACE.
  //
  // ADDITIVE, lower-stakes enrichment — deliberately a DIFFERENT failure
  // contract from getRules() itself, same distinction the XML/API transport's
  // sibling method (index.js's _enrichHitCounts) makes. Per CLAUDE.md's
  // getRules() rule ("must THROW on a retrieval failure — never return []"),
  // a missing hit-count is NOT that kind of failure: every rule simply keeps
  // its existing default hit_count (0). Never throws.
  async _enrichHitCounts(configTree, rules) {
    const vsysNames = sshParser.resolveVsysNames(configTree);

    if (vsysNames.length > 1) {
      // Multiple named vsys found in the parsed tree. Rule names are unique
      // PER vsys, not globally (see findSecurityRulesContainers()'s own
      // comment above, and the identical caveat on the XML/API transport's
      // any-vsys fallback) — merging hit counts from more than one vsys by
      // rule name alone risks attributing one vsys's count to a DIFFERENT
      // vsys's identically-named rule. Left at the default 0 for every rule
      // rather than risk a WRONG (not just missing) hit count — same
      // conservative call the XML/API transport makes for its own
      // multi-vsys case.
      console.warn(
        `[PaloAlto SSH] Device ${this.device.id}: ${vsysNames.length} vsys found ` +
          `(${vsysNames.join(', ')}) — skipping rule hit-count enrichment to avoid ` +
          'cross-vsys rule-name collisions. hit_count left at 0 for all rules.'
      );
      return;
    }

    const vsysName = vsysNames[0];
    try {
      const command = buildRuleHitCountCommand(vsysName);
      const results = await this._run([command]);
      const output = results[0] ? results[0].output : '';

      if (!loggedFirstHitCount) {
        // First-connect verification aid, same convention as the system-info/
        // config debug logs above — the output shape is doc-derived and
        // unverified. `show rule-hit-count` output carries rule names and hit
        // counts only, no secrets — safe to log unredacted.
        console.log(`[PaloAlto SSH Debug] rule-hit-count raw output (vsys=${vsysName}):\n${output}`);
        loggedFirstHitCount = true;
      }

      if (sshParser.looksLikeCliError(output)) {
        console.warn(
          `[PaloAlto SSH] \`${command}\` was rejected on device ${this.device.id} — ` +
            'hit_count left at 0 for all rules.'
        );
        return;
      }

      const hitCounts = sshParser.parseRuleHitCountOutput(output);
      for (const rule of rules) {
        if (!rule.rule_name) continue;
        if (!Object.prototype.hasOwnProperty.call(hitCounts, rule.rule_name)) continue;
        const hc = Number(hitCounts[rule.rule_name]);
        if (Number.isFinite(hc)) rule.hit_count = hc;
      }
    } catch (err) {
      // Never throws, never blocks/alters the already-built rule list — see
      // this method's own header comment. Every rule simply keeps hit_count
      // at its prior default (0).
      console.warn(
        `[PaloAlto SSH] Rule hit-count fetch failed for device ${this.device.id} (vsys=${vsysName}) — ` +
          `hit_count left at 0 for all rules: ${err.message}`
      );
    }
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

  // OPTIONAL — FirewallAdapter's getObjects() (see interface.js for the exact
  // contract). Deliberately does NOT open a new SSH session: by the time
  // collectAndStore() reaches this step, THIS pull's device_configs.config_parsed
  // row (built by getConfig() above, sshParser.parseConfig()'s `.tree`) is
  // already committed, and that tree already contains every address/
  // address-group/service/service-group definition — the same full-config-tree
  // dump getRules() parses for the rulebase. Reading it back via
  // getLatestConfigParsed() avoids a second multi-MB `show` over SSH. Never
  // throws — a missing/unreadable config degrades to all-empty arrays, same as
  // sshParser.extractObjects()'s own no-tree case.
  async getObjects() {
    const configParsed = await getLatestConfigParsed(this.device.id, this.pool);
    if (!configParsed || typeof configParsed !== 'object') {
      return { addresses: [], addressGroups: [], services: [], serviceGroups: [] };
    }
    const tree =
      configParsed.tree && typeof configParsed.tree === 'object' ? configParsed.tree : configParsed;
    return sshParser.extractObjects(tree);
  }
}

module.exports = { PaloaltoSshAdapter };
