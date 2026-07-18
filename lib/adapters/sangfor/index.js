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

// Version banner: Cisco-flavored first, Huawei-flavored fallback.
const VERSION_COMMANDS = ['show version', 'display version'];

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
}

module.exports = { SangforAdapter };
