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
      this._configText = attempt.output;
      this._configCommand = attempt.command;
      // First-connect verification aid: log a bounded preview, not the whole dump
      // (running configs can be tens of thousands of lines).
      const preview = attempt.output.slice(0, 2000);
      console.log(
        `[Sangfor Debug] Config via \`${attempt.command}\` (${attempt.output.length} chars). First 2000 chars:\n${preview}`
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

  // → NormalizedRule[] — degrades to [] (with a warning) rather than throwing:
  // Sangfor NGAF has no stable documented CLI for policy export, so zero extracted
  // rules is an expected outcome on some firmware lines, not an error.
  async getRules() {
    let configText = null;
    try {
      const result = await this._getConfigText();
      configText = result.text;
    } catch (err) {
      console.warn(`[Sangfor] Config retrieval for rule extraction failed: ${err.message}`);
      return [];
    }

    if (configText === null) {
      console.warn(
        '[Sangfor] No config output could be retrieved from any known command — rule extraction skipped.'
      );
      return [];
    }

    const rules = parser.parseRulesFromConfig(configText);

    if (rules.length === 0) {
      console.warn(
        '[Sangfor] No rules could be parsed from config — rule extraction for this vendor may require the NGAF web API or a newer firmware CLI; config snapshot is still collected.'
      );
      return [];
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

    return {
      raw: result.text,
      parsed: {
        source_command: result.command,
        line_count: result.text.split(/\r?\n/).length,
        sections: parser.parseConfigSections(result.text),
        collected_via: 'ssh',
      },
    };
  }
}

module.exports = { SangforAdapter };
