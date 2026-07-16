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

// ASA prompts: "hostname>" (user EXEC) / "hostname#" (privileged EXEC).
// NO `m` flag — see the DEFAULT_PROMPT_REGEX comment in ../sshClient.js. With
// `m`, `banner motd ####` (# is ASA's conventional banner delimiter) matches
// mid-config and silently truncates `show running-config`.
const ASA_PROMPT_REGEX = /[>#]\s*$/;

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
}

module.exports = { CiscoAsaAdapter };
