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
const { createSession, getMetrics, walkSubtree, closeSession, DEFAULT_TIMEOUT_MS } = require('../../snmpClient');
const { parseSnmpCredential } = require('../snmpCredential');

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

// Debug-only helper (never used for real parsing — sshParser.js owns that):
// lists distinct `key {` block openers found at brace-nesting depth <= maxDepth,
// in first-seen order, as a lightweight "table of contents" for a config dump
// that didn't contain an expected keyword anywhere. Deliberately naive (a plain
// depth counter over `{`/`}`, no awareness of quoted-string values that might
// themselves contain a brace character) — good enough to answer "what shallow
// sections exist in this dump", not meant to be a real tokenizer. See the
// 2026-07-23 "No rulebase substring found" case in _getConfigText() below for
// why this exists: guessing a further keyword blind would repeat this file's
// own documented history of costly wrong guesses.
function extractShallowBlockKeys(text, maxDepth = 3) {
  const keys = [];
  const seen = new Set();
  let depth = 0;
  const re = /([A-Za-z0-9_-]+)\s*\{|\}/g;
  let match;
  while ((match = re.exec(text)) !== null) {
    if (match[0] === '}') {
      depth = Math.max(0, depth - 1);
      continue;
    }
    if (depth <= maxDepth) {
      const label = `${'  '.repeat(depth)}${match[1]}`;
      if (!seen.has(label)) {
        seen.add(label);
        keys.push(label);
      }
    }
    depth += 1;
  }
  return keys;
}

// A full config dump over a WAN is slow — the shared client's 20s default is a
// version-command budget, not a config-dump budget.
const CONFIG_COMMAND_TIMEOUT_MS = 120000;

let loggedFirstSystemInfo = false;
let loggedFirstConfig = false;
let loggedFirstHitCount = false;
let loggedFirstSnmp = false;
let loggedFirstEffectivePolicy = false;

// Operational-mode command for the Panorama-managed fallback — see
// sshParser.js's "Effective/running security policy" section for the full
// rationale. Deliberately NOT run through `configure`/set-format like
// RUNNING_CONFIG_COMMAND above — this is a plain `show` command, confirmed
// live to work directly after login with no mode switch.
const EFFECTIVE_POLICY_COMMAND = 'show running security-policy';

// Builds the CLI command for `show rule-hit-count vsys <vsys-name> ...`.
// See sshParser.js's parseRuleHitCountOutput() for the output-shape caveat —
// doc-derived, not yet live-verified.
function buildRuleHitCountCommand(vsysName) {
  return `show rule-hit-count vsys ${vsysName} rule-base security rules all`;
}

// --- SNMP monitoring (added 2026-07-21) ---------------------------------
// getSnmpMetrics() is a SEPARATE UDP protocol/connection from this file's
// SSH/CLI management-plane transport — entirely independent credential
// (credential_type='snmp'), target host/port, and session. IDENTICAL logic
// to ./index.js's PaloaltoAdapter.getSnmpMetrics() — duplicated rather than
// shared, per this codebase's established "duplicate small per-adapter
// logic rather than extract a mixin" convention (SNMP doesn't care which
// management transport an adapter otherwise uses). See index.js's own copy
// of this comment block for the full source citations behind the OIDs below
// (PAN-COMMON-MIB's panSession subtree via oidref.com/mibs.observium.org,
// Palo Alto's own SNMP knowledgebase article + docs.paloaltonetworks.com's
// HOST-RESOURCES-MIB page, and standard MIB-II sysUpTime) — not re-quoted
// here to avoid the two copies drifting out of step with different prose
// while still agreeing on values; if the OIDs ever change, update both
// files' comment blocks together.
//
// PAN-OS has no single clean "CPU percent" scalar, so every OID below
// except sysUpTime is doc-derived and unverified against a real device —
// getSnmpMetrics() therefore ALWAYS sets lowConfidence: true for this
// vendor (explicit product direction for this round).
const SNMP_SCALAR_OIDS = {
  sysUpTime: '1.3.6.1.2.1.1.3.0',
  panSessionUtilization: '1.3.6.1.4.1.25461.2.1.2.3.1.0',
  panSessionActive: '1.3.6.1.4.1.25461.2.1.2.3.3.0',
};
const HR_PROCESSOR_LOAD_BASE_OID = '1.3.6.1.2.1.25.3.3.1.2';
const HR_STORAGE_DESCR_BASE_OID = '1.3.6.1.2.1.25.2.3.1.3';
const HR_STORAGE_ALLOC_UNITS_BASE_OID = '1.3.6.1.2.1.25.2.3.1.4';
const HR_STORAGE_SIZE_BASE_OID = '1.3.6.1.2.1.25.2.3.1.5';
const HR_STORAGE_USED_BASE_OID = '1.3.6.1.2.1.25.2.3.1.6';
const MEMORY_DESCR_PATTERN = /physical memory|real memory|\bram\b|\bmemory\b/i;

function averageCpuFromProcessorLoadRows(rows) {
  const values = (rows || []).map((r) => Number(r.value)).filter((v) => Number.isFinite(v));
  if (values.length === 0) return null;
  const avg = values.reduce((a, b) => a + b, 0) / values.length;
  return Math.round(avg * 100) / 100;
}

function indexHrStorageColumn(rows) {
  const out = {};
  for (const { oid, value } of rows || []) {
    const idx = String(oid).split('.').pop();
    out[idx] = value;
  }
  return out;
}

async function computeMemoryPercentFromHrStorage(session, timeoutMs, host) {
  const [descrRows, allocRows, sizeRows, usedRows] = await Promise.all([
    walkSubtree(session, HR_STORAGE_DESCR_BASE_OID, timeoutMs, host),
    walkSubtree(session, HR_STORAGE_ALLOC_UNITS_BASE_OID, timeoutMs, host),
    walkSubtree(session, HR_STORAGE_SIZE_BASE_OID, timeoutMs, host),
    walkSubtree(session, HR_STORAGE_USED_BASE_OID, timeoutMs, host),
  ]);
  const descrs = indexHrStorageColumn(descrRows);
  const allocs = indexHrStorageColumn(allocRows);
  const sizes = indexHrStorageColumn(sizeRows);
  const useds = indexHrStorageColumn(usedRows);

  let memRowIndex = null;
  for (const idx of Object.keys(descrs)) {
    if (MEMORY_DESCR_PATTERN.test(String(descrs[idx] || ''))) {
      memRowIndex = idx;
      break;
    }
  }

  const result = { rows: descrs, matchedRowIndex: memRowIndex, memoryPercent: null };
  if (memRowIndex === null) return result;

  const allocUnits = Number(allocs[memRowIndex]) || 1;
  const size = Number(sizes[memRowIndex]);
  const used = Number(useds[memRowIndex]);
  if (!Number.isFinite(size) || size <= 0 || !Number.isFinite(used)) return result;

  const percent = ((used * allocUnits) / (size * allocUnits)) * 100;
  result.memoryPercent = Math.round(percent * 100) / 100;
  result.matchedDescr = descrs[memRowIndex];
  return result;
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
        // ⛔ Live case found 2026-07-23: a real Panorama-managed device returned a
        // genuine, large (600KB+) config dump with NEITHER "rulebase" NOR
        // "pre-rulebase"/"post-rulebase" anywhere in it (that regex is already
        // substring-inclusive of both) -- ruling out the usual PAN-OS naming
        // pattern entirely, not just a wrong nesting depth. Guessing a fourth
        // keyword blind would repeat the exact mistake this file's own history
        // already warns against. Instead of guessing, list every shallow
        // (depth <= 3) brace-block key name actually present -- a real
        // "table of contents" of this device's config, so the next person can
        // SEE whether there's a policy-shaped hole (e.g. a restricted admin
        // role's Policy permission being off, plausible specifically on a
        // Panorama-managed device where policy is meant to be centrally owned)
        // instead of pattern-matching one string at a time.
        console.log(
          '[PaloAlto SSH Debug] No "rulebase" (or pre-/post-rulebase) substring found anywhere in ' +
            'the retrieved config -- the security rulebase may be under a key this codebase has ' +
            'never seen, the account may lack permission to see policy at all (plausible on a ' +
            'Panorama-managed device with a restricted local admin role), or the dump was truncated ' +
            `before reaching it. Shallow block keys actually present:\n${extractShallowBlockKeys(redacted).join('\n')}`
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
      // Same class of gap, fixed 2026-07-23: parseSystemInfoOutput() already
      // parses `hostname` (live-confirmed field name, see CLAUDE.md's Live
      // Validation Status) — it was likewise never included here.
      hostname: info.hostname || null,
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

    const { rules, containersFound, tree } = sshParser.parseSecurityRules(configText);

    // ⛔ Fixed 2026-07-23: this used to gate the Panorama-managed fallback on
    // `containersFound === 0` alone, which is NOT the same trigger point as
    // the XML/API transport's parallel fallback (index.js), despite this
    // file's own history and CLAUDE.md claiming they were identical. A
    // Panorama-managed device's local config can have an explicit but EMPTY
    // container (e.g. `pre-rulebase { security { rules { } } nat { ... } } }`)
    // — findSecurityRulesContainers() correctly counts that as a found
    // container (containersFound === 1) with zero parsed rules. The old code
    // took the `containersFound === 0` branch's false path in that shape, so
    // the fallback was never attempted, and fell into the "genuinely empty"
    // log below, returning [] without throwing — collectAndStore() then
    // silently wipes the device's real firewall_rules, exactly the class of
    // bug this file's history already fixed once. The fallback must trigger
    // whenever rules.length === 0, matching the XML/API transport's condition
    // exactly. `containersFound` is now used ONLY to choose the wording of
    // the final throw vs. the "genuinely empty" log below, never to gate
    // whether the fallback is attempted.
    if (rules.length === 0) {
      // No security rules were parsed — either because no
      // `rulebase.security.rules` container was found ANYWHERE in the parsed
      // tree, or because a container WAS found but is itself empty (both
      // shapes are plausible on a Panorama-managed device — see below).
      // Before treating this as a structural retrieval failure or an honest
      // empty ruleset, try the Panorama-managed fallback — see sshParser.js's
      // "Effective/running security policy" section for the full rationale,
      // and CLAUDE.md's Palo Alto SSH notes for the real device that
      // surfaced this: a wholly Panorama-managed device's local config tree
      // genuinely has no (or an empty) rulebase.security.rules content,
      // because every rule is Panorama-pushed and only appears in the
      // MERGED effective policy, not the local config. `show running
      // security-policy` is a completely different command/format and needs
      // no `configure`/set-format step.
      let effectiveRules = null;
      try {
        effectiveRules = await this._getEffectivePolicyRules();
      } catch (err) {
        console.warn(
          `[PaloAlto SSH] Panorama-managed fallback (\`${EFFECTIVE_POLICY_COMMAND}\`) also failed ` +
            `for device ${this.device.id}: ${err.message}`
        );
      }

      if (effectiveRules !== null) {
        console.log(
          `[PaloAlto SSH] Device ${this.device.id}: no security rules found in the local config tree, ` +
            `but \`${EFFECTIVE_POLICY_COMMAND}\` returned ${effectiveRules.length} rule(s) — using the ` +
            'merged effective policy instead. See sshParser.js\'s "Effective/running security policy" ' +
            'section for what this collection path can and cannot capture (no disabled-rule visibility, ' +
            'no log-state, no hit counts, no NAT).'
        );
        return effectiveRules;
      }

      if (containersFound === 0) {
        // No `rulebase.security.rules` container was found ANYWHERE in the
        // parsed tree — this is a structural retrieval failure (wrong
        // firmware shape, or a truncated/corrupted parse), not an honest
        // empty ruleset. Per CLAUDE.md ("getRules() must THROW on a
        // retrieval failure — never return []"), collectAndStore() DELETEs
        // the device's stored firewall_rules before reinserting whatever
        // getRules() returns — silently returning [] here would wipe a real,
        // previously-collected ruleset. Throw instead.
        throw new Error(
          `PAN-OS rule collection failed on device ${this.device.id}: no ` +
            '`rulebase.security.rules` container was found anywhere in the parsed config tree, and the ' +
            `Panorama-managed fallback (\`${EFFECTIVE_POLICY_COMMAND}\`) did not return a usable result ` +
            'either. Either this firmware structures the config tree differently, or the retrieved config ' +
            'was truncated/corrupted before reaching the rulebase — check the [PaloAlto SSH Debug] ' +
            '"rulebase" window and lib/adapters/paloalto/sshParser.js. Refusing to overwrite the ' +
            'existing stored ruleset with an empty result.'
        );
      }

      // A container WAS found (containersFound > 0) but it genuinely contains
      // zero rules, and the Panorama fallback didn't produce anything usable
      // either — an honest [], not a failure. Say so loudly anyway, since an
      // empty rulebase is unusual on a device in production use.
      console.warn(
        `[PaloAlto SSH] Config retrieved for device ${this.device.id}: ${containersFound} ` +
          'rulebase container(s) found, but no security rules were parsed from ' +
          `${containersFound === 1 ? 'it' : 'them'}. The rulebase appears to be genuinely empty.`
      );
      return rules;
    }

    // Hit-count enrichment (ADDITIVE, best-effort) — runs AFTER the real
    // ruleset is already built, so any failure here can never affect what
    // getRules() returns for the rules themselves. See _enrichHitCounts()'s
    // own header comment for the full failure contract. Reuses the `tree`
    // parseSecurityRules() already built above rather than re-parsing the
    // same config text a second time.
    try {
      await this._enrichHitCounts(tree, rules, containersFound);
    } catch (err) {
      console.warn(
        `[PaloAlto SSH] Hit-count enrichment failed unexpectedly for device ${this.device.id} — ` +
          `hit_count left at 0 for all rules: ${err.message}`
      );
    }

    return rules;
  }

  // Panorama-managed fallback — see sshParser.js's "Effective/running
  // security policy" section for the full rationale. Runs a SEPARATE plain
  // operational command (no `configure`/set-format) and parses its own
  // distinct format. Returns `null` (never throws past this method's own
  // boundary) when the command fails, looks like a CLI error, or doesn't
  // look like the expected format — the caller (getRules()) treats `null`
  // as "fallback not usable" and falls through to its existing throw,
  // exactly the same "no ruleset is safer than a wrong one" posture as
  // every other retrieval path in this file. Returns [] (not null) only for
  // the honest case: the command succeeded and looked right, but genuinely
  // contained zero rule blocks.
  async _getEffectivePolicyRules() {
    let results;
    try {
      results = await this._run([EFFECTIVE_POLICY_COMMAND]);
    } catch (err) {
      console.warn(
        `[PaloAlto SSH] \`${EFFECTIVE_POLICY_COMMAND}\` failed for device ${this.device.id}: ${err.message}`
      );
      return null;
    }
    const output = results[0] ? results[0].output : '';

    if (sshParser.looksLikeCliError(output)) {
      console.warn(
        `[PaloAlto SSH] \`${EFFECTIVE_POLICY_COMMAND}\` was rejected for device ${this.device.id} — ` +
          'the account may lack operational-command access to this command specifically.'
      );
      return null;
    }

    if (!loggedFirstEffectivePolicy) {
      // No redaction needed — security-policy rules (zones/addresses/actions)
      // never carry secrets, same reasoning already applied to the brace-tree
      // rule text elsewhere in this file.
      console.log(`[PaloAlto SSH Debug] \`${EFFECTIVE_POLICY_COMMAND}\` raw output:\n${output}`);
      loggedFirstEffectivePolicy = true;
    }

    if (!sshParser.looksLikeEffectiveSecurityPolicy(output)) {
      console.warn(
        `[PaloAlto SSH] \`${EFFECTIVE_POLICY_COMMAND}\` output for device ${this.device.id} did not ` +
          'match the expected format — check the [PaloAlto SSH Debug] raw output above.'
      );
      return null;
    }

    return sshParser.parseEffectiveSecurityPolicy(output);
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
  async _enrichHitCounts(configTree, rules, containersFound) {
    // ⛔ Found 2026-07-18 in an adversarial review: resolveVsysNames()'s own
    // tree walk (below) is LESS shape-tolerant than findSecurityRulesContainers()
    // (the deep, shape-agnostic search parseSecurityRules() itself trusts to
    // decide single-vs-multi-vsys) — it only recognizes one exact
    // `vsys { <name>: {...} }` wrapper shape. On a genuinely multi-vsys
    // device whose real wrapper doesn't match that one shape,
    // resolveVsysNames() would silently fall back to `['vsys1']` as if that
    // were CONFIRMED single-vsys, and this method would then merge vsys1's
    // hit counts onto same-named rules that were actually collected from a
    // DIFFERENT vsys container — exactly the cross-vsys corruption this
    // whole enrichment step exists to avoid. Gating on `containersFound`
    // FIRST closes that gap: it's the same signal getRules() itself already
    // uses to decide whether the ruleset is unambiguous, so "exactly one
    // container" here is at least as trustworthy as anything vsys-name
    // detection could independently conclude. Only when containersFound
    // is unambiguously 1 do we even attempt to resolve a vsys name for the
    // hit-count command.
    if (containersFound !== 1) {
      console.warn(
        `[PaloAlto SSH] Device ${this.device.id}: ${containersFound} rulebase container(s) found — ` +
          'skipping rule hit-count enrichment unless exactly one unambiguous container exists. ' +
          'hit_count left at 0 for all rules.'
      );
      return;
    }

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

  // OPTIONAL — FirewallAdapter's getSnmpMetrics() (see interface.js for the
  // exact contract). SNMP is a completely separate UDP protocol/connection
  // from the SSH/CLI transport used everywhere else in this file — its own
  // credential (credential_type='snmp'), its own session, never gated on
  // or mixed with _getSession()/_run() above. Identical logic to
  // ./index.js's PaloaltoAdapter.getSnmpMetrics() — see this file's own
  // "SNMP monitoring" comment block above for the OID sourcing.
  async getSnmpMetrics() {
    const targetHost = this.device.snmp_host || this.device.mgmt_ip;
    if (!targetHost) {
      throw new Error(
        `No SNMP target host resolvable for device ${this.device.id} — set snmp_host or mgmt_ip.`
      );
    }
    const targetPort = this.device.snmp_port || 161;

    const plaintext = await credStore.getCredential(this.device.id, 'snmp', this.pool);
    if (!plaintext) {
      throw new Error(
        `No SNMP credential stored for device ${this.device.id} — configure one under the device SNMP tab.`
      );
    }
    // parseSnmpCredential's errors are secret-free — see snmpCredential.js.
    const credential = parseSnmpCredential(plaintext);

    const timeoutMs = DEFAULT_TIMEOUT_MS;
    const session = createSession(credential, targetHost, targetPort, timeoutMs);
    try {
      const raw = {};

      const scalars = await getMetrics(session, SNMP_SCALAR_OIDS, timeoutMs, targetHost);
      raw.scalars = scalars;

      let uptimeSeconds = null;
      if (scalars.sysUpTime !== null && scalars.sysUpTime !== undefined) {
        const ticks = Number(scalars.sysUpTime);
        // sysUpTime is TimeTicks — hundredths of a second.
        if (Number.isFinite(ticks)) uptimeSeconds = Math.round(ticks / 100);
      }

      let sessionCount = null;
      if (scalars.panSessionActive !== null && scalars.panSessionActive !== undefined) {
        const n = Number(scalars.panSessionActive);
        if (Number.isFinite(n)) sessionCount = n;
      }

      let cpuPercent = null;
      try {
        const cpuRows = await walkSubtree(session, HR_PROCESSOR_LOAD_BASE_OID, timeoutMs, targetHost);
        raw.hrProcessorLoad = cpuRows;
        cpuPercent = averageCpuFromProcessorLoadRows(cpuRows);
      } catch (err) {
        raw.hrProcessorLoadError = err.message;
      }

      let memoryPercent = null;
      try {
        const memResult = await computeMemoryPercentFromHrStorage(session, timeoutMs, targetHost);
        raw.hrStorage = memResult;
        memoryPercent = memResult.memoryPercent;
      } catch (err) {
        raw.hrStorageError = err.message;
      }

      if (!loggedFirstSnmp) {
        // First-connect verification aid, same convention as this file's
        // other loggedFirst* debug logs — every OID here except sysUpTime
        // is doc-derived and unverified against a real device.
        console.log('[PaloAlto SSH SNMP Debug] raw SNMP metric response:', JSON.stringify(raw, null, 2));
        loggedFirstSnmp = true;
      }

      return {
        cpuPercent,
        memoryPercent,
        sessionCount,
        uptimeSeconds,
        raw,
        // REQUIRED for Palo Alto regardless of which OIDs resolved — see
        // this file's "SNMP monitoring" comment block above.
        lowConfidence: true,
        targetHost,
      };
    } finally {
      closeSession(session);
    }
  }
}

module.exports = { PaloaltoSshAdapter };
