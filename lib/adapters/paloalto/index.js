// lib/adapters/paloalto/index.js
// CommonJS ONLY — required (via the adapter registry) by services/engine-worker.js
// (plain node, CommonJS).
//
// Palo Alto PAN-OS adapter — talks to the firewall's XML API on the management
// interface (https://<mgmt_ip>:<port>/api/, key auth via `key` query param).
//
// Two auth modes, both first-class (see parseApiCredential in ../credentials.js for
// the stored plaintext forms):
//   - api_key            → used directly.
//   - username+password  → exchanged for an API key via PAN-OS's own
//                          ?type=keygen endpoint, then used identically. This is
//                          NOT a shim: keygen is how PAN-OS itself issues keys.
//   - a bare non-JSON string → legacy raw API key (backward compat, still works).
//
// See CLAUDE.md — in particular the Pool Warning: testConnectivity() and any function
// touching credStore/DB must always receive and use `this.pool`, even though it looks
// like a pure connectivity check. Removing pool builds clean and breaks silently at
// runtime.

const { FirewallAdapter } = require('../interface');
const credStore = require('../../credStore');
const { parseApiCredential } = require('../credentials');
const api = require('./api');
const parser = require('./parser');
const { PaloaltoSshAdapter } = require('./ssh');
const { getLatestConfigParsed } = require('../../engines/applicability');
const { createSession, getMetrics, walkSubtree, closeSession, DEFAULT_TIMEOUT_MS } = require('../../snmpClient');
const { parseSnmpCredential } = require('../snmpCredential');

// Per CLAUDE.md "External API Integrations": log the raw response the first time we
// see one so parser.js field mappings can be verified against the live device
// (the MVP was built without a live PAN-OS firewall).
let loggedFirstSystemInfo = false;
let loggedFirstHitCount = false;
let loggedFirstSnmp = false;
let loggedFirstEffectivePolicy = false;

// --- SNMP monitoring (added 2026-07-21) ---------------------------------
// getSnmpMetrics() is a SEPARATE UDP protocol/connection from this file's
// XML-API management-plane transport — entirely independent credential
// (credential_type='snmp'), target host/port, and session. Identical logic
// is duplicated (not shared) in ./ssh.js's PaloaltoSshAdapter, per this
// codebase's established "duplicate small per-adapter logic" convention —
// SNMP doesn't care which management transport an adapter otherwise uses.
//
// PAN-OS has no single clean "CPU percent" scalar the way FortiOS does, so
// every OID below EXCEPT sysUpTime is doc-derived from public MIB
// references, not yet live-verified against a real PAN-OS device — see
// CLAUDE.md's SNMP Monitoring section. getSnmpMetrics() therefore ALWAYS
// sets lowConfidence: true for this vendor (explicit product direction for
// this round), independent of which individual OIDs happen to resolve.
//
// Sources consulted (2026-07-21):
//  - PAN-COMMON-MIB (Palo Alto's own enterprise MIB), cross-checked via
//    oidref.com and mibs.observium.org: the panSession subtree at
//    1.3.6.1.4.1.25461.2.1.2.3 has BOTH panSessionUtilization (.1, a 0-100
//    percentage) and panSessionActive (.3, a RAW active-session COUNT).
//    panSessionActive is used for sessionCount (a real count, not a
//    percentage misrepresented as one); panSessionUtilization is kept in
//    `raw` for reference only. A candidate `panSysResourceUtilization` OID
//    was checked directly against the real MIB listing and does NOT exist
//    in PAN-COMMON-MIB — dropped rather than guessed, so there is no
//    PAN-COMMON-MIB fallback for CPU; HOST-RESOURCES-MIB is the only path.
//  - Palo Alto's own knowledgebase ("SNMP for Monitoring Palo Alto Networks
//    Devices") and docs.paloaltonetworks.com's HOST-RESOURCES-MIB page:
//    hrProcessorLoad table (1.3.6.1.2.1.25.3.3.1.2) — one row per processor
//    (management plane + each dataplane core on multi-dp platforms), each
//    already a 0-100 load average over the last 60s — averaged across every
//    returned row for cpuPercent. hrStorageTable (1.3.6.1.2.1.25.2.3.1) for
//    memory — genuinely fiddly (no fixed row index for "the RAM row" across
//    platforms/firmware), matched by hrStorageDescr text; if no row matches,
//    memoryPercent is left null rather than guessed.
//  - Standard MIB-II sysUpTime.0 (1.3.6.1.2.1.1.3.0) for uptime — universal,
//    not Palo Alto-specific, no live verification needed.
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
// Matches the hrStorageDescr text of whichever row represents physical RAM
// — this varies by platform/firmware ("Physical Memory", "Real Memory",
// plain "Memory", ...), so this is intentionally a loose, case-insensitive
// pattern rather than an exact string match.
const MEMORY_DESCR_PATTERN = /physical memory|real memory|\bram\b|\bmemory\b/i;

// hrProcessorLoad rows are already 0-100 load-average values, one per
// processor — average them for a single fleet-comparable cpuPercent. No
// rows (table not implemented on this firmware/platform) → null, never 0.
function averageCpuFromProcessorLoadRows(rows) {
  const values = (rows || []).map((r) => Number(r.value)).filter((v) => Number.isFinite(v));
  if (values.length === 0) return null;
  const avg = values.reduce((a, b) => a + b, 0) / values.length;
  return Math.round(avg * 100) / 100;
}

// hrStorageTable is 4 parallel columns (Descr/AllocationUnits/Size/Used)
// sharing one row index — walkSubtree returns each column as its own flat
// list, so this reassembles a column into {rowIndex: value} keyed off the
// trailing OID segment (net-snmp's subtree walk returns full OIDs, and the
// row index is always the last segment for a scalar-per-row table).
function indexHrStorageColumn(rows) {
  const out = {};
  for (const { oid, value } of rows || []) {
    const idx = String(oid).split('.').pop();
    out[idx] = value;
  }
  return out;
}

// Walks the 4 hrStorageTable columns needed to compute a memory percentage,
// finds the row whose descr looks like physical RAM, and computes
// used/size as a percentage. Genuinely fiddly across platforms/firmware —
// returns memoryPercent: null (never a guess) when no row confidently
// matches or the matched row's numbers don't resolve cleanly.
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

  // allocUnits cancels out of the ratio (both size and used are in the same
  // unit), computed explicitly anyway to keep the real formula visible.
  const percent = ((used * allocUnits) / (size * allocUnits)) * 100;
  result.memoryPercent = Math.round(percent * 100) / 100;
  result.matchedDescr = descrs[memRowIndex];
  return result;
}

class PaloaltoAdapter extends FirewallAdapter {
  constructor({ device, pool }) {
    super({ device, pool });
    // Keygen result cache, for the LIFE OF THIS ADAPTER INSTANCE only.
    //
    // collectAndStore() builds one adapter per device per collect and then calls
    // getVersion/getRules/getConfig on it — each of which calls _getConn(). Without
    // this, a single collect would hit ?type=keygen four times, putting the
    // password on the wire four times over.
    //
    // NOT persisted, deliberately: credStore/device_credentials is the only
    // credential store in this app (CLAUDE.md Security). The key dies with the
    // instance; the next collect mints a fresh one.
    this._apiKey = null;
    this._apiKeyPromise = null;
  }

  // Resolves the API key for this device: returned as-is when one is stored, or
  // minted from username+password via PAN-OS keygen.
  //
  // The in-flight PROMISE is cached, not just the result — getVersion/getRules/
  // getConfig can overlap, and caching only the resolved value would still allow
  // concurrent callers to each fire their own keygen. A failure clears the cache so
  // the next attempt retries rather than replaying a stale rejection.
  async _resolveApiKey() {
    if (this._apiKey) return this._apiKey;
    if (this._apiKeyPromise) return this._apiKeyPromise;

    this._apiKeyPromise = (async () => {
      const plaintext = await credStore.getCredential(this.device.id, 'rest_api', this.pool);
      if (!plaintext) {
        throw new Error(
          `No PAN-OS API credential found for device ${this.device.id} — save credentials before connecting.`
        );
      }

      // Never surfaces the plaintext in its errors — see ../credentials.js.
      const { apiKey, username, password } = parseApiCredential(plaintext, 'PAN-OS device');

      if (apiKey) return apiKey;

      // username+password → keygen. api.generateApiKey() redacts the password from
      // every error string it can throw and never echoes the response body (which
      // contains the minted key). Nothing about the password is logged here either.
      return api.generateApiKey({
        host: this.device.mgmt_ip,
        port: this.device.mgmt_port || 443,
        username,
        password,
        allowSelfSignedSsl: this.device.allow_self_signed_ssl !== false,
      });
    })();

    try {
      this._apiKey = await this._apiKeyPromise;
      return this._apiKey;
    } catch (err) {
      this._apiKeyPromise = null;
      throw err;
    }
  }

  // Builds the PAN-OS connection descriptor, decrypting the stored credential via
  // credStore. Always uses this.pool — never omit it (CLAUDE.md Pool Warning).
  async _getConn() {
    const apiKey = await this._resolveApiKey();

    return {
      host: this.device.mgmt_ip,
      port: this.device.mgmt_port || 443,
      apiKey,
      allowSelfSignedSsl: this.device.allow_self_signed_ssl !== false,
    };
  }

  // → { ok: bool, latency_ms, message } — must never throw.
  async testConnectivity() {
    const startedAt = Date.now();
    try {
      const conn = await this._getConn();
      await api.showSystemInfo(conn);
      return { ok: true, latency_ms: Date.now() - startedAt, message: 'Connected' };
    } catch (err) {
      return { ok: false, latency_ms: null, message: err.message };
    }
  }

  // → { version_string, version_tuple, build, model }
  async getVersion() {
    const conn = await this._getConn();
    const systemInfoResult = await api.showSystemInfo(conn);

    if (!loggedFirstSystemInfo) {
      // First-connect verification aid: field names must be checked against the live
      // device before trusting parser.js mappings (CLAUDE.md: documentation lies).
      console.log(
        '[PaloAlto Debug] show system info result:',
        JSON.stringify(systemInfoResult, null, 2)
      );
      loggedFirstSystemInfo = true;
    }

    return parser.parseSystemInfo(systemInfoResult);
  }

  // → NormalizedRule[]
  async getRules() {
    const conn = await this._getConn();
    const rulesResult = await api.getSecurityRules(conn);
    const rules = parser.parseRules(rulesResult);
    if (rules.length > 0) {
      // Hit-count enrichment (ADDITIVE, best-effort — see _enrichHitCounts()).
      // Only reached on the primary path, where rules were already
      // successfully retrieved via the hardcoded api.DEFAULT_VSYS xpath —
      // safe to enrich against that SAME vsys name because it's the exact
      // one that produced these rules, not because device topology is
      // confirmed single-vsys (this path is taken whenever vsys1 alone
      // yields rules, even on an otherwise multi-vsys device — see the
      // any-vsys fallback comment below for why that's a separate, known,
      // pre-existing completeness gap this enrichment step doesn't change
      // either way). Runs AFTER the real ruleset is already built, so a
      // failure here can never affect what getRules() returns for the
      // rules themselves.
      await this._enrichHitCounts(conn, rules, api.DEFAULT_VSYS);
      return rules;
    }

    // Zero rules from the default single-vsys xpath is AMBIGUOUS: either the
    // rulebase really is empty, or this is a multi-vsys device whose rules live
    // under vsys2/vsys3/... — where the xpath resolves to nothing and PAN-OS
    // answers `<response status="success"><result/></response>`, which presents as
    // "this device has no rules" while collectAndStore DELETEs the real ruleset.
    //
    // So before accepting "no rules", look across every vsys. This runs ONLY when
    // the primary path already found nothing, so it cannot regress the working
    // single-vsys case — the cost of a genuinely empty rulebase is one extra
    // config-get that also returns nothing.
    let fallbackRules = [];
    try {
      const anyVsysResult = await api.getSecurityRulesAnyVsys(conn);
      fallbackRules = parser.parseRulesDeep(anyVsysResult);
    } catch (err) {
      // The primary call already succeeded, so the device is reachable — a failing
      // fallback probe is diagnostic noise, not a reason to fail the pull.
      console.warn(
        `[PaloAlto] Any-vsys rule fallback failed for device ${this.device.id}: ${err.message}`
      );
      return rules;
    }

    if (fallbackRules.length > 0) {
      console.warn(
        `[PaloAlto] Device ${this.device.id}: no rules at the default vsys ` +
          `(${api.DEFAULT_VSYS}) but ${fallbackRules.length} found across all vsys — this looks ` +
          'like a multi-vsys firewall. Rules from every vsys are being stored together; ' +
          'per-vsys separation would need a per-device vsys setting.'
      );
      // Hit-count enrichment intentionally SKIPPED here, not just best-effort
      // attempted-and-tolerated: parseRulesDeep() concatenates rules from
      // POTENTIALLY MULTIPLE vsys with no vsys tag retained per rule (see its
      // own comment — "Rule names are unique per vsys but NOT across vsys").
      // rule-hit-count is queried per named vsys; there is no single vsys
      // name to ask, and merging a per-vsys hit-count map back onto this
      // flattened list by rule_name alone risks attributing one vsys's count
      // to a DIFFERENT vsys's identically-named rule — a wrong hit_count is
      // worse than a missing one (same reasoning CLAUDE.md already applies
      // to getRules()'s "no ruleset is safer than the wrong one").
      console.warn(
        `[PaloAlto] Device ${this.device.id}: skipping rule hit-count enrichment for the ` +
          'any-vsys fallback result — rule names are not unique across vsys, so a per-vsys ' +
          'hit-count fetch could not be merged back without risking a wrong (not just missing) count.'
      );
      return fallbackRules;
    }

    // Neither the default-vsys nor the any-vsys xpath found anything — the
    // exact same "no rulebase found anywhere in the local config tree"
    // signal that triggers the SSH transport's Panorama-managed fallback
    // (sshParser.js: containersFound === 0). Before falling through to this
    // transport's existing (documented, known-limitation) silent-empty
    // return, try the merged/effective security policy — see
    // api.getEffectiveSecurityPolicy()/parser.parseEffectiveSecurityPolicy()
    // for the full rationale and the DOC-DERIVED, NOT YET LIVE-VERIFIED
    // caveat. Wrapped the same way the any-vsys fallback above is: the
    // primary call already succeeded, so a failing fallback probe here is
    // diagnostic noise, not a reason to fail the whole pull.
    let effectiveRules = null;
    try {
      const { raw: effectiveRaw, result: effectiveResult } = await api.getEffectiveSecurityPolicy(conn);
      if (!loggedFirstEffectivePolicy) {
        console.log(
          `[PaloAlto Debug] effective security-policy raw response (device ${this.device.id}):`,
          effectiveRaw.slice(0, 8000)
        );
        loggedFirstEffectivePolicy = true;
      }
      effectiveRules = parser.parseEffectiveSecurityPolicy(effectiveResult);
    } catch (err) {
      console.warn(
        `[PaloAlto] Effective security-policy fallback failed for device ${this.device.id}: ${err.message}`
      );
    }

    if (effectiveRules !== null) {
      console.log(
        `[PaloAlto] Device ${this.device.id}: no rulebase found via config-get (default or any ` +
          `vsys), but the effective/merged security policy returned ${effectiveRules.length} ` +
          'rule(s) — using it instead. This looks like a Panorama-managed device whose rules are ' +
          'pushed centrally rather than stored locally. ⚠️ This XML/API-transport parse path is ' +
          'DOC-DERIVED and NOT YET LIVE-VERIFIED (unlike the SSH transport\'s identical fallback) — ' +
          'check this result against the device\'s real ruleset and the ' +
          '[PaloAlto Debug] raw response above before trusting it. Known limitations even once ' +
          'verified (same as the SSH transport): no disabled-rule visibility, no real logging ' +
          'state, no hit counts, no NAT.'
      );
      return effectiveRules;
    }

    return rules;
  }

  // Fetches `show rule-hit-count` for one vsys and merges the resulting
  // ruleName → hitCount map into `rules` (matched by rule_name) IN PLACE.
  //
  // ADDITIVE, lower-stakes enrichment — deliberately a DIFFERENT failure
  // contract from getRules() itself. Per CLAUDE.md's getRules() rule ("must
  // THROW on a retrieval failure — never return []", because an empty
  // ruleset silently wipes the real one via collectAndStore's DELETE+
  // reinsert), a missing hit-count is NOT that kind of failure: every rule
  // simply keeps its existing default hit_count (0). Never throws.
  async _enrichHitCounts(conn, rules, vsysName) {
    try {
      const hitCountResult = await api.getRuleHitCount(conn, vsysName);

      if (!loggedFirstHitCount) {
        // First-connect verification aid, same convention as the system-info
        // debug log above — the response shape is doc-derived and unverified.
        console.log(
          '[PaloAlto Debug] rule-hit-count raw response:',
          JSON.stringify(hitCountResult, null, 2)
        );
        loggedFirstHitCount = true;
      }

      const hitCounts = parser.parseRuleHitCount(hitCountResult);
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
        `[PaloAlto] Rule hit-count fetch failed for device ${this.device.id} (vsys=${vsysName}) — ` +
          `hit_count left at 0 for all rules: ${err.message}`
      );
    }
  }

  // → { raw: string, parsed: object }
  // raw = the full `show config running` response XML string;
  // parsed = the config tree (rooted at the <config> element) with the parsed
  // `show system info` result merged in under parsed.system_info — this structure
  // feeds the Phase 6 dot-path predicate engine.
  async getConfig() {
    const conn = await this._getConn();
    const { raw, result: configResult } = await api.showRunningConfig(conn);

    // Best-effort: the config snapshot is still useful without system info, so a
    // failed info call is logged, not fatal.
    let systemInfoResult = null;
    try {
      systemInfoResult = await api.showSystemInfo(conn);
    } catch (err) {
      console.warn(
        `[PaloAlto] Failed to fetch system info for config snapshot on device ${this.device.id}: ${err.message}`
      );
    }

    // ⛔ SECURITY — CLAUDE.md: "Any NEW adapter that returns a raw text config MUST
    // redact before returning it from getConfig()." Found missing entirely in a
    // full-app audit (2026-07-16) — this transport is Palo Alto's DEFAULT
    // mgmt_method, so every Palo Alto device added the default way had its full
    // config (phash hashes, IKE pre-shared keys, SNMPv3 secrets) stored verbatim.
    // Both `raw` (the XML string) and the object tree feeding `parsed` are
    // redacted — device_configs/config_backups are GRANT SELECT'd to
    // claude_readonly/nocvault_readonly, the same roles device_credentials is
    // barred from. Nothing downstream redacts.
    const redactedRaw = parser.redactConfigXml(raw);
    const redactedConfigResult = parser.redactConfigTree(configResult);

    return {
      raw: redactedRaw,
      parsed: parser.parseConfig(redactedConfigResult, systemInfoResult),
    };
  }

  // OPTIONAL — FirewallAdapter's getObjects() (see interface.js for the exact
  // contract). Deliberately does NOT make a new device call: by the time
  // collectAndStore() reaches this step, THIS pull's device_configs.config_parsed
  // row (built by getConfig() above) is already committed — and the XML/API
  // transport's parseConfig() already spreads the ENTIRE PAN-OS config tree at
  // the top level, which contains every address/address-group/service/
  // service-group definition. Reading it back via getLatestConfigParsed() is
  // cheaper and avoids a redundant live pull. Never throws — an unreadable or
  // missing config degrades to all-empty arrays, same as parser.extractObjects()'s
  // own no-tree case.
  async getObjects() {
    const configParsed = await getLatestConfigParsed(this.device.id, this.pool);
    if (!configParsed || typeof configParsed !== 'object') {
      return { addresses: [], addressGroups: [], services: [], serviceGroups: [] };
    }
    return parser.extractObjects(configParsed);
  }

  // OPTIONAL — FirewallAdapter's getSnmpMetrics() (see interface.js for the
  // exact contract). SNMP is a completely separate UDP protocol/connection
  // from the XML API used everywhere else in this file — its own
  // credential (credential_type='snmp'), its own session, never gated on
  // or mixed with _getConn()/_resolveApiKey() above.
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
        console.log('[PaloAlto SNMP Debug] raw SNMP metric response:', JSON.stringify(raw, null, 2));
        loggedFirstSnmp = true;
      }

      return {
        cpuPercent,
        memoryPercent,
        sessionCount,
        uptimeSeconds,
        raw,
        // REQUIRED for Palo Alto regardless of which OIDs resolved — see
        // this method's own header comment above the class.
        lowConfidence: true,
        targetHost,
      };
    } finally {
      closeSession(session);
    }
  }
}

// PaloaltoSshAdapter is re-exported here (not defined here) so the registry's
// `const { PaloaltoAdapter, PaloaltoSshAdapter } = require('./paloalto');` resolves.
// Both names are load-bearing — lib/adapters/index.js destructures them at require
// time, so a rename breaks the app on startup, not at first use.
module.exports = { PaloaltoAdapter, PaloaltoSshAdapter };
