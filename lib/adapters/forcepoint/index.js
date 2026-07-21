// lib/adapters/forcepoint/index.js
// CommonJS ONLY — required (via lib/adapters/index.js) by services/engine-worker.js
// under plain node.
//
// This module implements ONLY the FirewallAdapter interface. The shared collect
// pipeline (device_versions / firewall_rules / device_configs persistence plus
// the Phase 5/6 hooks) lives in lib/adapters/index.js — do not add storage
// logic here.
//
// See CLAUDE.md "Forcepoint SMC Integration" — in particular the Pool Warning:
// testConnectivity() and any function touching credStore/DB must always receive and
// use the `pool` parameter, even though it looks like a pure connectivity check.

const { FirewallAdapter } = require('../interface');
const credStore = require('../../credStore');
const smc = require('./smc');
const parser = require('./parser');
const { parseSnmpCredential } = require('../snmpCredential');
const { createSession, getMetrics, walkSubtree, closeSession } = require('../../snmpClient');

// SNMP OIDs for getSnmpMetrics() — a DELIBERATE, explicitly-approved exception
// to this file's own "never SSH/never talk to the engine directly, only the
// SMC" rule (see CLAUDE.md's "SNMP Monitoring" section): Forcepoint NGFW SNMP
// agents run per-engine, not on the SMC, so this one method polls
// this.device.snmp_host directly. Every OTHER method in this file
// (testConnectivity/getVersion/getRules/getConfig/getObjects) is completely
// untouched and still goes exclusively through smc.js — do not change that.
//
// Unlike cisco_asa/index.js's SNMP OIDs (confirmed against Cisco's own
// current MIB reference), FORCEPOINT-NGFW-ENGINE-MIB (the modern MIB name,
// 6.11+) was searched for during this feature's build and only its TRAP
// definitions were found documented publicly — no polled-metric OID catalog
// for that MIB. What WAS found, and is used below: the older
// STONESOFT-FIREWALL-MIB (Forcepoint NGFW was formerly "Stonesoft" — NGFW
// engines still ship/support this MIB per Forcepoint's own SNMP docs), via
// two independent third-party MIB-browser sites (mibbrowser.online and
// mibs.observium.org) that parsed the real MIB file and agreed exactly on
// every numeric OID below — not a single uncorroborated guess, but still
// NOT confirmed against a live engine's actual SNMP responses, which is
// exactly why lowConfidence is forced true unconditionally for this vendor
// regardless of source quality (see the method comment below).
//
// - sysUpTime.0 (MIB-II, RFC 1213) — universal, no vendor-specific doc needed.
// - fwCpuTotal (STONESOFT-FIREWALL-MIB), table column
//   1.3.6.1.4.1.1369.5.2.1.11.1.1.3 under fwCpuStatsTable, indexed by
//   fwCpuStatsId — per the MIB's own object description, index/id "0" is
//   "designed for total values" (i.e. the whole-engine aggregate, not one
//   core). Walked rather than GET'd at a guessed ".0" instance suffix,
//   picking the row whose OID ends in ".0" if present, else the first row —
//   "search deep, don't assume the exact instance," the same posture this
//   codebase already applies to doc-derived Palo Alto/Fortinet paths.
// - fwMemBytesTotal / fwMemBytesUsed (STONESOFT-FIREWALL-MIB),
//   1.3.6.1.4.1.1369.5.2.1.11.2.4 / .11.2.5 under fwMemoryInfo — walked (not
//   GET'd at a bare ".0") for the same "don't assume, confirm the shape via
//   the raw response" reason; both sources describe these as scalar-like,
//   but neither had the formal INDEX clause to confirm with certainty.
// - fwConnNumber (STONESOFT-FIREWALL-MIB), 1.3.6.1.4.1.1369.5.2.1.4 — "Number
//   of current connections," used for sessionCount. Same walk-not-guess
//   treatment.
//
// Sources: https://mibbrowser.online/mibdb_search.php?mib=STONESOFT-FIREWALL-MIB
// and https://mibs.observium.org/mib/STONESOFT-FIREWALL-MIB/ (independently
// agreeing), cross-checked against Forcepoint's own SNMP docs confirming NGFW
// engines still carry Stonesoft-era MIBs
// (https://help.forcepoint.com/ngfw/en-us/6.10.100/GUID-6D0B949F-CA4E-4EEF-BAB4-AF7C248D9EB7.html).
const FORCEPOINT_SNMP_OID = {
  sysUpTime: '1.3.6.1.2.1.1.3.0',
};
const FW_CPU_TOTAL_TABLE_BASE = '1.3.6.1.4.1.1369.5.2.1.11.1.1.3'; // fwCpuTotal
const FW_MEM_TOTAL_BASE = '1.3.6.1.4.1.1369.5.2.1.11.2.4'; // fwMemBytesTotal
const FW_MEM_USED_BASE = '1.3.6.1.4.1.1369.5.2.1.11.2.5'; // fwMemBytesUsed
const FW_CONN_NUMBER_BASE = '1.3.6.1.4.1.1369.5.2.1.4'; // fwConnNumber

let forcepointSnmpDebugLogged = false;

// Picks the "total" row from a walked table: the row whose OID ends in the
// literal index 0 (per fwCpuStatsId's own description, "designed for total
// values"), falling back to the first row returned when no such index is
// present — never guesses a value when the rows array is empty.
function pickTotalRow(rows) {
  if (!Array.isArray(rows) || rows.length === 0) return null;
  const totalRow = rows.find((r) => typeof r.oid === 'string' && r.oid.endsWith('.0'));
  return totalRow || rows[0];
}

function numericOrNull(value) {
  if (value === null || value === undefined) return null;
  const n = Number(value);
  return Number.isNaN(n) ? null : n;
}

class ForcepointAdapter extends FirewallAdapter {
  constructor({ device, pool }) {
    super({ device, pool });
  }

  // Builds the SMC connection descriptor, decrypting the stored API key via credStore.
  // Always uses this.pool — never omit it (CLAUDE.md Pool Warning).
  async _getConn() {
    const apiKey = await credStore.getCredential(this.device.id, 'smc_api', this.pool);
    if (!apiKey) {
      throw new Error(
        `No SMC API key credential found for device ${this.device.id} — save credentials before connecting.`
      );
    }

    return {
      smcHost: this.device.smc_host,
      smcPort: this.device.smc_port || 8082,
      apiKey,
      allowSelfSignedSsl: this.device.allow_self_signed_ssl !== false,
    };
  }

  // → { ok: bool, latency_ms, message } — must never throw.
  async testConnectivity() {
    const startedAt = Date.now();
    try {
      const conn = await this._getConn();
      await smc.getApiInfo(conn);
      return { ok: true, latency_ms: Date.now() - startedAt, message: 'Connected' };
    } catch (err) {
      return { ok: false, latency_ms: null, message: err.message };
    }
  }

  // Resolves the ONE engine element on this SMC server that IS this device — see
  // CLAUDE.md Bug 1 / parser.findEngineByIdentity. smc.getEngines(conn) returns EVERY
  // engine on the whole SMC server unfiltered; a positional engines[0] pick silently
  // collapses every device pointed at this smc_host onto whichever engine happens to be
  // first in the listing. THROWS (naming the candidate engine names found on the
  // server) rather than falling back to any positional pick — mirrors
  // lib/adapters/checkpoint/index.js's gateway-identity resolution: storing nothing is
  // recoverable, storing the wrong engine's data silently is not.
  async _resolveEngine(conn) {
    const engines = await smc.getEngines(conn);
    const engine = parser.findEngineByIdentity(engines, this.device);
    if (!engine) {
      throw new Error(
        `No engine on SMC ${conn.smcHost} matches device "${this.device.name}" by name ` +
          `(candidates found on the server: ${parser.describeEngineCandidates(engines)}). Refusing ` +
          'to guess — collecting another engine\'s version/rules/config would silently report the ' +
          'wrong physical firewall\'s data for this device. Fix: make the SecVault device name ' +
          'exactly match the engine element\'s name on the SMC server, then re-run the collection.'
      );
    }
    return engine;
  }

  // → { version_string, version_tuple, model }
  async getVersion() {
    const conn = await this._getConn();
    const engine = await this._resolveEngine(conn);
    return parser.parseEngineVersion(engine);
  }

  // → NormalizedRule[]
  async getRules() {
    const conn = await this._getConn();
    const engine = await this._resolveEngine(conn);

    // Best-effort: follow a policy reference on the engine element if present.
    // Field names for the assigned policy reference are not guaranteed consistent
    // across SMC versions — check a few known candidates defensively.
    let policyHref =
      (engine.fw_policy && (engine.fw_policy.href || engine.fw_policy)) ||
      (engine.policy && (engine.policy.href || engine.policy)) ||
      null;

    if (policyHref && typeof policyHref !== 'string') {
      policyHref = null;
    }

    // ⛔ MUST THROW, not fall back to a positional pick — see CLAUDE.md Bug 2. When the
    // matched engine element doesn't expose a fw_policy/policy href (a real
    // possibility: these field names are doc-derived, never live-verified — see
    // CLAUDE.md "Live Validation Status"), the previous code fetched the FIRST policy
    // on the ENTIRE SMC server and stored it as this device's ruleset — completely
    // unrelated to the actual device. No ruleset is safer than the wrong one.
    if (!policyHref) {
      throw new Error(
        `Forcepoint rule collection failed for device ${this.device.id} ("${this.device.name}") — ` +
          'no policy reference (checked fw_policy, policy) was found on the matched engine element ' +
          `(raw keys present: ${JSON.stringify(Object.keys(engine || {}))}). Refusing to fall back to ` +
          "a positionally-picked policy from the server's full policy list — that could silently " +
          "store an unrelated device's ruleset. Fix: verify the policy-reference field name for this " +
          'SMC version (see CLAUDE.md "SMC API" Field Name Verification / [SMC Debug] log) and update ' +
          "this adapter, or confirm the engine has a policy assigned in SMC."
      );
    }

    let policyElement;
    try {
      policyElement = await smc.getPolicy(conn, policyHref);
    } catch (err) {
      // ⛔ MUST THROW, not swallow to null — found in a full-app audit
      // (2026-07-16). parser.parsePolicy(null, ...) returns [], and
      // collectAndStore DELETEs the device's real firewall_rules before
      // reinserting whatever getRules() returns. A transient SMC failure here
      // (timeout, 503, auth error, unexpected href/field shape on this SMC
      // version) must never be mistaken for "this device genuinely has zero
      // rules" — the same class of bug already fixed in Fortinet/Sangfor
      // ("getRules() must THROW on a retrieval failure — never return []").
      throw new Error(
        `Forcepoint rule collection failed — could not resolve the assigned policy for ` +
          `device ${this.device.id}: ${err.message}`
      );
    }

    const [networkElements, serviceElements] = await Promise.all([
      smc.getNetworkElements(conn).catch((err) => {
        console.warn(`[Forcepoint] Failed to fetch network elements: ${err.message}`);
        return [];
      }),
      smc.getServiceElements(conn).catch((err) => {
        console.warn(`[Forcepoint] Failed to fetch service elements: ${err.message}`);
        return [];
      }),
    ]);

    return parser.parsePolicy(policyElement, networkElements, serviceElements);
  }

  // → { raw: string, parsed: object }
  async getConfig() {
    const conn = await this._getConn();
    const engine = await this._resolveEngine(conn);

    // Re-fetch the engine's full element via its own href to make sure we have the
    // complete, current element (getEngines() may already have done this, but the
    // href is always authoritative per HATEOAS — never assume the cached copy is fresh).
    let fullEngineElement = engine;
    if (engine.href) {
      try {
        fullEngineElement = await smc.getElement(conn, engine.href);
      } catch (err) {
        console.warn(
          `[Forcepoint] Failed to re-fetch full engine element for device ${this.device.id}: ${err.message}`
        );
        fullEngineElement = engine;
      }
    }

    // ⛔ Redact before storing — see CLAUDE.md Bug 3. device_configs.config_raw/
    // config_parsed are GRANT SELECT'd to claude_readonly/nocvault_readonly, the same
    // roles CLAUDE.md bars from device_credentials; every other adapter in this
    // codebase redacts before persisting, this one previously didn't at all.
    const redactedElement = parser.redactEngineElement(fullEngineElement);
    return parser.parseConfig(redactedElement);
  }

  // OPTIONAL — see lib/adapters/interface.js's getObjects() contract comment.
  // → { addresses, addressGroups, services, serviceGroups }
  //
  // Deliberately does NOT call _resolveEngine() — unlike getVersion()/getRules()/
  // getConfig(), SMC's object catalog (network_elements/service_elements) is
  // SERVER-WIDE, not scoped to one engine, so there is no per-engine identity to
  // resolve here (see CLAUDE.md's Forcepoint bug-sweep paragraph for why identity
  // matching matters for the other three methods).
  //
  // Also deliberately different from getRules()'s fail-loud philosophy: a partial
  // object catalog (e.g. addresses collected, service objects failed) still feeds
  // lib/engines/objectUsage.js's unused/duplicate-object matching usefully — there
  // is no destructive DELETE-then-nothing consequence here the way an empty
  // getRules() result has for firewall_rules. Each of the two underlying SMC
  // fetches (network_elements / service_elements) is isolated in its own
  // try/catch, degrading its pair of output arrays to [] independently rather
  // than throwing the whole method.
  async getObjects() {
    const conn = await this._getConn();

    let addresses = [];
    let addressGroups = [];
    try {
      const networkElements = await smc.getNetworkElements(conn);
      ({ addresses, addressGroups } = parser.parseAddressObjects(networkElements));
    } catch (err) {
      console.warn(
        `[Forcepoint] getObjects: failed to fetch/parse network elements for device ${this.device.id}: ${err.message}`
      );
    }

    let services = [];
    let serviceGroups = [];
    try {
      const serviceElements = await smc.getServiceElements(conn);
      ({ services, serviceGroups } = parser.parseServiceObjectCatalog(serviceElements));
    } catch (err) {
      console.warn(
        `[Forcepoint] getObjects: failed to fetch/parse service elements for device ${this.device.id}: ${err.message}`
      );
    }

    return { addresses, addressGroups, services, serviceGroups };
  }

  // OPTIONAL — see lib/adapters/interface.js's getSnmpMetrics() contract
  // comment. DELIBERATE EXCEPTION to this file's "never talk to the engine
  // directly, only the SMC" rule — SNMP agents run per-engine on Forcepoint
  // NGFW, not on the SMC (see CLAUDE.md's "SNMP Monitoring" section). Uses a
  // SEPARATE credential (credential_type='snmp') from this adapter's own SMC
  // API key — never gated on / mixed with testConnectivity()/getRules()'s
  // auth, and does NOT go through _getConn()/smc.js/_resolveEngine() at all.
  //
  // Target host resolution is DIFFERENT from every other vendor in this
  // codebase: this.device.mgmt_ip does not exist for Forcepoint rows (this
  // vendor uses the `smc` connection type, storing smc_host — the SMC
  // server's own address — never the individual engine's IP). Falling back
  // to smc_host would silently SNMP-poll the management console instead of a
  // firewall engine, producing misleading data (or nonsense, if it responds
  // to SNMP at all) with no indication anything was wrong — so snmp_host is
  // REQUIRED for this vendor, not an optional override the way it is
  // everywhere else, and this throws a clear, actionable error rather than
  // guessing when it's unset.
  //
  // MAY throw (missing credential, snmp_host unset, timeout, auth failure) —
  // engine-worker's snmp-poll job already treats that like any other
  // per-device polling failure: logged and skipped, never fatal to the job
  // or other devices.
  async getSnmpMetrics() {
    const plaintext = await credStore.getCredential(this.device.id, 'snmp', this.pool);
    if (!plaintext) {
      throw new Error(
        `No SNMP credential found for device ${this.device.id} — configure one under the device SNMP tab before polling.`
      );
    }
    const credential = parseSnmpCredential(plaintext);

    const targetHost = this.device.snmp_host;
    if (!targetHost) {
      throw new Error(
        `Device ${this.device.id} ("${this.device.name}") has no snmp_host configured. Forcepoint SNMP ` +
          'polling talks directly to the individual NGFW engine, not the SMC — set snmp_host to that ' +
          "engine's own management IP under the device SNMP tab (this device's smc_host is the SMC " +
          'server, not the engine, and is deliberately never used as a fallback here).'
      );
    }
    const targetPort = this.device.snmp_port || 161;

    const session = createSession(credential, targetHost, targetPort);
    try {
      const scalarResult = await getMetrics(session, FORCEPOINT_SNMP_OID, undefined, targetHost);
      const cpuRows = await walkSubtree(session, FW_CPU_TOTAL_TABLE_BASE, undefined, targetHost);
      const memTotalRows = await walkSubtree(session, FW_MEM_TOTAL_BASE, undefined, targetHost);
      const memUsedRows = await walkSubtree(session, FW_MEM_USED_BASE, undefined, targetHost);
      const connRows = await walkSubtree(session, FW_CONN_NUMBER_BASE, undefined, targetHost);

      if (!forcepointSnmpDebugLogged) {
        forcepointSnmpDebugLogged = true;
        console.log(
          '[Forcepoint SNMP Debug] raw responses:',
          JSON.stringify({ scalarResult, cpuRows, memTotalRows, memUsedRows, connRows })
        );
      }

      const uptimeTicks = scalarResult.sysUpTime;
      const uptimeSeconds =
        uptimeTicks !== null && uptimeTicks !== undefined && !Number.isNaN(Number(uptimeTicks))
          ? Math.round(Number(uptimeTicks) / 100)
          : null;

      const cpuTotalRow = pickTotalRow(cpuRows);
      const cpuPercent = cpuTotalRow ? numericOrNull(cpuTotalRow.value) : null;

      const memTotalRow = pickTotalRow(memTotalRows);
      const memUsedRow = pickTotalRow(memUsedRows);
      const memTotalBytes = memTotalRow ? numericOrNull(memTotalRow.value) : null;
      const memUsedBytes = memUsedRow ? numericOrNull(memUsedRow.value) : null;
      let memoryPercent = null;
      if (memTotalBytes !== null && memUsedBytes !== null && memTotalBytes > 0) {
        memoryPercent = Math.round((memUsedBytes / memTotalBytes) * 10000) / 100;
      }

      const connRow = pickTotalRow(connRows);
      const sessionCount = connRow ? numericOrNull(connRow.value) : null;

      return {
        cpuPercent,
        memoryPercent,
        sessionCount,
        uptimeSeconds,
        raw: { scalarResult, cpuRows, memTotalRows, memUsedRows, connRows },
        // Always true for Forcepoint — see the OID comment block above this
        // class: even though these OIDs are corroborated by two independent
        // sources against a real MIB, they are not yet confirmed against a
        // live engine's actual SNMP response, unlike e.g. cisco_asa's
        // equivalent (confirmed against Cisco's current MIB reference).
        lowConfidence: true,
        targetHost,
      };
    } finally {
      closeSession(session);
    }
  }
}

module.exports = { ForcepointAdapter };
