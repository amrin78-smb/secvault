// lib/engines/reachabilityMatrix.js
//
// Single-device, config-only "effective zone reachability" summary.
//
// computeZoneReachability() is a PURE function (no DB) — same "pure, no DB"
// convention as lib/engines/ruleAnalysis.js's analyzeRules() and
// lib/engines/objectUsage.js's analyzeObjectUsage(). Given this device's own
// (enabled) firewall_rules, it answers "which zone-to-zone paths are
// currently reachable, per THIS device's ruleset alone" — a simple,
// defensible first-match-wins model, not a full 5-tuple packet simulator.
//
// Deliberately scoped DOWN from a full multi-hop, cross-device network path
// analysis: SecVault has no topology model of how devices connect to each
// other, and building one is out of scope here. This file only ever answers
// "given this one device's ruleset, what zone pairs does it allow/deny" —
// never anything about paths that cross more than one device.
//
// CommonJS only, matching every other lib/engines/*.js file in this
// codebase.

'use strict';

// ─────────────────────────────────────────
// Small pure helpers
// ─────────────────────────────────────────
//
// Deliberately duplicated, small, local equivalents of the identically-named
// helpers in ruleAnalysis.js (isAny/normList) rather than importing them —
// ruleAnalysis.js does not export its internal helpers, and this codebase's
// own established convention (see CLAUDE.md) is that small per-file helpers
// get duplicated rather than shared via a new common module.

// Vendor-specific wildcard spellings, beyond the literal string 'any' — same
// vocabulary ruleAnalysis.js's ANY_ALIASES uses (Fortinet's built-in "all"
// object, Cisco ASA's any4/any6 keywords).
const ANY_ALIASES = new Set(['any', 'all', 'any4', 'any6']);

function normItem(item) {
  return String(item).trim().toLowerCase();
}

function normList(list) {
  if (!Array.isArray(list)) return [];
  return list.map(normItem).filter((s) => s.length > 0);
}

// A field is "any" when it is null/undefined, an empty array, or contains an
// entry recognized as a wildcard (case-insensitive) — mirrors
// ruleAnalysis.js's isAny() exactly.
function isAny(list) {
  if (list === null || list === undefined) return true;
  if (!Array.isArray(list)) return false;
  const norm = normList(list);
  if (norm.length === 0) return true;
  return norm.some((s) => ANY_ALIASES.has(s));
}

const ALLOW_ACTIONS = new Set(['allow', 'permit', 'accept']);
const DENY_ACTIONS = new Set(['deny', 'drop', 'reject', 'block']);

function normAction(action) {
  return action === null || action === undefined ? '' : String(action).trim().toLowerCase();
}

// Mirrors ruleAnalysis.js's actionCategory() -- allow/permit/accept collapse
// to 'allow', deny/drop/reject/block collapse to 'deny', anything else is
// returned as its own raw lowercased string (so an unrecognized action never
// gets silently mapped into 'allow' or 'deny').
function actionCategory(rule) {
  const a = normAction(rule.action);
  if (ALLOW_ACTIONS.has(a)) return 'allow';
  if (DENY_ACTIONS.has(a)) return 'deny';
  return a;
}

// ─────────────────────────────────────────
// Main engine
// ─────────────────────────────────────────

/**
 * @param {object[]} rules - firewall_rules rows, ANY order (sorted
 *   internally by sequence_number ASC, nulls last).
 * @returns {{
 *   zones: string[],
 *   matrix: Object<string, Object<string, {verdict: 'allow'|'deny'|'unspecified', ruleName: string|null}>>,
 *   hasZoneData: boolean,
 * }}
 */
function computeZoneReachability(rules) {
  const allRules = Array.isArray(rules) ? rules : [];

  // Step 2: distinct set of REAL (non-wildcard) zone names across every
  // rule's src_zones AND dst_zones.
  const zoneSet = new Set();
  for (const rule of allRules) {
    for (const z of normList(rule.src_zones)) {
      if (!ANY_ALIASES.has(z)) zoneSet.add(z);
    }
    for (const z of normList(rule.dst_zones)) {
      if (!ANY_ALIASES.has(z)) zoneSet.add(z);
    }
  }

  const zones = Array.from(zoneSet).sort((a, b) => a.localeCompare(b));

  if (zones.length === 0) {
    // No real zone data anywhere in the input -- don't fabricate a matrix
    // from nothing.
    return { zones: [], matrix: {}, hasZoneData: false };
  }

  // Step 3: enabled rules only, sorted by sequence_number ASC, nulls last.
  // Rules with no sequence_number are "unordered" -- processed last, in
  // whatever stable order they arrive (Array.prototype.sort is stable per
  // the ES2019+ spec, which this codebase's Node 20 runtime satisfies).
  const enabledRules = allRules
    .filter((r) => r.enabled !== false)
    .slice()
    .sort((a, b) => {
      const aSeq = a.sequence_number;
      const bSeq = b.sequence_number;
      if (aSeq === null || aSeq === undefined) {
        if (bSeq === null || bSeq === undefined) return 0;
        return 1;
      }
      if (bSeq === null || bSeq === undefined) return -1;
      return aSeq - bSeq;
    });

  // Precompute each enabled rule's normalized src/dst zone lists + whether
  // each side is a wildcard, once, rather than re-normalizing per pair.
  const prepared = enabledRules.map((rule) => ({
    rule,
    srcIsAny: isAny(rule.src_zones),
    dstIsAny: isAny(rule.dst_zones),
    srcZones: new Set(normList(rule.src_zones)),
    dstZones: new Set(normList(rule.dst_zones)),
  }));

  // Step 4: for every ordered (srcZone, dstZone) pair (including
  // srcZone === dstZone), walk the sorted enabled rules in order; the FIRST
  // matching rule decides the verdict.
  const matrix = {};
  for (const srcZone of zones) {
    matrix[srcZone] = {};
    for (const dstZone of zones) {
      let verdict = 'unspecified';
      let ruleName = null;

      for (const p of prepared) {
        const srcMatches = p.srcIsAny || p.srcZones.has(srcZone);
        if (!srcMatches) continue;
        const dstMatches = p.dstIsAny || p.dstZones.has(dstZone);
        if (!dstMatches) continue;

        // First matching rule wins.
        const category = actionCategory(p.rule);
        verdict = category === 'allow' || category === 'deny' ? category : 'unspecified';
        ruleName = p.rule.rule_name || p.rule.rule_id_vendor || null;
        break;
      }

      matrix[srcZone][dstZone] = { verdict, ruleName };
    }
  }

  return { zones, matrix, hasZoneData: true };
}

module.exports = { computeZoneReachability };
