// lib/engines/ruleAnalysis.js
//
// Phase 5 rule hygiene analysis engine.
//
// analyzeRules() is a PURE function (no DB) that takes firewall_rules rows
// (ordered by sequence_number ASC) and emits findings for the 10 finding
// types stored in rule_analysis_results. runAnalysisForDevice() /
// runAnalysisForAllDevices() are the DB-backed wrappers used by the engine
// worker and API routes.
//
// Per CLAUDE.md "Rule Shadow Analysis": shadow detection is O(n^2) against
// rule count. For rulesets larger than maxRulesForShadow (default 1000) the
// pairwise analyses (shadow, redundant, reorder_candidate) are skipped
// entirely and a warning is logged by the caller.
//
// CommonJS only -- required by services/engine-worker.js under plain node
// AND by Next.js API routes.

'use strict';

const { computeRiskScore } = require('./riskScore');
const { cidrContains } = require('./cidrUtils');

// ─────────────────────────────────────────
// Defaults
// ─────────────────────────────────────────

// Risky service list. Each entry matches a services jsonb array item when the
// item contains the port number as a standalone token (e.g. "TCP/3389",
// "3389") or one of the aliases as a standalone token (e.g. "rdp"),
// case-insensitive. srcAnyOnly entries only fire when the rule's source is
// "any" (e.g. an open SMTP relay exposure).
const DEFAULT_RISKY_PORTS = [
  { name: 'telnet', port: 23, aliases: ['telnet'] },
  { name: 'ftp', port: 21, aliases: ['ftp'] },
  { name: 'rdp', port: 3389, aliases: ['rdp'] },
  { name: 'smb', port: 445, aliases: ['smb', 'cifs'] },
  { name: 'netbios', port: 139, aliases: ['netbios'] },
  { name: 'tftp', port: 69, aliases: ['tftp'] },
  {
    name: 'snmp-v1',
    port: 161,
    aliases: ['snmp'],
    note: 'SNMP v1/v2c uses cleartext community strings; write access over SNMP is especially dangerous',
  },
  { name: 'vnc', port: 5900, aliases: ['vnc'] },
  { name: 'mssql', port: 1433, aliases: ['mssql'] },
  { name: 'mysql', port: 3306, aliases: ['mysql'] },
  { name: 'postgres', port: 5432, aliases: ['postgres', 'postgresql'] },
  { name: 'rlogin', port: 513, aliases: ['rlogin'] },
  { name: 'rsh', port: 514, aliases: ['rsh'] },
  { name: 'smtp-open', port: 25, aliases: ['smtp'], srcAnyOnly: true },
];

// NOTE: `now` is resolved at analyzeRules() call time (options.now || new
// Date()) rather than frozen at module load.
const DEFAULT_OPTIONS = {
  unusedDays: 90,
  expiryWindowDays: 14,
  riskyPorts: DEFAULT_RISKY_PORTS,
  maxRulesForShadow: 1000,
};

const MS_PER_DAY = 24 * 60 * 60 * 1000;

// ─────────────────────────────────────────
// Small pure helpers
// ─────────────────────────────────────────

const ALLOW_ACTIONS = new Set(['allow', 'permit', 'accept']);
const DENY_ACTIONS = new Set(['deny', 'drop', 'reject', 'block']);

function normAction(action) {
  return action === null || action === undefined ? '' : String(action).trim().toLowerCase();
}

function isAllow(rule) {
  return ALLOW_ACTIONS.has(normAction(rule.action));
}

function isDeny(rule) {
  return DENY_ACTIONS.has(normAction(rule.action));
}

// Action "category" used for shadow/redundant same-action comparison:
// allow/permit/accept are equivalent, deny/drop/reject/block are equivalent.
function actionCategory(rule) {
  if (isAllow(rule)) return 'allow';
  if (isDeny(rule)) return 'deny';
  return normAction(rule.action);
}

function normItem(item) {
  return String(item).trim().toLowerCase();
}

function normList(list) {
  if (!Array.isArray(list)) return [];
  return list.map(normItem).filter((s) => s.length > 0);
}

// Vendor-specific wildcard spellings, beyond the literal string 'any'.
// Found missing in a full-app audit (2026-07-16): a genuine allow-all
// FortiGate policy (`set srcaddr "all"` — FortiOS's built-in address/service
// object is literally named "all"/"ALL", not "any") or a Cisco ASA ACE using
// `any4`/`any6` (standard 8.3+ syntax, a reserved keyword there — never a
// legitimate custom object name, unlike Fortinet's "all") was silently
// treated as a SPECIFIC value rather than a wildcard, suppressing the
// critical any_any finding (plus overly_permissive/shadow/reorder_candidate,
// which also key off isAny() via fieldCovers) for two of six vendors.
// 'all' does carry a small, accepted over-detection risk (a customer could
// theoretically name a custom object "all") — deliberately accepted, since
// under-detecting a real any-any rule is the far worse failure mode here.
const ANY_ALIASES = new Set(['any', 'all', 'any4', 'any6']);

// A field is "any" when it is null/undefined, an empty array, or contains an
// entry recognized as a wildcard (case-insensitive) — see ANY_ALIASES.
function isAny(list) {
  if (list === null || list === undefined) return true;
  if (!Array.isArray(list)) return false;
  const norm = normList(list);
  if (norm.length === 0) return true;
  return norm.some((s) => ANY_ALIASES.has(s));
}

// Superset test: does earlier field S cover later field R?
// S covers R iff S is "any", or (R is not "any" and every item of R appears
// in S, string equality, case-insensitive, trimmed), OR — added 2026-07-19 —
// every item of R that ISN'T a literal string match is nonetheless covered by
// SOME item of S via real CIDR containment (see lib/engines/cidrUtils.js).
//
// This only ever ADDS matches on top of the pre-existing string-equality
// test, never removes any — so this stays exactly as conservative in the
// "no false shadows" direction as before. cidrContains() returns `null`
// (never `false`) whenever either side isn't a parseable IPv4 literal/CIDR —
// which is the common case, since most address-list items across every
// Tier 1 vendor are unresolved address-OBJECT NAMES (e.g. "LAN-subnet"), not
// literal CIDRs. This enhancement only fires for the real-world shape where
// an admin typed a literal CIDR straight into a rule instead of referencing
// an object — confirmed to actually happen on Palo Alto (both SSH and
// XML/API transports store whatever string PAN-OS returns for
// source/destination verbatim, with no distinction between an object name
// and a literal CIDR). For every other vendor/shape this is a no-op: object
// names never parse as CIDRs, so cidrContains() returns null and the result
// is identical to the pre-2026-07-19 string-only behavior.
//
// Still no attempt at cross-vendor address-OBJECT resolution (looking up
// what CIDR "LAN-subnet" actually represents) — that would need a whole new
// per-vendor object-fetch layer (config firewall address on Fortinet,
// address/address-group xpaths on Palo Alto) that does not exist in this
// codebase today. Out of scope here; see CLAUDE.md for this as a documented,
// deliberately-not-done follow-up.
function fieldCovers(sList, rList) {
  if (isAny(sList)) return true;
  if (isAny(rList)) return false;
  const sNorm = normList(sList);
  const sSet = new Set(sNorm);
  return normList(rList).every((item) => {
    if (sSet.has(item)) return true;
    return sNorm.some((sItem) => cidrContains(sItem, item) === true);
  });
}

// Order-insensitive, case-insensitive set equality. "any" fields (null,
// empty, or containing 'any') are canonicalized to the same set.
//
// Deliberately NOT given the same CIDR-aware fallback fieldCovers() got in
// 2026-07-19 (e.g. treating "10.0.0.0/24" and "10.0.0.1/24" as an equal
// SET member for redundant-rule detection). Per-item containment (fieldCovers)
// is a straightforward "does S have something that covers this R item"
// existence check; SET equality with CIDR-aware equivalence is a harder
// bipartite-matching problem once either side has more than one item (which
// item pairs with which?), and getting that subtly wrong risks a false
// `redundant` finding — worse than fieldCovers' worst case, since redundant
// findings suggest deleting a rule outright. Scoped out for now; flagged as
// an accepted, documented follow-up rather than guessed at under time
// pressure.
function fieldEquals(aList, bList) {
  const aAny = isAny(aList);
  const bAny = isAny(bList);
  if (aAny || bAny) return aAny && bAny;
  const aSet = new Set(normList(aList));
  const bSet = new Set(normList(bList));
  if (aSet.size !== bSet.size) return false;
  for (const item of aSet) {
    if (!bSet.has(item)) return false;
  }
  return true;
}

// Human-readable rule label for finding detail text.
function ruleLabel(rule) {
  if (rule.rule_name) return `"${rule.rule_name}"`;
  if (rule.rule_id_vendor) return `"${rule.rule_id_vendor}"`;
  if (rule.sequence_number !== null && rule.sequence_number !== undefined) {
    return `at position ${rule.sequence_number}`;
  }
  return `(${rule.id})`;
}

// Tokenize a services entry into standalone alphanumeric tokens
// ("TCP/3389" -> ['tcp','3389']).
function serviceTokens(entry) {
  return normItem(entry)
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 0);
}

// Return the risky-port entries matched by a rule's services list.
function matchRiskyServices(rule, riskyPorts) {
  const services = Array.isArray(rule.services) ? rule.services : [];
  const matched = [];
  const srcIsAny = isAny(rule.src_addresses);

  for (const risky of riskyPorts) {
    if (risky.srcAnyOnly && !srcIsAny) continue;
    const portToken = risky.port !== null && risky.port !== undefined ? String(risky.port) : null;
    const aliasSet = new Set(
      [risky.name].concat(Array.isArray(risky.aliases) ? risky.aliases : []).map(normItem)
    );

    let hit = false;
    for (const entry of services) {
      for (const token of serviceTokens(entry)) {
        if ((portToken !== null && token === portToken) || aliasSet.has(token)) {
          hit = true;
          break;
        }
      }
      if (hit) break;
    }
    if (hit) matched.push(risky);
  }

  return matched;
}

// sequence-strictly-earlier test (both sequence numbers must be present).
function isStrictlyEarlier(sRule, rRule) {
  if (
    sRule.sequence_number === null ||
    sRule.sequence_number === undefined ||
    rRule.sequence_number === null ||
    rRule.sequence_number === undefined
  ) {
    return false;
  }
  return sRule.sequence_number < rRule.sequence_number;
}

// Full traffic-coverage test used by shadow and reorder_candidate:
// S covers R when S's zones, addresses and services are EACH supersets of R's.
//
// Zones are part of the match criteria on every vendor that reports them: a
// rule scoped to src_zone 'trust' does not carry traffic arriving on
// 'untrust', so it cannot shadow (or pre-empt) a rule scoped to 'untrust'
// even when the two rules' addresses and services are identical. Omitting the
// zone test produces false `shadow`/`reorder_candidate` findings that tell an
// operator to delete a rule which is in fact live — the exact failure mode
// CLAUDE.md's "deliberately conservative to avoid false shadows" rule exists
// to prevent, and consistent with `redundant`, which already compares zones.
//
// Vendors that don't report zones leave these fields null, which isAny()
// treats as "any" on both sides — so this test is a no-op for them.
function ruleCovers(sRule, rRule) {
  return (
    fieldCovers(sRule.src_zones, rRule.src_zones) &&
    fieldCovers(sRule.dst_zones, rRule.dst_zones) &&
    fieldCovers(sRule.src_addresses, rRule.src_addresses) &&
    fieldCovers(sRule.dst_addresses, rRule.dst_addresses) &&
    fieldCovers(sRule.services, rRule.services)
  );
}

// ─────────────────────────────────────────
// analyzeRules — PURE, no DB
// ─────────────────────────────────────────

/**
 * Analyze a device's firewall rules and return hygiene findings.
 *
 * @param {object[]} rules - firewall_rules rows ordered by sequence_number
 *   ASC. jsonb columns arrive as parsed JS arrays, hit_count as string
 *   (bigint), timestamps as JS Date or null.
 * @param {{unusedDays?: number, expiryWindowDays?: number, riskyPorts?: object[], maxRulesForShadow?: number, now?: Date}} [options]
 * @returns {{rule_id: string, finding_type: string, severity: string, detail: string, affected_rule_ids: string[], remediation: string}[]}
 */
function analyzeRules(rules, options) {
  const opts = Object.assign({}, DEFAULT_OPTIONS, options || {});
  const now = opts.now instanceof Date ? opts.now : new Date();
  const riskyPorts =
    Array.isArray(opts.riskyPorts) && opts.riskyPorts.length > 0
      ? opts.riskyPorts
      : DEFAULT_RISKY_PORTS;

  const findings = [];
  const ruleList = Array.isArray(rules) ? rules : [];

  // ── Per-rule checks ──
  for (const rule of ruleList) {
    // expiring_soon is the ONLY check that also applies to disabled rules.
    if (rule.expiry_date instanceof Date && !isNaN(rule.expiry_date.getTime())) {
      const deltaMs = rule.expiry_date.getTime() - now.getTime();
      if (deltaMs < 0) {
        findings.push({
          rule_id: rule.id,
          finding_type: 'expiring_soon',
          severity: 'medium',
          detail: `Rule ${ruleLabel(rule)} already expired on ${rule.expiry_date.toISOString().slice(0, 10)}.`,
          affected_rule_ids: [],
          remediation: 'Remove or renew this expired rule; expired rules are dead configuration that obscures the policy.',
        });
      } else if (deltaMs <= opts.expiryWindowDays * MS_PER_DAY) {
        findings.push({
          rule_id: rule.id,
          finding_type: 'expiring_soon',
          severity: 'medium',
          detail: `Rule ${ruleLabel(rule)} expires on ${rule.expiry_date.toISOString().slice(0, 10)}, within ${opts.expiryWindowDays} days.`,
          affected_rule_ids: [],
          remediation: 'Confirm whether this rule is still needed and renew or remove it before it expires.',
        });
      }
    }

    // Disabled rules: skip everything else.
    if (rule.enabled === false) continue;

    const allow = isAllow(rule);
    const srcAny = isAny(rule.src_addresses);
    const dstAny = isAny(rule.dst_addresses);
    const svcAny = isAny(rule.services);

    // any_any — critical
    const isAnyAny = allow && srcAny && dstAny && svcAny;
    if (isAnyAny) {
      findings.push({
        rule_id: rule.id,
        finding_type: 'any_any',
        severity: 'critical',
        detail: `Rule ${ruleLabel(rule)} allows any source to any destination on any service.`,
        affected_rule_ids: [],
        remediation: 'Replace this rule with narrowly scoped rules restricting source, destination, and services to the minimum required.',
      });
    }

    // overly_permissive — medium (not already any_any)
    if (allow && !isAnyAny && (srcAny || dstAny) && svcAny) {
      const openSide = srcAny ? 'any source' : 'any destination';
      findings.push({
        rule_id: rule.id,
        finding_type: 'overly_permissive',
        severity: 'medium',
        detail: `Rule ${ruleLabel(rule)} allows ${openSide} on any service.`,
        affected_rule_ids: [],
        remediation: 'Restrict the open address field and limit services to only those required.',
      });
    }

    // risky_service — high
    if (allow) {
      const matched = matchRiskyServices(rule, riskyPorts);
      if (matched.length > 0) {
        const names = matched
          .map((m) => (m.port !== null && m.port !== undefined ? `${m.name} (${m.port})` : m.name))
          .join(', ');
        const notes = matched
          .filter((m) => m.note)
          .map((m) => ` Note: ${m.note}.`)
          .join('');
        findings.push({
          rule_id: rule.id,
          finding_type: 'risky_service',
          severity: 'high',
          detail: `Rule ${ruleLabel(rule)} allows high-risk service(s): ${names}.${notes}`,
          affected_rule_ids: [],
          remediation: 'Replace these legacy/high-risk services with secure alternatives (e.g. SSH/SFTP, TLS) or restrict them to tightly scoped management sources.',
        });
      }
    }

    // unused — medium (hit_count is bigint -> string; coerce with Number())
    //
    // ⛔ Simplified 2026-07-19, found in a follow-up bug sweep: this used to
    // read `Number(rule.hit_count) === 0 && !rule.last_hit_at`. No adapter,
    // for any vendor, has ever populated `firewall_rules.last_hit_at` — it
    // isn't even in collectAndStore()'s INSERT column list (lib/adapters/
    // index.js), so it is permanently NULL for every rule from every
    // vendor. `!rule.last_hit_at` was therefore always true, making it dead
    // weight on the condition rather than a real second signal — hit_count
    // alone was always the entire decision. Simplified to say what's
    // actually being checked; if a future adapter change starts populating
    // last_hit_at, THAT would be the point to reintroduce it as a genuine
    // second condition (e.g. an old-but-nonzero-hit-count rule), not before.
    if (Number(rule.hit_count) === 0) {
      findings.push({
        rule_id: rule.id,
        finding_type: 'unused',
        severity: 'medium',
        detail: `Rule ${ruleLabel(rule)} has zero recorded hits (hit-count data may be unavailable from this vendor/transport — see CLAUDE.md's Known Limitations for Fortinet/Sangfor SSH).`,
        affected_rule_ids: [],
        remediation: `Verify the rule is still required; if it has genuinely had no traffic for over ${opts.unusedDays} days, disable and then remove it.`,
      });
    }

    // log_disabled — info
    if (allow && rule.log_enabled === false) {
      findings.push({
        rule_id: rule.id,
        finding_type: 'log_disabled',
        severity: 'info',
        detail: `Allow rule ${ruleLabel(rule)} has logging disabled.`,
        affected_rule_ids: [],
        remediation: 'Enable logging on this rule so permitted traffic is auditable and usable for exploitation correlation.',
      });
    }
  }

  // ── Pairwise checks (shadow, redundant, reorder_candidate) ──
  // Skipped entirely above the O(n^2) cap; the DB caller logs the warning.
  if (ruleList.length <= opts.maxRulesForShadow) {
    // shadowPairs: "laterId|earlierId" pairs already reported as shadow, so
    // redundant never double-reports the same pair.
    const shadowPairs = new Set();
    // correlationPairs: "laterId|earlierId" pairs already reported as
    // correlation, so the same pair is never reported twice.
    const correlationPairs = new Set();

    for (let i = 0; i < ruleList.length; i++) {
      const r = ruleList[i];
      if (r.enabled === false) continue;

      // shadow — high: r fully covered by an earlier enabled rule with the
      // same action.
      for (let j = 0; j < i; j++) {
        const s = ruleList[j];
        if (s.enabled === false) continue;
        if (!isStrictlyEarlier(s, r)) continue;
        if (actionCategory(s) !== actionCategory(r)) continue;
        if (!ruleCovers(s, r)) continue;

        shadowPairs.add(`${r.id}|${s.id}`);
        findings.push({
          rule_id: r.id,
          finding_type: 'shadow',
          severity: 'high',
          detail: `Rule ${ruleLabel(r)} is fully shadowed by earlier rule ${ruleLabel(s)} with the same action and can never match traffic.`,
          affected_rule_ids: [s.id],
          remediation: 'Remove the shadowed rule, or reorder/narrow the earlier rule if this rule was intended to take precedence.',
        });
        break; // first covering earlier rule is enough
      }

      // redundant — medium: identical addresses, zones, services and action
      // at a different position; flag the later one.
      for (let j = 0; j < i; j++) {
        const s = ruleList[j];
        if (s.enabled === false) continue;
        if (!isStrictlyEarlier(s, r)) continue;
        if (actionCategory(s) !== actionCategory(r)) continue;
        if (shadowPairs.has(`${r.id}|${s.id}`)) continue; // already reported as shadow of the same rule
        if (
          !fieldEquals(s.src_addresses, r.src_addresses) ||
          !fieldEquals(s.dst_addresses, r.dst_addresses) ||
          !fieldEquals(s.src_zones, r.src_zones) ||
          !fieldEquals(s.dst_zones, r.dst_zones) ||
          !fieldEquals(s.services, r.services)
        ) {
          continue;
        }

        findings.push({
          rule_id: r.id,
          finding_type: 'redundant',
          severity: 'medium',
          detail: `Rule ${ruleLabel(r)} duplicates earlier rule ${ruleLabel(s)} (identical zones, addresses, services, and action).`,
          affected_rule_ids: [s.id],
          remediation: 'Remove the duplicate later rule to simplify the policy.',
        });
        break;
      }

      // correlation — medium: ManageEngine Firewall Analyzer "Policy
      // Anomalies > Correlation" concept. Two enabled rules with the same
      // action category, same zones, and same service(s), differing ONLY in
      // source OR ONLY in destination addresses (not both — that's
      // `redundant`, above — and not neither), where neither differing side
      // is "any" (an "any" side is already maximally broad; there's nothing
      // meaningful left to merge). A ruleset-simplification suggestion, not
      // a security exposure — same severity class as redundant/
      // overly_permissive, not high/critical like shadow/reorder_candidate.
      for (let j = 0; j < i; j++) {
        const s = ruleList[j];
        if (s.enabled === false) continue;
        if (!isStrictlyEarlier(s, r)) continue;
        if (actionCategory(s) !== actionCategory(r)) continue;
        // Shouldn't overlap in practice (redundant requires src AND dst
        // equal; correlation requires exactly one to differ), but guard
        // anyway to match this codebase's existing defensive style.
        if (shadowPairs.has(`${r.id}|${s.id}`)) continue;
        if (correlationPairs.has(`${r.id}|${s.id}`)) continue;
        if (!fieldEquals(s.src_zones, r.src_zones)) continue;
        if (!fieldEquals(s.dst_zones, r.dst_zones)) continue;
        if (!fieldEquals(s.services, r.services)) continue;

        const srcEqual = fieldEquals(s.src_addresses, r.src_addresses);
        const dstEqual = fieldEquals(s.dst_addresses, r.dst_addresses);

        let differingField = null;
        if (srcEqual && !dstEqual) {
          // Case A: same source, different destination — nothing to merge
          // if either side's destination is already "any".
          if (!isAny(s.dst_addresses) && !isAny(r.dst_addresses)) {
            differingField = 'destination';
          }
        } else if (dstEqual && !srcEqual) {
          // Case B: same destination, different source — nothing to merge
          // if either side's source is already "any".
          if (!isAny(s.src_addresses) && !isAny(r.src_addresses)) {
            differingField = 'source';
          }
        }
        // Both differ, or both equal (redundant's territory): not a match.
        if (differingField === null) continue;

        correlationPairs.add(`${r.id}|${s.id}`);
        findings.push({
          rule_id: r.id,
          finding_type: 'correlation',
          severity: 'medium',
          detail: `Rule ${ruleLabel(r)} and earlier rule ${ruleLabel(s)} share the same action, zones, and service(s), differing only in ${differingField} addresses — consider merging them into a single rule using an address group to reduce ruleset complexity.`,
          affected_rule_ids: [s.id],
          remediation: 'Combine the differing address lists into a single address group/object and merge these two rules into one, or confirm they are intentionally kept separate for auditability.',
        });
        break;
      }

      // reorder_candidate — high: a deny/drop/reject rule appearing after an
      // allow rule that fully covers its traffic — the deny can never fire.
      if (isDeny(r)) {
        for (let j = 0; j < i; j++) {
          const s = ruleList[j];
          if (s.enabled === false) continue;
          if (!isStrictlyEarlier(s, r)) continue;
          if (!isAllow(s)) continue;
          if (!ruleCovers(s, r)) continue;

          findings.push({
            rule_id: r.id,
            finding_type: 'reorder_candidate',
            severity: 'high',
            detail: `Deny rule ${ruleLabel(r)} appears after allow rule ${ruleLabel(s)} which fully covers its traffic — the deny can never fire.`,
            affected_rule_ids: [s.id],
            remediation: 'Move the deny rule above the covering allow rule, or narrow the allow rule so the deny takes effect.',
          });
          break;
        }
      }
    }
  }

  return findings;
}

// ─────────────────────────────────────────
// DB-backed wrappers
// ─────────────────────────────────────────

// Load optional analysis-option overrides from the settings table. Any
// missing key or parse failure falls back safely to the defaults.
async function loadOptionsFromSettings(pool) {
  const opts = Object.assign({}, DEFAULT_OPTIONS);

  try {
    const { rows } = await pool.query(
      "SELECT key, value FROM settings WHERE key IN ('rule_unused_days', 'rule_expiry_window_days', 'risky_ports')"
    );

    for (const row of rows) {
      if (row.key === 'rule_unused_days') {
        const n = parseInt(row.value, 10);
        if (Number.isFinite(n) && n > 0) opts.unusedDays = n;
      } else if (row.key === 'rule_expiry_window_days') {
        const n = parseInt(row.value, 10);
        if (Number.isFinite(n) && n > 0) opts.expiryWindowDays = n;
      } else if (row.key === 'risky_ports') {
        try {
          const parsed = JSON.parse(row.value);
          const normalized = normalizeRiskyPorts(parsed);
          if (normalized.length > 0) opts.riskyPorts = normalized;
        } catch (err) {
          console.warn('[ruleAnalysis] Invalid risky_ports setting JSON, using defaults:', err.message);
        }
      }
    }
  } catch (err) {
    console.warn('[ruleAnalysis] Failed to read settings overrides, using defaults:', err.message);
  }

  return opts;
}

// Accepts an array of numbers ("[23, 3389]"), numeric strings, service-name
// strings, or objects ({ name, port, aliases, srcAnyOnly }) and normalizes to
// the DEFAULT_RISKY_PORTS entry shape. Invalid entries are dropped.
function normalizeRiskyPorts(parsed) {
  if (!Array.isArray(parsed)) return [];
  const out = [];
  for (const entry of parsed) {
    if (typeof entry === 'number' && Number.isFinite(entry)) {
      out.push({ name: String(entry), port: entry, aliases: [] });
    } else if (typeof entry === 'string' && entry.trim().length > 0) {
      const n = Number(entry.trim());
      if (Number.isFinite(n)) {
        out.push({ name: entry.trim(), port: n, aliases: [] });
      } else {
        out.push({ name: entry.trim(), port: null, aliases: [entry.trim()] });
      }
    } else if (entry && typeof entry === 'object' && (entry.port !== undefined || entry.name)) {
      const port = entry.port !== undefined && entry.port !== null ? Number(entry.port) : null;
      out.push({
        name: entry.name ? String(entry.name) : String(entry.port),
        port: Number.isFinite(port) ? port : null,
        aliases: Array.isArray(entry.aliases) ? entry.aliases.map(String) : [],
        srcAnyOnly: entry.srcAnyOnly === true,
        note: entry.note ? String(entry.note) : undefined,
      });
    }
  }
  return out;
}

/**
 * Run rule analysis for one device: load rules, analyze, and rewrite that
 * device's rule_analysis_results rows.
 *
 * @param {string} deviceId
 * @param {import('pg').Pool} pool
 * @returns {Promise<{findings: number, byType: Object<string, number>}>}
 */
async function runAnalysisForDevice(deviceId, pool) {
  const { rows: rules } = await pool.query(
    'SELECT * FROM firewall_rules WHERE device_id = $1 ORDER BY sequence_number ASC NULLS LAST',
    [deviceId]
  );

  const options = await loadOptionsFromSettings(pool);

  if (rules.length > options.maxRulesForShadow) {
    // Per CLAUDE.md "Rule Shadow Analysis": O(n^2) analyses are capped.
    console.warn(
      `[ruleAnalysis] Device ${deviceId} has ${rules.length} rules (cap ${options.maxRulesForShadow}); ` +
        'skipping shadow/redundant/reorder analysis for this ruleset.'
    );
  }

  const findings = analyzeRules(rules, options);

  // Rewrite this device's findings: delete then insert.
  await pool.query('DELETE FROM rule_analysis_results WHERE device_id = $1', [deviceId]);

  const byType = {};
  for (const f of findings) {
    await pool.query(
      `INSERT INTO rule_analysis_results
         (device_id, rule_id, finding_type, severity, detail, affected_rule_ids, remediation)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`,
      [
        deviceId,
        f.rule_id,
        f.finding_type,
        f.severity,
        f.detail,
        JSON.stringify(f.affected_rule_ids || []),
        f.remediation,
      ]
    );
    byType[f.finding_type] = (byType[f.finding_type] || 0) + 1;
  }

  // Rule Analysis Dashboard Phase 4: snapshot the risk score every time
  // analysis actually runs, regardless of what triggered it. This is the
  // ONE function both the scheduled 24h collect (via collectAndStore) and a
  // manual "Run Analysis" click (via POST /api/devices/[id]/analysis) both
  // go through, so snapshotting here covers both without duplicating this
  // logic at either call site. Best-effort: a failure to snapshot the trend
  // point must never fail the analysis run itself (the findings above are
  // already committed by this point).
  try {
    const risk = computeRiskScore(findings);
    await pool.query(
      'INSERT INTO device_risk_history (device_id, score, band) VALUES ($1, $2, $3)',
      [deviceId, risk.score, risk.band]
    );
  } catch (err) {
    console.warn(`[ruleAnalysis] Failed to snapshot risk history for device ${deviceId}: ${err.message}`);
  }

  return { findings: findings.length, byType };
}

/**
 * Run rule analysis for every active device. One device's failure never
 * aborts the rest (engine worker job-isolation rule).
 *
 * @param {import('pg').Pool} pool
 * @returns {Promise<{devices: number, totalFindings: number, errors: {device_id: string, error: string}[]}>}
 */
async function runAnalysisForAllDevices(pool) {
  const errors = [];
  let devices = 0;
  let totalFindings = 0;

  const { rows: deviceRows } = await pool.query('SELECT id FROM devices WHERE active = true');

  for (const device of deviceRows) {
    try {
      const result = await runAnalysisForDevice(device.id, pool);
      devices += 1;
      totalFindings += result.findings;
    } catch (err) {
      errors.push({ device_id: device.id, error: err.message });
    }
  }

  return { devices, totalFindings, errors };
}

module.exports = {
  analyzeRules,
  runAnalysisForDevice,
  runAnalysisForAllDevices,
  DEFAULT_RISKY_PORTS,
  DEFAULT_OPTIONS,
};
