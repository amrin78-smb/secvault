// lib/engines/adminAccountSummary.js
//
// Vendor-agnostic admin/local-user account summary, read from
// device_configs.config_parsed -- NOT vendor-specific adapter code. Same
// architectural role as lib/engines/vpnSummary.js (read that file first --
// this module is its direct sibling): each vendor's config_parsed shape is
// wildly different, so this is a single place that knows how to interpret
// each one for "who can log into this box" purposes, kept separate from the
// adapters themselves (CLAUDE.md's "adapters implement ONLY the
// FirewallAdapter interface" boundary applies here exactly as it does there).
//
// Pure, no DB, no I/O -- CommonJS, required by both API routes and server
// component pages. Defensive: a per-vendor interpreter throwing on an
// unexpected shape degrades to a safe empty result, never propagates up into
// a page render (same discipline as vpnSummary.js's summarizeVpnConfig()).

'use strict';

function isPlainObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

// ---------------------------------------------------------------------------
// Fortinet — configParsed.admins is an array of admin entries, collected
// identically by both transports (lib/adapters/fortinet/{cliParser,index}.js's
// getConfig(): 'admins': entriesOfAll('system admin') / api.getAdmins). Real
// shape confirmed live against a production FortiGate-200E ("TUS",
// 2026-07-19):
//   [{ name: "admin", accprofile: "super_admin", "two-factor": "disable",
//      trusthost1: ["203.195.106.0","255.255.254.0"],
//      trusthost9: ["0.0.0.0","0.0.0.0"], ... }, ...]
// ---------------------------------------------------------------------------
function summarizeFortinet(configParsed) {
  const admins = configParsed && Array.isArray(configParsed.admins) ? configParsed.admins : null;
  if (!admins) return { accounts: [] };

  const accounts = admins.map((entry) => {
    const e = isPlainObject(entry) ? entry : {};
    return {
      username: e.name || null,
      privilege: e.accprofile || null,
      twoFactorEnabled: e['two-factor'] === 'enable',
      sourceRestricted: fortinetHasTrusthostRestriction(e),
    };
  });

  return { accounts };
}

// A FortiGate admin entry can carry up to 10 trusthostN fields. The wide-open
// default is "0.0.0.0 0.0.0.0" (any source) -- a slot that's simply absent is
// NOT evidence of restriction (FortiOS omits unset trusthost slots entirely,
// it doesn't fill them with the wide-open value), so "missing" and "wide
// open" both mean "not restricted" here, matching this app's "absence of
// evidence isn't provable absence" discipline used throughout
// lib/engines/applicability.js. True only when at least one present
// trusthostN's first (address) token is something other than "0.0.0.0".
function fortinetHasTrusthostRestriction(entry) {
  for (let i = 1; i <= 10; i += 1) {
    const val = entry[`trusthost${i}`];
    if (!val) continue;
    const tokens = Array.isArray(val) ? val : [val];
    if (tokens[0] && tokens[0] !== '0.0.0.0') return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Palo Alto — both transports collect the SAME underlying data
// (mgt-config.users), just via different shapes (see
// lib/adapters/paloalto/{parser,sshParser}.js's own parseConfig()):
//
//  XML/API transport: configParsed['mgt-config'].users.entry is an array, OR
//  a single bare object when there's exactly one user -- fast-xml-parser's
//  standard "collapse a single repeated element" convention. Confirmed live
//  against a production device ("ITC-SLY", 2026-07-19):
//    { users: { entry: [
//        { "@_name": "Naron", permissions: { "role-based": { superuser: "yes" } } },
//        { "@_name": "Nuttapon.R", permissions: { "role-based": { superreader: "yes" } } },
//        { "@_name": "__telemetryuser", permissions: { "role-based": { deviceadmin: {...} } } },
//    ] } }
//
//  SSH transport: configParsed.tree is the brace-format config parsed by
//  parseBraceConfig() -- a PLAIN nested object (sshParser.js's own comment on
//  parseBraceBlock(): "Each block is a plain object (not a Map) so callers
//  can use ordinary dot access ... directly on the result"), NOT the
//  {settings, blocks: {name: Node}, entries: [Node]} shape that
//  vpnSummary.js's deepFindBlockInTree()/flattenNodeSettings() comments
//  describe and are written against. That pair of helpers appears to predate
//  the "Round 3" brace-tree rewrite documented in CLAUDE.md's Live Validation
//  Status section and does not match the parser's current output -- verified
//  directly against lib/adapters/paloalto/sshParser.js's actual code before
//  writing this (per CLAUDE.md's "verify against actual code/live responses"
//  rule), not assumed from that comment. So this module does NOT reuse
//  deepFindBlockInTree/flattenNodeSettings; it does its own bounded deep
//  search shaped for the REAL plain-object tree, which turns out to make
//  privilege extraction on SSH just as clean as on XML/API (mgt-config.users
//  is an ordinary `{ username: { permissions: { "role-based": { role: ... } } } }`
//  block, the same "block key IS the identity" convention
//  findSecurityRulesContainers()/ruleFromBraceEntry() already use for
//  security rules) -- NOT the degraded "privilege likely unavailable on SSH"
//  case that seemed plausible before checking the real parser.
// ---------------------------------------------------------------------------
const MAX_SEARCH_DEPTH = 8;
const MGT_CONFIG_PATTERN = /mgt.?config/i;
const USERS_KEY_PATTERN = /^users$/i;

// Bounded depth-first search for the first key matching `pattern` anywhere in
// a plain nested object (own keys checked before descending into children,
// same shallow-first order as vpnSummary.js's deepFindKeyByPattern -- this is
// a local, independent copy because this module doesn't import from
// vpnSummary.js and isn't sharing helpers this round; kept close to that
// file's proven approach on purpose for consistency).
function deepFindValueByKeyPattern(obj, pattern, depth) {
  if (!isPlainObject(obj) || depth > MAX_SEARCH_DEPTH) return null;
  for (const [key, value] of Object.entries(obj)) {
    if (pattern.test(key)) return value;
  }
  for (const value of Object.values(obj)) {
    if (isPlainObject(value)) {
      const found = deepFindValueByKeyPattern(value, pattern, depth + 1);
      if (found !== null) return found;
    }
  }
  return null;
}

// permissions.role-based is itself a brace/XML block whose OWN key names the
// role (superuser / superreader / deviceadmin / ...) on both transports --
// identical shape, so one extractor covers both.
function privilegeFromPermissions(permissions) {
  const roleBased = permissions && isPlainObject(permissions['role-based']) ? permissions['role-based'] : null;
  if (!roleBased) return null;
  const roles = Object.keys(roleBased);
  return roles.length > 0 ? roles[0] : null;
}

function summarizePaloAltoXml(configParsed) {
  const mgtConfig = configParsed && configParsed['mgt-config'];
  const usersNode = mgtConfig && mgtConfig.users;
  const rawEntry = usersNode && usersNode.entry;
  if (!rawEntry) return { accounts: [] };

  const entries = Array.isArray(rawEntry) ? rawEntry : [rawEntry];
  const accounts = entries.map((entry) => {
    const e = isPlainObject(entry) ? entry : {};
    return {
      username: e['@_name'] || null,
      privilege: privilegeFromPermissions(e.permissions),
      // PAN-OS mgt-config doesn't model 2FA/MFA the same way GlobalProtect
      // does -- "not modeled here", not "confirmed disabled". Never coerce
      // an unmodeled fact to false; see CLAUDE.md's tri-state discipline.
      twoFactorEnabled: null,
      sourceRestricted: null,
    };
  });

  return { accounts };
}

function summarizePaloAltoSsh(tree) {
  const mgtConfig = deepFindValueByKeyPattern(tree, MGT_CONFIG_PATTERN, 0);
  const usersNode = isPlainObject(mgtConfig) ? deepFindValueByKeyPattern(mgtConfig, USERS_KEY_PATTERN, 0) : null;
  if (!isPlainObject(usersNode)) return { accounts: [] };

  const accounts = Object.entries(usersNode).map(([username, attrs]) => {
    const a = isPlainObject(attrs) ? attrs : {};
    return {
      username: username || null,
      privilege: privilegeFromPermissions(a.permissions),
      twoFactorEnabled: null,
      sourceRestricted: null,
    };
  });

  return { accounts };
}

function summarizePaloAlto(configParsed) {
  if (!isPlainObject(configParsed)) return { accounts: [] };
  // SSH transport nests everything under .tree (a plain object, see the
  // header comment above); XML/API transport has mgt-config at the top level.
  if (isPlainObject(configParsed.tree)) {
    return summarizePaloAltoSsh(configParsed.tree);
  }
  return summarizePaloAltoXml(configParsed);
}

// ---------------------------------------------------------------------------
// Cisco ASA — configParsed.usernames is a flat array of plain username
// STRINGS, never objects (lib/adapters/cisco_asa/parser.js's own comment:
// "usernames are captured as names only, never their password hashes" --
// parseRunningConfig()'s `username <name> ...` line handler pushes only the
// captured name, deliberately never the password-hash tail of the line).
// No privilege/2FA/source-restriction data is modeled for this vendor today.
// ---------------------------------------------------------------------------
function summarizeCiscoAsa(configParsed) {
  const usernames = configParsed && Array.isArray(configParsed.usernames) ? configParsed.usernames : null;
  if (!usernames) return { accounts: [] };

  const accounts = usernames
    .filter((u) => typeof u === 'string' && u.length > 0)
    .map((u) => ({ username: u, privilege: null, twoFactorEnabled: null, sourceRestricted: null }));

  return { accounts };
}

// ---------------------------------------------------------------------------
// Dispatch — Sangfor and Check Point collect no admin/user account data at
// all today (confirmed by reading both adapters' parsers directly), and
// Forcepoint's SMC parser has no admin/user fields either (confirmed the same
// way -- also absent from vpnSummary.js's own SUMMARIZERS for the same
// reason). All three fall through to `supported: false` below, same as any
// vendor not listed here -- distinct from `supported: true, accounts: []`
// ("this vendor IS modeled, this device just has none collected yet"), which
// Fortinet/Palo Alto/Cisco ASA can still legitimately return.
// ---------------------------------------------------------------------------
const SUMMARIZERS = {
  fortinet: summarizeFortinet,
  paloalto: summarizePaloAlto,
  cisco_asa: summarizeCiscoAsa,
};

// Best-effort, case-insensitive cross-vendor "full admin" heuristic --
// catches Fortinet's "super_admin" and Palo Alto's "superuser". Deliberately
// anchored (not a bare /super/i substring test) so Palo Alto's "superreader"
// -- read-only, despite the "super" prefix -- does NOT count as a superuser;
// a naive substring match was tried first and miscounted it, caught by this
// module's own test script before shipping. Not a security boundary, just a
// UI summary signal; won't catch every vendor's own naming for "full admin"
// (e.g. a hypothetical vendor calling it "root"/"administrator") and isn't
// meant to.
const SUPERUSER_PATTERN = /^super(_?admin|user)$/i;

function countSuperusers(accounts) {
  return accounts.filter((a) => typeof a.privilege === 'string' && SUPERUSER_PATTERN.test(a.privilege)).length;
}

/**
 * @param {string} vendor
 * @param {object|null} configParsed - device_configs.config_parsed (latest row)
 * @returns {{supported: boolean, accounts: {username: string, privilege: string|null,
 *   twoFactorEnabled: boolean|null, sourceRestricted: boolean|null}[],
 *   totalCount: number, superuserCount: number, error?: boolean}}
 */
function summarizeAdminAccounts(vendor, configParsed) {
  const fn = SUMMARIZERS[vendor];
  if (!fn) return { supported: false, accounts: [], totalCount: 0, superuserCount: 0 };

  try {
    const result = fn(configParsed) || {};
    const accounts = Array.isArray(result.accounts) ? result.accounts : [];
    return {
      supported: true,
      accounts,
      totalCount: accounts.length,
      superuserCount: countSuperusers(accounts),
    };
  } catch (err) {
    // Never let a malformed/unexpected config_parsed shape throw up into an
    // API route or page render -- degrade to "collected but unreadable",
    // same discipline as vpnSummary.js's summarizeVpnConfig().
    console.warn(`[adminAccountSummary] Failed to summarize admin accounts for vendor "${vendor}": ${err.message}`);
    return { supported: true, accounts: [], totalCount: 0, superuserCount: 0, error: true };
  }
}

module.exports = { summarizeAdminAccounts };
