// lib/ldapRoles.js
//
// Which SecVault role a directory user gets, from the groups they are in.
//
// Before this, `app/api/auth/[...nextauth]/route.js` returned a hardcoded
// `role: 'admin'` for ANY successful bind. Every person in the directory was an
// administrator of the firewall-management platform, and the only lever was
// whether LDAP was configured at all.
//
// PURE except for the three functions that take a `pool`, and the judgement —
// `resolveRole` — takes everything it needs as arguments so it can be tested
// without a directory, a database or a network.
//
// ⛔ VERIFIED AGAINST THE LIVE DIRECTORY (thaiunion.co.th, 2026-09-16) rather
// than written from documentation, per this codebase's own rule. What that
// probe established, and what it cost the old code:
//
//   * A USER'S DN CANNOT BE BUILT FROM THEIR USERNAME. The probed account's DN
//     is `CN=Service MFA,OU=Hybrid Joined Device,OU=Windows Update Delivery
//     Optimization,OU=TUF HQ,OU=TUF,DC=thaiunion,DC=co,DC=th` — the CN is the
//     DISPLAY NAME, not the login, and the account is four OUs deep. The old
//     `cn=${username},${baseDn}` builds a DN that does not exist, so that bind
//     could never have succeeded against this directory.
//   * `userPrincipalName` is `FIRMANS0@thaiunion.com` while the directory is
//     `DC=thaiunion,DC=co,DC=th`. The UPN suffix is NOT the DNS domain and
//     cannot be derived from the base DN.
//   * `memberOf` IS populated and holds full group DNs.
//   * Group DNs live in mixed containers — `OU=Microsoft Exchange Security
//     Groups`, `CN=Users`, `CN=Builtin` — and contain SPACES
//     (`CN=Help Desk,...`). Nothing may assume a flat tree or a token-safe name.

'use strict';

const { SUPER_ADMIN_ROLE, ADMIN_ROLE, OPERATOR_ROLE, ASSIGNABLE_ROLES } = require('./rbac');

/**
 * Most privileged first. Used ONLY to break a tie when a user is in several
 * mapped groups.
 *
 * ⛔ THE MOST PRIVILEGED MATCH WINS, not the least. A user in both "Firewall
 * Admins" and "Helpdesk" is a firewall admin who is also on the helpdesk;
 * resolving that to the lower role would make adding someone to a second group
 * silently REMOVE access they still need, and the administrator who granted it
 * would have no way to see why.
 */
const ROLE_RANK = [SUPER_ADMIN_ROLE, ADMIN_ROLE, OPERATOR_ROLE];

/** Why a login was refused, or which mapping granted it. */
const OUTCOME = {
  MAPPED: 'mapped',
  LEGACY_NO_MAPPINGS: 'legacy_no_mappings',
  NO_MATCHING_GROUP: 'no_matching_group',
  GROUPS_UNREADABLE: 'groups_unreadable',
};

/**
 * Canonical form of a group DN, for comparison only.
 *
 * ⛔ DNs ARE CASE-INSENSITIVE AND WHITESPACE-TOLERANT IN AD, and an operator
 * pasting one out of ADUC will not match the byte sequence the directory
 * returns. `CN=Help Desk, OU=Groups, DC=x` and `cn=help desk,ou=groups,dc=x`
 * are the SAME GROUP; comparing them raw would silently deny a user whose
 * mapping is visibly correct on screen — the worst kind of access bug, because
 * the configuration looks right.
 *
 * Only spacing AROUND the comma separators is normalised. Spacing INSIDE a
 * value is significant and preserved: `CN=Help Desk` is a real group name.
 */
function normaliseDn(dn) {
  if (typeof dn !== 'string') return null;
  const trimmed = dn.trim();
  if (!trimmed) return null;
  return trimmed
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '')
    .join(',')
    .toLowerCase();
}

/**
 * Is this a role an LDAP mapping may grant?
 *
 * ⛔ Validated against `ASSIGNABLE_ROLES`, never against a local list. A typo'd
 * or retired role (`viewer`) stored in a mapping would resolve to a role
 * `lib/rbac.js` grants NO capabilities — the user would authenticate
 * successfully and then find every page refusing them, with the mapping looking
 * perfectly healthy in Settings.
 */
function isMappableRole(role) {
  return typeof role === 'string' && ASSIGNABLE_ROLES.includes(role);
}

/**
 * Decide the role for a directory user.
 *
 * @param {object} o
 * @param {string[]|null} o.groups    the user's group DNs, or NULL if the
 *                                    directory could not be asked
 * @param {Array<{groupDn: string, role: string}>} o.mappings  configured mappings
 * @returns {{role: string|null, outcome: string, matched: string[], reason: string}}
 */
function resolveRole({ groups, mappings }) {
  const configured = Array.isArray(mappings) ? mappings : [];

  // ⛔ "NO MAPPINGS CONFIGURED" AND "NO MAPPING MATCHED" ARE OPPOSITE
  // INSTRUCTIONS AND MUST NEVER COLLAPSE — the same distinction the vendor-PSIRT
  // gate draws between an empty inventory and an unreadable one.
  //
  // Zero mappings means nobody has expressed an intent yet. Denying there would
  // lock every existing LDAP install out of its own platform on the upgrade that
  // delivered this file — turning a security improvement into an outage, for
  // customers who did nothing wrong.
  //
  // ONE mapping means an administrator HAS expressed an intent, and a user
  // outside it is outside it. From that point the gate is closed.
  //
  // ⛔ LEGACY MODE IS A RAMP, NOT A RESTING STATE. It preserves the old
  // behaviour and says so loudly — on every login, and in Settings — because an
  // insecure default that nothing complains about is one nobody ever fixes.
  if (configured.length === 0) {
    return {
      role: ADMIN_ROLE,
      outcome: OUTCOME.LEGACY_NO_MAPPINGS,
      matched: [],
      reason: 'No LDAP group-to-role mappings are configured, so this directory user was granted '
        + 'Administrator — the behaviour of every release before mappings existed. Configure at '
        + 'least one mapping to close this: as soon as one exists, a user in no mapped group is '
        + 'refused.',
    };
  }

  // ⛔ UNREADABLE GROUPS IS NOT "NO GROUPS". If the directory search failed we do
  // not know what this person is entitled to, and guessing in the permissive
  // direction is how a read failure becomes an authorisation decision. This is
  // the one place in this file that fails CLOSED on an infrastructure problem,
  // because it is an AUTHORISATION check — the opposite call from the licence
  // guard, which fails open because it is only a billing one.
  if (groups === null || groups === undefined) {
    return {
      role: null,
      outcome: OUTCOME.GROUPS_UNREADABLE,
      matched: [],
      reason: 'The directory did not return this user\'s group membership, so no role could be '
        + 'determined. The login was refused rather than assigned a default.',
    };
  }

  const userGroups = new Set(
    (Array.isArray(groups) ? groups : [])
      .map(normaliseDn)
      .filter(Boolean)
  );

  const matched = [];
  let best = null;
  let bestRank = Number.POSITIVE_INFINITY;

  for (const m of configured) {
    if (!m || !isMappableRole(m.role)) continue;
    const key = normaliseDn(m.groupDn);
    if (!key || !userGroups.has(key)) continue;
    matched.push(m.groupDn);
    const rank = ROLE_RANK.indexOf(m.role);
    if (rank !== -1 && rank < bestRank) {
      bestRank = rank;
      best = m.role;
    }
  }

  if (!best) {
    return {
      role: null,
      outcome: OUTCOME.NO_MATCHING_GROUP,
      matched: [],
      reason: 'This directory user is not a member of any group mapped to a SecVault role, so the '
        + 'login was refused. Add a mapping for one of their groups to grant access.',
    };
  }

  return {
    role: best,
    outcome: OUTCOME.MAPPED,
    matched,
    reason: matched.length === 1
      ? `Granted ${best} by the mapping for ${matched[0]}.`
      : `Granted ${best} — the most privileged of ${matched.length} matching mappings.`,
  };
}

/**
 * Did this resolution permit the login?
 *
 * ⛔ A SEPARATE FUNCTION, not `!!role`, so the caller cannot accidentally treat
 * a null role as "logged in with no capabilities". An LDAP user who reached a
 * session holding no role would see every page deny them and conclude the
 * product is broken, which is a worse outcome than a clean refusal at the login
 * form.
 */
function isPermitted(resolution) {
  return !!(resolution && resolution.role && isMappableRole(resolution.role));
}

// ─────────────────────────────────────────────────────────────────────────────
// Storage
// ─────────────────────────────────────────────────────────────────────────────

/**
 * All configured mappings.
 *
 * ⛔ THROWS on a read failure rather than returning []. An empty array is an
 * INSTRUCTION here — it means "legacy mode, grant admin" — so returning it for
 * a failed read would turn a database blip into a fleet-wide grant of
 * Administrator to the entire directory. This is the failed-read-as-a-fact rule
 * at its most expensive.
 */
async function loadMappings(pool) {
  const { rows } = await pool.query(
    `SELECT id, group_dn, role, description, created_at, updated_at
       FROM ldap_role_mappings
      ORDER BY role, group_dn`
  );
  return rows.map((r) => ({
    id: r.id,
    groupDn: r.group_dn,
    role: r.role,
    description: r.description,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  }));
}

/** Add or update one mapping. Returns the stored row. */
async function upsertMapping(pool, { groupDn, role, description }) {
  if (!normaliseDn(groupDn)) throw new Error('A group DN is required.');
  if (!isMappableRole(role)) throw new Error(`'${role}' is not an assignable role.`);
  const { rows } = await pool.query(
    `INSERT INTO ldap_role_mappings (group_dn, group_dn_normalised, role, description)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (group_dn_normalised)
       DO UPDATE SET group_dn = EXCLUDED.group_dn,
                     role = EXCLUDED.role,
                     description = EXCLUDED.description,
                     updated_at = now()
     RETURNING id, group_dn, role, description`,
    [String(groupDn).trim(), normaliseDn(groupDn), role, description || null]
  );
  return rows[0];
}

async function deleteMapping(pool, id) {
  const { rowCount } = await pool.query('DELETE FROM ldap_role_mappings WHERE id = $1', [id]);
  return rowCount > 0;
}

module.exports = {
  OUTCOME,
  ROLE_RANK,
  normaliseDn,
  isMappableRole,
  resolveRole,
  isPermitted,
  loadMappings,
  upsertMapping,
  deleteMapping,
};
