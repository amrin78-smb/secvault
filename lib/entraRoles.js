// lib/entraRoles.js
//
// Microsoft Entra ID group-to-role resolution. Phase 1 of
// .ai-codex/entra-sso-proposal.md.
//
// ⛔ THE JUDGEMENT IS NOT REIMPLEMENTED. `ldapRoles.resolveRole` already
// answers "a directory says this person is in these groups — what role is
// that?", with most-privileged-match-wins and the matched-mapping report. None
// of that is LDAP-specific, and two files deciding the same thing would
// eventually disagree — with the wrong one granting access. This file owns
// only what is genuinely different about Entra:
//
//   1. the GROUP CLAIM, which can be absent for a reason that is not "no groups"
//   2. the ZERO-MAPPINGS call, which is the OPPOSITE of LDAP's
//
// Everything else delegates.

const ldapRoles = require('./ldapRoles');

/** Why an Entra login was refused, or which mapping granted it. */
const OUTCOME = {
  MAPPED: 'mapped',
  NOT_CONFIGURED: 'not_configured',
  NO_MAPPINGS: 'no_mappings',
  NO_MATCHING_GROUP: 'no_matching_group',
  GROUPS_UNREADABLE: 'groups_unreadable',
  GROUPS_OVERAGE: 'groups_overage',
};

// ⛔ THE OVERAGE IS THE DANGEROUS CASE, AND IT LOOKS EXACTLY LIKE INNOCENCE.
// Entra omits the `groups` claim once a user exceeds roughly 200 memberships
// and sends a `_claim_names` / `_claim_sources` pointer instead, to be followed
// with a Microsoft Graph call. Unhandled, the token simply has no `groups`
// array — which reads as "this user is in no groups" and resolves to no role.
//
// A user in 201 groups is not a user in zero. That substitution is this
// codebase's signature bug (a failed read recorded as an affirmative value),
// landing on the authorisation path, and it would hit the most heavily
// group-assigned accounts in a customer's directory — which in practice means
// their administrators.
const OVERAGE_KEYS = ['_claim_names', '_claim_sources'];

/**
 * Is this token telling us the group claim was TRUNCATED rather than empty?
 *
 * ⛔ Checked BEFORE the groups array is trusted. An overage token may carry no
 * `groups` key at all, or an empty one; neither means the user has no groups.
 */
function hasGroupOverage(claims) {
  if (!claims || typeof claims !== 'object') return false;
  for (const key of OVERAGE_KEYS) {
    const v = claims[key];
    if (v && typeof v === 'object' && Object.prototype.hasOwnProperty.call(v, 'groups')) {
      return true;
    }
  }
  return false;
}

/**
 * Extract group ids from an Entra id_token's claims.
 *
 * ⛔ THREE OUTCOMES, NOT TWO, and the third is the whole point:
 *   - an array            -> the groups, however many (possibly zero)
 *   - `null`              -> WE COULD NOT ASK. Overage, or a malformed claim.
 *                            Never "no groups".
 *   - an empty array      -> the directory genuinely reports no memberships
 *
 * `null` and `[]` must reach `resolveRole` as different things, exactly as
 * ldapRoles already requires ("UNREADABLE GROUPS IS NOT 'NO GROUPS'").
 *
 * @returns {{groups: string[]|null, overage: boolean}}
 */
function groupsFromClaims(claims) {
  if (!claims || typeof claims !== 'object') return { groups: null, overage: false };
  if (hasGroupOverage(claims)) return { groups: null, overage: true };

  const raw = claims.groups;
  if (raw === undefined || raw === null) return { groups: null, overage: false };
  if (!Array.isArray(raw)) return { groups: null, overage: false };

  // Entra emits group OBJECT IDs (GUIDs) by default. Non-string entries are
  // dropped rather than coerced -- a coerced "[object Object]" would be a
  // group id that can never match, i.e. a silent denial.
  const groups = raw.filter((g) => typeof g === 'string' && g.trim() !== '');
  return { groups, overage: false };
}

/**
 * Decide the role for an Entra user.
 *
 * @param {object} o
 * @param {object} o.claims    the id_token claims (or the profile)
 * @param {Array<{groupKey: string, role: string}>} o.mappings  entra mappings
 * @returns {{role: string|null, outcome: string, matched: string[], reason: string}}
 */
function resolveEntraRole({ claims, mappings }) {
  const configured = Array.isArray(mappings) ? mappings : [];
  const { groups, overage } = groupsFromClaims(claims);

  // ⛔ OVERAGE IS REFUSED, NOT GUESSED AT, and it is checked FIRST -- before
  // the zero-mappings branch -- because "we could not read this user's groups"
  // outranks every later question. Following the overage pointer needs a Graph
  // call (Phase 3); until that exists, the honest answer is a refusal that
  // NAMES the cause, so an administrator can act on it. Resolving to "no role"
  // would be indistinguishable from the user genuinely having none.
  if (overage) {
    return {
      role: null,
      outcome: OUTCOME.GROUPS_OVERAGE,
      matched: [],
      reason: 'Entra did not include this user\'s groups in the sign-in token because they are a '
        + 'member of too many groups (roughly 200+). SecVault cannot tell which groups they are '
        + 'in, so the sign-in was refused rather than guessed at. Fix this in Entra by setting '
        + 'the app registration to emit only groups ASSIGNED TO THE APPLICATION, which keeps the '
        + 'claim small.',
    };
  }

  // ⛔ UNREADABLE GROUPS FAIL CLOSED. Same call ldapRoles makes, and the
  // opposite of the licence guard one module over: this is an AUTHORISATION
  // check, not a billing one.
  if (groups === null) {
    return {
      role: null,
      outcome: OUTCOME.GROUPS_UNREADABLE,
      matched: [],
      reason: 'The sign-in token carried no readable group claim, so SecVault could not determine '
        + 'this user\'s access and refused the sign-in. Check that the app registration is '
        + 'configured to emit group claims.',
    };
  }

  // ⛔ ZERO MAPPINGS DENIES -- THE DELIBERATE OPPOSITE OF ldapRoles.
  //
  // LDAP treats an empty mapping table as "grant admin", because LDAP shipped
  // BEFORE mappings existed and making empty mean deny would have locked every
  // installed customer out of their own platform on the upgrade that delivered
  // it. That reasoning is sound and it does not transfer: SecVault has never
  // shipped Entra SSO, so there is no installed base to protect, and failing
  // open here would only create a hole. Exactly the call productLicense.js
  // makes about `modules` while the sibling suite apps fail open.
  if (configured.length === 0) {
    return {
      role: null,
      outcome: OUTCOME.NO_MAPPINGS,
      matched: [],
      reason: 'No Entra group-to-role mappings are configured, so no directory user can sign in '
        + 'yet. Map at least one Entra group to a SecVault role in Settings. (This is deliberately '
        + 'unlike LDAP, where an empty table preserves pre-existing access.)',
    };
  }

  // ⛔ DELEGATED, UNCHANGED. Most-privileged-match-wins, the matched list and
  // the comparison rules all come from ldapRoles. `groupDn` is that function's
  // field name; an Entra group id is simply what occupies it here.
  const resolved = ldapRoles.resolveRole({
    groups,
    mappings: configured.map((m) => ({ groupDn: m.groupKey, role: m.role })),
  });

  // The delegate cannot return its LEGACY_NO_MAPPINGS outcome, because the
  // zero case was handled above and never reaches it.
  if (resolved.role) {
    return { ...resolved, outcome: OUTCOME.MAPPED };
  }
  return {
    role: null,
    outcome: OUTCOME.NO_MATCHING_GROUP,
    matched: [],
    reason: 'This user is not in any Entra group mapped to a SecVault role.',
  };
}

/**
 * Is Entra SSO configured on this installation?
 *
 * ⛔ UNCONFIGURED IS NOT AN ERROR, AND NOT A BROKEN BUTTON. This product
 * installs on segmented and air-gapped networks -- the target customer, not an
 * edge case -- where login.microsoftonline.com is unreachable by design. With
 * no tenant configured the provider is never registered, so no sign-in button
 * renders and nothing is logged as a fault. Same contract as
 * CVE_HUB_LICENSE_KEY returning `notRun`.
 *
 * ⛔ ALL THREE VALUES ARE REQUIRED. A half-configured tenant would register a
 * button that cannot complete a sign-in, which is worse than no button: the
 * operator concludes the product is broken rather than that they have not
 * finished configuring it.
 */
function isEntraConfigured(env = process.env) {
  return Boolean(
    env.ENTRA_TENANT_ID && env.ENTRA_CLIENT_ID && env.ENTRA_CLIENT_SECRET
  );
}

module.exports = {
  OUTCOME,
  hasGroupOverage,
  groupsFromClaims,
  resolveEntraRole,
  isEntraConfigured,
};
