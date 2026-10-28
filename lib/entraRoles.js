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

/**
 * Why an Entra login was refused, or which mapping granted it.
 *
 * ⛔ EVERY MEMBER HERE IS RETURNED BY SOME INPUT, and a test proves it
 * (`tests/entraAuthRefusal.test.js`, "every OUTCOME is reachable"). This enum
 * used to carry a seventh, `NOT_CONFIGURED`, which NOTHING returned and
 * NOTHING read — a repo-wide grep found only its definition. It is removed
 * rather than kept "for completeness": a dead state in the enum that drives an
 * authorisation decision invites the next reader to branch on it believing it
 * fires, and a branch keyed on a value that can never arrive is a guard that
 * cannot fire. The condition it named is handled a layer up and differently —
 * `isEntraConfigured()` false means the provider is NEVER REGISTERED, so no
 * sign-in can reach this function at all.
 */
const OUTCOME = {
  MAPPED: 'mapped',
  NO_MAPPINGS: 'no_mappings',
  NO_MATCHING_GROUP: 'no_matching_group',
  GROUPS_UNREADABLE: 'groups_unreadable',
  GROUPS_OVERAGE: 'groups_overage',
  // ⛔ A SECVAULT FAULT, NOT A CUSTOMER MISCONFIGURATION, AND THE TWO WERE
  // COLLAPSED. The auth route seeded its outcome variable with
  // GROUPS_UNREADABLE and that value survived the catch around loadMappings —
  // so when PostgreSQL was unavailable the audit row and the Settings panel
  // told the administrator to "check that the app registration is configured
  // to emit group claims", pointing at Entra while the database was the
  // problem. Two causes, two completely different fixes, one label.
  MAPPINGS_UNREADABLE: 'mappings_unreadable',
  // ⛔ THE PLUMBING TRIPWIRE. See the usable-key check in resolveEntraRole.
  MAPPINGS_MALFORMED: 'mappings_malformed',
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
 * ⛔ `mappings` CARRY `groupDn`, THE SAME FIELD NAME `ldapRoles.resolveRole`
 * USES, AND THERE IS DELIBERATELY NO SECOND NAME FOR IT. This function used to
 * read `groupKey` and the auth route re-shaped every row
 * (`{ groupKey: m.groupDn, role: m.role }`) on the way in. Nothing validated
 * that the key had arrived, so the obvious future "simplification" — passing
 * `loadMappings`' rows straight through, exactly as the LDAP branch correctly
 * does — would have made every `normaliseDn(undefined)` null, skipped every
 * mapping, and REFUSED EVERY ENTRA USER PRODUCT-WIDE with
 * `NO_MATCHING_GROUP`: a reason that reads as the customer's directory being
 * wired wrong. No test would have failed. One name for one field removes the
 * shim; the usable-key check below makes the mistake loud if a shim ever
 * returns.
 *
 * @param {object} o
 * @param {object} o.claims    the id_token claims (or the profile)
 * @param {Array<{groupDn: string, role: string}>} o.mappings  entra mappings
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

  // ⛔ MAPPINGS EXIST BUT NOT ONE OF THEM CARRIES A GROUP — THAT IS OUR BUG,
  // AND IT MUST NOT WEAR THE CUSTOMER'S LABEL.
  //
  // `ldapRoles.resolveRole` skips a mapping whose key does not normalise, so a
  // whole table arriving without keys resolves to NO_MATCHING_GROUP — "this
  // user is in no mapped group", which sends an administrator to inspect a
  // directory that is perfectly correct while every single user is locked out.
  // A key cannot go missing from the database (`upsertMapping` refuses one and
  // the column is populated on every row), so the realistic cause is a
  // PLUMBING fault: a caller re-shaping rows onto the wrong field name. That
  // fault takes out EVERY mapping at once, which is exactly the shape tested
  // for here.
  //
  // ⛔ SOME-BUT-NOT-ALL IS SKIPPED, NOT REFUSED, deliberately: one damaged row
  // among five must not deny a user who genuinely matches one of the other
  // four, and that is already how an unmappable ROLE behaves in the delegate.
  // Only the total absence of a usable key is treated as a fault.
  const usable = configured.filter((m) => m && ldapRoles.normaliseDn(m.groupDn));
  if (usable.length === 0) {
    return {
      role: null,
      outcome: OUTCOME.MAPPINGS_MALFORMED,
      matched: [],
      reason: `${configured.length} Entra group mapping(s) are configured but none carries a `
        + 'readable group id, so no user can be matched against them. This is a SecVault fault, '
        + 'not a directory or app-registration problem — check the server log. Re-saving the '
        + 'mappings will not fix it.',
    };
  }

  // ⛔ DELEGATED, UNCHANGED. Most-privileged-match-wins, the matched list and
  // the comparison rules all come from ldapRoles. `groupDn` is that function's
  // field name; an Entra group OBJECT ID is simply what occupies it here, and
  // it is passed through under that same name rather than renamed.
  const resolved = ldapRoles.resolveRole({ groups, mappings: usable });

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
 * Did this resolution permit the sign-in?
 *
 * ⛔ A FUNCTION, NEVER `!!role`, and the auth route's Entra branch WAS `!!role`
 * — `token.role = again.role || null`, which is precisely the test
 * `ldapRoles.isPermitted` exists to prevent. It delegates rather than
 * re-deriving, so "permitted" cannot come to mean two different things in two
 * providers: the role must be present AND be a role a mapping is allowed to
 * grant, checked against `ASSIGNABLE_ROLES` rather than a local list.
 */
function isEntraPermitted(resolution) {
  return ldapRoles.isPermitted(resolution);
}

/**
 * ⛔ THE ONE ENTRA SIGN-IN DECISION. Both `callbacks.signIn` (the front door)
 * and `callbacks.jwt` (the per-request re-resolution) call THIS. They used to
 * be separate: `jwt()` resolved, logged `[entra] sign-in REFUSED`, wrote an
 * `entra_signin_refused` audit row — and then `return token`. There was no
 * `signIn` callback at all, so NextAuth's default `true` applied and the OAuth
 * sign-in COMPLETED. The log line and the audit row both asserted the opposite
 * of what the code did, and the refused account got a working session with
 * whole-fleet read access (`lib/deviceScope.js` lists `entra` as UNSCOPABLE, so
 * it is handed every firewall; GET routes are not RBAC-gated by design).
 *
 * ⛔ TWO PLACES DECIDING "MAY THIS PERSON IN" WILL EVENTUALLY DISAGREE, AND THE
 * WRONG ONE WILL BE THE ONE GRANTING ACCESS. Hence one helper and one
 * `isEntraPermitted`, rather than a second copy of the resolution in whichever
 * callback was added last.
 *
 * ⛔ ORDER: THE MAPPINGS ARE READ EVEN FOR A SIGN-IN THAT IS ALREADY DOOMED.
 * An overage or unreadable group claim is refused regardless of what the table
 * says, so the query is wasted work on those paths — but short-circuiting
 * ahead of `resolveEntraRole` would mean this function deciding the precedence
 * of the refusals TOO, in a second place, which is the duplication the whole
 * helper exists to avoid. One query on a refused sign-in is not worth that.
 *
 * ⛔ AN UNREADABLE MAPPING TABLE REFUSES. `ldapRoles.loadMappings` THROWS
 * rather than returning `[]` precisely so that an empty array keeps its
 * meaning, and here an empty array means DENY — so a database blip must not be
 * able to impersonate one. Note the corollary: when this fires because
 * PostgreSQL is unreachable, the `activity_log` INSERT that records the refusal
 * will fail for the same reason, so the SERVER LOG is the only record of it.
 *
 * @param {{query: Function}} pool
 * @param {object} claims  the Entra id_token claims captured at sign-in
 */
async function decideEntraAccess(pool, claims) {
  let mappings;
  try {
    mappings = await ldapRoles.loadMappings(pool, 'entra');
  } catch (err) {
    return {
      role: null,
      outcome: OUTCOME.MAPPINGS_UNREADABLE,
      matched: [],
      reason: 'The Entra group-to-role mappings could not be read from the SecVault database, so '
        + 'the sign-in was refused rather than guessed at. This is a DATABASE problem: check that '
        + 'PostgreSQL is running and look for connection errors in the server log. Nothing in the '
        + 'directory or in the sign-in token is at fault, and re-saving the mappings will not '
        + 'help.',
      // Carried for the caller's log line only. Never put in `reason`, which is
      // stored and displayed; a driver message is diagnostics, not an
      // instruction to an administrator.
      error: err && err.message ? err.message : String(err),
    };
  }
  return resolveEntraRole({ claims, mappings });
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
  isEntraPermitted,
  decideEntraAccess,
  isEntraConfigured,
};
