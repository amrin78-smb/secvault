'use strict';
//
// lib/deviceScope.js — WHICH firewalls may this account see?
//
// Until v2.168.0 the answer was always "all of them". That is correct for one
// organisation watching its own estate and is a hard cap on anything else: an
// MSP, a holding company, or simply "the Vietnam team sees Vietnam's
// firewalls". It is architectural, so the cost of not having it only grows.
//
// ⛔ THE DANGEROUS FAILURE HERE IS NOT "TOO LITTLE ACCESS", IT IS "LOOKS
// SCOPED, LEAKS ANYWAY". 104 non-test files in this repo read device data, and
// there is no single chokepoint they all pass through. A retrofit that covered
// sixty of them would produce a product that PRESENTS as scoped — an
// administrator creates a user restricted to two firewalls, the device list
// obeys it — while a report or a dashboard tile quietly shows the other
// fourteen. That is strictly worse than having no scoping at all, because the
// administrator has been given a reason to believe in a boundary that is not
// there.
//
// So the enforcement model is DEFAULT-DENY, not default-allow:
//
//   a SCOPED user is REFUSED by any surface that is not scope-aware yet.
//
// Partial coverage therefore degrades to LESS access, never more. A scoped
// account gets a smaller product that grows as surfaces are covered, and at no
// point does it see a firewall it was not granted. `lib/deviceScopeCoverage.js`
// is the register of which surfaces are covered, and a test fails the build
// when a new device-reading surface appears on neither list.
//
// ⛔ AN ACCOUNT WITH NO ROWS IS UNSCOPED, AND THAT IS NOT THE SAME AS AN
// ACCOUNT WITH NO DEVICES. Zero rows means nobody has expressed an intent for
// that account, so it keeps today's behaviour and sees the whole fleet — the
// same distinction `ldapRoles.js` draws between "no mappings configured" and
// "no mapping matched". Making an empty table mean deny would lock every
// existing installation out of its own platform on the deploy that delivers
// this, for customers who did nothing wrong.
//
// Pure except for the two loaders at the bottom, which take a pool.

// The three states a session's device scope can be in. ⛔ `unknown` is NOT a
// third flavour of allow: it is what a failed read produces, and every consumer
// treats it as deny. It exists as its own value so the REASON can be reported —
// "we could not determine your access" is a different sentence from "you do not
// have access", and an operator chasing the first should not be sent looking
// for a permission that was never the problem.
const SCOPE_STATES = Object.freeze({
  UNSCOPED: 'unscoped',
  SCOPED: 'scoped',
  UNKNOWN: 'unknown',
});

/**
 * Build a scope descriptor from an already-loaded row set.
 * Pure: takes rows, returns a verdict.
 *
 * @param {Array<{device_id: string}>|null} rows  null means the read FAILED
 * @returns {{state: string, deviceIds: string[]|null}}
 */
function scopeFromRows(rows) {
  // ⛔ null is a FAILED READ and is never an empty scope. `[]` means "this
  // account has no scope rows" (so: unscoped); `null` means "we do not know",
  // and guessing either way is wrong in a different direction.
  if (rows === null || rows === undefined) {
    return { state: SCOPE_STATES.UNKNOWN, deviceIds: null };
  }
  if (!Array.isArray(rows)) return { state: SCOPE_STATES.UNKNOWN, deviceIds: null };
  if (rows.length === 0) return { state: SCOPE_STATES.UNSCOPED, deviceIds: null };

  const ids = [];
  for (const r of rows) {
    const id = r && (r.device_id || r.deviceId);
    if (typeof id === 'string' && id) ids.push(id);
  }
  // ⛔ Rows that exist but carry no usable id are NOT an unscoped account.
  // Someone granted this user something; we failed to read what.
  if (ids.length === 0) return { state: SCOPE_STATES.UNKNOWN, deviceIds: null };
  return { state: SCOPE_STATES.SCOPED, deviceIds: Array.from(new Set(ids)) };
}

/** Is this session restricted to a subset of the fleet? */
function isScoped(scope) {
  return Boolean(scope) && scope.state === SCOPE_STATES.SCOPED;
}

/**
 * May this session see this device?
 *
 * ⛔ FAILS CLOSED on anything that is not a clean allow. An authorisation
 * check that degrades to "probably fine" is not a check — the same call
 * `rbac.js` makes for an unknown role and `ldapRoles.js` makes for unreadable
 * groups. (The licence guard fails OPEN and sits one line away in some routes;
 * the order there is deliberate and unchanged: authorisation first.)
 */
function canSeeDevice(scope, deviceId) {
  if (!scope || typeof deviceId !== 'string' || !deviceId) return false;
  if (scope.state === SCOPE_STATES.UNSCOPED) return true;
  if (scope.state !== SCOPE_STATES.SCOPED) return false; // unknown -> deny
  return Array.isArray(scope.deviceIds) && scope.deviceIds.includes(deviceId);
}

/**
 * Narrow a list of device rows to what this session may see.
 * ⛔ Returns [] for an unknown scope rather than the input — a failed read must
 * not pass the fleet through.
 */
function filterDevices(scope, devices) {
  const list = Array.isArray(devices) ? devices : [];
  if (!scope) return [];
  if (scope.state === SCOPE_STATES.UNSCOPED) return list;
  if (scope.state !== SCOPE_STATES.SCOPED) return [];
  return list.filter((d) => d && canSeeDevice(scope, d.id || d.device_id));
}

/**
 * A SQL fragment + params for narrowing a query, for the surfaces that filter
 * in the database rather than in JS.
 *
 * ⛔ PARAMETERISED, ALWAYS. The ids come from our own table and are UUIDs, and
 * interpolating them anyway would be the one place in this codebase where a
 * value reaching SQL as text is "fine because of where it came from" — which is
 * how that rule erodes.
 *
 * ⛔ An UNKNOWN scope yields a clause that matches NOTHING, never one that
 * matches everything. `FALSE` is the honest translation of "we could not
 * determine access".
 *
 * @param {object} scope
 * @param {string} column  the device-id column to constrain, e.g. 'd.id'
 * @param {number} nextParamIndex  1-based index of the next free $n
 */
function scopeSqlClause(scope, column, nextParamIndex) {
  if (!scope || scope.state === SCOPE_STATES.UNSCOPED) {
    return { sql: '', params: [] };
  }
  if (scope.state !== SCOPE_STATES.SCOPED) {
    return { sql: ' AND FALSE', params: [] };
  }
  return {
    sql: ` AND ${column} = ANY($${nextParamIndex}::uuid[])`,
    params: [scope.deviceIds],
  };
}

/**
 * The sentence a refused surface shows. ⛔ It names the state, because
 * "we could not determine your access" and "you were not granted this
 * firewall" send an operator to two different places.
 */
function refusalMessage(scope, what = 'this firewall') {
  if (scope && scope.state === SCOPE_STATES.UNKNOWN) {
    return `Your firewall access could not be determined, so ${what} is not being shown. `
      + 'This is a fault, not a permission — report it rather than requesting access.';
  }
  return `${what.charAt(0).toUpperCase()}${what.slice(1)} is outside the firewalls your account `
    + 'has been granted. Ask a Super Admin if you need it.';
}

// ── loaders (take a pool) ────────────────────────────────────────────────

// ⛔ WHICH PROVIDER MAY CARRY A SCOPE IS A LIST, NOT A SHAPE (v2.205.0).
// A scope row is `user_device_scopes.user_id UUID NOT NULL REFERENCES
// users(id)`, so only a provider that OWNS a `users` row can hold one.
//
// SCOPABLE   — has a `users` row; look the scope up.
// UNSCOPABLE — a real identity with no `users` row, so genuinely unscoped.
// anything else, including absent — UNKNOWN, which denies. A provider nobody
// has classified must never default into either answer: one of them hands over
// the whole fleet.
const SCOPABLE_PROVIDERS = new Set(['local']);
// ⛔ ENTRA JOINS LDAP HERE (v2.212.0), AND THIS IS A DELIBERATE TRADE, NOT A
// RELAXATION OF THE v2.205.0 FIX.
//
// What v2.205.0 forbade was DECIDING FROM THE SHAPE OF AN ID — an Entra `oid`
// is a GUID, so a shape test silently mistook it for a local account and handed
// over the whole fleet. Listing 'entra' here is the opposite act: an explicit
// classification, in the one place that holds them, with the same consequence
// LDAP has had for this product's entire life. The protection that mattered —
// an UNRECOGNISED provider still denies — is untouched.
//
// ⛔ THE COST IS REAL AND IS NOT HIDDEN: an Entra account CANNOT be restricted
// to specific firewalls. `user_device_scopes.user_id` is a foreign key to
// `users(id)` and a directory account has no such row, so there is nowhere to
// hang a scope. Every Entra user who resolves to a role therefore sees the
// whole fleet, exactly as every LDAP user already does. What they can DO with
// it is still governed by the group-to-role mapping.
//
// ⛔ THE ALTERNATIVE WAS WORSE, which is why this changed. Refusing left an
// Entra Super Admin looking at an empty product with a banner saying their
// account is "restricted to specific firewalls" — which was not true: nobody
// had restricted them, SecVault simply could not represent their identity.
// A refusal that misdescribes its own cause is worse than the limitation it
// is protecting against.
//
// ⛔ PHASE 3 OF .ai-codex/entra-sso-proposal.md REVERSES THIS by giving Entra
// accounts a local shadow row keyed on the `oid`, at which point 'entra' moves
// to SCOPABLE_PROVIDERS above. Until then, per-user firewall restriction is a
// LOCAL-ACCOUNT-ONLY feature and the Settings panel should say so.
const UNSCOPABLE_PROVIDERS = new Set(['ldap', 'entra']);

// Kept only as a CONTRADICTION CHECK on a provider that claims to be local.
// It is no longer how the decision is made — see the ⛔ block below.
const LOCAL_ID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Load a session's device scope.
 *
 * ⛔ THE DECISION IS `session.user.provider`, NEVER THE SHAPE OF THE ID — AND
 * THE SHAPE VERSION WAS A FAIL-OPEN WAITING FOR A THIRD PROVIDER (fixed
 * v2.205.0, Phase 0 of .ai-codex/entra-sso-proposal.md).
 *
 * This used to test the id against a UUID regex and treat any non-match as an
 * LDAP username. That works only while exactly two providers exist and their
 * id shapes happen to differ. **A Microsoft Entra `oid` is a GUID** and matches
 * that regex exactly, so an Entra account would have been read as LOCAL, its
 * `user_device_scopes` lookup would have returned zero rows (there is no
 * `users` row for it to have any), and zero rows is UNSCOPED — the entire
 * fleet, silently, with nothing on screen different. It could not have been
 * restricted even deliberately, because the insert would violate the foreign
 * key above.
 *
 * ⛔ The previous comment here said "THREE CASES, NOT TWO" and recorded an
 * earlier version falling open on the third. Entra was a FOURTH case the check
 * could not see, because it differs from a local account by PROVENANCE, not by
 * shape. A shape test cannot be made safe by adding more shapes; the provider
 * is the only thing that actually carries the fact.
 *
 * ⛔ A THROW BECOMES `unknown`, NOT `unscoped`. A database blip must not widen
 * anyone's access.
 */
async function loadScopeForSession(session, pool) {
  if (!session || !session.user) return { state: SCOPE_STATES.UNKNOWN, deviceIds: null };
  const { id, provider } = session.user;

  // ⛔ An unclassified or absent provider DENIES. `pageRefusal()` refuses every
  // `blocked` surface on `unknown`, so this is a loud failure rather than a
  // quiet one — which is the right direction for an authorisation check, and
  // the opposite of what the shape test did. It is logged because a guard that
  // starts firing for an unexpected reason must be traceable to this line
  // rather than looking like a permissions problem.
  if (typeof provider !== 'string' || provider === '') {
    console.warn('[deviceScope] session carries no provider; refusing scoped surfaces');
    return { state: SCOPE_STATES.UNKNOWN, deviceIds: null };
  }
  if (UNSCOPABLE_PROVIDERS.has(provider)) {
    return { state: SCOPE_STATES.UNSCOPED, deviceIds: null };
  }
  if (!SCOPABLE_PROVIDERS.has(provider)) {
    console.warn(`[deviceScope] unclassified provider '${provider}'; refusing scoped surfaces`);
    return { state: SCOPE_STATES.UNKNOWN, deviceIds: null };
  }

  // Local from here. An id that is absent, or not shaped like the UUID a
  // `users` row actually has, is a CONTRADICTION rather than another provider —
  // so it is `unknown` (deny), never `unscoped`.
  if (typeof id !== 'string' || id === '' || !LOCAL_ID_SHAPE.test(id)) {
    return { state: SCOPE_STATES.UNKNOWN, deviceIds: null };
  }
  try {
    const { rows } = await pool.query(
      'SELECT device_id FROM user_device_scopes WHERE user_id = $1',
      [id]
    );
    return scopeFromRows(rows);
  } catch (err) {
    console.warn(`[deviceScope] scope read failed for ${id}: ${err.message}`);
    return scopeFromRows(null);
  }
}

/**
 * May this account be restricted to specific firewalls at all?
 *
 * ⛔ AN ACCOUNT THAT CAN MANAGE USERS MAY NOT BE SCOPED.
 * /api/users/[id]/device-scope is itself a BLOCKED surface — it returns the
 * names of firewalls the caller may not hold — so a Super Admin who scoped
 * themselves, or scoped the last other Super Admin, would be refused by the
 * only endpoint that can undo it, from every account able to reach it. The
 * recovery is a direct database edit. That is precisely the failure the
 * last-super_admin guard in app/api/users/[id]/route.js exists to prevent, and
 * the authority being protected is the same one.
 *
 * ⛔ DECIDED ON THE CAPABILITY, NEVER THE WORD "admin". `admin` does not hold
 * manage_users and IS scopable — which is the common case, and the whole point
 * of the feature.
 *
 * ⛔ CLEARING a scope is always allowed. Zero rows means unscoped, so it can
 * only ever widen access and can never lock anyone out.
 *
 * @returns {string|null} the refusal sentence, or null to proceed
 */
function scopeAssignmentRefusal(targetRole, deviceIds) {
  const wanted = Array.isArray(deviceIds) ? deviceIds.filter(Boolean) : [];
  if (wanted.length === 0) return null;
  // Required lazily so this module stays importable from the edge-safe
  // deviceScopePaths chain without dragging rbac in at load time.
  const { capabilitiesOf, MANAGE_USERS } = require('./rbac');
  const caps = capabilitiesOf({ user: { role: targetRole } });
  if (!caps || !caps[MANAGE_USERS]) return null;
  return 'This account can manage user accounts, so it cannot be restricted to specific '
    + 'firewalls. Managing accounts means being able to see every account’s scope, and an '
    + 'account scoped out of that endpoint could never undo its own restriction. Change the '
    + 'role first if this account should be limited.';
}

/**
 * Which accounts would be left with NO device scope at all if this firewall
 * were deleted?
 *
 * ⛔ THE ANSWER IS AN ACCESS WIDENING, NOT A CLEAN-UP.
 * `user_device_scopes.device_id` is ON DELETE CASCADE and zero rows for a user
 * means UNSCOPED — the whole fleet. So removing the LAST firewall from an
 * account's scope does not reduce that account to nothing, it promotes it to
 * everything, silently, as a side effect of retiring an unrelated device.
 *
 * ⛔ THROWS RATHER THAN RETURNING [] ON A FAILED READ. `[]` here means "nobody
 * is affected, go ahead and delete", and a database error must never be able
 * to say that — the same rule the adapter contract applies to getRules().
 * Callers refuse the deletion on a throw; a delete is irreversible and the
 * safe answer to "we could not check" is "not yet".
 *
 * @returns {Promise<string[]>} usernames, alphabetical; empty means safe
 */
async function scopesEmptiedByDeviceDeletion(pool, deviceId) {
  if (typeof deviceId !== 'string' || !deviceId) {
    throw new Error('scopesEmptiedByDeviceDeletion: a device id is required');
  }
  const { rows } = await pool.query(
    `SELECT u.username
       FROM user_device_scopes uds
       JOIN users u ON u.id = uds.user_id
      WHERE uds.device_id = $1
        AND NOT EXISTS (
          SELECT 1 FROM user_device_scopes other
           WHERE other.user_id = uds.user_id
             AND other.device_id <> $1
        )
      ORDER BY u.username ASC`,
    [deviceId]
  );
  return rows.map((r) => r.username);
}

module.exports = {
  SCOPE_STATES,
  scopeAssignmentRefusal,
  scopesEmptiedByDeviceDeletion,
  scopeFromRows,
  isScoped,
  canSeeDevice,
  filterDevices,
  scopeSqlClause,
  refusalMessage,
  loadScopeForSession,
};
