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

/**
 * Load a session's device scope.
 *
 * ⛔ ONLY A LOCAL ACCOUNT CAN BE SCOPED TODAY, AND THAT IS STATED RATHER THAN
 * IMPLIED. `session.user.id` is a UUID with a `users` row for the local
 * provider and the bare username for LDAP, which has no row to hang a scope on
 * — the same shape check saved views already make. An LDAP account is therefore
 * UNSCOPED, and Settings says so rather than offering a control that would
 * silently do nothing.
 *
 * ⛔ A THROW BECOMES `unknown`, NOT `unscoped`. A database blip must not widen
 * anyone's access.
 */
async function loadScopeForSession(session, pool) {
  if (!session || !session.user) return { state: SCOPE_STATES.UNKNOWN, deviceIds: null };
  const id = session.user.id;

  // ⛔ THREE CASES, NOT TWO — an earlier version had two and fell open on the
  // third. A session carrying NO id at all took the same branch as an LDAP one
  // and was reported UNSCOPED, i.e. handed the whole fleet. That is not what
  // "this provider cannot be scoped" means; it is "we do not know who this is",
  // which is the definition of `unknown` and must deny.
  if (typeof id !== 'string' || id === '') {
    return { state: SCOPE_STATES.UNKNOWN, deviceIds: null };
  }
  const looksLocal = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
  // A non-empty, non-UUID id is an LDAP username: a real identity with no
  // `users` row to hang a scope on, so genuinely unscoped.
  if (!looksLocal) return { state: SCOPE_STATES.UNSCOPED, deviceIds: null };
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
