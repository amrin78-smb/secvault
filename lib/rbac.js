'use strict';

// lib/rbac.js
//
// Role-based access control. THREE roles, and a capability layer between the
// role and the route so that "what may this person do" is answered in one
// place rather than re-derived at 39 call sites.
//
//   super_admin   everything
//   admin         everything EXCEPT managing users and credential profiles
//   operator      day-to-day operational work only; no fleet or system
//                 administration, no identity data, no log search
//
// ⛔ WHY A CAPABILITY LAYER NOW, WHEN A BOOLEAN WAS DELIBERATE BEFORE. The old
// file argued — correctly, for two roles — that a coarse boundary is safer than
// a fine-grained one easy to get subtly wrong. That argument does not survive a
// third role: with three roles and one boolean, every route has to decide which
// side of the line each new role falls on, at the call site, from memory. The
// capability map makes each decision once, in a table a test can pin. The
// granularity is still deliberately COARSE — eight capabilities, not one per
// route — because the failure mode of a sprawling permission system is a hole
// nobody can see.
//
// ⛔ ADMIN CANNOT MANAGE USERS **AT ALL**, not merely "cannot create" them. The
// requirement was phrased as "cannot create new users or credential profiles",
// and create-only would be a hole rather than a boundary: editing another
// user's role or password achieves exactly what creating one does, and editing
// a credential profile lets you replace — and therefore learn the effect of —
// its stored secret. The capability covers create, update and delete together.
//
// ⛔ FAILS CLOSED, ALWAYS. No session, no user, an unrecognised role, or a role
// of null (which app/api/auth sets when the database is unreachable, rather
// than trusting a stale cached role) all resolve to NO capabilities. A legacy
// `viewer` row from the two-role era lands here too and behaves read-only,
// which is exactly what it always meant.
//
// Pure, dependency-free CommonJS: no pool, no session resolution, no imports.
// Every route resolves its own session via getServerSession(authOptions) and
// then asks this module. Keeping it dependency-free is what lets tests/ require
// it with no stubbing and avoids ESM/CJS interop risk in Next route files.

// ── roles ───────────────────────────────────────────────────────────────────
const SUPER_ADMIN_ROLE = 'super_admin';
const ADMIN_ROLE = 'admin';
const OPERATOR_ROLE = 'operator';

/**
 * The roles that may be ASSIGNED to a user. Order is most- to least-privileged
 * and is what the Users panel renders.
 *
 * ⛔ `viewer` is deliberately absent. It was the second role in the two-role
 * era, no account has ever used it on this deployment, and it is not offered.
 * A stray stored 'viewer' is not an error — it simply has no capabilities.
 */
const ASSIGNABLE_ROLES = [SUPER_ADMIN_ROLE, ADMIN_ROLE, OPERATOR_ROLE];

const ROLE_LABELS = {
  [SUPER_ADMIN_ROLE]: 'Super Admin',
  [ADMIN_ROLE]: 'Admin',
  [OPERATOR_ROLE]: 'Operator',
};

const ROLE_DESCRIPTIONS = {
  [SUPER_ADMIN_ROLE]: 'Full access, including user accounts and credential profiles.',
  [ADMIN_ROLE]: 'Full access to the fleet and settings. Cannot manage user accounts or credential profiles.',
  [OPERATOR_ROLE]:
    'Day-to-day operations: acknowledge findings, run analyses and collections, raise rule change '
    + 'requests. No device, user or system administration; no VPN identity data; no log search.',
};

// ── capabilities ────────────────────────────────────────────────────────────
//
// ⛔ Each capability is a JOB, not a route. When adding a route, pick the job it
// belongs to; only add a capability when a genuinely new kind of authority
// appears. Nine is a deliberate ceiling, not an accident.

/** Create, edit, delete user accounts and change their roles. */
const MANAGE_USERS = 'manage_users';
/** Create, edit, delete reusable credential profiles (they hold secrets). */
const MANAGE_CREDENTIAL_PROFILES = 'manage_credential_profiles';
/** Add/edit/delete firewalls, rotate their credentials, manage zones. */
const MANAGE_DEVICES = 'manage_devices';
/** Change application settings, including notification channels. */
const MANAGE_SETTINGS = 'manage_settings';
/** Trigger the in-app updater (restarts every service). */
const RUN_UPDATE = 'run_update';
/** Acknowledge findings, run analyses/collections, raise change requests. */
const OPERATE = 'operate';
/** See VPN data that names individual people. */
const VIEW_IDENTITY = 'view_identity';
/** Search raw syslog. */
const VIEW_LOG_SEARCH = 'view_log_search';
/**
 * Install, replace or remove the SecVault subscription key.
 *
 * ⛔ SEPARATE FROM MANAGE_SETTINGS, which `admin` holds. This is the COMMERCIAL
 * boundary, not an operational one: whoever can swap the licence key decides how
 * many firewalls the organisation is entitled to monitor and when the
 * subscription lapses. That belongs with whoever can also create accounts, not
 * with every administrator — the same reasoning that keeps MANAGE_USERS and
 * MANAGE_CREDENTIAL_PROFILES out of `admin`.
 */
const MANAGE_LICENSE = 'manage_license';

const ALL_CAPABILITIES = [
  MANAGE_USERS,
  MANAGE_CREDENTIAL_PROFILES,
  MANAGE_DEVICES,
  MANAGE_SETTINGS,
  RUN_UPDATE,
  OPERATE,
  VIEW_IDENTITY,
  VIEW_LOG_SEARCH,
  MANAGE_LICENSE,
];

/**
 * THE MATRIX. This table is the whole access-control policy; everything else in
 * this file is lookup. Pinned exhaustively by tests/rbac.test.js so a change
 * here fails a build rather than shipping quietly.
 *
 * ⛔ Capabilities are listed EXPLICITLY per role rather than derived by
 * subtraction from ALL_CAPABILITIES. A new capability added to the list must
 * therefore be granted deliberately to each role — it cannot leak into `admin`
 * by default, which is what "everything except X" would do.
 */
const ROLE_CAPABILITIES = {
  [SUPER_ADMIN_ROLE]: [
    MANAGE_USERS,
    MANAGE_CREDENTIAL_PROFILES,
    MANAGE_DEVICES,
    MANAGE_SETTINGS,
    RUN_UPDATE,
    OPERATE,
    VIEW_IDENTITY,
    VIEW_LOG_SEARCH,
    MANAGE_LICENSE,
  ],
  [ADMIN_ROLE]: [
    // ⛔ No MANAGE_USERS, no MANAGE_CREDENTIAL_PROFILES, no MANAGE_LICENSE.
    // Everything else.
    MANAGE_DEVICES,
    MANAGE_SETTINGS,
    RUN_UPDATE,
    OPERATE,
    VIEW_IDENTITY,
    VIEW_LOG_SEARCH,
  ],
  [OPERATOR_ROLE]: [
    // ⛔ OPERATE only. No administration of any kind, no identity data, no log
    // search. An operator can act on what the engines found; they cannot change
    // what the product watches or who can use it.
    OPERATE,
  ],
};

// ── resolution ──────────────────────────────────────────────────────────────

/**
 * The role on a session, or null. Never throws, never guesses.
 */
function roleOf(session) {
  if (!session || typeof session !== 'object') return null;
  const user = session.user;
  if (!user || typeof user !== 'object') return null;
  const role = user.role;
  return typeof role === 'string' && role.length > 0 ? role : null;
}

/**
 * THE ONE CHECK. `can(session, MANAGE_USERS)`.
 *
 * ⛔ Unknown role -> false. Unknown capability -> false. Both directions matter:
 * a typo'd capability string must DENY, never accidentally match, so this never
 * falls back to "allow if we don't recognise the question".
 */
function can(session, capability) {
  if (typeof capability !== 'string' || !ALL_CAPABILITIES.includes(capability)) return false;
  const role = roleOf(session);
  if (!role) return false;
  const granted = ROLE_CAPABILITIES[role];
  if (!Array.isArray(granted)) return false; // legacy 'viewer', or anything else
  return granted.includes(capability);
}

/** Every capability a session holds — for handing the UI one object. */
function capabilitiesOf(session) {
  const role = roleOf(session);
  // ⛔ OWN PROPERTY ONLY, AND Array.isArray — the same guard can() already uses.
  //
  // `ROLE_CAPABILITIES[role]` reaches the prototype chain, so a role string of
  // 'constructor', 'toString' or 'valueOf' returned a truthy NON-ARRAY and
  // `granted.includes` threw TypeError. can() handles this correctly and
  // returns false; this function was the single asymmetry in a module whose
  // whole contract is that every unrecognised input fails CLOSED — and it
  // throws inside the call that builds the UI's capability object, so the
  // failure mode is a 500 on page render rather than a denial.
  //
  // Not reachable today (roles are validated against ASSIGNABLE_ROLES on write
  // and re-read from the database), but "not reachable today" is not the
  // standard this file holds itself to anywhere else.
  const granted = Object.prototype.hasOwnProperty.call(ROLE_CAPABILITIES, role)
    ? ROLE_CAPABILITIES[role]
    : [];
  const safe = Array.isArray(granted) ? granted : [];
  const out = {};
  for (const cap of ALL_CAPABILITIES) out[cap] = safe.includes(cap);
  return out;
}

/**
 * LEGACY ALIAS, kept so the routes that have not been given a more specific
 * capability keep their exact previous meaning: "may administer the fleet".
 *
 * ⛔ Deliberately mapped to MANAGE_DEVICES, which super_admin and admin hold and
 * operator does NOT. That makes the introduction of `operator` a pure
 * restriction: every route still on isAdmin() denies operators by default, and
 * each is opened up only by a deliberate edit. Prefer can() in new code.
 */
function isAdmin(session) {
  return can(session, MANAGE_DEVICES);
}

/** True for the top role only. */
function isSuperAdmin(session) {
  return roleOf(session) === SUPER_ADMIN_ROLE;
}

/** Is this a role we are willing to store on a user? */
function isAssignableRole(role) {
  return ASSIGNABLE_ROLES.includes(role);
}

/**
 * Standard 403. The message names the capability when one is given, because
 * "Forbidden — admin role required" was actively misleading once three roles
 * existed: an operator denied a settings write is not missing "admin", they are
 * missing that specific authority.
 */
function forbiddenResponse(capability) {
  const detail = capability && ALL_CAPABILITIES.includes(capability)
    ? `Forbidden — this action requires the "${capability}" permission`
    : 'Forbidden — you do not have permission to perform this action';
  return new Response(
    JSON.stringify({ error: detail, required: capability || null }),
    { status: 403, headers: { 'Content-Type': 'application/json' } }
  );
}

module.exports = {
  // roles
  SUPER_ADMIN_ROLE,
  ADMIN_ROLE,
  OPERATOR_ROLE,
  ASSIGNABLE_ROLES,
  ROLE_LABELS,
  ROLE_DESCRIPTIONS,
  // capabilities
  MANAGE_USERS,
  MANAGE_CREDENTIAL_PROFILES,
  MANAGE_DEVICES,
  MANAGE_SETTINGS,
  RUN_UPDATE,
  OPERATE,
  VIEW_IDENTITY,
  VIEW_LOG_SEARCH,
  MANAGE_LICENSE,
  ALL_CAPABILITIES,
  ROLE_CAPABILITIES,
  // checks
  roleOf,
  can,
  capabilitiesOf,
  isAdmin,
  isSuperAdmin,
  isAssignableRole,
  forbiddenResponse,
};
