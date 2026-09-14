'use strict';
// Pins the three-role RBAC model (v2.110.0): super_admin / admin / operator.
//
// WHY THIS FILE IS DIFFERENT FROM THE OTHER TESTS HERE. Everything else in
// tests/ guards against a wrong NUMBER. This guards against a wrong ANSWER to
// "may this person do that", where the failure is silent, invisible in the UI,
// and only discovered by someone doing something they should not have been able
// to do. There is no log line for a permission that was too generous.
//
// Three classes of failure are pinned:
//
//   1. THE MATRIX ITSELF, exhaustively — every role against every capability,
//      asserted as a complete table rather than spot-checked. A capability
//      added to ALL_CAPABILITIES without a deliberate grant decision fails
//      here, which is the point: "everything except X" must never be expressed
//      by subtraction, or the next capability leaks into `admin` by default.
//   2. FAILING CLOSED — no session, no user, a null role (what the auth layer
//      sets when the database is unreachable), an unknown role, and a legacy
//      `viewer` row from the two-role era all get NOTHING.
//   3. STRUCTURAL — every mutating API route still has a guard, by repo scan.
//      A new route with no check is the realistic way this regresses; nobody
//      removes an existing guard, they forget to add one.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const rbac = require('../lib/rbac');
const {
  SUPER_ADMIN_ROLE, ADMIN_ROLE, OPERATOR_ROLE,
  ASSIGNABLE_ROLES, ALL_CAPABILITIES, ROLE_CAPABILITIES,
  MANAGE_USERS, MANAGE_CREDENTIAL_PROFILES, MANAGE_DEVICES, MANAGE_SETTINGS,
  RUN_UPDATE, OPERATE, VIEW_IDENTITY, VIEW_LOG_SEARCH,
  can, roleOf, capabilitiesOf, isAdmin, isSuperAdmin, isAssignableRole,
} = rbac;

const sessionFor = (role) => ({ user: { id: 'u1', name: 'x', role } });

describe('the capability matrix, asserted in full', () => {
  // ⛔ Written out as a literal table rather than derived from the source, so a
  // change to ROLE_CAPABILITIES must be MIRRORED here deliberately. A test that
  // computed the expectation from the thing under test would pass for any
  // matrix at all.
  const EXPECTED = {
    [SUPER_ADMIN_ROLE]: {
      manage_users: true,
      manage_credential_profiles: true,
      manage_devices: true,
      manage_settings: true,
      run_update: true,
      operate: true,
      view_identity: true,
      view_log_search: true,
    },
    [ADMIN_ROLE]: {
      manage_users: false,              // ⛔ the whole point of the role
      manage_credential_profiles: false, // ⛔ likewise
      manage_devices: true,
      manage_settings: true,
      run_update: true,
      operate: true,
      view_identity: true,
      view_log_search: true,
    },
    [OPERATOR_ROLE]: {
      manage_users: false,
      manage_credential_profiles: false,
      manage_devices: false,
      manage_settings: false,
      run_update: false,
      operate: true,                     // ⛔ the only thing an operator may do
      view_identity: false,
      view_log_search: false,
    },
  };

  for (const role of ASSIGNABLE_ROLES) {
    for (const cap of ALL_CAPABILITIES) {
      it(`${role} ${EXPECTED[role][cap] ? 'CAN' : 'cannot'} ${cap}`, () => {
        assert.equal(can(sessionFor(role), cap), EXPECTED[role][cap]);
      });
    }
  }

  it('covers every capability that exists — no capability is untested', () => {
    for (const role of ASSIGNABLE_ROLES) {
      assert.deepEqual(
        Object.keys(EXPECTED[role]).sort(),
        [...ALL_CAPABILITIES].sort(),
        `${role} is missing an expectation for a capability that exists`
      );
    }
  });

  it('grants are listed explicitly, never derived by subtraction', () => {
    // admin must not simply be "everything minus two" computed at runtime.
    const adminGrants = ROLE_CAPABILITIES[ADMIN_ROLE];
    assert.ok(Array.isArray(adminGrants));
    assert.equal(adminGrants.includes(MANAGE_USERS), false);
    assert.equal(adminGrants.includes(MANAGE_CREDENTIAL_PROFILES), false);
    assert.equal(adminGrants.length, ALL_CAPABILITIES.length - 2);
  });
});

describe('⛔ fails closed', () => {
  const DENIED = [
    ['no session', null],
    ['undefined session', undefined],
    ['session with no user', {}],
    ['user with no role', { user: {} }],
    ['null role (database unreachable)', { user: { role: null } }],
    ['empty-string role', { user: { role: '' } }],
    ['unknown role', { user: { role: 'root' } }],
    ['legacy viewer row', { user: { role: 'viewer' } }],
    ['role as a non-string', { user: { role: { admin: true } } }],
  ];

  for (const [label, session] of DENIED) {
    it(`${label} gets NO capabilities`, () => {
      for (const cap of ALL_CAPABILITIES) {
        assert.equal(can(session, cap), false, `${label} unexpectedly has ${cap}`);
      }
      assert.equal(isAdmin(session), false);
      assert.equal(isSuperAdmin(session), false);
    });
  }

  it('an unrecognised capability string is DENIED, never allowed', () => {
    // A typo'd capability must fail shut. If can() fell through to "allow when
    // we do not recognise the question", one mistyped constant would open a
    // route to everyone.
    for (const role of ASSIGNABLE_ROLES) {
      assert.equal(can(sessionFor(role), 'manage_userz'), false);
      assert.equal(can(sessionFor(role), ''), false);
      assert.equal(can(sessionFor(role), null), false);
      assert.equal(can(sessionFor(role), undefined), false);
    }
  });

  it('never throws on malformed input', () => {
    for (const bad of [null, undefined, 0, '', [], 'session', { user: 1 }]) {
      assert.doesNotThrow(() => can(bad, OPERATE));
      assert.doesNotThrow(() => roleOf(bad));
      assert.doesNotThrow(() => capabilitiesOf(bad));
    }
  });
});

describe('the legacy isAdmin() alias', () => {
  it('still means "may administer the fleet" — super_admin and admin only', () => {
    assert.equal(isAdmin(sessionFor(SUPER_ADMIN_ROLE)), true);
    assert.equal(isAdmin(sessionFor(ADMIN_ROLE)), true);
    // ⛔ The load-bearing one. Every route not yet given a specific capability
    // is still on isAdmin(), so this false is what makes introducing `operator`
    // a pure restriction rather than a silent grant across ~20 routes.
    assert.equal(isAdmin(sessionFor(OPERATOR_ROLE)), false);
  });

  it('isSuperAdmin is the only check that separates the top two roles', () => {
    assert.equal(isSuperAdmin(sessionFor(SUPER_ADMIN_ROLE)), true);
    assert.equal(isSuperAdmin(sessionFor(ADMIN_ROLE)), false);
  });
});

describe('assignable roles', () => {
  it('is exactly the three roles, most privileged first', () => {
    assert.deepEqual(ASSIGNABLE_ROLES, [SUPER_ADMIN_ROLE, ADMIN_ROLE, OPERATOR_ROLE]);
  });

  it('⛔ does NOT offer viewer', () => {
    assert.equal(isAssignableRole('viewer'), false);
    assert.equal(ASSIGNABLE_ROLES.includes('viewer'), false);
  });

  it('rejects anything not in the list', () => {
    for (const bad of ['root', 'Admin', 'SUPER_ADMIN', '', null, undefined]) {
      assert.equal(isAssignableRole(bad), false);
    }
  });

  it('every assignable role has a label and a description', () => {
    for (const role of ASSIGNABLE_ROLES) {
      assert.equal(typeof rbac.ROLE_LABELS[role], 'string');
      assert.ok(rbac.ROLE_LABELS[role].length > 0);
      assert.equal(typeof rbac.ROLE_DESCRIPTIONS[role], 'string');
    }
  });
});

describe('capabilitiesOf returns a complete object', () => {
  it('contains every capability as an explicit boolean', () => {
    const caps = capabilitiesOf(sessionFor(OPERATOR_ROLE));
    assert.deepEqual(Object.keys(caps).sort(), [...ALL_CAPABILITIES].sort());
    for (const v of Object.values(caps)) assert.equal(typeof v, 'boolean');
  });

  it('an unknown role yields all-false, not an empty object', () => {
    // ⛔ The UI does `capabilities[x]` — an empty object would be undefined,
    // which is falsy and therefore safe, but an explicit false is what makes
    // the shape checkable.
    const caps = capabilitiesOf({ user: { role: 'nope' } });
    assert.equal(Object.keys(caps).length, ALL_CAPABILITIES.length);
    assert.equal(Object.values(caps).some(Boolean), false);
  });
});

describe('403 responses name the missing authority', () => {
  it('includes the capability when given one', async () => {
    const res = rbac.forbiddenResponse(MANAGE_USERS);
    assert.equal(res.status, 403);
    const body = await res.json();
    assert.equal(body.required, MANAGE_USERS);
    assert.match(body.error, /manage_users/);
  });

  it('degrades to a generic message rather than lying about the reason', async () => {
    // ⛔ The old message was "admin role required", which with three roles is
    // actively wrong: an operator denied a settings write is not missing
    // "admin", they are missing that specific authority.
    const res = rbac.forbiddenResponse();
    const body = await res.json();
    assert.equal(body.required, null);
    assert.doesNotMatch(body.error, /admin role required/);
  });
});

// ── structural: the guards actually exist on disk ──────────────────────────
describe('every mutating API route is guarded', () => {
  const API = path.join(__dirname, '..', 'app', 'api');

  function walk(dir, out) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full, out);
      else if (e.name === 'route.js') out.push(full);
    }
    return out;
  }

  const ROUTES = walk(API, []);

  // Routes that mutate nothing, or authenticate rather than authorise.
  // Matched on the directory NAME rather than a full path: route folders sit
  // under dynamic segments like devices/[id]/, so a joined prefix does not match.
  const EXEMPT = [
    '[...nextauth]',   // the login endpoint itself, not an authorisation surface
    'access-path',     // documented in CLAUDE.md: computes, persists nothing
    'path-query',      // documented: computes, persists nothing
    'saved-views',     // documented: a user's OWN bookmark, owner-scoped in SQL
    // ⛔ SELF-SERVICE MFA. Acts on session.user.id and NEVER on a body
    // parameter, so there is no user id in any request shape it accepts — the
    // authorisation is structural rather than a check that could be forgotten.
    // An Operator must be able to protect their own account; requiring an
    // administrative capability would leave the least privileged users the
    // least able to secure themselves. The ADMIN path over another account
    // (app/api/users/[id]/mfa) is separately gated on MANAGE_USERS.
    ['api','mfa','route.js'].join(path.sep),
  ];

  it('scans a meaningful number of routes', () => {
    assert.ok(ROUTES.length > 40, 'expected >40 route files, got ' + ROUTES.length);
  });

  it('⛔ no mutating handler lacks a capability check', () => {
    const offenders = [];
    for (const file of ROUTES) {
      const rel = path.relative(path.join(__dirname, '..'), file);
      if (EXEMPT.some((e) => rel.includes(e))) continue;
      const src = fs.readFileSync(file, 'utf8');
      const mutates = /export async function (POST|PUT|PATCH|DELETE)/.test(src);
      if (!mutates) continue;
      const guarded = /can\(session,\s*[A-Z_]+\)/.test(src) || /isAdmin\(session\)/.test(src);
      if (!guarded) offenders.push(rel);
    }
    assert.deepEqual(offenders, [],
      'mutating routes with no RBAC guard:\n  ' + offenders.join('\n  '));
  });

  it('⛔ every capability named in a route actually exists', () => {
    // A typo'd constant imports as undefined, and `can(session, undefined)`
    // denies — safe, but it denies EVERYONE including super_admin, which
    // presents as "the button is broken" rather than "you lack permission".
    const offenders = [];
    for (const file of ROUTES) {
      const src = fs.readFileSync(file, 'utf8');
      for (const m of src.matchAll(/can\(session,\s*([A-Z_]+)\)/g)) {
        const constName = m[1];
        if (rbac[constName] === undefined || !ALL_CAPABILITIES.includes(rbac[constName])) {
          offenders.push(path.relative(path.join(__dirname, '..'), file) + ' -> ' + constName);
        }
      }
    }
    assert.deepEqual(offenders, [], 'routes referencing a non-existent capability:\n  ' + offenders.join('\n  '));
  });

  it('the user and credential-profile routes require the super-admin capabilities', () => {
    const checks = [
      ['users', MANAGE_USERS],
      ['credential-profiles', MANAGE_CREDENTIAL_PROFILES],
    ];
    for (const [dir, cap] of checks) {
      const files = ROUTES.filter((f) => f.includes(path.sep + dir + path.sep));
      assert.ok(files.length > 0, 'no route files found for ' + dir);
      for (const f of files) {
        const src = fs.readFileSync(f, 'utf8');
        assert.match(src, new RegExp('can\\(session,\\s*' + cap.toUpperCase() + '\\)'),
          path.basename(path.dirname(f)) + '/route.js does not require ' + cap);
      }
    }
  });
});

describe('the UI never hardcodes a role list', () => {
  // ⛔ FOUND LIVE AT v2.110.0. UsersPanel had TWO role dropdowns — the per-row
  // one and the create-user form — and only the first was migrated. The second
  // still offered `viewer`, so the form looked correct and would have silently
  // created an Operator instead (the server coerces an unassignable role to the
  // least-privileged one). A hardcoded list drifts; ASSIGNABLE_ROLES cannot.
  const UI_DIRS = ['components', 'app'];

  function walk(dir, out) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === 'node_modules' || e.name === '.next') continue;
        walk(full, out);
      } else if (e.name.endsWith('.js')) out.push(full);
    }
    return out;
  }

  const FILES = UI_DIRS.flatMap((d) => walk(path.join(__dirname, '..', d), []));

  it('scans a meaningful number of UI files', () => {
    assert.ok(FILES.length > 150, 'expected >150 files, got ' + FILES.length);
  });

  it('⛔ no <option> hardcodes a role value', () => {
    const offenders = [];
    for (const file of FILES) {
      const src = fs.readFileSync(file, 'utf8');
      for (const m of src.matchAll(/<option value="(super_admin|admin|operator|viewer)"/g)) {
        offenders.push(path.relative(path.join(__dirname, '..'), file) + ' -> ' + m[1]);
      }
    }
    assert.deepEqual(offenders, [],
      'role <option> values must come from ASSIGNABLE_ROLES:\n  ' + offenders.join('\n  '));
  });

  it('⛔ no UI file still references the retired viewer role', () => {
    const offenders = [];
    for (const file of FILES) {
      const src = fs.readFileSync(file, 'utf8')
        .replace(/\/\*[\s\S]*?\*\//g, ' ')
        .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
      if (/['"]viewer['"]/.test(src)) {
        offenders.push(path.relative(path.join(__dirname, '..'), file));
      }
    }
    assert.deepEqual(offenders, [], 'viewer role still referenced in UI code:\n  ' + offenders.join('\n  '));
  });

  it('⛔ a role is never displayed by raw string transform', () => {
    // `textTransform: capitalize` turned `super_admin` into "Super_admin" in the
    // header. Roles are shown through ROLE_LABELS or not at all.
    const offenders = [];
    for (const file of FILES) {
      const src = fs.readFileSync(file, 'utf8');
      if (/textTransform:\s*'capitalize'[^}]*\}\}>\{role\}/.test(src)) {
        offenders.push(path.relative(path.join(__dirname, '..'), file));
      }
    }
    assert.deepEqual(offenders, [], 'raw role string rendered:\n  ' + offenders.join('\n  '));
  });
});

describe('⛔ capabilitiesOf fails CLOSED like can()', () => {
  // The single asymmetry in an otherwise uniformly fail-closed module:
  // ROLE_CAPABILITIES[role] reaches the prototype chain, so a role string of
  // 'constructor' returned a truthy non-array and .includes threw TypeError —
  // a 500 while building the UI's capability object, rather than a denial.
  for (const role of ['constructor', 'toString', 'valueOf', 'hasOwnProperty', '__proto__']) {
    it(`a role named '${role}' grants nothing and does not throw`, () => {
      const session = { user: { role } };
      const caps = capabilitiesOf(session);
      assert.equal(Object.values(caps).some(Boolean), false, 'no capability may be granted');
      assert.equal(can(session, OPERATE), false);
    });
  }

  it('agrees with can() for every assignable role', () => {
    // The two must never disagree: one gates the API, the other draws the UI,
    // and a UI gate stricter than its route reads to the operator as a broken
    // product rather than as a permission boundary.
    for (const role of ASSIGNABLE_ROLES) {
      const session = { user: { role } };
      const caps = capabilitiesOf(session);
      for (const cap of ALL_CAPABILITIES) {
        assert.equal(caps[cap], can(session, cap), `${role}/${cap} disagrees`);
      }
    }
  });
});

describe('⛔ the last Super Admin cannot be removed OR demoted', () => {
  // This guard had NO test, and shipped broken in both halves: it referenced an
  // identifier that was never imported (so it threw and 500'd, never once
  // executing), and underneath that it compared against the wrong role — so the
  // obvious one-line fix would have OPENED the hole rather than closing it.
  // Demoting the last super_admin to `admin` skipped the check entirely and
  // left an installation where nobody holds MANAGE_USERS, recoverable only by
  // a direct database edit.
  // ⛔ COMMENTS STRIPPED FIRST. The fix for this guard documents the old broken
  // comparison verbatim in a comment, so a naive source scan matches the
  // explanation rather than the code and reports a bug that was already fixed.
  // A source-scanning test has to read what RUNS, not what is written about it.
  const rawRouteSrc = require('fs').readFileSync(
    require.resolve('../app/api/users/[id]/route.js'), 'utf8'
  );
  const routeSrc = rawRouteSrc
    .split('\n')
    .filter((l) => !l.trim().startsWith('//'))
    .join('\n');

  it('compares against SUPER_ADMIN_ROLE, never ADMIN_ROLE', () => {
    assert.equal(
      /targetRole === ADMIN_ROLE/.test(routeSrc), false,
      'a target being set to `admin` must NOT count as still holding super_admin'
    );
    assert.ok(
      routeSrc.includes('targetRole === SUPER_ADMIN_ROLE'),
      'the survivor test must follow the capability, not the word "admin"'
    );
  });

  it('runs the guard for ANY role change away from super_admin, including to admin', () => {
    assert.equal(
      /nextRole !== ADMIN_ROLE/.test(routeSrc), false,
      'skipping the check when the new role is `admin` is the demotion hole'
    );
    assert.ok(routeSrc.includes('nextRole !== SUPER_ADMIN_ROLE'));
  });

  it('every role identifier it uses is actually imported', () => {
    // The defect that made this unexecutable. ESM is strict mode, so a free
    // variable is a ReferenceError at call time, not a load-time failure —
    // which is why it passed every static check and every build.
    const importLine = routeSrc.split('\n').find((l) => l.includes("from '../../../../lib/rbac'"));
    assert.ok(importLine, 'the rbac import must exist');
    for (const ident of routeSrc.match(/\b[A-Z][A-Z_]*_ROLE\b/g) || []) {
      assert.ok(importLine.includes(ident), `${ident} is used but never imported`);
    }
  });
});
