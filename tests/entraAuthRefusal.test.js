// tests/entraAuthRefusal.test.js
//
// ⛔ THE ENTRA SIGN-IN PATH HAD NO TESTS AT ALL, AND THAT ASYMMETRY IS HOW THE
// DEFECT SHIPPED. The LDAP equivalents are pinned — including "refuses the
// login when the mapping table cannot be read" — while `entraClaims`,
// `entraOutcome`, `entra_signin_refused` and `provider === 'entra'` had zero
// hits anywhere under tests/. So the Entra branch of jwt() could compute a
// refusal, log it, write it to activity_log and then complete the sign-in, for
// thirty versions, with a green suite.
//
// ⛔ WHAT IS PINNED HERE IS THE OUTCOME, NOT THE MECHANISM. This repo has
// shipped three features that passed tests asserting a line of code existed
// while the behaviour was broken (the MFA field's default, the `hidden`
// attribute, cveHub's freshness `errors.push`). So:
//
//   - the DECISION is driven through its real function with a stub pool
//   - `callbacks.signIn` is CALLED and its return value asserted
//   - `middleware()` is CALLED with a real encrypted NextAuth cookie and a real
//     NextRequest, and the HTTP response is read
//
// The route and middleware are ESM with extensionless imports and a bare
// `next/server`, neither of which plain node resolves, so they are compiled on
// require with the same `next/dist/build/swc` hook tests/applicationRoutes.test.js
// already uses. That adds no devDependency (package.json has none) and it runs
// the SHIPPED SOURCE — never a copy of its logic.

const { it, describe, before } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

// Required BEFORE the compile hook is installed, so the pure modules load as
// the plain CommonJS they are.
const entraRoles = require('../lib/entraRoles');
const ldapRoles = require('../lib/ldapRoles');
const { ADMIN_ROLE, OPERATOR_ROLE, SUPER_ADMIN_ROLE } = require('../lib/rbac');

const REPO = path.join(__dirname, '..');
const G_ADMIN = '8f4a1c2e-9b7d-4e6a-bc13-5d2f70a9e4c1';
const G_OPS = '1b2c3d4e-5f60-4718-9a2b-3c4d5e6f7081';

// ─────────────────────────────────────────────────────────────────────────────
// A stub pool, shaped like the real reads
// ─────────────────────────────────────────────────────────────────────────────
//
// ⛔ IT ROUTES ON THE SQL, so `loadMappings` and `logActivity` can both be
// observed from one object — the auth route holds a single module-level `pool`
// and neither call is injectable.

/**
 * @param {{mappings?: Array|Error}} o  rows for ldap_role_mappings, or an Error
 *                                      to throw (the unreadable-database case)
 */
function stubPool({ mappings = [] }) {
  const audit = [];
  const seen = [];
  return {
    audit,
    seen,
    async query(sql, params) {
      seen.push({ sql: String(sql), params });
      if (/ldap_role_mappings/.test(sql)) {
        if (mappings instanceof Error) throw mappings;
        return { rows: mappings };
      }
      if (/INSERT INTO activity_log/i.test(sql)) {
        audit.push({ action: params[1], detail: params[3], actor: params[0] });
        return { rows: [] };
      }
      // Anything else is a read this path should not be making.
      throw new Error(`unexpected query in the Entra sign-in path: ${String(sql).slice(0, 60)}`);
    },
  };
}

// ⛔ A DATABASE ROW, IN THE DATABASE'S OWN SPELLING. `loadMappings` is what
// maps snake_case to camelCase, and it is under test here — a stub that
// pre-camelCased these would skip the very translation step the groupKey shim
// got wrong. (Written camelCase first by mistake, and every mapped case
// correctly came back MAPPINGS_MALFORMED, which is that guard working.)
const row = (groupDn, role) => ({
  id: 'id-' + groupDn, group_dn: groupDn, display_name: null, role, description: null,
  created_at: null, updated_at: null,
});

// ─────────────────────────────────────────────────────────────────────────────
// 1. The decision itself
// ─────────────────────────────────────────────────────────────────────────────

describe('⛔ decideEntraAccess — ONE decision, shared by the front door and the token', () => {
  it('grants a mapped user', async () => {
    const d = await entraRoles.decideEntraAccess(
      stubPool({ mappings: [row(G_OPS, OPERATOR_ROLE)] }),
      { groups: [G_OPS] }
    );
    assert.equal(d.role, OPERATOR_ROLE);
    assert.equal(entraRoles.isEntraPermitted(d), true);
  });

  it('⛔ reads the rows loadMappings ACTUALLY returns, with no re-shaping step', async () => {
    // The regression this file exists for one layer down: the route used to map
    // `{ groupKey: m.groupDn }` on the way in. If the resolver and the loader
    // ever disagree about the field name again, a row straight out of the
    // loader stops matching and this goes red.
    const loaded = await ldapRoles.loadMappings(
      stubPool({ mappings: [row(G_ADMIN, ADMIN_ROLE)] }), 'entra'
    );
    const keys = Object.keys(loaded[0]);
    assert.ok(keys.includes('groupDn'), 'loadMappings returns groupDn');
    assert.ok(!keys.includes('groupKey'), 'and there is no second name for it');
    const r = entraRoles.resolveEntraRole({ claims: { groups: [G_ADMIN] }, mappings: loaded });
    assert.equal(r.role, ADMIN_ROLE, 'a loader row must resolve with no translation');
  });

  it('⛔ ZERO MAPPINGS DENIES — the opposite of LDAP, and it must stay opposite', async () => {
    const d = await entraRoles.decideEntraAccess(stubPool({ mappings: [] }), { groups: [G_ADMIN] });
    assert.equal(d.role, null);
    assert.equal(entraRoles.isEntraPermitted(d), false);
    assert.equal(d.outcome, entraRoles.OUTCOME.NO_MAPPINGS);
    assert.notEqual(d.role, ADMIN_ROLE, 'LDAP legacy mode must never leak across providers');
  });

  it('⛔ GROUP OVERAGE DENIES — a user in 201 groups is not a user in zero', async () => {
    const d = await entraRoles.decideEntraAccess(
      stubPool({ mappings: [row(G_ADMIN, ADMIN_ROLE)] }),
      { _claim_names: { groups: 'src1' }, groups: [G_ADMIN] }
    );
    assert.equal(entraRoles.isEntraPermitted(d), false,
      'a truncated membership list must not grant on its visible half');
    assert.equal(d.outcome, entraRoles.OUTCOME.GROUPS_OVERAGE);
  });

  it('⛔ THE "WE COULD NOT MEASURE THIS" CASE: no group claim at all denies', async () => {
    // The dominant bug in this codebase is a failed read recorded as an
    // affirmative value. Here the affirmative value would be "this user is in
    // no groups", which is a fact about the user; "the token carried no
    // readable group claim" is a fact about our read.
    const d = await entraRoles.decideEntraAccess(
      stubPool({ mappings: [row(G_ADMIN, ADMIN_ROLE)] }),
      {}
    );
    assert.equal(entraRoles.isEntraPermitted(d), false);
    assert.equal(d.outcome, entraRoles.OUTCOME.GROUPS_UNREADABLE);
    assert.notEqual(d.outcome, entraRoles.OUTCOME.NO_MATCHING_GROUP,
      'collapsing an unreadable claim into "no matching group" is the failed-read-as-a-fact bug');
  });

  it('an empty group array is a real answer and is refused as NO_MATCHING_GROUP', async () => {
    const d = await entraRoles.decideEntraAccess(
      stubPool({ mappings: [row(G_ADMIN, ADMIN_ROLE)] }),
      { groups: [] }
    );
    assert.equal(entraRoles.isEntraPermitted(d), false);
    assert.equal(d.outcome, entraRoles.OUTCOME.NO_MATCHING_GROUP);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. An unreadable DATABASE is not an unreadable GROUP CLAIM
// ─────────────────────────────────────────────────────────────────────────────

describe('⛔ a failed MAPPINGS read is labelled as a mappings problem', () => {
  const unreadable = () => stubPool({ mappings: new Error('connect ECONNREFUSED 127.0.0.1:5432') });

  it('denies', async () => {
    const d = await entraRoles.decideEntraAccess(unreadable(), { groups: [G_ADMIN] });
    assert.equal(d.role, null);
    assert.equal(entraRoles.isEntraPermitted(d), false,
      'loadMappings throws rather than returning [] precisely so a blip cannot mean "deny-by-config"');
  });

  it('⛔ has its OWN outcome, not GROUPS_UNREADABLE', async () => {
    // The route seeded `outcome = GROUPS_UNREADABLE` and that value survived
    // the catch around loadMappings, so a PostgreSQL outage told the
    // administrator to check the Entra app registration.
    const d = await entraRoles.decideEntraAccess(unreadable(), { groups: [G_ADMIN] });
    assert.equal(d.outcome, entraRoles.OUTCOME.MAPPINGS_UNREADABLE);
    assert.notEqual(d.outcome, entraRoles.OUTCOME.GROUPS_UNREADABLE,
      'two causes with two different fixes must not share one label');
  });

  it('⛔ its reason sends the administrator to the DATABASE, not to Entra', async () => {
    const d = await entraRoles.decideEntraAccess(unreadable(), { groups: [G_ADMIN] });
    assert.match(d.reason, /database/i, 'it must name the thing that is actually broken');
    assert.doesNotMatch(d.reason, /app registration/i,
      'the old reason pointed at Entra while the database was the problem');
    assert.doesNotMatch(d.reason, /group claim/i);
  });

  it('carries the driver message for the log, and keeps it OUT of the stored reason', async () => {
    const d = await entraRoles.decideEntraAccess(unreadable(), { groups: [G_ADMIN] });
    assert.match(String(d.error), /ECONNREFUSED/, 'diagnostics for the server log');
    assert.doesNotMatch(d.reason, /ECONNREFUSED/,
      'a driver message is diagnostics, not an instruction to an administrator');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. The groupKey shim — the mistake that would refuse every user silently
// ─────────────────────────────────────────────────────────────────────────────

describe('⛔ a mapping that lost its group id is a SecVault fault, loudly', () => {
  it('⛔ the exact old shim shape is REFUSED AS MALFORMED, not as "no matching group"', async () => {
    // This is the shape the route used to build. Passing `loadMappings`' rows
    // straight through — the obvious "simplification", and what the LDAP branch
    // correctly does — produced `groupKey: undefined` on every row, which
    // `normaliseDn` turned into null, which skipped every mapping, which read
    // as NO_MATCHING_GROUP: "this user is in no mapped group". Every Entra user
    // in the product refused, with a reason blaming the customer's directory.
    const shimmed = [{ groupKey: G_ADMIN, role: ADMIN_ROLE }];
    const r = entraRoles.resolveEntraRole({ claims: { groups: [G_ADMIN] }, mappings: shimmed });
    assert.equal(r.role, null, 'a mapping under the wrong field name cannot grant');
    assert.equal(r.outcome, entraRoles.OUTCOME.MAPPINGS_MALFORMED);
    assert.notEqual(r.outcome, entraRoles.OUTCOME.NO_MATCHING_GROUP,
      'the fault is ours; it must not be reported as the directory being wired wrong');
  });

  it('its reason says the fix is NOT in Entra and NOT in the mappings UI', async () => {
    const r = entraRoles.resolveEntraRole({
      claims: { groups: [G_ADMIN] },
      mappings: [{ role: ADMIN_ROLE }],
    });
    assert.match(r.reason, /SecVault fault/i);
    assert.match(r.reason, /server log/i, 'it must point somewhere a fix can start');
  });

  it('⛔ ONE damaged row does not deny a user who matches a good one', async () => {
    // Refusing on a partial fault would make a single bad row an outage. The
    // delegate already skips a mapping with an unmappable ROLE for the same
    // reason.
    const r = entraRoles.resolveEntraRole({
      claims: { groups: [G_OPS] },
      mappings: [{ role: ADMIN_ROLE }, { groupDn: G_OPS, role: OPERATOR_ROLE }],
    });
    assert.equal(r.role, OPERATOR_ROLE);
    assert.equal(r.outcome, entraRoles.OUTCOME.MAPPED);
  });

  it('a blank or non-string group id counts as missing', async () => {
    for (const bad of ['', '   ', null, 7, {}, undefined]) {
      const r = entraRoles.resolveEntraRole({
        claims: { groups: [G_ADMIN] },
        mappings: [{ groupDn: bad, role: ADMIN_ROLE }],
      });
      assert.equal(r.outcome, entraRoles.OUTCOME.MAPPINGS_MALFORMED, JSON.stringify(bad));
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. No dead states in the enum that drives the decision
// ─────────────────────────────────────────────────────────────────────────────

describe('⛔ every OUTCOME is reachable', () => {
  it('each member is produced by some input', async () => {
    // `NOT_CONFIGURED` was in this enum, returned by nothing and read by
    // nothing. A dead state in an enum driving a security decision invites the
    // next reader to branch on it believing it fires.
    const reached = new Set();
    const cases = [
      [{ mappings: [row(G_ADMIN, ADMIN_ROLE)] }, { groups: [G_ADMIN] }],
      [{ mappings: [] }, { groups: [G_ADMIN] }],
      [{ mappings: [row(G_ADMIN, ADMIN_ROLE)] }, { groups: ['other'] }],
      [{ mappings: [row(G_ADMIN, ADMIN_ROLE)] }, {}],
      [{ mappings: [row(G_ADMIN, ADMIN_ROLE)] }, { _claim_names: { groups: 's' } }],
      [{ mappings: new Error('down') }, { groups: [G_ADMIN] }],
      [{ mappings: [{ role: ADMIN_ROLE }] }, { groups: [G_ADMIN] }],
    ];
    for (const [poolArgs, claims] of cases) {
      const d = await entraRoles.decideEntraAccess(stubPool(poolArgs), claims);
      reached.add(d.outcome);
    }
    for (const value of Object.values(entraRoles.OUTCOME)) {
      assert.ok(reached.has(value), `OUTCOME.${value} is never returned — remove it or use it`);
    }
  });

  it('isEntraPermitted is true for MAPPED alone', async () => {
    const d = await entraRoles.decideEntraAccess(
      stubPool({ mappings: [row(G_ADMIN, SUPER_ADMIN_ROLE)] }), { groups: [G_ADMIN] }
    );
    assert.equal(d.outcome, entraRoles.OUTCOME.MAPPED);
    assert.equal(entraRoles.isEntraPermitted(d), true);
    // ⛔ Not `!!role`: it also refuses a role no mapping may grant, which is
    // what ldapRoles.isPermitted adds over a truthiness test.
    assert.equal(entraRoles.isEntraPermitted({ role: 'viewer', outcome: 'mapped' }), false,
      'a retired role must not be grantable through a mapping');
    assert.equal(entraRoles.isEntraPermitted({ role: 'root', outcome: 'mapped' }), false);
    assert.equal(entraRoles.isEntraPermitted(null), false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. The real callbacks, and the real middleware
// ─────────────────────────────────────────────────────────────────────────────

let authOptions = null;
let middleware = null;
let mwConfig = null;
let NextRequest = null;
let encodeJwt = null;
let dbModule = null;
let loadError = null;

const SECRET = 'entra-refusal-test-secret-0123456789abcdef';

before(() => {
  try {
    const swc = require('next/dist/build/swc');
    const origExt = Module._extensions['.js'];
    Module._extensions['.js'] = function (mod, filename) {
      if (filename.split(path.sep).join('/').includes('/node_modules/')) {
        return origExt(mod, filename);
      }
      const out = swc.transformSync(fs.readFileSync(filename, 'utf8'), {
        filename,
        jsc: { parser: { syntax: 'ecmascript', jsx: true }, target: 'es2020' },
        module: { type: 'commonjs' },
      });
      return mod._compile(out.code, filename);
    };

    process.env.NEXTAUTH_SECRET = SECRET;
    // ⛔ Entra must NOT be configured here. The provider array is built once at
    // module load, and registering an OAuth provider is irrelevant to the
    // callbacks under test — which are reached directly.
    delete process.env.ENTRA_TENANT_ID;
    delete process.env.ENTRA_CLIENT_ID;
    delete process.env.ENTRA_CLIENT_SECRET;

    dbModule = require('../lib/db');
    ({ NextRequest } = require('next/server'));
    ({ encode: encodeJwt } = require('next-auth/jwt'));

    ({ authOptions } = require('../app/api/auth/[...nextauth]/route.js'));
    const mw = require('../middleware.js');
    middleware = mw.middleware;
    mwConfig = mw.config;
  } catch (err) {
    // ⛔ Reported as a failure, never skipped. A suite that quietly stops
    // checking the only gate on this path is the same shape of problem as the
    // defect it covers.
    loadError = err;
  }
});

/** Point the auth route's module-level pool at a stub for one call. */
async function withPool(stub, fn) {
  const original = dbModule.pool.query;
  dbModule.pool.query = stub.query.bind(stub);
  try {
    return await fn();
  } finally {
    dbModule.pool.query = original;
  }
}

describe('⛔ callbacks.signIn — a refused Entra sign-in is actually refused', () => {
  it('the callback EXISTS', () => {
    assert.ok(!loadError, 'could not load the auth route: ' + (loadError && loadError.message));
    assert.equal(typeof authOptions.callbacks.signIn, 'function',
      'without this callback NextAuth defaults to true and every refusal completes the sign-in');
  });

  const signIn = (args) => authOptions.callbacks.signIn(args);
  const entraUser = (claims) => ({ id: 'oid-1', name: 'Dana', email: 'dana@x.test', entraClaims: claims });
  const entraAccount = { provider: 'entra', type: 'oauth', providerAccountId: 'oid-1' };

  it('⛔ NO MAPPINGS: the sign-in does NOT complete', async () => {
    const stub = stubPool({ mappings: [] });
    const verdict = await withPool(stub, () => signIn({ user: entraUser({ groups: [G_ADMIN] }), account: entraAccount }));
    assert.notEqual(verdict, true, 'returning true completes the OAuth sign-in');
    assert.ok(verdict === false || typeof verdict === 'string',
      'a refusal is either false or a redirect target');
  });

  it('⛔ it redirects to the agreed login cue, /login?sso=refused', async () => {
    const stub = stubPool({ mappings: [] });
    const verdict = await withPool(stub, () => signIn({ user: entraUser({ groups: [G_ADMIN] }), account: entraAccount }));
    assert.equal(verdict, '/login?sso=refused',
      'the login page matches this literal value and renders its own explanation');
  });

  it('⛔ the NAMED OUTCOME is NOT in the redirect — it would disclose how the directory is wired', async () => {
    for (const claims of [{ groups: [G_ADMIN] }, {}, { _claim_names: { groups: 's' } }]) {
      const stub = stubPool({ mappings: [] });
      const verdict = await withPool(stub, () => signIn({ user: entraUser(claims), account: entraAccount }));
      assert.equal(verdict, '/login?sso=refused',
        'every refusal reads identically to an unauthenticated visitor');
      assert.doesNotMatch(String(verdict), /no_matching_group|groups_unreadable|groups_overage|no_mappings/,
        'three refusals need three different ADMINISTRATOR fixes; none belongs on a pre-auth page');
    }
  });

  it('⛔ the refusal IS recorded for the administrator, in activity_log', async () => {
    const stub = stubPool({ mappings: [row(G_ADMIN, ADMIN_ROLE)] });
    await withPool(stub, () => signIn({ user: entraUser({ groups: ['nope'] }), account: entraAccount }));
    assert.equal(stub.audit.length, 1, 'Settings -> Single sign-on reads refusals out of this table');
    assert.equal(stub.audit[0].action, 'entra_signin_refused');
    assert.match(stub.audit[0].detail, /no_matching_group/,
      'the named outcome goes HERE, where only a super_admin can read it');
  });

  it('⛔ UNREADABLE MAPPINGS: refused, and labelled as a mappings problem', async () => {
    const stub = stubPool({ mappings: new Error('connect ECONNREFUSED') });
    const verdict = await withPool(stub, () => signIn({ user: entraUser({ groups: [G_ADMIN] }), account: entraAccount }));
    assert.equal(verdict, '/login?sso=refused');
    // The audit INSERT goes to the same database, so nothing is recorded —
    // which is why the console line is the record on this path.
  });

  it('⛔ GROUP OVERAGE: refused', async () => {
    const stub = stubPool({ mappings: [row(G_ADMIN, ADMIN_ROLE)] });
    const verdict = await withPool(stub, () => signIn({
      user: entraUser({ _claim_names: { groups: 'src1' }, groups: [G_ADMIN] }),
      account: entraAccount,
    }));
    assert.notEqual(verdict, true);
  });

  it('a MAPPED user signs in, and nothing is written to activity_log', async () => {
    const stub = stubPool({ mappings: [row(G_OPS, OPERATOR_ROLE)] });
    const verdict = await withPool(stub, () => signIn({ user: entraUser({ groups: [G_OPS] }), account: entraAccount }));
    assert.equal(verdict, true);
    assert.equal(stub.audit.length, 0, 'a successful sign-in must not bury the refusal list');
  });

  it('⛔ the credentials providers are untouched — they refuse in authorize()', async () => {
    for (const provider of ['local', 'ldap']) {
      const verdict = await authOptions.callbacks.signIn({
        user: { id: 'u', name: 'u', role: ADMIN_ROLE },
        account: { provider, type: 'credentials' },
      });
      assert.equal(verdict, true, `${provider} must not be re-judged here`);
    }
    // No account at all (a shape NextAuth can hand an email flow) must not throw.
    assert.equal(await authOptions.callbacks.signIn({ user: {}, account: null }), true);
  });
});

describe('⛔ callbacks.jwt — the mid-session re-resolution still nulls the role', () => {
  const jwt = (args) => authOptions.callbacks.jwt(args);

  it('a revoked mapping nulls the role on the next token use', async () => {
    assert.ok(!loadError, 'could not load the auth route');
    const stub = stubPool({ mappings: [] });
    const token = await withPool(stub, () => jwt({
      token: { provider: 'entra', id: 'oid-1', role: ADMIN_ROLE, entraClaims: { groups: [G_ADMIN] } },
    }));
    assert.equal(token.role, null, 'a mapping an administrator removed must stop working at once');
  });

  it('a still-mapped user keeps the role the mapping grants', async () => {
    const stub = stubPool({ mappings: [row(G_ADMIN, SUPER_ADMIN_ROLE)] });
    const token = await withPool(stub, () => jwt({
      token: { provider: 'entra', id: 'oid-1', role: OPERATOR_ROLE, entraClaims: { groups: [G_ADMIN] } },
    }));
    assert.equal(token.role, SUPER_ADMIN_ROLE, 'and a PROMOTION applies immediately too');
  });

  it('⛔ an unreadable mapping table nulls the role rather than keeping the old one', async () => {
    const stub = stubPool({ mappings: new Error('down') });
    const token = await withPool(stub, () => jwt({
      token: { provider: 'entra', id: 'oid-1', role: SUPER_ADMIN_ROLE, entraClaims: { groups: [G_ADMIN] } },
    }));
    assert.equal(token.role, null);
  });

  it('⛔ no unread copy of the outcome is left on the token', async () => {
    // v2.211.0 fixed the REASON by logging it and left `token.entraOutcome` —
    // written on every request, read by nothing — in place. A third unread copy
    // is not a fix.
    const stub = stubPool({ mappings: [] });
    const token = await withPool(stub, () => jwt({
      token: { provider: 'entra', id: 'oid-1', entraClaims: { groups: [G_ADMIN] } },
    }));
    assert.ok(!('entraOutcome' in token), 'carry it somewhere readable or stop writing it');
  });

  it('⛔ it writes NO audit row per request — this callback runs on every one', async () => {
    const stub = stubPool({ mappings: [] });
    for (let i = 0; i < 3; i += 1) {
      await withPool(stub, () => jwt({
        token: { provider: 'entra', id: 'oid-1', entraClaims: { groups: [G_ADMIN] } },
      }));
    }
    assert.equal(stub.audit.length, 0, 'one INSERT per page load would bury activity_log');
  });
});

describe('⛔ middleware — a role-less session is denied, not merely capability-less', () => {
  const cookieFor = async (token) =>
    `next-auth.session-token=${await encodeJwt({ token, secret: SECRET })}`;

  const hit = async (pathname, token) => {
    const headers = token ? { cookie: await cookieFor(token) } : {};
    return middleware(new NextRequest('http://secvault.test' + pathname, { headers }));
  };

  it('the pure verdict denies an absent, null, empty or non-string role', () => {
    assert.ok(!loadError, 'could not load middleware: ' + (loadError && loadError.message));
    const { roleRefusal } = require('../middleware.js');
    for (const role of [undefined, null, '', '   ', 0, false, {}, []]) {
      assert.ok(roleRefusal({ role }), `role=${JSON.stringify(role)} must be refused`);
    }
    for (const role of [SUPER_ADMIN_ROLE, ADMIN_ROLE, OPERATOR_ROLE]) {
      assert.equal(roleRefusal({ role }), null, role);
    }
  });

  it('⛔ a PAGE request with a role-less token does not reach the page', async () => {
    const res = await hit('/devices', { id: 'oid-1', provider: 'entra', role: null });
    assert.equal(res.status, 307, 'a role-less session kept whole-fleet READ access before this');
    const loc = res.headers.get('location');
    assert.ok(loc, 'it must be redirected somewhere');
    assert.equal(new URL(loc).pathname, '/login');
  });

  it('⛔ it lands somewhere that can explain itself, not a bare /login', async () => {
    const res = await hit('/compliance', { id: 'u', provider: 'local', role: null });
    const loc = new URL(res.headers.get('location'));
    assert.equal(loc.searchParams.get('sso'), 'norole',
      'a silent bounce reads as "my password stopped working"');
  });

  it('⛔ and it reads DIFFERENTLY from a front-door refusal', async () => {
    const res = await hit('/devices', { id: 'u', provider: 'entra', role: null });
    const loc = new URL(res.headers.get('location'));
    assert.notEqual(loc.searchParams.get('sso'), 'refused',
      'a mid-session revocation is often transient; a front-door refusal needs an administrator');
  });

  it('a role-bearing token is admitted', async () => {
    const res = await hit('/devices', { id: 'u', provider: 'local', role: ADMIN_ROLE });
    assert.equal(res.status, 200, 'this must change nothing for every account that exists today');
    assert.equal(res.headers.get('location'), null);
  });

  it('⛔ EVERY PROVIDER, including local — a deleted account also nulls its role', async () => {
    for (const provider of ['local', 'ldap', 'entra', undefined]) {
      const res = await hit('/devices', { id: 'u', provider, role: null });
      assert.equal(res.status, 307, `provider=${provider} must be refused`);
      assert.equal(new URL(res.headers.get('location')).pathname, '/login');
    }
  });

  it('⛔ an API request gets 403 and says why — never a 401 against a valid credential', async () => {
    const res = await hit('/api/devices', { id: 'u', provider: 'entra', role: null });
    assert.equal(res.status, 403);
    const body = await res.json();
    assert.equal(body.noRole, true);
    assert.match(body.error, /no SecVault role/i);
  });

  it('an API request with a role is admitted', async () => {
    const res = await hit('/api/devices', { id: 'u', provider: 'local', role: OPERATOR_ROLE });
    assert.equal(res.status, 200);
  });

  it('⛔ no token still behaves exactly as before', async () => {
    const page = await hit('/devices', null);
    assert.equal(page.status, 307);
    assert.equal(new URL(page.headers.get('location')).pathname, '/login');
    assert.equal(new URL(page.headers.get('location')).searchParams.get('sso'), null,
      'a never-signed-in visitor has nothing to explain');
    const api = await hit('/api/devices', null);
    assert.equal(api.status, 401);
  });

  it('⛔ REGRESSION: device scoping is still enforced, and the role check runs first', async () => {
    const scoped = { id: 'u', provider: 'local', role: ADMIN_ROLE, deviceScoped: true };
    const blocked = await hit('/compliance', scoped);
    assert.equal(blocked.status, 307);
    assert.equal(new URL(blocked.headers.get('location')).pathname, '/devices');

    // A scoped account with NO role must be sent to /login, not to the
    // /devices landing page a scoped account is normally redirected to —
    // otherwise it would be bounced to a page it is also refused.
    const both = await hit('/compliance', { ...scoped, role: null });
    assert.equal(new URL(both.headers.get('location')).pathname, '/login');
  });
});

describe('⛔ the matcher excludes the icon this product actually ships', () => {
  // ⛔ A SOURCE/CONFIG ASSERTION IS RIGHT HERE and nowhere else in this file:
  // Next compiles `config.matcher` at build time and middleware is never
  // invoked for an excluded path, so there is no runtime behaviour to drive.
  // The regex itself is the control.
  const rx = () => {
    assert.ok(!loadError, 'could not load middleware');
    const pattern = Array.isArray(mwConfig.matcher) ? mwConfig.matcher[0] : mwConfig.matcher;
    return new RegExp('^' + pattern + '$');
  };

  it('/icon.svg is NOT matched — app/icon.svg is a real route', () => {
    assert.equal(rx().test('/icon.svg'), false,
      'the only favicon this repo ships was 307d to /login for every unauthenticated visitor');
  });

  it('the exclusions that were already load-bearing still hold', () => {
    const r = rx();
    for (const p of ['/api/auth/session', '/_next/static/chunk.js', '/fonts/IBMPlexSans.woff2',
      '/login', '/favicon.ico']) {
      assert.equal(r.test(p), false, p);
    }
  });

  it('⛔ and it still matches everything it must gate', () => {
    const r = rx();
    // ⛔ `/iconXsvg` proves the dot is ESCAPED. `favicon.ico` beside it is not,
    // so it also excludes `/faviconXico` — harmless, and left alone rather
    // than "tidied", because the line is load-bearing and this change is not
    // about it.
    //
    // ⛔ THE EXCLUSION IS A PREFIX, LIKE EVERY OTHER ONE IN THIS MATCHER
    // (`fonts`, `login`), so `/icon.svg...` is excluded too. Anchoring the
    // alternative with `$` would narrow it, and was NOT done: Next compiles
    // this string into its own regex and whether an anchor survives that
    // compilation is exactly the kind of Next-internal behaviour this
    // codebase has been wrong about by reasoning instead of probing (see the
    // /_next/image note in middleware.js). No route begins with `icon.svg`,
    // so the prefix form costs nothing.
    for (const p of ['/', '/devices', '/compliance', '/api/devices', '/api/health', '/iconXsvg']) {
      assert.equal(r.test(p), true, `${p} must still reach middleware`);
    }
  });
});
