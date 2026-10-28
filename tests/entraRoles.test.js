// tests/entraRoles.test.js
//
// Phase 1 of .ai-codex/entra-sso-proposal.md.
//
// ⛔ EVERY CASE HERE INCLUDES THE "WE COULD NOT READ THIS" OUTCOME, not only
// pass and fail. That is the one that regresses silently on this path, because
// the wrong answer is a plausible role rather than a crash.

const { it, describe } = require('node:test');
const assert = require('node:assert/strict');

const {
  OUTCOME, hasGroupOverage, groupsFromClaims, resolveEntraRole, isEntraConfigured,
} = require('../lib/entraRoles');
const { SUPER_ADMIN_ROLE, ADMIN_ROLE, OPERATOR_ROLE } = require('../lib/rbac');

const G_ADMIN = '8f4a1c2e-9b7d-4e6a-bc13-5d2f70a9e4c1';
const G_OPS = '1b2c3d4e-5f60-4718-9a2b-3c4d5e6f7081';
// ⛔ `groupDn`, NOT `groupKey`. This is the field name `ldapRoles.resolveRole`
// and `ldapRoles.loadMappings` both use, so an Entra mapping row now travels
// from the database to the resolver under ONE name with no re-shaping step in
// between. The old second name is what made the auth route's shim possible —
// see tests/entraAuthRefusal.test.js, which pins the failure a dropped key
// used to produce.
const map = (groupDn, role) => ({ groupDn, role });

describe('⛔ the local account is never affected by Entra configuration', () => {
  it('isEntraConfigured is false unless ALL THREE values are present', () => {
    assert.equal(isEntraConfigured({}), false, 'nothing configured');
    assert.equal(isEntraConfigured({ ENTRA_TENANT_ID: 't' }), false, 'tenant only');
    assert.equal(isEntraConfigured({ ENTRA_TENANT_ID: 't', ENTRA_CLIENT_ID: 'c' }), false,
      'a half-configured tenant renders a button that cannot complete a sign-in');
    assert.equal(
      isEntraConfigured({ ENTRA_TENANT_ID: 't', ENTRA_CLIENT_ID: 'c', ENTRA_CLIENT_SECRET: 's' }),
      true
    );
  });

  it('⛔ an empty string is NOT configured — a blank env var is the normal state', () => {
    assert.equal(
      isEntraConfigured({ ENTRA_TENANT_ID: '', ENTRA_CLIENT_ID: '', ENTRA_CLIENT_SECRET: '' }),
      false,
      '.env.local.example ships these blank; blank must mean absent, not broken'
    );
  });

  it('⛔ the auth route registers Entra ONLY when configured, and never gates local', () => {
    // A source property, because the alternative is standing up NextAuth. The
    // two things that must remain true: the spread is conditional, and the
    // local provider is not inside any conditional.
    const fs = require('node:fs');
    const src = fs.readFileSync(
      require('node:path').join(__dirname, '..', 'app', 'api', 'auth', '[...nextauth]', 'route.js'),
      'utf8'
    );
    assert.match(src, /\.\.\.\(entraRoles\.isEntraConfigured\(process\.env\)/,
      'Entra must be spread in conditionally, not registered unconditionally');
    assert.match(src, /CredentialsProvider\(\{\s*\n\s*id: 'local'/,
      'the local provider must still be a plain, unconditional array entry');
    // ⛔ The local provider must appear BEFORE the Entra conditional, i.e. it
    // cannot have been moved inside it.
    assert.ok(
      src.indexOf("id: 'local'") < src.indexOf('isEntraConfigured'),
      'local sign-in must not sit behind any Entra condition'
    );
  });
});

describe('⛔ the provider id IS the redirect URI, so it cannot be renamed casually', () => {
  it('the provider is registered as `entra`', () => {
    // ⛔ NextAuth derives the OAuth callback from the provider id:
    //     <NEXTAUTH_URL>/api/auth/callback/<id>
    // That exact URL is typed into the Entra app registration's Redirect URI
    // by whoever sets the tenant up, and Entra REFUSES any mismatch outright.
    // Renaming this id silently invalidates every customer's app registration
    // with an error that appears on Microsoft's side, not ours -- so it is
    // pinned here rather than left as an implementation detail.
    const fs = require('node:fs');
    const src = fs.readFileSync(
      require('node:path').join(__dirname, '..', 'app', 'api', 'auth', '[...nextauth]', 'route.js'),
      'utf8'
    );
    assert.match(src, /AzureADProvider\(\{\s*\n\s*id: 'entra'/,
      'the callback path /api/auth/callback/entra is registered with customers; do not rename it');
  });

  it('the login page asks for that same id', () => {
    const fs = require('node:fs');
    const src = fs.readFileSync(
      require('node:path').join(__dirname, '..', 'app', '(auth)', 'login', 'page.js'),
      'utf8'
    );
    assert.match(src, /signIn\('entra'/, 'the button must call the id the provider registered');
    assert.match(src, /p && p\.entra/, 'and must only render when the server reports that provider');
  });
});

describe('⛔ the group overage is refused, never read as "no groups"', () => {
  it('detects the overage pointer in either claim', () => {
    assert.equal(hasGroupOverage({ _claim_names: { groups: 'src1' } }), true);
    assert.equal(hasGroupOverage({ _claim_sources: { groups: { endpoint: 'https://…' } } }), true);
    assert.equal(hasGroupOverage({ groups: [G_ADMIN] }), false);
    assert.equal(hasGroupOverage({}), false);
    assert.equal(hasGroupOverage(null), false);
  });

  it('⛔ an overage token REFUSES with its own outcome, not NO_MATCHING_GROUP', () => {
    const r = resolveEntraRole({
      claims: { _claim_names: { groups: 'src1' } },
      mappings: [map(G_ADMIN, ADMIN_ROLE)],
    });
    assert.equal(r.role, null, 'a user in 201 groups is not a user in zero');
    assert.equal(r.outcome, OUTCOME.GROUPS_OVERAGE);
    assert.match(r.reason, /too many groups/i, 'the reason must name the cause so it is fixable');
  });

  it('⛔ overage is decided BEFORE the zero-mappings branch', () => {
    // Both conditions true at once. "We could not read this user's groups"
    // outranks every later question; reporting NO_MAPPINGS here would send an
    // administrator to fix the wrong thing.
    const r = resolveEntraRole({ claims: { _claim_names: { groups: 'src1' } }, mappings: [] });
    assert.equal(r.outcome, OUTCOME.GROUPS_OVERAGE);
  });

  it('⛔ an overage token that ALSO carries a groups array is still refused', () => {
    // Entra may send a truncated array alongside the pointer. Trusting it
    // would grant on a partial membership list.
    const r = resolveEntraRole({
      claims: { groups: [G_OPS], _claim_names: { groups: 'src1' } },
      mappings: [map(G_OPS, OPERATOR_ROLE)],
    });
    assert.equal(r.role, null);
    assert.equal(r.outcome, OUTCOME.GROUPS_OVERAGE);
  });
});

describe('⛔ absent groups and empty groups are different facts', () => {
  it('no claim at all is null (unreadable), not an empty list', () => {
    assert.deepEqual(groupsFromClaims({}), { groups: null, overage: false });
    assert.deepEqual(groupsFromClaims({ groups: null }), { groups: null, overage: false });
    assert.deepEqual(groupsFromClaims({ groups: 'not-an-array' }), { groups: null, overage: false });
  });

  it('an empty array is a real answer: this user is in no groups', () => {
    assert.deepEqual(groupsFromClaims({ groups: [] }), { groups: [], overage: false });
  });

  it('⛔ they resolve to DIFFERENT outcomes', () => {
    const mappings = [map(G_ADMIN, ADMIN_ROLE)];
    const unreadable = resolveEntraRole({ claims: {}, mappings });
    const empty = resolveEntraRole({ claims: { groups: [] }, mappings });
    assert.equal(unreadable.outcome, OUTCOME.GROUPS_UNREADABLE);
    assert.equal(empty.outcome, OUTCOME.NO_MATCHING_GROUP);
    assert.equal(unreadable.role, null);
    assert.equal(empty.role, null);
    assert.notEqual(unreadable.outcome, empty.outcome,
      'collapsing these is the failed-read-as-a-fact bug on the authorisation path');
  });

  it('non-string group entries are dropped, never coerced', () => {
    // A coerced "[object Object]" is a group id that can never match — a
    // silent denial rather than a visible fault.
    assert.deepEqual(groupsFromClaims({ groups: [G_ADMIN, { x: 1 }, '', 42] }),
      { groups: [G_ADMIN], overage: false });
  });
});

describe('⛔ zero mappings DENIES — the deliberate opposite of LDAP', () => {
  it('a valid user with no mappings configured is refused', () => {
    const r = resolveEntraRole({ claims: { groups: [G_ADMIN] }, mappings: [] });
    assert.equal(r.role, null, 'SecVault has never shipped Entra, so there is no access to preserve');
    assert.equal(r.outcome, OUTCOME.NO_MAPPINGS);
  });

  it('⛔ it must NOT return the LDAP legacy admin grant', () => {
    const r = resolveEntraRole({ claims: { groups: [G_ADMIN] }, mappings: [] });
    assert.notEqual(r.role, ADMIN_ROLE,
      'LDAP grants admin on an empty table to protect an installed base Entra does not have');
    assert.notEqual(r.outcome, 'legacy_no_mappings');
  });

  it('a non-array mappings value is treated as zero, not trusted', () => {
    for (const bad of [null, undefined, 'x', 7, {}]) {
      const r = resolveEntraRole({ claims: { groups: [G_ADMIN] }, mappings: bad });
      assert.equal(r.role, null, JSON.stringify(bad));
    }
  });
});

describe('the mapped path delegates to ldapRoles unchanged', () => {
  it('maps a single group to its role', () => {
    const r = resolveEntraRole({
      claims: { groups: [G_OPS] },
      mappings: [map(G_OPS, OPERATOR_ROLE)],
    });
    assert.equal(r.role, OPERATOR_ROLE);
    assert.equal(r.outcome, OUTCOME.MAPPED);
  });

  it('⛔ the MOST PRIVILEGED match wins', () => {
    // Resolving downward would mean adding someone to a second group silently
    // REMOVED access — the rule ldapRoles already owns, inherited here.
    const r = resolveEntraRole({
      claims: { groups: [G_OPS, G_ADMIN] },
      mappings: [map(G_OPS, OPERATOR_ROLE), map(G_ADMIN, SUPER_ADMIN_ROLE)],
    });
    assert.equal(r.role, SUPER_ADMIN_ROLE);
  });

  it('a user in no mapped group is refused once mappings exist', () => {
    const r = resolveEntraRole({
      claims: { groups: ['99999999-0000-0000-0000-000000000000'] },
      mappings: [map(G_ADMIN, ADMIN_ROLE)],
    });
    assert.equal(r.role, null);
    assert.equal(r.outcome, OUTCOME.NO_MATCHING_GROUP);
  });

  it('⛔ group ids compare case-insensitively — Entra GUID casing is not stable', () => {
    const r = resolveEntraRole({
      claims: { groups: [G_ADMIN.toUpperCase()] },
      mappings: [map(G_ADMIN.toLowerCase(), ADMIN_ROLE)],
    });
    assert.equal(r.role, ADMIN_ROLE, 'the same group in different casing is the same group');
  });
});
