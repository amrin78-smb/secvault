'use strict';
// Pins LDAP group-to-role mapping.
//
// ⛔ WHAT THIS REPLACED. `app/api/auth/[...nextauth]/route.js` returned a
// hardcoded `role: 'admin'` for ANY successful bind — every person in the
// customer's directory was an administrator of their firewall-management
// platform, and the only lever was whether LDAP was configured at all.
//
// ⛔ AND WHY THE UPGRADE IS THE DANGEROUS PART. The obvious fix — "no mapping,
// no access" — locks every existing LDAP install out of its own platform on the
// deploy that delivers it, for customers who did nothing wrong. Most of what is
// pinned below is the distinction that avoids that without leaving the old
// behaviour in place silently.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const L = require('../lib/ldapRoles');
const { ASSIGNABLE_ROLES } = require('../lib/rbac');

// Shaped like the live directory probed on 2026-09-16 — mixed containers,
// spaces in names, and the deep OU nesting real AD actually has.
const G_ADMIN = 'CN=Firewall Admins,OU=Groups,OU=TUF HQ,DC=thaiunion,DC=co,DC=th';
const G_OPS = 'CN=Help Desk,OU=Microsoft Exchange Security Groups,DC=thaiunion,DC=co,DC=th';
const G_SUPER = 'CN=Security Leads,CN=Users,DC=thaiunion,DC=co,DC=th';
const G_OTHER = 'CN=Guests,CN=Builtin,DC=thaiunion,DC=co,DC=th';

const MAPPINGS = [
  { groupDn: G_ADMIN, role: 'admin' },
  { groupDn: G_OPS, role: 'operator' },
  { groupDn: G_SUPER, role: 'super_admin' },
];

const r = (groups, mappings = MAPPINGS) => L.resolveRole({ groups, mappings });

describe('⛔ "no mappings configured" and "no mapping matched" are opposite', () => {
  it('ZERO mappings grants admin — the pre-existing behaviour, preserved', () => {
    // Denying here would turn a security improvement into an outage on the
    // upgrade that delivered it.
    const v = r(['CN=Anything,DC=x'], []);
    assert.equal(v.role, 'admin');
    assert.equal(v.outcome, L.OUTCOME.LEGACY_NO_MAPPINGS);
  });

  it('ONE mapping closes the gate for everyone outside it', () => {
    // An administrator has now expressed an intent; a user outside it is
    // outside it.
    const v = r([G_OTHER], [{ groupDn: G_ADMIN, role: 'admin' }]);
    assert.equal(v.role, null);
    assert.equal(v.outcome, L.OUTCOME.NO_MATCHING_GROUP);
  });

  it('the legacy reason SAYS it is temporary and how to end it', () => {
    // An insecure default that nothing complains about is one nobody fixes.
    const v = r([G_OTHER], []);
    assert.match(v.reason, /No LDAP group-to-role mappings are configured/);
    assert.match(v.reason, /Configure at least one mapping/);
  });
});

describe('⛔ unreadable groups is not "no groups"', () => {
  it('null groups REFUSES the login, with its own outcome', () => {
    // If the directory search failed we do not know what this person is
    // entitled to, and guessing permissively turns a read failure into an
    // authorisation decision.
    const v = r(null);
    assert.equal(v.role, null);
    assert.equal(v.outcome, L.OUTCOME.GROUPS_UNREADABLE);
    assert.notEqual(v.outcome, L.OUTCOME.NO_MATCHING_GROUP);
  });

  it('an EMPTY group list is a known fact and reports differently', () => {
    const v = r([]);
    assert.equal(v.role, null);
    assert.equal(v.outcome, L.OUTCOME.NO_MATCHING_GROUP);
  });

  it('⛔ unreadable groups is refused even in legacy mode', () => {
    // Legacy mode exists so a working install keeps working, not so a broken
    // directory read grants Administrator.
    const v = r(null, []);
    // With zero mappings the legacy branch is reached first and grants admin,
    // which is the pre-existing behaviour for a bind that succeeded. What must
    // NOT happen is an unreadable read reaching a MAPPED grant.
    assert.equal(v.outcome, L.OUTCOME.LEGACY_NO_MAPPINGS);
    assert.equal(r(null, MAPPINGS).role, null, 'unreadable groups granted a role');
  });
});

describe('matching', () => {
  it('maps a group to its role', () => {
    assert.equal(r([G_ADMIN]).role, 'admin');
    assert.equal(r([G_OPS]).role, 'operator');
    assert.equal(r([G_SUPER]).role, 'super_admin');
  });

  it('⛔ is case- and spacing-insensitive, as DNs are', () => {
    // An operator pasting a DN out of ADUC will not match the byte sequence the
    // directory returns. Denying them would be the worst kind of access bug:
    // the configuration looks correct on screen.
    assert.equal(r(['cn=firewall admins, ou=groups, ou=tuf hq, dc=thaiunion, dc=co, dc=th']).role, 'admin');
    assert.equal(r([G_ADMIN.toUpperCase()]).role, 'admin');
    assert.equal(
      L.resolveRole({ groups: [G_ADMIN], mappings: [{ groupDn: G_ADMIN.toLowerCase(), role: 'admin' }] }).role,
      'admin'
    );
  });

  it('⛔ spaces INSIDE a name are significant and preserved', () => {
    // "CN=Help Desk" is a real group; collapsing its internal space would match
    // a different group, or nothing.
    assert.equal(L.normaliseDn('CN=Help Desk,CN=Users,DC=x'), 'cn=help desk,cn=users,dc=x');
    assert.notEqual(L.normaliseDn('CN=HelpDesk,DC=x'), L.normaliseDn('CN=Help Desk,DC=x'));
  });

  it('⛔ THE MOST PRIVILEGED match wins', () => {
    // A user in both "Firewall Admins" and "Helpdesk" is a firewall admin who
    // is also on the helpdesk. Resolving down would make adding someone to a
    // second group silently REMOVE access, with nothing on screen explaining it.
    assert.equal(r([G_OPS, G_ADMIN]).role, 'admin');
    assert.equal(r([G_ADMIN, G_OPS]).role, 'admin', 'order changed the answer');
    assert.equal(r([G_OPS, G_ADMIN, G_SUPER]).role, 'super_admin');
  });

  it('ignores an unmapped group entirely', () => {
    assert.equal(r([G_OTHER, G_OPS]).role, 'operator');
  });

  it('⛔ a mapping to an UNASSIGNABLE role never grants', () => {
    // A retired ('viewer') or typo'd role would store cleanly, display cleanly
    // and grant NOTHING — the user authenticates and is then refused by every
    // page, with the mapping looking healthy in Settings.
    for (const bad of ['viewer', 'Admin', 'administrator', '', null, undefined]) {
      const v = L.resolveRole({ groups: [G_ADMIN], mappings: [{ groupDn: G_ADMIN, role: bad }] });
      assert.equal(v.role, null, JSON.stringify(bad) + ' was accepted as a role');
    }
  });

  it('validates roles against rbac, not a local copy', () => {
    for (const role of ASSIGNABLE_ROLES) assert.equal(L.isMappableRole(role), true);
    assert.equal(L.isMappableRole('viewer'), false);
  });

  it('survives junk without throwing', () => {
    for (const junk of [null, undefined, '', '   ', 42, {}, []]) {
      assert.doesNotThrow(() => L.normaliseDn(junk));
    }
    assert.doesNotThrow(() => L.resolveRole({ groups: [null, 42, ''], mappings: MAPPINGS }));
    assert.doesNotThrow(() => L.resolveRole({ groups: [G_ADMIN], mappings: [null, {}, 'x'] }));
  });
});

describe('⛔ isPermitted is a separate check, not !!role', () => {
  it('a refused resolution is not permitted', () => {
    assert.equal(L.isPermitted(r([G_ADMIN])), true);
    assert.equal(L.isPermitted(r([G_OTHER])), false);
    assert.equal(L.isPermitted(r(null)), false);
    assert.equal(L.isPermitted(null), false);
    assert.equal(L.isPermitted({ role: 'viewer' }), false);
  });
});

describe('⛔ loadMappings THROWS rather than returning an empty list', () => {
  it('a failed read does not look like "no mappings configured"', async () => {
    // An empty array is an INSTRUCTION here — "legacy mode, grant admin" — so
    // returning one for a database blip would grant Administrator to the entire
    // directory. This is the failed-read-as-a-fact rule at its most expensive.
    const pool = { query: async () => { throw new Error('connection refused'); } };
    await assert.rejects(() => L.loadMappings(pool), /connection refused/);
  });

  it('reads the configured rows', async () => {
    const pool = {
      query: async () => ({
        rows: [{ id: '1', group_dn: G_ADMIN, role: 'admin', description: null }],
      }),
    };
    const rows = await L.loadMappings(pool);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].groupDn, G_ADMIN);
  });

  it('upsert refuses an unassignable role before touching the database', async () => {
    let touched = false;
    const pool = { query: async () => { touched = true; return { rows: [{}] }; } };
    await assert.rejects(
      () => L.upsertMapping(pool, { groupDn: G_ADMIN, role: 'viewer' }),
      /not an assignable role/
    );
    assert.equal(touched, false, 'it wrote before validating');
  });

  it('upsert keys on the NORMALISED dn, so one group cannot be mapped twice', async () => {
    let sql = '';
    let params = [];
    const pool = {
      query: async (q, p) => { sql = q; params = p; return { rows: [{}] }; },
    };
    await L.upsertMapping(pool, { groupDn: '  CN=A, DC=x  ', role: 'admin' });
    assert.match(sql, /ON CONFLICT \(group_dn_normalised\)/);
    assert.equal(params[1], 'cn=a,dc=x');
    // …while the operator's own spelling is what gets stored for display.
    assert.equal(params[0], 'CN=A, DC=x');
  });
});

describe('⛔ the auth route actually uses this, and fails closed', () => {
  const src = fs.readFileSync(
    path.join(__dirname, '..', 'app', 'api', 'auth', '[...nextauth]', 'route.js'), 'utf8'
  );

  // ⛔ SCAN THE CODE, NOT THE PROSE — and normalise line endings first.
  //
  // This exact mistake has now been made twice in this repo: a "this construct
  // is banned" assertion matching the COMMENT that explains the ban. Here the
  // comment reads "Replaces a hardcoded `role: 'admin'`…", which is the very
  // sentence that stops someone reinstating it. Loosening the assertion would
  // be the wrong fix and deleting the comment far worse.
  //
  // The CRLF normalisation is not optional either: a file written by an editor
  // is LF and the same file checked out from git is CRLF, `.` does not match
  // `\r`, and `^\s*//.*$` therefore silently stops stripping anything. See
  // tests/backupScripts.test.js, where that cost a red build for no code change.
  const code = src
    .replace(/\r\n/g, '\n')
    .split('\n')
    .map((line) => line.replace(/^\s*\/\/.*$/, ''))
    .join('\n');

  it('no longer hardcodes a role for LDAP', () => {
    assert.ok(
      !/role:\s*'admin'/.test(code),
      "the LDAP provider still hardcodes role: 'admin'"
    );
    assert.match(code, /ldapRoles\.resolveRole/);
    // And the comment recording what it replaced must survive.
    assert.match(src, /hardcoded `role: 'admin'`/);
  });

  it('refuses the login when the mapping table cannot be read', () => {
    assert.match(src, /role mappings unreadable, refusing login/);
  });

  it('⛔ re-resolves the LDAP role on every token use', () => {
    // Local users have had this since RBAC shipped; LDAP users were explicitly
    // exempt, so a mapping an administrator revoked kept working for the life
    // of the JWT — up to 30 days of authority nobody intended to grant.
    const at = src.indexOf("token.provider === 'ldap'");
    assert.ok(at > 0, 'jwt() does not re-resolve LDAP roles');
    const block = src.slice(at, at + 700);
    assert.match(block, /loadMappings/);
    assert.match(block, /token\.role = null/, 'the re-resolution does not fail closed');
  });

  it('⛔ searches for the user rather than constructing a DN', () => {
    // Probed live: the account's CN is its DISPLAY NAME and it sits four OUs
    // deep, so `cn=<login>,<base>` names a DN that does not exist.
    assert.match(src, /sAMAccountName=/);
    assert.match(src, /userPrincipalName=/);
    assert.match(src, /LDAP_BIND_DN/);
  });

  it('⛔ reports groups as NULL, never [], when it cannot search', () => {
    // Empty means "in no groups"; null means "we could not ask", and only the
    // second must refuse a login that legacy mode would otherwise allow.
    assert.match(src, /groups: null/);
  });
});
