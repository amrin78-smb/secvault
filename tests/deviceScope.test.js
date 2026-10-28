'use strict';
// tests/deviceScope.test.js
//
// ⛔ EVERY ASSERTION HERE IS ABOUT A STATE THAT MUST NOT WIDEN ACCESS.
// This is an authorisation primitive, so it fails CLOSED everywhere: a failed
// read, a malformed row, an unrecognised state and a missing session all deny.
// The one place it deliberately does NOT deny is an account with no scope rows
// at all, which keeps today's fleet-wide behaviour — and that asymmetry is the
// single most important thing in the file, because getting it backwards locks
// every existing installation out of its own platform on the deploy that
// delivers this.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  SCOPE_STATES, scopeFromRows, isScoped, canSeeDevice, filterDevices,
  scopeSqlClause, refusalMessage, loadScopeForSession,
} = require('../lib/deviceScope');

const UUID = '11111111-2222-3333-4444-555555555555';
const A = 'aaaaaaaa-0000-0000-0000-000000000001';
const B = 'bbbbbbbb-0000-0000-0000-000000000002';

const unscoped = () => scopeFromRows([]);
const scoped = (...ids) => scopeFromRows(ids.map((device_id) => ({ device_id })));
const unknown = () => scopeFromRows(null);

describe('⛔ no rows is UNSCOPED — not "no devices"', () => {
  it('an account nobody has scoped keeps seeing the whole fleet', () => {
    // Reversing this bricks every existing install on the upgrade that
    // delivers scoping, for customers who did nothing wrong. Same call
    // ldapRoles.js makes for an empty mapping table.
    const s = unscoped();
    assert.equal(s.state, SCOPE_STATES.UNSCOPED);
    assert.equal(isScoped(s), false);
    assert.equal(canSeeDevice(s, A), true);
    assert.deepEqual(filterDevices(s, [{ id: A }, { id: B }]).map((d) => d.id), [A, B]);
  });

  it('and contributes no SQL clause at all', () => {
    assert.deepEqual(scopeSqlClause(unscoped(), 'd.id', 2), { sql: '', params: [] });
  });
});

describe('⛔ a failed read is UNKNOWN and denies everything', () => {
  it('null rows never become an empty (and therefore unscoped) scope', () => {
    // The signature bug: `[]` and `null` mean opposite things here, and
    // collapsing them would turn a database blip into fleet-wide access.
    const s = unknown();
    assert.equal(s.state, SCOPE_STATES.UNKNOWN);
    assert.equal(canSeeDevice(s, A), false);
    assert.deepEqual(filterDevices(s, [{ id: A }]), []);
  });

  it('⛔ its SQL clause matches NOTHING, never everything', () => {
    const { sql, params } = scopeSqlClause(unknown(), 'd.id', 2);
    assert.equal(sql, ' AND FALSE');
    assert.deepEqual(params, []);
  });

  it('rows that exist but carry no usable id are UNKNOWN, not unscoped', () => {
    // Someone granted this user something and we failed to read what. Reading
    // that as "no restriction" inverts the grant.
    for (const rows of [[{}], [{ device_id: null }], [{ device_id: '' }]]) {
      assert.equal(scopeFromRows(rows).state, SCOPE_STATES.UNKNOWN, JSON.stringify(rows));
    }
  });

  it('a non-array is UNKNOWN', () => {
    for (const bad of ['rows', 42, {}, true]) {
      assert.equal(scopeFromRows(bad).state, SCOPE_STATES.UNKNOWN, JSON.stringify(bad));
    }
  });

  it('and the refusal says it is a FAULT, not a permission', () => {
    // An operator chasing "could not be determined" should not be sent to ask
    // for access they may already have.
    assert.match(refusalMessage(unknown()), /could not be determined/);
    assert.match(refusalMessage(unknown()), /not a permission/);
    assert.match(refusalMessage(scoped(A)), /Ask a Super Admin/);
  });
});

describe('a scoped account sees exactly what it was granted', () => {
  it('allows the granted device and denies the rest', () => {
    const s = scoped(A);
    assert.equal(isScoped(s), true);
    assert.equal(canSeeDevice(s, A), true);
    assert.equal(canSeeDevice(s, B), false);
  });

  it('deduplicates repeated grants', () => {
    assert.deepEqual(scoped(A, A, B).deviceIds, [A, B]);
  });

  it('filters a device list by either id shape', () => {
    const s = scoped(A);
    assert.deepEqual(filterDevices(s, [{ id: A }, { id: B }]).map((d) => d.id), [A]);
    assert.deepEqual(filterDevices(s, [{ device_id: A }, { device_id: B }]).length, 1);
  });

  it('⛔ binds the ids as a parameter rather than interpolating them', () => {
    // They are our own UUIDs, which is exactly the argument that erodes this
    // rule everywhere else.
    const { sql, params } = scopeSqlClause(scoped(A, B), 'd.id', 3);
    assert.equal(sql, ' AND d.id = ANY($3::uuid[])');
    assert.deepEqual(params, [[A, B]]);
    assert.equal(sql.includes(A), false, 'no id may appear in the SQL text');
  });
});

describe('⛔ junk input denies rather than throwing', () => {
  it('a missing scope or device id is a denial', () => {
    assert.equal(canSeeDevice(null, A), false);
    assert.equal(canSeeDevice(undefined, A), false);
    assert.equal(canSeeDevice(scoped(A), null), false);
    assert.equal(canSeeDevice(scoped(A), ''), false);
    assert.deepEqual(filterDevices(null, [{ id: A }]), []);
  });

  it('an unrecognised state denies — a typo must never match', () => {
    const forged = { state: 'admin', deviceIds: [A] };
    assert.equal(canSeeDevice(forged, A), false);
    assert.deepEqual(filterDevices(forged, [{ id: A }]), []);
    assert.equal(scopeSqlClause(forged, 'd.id', 1).sql, ' AND FALSE');
  });

  it('filterDevices tolerates a non-array and null entries', () => {
    assert.deepEqual(filterDevices(scoped(A), null), []);
    assert.deepEqual(filterDevices(scoped(A), [null, { id: A }]).length, 1);
  });
});

describe('loadScopeForSession', () => {
  const pool = (impl) => ({ query: impl });

  it('reads the scope for a local account', async () => {
    const seen = [];
    const s = await loadScopeForSession(
      { user: { id: UUID, provider: 'local' } },
      pool(async (sql, params) => { seen.push({ sql, params }); return { rows: [{ device_id: A }] }; })
    );
    assert.equal(s.state, SCOPE_STATES.SCOPED);
    assert.deepEqual(seen[0].params, [UUID], 'the user id comes from the session, bound');
  });

  it('⛔ an LDAP account is UNSCOPED — it has no users row to hang a scope on', () => {
    // ⛔ Decided on the PROVIDER, not the id shape. This test used to pass a
    // non-UUID id and rely on the shape test; that only worked while exactly
    // two providers existed and their shapes happened to differ. See the
    // Entra case below for what that cost.
    return loadScopeForSession({ user: { id: 'firmans0', provider: 'ldap' } }, pool(async () => {
      throw new Error('must not query for an unscopable provider');
    })).then((s) => assert.equal(s.state, SCOPE_STATES.UNSCOPED));
  });

  it('⛔ an Entra account is UNSCOPED — it has no users row to hang a scope on', async () => {
    // ⛔ CLASSIFIED, NOT GUESSED. v2.205.0 forbade deciding from the SHAPE of
    // an id; this is an explicit entry in UNSCOPABLE_PROVIDERS, the same
    // treatment LDAP has always had. The query must still never run — there is
    // no users row for that oid to match.
    let queried = false;
    const s = await loadScopeForSession(
      { user: { id: '8f4a1c2e-9b7d-4e6a-bc13-5d2f70a9e4c1', provider: 'entra' } },
      pool(async () => { queried = true; return { rows: [] }; })
    );
    assert.equal(queried, false, 'an Entra oid must never be used as a users.id');
    assert.equal(s.state, SCOPE_STATES.UNSCOPED);
  });

  it('⛔ a GUID-shaped id from an UNCLASSIFIED provider NEVER reaches the query', async () => {
    // ⛔ THE PHASE 0 DEFECT (.ai-codex/entra-sso-proposal.md). A Microsoft
    // Entra `oid` is a GUID and matches the local-UUID shape exactly. Under
    // the old shape test this was read as LOCAL, the lookup returned zero rows
    // (there is no `users` row for it to have any), and zero rows is UNSCOPED
    // — the whole fleet, silently. It must be UNKNOWN, which denies, and the
    // query must not run at all.
    const ENTRA_OID = '8f4a1c2e-9b7d-4e6a-bc13-5d2f70a9e4c1';
    assert.match(ENTRA_OID, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
      'the fixture must genuinely look like a local UUID, or this proves nothing');
    // ⛔ THE ASSERTION IS "THE QUERY NEVER RAN", NOT "THE STATE IS UNKNOWN".
    // A throwing pool would make the old code reach UNKNOWN too, via the
    // catch -> scopeFromRows(null) path — so asserting only the state passes
    // over the very bug this test exists for. Verified by mutation: with the
    // old shape check restored, the state assertion alone stayed GREEN.
    let queried = false;
    const s = await loadScopeForSession(
      { user: { id: ENTRA_OID, provider: 'saml' } },
      pool(async () => { queried = true; return { rows: [] }; })
    );
    assert.equal(queried, false, 'an unclassified provider must not reach the scope query');
    assert.equal(s.state, SCOPE_STATES.UNKNOWN, 'an unclassified provider must deny');
    assert.equal(canSeeDevice(s, A), false, 'and must not see a device');
  });

  it('⛔ a session with no provider is UNKNOWN, not unscoped', async () => {
    const s = await loadScopeForSession(
      { user: { id: UUID } },
      pool(async () => { throw new Error('must not query without a provider'); })
    );
    assert.equal(s.state, SCOPE_STATES.UNKNOWN);
  });

  it('⛔ an UNSCOPABLE provider with no usable id is UNKNOWN, never the whole fleet', async () => {
    // ⛔ ORDER IS LOAD-BEARING. With the provider branches ahead of the id
    // check, `{ id: null, provider: 'entra' }` — an Entra id_token carrying
    // neither `oid` nor `sub` — took the UNSCOPABLE branch and resolved to
    // `unscoped`, i.e. every firewall, silently, for a session SecVault could
    // not identify. The byte-identical `local` case was denied, so the
    // three-state rule held for one provider out of three.
    //
    // ⛔ The query must not run either: without an id there is nothing to bind,
    // and a pool that throws would otherwise reach UNKNOWN through the catch
    // and make a state-only assertion green under the bug.
    for (const user of [{ provider: 'entra' }, { id: null, provider: 'entra' },
                        { id: '', provider: 'ldap' }, { id: 7, provider: 'ldap' }]) {
      let queried = false;
      const s = await loadScopeForSession({ user }, pool(async () => {
        queried = true;
        return { rows: [] };
      }));
      assert.equal(queried, false, `must not query: ${JSON.stringify(user)}`);
      assert.equal(s.state, SCOPE_STATES.UNKNOWN, JSON.stringify(user));
      assert.equal(canSeeDevice(s, A), false, 'and must not see a device');
    }
  });

  it('⛔ a local provider whose id is not a UUID is a contradiction, so UNKNOWN', async () => {
    // Not "another provider" — the claim and the id disagree, and guessing
    // which half is right is how the original fail-open was built.
    const s = await loadScopeForSession(
      { user: { id: 'firmans0', provider: 'local' } },
      pool(async () => { throw new Error('must not query a malformed local id'); })
    );
    assert.equal(s.state, SCOPE_STATES.UNKNOWN);
  });

  it('⛔ a throwing pool yields UNKNOWN, never unscoped', async () => {
    const s = await loadScopeForSession(
      { user: { id: UUID, provider: 'local' } },
      pool(async () => { throw new Error('db down'); })
    );
    assert.equal(s.state, SCOPE_STATES.UNKNOWN, 'a database blip must not widen access');
  });

  it('no session is UNKNOWN, which denies', async () => {
    for (const bad of [null, undefined, {}]) {
      const s = await loadScopeForSession(bad, pool(async () => ({ rows: [] })));
      assert.equal(s.state, SCOPE_STATES.UNKNOWN, JSON.stringify(bad));
      assert.equal(canSeeDevice(s, A), false);
    }
  });
});
