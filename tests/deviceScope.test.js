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

  it('reads the scope for a local (UUID) account', async () => {
    const seen = [];
    const s = await loadScopeForSession(
      { user: { id: UUID } },
      pool(async (sql, params) => { seen.push({ sql, params }); return { rows: [{ device_id: A }] }; })
    );
    assert.equal(s.state, SCOPE_STATES.SCOPED);
    assert.deepEqual(seen[0].params, [UUID], 'the user id comes from the session, bound');
  });

  it('⛔ an LDAP account is UNSCOPED — it has no users row to hang a scope on', () => {
    // The two providers do not return the same kind of id, so the SHAPE is
    // checked rather than the provider name trusted — the call saved views
    // already make.
    return loadScopeForSession({ user: { id: 'firmans0' } }, pool(async () => {
      throw new Error('must not query for a non-UUID id');
    })).then((s) => assert.equal(s.state, SCOPE_STATES.UNSCOPED));
  });

  it('⛔ a throwing pool yields UNKNOWN, never unscoped', async () => {
    const s = await loadScopeForSession(
      { user: { id: UUID } },
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
