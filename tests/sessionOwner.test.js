// ⛔ ONE DECISION, ONE MODULE, AND A SCAN THAT STOPS A FOURTH COPY APPEARING.
//
// The rule — an account's ability to own per-user rows is decided on
// `session.user.provider`, NEVER on the SHAPE of `session.user.id` — was
// established product-wide in v2.205.0 because an Entra `oid` is a
// 36-character GUID that passes any local-UUID test. It then existed in THREE
// hand-written copies, and the third was still wrong: `/api/mfa` kept
// `/^[0-9a-f-]{36}$/i` under a comment asserting the superseded rule verbatim,
// so an Entra session was read as a local account, offered MFA enrolment it
// cannot hold, and sent an INSERT that could only raise a foreign-key
// violation — on a route with no try/catch and a panel with no catch, i.e. a
// silently dead button.
//
// The two saved-views copies were byte-identical under a comment reading
// "change both in the same commit", which is a hope rather than an invariant.
// This file is the invariant.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { stripComments } = require('./stripComments');

const {
  ownerOf, OWNER_STATES, providerLabel, OWNING_PROVIDERS, NON_OWNING_PROVIDERS,
} = require('../lib/sessionOwner');

const REPO = path.join(__dirname, '..');
const LOCAL_ID = '3f2504e0-4f89-11d3-9a0c-0305e82c3301';
// A real Entra object id is a GUID, which is the whole point.
const ENTRA_OID = '8f4a1c2e-9b7d-4e6a-bc13-5d2f70a9e4c1';

describe('⛔ the owner is decided by PROVIDER, never by the id\'s shape', () => {
  it('a local account with a users-row UUID owns rows', () => {
    const o = ownerOf({ user: { id: LOCAL_ID, provider: 'local' } });
    assert.equal(o.state, OWNER_STATES.OWNER);
    assert.equal(o.userId, LOCAL_ID);
  });

  // ⛔ THE REGRESSION TEST. Under the old shape check this returned the oid as
  // a usable local user id.
  it('⛔ an Entra oid is NON-OWNING even though it is shaped exactly like a local id', () => {
    const o = ownerOf({ user: { id: ENTRA_OID, provider: 'entra' } });
    assert.equal(o.state, OWNER_STATES.NON_OWNING,
      'an Entra GUID must never be read as a local account');
    assert.equal(o.userId, null, 'no user id may escape for a provider that owns no rows');
  });

  it('an LDAP bare username is non-owning', () => {
    const o = ownerOf({ user: { id: 'FIRMANS0', provider: 'ldap' } });
    assert.equal(o.state, OWNER_STATES.NON_OWNING);
  });

  // ⛔ THREE STATES, NEVER TWO. "This provider cannot own rows" is a limitation
  // to explain; "we do not know who this is" is a fault to report. Collapsing
  // them tells someone whose session failed to read that their directory does
  // not support the feature, which sends them to the wrong person.
  it('⛔ an unknown provider, an absent provider and an absent id are all UNKNOWN, not non-owning', () => {
    for (const [what, session] of [
      ['unclassified provider', { user: { id: LOCAL_ID, provider: 'saml' } }],
      ['absent provider', { user: { id: LOCAL_ID } }],
      ['empty provider', { user: { id: LOCAL_ID, provider: '' } }],
      ['absent id', { user: { provider: 'local' } }],
      ['empty id', { user: { id: '', provider: 'local' } }],
      ['no user', {}],
      ['no session', null],
    ]) {
      const o = ownerOf(session);
      assert.equal(o.state, OWNER_STATES.UNKNOWN, what);
      assert.equal(o.userId, null, `${what}: no id may escape an unknown verdict`);
    }
  });

  it('⛔ a local claim carrying a non-UUID id is a CONTRADICTION, not another provider', () => {
    const o = ownerOf({ user: { id: 'FIRMANS0', provider: 'local' } });
    assert.equal(o.state, OWNER_STATES.UNKNOWN);
  });

  it('the two provider sets are disjoint, so a provider cannot be both', () => {
    for (const p of OWNING_PROVIDERS) {
      assert.equal(NON_OWNING_PROVIDERS.has(p), false, `${p} is in both sets`);
    }
  });

  it('providerLabel names the directory, and falls back rather than printing undefined', () => {
    assert.equal(providerLabel('entra'), 'Microsoft Entra ID');
    assert.equal(providerLabel('ldap'), 'LDAP');
    assert.equal(providerLabel('wat'), 'a directory');
    assert.equal(providerLabel(undefined), 'a directory');
  });
});

describe('⛔ no route re-implements the decision', () => {
  // ⛔ THIS IS WHAT REPLACES "change both in the same commit". The scan is the
  // reason the module exists: three copies drifted, and only one of them was
  // caught by a human reading it.
  const CONSUMERS = [
    'app/api/mfa/route.js',
    'app/api/saved-views/route.js',
    'app/api/saved-views/[id]/route.js',
  ];

  it('every consumer imports the shared helper', () => {
    for (const f of CONSUMERS) {
      const src = stripComments(fs.readFileSync(path.join(REPO, f), 'utf8'));
      assert.match(src, /from '(\.\.\/)+lib\/sessionOwner'/,
        `${f} must import lib/sessionOwner rather than deciding for itself`);
    }
  });

  it('⛔ and none of them keeps a private copy of the rule', () => {
    for (const f of CONSUMERS) {
      const src = stripComments(fs.readFileSync(path.join(REPO, f), 'utf8'));
      assert.doesNotMatch(src, /function ownerOf\s*\(/, `${f} redefines ownerOf`);
      assert.doesNotMatch(src, /OWNING_PROVIDERS\s*=\s*new Set/, `${f} redeclares the provider sets`);
      // The id-shape test is the specific thing that was still live in /api/mfa.
      assert.doesNotMatch(src, /\[0-9a-f-\]\{36\}/,
        `${f} still tests the id's SHAPE — an Entra oid passes that`);
    }
  });

  it('⛔ no surface anywhere decides scopability from a 36-char id shape', () => {
    // The loose `[0-9a-f-]{36}` form is the dangerous one: it matches an Entra
    // GUID. lib/deviceScope.js keeps a STRICT dashed-UUID regex as its own
    // contradiction check, which is a different thing and is allowed.
    const roots = ['app', 'lib', 'components'];
    const offenders = [];
    const walk = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) { walk(full); continue; }
        if (!e.name.endsWith('.js')) continue;
        const src = stripComments(fs.readFileSync(full, 'utf8'));
        if (/\[0-9a-f-\]\{36\}/.test(src)) offenders.push(path.relative(REPO, full));
      }
    };
    for (const r of roots) walk(path.join(REPO, r));
    assert.deepEqual(offenders, [],
      'these decide something from a 36-character id shape, which an Entra oid satisfies: '
      + offenders.join(', '));
  });
});
