'use strict';
// tests/configDiffTreePaths.test.js
//
// ⛔ THE BIGGEST REMAINING WALL OF RAW PATHS ON THE CONFIG-CHANGES PAGE.
// The PAN-OS CLI/brace capture writes the object's name INTO the path, and a
// PAN-OS name legitimately contains dots and spaces:
//
//   tree.address.NW_GoogleCloud-10.120.0.0_20
//   tree.shared.local-user-database.user-group.SSL_GROUP.user[67]
//   tree.rulebase.nat.rules.192.168.2.0 TO WAN-Specific.source[4]
//
// Every builder in configDiff.js resolves a name by splitting on '.', so each
// of these either fragments into an object that does not exist or resolves
// nothing at all. Measured on the live fleet: 496 of 523 rendered entries on
// one firewall's page were raw `tree.` paths, and the shape is current on 7
// Palo Altos.
//
// The two ways to get this wrong are opposite and both are fabrications: cut
// the name short and you name an object the device does not have; swallow a
// real field into the name and you do the same. Both are pinned below.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { classifyDiff } = require('../lib/engines/configDiff');

const diffOf = (a = [], r = [], m = []) => ({ added: a, removed: r, modified: m });

function describeAll(diff) {
  const out = [];
  for (const s of classifyDiff(diff).sections) {
    for (const e of s.entries) out.push(e.friendlyDescription || `(raw) ${e.path}`);
  }
  return out;
}

const one = (entry, kind = 'added') => describeAll(
  kind === 'added' ? diffOf([entry]) : kind === 'removed' ? diffOf([], [entry]) : diffOf([], [], [entry])
)[0];

describe('⛔ a `tree.` name is read whole, never split on its own dots', () => {
  it('names an address object whose name contains dots', () => {
    assert.equal(
      one({ path: 'tree.address.NW_GoogleCloud-10.120.0.0_20', value: { 'ip-netmask': '10.120.0.0/20' } }),
      'Address object "NW_GoogleCloud-10.120.0.0_20" was added'
    );
  });

  it('⛔ and never reports the FRAGMENT as the object', () => {
    // `Address object "NW_GoogleCloud-10" was changed` names something that is
    // not on the device, with no hedge — worse than the raw path it replaced.
    // This is why the anchored namer runs BEFORE the path-splitting builders
    // for a dotted or spaced name.
    const line = one(
      { path: 'tree.address.NW_GoogleCloud-10.120.0.0_20.ip-netmask', old: '10.120.0.0/20', new: '10.120.0.0/21' },
      'modified'
    );
    assert.match(line, /"NW_GoogleCloud-10\.120\.0\.0_20"/, line);
    assert.equal(/"NW_GoogleCloud-10"/.test(line), false, line);
  });

  it('a name containing SPACES survives too', () => {
    assert.equal(
      one({ path: 'tree.rulebase.nat.rules.192.168.2.0 TO WAN-Specific.source[4]', value: '10.1.1.1' }),
      'NAT rule "192.168.2.0 TO WAN-Specific"\'s source was added'
    );
  });

  it('⛔ AN FQDN ADDRESS OBJECT IS A NAME, NOT A NAME PLUS A FIELD', () => {
    // Live on this fleet: `{"fqdn":"adobe.com"}`. The field-tail pattern
    // happily eats `.com`, which produced `Address object "adobe"'s com was
    // added` — an object that is not there and a setting that does not exist.
    assert.equal(
      one({ path: 'tree.address.adobe.com', value: { fqdn: 'adobe.com' } }),
      'Address object "adobe.com" was added'
    );
    assert.equal(
      one({ path: 'tree.address.m.platform.boomi.com', value: { fqdn: 'm.platform.boomi.com' } }),
      'Address object "m.platform.boomi.com" was added'
    );
  });

  it('⛔ a REAL field is still a field, even when its value is an object', () => {
    // `protocol` is PAN-OS schema, so it outranks the value-shape tiebreak —
    // this one carries `{"enabled":"no", ...}` and is still a field, not part
    // of the gateway's name.
    assert.equal(
      one({
        path: 'tree.network.ike.gateway.IDC-Salaya.protocol.ikev2.pq-ppk',
        value: { enabled: 'no', 'negotiation-mode': 'preferred' },
      }),
      'IKE gateway "IDC-Salaya"\'s protocol ikev2 pq ppk was added'
    );
  });

  it('an UNRECOGNISED tail on a scalar is still read as a field', () => {
    // A scalar value means the path ended at a leaf, so the split stands even
    // though nothing in the schema list matches.
    assert.equal(
      one({ path: 'tree.address.WEB-SRV.some-new-field', value: '10.0.0.5/32' }),
      'Address object "WEB-SRV"\'s some new field was added'
    );
  });

  it('an all-lower-case one-word name is not mistaken for a field', () => {
    assert.equal(
      one({ path: 'tree.shared.local-user-database.user.zenith01', value: { disabled: 'no' } }),
      'Local user "zenith01" was added'
    );
  });

  it('`shared` is a wrapper, so one section list serves both scopes', () => {
    assert.equal(
      one({ path: 'tree.shared.address.host.example.com', value: { fqdn: 'host.example.com' } }),
      'Address object "host.example.com" was added'
    );
  });

  it('the whole section appearing names the SECTION, never an object', () => {
    assert.equal(one({ path: 'tree.address', value: {} }), 'Address object section was added');
  });

  it('⛔ a secret-shaped field is never named in the sentence', () => {
    const line = one(
      { path: 'tree.network.ike.gateway.IDC-Salaya.pre-shared-key', old: '<redacted>', new: '<redacted>' },
      'modified'
    );
    assert.equal(line, 'IKE gateway "IDC-Salaya" was changed');
    assert.equal(/pre|shared|key/i.test(line), false, line);
  });
});

describe('⛔ the anchored namer never overrides a builder that knows more', () => {
  it('a group membership keeps its own sentence', () => {
    // `User group "SSL_GROUP"'s user was added` would be true and useless:
    // the local-user-database builder says WHO joined WHICH group.
    assert.equal(
      one({ path: 'tree.shared.local-user-database.user-group.SSL_GROUP.user[67]', value: 'jdoe' }),
      'User "jdoe" was added to group "SSL_GROUP"'
    );
  });

  it('a section nobody registered still falls back to the raw path', () => {
    // Inventing a noun for an unknown PAN-OS section is the guess this file
    // refuses; the raw path claims nothing.
    assert.match(one({ path: 'tree.some-unknown-section.Thing', value: { a: 1 } }), /^\(raw\) tree\./);
  });

  it('a path that is not `tree.`-prefixed is untouched by any of this', () => {
    assert.equal(
      one({ path: 'firewall.address.DC-Server', value: { subnet: '10.0.0.0/24' } }),
      'Address object "DC-Server" was added'
    );
  });

  it('never throws on a malformed entry', () => {
    for (const bad of [
      { path: 'tree.', value: 1 },
      { path: 'tree.address.', value: 1 },
      { path: 'tree.address..x', value: 1 },
      { path: 'tree.address.X', value: null },
    ]) {
      assert.doesNotThrow(() => describeAll(diffOf([bad])), JSON.stringify(bad));
    }
  });
});
