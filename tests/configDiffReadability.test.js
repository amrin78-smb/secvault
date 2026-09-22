'use strict';
// tests/configDiffReadability.test.js
//
// ⛔ THE CONFIG-CHANGES PAGE WAS SHOWING INTERNAL PAN-OS PATHS TO OPERATORS.
// The summary line read:
//
//   12 added — e.g. devices.entry.vsys.entry.tag.entry[17],
//   devices.entry.vsys.entry.tag.entry[18], devices.entry.vsys.entry.tag.entry[19]
//
// and each detail row was headed by the same kind of string. An array index
// into a config tree is not something a person can look up, and it pushed the
// one fact worth reading — WHAT KIND of thing changed — off the end of the
// line. Raised on direct user feedback 2026-09-22, comparing against
// ManageEngine Firewall Analyzer.
//
// Two separate causes, and both are the same shape: a builder that resolves a
// name from the PATH, meeting a vendor shape that does not put the name there.
// PAN-OS's XML/API form is `address.entry[1716]` with the name in the VALUE as
// `@_name`. Measured live: 101 address objects, 65 security rules, 53 local
// users, 41 static routes, 23 IPsec proxy-ids.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { summarizeDiff, classifyDiff } = require('../lib/engines/configDiff');

const added = (path, value) => ({ path, value });
const diffOf = (a = [], r = [], m = []) => ({ added: a, removed: r, modified: m });

// Every friendlyDescription in a diff, flattened, for assertions.
function describeAll(diff) {
  const out = [];
  for (const s of classifyDiff(diff).sections) {
    for (const e of s.entries) out.push(e.friendlyDescription || `(raw) ${e.path}`);
  }
  return out;
}

describe('⛔ the summary says WHAT changed, not where it lives in the tree', () => {
  it('replaces the example paths with the kinds of object that moved', () => {
    const d = diffOf([
      added('devices.entry.vsys.entry.tag.entry[17]', { '@_name': 'BioStar' }),
      added('devices.entry.vsys.entry.tag.entry[18]', { '@_name': 'HRIS' }),
      added('devices.entry.vsys.entry.address.entry[1716]', { '@_name': 'HRIS-172.40.33.15' }),
      added('devices.entry.vsys.entry.service.entry[274]', { '@_name': 'FaceScan-51213' }),
    ]);
    const s = summarizeDiff(d);
    assert.match(s, /^4 added — /);
    assert.match(s, /2 tags/);
    assert.match(s, /1 address object\b/, 'singular, not "1 address objects"');
    assert.match(s, /1 service object\b/);
    assert.equal(/devices\.entry/.test(s), false, 'no internal config path may reach the summary');
    assert.equal(/e\.g\./.test(s), false);
  });

  it('keeps the added/removed/modified counts it always had', () => {
    const d = diffOf(
      [added('devices.entry.vsys.entry.address.entry[1]', { '@_name': 'a' })],
      [added('devices.entry.vsys.entry.address.entry[2]', { '@_name': 'b' })],
      [{ path: 'devices.entry.vsys.entry.address.entry[3]', old: 1, new: 2 }]
    );
    assert.match(summarizeDiff(d), /^1 added, 1 removed, 1 modified — /);
  });

  it('an empty diff still says so', () => {
    assert.equal(summarizeDiff(diffOf()), 'no changes');
  });

  it('⛔ the path fallback SURVIVES for a diff nothing can classify', () => {
    // An unclassifiable change is still a change. A summary naming only the
    // counts would hide which part of the config it touched, leaving the
    // reader with LESS than the ugly version gave them.
    const d = diffOf([added('some.unrecognised.vendor.leaf', 'x')]);
    const s = summarizeDiff(d);
    assert.match(s, /^1 added — /);
    assert.ok(/e\.g\./.test(s) || /\w/.test(s.split('—')[1]), 'something must follow the dash');
  });

  it('⛔ a long list is TRUNCATED WITH A COUNT, never silently cut', () => {
    // A list quietly cut to four reads as the whole story.
    const many = [];
    for (const kind of ['address', 'service', 'tag', 'address-group', 'schedule', 'region']) {
      many.push(added(`devices.entry.vsys.entry.${kind}.entry[1]`, { '@_name': `x-${kind}` }));
    }
    const s = summarizeDiff(diffOf(many));
    assert.match(s, / and \d+ more$/, s);
  });

  it('⛔ an acronym in a section label is not lowercased', () => {
    // Blanket-lowercasing turned "NAT Rules" into "2 nat rules", which reads
    // as a typo on the page an operator judges the product by.
    const s = summarizeDiff(diffOf([
      added('devices.entry.vsys.entry.rulebase.nat.rules.entry[27]', { '@_name': 'a' }),
      added('devices.entry.vsys.entry.rulebase.nat.rules.entry[28]', { '@_name': 'b' }),
    ]));
    assert.match(s, /2 NAT rules/);
    assert.equal(/nat rules/.test(s), false, s);
  });

  it('never throws on a malformed diff', () => {
    for (const bad of [{}, { added: null }, { added: [{}] }, { added: [{ path: null }] }]) {
      assert.doesNotThrow(() => summarizeDiff(bad), JSON.stringify(bad));
    }
  });
});

describe('⛔ an indexed entry is named from its own value', () => {
  it('names the object kinds the live fleet actually produces', () => {
    const d = diffOf([
      added('devices.entry.vsys.entry.address.entry[1716]', { '@_name': 'HRIS-172.40.33.15' }),
      added('devices.entry.vsys.entry.service.entry[274]', { '@_name': 'FaceScan-51213' }),
      added('devices.entry.vsys.entry.tag.entry[17]', { '@_name': 'BioStar' }),
      added('shared.local-user-database.user.entry[530]', { '@_name': 'abeam_cm' }),
      added('devices.entry.network.virtual-router.entry.routing-table.ip.static-route.entry[3]', { '@_name': 'to-DC' }),
    ]);
    const all = describeAll(d).join('\n');
    assert.match(all, /Address object "HRIS-172\.40\.33\.15" was added/);
    assert.match(all, /Service object "FaceScan-51213" was added/);
    assert.match(all, /Tag "BioStar" was added/);
    assert.match(all, /Local user "abeam_cm" was added/);
    assert.match(all, /Static route "to-DC" was added/);
    assert.equal(/\(raw\)/.test(all), false, 'none of these may fall back to a path');
  });

  it('reads the name on a removal and a modification too', () => {
    const rm = describeAll(diffOf([], [
      added('devices.entry.vsys.entry.address.entry[249]', { '@_name': 'S4B-sandbox' }),
    ]));
    assert.match(rm[0], /Address object "S4B-sandbox" was removed/);

    const mod = describeAll(diffOf([], [], [
      { path: 'devices.entry.vsys.entry.address.entry[9]', old: { '@_name': 'Old' }, new: { '@_name': 'New' } },
    ]));
    assert.match(mod[0], /Address object "New" was changed/, 'the new value names it');
  });

  it('⛔ A FIELD UNDER AN ENTRY IS NOT RENAMED, AND THIS ONE WOULD LIE', () => {
    // The naming rule requires the final segment to be the INDEXED ENTRY
    // ITSELF. Drop that requirement and
    //   shared.local-user-database.user-group.entry[0].user.member[42]
    // — 31 live occurrences — renders as `Local user "abeam_cm" was added`,
    // because the segment before `member` is `user`. That is not a new
    // account, it is an existing account being put into a group, and on the
    // change feed of a security product those are very different sentences.
    // A raw path is worse to read and does not claim anything false.
    const all = describeAll(diffOf([
      added('shared.local-user-database.user-group.entry[0].user.member[42]', { '@_name': 'abeam_cm' }),
    ]));
    assert.equal(/Local user "abeam_cm" was added/.test(all[0] || ''), false,
      'a group membership must never be described as a new user account');

    // A rule field is likewise left to the per-rule table, which already
    // renders it with the rule's own name and a field label.
    const rule = describeAll(diffOf([
      added('devices.entry.vsys.entry.rulebase.security.rules.entry[5].target', { '@_name': 'fw-1' }),
    ]));
    assert.equal(/"fw-1" was added/.test(rule[0] || ''), false, rule[0]);
  });

  it('⛔ an entry with NO name falls back to the path rather than naming it ""', () => {
    // `Address object "" was added` is worse than the path it replaced.
    const all = describeAll(diffOf([
      added('devices.entry.vsys.entry.address.entry[7]', { 'ip-netmask': '10.0.0.1/32' }),
      added('devices.entry.vsys.entry.address.entry[8]', { '@_name': '   ' }),
      added('devices.entry.vsys.entry.address.entry[9]', 'a-string-not-an-object'),
    ]));
    for (const line of all) assert.match(line, /^\(raw\)/, line);
  });

  it('an unmapped container still gets a name, humanised', () => {
    // Worth far more than the raw path even with no curated label.
    const all = describeAll(diffOf([
      added('devices.entry.vsys.entry.some-new-thing.entry[1]', { '@_name': 'Widget' }),
    ]));
    assert.match(all[0], /"Widget" was added/);
    assert.equal(/\(raw\)/.test(all[0]), false);
  });
});

describe('⛔ the path-named shapes are untouched', () => {
  it('a name carried IN the path still uses its own builder', () => {
    // The fallback runs LAST precisely so it cannot override these.
    const all = describeAll(diffOf(
      [added('firewall.address.DC-Server', { subnet: '10.0.0.0/24' })],
      [],
      [{ path: 'address.WebSrv.ip-netmask', old: '10.0.0.1/32', new: '10.0.0.2/32' }]
    ));
    assert.match(all.join('\n'), /Address object "DC-Server" was added/);
    assert.match(all.join('\n'), /Address object "WebSrv"'s ip netmask was changed/);
  });
});
