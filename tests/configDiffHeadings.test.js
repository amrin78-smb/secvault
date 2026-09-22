'use strict';
// tests/configDiffHeadings.test.js
//
// ⛔ WHAT THE CONFIG-CHANGES PAGE CALLS A CHANGE, AND WHERE IT FILES IT.
// Every case below was found on the live fleet, and every one of them is the
// same family of defect: a sentence or a heading that states something the
// diff entry does not say — a rule field filed as an object, a VPN user
// called an administrator, an ethernet sub-interface called a tunnel, an
// array slot called `entry`, and a corrupted path printed verbatim as a
// heading. None of them crashes; all of them read as fact.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { summarizeDiff, classifyDiff } = require('../lib/engines/configDiff');

const added = (path, value) => ({ path, value });
const diffOf = (a = [], r = [], m = []) => ({ added: a, removed: r, modified: m });

function describeAll(diff) {
  const out = [];
  for (const s of classifyDiff(diff).sections) {
    for (const e of s.entries) out.push(e.friendlyDescription || `(raw) ${e.path}`);
  }
  return out;
}

const labelsOf = (diff) => classifyDiff(diff).sections.map((s) => s.label);

describe('⛔ one rule edit stays under ONE heading', () => {
  // PAN-OS writes a rule's multi-value fields as `.tag.member[0]` and
  // `.profile-setting.profiles.virus.member[0]`, so the ambiguous key is NOT
  // the final segment and the deferral written for it could never fire. One
  // edit an operator made once was split across "Security Rules", "Tags" and
  // "Security Profiles".
  const RULE = 'devices.entry.vsys.entry.rulebase.security.rules.entry[5]';

  it('files every field of a rule with its rule', () => {
    const labels = labelsOf(diffOf([
      added(`${RULE}.tag.member[0]`, 'TUIP'),
      added(`${RULE}.profile-setting.profiles.virus.member[0]`, 'default'),
      added(`${RULE}.service.member[0]`, 'tcp-7903'),
    ]));
    assert.deepEqual(labels, ['Security Rules'], JSON.stringify(labels));
  });

  it('⛔ and a rule’s service field is not a SERVICE OBJECT', () => {
    // It rendered as `Service object "member" was added`: the object loop
    // matched the word `service` inside a rule path and then named the
    // literal word `member` as the object. The member IS the value, which is
    // what the row says now.
    const all = describeAll(diffOf([added(`${RULE}.service.member[0]`, 'tcp-7903')]));
    assert.equal(all[0], 'Service member "tcp-7903" was added');
  });

  it('⛔ the WHOLE tag collection is still the Tags section', () => {
    // The deferral is positional — below a rulebase segment. A tag namespace
    // captured as one entry has no rulebase above it and keeps its own
    // heading, which is what the original "is it the last segment" test was
    // protecting.
    assert.deepEqual(labelsOf(diffOf([added('devices.entry.vsys.entry.tag', { BioStar: {} })])), ['Tags']);
  });

  it('a real service OBJECT is untouched', () => {
    assert.deepEqual(
      labelsOf(diffOf([added('devices.entry.vsys.entry.service.entry[274]', { '@_name': 'FaceScan-51213' })])),
      ['Service Objects']
    );
  });
});

describe('⛔ a container entry is named, not called `entry`', () => {
  it('reads an HA group’s name out of its value', () => {
    // `deviceconfig.high-availability.group.entry[0]` said "High availability
    // group entry was added" — and because a description now existed, the
    // display layer dropped the `@_name` row as a duplicate of a heading that
    // never said it. The name then appeared NOWHERE on the page.
    const all = describeAll(diffOf([
      added('devices.entry.deviceconfig.high-availability.group.entry[0]', {
        '@_name': 'HA-Group-1',
        mode: { 'active-passive': {} },
      }),
    ]));
    assert.equal(all[0], 'High availability group "HA-Group-1" was added');
    assert.equal(/\bentry\b/.test(all[0]), false, all[0]);
  });

  it('an ordinary deviceconfig setting still names the setting', () => {
    const all = describeAll(diffOf([], [], [
      { path: 'devices.entry.deviceconfig.system.ip-address', old: '10.0.0.1', new: '10.0.0.2' },
    ]));
    assert.match(all[0], /System ip address was changed/i);
  });

  it('⛔ an entry with no readable name claims nothing', () => {
    const all = describeAll(diffOf([
      added('devices.entry.deviceconfig.high-availability.group.entry[0]', { mode: {} }),
    ]));
    assert.equal(/"/.test(all[0]), false, all[0]);
  });
});

describe('⛔ a noun must not claim the wrong kind of thing', () => {
  it('`units` is every interface type’s sub-interface container, not tunnels’', () => {
    // "Tunnel interface ip was added" about an ETHERNET sub-interface is a
    // false statement about which interface changed.
    const eth = describeAll(diffOf([], [], [{
      path: 'devices.entry.network.interface.ethernet.entry[2].layer3.units.entry[5].ip',
      old: '10.0.0.1/24',
      new: '10.0.0.2/24',
    }]))[0];
    assert.equal(/tunnel/i.test(eth), false, eth);
    assert.match(eth, /interface unit ip was changed/i);
  });

  it('...and the tunnel wording survives where it is true', () => {
    const tun = describeAll(diffOf([], [], [{
      path: 'devices.entry.network.interface.tunnel.units.entry[5].ip',
      old: '10.0.0.1/32',
      new: '10.0.0.2/32',
    }]))[0];
    assert.match(tun, /Tunnel interface ip was changed/i);
  });

  it('⛔ a VPN user is NOT an administrator', () => {
    // `Administrator "vpnuser1" was added` is a privileged-account-creation
    // claim, made about a `users` container with nothing to do with
    // mgt-config.
    const vpn = describeAll(diffOf([
      added('devices.entry.ssl_vpn.users.entry[0]', { '@_name': 'vpnuser1' }),
    ]))[0];
    assert.equal(/administrator/i.test(vpn), false, vpn);
    assert.match(vpn, /"vpnuser1" was added/);
  });

  it('...and a real PAN-OS admin still reads as one', () => {
    const admin = describeAll(diffOf([
      added('devices.entry.mgt-config.users.entry[0]', { '@_name': 'awnadm' }),
    ]))[0];
    assert.match(admin, /Administrator "awnadm" was added/);
  });
});

describe('⛔ the section phrase is English, not a template', () => {
  const summaryFor = (prefix, count) => {
    const entries = [];
    for (let i = 0; i < count; i += 1) entries.push(added(`${prefix}${i}`, i));
    return summarizeDiff(diffOf(entries));
  };

  it('an acronym is neither lowercased nor cut in half', () => {
    // The trailing-`s` strip ran BEFORE the acronym lookup, so "DNS" was cut
    // to "DN" and the line read "1 dn".
    assert.match(summaryFor('dns.server', 1), /1 change to DNS$/);
    assert.match(summaryFor('dns.server', 3), /3 changes to DNS$/);
  });

  it('a proper noun is not pluralised', () => {
    // Seen live: "2 global protects".
    const s = summaryFor('global-protect.setting', 2);
    assert.match(s, /2 changes to GlobalProtect$/);
    assert.equal(/global protect/.test(s), false, s);
  });

  it('⛔ a section that is not a COUNT NOUN is reported as changes TO it', () => {
    // "system infos" and "password policys" are not words. These name a part
    // of the configuration, not a countable thing.
    assert.match(summaryFor('system_info.field', 2), /2 changes to System Info$/);
    assert.match(summaryFor('password_policy.field', 1), /1 change to Password Policy$/);
  });

  it('a count noun still counts, singular and plural', () => {
    assert.match(summaryFor('devices.entry.vsys.entry.tag.entry', 1), /1 tag$/);
    assert.match(summaryFor('devices.entry.vsys.entry.tag.entry', 4), /4 tags$/);
  });

  it('every word of a compound label is singularised, not just the last', () => {
    // "1 zones/interface" reads as a bug in the product.
    assert.match(summaryFor('devices.entry.vsys.entry.zone.entry', 1), /1 zone\/interface$/);
    assert.match(summaryFor('devices.entry.vsys.entry.zone.entry', 3), /3 zones\/interfaces$/);
  });

  it('the NAT acronym case this page already promised still holds', () => {
    assert.match(summaryFor('devices.entry.vsys.entry.rulebase.nat.rules.entry', 2), /2 NAT rules/);
  });
});

describe('⛔ a corrupted path may not become a corrupted HEADING', () => {
  // The brace-grammar redaction bug can swallow thousands of characters of
  // raw config text — literal newlines included — into what should have been
  // one key. sanitizeExamplePath() caught that for the example paths; the
  // section phrase introduced later never went through it, so one corrupted
  // row produced a multi-thousand-character multi-line change_summary again.
  const corrupt = `${'foo { ip-netmask 1.2.3.0/24; }\n'.repeat(400)}bar`;

  it('the summary stays short and single-line', () => {
    const s = summarizeDiff(diffOf([added(corrupt, 1)]));
    assert.ok(s.length < 200, `summary was ${s.length} characters`);
    assert.equal(/[\n{}]/.test(s), false, JSON.stringify(s.slice(0, 120)));
  });

  it('and the SECTION HEADING is bounded too, not just the summary', () => {
    // config_diffs has several independent places a path can render, and
    // fixing one is not fixing the others.
    assert.deepEqual(labelsOf(diffOf([added(corrupt, 1)])), ['Other (unreadable)']);
  });

  it('a merely LONG segment is refused the same way', () => {
    assert.deepEqual(labelsOf(diffOf([added(`${'a'.repeat(300)}.leaf`, 1)])), ['Other (unreadable)']);
  });

  it('an ordinary unknown segment still names itself', () => {
    assert.deepEqual(
      labelsOf(diffOf([added('some-new-vendor-section.leaf', 1)])),
      ['Other (Some New Vendor Section)']
    );
  });
});
