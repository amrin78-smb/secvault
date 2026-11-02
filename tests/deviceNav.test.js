'use strict';

// lib/deviceNav.js — the per-device navigation.
//
// ⛔ THE TWO INVARIANTS WORTH PINNING ARE "NOTHING WAS LOST" AND "EXACTLY ONE
// ENTRY IS ACTIVE". Neither can be asserted against a hand-written tab row,
// which is why the registry is data — and the first one matters because this
// change CONSOLIDATED three unrelated navigations, so a destination quietly
// dropped in the merge would be reachable from nowhere.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  DEVICE_NAV, deviceNavHref, activeDeviceNavKey, visibleDeviceNav,
} = require('../lib/deviceNav');

const ID = '11111111-2222-3333-4444-555555555555';
const always = () => true;

describe('the registry', () => {
  it('every key is unique', () => {
    const keys = DEVICE_NAV.map((e) => e.key);
    assert.equal(new Set(keys).size, keys.length);
  });

  it('every label is unique and non-empty', () => {
    const labels = DEVICE_NAV.map((e) => e.label);
    assert.equal(new Set(labels).size, labels.length);
    for (const l of labels) assert.ok(l && l.trim().length > 1, `bad label: ${JSON.stringify(l)}`);
  });

  it('every entry resolves to an href', () => {
    for (const e of DEVICE_NAV) {
      const href = deviceNavHref(e, ID);
      assert.ok(href && href.startsWith('/'), `${e.key}: ${href}`);
    }
  });

  it('⛔ an entry is EITHER a tab on the device page OR a sub-route, never both', () => {
    for (const e of DEVICE_NAV) {
      if (e.absolute) continue;
      const isTab = Boolean(e.tab);
      const isPath = Boolean(e.path);
      assert.notEqual(isTab, isPath,
        `${e.key}: a destination with both a path and an owned tab has two addresses`);
    }
  });

  it('⛔ EVERY DESTINATION THAT EXISTED BEFORE THE MERGE IS STILL REACHABLE', () => {
    // The three navigations this registry replaced, as hrefs. A destination
    // missing from this set is one the merge silently dropped.
    const hrefs = new Set(visibleDeviceNav({
      deviceId: ID, pathname: `/devices/${ID}`, tab: 'overview', can: always,
    }).map((e) => e.href));
    const required = [
      `/devices/${ID}?tab=overview`,
      `/devices/${ID}?tab=cve`,
      `/devices/${ID}?tab=traffic`,
      `/devices/${ID}?tab=admins`,
      `/devices/${ID}?tab=manage`,
      `/devices/${ID}/rules`,
      `/devices/${ID}/changes`,
      `/devices/${ID}/vpn`,
      `/devices/${ID}/snmp`,
      `/compliance/${ID}`,
    ];
    for (const r of required) assert.ok(hrefs.has(r), `lost destination: ${r}`);
  });

  it('⛔ the two tabs with no nav entry of their own still resolve to one', () => {
    // ?tab=rules (a ten-row sample of the ruleset) and ?tab=config (a summary
    // of the change history) are both still linked to from the overview
    // tiles. They must light SOMETHING up, or the nav shows no active entry
    // on a page the product itself linked to.
    assert.equal(activeDeviceNavKey(`/devices/${ID}`, 'rules', ID), 'policy');
    assert.equal(activeDeviceNavKey(`/devices/${ID}`, 'config', ID), 'changes');
  });

  it('⛔ /analysis lights Policy — it is not a destination with no home', () => {
    assert.equal(activeDeviceNavKey(`/devices/${ID}/analysis`, '', ID), 'policy');
    assert.equal(activeDeviceNavKey(`/devices/${ID}/analysis`, 'cleanup', ID), 'policy');
  });
});

describe('active state', () => {
  it('⛔ EXACTLY ONE entry is active on every destination', () => {
    const nav = visibleDeviceNav({ deviceId: ID, pathname: `/devices/${ID}`, tab: '', can: always });
    for (const e of nav) {
      const at = e.href.includes('?tab=')
        ? { pathname: `/devices/${ID}`, tab: e.href.split('?tab=')[1] }
        : { pathname: e.href, tab: '' };
      const resolved = visibleDeviceNav({ deviceId: ID, ...at, can: always })
        .filter((x) => x.active);
      assert.equal(resolved.length, 1, `${e.key}: ${resolved.length} active`);
      assert.equal(resolved[0].key, e.key, `${e.key} resolved to ${resolved[0].key}`);
    }
  });

  it('⛔ THE PATH BEATS A STALE TAB PARAMETER', () => {
    // /devices/<id>/rules?tab=cve is the ruleset page, whatever the leftover
    // parameter says.
    assert.equal(activeDeviceNavKey(`/devices/${ID}/rules`, 'cve', ID), 'policy');
  });

  it('⛔ the suffix matches on a SEGMENT BOUNDARY, not a prefix', () => {
    // A future /rules-export must not light Policy.
    assert.equal(activeDeviceNavKey(`/devices/${ID}/rules-export`, '', ID), null);
    // ...but a real child of /rules does.
    assert.equal(activeDeviceNavKey(`/devices/${ID}/rules/42`, '', ID), 'policy');
  });

  it('⛔ an UNKNOWN sub-route activates NOTHING rather than defaulting to Overview', () => {
    assert.equal(activeDeviceNavKey(`/devices/${ID}/something-new`, '', ID), null,
      'lighting up Overview tells the operator they are somewhere they are not');
  });

  it('a missing tab is the default tab', () => {
    assert.equal(activeDeviceNavKey(`/devices/${ID}`, '', ID), 'overview');
    assert.equal(activeDeviceNavKey(`/devices/${ID}`, undefined, ID), 'overview');
  });

  it('an unrecognised tab activates nothing', () => {
    assert.equal(activeDeviceNavKey(`/devices/${ID}`, 'nonsense', ID), null);
  });

  it('a different device, or another page entirely, activates nothing', () => {
    assert.equal(activeDeviceNavKey('/devices/other-id/rules', '', ID), null);
    assert.equal(activeDeviceNavKey('/work', '', ID), null);
    assert.equal(activeDeviceNavKey('/compliance/other-id', '', ID), null);
  });

  it('compliance resolves from outside the /devices tree', () => {
    assert.equal(activeDeviceNavKey(`/compliance/${ID}`, '', ID), 'compliance');
  });

  it('non-string input is handled rather than thrown on', () => {
    assert.equal(activeDeviceNavKey(null, '', ID), null);
    assert.equal(activeDeviceNavKey(`/devices/${ID}`, '', null), null);
  });
});

describe('capability gating', () => {
  it('⛔ A GATED ENTRY IS HIDDEN WHEN NO PREDICATE IS SUPPLIED', () => {
    const nav = visibleDeviceNav({ deviceId: ID, pathname: `/devices/${ID}`, tab: 'overview' });
    assert.equal(nav.some((e) => e.key === 'manage'), false,
      'a caller that forgot the predicate must not get a Manage tab by default — '
      + 'a UI looser than the route behind it is the one direction this product refuses');
  });

  it('a denying predicate hides it; an allowing one shows it', () => {
    const deny = visibleDeviceNav({ deviceId: ID, pathname: `/devices/${ID}`, tab: 'overview', can: () => false });
    assert.equal(deny.some((e) => e.key === 'manage'), false);
    const allow = visibleDeviceNav({ deviceId: ID, pathname: `/devices/${ID}`, tab: 'overview', can: always });
    assert.equal(allow.some((e) => e.key === 'manage'), true);
  });

  it('the predicate is asked for the capability the entry names', () => {
    const asked = [];
    visibleDeviceNav({
      deviceId: ID, pathname: `/devices/${ID}`, tab: 'overview',
      can: (cap) => { asked.push(cap); return true; },
    });
    assert.deepEqual(asked, ['manage_devices']);
  });

  it('⛔ only ONE entry is gated — the rest are read-only views', () => {
    const gated = DEVICE_NAV.filter((e) => e.requires);
    assert.deepEqual(gated.map((e) => e.key), ['manage']);
  });
});

describe('the renderer', () => {
  const SRC = fs.readFileSync(
    path.join(__dirname, '..', 'components', 'devices', 'DeviceContextHeader.js'), 'utf8'
  );

  it('⛔ marks the active entry with aria-current, not colour alone', () => {
    assert.match(SRC, /aria-current=\{e\.active \? 'page' : undefined\}/);
  });

  it('⛔ the device name is a real <h1>', () => {
    assert.match(SRC, /<h1 className="dev-ctx-name">/,
      'every per-device page previously opened with a .page-title div and a '
      + 'PageHeader repeating the same name — two headings, neither marked up as one');
  });

  it('⛔ the nav is a <nav> with an accessible name', () => {
    assert.match(SRC, /<nav className="dev-ctx-nav" aria-label=/);
  });

  it('⛔ an unmeasured figure renders an em-dash with no hue, never a 0', () => {
    const fn = SRC.slice(SRC.indexOf('function Figure('), SRC.indexOf('export default function'));
    assert.match(fn, /if \(!fig\.measured\)/, 'the unmeasured branch comes first');
    const branch = fn.slice(fn.indexOf('if (!fig.measured)'), fn.indexOf('const hot'));
    assert.match(branch, /var\(--unmeasured\)/);
    assert.match(branch, /<strong>—<\/strong>/);
    assert.equal(/tone/.test(branch), false, 'a gap in our evidence is not a severity');
  });

  it('⛔ a hue is applied ONLY to a measured, non-zero value', () => {
    assert.match(SRC, /const hot = fig\.value > 0 && tone;/,
      'a measured zero is good news stated quietly, not a coloured one');
  });

  it('⛔ renders even when the context failed to load, from the fallback identity', () => {
    assert.match(SRC, /fallback && fallback\.name/,
      'chrome that disappears on a failed query takes the operator’s sense of place with it');
  });

  it('⛔ criticality is shown only above the column default', () => {
    // Every device carries `medium`; a chip on all of them teaches the
    // operator to ignore the one that says critical.
    assert.match(SRC, /c\.criticality === 'critical' \|\| c\.criticality === 'high'/);
  });

  it('⛔ the coverage gaps are joined as named sentences, not counted', () => {
    assert.match(SRC, /c\.gaps\.map\(\(g\) => g\.label\)\.join/);
    assert.equal(/gaps\.length\}%|coveragePct/.test(SRC), false);
  });
});
