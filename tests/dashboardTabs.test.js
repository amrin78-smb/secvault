'use strict';
// Pins the dashboard's ?tab= handling.
//
// A tab key is USER-SUPPLIED INPUT — it arrives from the URL bar, a stale
// bookmark, or a link in a ticket. Every other tabbed page in this app
// whitelists it inline, and this is the one place that behaviour is tested:
// an unrecognised value must land on a real tab, because a blank dashboard is
// indistinguishable from an outage to whoever is looking at it.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  DASHBOARD_TABS,
  DEFAULT_DASHBOARD_TAB,
  resolveDashboardTab,
  dashboardTabByKey,
} = require('../lib/dashboardTabs');

const KEYS = DASHBOARD_TABS.map((t) => t.key);

describe('dashboardTabs: the tab list itself', () => {
  it('has a default that is actually one of the tabs', () => {
    assert.ok(
      KEYS.includes(DEFAULT_DASHBOARD_TAB),
      'the fallback must be renderable, or every bad URL renders nothing'
    );
  });

  it('has unique keys', () => {
    assert.equal(new Set(KEYS).size, KEYS.length, 'a duplicate key makes one tab unreachable');
  });

  it('gives every tab a key, a label and a description', () => {
    for (const tab of DASHBOARD_TABS) {
      assert.equal(typeof tab.key, 'string');
      assert.ok(tab.key.length > 0);
      assert.equal(typeof tab.label, 'string');
      assert.ok(tab.label.length > 0, `${tab.key} needs a visible label`);
      assert.equal(typeof tab.description, 'string');
      assert.ok(tab.description.length > 0);
    }
  });

  it('keeps keys URL-safe and lowercase', () => {
    // These become query-string values and, once shared, a public contract.
    for (const key of KEYS) {
      assert.equal(key, key.toLowerCase());
      assert.equal(key, encodeURIComponent(key), `${key} would need escaping in a URL`);
    }
  });

  it('does NOT ship a live-traffic tab yet', () => {
    // Deliberately absent until services/collector.js (Phase 8) exists. A tab
    // that renders "no data" for a capability the product does not have reads
    // as a broken feature rather than a roadmap. Delete this test in the same
    // commit that adds the tab — that is the point of it.
    assert.ok(
      !KEYS.some((k) => /traffic|syslog|log/.test(k)),
      'add the tab and remove this test together, once the syslog collector ships'
    );
  });
});

describe('dashboardTabs: resolving a ?tab= value never yields a blank page', () => {
  it('accepts every real key unchanged', () => {
    for (const key of KEYS) {
      assert.equal(resolveDashboardTab(key), key);
    }
  });

  it('falls back to the default for an unknown key', () => {
    assert.equal(resolveDashboardTab('nope'), DEFAULT_DASHBOARD_TAB);
    assert.equal(resolveDashboardTab('traffic'), DEFAULT_DASHBOARD_TAB);
  });

  it('falls back for a missing or non-string value', () => {
    for (const junk of [undefined, null, '', 42, true, {}, () => {}]) {
      assert.equal(
        resolveDashboardTab(junk),
        DEFAULT_DASHBOARD_TAB,
        `${JSON.stringify(junk)} must resolve to a renderable tab`
      );
    }
  });

  it('takes the first entry when the param repeats (?tab=a&tab=b)', () => {
    // Next.js hands searchParams an ARRAY for a repeated key. Stringifying it
    // would produce "security,fleet", match nothing, and silently bounce a
    // user who asked for a real tab back to Overview.
    assert.equal(resolveDashboardTab(['security', 'fleet']), 'security');
    assert.equal(resolveDashboardTab(['nope', 'security']), DEFAULT_DASHBOARD_TAB);
    assert.equal(resolveDashboardTab([]), DEFAULT_DASHBOARD_TAB);
  });

  it('tolerates surrounding whitespace and casing from a hand-typed URL', () => {
    assert.equal(resolveDashboardTab('  security '), 'security');
    assert.equal(resolveDashboardTab('SECURITY'), 'security');
  });

  it('always returns a key that dashboardTabByKey() can render', () => {
    for (const junk of ['nope', undefined, ['x'], 42, 'fleet']) {
      const resolved = resolveDashboardTab(junk);
      assert.ok(dashboardTabByKey(resolved), `${resolved} must be renderable`);
    }
  });
});

describe('dashboardTabs: dashboardTabByKey', () => {
  it('returns the tab for a real key', () => {
    const tab = dashboardTabByKey(DEFAULT_DASHBOARD_TAB);
    assert.ok(tab);
    assert.equal(tab.key, DEFAULT_DASHBOARD_TAB);
  });

  it('returns null — not undefined, not a fake tab — for an unknown key', () => {
    assert.equal(dashboardTabByKey('nope'), null);
    assert.equal(dashboardTabByKey(undefined), null);
  });
});
