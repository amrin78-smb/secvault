'use strict';

// lib/settingsTabs.js — Settings split by WHOSE setting it is.
//
// ⛔ THE DEFECT WAS INSIDE TWO TABS, NOT ONLY BETWEEN THEM. "General" and
// "Security" are the only two an Operator can open, and both mixed that
// person's own settings with the whole installation's. So the test that
// matters is not "are there groups" — it is "can a tab with no capability
// requirement still reach a server-wide control".

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { stripComments } = require('./stripComments');

const {
  SETTINGS_GROUPS, SETTINGS_TABS, LEGACY_TAB_ALIASES, DEFAULT_SETTINGS_TAB,
  resolveSettingsTab, visibleSettingsGroups, visibleSettingsTabs, groupForSettingsTab,
} = require('../lib/settingsTabs');

const PAGE = stripComments(
  fs.readFileSync(path.join(__dirname, '..', 'app', '(dashboard)', 'settings', 'page.js'), 'utf8')
);

// The whole `security` panel block, bounded by the next tab block rather
// than by a character count.
function securityBlock() {
  const start = PAGE.indexOf("effectiveTab === 'security'");
  const rest = PAGE.slice(start + 10);
  const next = rest.search(/effectiveTab === '/);
  return rest.slice(0, next === -1 ? undefined : next);
}

const SUPER_ADMIN = {
  manage_users: true, manage_credential_profiles: true, manage_devices: true,
  manage_settings: true, run_update: true, operate: true,
  view_identity: true, view_log_search: true, manage_license: true,
};
const OPERATOR = { operate: true };

describe('nothing was lost in the regrouping', () => {
  // Every tab the flat list carried, before the split.
  const HISTORICAL = [
    'general', 'security', 'users', 'signon', 'profiles',
    'notifications', 'certificate', 'subscription', 'updates', 'about',
  ];

  it('⛔ every historical tab key still exists', () => {
    const keys = SETTINGS_TABS.map((t) => t.key);
    for (const k of HISTORICAL) {
      assert.ok(keys.includes(k) || LEGACY_TAB_ALIASES[k], `lost tab: ${k}`);
    }
  });

  it('⛔ every historical ?tab= value still resolves to a real tab', () => {
    for (const k of HISTORICAL) {
      const r = resolveSettingsTab(k);
      assert.ok(SETTINGS_TABS.some((t) => t.key === r), `${k} resolves to nothing`);
    }
  });

  it('⛔ `general` and `security` KEPT their keys although their contents moved', () => {
    // Both are in this product's own release notes and in tickets.
    assert.equal(resolveSettingsTab('general'), 'general');
    assert.equal(resolveSettingsTab('security'), 'security');
  });

  it('every alias points at a tab that exists', () => {
    for (const [from, to] of Object.entries(LEGACY_TAB_ALIASES)) {
      assert.ok(SETTINGS_TABS.some((t) => t.key === to), `${from} -> ${to} (missing)`);
    }
  });

  it('keys and labels are unique across all three groups', () => {
    const keys = SETTINGS_TABS.map((t) => t.key);
    assert.equal(new Set(keys).size, keys.length);
    const labels = SETTINGS_TABS.map((t) => t.label);
    assert.equal(new Set(labels).size, labels.length);
  });

  it('⛔ the page renders a block for every registered tab', () => {
    for (const t of SETTINGS_TABS) {
      assert.ok(PAGE.includes(`effectiveTab === '${t.key}'`), `${t.key} has no panel`);
    }
  });

  it('⛔ and renders nothing for a tab that is not registered', () => {
    const rendered = [...PAGE.matchAll(/effectiveTab === '([a-z]+)'/g)].map((m) => m[1]);
    const keys = new Set(SETTINGS_TABS.map((t) => t.key));
    for (const r of new Set(rendered)) {
      assert.ok(keys.has(r), `${r} is rendered but unreachable from any tab`);
    }
  });
});

describe('⛔ an ungated tab may not reach a server-wide control', () => {
  it('My preferences holds no gated tab — that is what defines the group', () => {
    const prefs = SETTINGS_GROUPS.find((g) => g.key === 'preferences');
    for (const t of prefs.tabs) {
      assert.equal(t.requires, undefined,
        `${t.key} needs a capability, so it affects more than the signed-in user `
        + 'and belongs in Administration');
    }
  });

  it('⛔ FEED SYNC LEFT THE UNGATED TAB. It is the server collection schedule', () => {
    const feeds = SETTINGS_TABS.find((t) => t.key === 'feeds');
    assert.ok(feeds, 'the feeds tab is missing');
    assert.equal(feeds.requires, 'manage_settings');
    assert.equal(groupForSettingsTab('feeds'), 'administration');
    // And it is no longer inside the general block.
    const general = PAGE.slice(PAGE.indexOf("effectiveTab === 'general'"));
    assert.equal(/Feed Sync/.test(general.slice(0, 400)), false);
  });

  it('⛔ THE SESSION TIMEOUT DELIBERATELY STAYED PERSONAL, and this pins the reason', () => {
    // SessionTimeoutPanel is shown to EVERY role and editable only with
    // manage_settings, because every role is SUBJECT to the timeout and
    // someone signed out who cannot find out why concludes the product is
    // broken. Moving it behind an admin gate would have hidden the
    // explanation from exactly the people who need it.
    assert.equal(SETTINGS_TABS.some((t) => t.key === 'sessions'), false,
      'an admin-gated Sessions tab would remove a deliberate existing behaviour');
    // ⛔ SLICED TO THE NEXT TAB BLOCK, not to a fixed character count. The
    // first draft read 900 characters and missed the panel, because the
    // password card moved in above it and is longer than that — a guard whose
    // window depends on the length of unrelated markup is one that stops
    // firing the next time something is inserted.
    assert.match(securityBlock(), /<SessionTimeoutPanel canManage=\{Boolean\(caps\.manage_settings\)\}/,
      'it must stay visible to every role, read-only without the capability');
  });

  it('⛔ your password and your second factor are in ONE place now', () => {
    assert.match(securityBlock(), /<SecurityPanel \/>/);
    assert.match(securityBlock(), /Change Your Password/);
  });
});

describe('what each role actually sees', () => {
  it('a Super Admin sees all three groups', () => {
    const g = visibleSettingsGroups(SUPER_ADMIN);
    assert.deepEqual(g.map((x) => x.key), ['preferences', 'administration', 'system']);
  });

  it('⛔ AN OPERATOR SEES NO EMPTY "Administration" HEADING', () => {
    const g = visibleSettingsGroups(OPERATOR);
    assert.deepEqual(g.map((x) => x.key), ['preferences', 'system'],
      'a heading over nothing reads as a loading failure, or as something being withheld');
  });

  it('an Operator keeps appearance, their own account, subscription and about', () => {
    const tabs = visibleSettingsTabs(OPERATOR).map((t) => t.key);
    assert.deepEqual(tabs, ['general', 'security', 'subscription', 'about']);
  });

  it('⛔ Subscription stays visible to every role — the Server ID lives there', () => {
    const sub = SETTINGS_TABS.find((t) => t.key === 'subscription');
    assert.equal(sub.requires, undefined,
      'an operator asked to read the Server ID off the server for a renewal '
      + 'should not need to borrow a Super Admin account');
  });

  it('no capabilities at all still yields a usable Settings page', () => {
    const tabs = visibleSettingsTabs({});
    assert.ok(tabs.length >= 3);
    assert.ok(tabs.some((t) => t.key === 'general'));
  });

  it('every gated tab names a real capability', () => {
    const CAPS = new Set(Object.keys(SUPER_ADMIN));
    for (const t of SETTINGS_TABS) {
      if (!t.requires) continue;
      assert.ok(CAPS.has(t.requires), `${t.key} requires unknown capability ${t.requires}`);
    }
  });
});

describe('resolution', () => {
  it('an unknown tab falls back to the default', () => {
    assert.equal(resolveSettingsTab('nonsense'), DEFAULT_SETTINGS_TAB);
    assert.equal(resolveSettingsTab(undefined), DEFAULT_SETTINGS_TAB);
  });

  it('every tab belongs to exactly one group', () => {
    for (const t of SETTINGS_TABS) {
      const owning = SETTINGS_GROUPS.filter((g) => g.tabs.some((x) => x.key === t.key));
      assert.equal(owning.length, 1, `${t.key}: ${owning.length} groups`);
    }
  });

  it('⛔ the page resolves deep links through the registry, not a local copy', () => {
    // ⛔ THE ASSERTION MOVED WITH THE MECHANISM. It used to match the
    // mount-only effect's `SETTINGS_TABS.some(...)`; v2.221.0 made the URL
    // the single source, so the registry is consulted through
    // resolveSettingsTab() on every render instead of once on mount.
    assert.match(PAGE, /resolveSettingsTab\(urlParams\.get\('tab'\)\)/);
    assert.equal(/const TABS = \[/.test(PAGE), false, 'a second copy of the tab list');
  });

  it('⛔ THE URL IS THE TAB, so a link into a tab works from Settings itself', () => {
    // The mount-only effect meant navigating /settings?tab=general ->
    // /settings?tab=users changed the address bar and nothing else. The
    // command palette now offers all eleven tabs, so that is the one page
    // where it would have looked broken.
    assert.match(PAGE, /const urlParams = useSearchParams\(\)/);
    assert.equal(
      /useState\('general'\)/.test(PAGE), false,
      'client-only tab state cannot be linked to and breaks the Back button'
    );
    assert.match(PAGE, /router\.replace\(`\/settings\?tab=\$\{key\}`/,
      'a tab click must write the URL, or the URL and the view disagree');
  });

  it('⛔ the tab bar marks the active tab with aria-current, not colour alone', () => {
    assert.match(PAGE, /aria-current=\{effectiveTab === tab\.key \? 'page' : undefined\}/);
  });
});
