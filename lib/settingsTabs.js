'use strict';

// SETTINGS, SPLIT INTO WHOSE SETTINGS THEY ARE.
//
// ⛔ ═══ THE PROBLEM WAS INSIDE THE TABS, NOT ONLY BETWEEN THEM ═══════════
// Ten tabs in one flat row, and the two an ordinary operator could open both
// MIXED their own settings with the whole installation's:
//
//   General  = Appearance (yours) + Change password (yours) + Feed Sync (the
//              server's schedule, affecting every user)
//   Security = MFA enrolment (yours) + Session idle timeout (the server's
//              policy, signing everybody out)
//
// So "Settings" answered two different questions in one list, and the two
// server-wide controls were sitting in the two tabs with no capability
// requirement — reachable by every role, presented beside things that are
// genuinely personal. The panels themselves are gated server-side, so this
// was never a privilege hole; it was an operator opening "Security" to turn
// on their own MFA and finding a control that logs out the organisation.
//
// Three groups now, and the grouping is the actual answer to "whose setting
// is this":
//
//   My preferences  — only ever affects the signed-in user. No capability.
//   Administration  — affects the installation. Every tab gated.
//   System          — facts about this install, not settings at all.
//
// ⛔ ═══ EVERY EXISTING `?tab=` VALUE STILL RESOLVES ══════════════════════
// Settings reads `?tab=` once on mount for deep links, and those links are in
// tickets and in this product's own release notes. `general` and `security`
// keep their keys even though their CONTENTS changed, and the two tabs split
// out of them are new keys — so no existing link 404s or lands on a blank
// pane. LEGACY_TAB_ALIASES covers anything that did have to move.

// ⛔ ═══ THE SESSION TIMEOUT STAYS IN "MY ACCOUNT", AND THAT REVERSES THIS
// FILE'S OWN FIRST DRAFT. It is server-wide policy, so the obvious move was an
// admin-gated "Sessions" tab beside Certificate. That would have REMOVED a
// deliberate existing behaviour: SessionTimeoutPanel is shown to EVERY role
// and editable only with manage_settings, because — in its own words — "every
// role is SUBJECT to the timeout, and someone signed out after half an hour
// who cannot find out why concludes the product is broken rather than that a
// policy is in force."
//
// Gating the tab would have hidden the explanation from exactly the people who
// need it, to satisfy a tidier grouping. The panel already solves the mixing
// problem internally: it is read-only for an Operator. What genuinely did not
// belong in a tab open to everyone was FEED SYNC, which has no personal aspect
// at all, and that is what moved.

const SETTINGS_GROUPS = [
  {
    key: 'preferences',
    label: 'My preferences',
    // ⛔ NO CAPABILITY ON THE WHOLE GROUP, and that is the definition rather
    // than an oversight: a tab belongs here only if it cannot affect anybody
    // else. The moment one needs a gate it is in the wrong group.
    tabs: [
      { key: 'general', label: 'Appearance' },
      // ⛔ KEEPS THE `security` KEY. MFA enrolment was already here, so every
      // existing ?tab=security link lands on the same control it always did;
      // what left is the session timeout, which was never personal.
      { key: 'security', label: 'My account' },
    ],
  },
  {
    key: 'administration',
    label: 'Administration',
    tabs: [
      { key: 'users', label: 'Users', requires: 'manage_users' },
      // Split out of `users` in v2.210.0: who has an account here, versus
      // which directory is trusted to issue them.
      { key: 'signon', label: 'Single sign-on', requires: 'manage_users' },
      { key: 'profiles', label: 'Credential profiles', requires: 'manage_credential_profiles' },
      { key: 'notifications', label: 'Notifications', requires: 'manage_settings' },
      { key: 'certificate', label: 'Certificate', requires: 'manage_settings' },
      // ⛔ NEW KEY, MOVED OUT OF `general`. Feed sync is the server's
      // collection schedule and affects every user; it was sitting in the one
      // tab with no capability requirement, beside the operator's own
      // appearance settings and their own password.
      { key: 'feeds', label: 'Feeds', requires: 'manage_settings' },
      { key: 'updates', label: 'Updates', requires: 'run_update' },
    ],
  },
  {
    key: 'system',
    label: 'System',
    tabs: [
      // ⛔ VISIBLE TO EVERY ROLE, unlike the rest of Administration — which is
      // why it is in this group rather than that one. The panel holds the
      // Server ID, and an operator asked to read it off the server for a
      // renewal should not need a Super Admin account. Only the ACTIVATION
      // controls are gated, by MANAGE_LICENSE, in the panel and in the route.
      { key: 'subscription', label: 'Subscription' },
      { key: 'about', label: 'About' },
    ],
  },
];

// ⛔ NOTHING MOVED KEYS, SO THIS IS EMPTY — and it exists anyway, because the
// next tab that DOES move needs somewhere to declare it rather than quietly
// breaking a link. A test asserts every alias points at a real tab.
const LEGACY_TAB_ALIASES = Object.freeze({});

const SETTINGS_TABS = SETTINGS_GROUPS.flatMap((g) =>
  g.tabs.map((t) => ({ ...t, group: g.key })));

const DEFAULT_SETTINGS_TAB = 'general';

/** Resolve a (possibly legacy, possibly bogus) ?tab= value to a real key. */
function resolveSettingsTab(tab) {
  const t = LEGACY_TAB_ALIASES[tab] || tab;
  return SETTINGS_TABS.some((x) => x.key === t) ? t : DEFAULT_SETTINGS_TAB;
}

/**
 * The groups a given viewer may see, with empty groups dropped.
 *
 * ⛔ AN EMPTY GROUP IS NOT RENDERED. An Operator holds none of the
 * administrative capabilities, so "Administration" would be a heading over
 * nothing — which reads as a loading failure, or worse as a hint that
 * something is being withheld in a way they could argue with.
 *
 * ⛔ HIDING A TAB IS NOT THE SECURITY BOUNDARY. Every panel behind these is
 * backed by a route that checks the same capability server-side; this list
 * exists so an Operator is not shown five doors that all refuse to open.
 */
function visibleSettingsGroups(caps) {
  const c = caps || {};
  return SETTINGS_GROUPS
    .map((g) => ({
      key: g.key,
      label: g.label,
      tabs: g.tabs.filter((t) => !t.requires || c[t.requires]),
    }))
    .filter((g) => g.tabs.length > 0);
}

/** Flat list of the tabs a viewer may see, in group order. */
function visibleSettingsTabs(caps) {
  return visibleSettingsGroups(caps).flatMap((g) =>
    g.tabs.map((t) => ({ ...t, group: g.key })));
}

/** The group a tab belongs to. */
function groupForSettingsTab(tab) {
  const t = resolveSettingsTab(tab);
  const g = SETTINGS_GROUPS.find((grp) => grp.tabs.some((x) => x.key === t));
  return g ? g.key : SETTINGS_GROUPS[0].key;
}

module.exports = {
  SETTINGS_GROUPS,
  SETTINGS_TABS,
  LEGACY_TAB_ALIASES,
  DEFAULT_SETTINGS_TAB,
  resolveSettingsTab,
  visibleSettingsGroups,
  visibleSettingsTabs,
  groupForSettingsTab,
};
