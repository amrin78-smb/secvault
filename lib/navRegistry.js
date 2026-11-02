/**
 * Every destination in the product, as DATA.
 *
 * ⛔ WHY THIS IS NOT INSIDE components/layout/Sidebar.js ANY MORE. It was, and
 * three test files reached it by REGEX over the component's source —
 * `/\{\s*href:\s*'([^']+)'/`, `/Icon: (Icon\w+)/`. That worked while the
 * registry was a flat list and stopped working the moment it gained a level:
 * a regex cannot tell a section header's glyph from its children's, so the
 * glyph-uniqueness guard could only express "every icon mentioned anywhere in
 * this file is different", which is not the invariant (see below). It also
 * silently depended on `href` being the FIRST key in each object literal, so
 * writing `label` first would have hidden a destination from the guard that
 * exists to stop destinations going missing.
 *
 * A guard that can only see the shape of the source is the "testing the
 * mechanism, not the outcome" pattern this codebase has already paid for three
 * times. The structure is data now, and the tests assert the structure.
 *
 * ⛔ CommonJS, like `lib/rbac.js` and `lib/navLayout.js`, so `node:test` can
 * `require()` it with no transform. Icons are named as STRINGS rather than
 * imported, because this file must stay loadable outside a JSX pipeline —
 * `components/layout/Sidebar.js` owns the name → component map, and
 * `tests/navigation.test.js` fails the build on a name that is not a real
 * export of `components/icons.js`.
 */

'use strict';

// ⛔ SEVEN PRIMARY DESTINATIONS, NOT FIFTEEN (v2.216.0).
//
// The previous structure was four labelled CLUSTERS of fifteen peer links. The
// groups were real and the labels were right, but a label with no disclosure is
// a caption, not a structure: all fifteen destinations were always on screen,
// which is what pushed the rail to the bottom of a 900px viewport and made the
// vertical-space tuning in globals.css necessary in the first place. Seven
// collapsible sections is the same information arranged so the operator reads
// SEVEN things to find where they are going.
//
// ⛔ HREFS ARE UNCHANGED, AGAIN, AND THIS IS THE THIRD RESTRUCTURE TO SAY SO.
// Only what is RENDERED moved. Every bookmark, every link in a sent
// notification, every URL pasted into a ticket still resolves, and no route was
// added, removed or redirected.
//
// ⛔ A SECTION IS A LEAF **OR** A GROUP, DISCRIMINATED ON `items`.
//   leaf  — { href, label, icon }     one row, navigates
//   group — { group, icon, items[] }  a disclosure button, navigates nowhere
// A group header is deliberately NOT also a link. "Clicking it navigates AND
// expands" has two outcomes for one gesture, cannot be given one accessible
// name, and makes the keyboard behaviour unexplainable. The group's landing
// page is its FIRST CHILD instead (Assets → Firewalls, Work queue → Queue), so
// nothing is one click further away than its own label.
//
// ⛔ TWO GLYPH LAYERS, AND THEY CARRY DIFFERENT INVARIANTS.
// At rail width (1024–1279px) the group HEADERS are hidden by the stylesheet
// and every item is shown flat as an icon, so no destination is ever more than
// one click away and nothing hides behind a hover. That means:
//   • every ITEM glyph must be distinct from every other ITEM glyph — this is
//     the wayfinding cue, it is what the rail actually shows, and all fifteen
//     still are;
//   • the seven TOP-LEVEL glyphs must be distinct from EACH OTHER, because in
//     the wide and drawer shapes those seven rows are what the operator scans.
//     This is why Investigate takes IconActivity rather than the IconSearch
//     that would have read better: IconSearch is Compliance's, and two
//     identical glyphs at the top level is exactly what the rule prevents;
//   • a group header MAY repeat one of ITS OWN children's glyphs (Assets and
//     Firewalls are both IconDevices) — a header only ever renders beside its
//     label, where the label disambiguates, and sharing the landing page's
//     glyph is what makes the pair read as one place. It may NOT borrow an
//     unrelated section's.
// All three are asserted in tests/navigation.test.js.
const NAV_SECTIONS = [
  { href: '/', label: 'Overview', icon: 'IconDashboard', exact: true },
  {
    group: 'Work queue',
    icon: 'IconChecklist',
    items: [
      // ⛔ The queue is the group's landing page and so comes first. The
      // Overview answers "how is the fleet"; this answers "what do I do about
      // it", which is why the whole section sits second rather than first.
      { href: '/work', label: 'Queue', icon: 'IconChecklist' },
      { href: '/alerts', label: 'Alerts', icon: 'IconBell' },
    ],
  },
  {
    group: 'Assets',
    icon: 'IconDevices',
    items: [
      { href: '/devices', label: 'Firewalls', icon: 'IconDevices' },
      { href: '/lifecycle', label: 'Lifecycle & health', icon: 'IconLifecycle' },
      // Where SecVault cannot see. Filed under Assets rather than Risk because
      // it is not a finding about the firewalls — it is a statement about how
      // much of everything else in this product is actually measured, which is
      // a property of the inventory.
      { href: '/coverage', label: 'Data health', icon: 'IconEyeOff' },
    ],
  },
  {
    group: 'Investigate',
    icon: 'IconActivity',
    items: [
      // ⛔ The only nav entry with a capability requirement today. Log search
      // returns unredacted syslog; the Operator role does not include it.
      // Hiding it here stops discovery — app/(dashboard)/logs/page.js is what
      // actually refuses the request.
      { href: '/logs', label: 'Log search', icon: 'IconDocument', requires: 'view_log_search' },
      { href: '/topology', label: 'Topology & paths', icon: 'IconTopology' },
      { href: '/vpn', label: 'VPN & identity', icon: 'IconUser' },
    ],
  },
  {
    group: 'Risk',
    icon: 'IconAlertTriangle',
    items: [
      { href: '/vulnerability', label: 'Vulnerabilities', icon: 'IconShield' },
      { href: '/exposure', label: 'Exposure', icon: 'IconAlertTriangle' },
      { href: '/analysis', label: 'Rule hygiene', icon: 'IconChart' },
      // ⛔ ONE RENDERED ENTRY FOR TWO ROUTES (2026-09-29). This pair is the only
      // place where merging is a LEGIBILITY win rather than hiding a
      // destination behind a click: /segmentation and /applications are the
      // SAME MECHANIC one grain apart — declared intent re-checked against the
      // collected rulebase, honest about what it could not verify.
      // `components/layout/IntentTabs.js` carries the strip between them.
      //
      // ⛔ NOTHING MOVED AT THE ROUTING LAYER. Both routes still exist and
      // still resolve; only what the sidebar RENDERS changed.
      { href: '/segmentation', label: 'Intent', icon: 'IconGrid', alsoActiveFor: ['/applications'] },
      // Which firewall is unlike its peers. In Risk rather than Assets because
      // a deviation is a triage lead — though never, on its own, a fault: the
      // odd one out may be the only one configured deliberately.
      { href: '/conformance', label: 'Conformance', icon: 'IconOddOneOut' },
      // ⛔ `navHidden` REMOVES IT FROM THE RAIL, NOT FROM THE PRODUCT. It must
      // stay in NAV_SECTIONS because `NAV` is what HeaderSearch's matchPages()
      // filters over — dropping the entry outright would make Ctrl+K answer "no
      // results" to 'applications', 'apps', 'flows', 'cloud', 'office 365' and
      // 'saas', which is precisely the failure PAGE_KEYWORDS exists to prevent.
      // Reachable by URL, by the palette, and by the Intent tab strip.
      { href: '/applications', label: 'Applications', icon: 'IconApplications', navHidden: true },
    ],
  },
  // ⛔ LEAVES, NOT GROUPS, AND THAT IS A REFUSAL RATHER THAN AN OMISSION.
  // Compliance would read naturally as a group over Assessments / Framework
  // comparison / Exceptions, and Reports over Catalog / Generated / Schedules.
  // Of those six, FOUR ARE NOT ROUTES: the framework comparison is a `?view=`
  // on /compliance, exceptions are a panel inside a device's assessment, and
  // neither generated-report history nor schedules exist anywhere in this
  // product. A disclosure containing one real destination and two entries that
  // cannot be opened is a menu that lies about what the product does.
  { href: '/compliance', label: 'Compliance', icon: 'IconSearch' },
  { href: '/reports', label: 'Reports', icon: 'IconReport' },
];

// ⛔ Settings is deliberately OUTSIDE the seven and pinned last. It is not one
// of the operator's seven questions, and filing it under any of them would make
// that section mean less. It carries NO capability gate: CLAUDE.md's licensing
// section records why — the Server ID lives there and is the one thing a
// customer must read off the server to buy or renew anything, so every role can
// open the page even though most of its tabs refuse to save.
const SETTINGS_ITEM = { href: '/settings', label: 'Settings', icon: 'IconSettings' };

/** The seven top-level rows, section headers included. */
const NAV_TOP_LEVEL = NAV_SECTIONS.map((s) => (s.items
  ? { label: s.group, icon: s.icon, group: true }
  : { label: s.label, icon: s.icon, href: s.href }));

/**
 * Every destination, flattened — the active-item lookup and Ctrl+K read this.
 *
 * ⛔ INCLUDES `navHidden` AND CAPABILITY-GATED ENTRIES. A destination may leave
 * the SIDEBAR; it may never leave this list. The command palette filters over
 * it, and an entry missing here is a page the palette quietly stops finding —
 * no error, no broken link, just a search that answers "no results" for a page
 * that works.
 */
const NAV = [
  ...NAV_SECTIONS.flatMap((s) => (s.items ? s.items : [s])),
  SETTINGS_ITEM,
];

/** Just the destinations the sidebar renders, for a given capability set. */
function visibleNavItems(section, capabilities) {
  if (!section.items) return [section];
  // ⛔ TWO SEPARATE REASONS AN ENTRY IS NOT RENDERED, and they are not the same
  // thing. `requires` is an AUTHORISATION gate — the page itself refuses too,
  // this only stops discovery. `navHidden` is a LAYOUT choice for a destination
  // that is still fully available by URL, by Ctrl+K and from another page's tab
  // strip. Collapsing them into one flag would eventually hide a page from
  // someone entitled to it, or advertise one they are not.
  return section.items.filter(
    (it) => !it.navHidden
      && (!it.requires || !capabilities || capabilities[it.requires])
  );
}

/**
 * Is this href (or one of its `alsoActiveFor` siblings) the current page?
 *
 * Pure, and exported so the active-state rules are tested by BEHAVIOUR rather
 * than by a regex looking for the right words in the component.
 */
function isActive(pathname, href, exact, alsoActiveFor) {
  if (typeof pathname !== 'string') return false;
  if (exact) return pathname === href;
  const under = (base) => pathname === base || pathname.startsWith(`${base}/`);
  if (under(href)) return true;
  // ⛔ A SIBLING ROUTE SHARING THIS ENTRY MUST LIGHT IT UP. Without this the
  // Intent entry goes dark on /applications and the sidebar claims you are
  // nowhere — worse than an unmerged list, because the operator cannot tell
  // which section they are in.
  return Array.isArray(alsoActiveFor) && alsoActiveFor.some(under);
}

/**
 * Is anything inside this section the current page?
 *
 * ⛔ IT TESTS EVERY ITEM INCLUDING THE HIDDEN AND THE UNAUTHORISED ONES, and
 * that is deliberate on both counts. /applications is navHidden but IS a page
 * you can be standing on, and a section header that went dark there would tell
 * the operator they are nowhere. Authorisation is irrelevant to this question:
 * if the page rendered, you are on it.
 */
function sectionIsActive(pathname, section) {
  if (!section.items) return isActive(pathname, section.href, section.exact, section.alsoActiveFor);
  return section.items.some((it) => isActive(pathname, it.href, it.exact, it.alsoActiveFor));
}

module.exports = {
  NAV_SECTIONS,
  NAV_TOP_LEVEL,
  SETTINGS_ITEM,
  NAV,
  visibleNavItems,
  isActive,
  sectionIsActive,
};
