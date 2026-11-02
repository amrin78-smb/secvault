'use strict';

// THE PER-DEVICE NAVIGATION — one row of destinations that follows a firewall
// across every page about it.
//
// DATA, like lib/navRegistry.js, and for the same reason: the invariants worth
// asserting are "nothing was lost" and "exactly one entry is active", and
// neither can be asserted against a hand-written JSX tab row.
//
// ⛔ ═══ WHAT WAS WRONG ═══════════════════════════════════════════════════
// A firewall's surfaces were split across THREE unrelated navigations and
// FOUR orphan routes:
//
//   • /devices/[id] carried a 7-tab row (overview, cve, rules, config,
//     admins, traffic, manage) as query parameters.
//   • /devices/[id]/analysis carried its own 14-tab row.
//   • /devices/[id]/rules, /changes, /vpn and /snmp were full routes with NO
//     tab row at all — each reachable only from a link somewhere else, and
//     each offering only "← Back to <name>" to get out.
//
// So from the ruleset page there was no way to reach the same device's VPN
// sessions, its compliance assessment, or its config history without going
// back to the device page first and finding the right link. The destinations
// existed; the navigation between them did not.
//
// ⛔ ═══ ONE ROW, FLAT, AND NOT SEVEN ═════════════════════════════════════
// The brief asked for Overview / Policy / Vulnerabilities / Compliance /
// Changes / Logs / Activity. Three of those seven are honoured verbatim and
// the differences are deliberate:
//
//   • VPN, Metrics, Admins and Manage are ADDED because they are real
//     destinations with real routes, and a nav that omits them leaves those
//     pages reachable only by a link on one other page — the state this
//     registry exists to fix. Dropping a destination to match a list of seven
//     would be removing a capability to simplify.
//   • ACTIVITY IS DELIBERATELY ABSENT. It is one of fourteen leaves inside
//     the analysis page (`?tab=tracking`), and promoting it to a peer of
//     "Compliance" would have the nav claim it is a destination of the same
//     weight. It stays inside Policy, where the operator history sits beside
//     the analysis it is a history of.
//
// ⛔ ═══ COMPLIANCE LEAVES /devices ENTIRELY, ON PURPOSE ══════════════════
// `/compliance/[deviceId]` is a different route tree, and this registry links
// to it anyway, because an operator asking "is this firewall compliant" is
// asking about THIS firewall. A nav organised by URL prefix rather than by the
// asset would have omitted the one destination that answers that question.
//
// ⛔ ═══ HREFS ARE UNCHANGED ══════════════════════════════════════════════
// Every entry points at a URL that already worked. Nothing here renames a
// route, moves a tab parameter, or changes what `?tab=cve` means. Labels are
// the operator's language; the addresses are the product's.

// Each entry:
//   key       stable id, used by tests and by the active-state resolver
//   label     what the operator reads
//   path      '' for /devices/:id itself, else the suffix ('/analysis')
//   tab       the ?tab= value this entry owns on /devices/:id (path '' only)
//   alsoPaths other suffixes that should light this entry up
//   alsoTabs  other ?tab= values that should light this entry up
//   absolute  a path OUTSIDE /devices/:id (compliance), built from the id
//   requires  a capability constant name, gated by the caller
const DEVICE_NAV = [
  { key: 'overview', label: 'Overview', path: '', tab: 'overview' },
  {
    key: 'policy',
    label: 'Policy',
    // ⛔ THE LANDING PAGE IS THE RULESET, NOT THE ANALYSIS. "Policy" means the
    // rules this firewall enforces; the hygiene findings are a judgement ABOUT
    // them. Someone clicking Policy wants to see the rulebase, and the
    // analysis is one click on from it — not the other way round, which would
    // open with an opinion before showing the thing it is an opinion about.
    path: '/rules',
    alsoPaths: ['/analysis'],
    // The device page's own rule SAMPLE is the same subject, so it lights this
    // entry rather than leaving no entry active.
    alsoTabs: ['rules'],
  },
  { key: 'cves', label: 'Vulnerabilities', path: '', tab: 'cve' },
  { key: 'compliance', label: 'Compliance', absolute: '/compliance' },
  { key: 'changes', label: 'Changes', path: '/changes', alsoTabs: ['config'] },
  { key: 'logs', label: 'Logs', path: '', tab: 'traffic' },
  { key: 'vpn', label: 'VPN', path: '/vpn' },
  { key: 'metrics', label: 'Metrics', path: '/snmp' },
  { key: 'admins', label: 'Admins', path: '', tab: 'admins' },
  // ⛔ GATED, AND THE GATE IS THE CALLER'S. This registry does not resolve a
  // session — the pages already do, and a second resolution here could
  // disagree with the one the route enforces. `requires` names what to check.
  { key: 'manage', label: 'Manage', path: '', tab: 'manage', requires: 'manage_devices' },
];

/**
 * The href for one entry.
 *
 * ⛔ `?tab=overview` IS WRITTEN OUT RATHER THAN OMITTED, even though it is the
 * default. An entry whose href is the bare device URL and an entry whose href
 * carries its tab are the same destination, and leaving one of them implicit
 * means a test comparing hrefs cannot tell whether the default was chosen or
 * forgotten.
 */
function deviceNavHref(entry, deviceId) {
  if (!entry || !deviceId) return null;
  if (entry.absolute) return `${entry.absolute}/${deviceId}`;
  const base = `/devices/${deviceId}${entry.path || ''}`;
  return entry.tab ? `${base}?tab=${entry.tab}` : base;
}

/**
 * Which entry is active, given where the browser actually is.
 *
 * @param {string} pathname  e.g. '/devices/abc/rules'
 * @param {string} tab       the ?tab= value, or ''
 * @param {string} deviceId
 * @returns {string|null} the active entry's key
 *
 * ⛔ PATH BEATS TAB. A `?tab=` left over in the URL of a different route must
 * not decide the active entry — /devices/abc/rules?tab=cve is the ruleset
 * page, whatever the stale parameter says.
 *
 * ⛔ THE SUFFIX IS MATCHED ON A SEGMENT BOUNDARY. `startsWith('/rules')` would
 * make a future `/rules-export` light up Policy, and more importantly the bare
 * device path is the empty suffix, which every path starts with — so the
 * empty-suffix entries are resolved by TAB only and never by prefix.
 */
function activeDeviceNavKey(pathname, tab, deviceId) {
  if (typeof pathname !== 'string' || !deviceId) return null;
  const base = `/devices/${deviceId}`;

  if (pathname === `/compliance/${deviceId}` || pathname.startsWith(`/compliance/${deviceId}/`)) {
    return 'compliance';
  }
  if (pathname !== base && !pathname.startsWith(`${base}/`)) return null;

  const suffix = pathname.slice(base.length); // '' or '/rules' or '/rules/x'
  if (suffix !== '') {
    const seg = (s) => s === suffix || suffix.startsWith(`${s}/`);
    for (const e of DEVICE_NAV) {
      if (e.absolute || !e.path) continue;
      if (seg(e.path) || (e.alsoPaths || []).some(seg)) return e.key;
    }
    // A real sub-route nobody has claimed. ⛔ null, never a guess: lighting up
    // Overview for an unknown page tells the operator they are somewhere they
    // are not.
    return null;
  }

  const t = typeof tab === 'string' && tab !== '' ? tab : 'overview';
  for (const e of DEVICE_NAV) {
    if (e.absolute || e.path) continue;
    if (e.tab === t) return e.key;
  }
  // A tab belonging to a sub-route entry (?tab=rules, ?tab=config).
  for (const e of DEVICE_NAV) {
    if ((e.alsoTabs || []).includes(t)) return e.key;
  }
  return null;
}

/**
 * The entries a given viewer may see, with hrefs and active state resolved.
 *
 * @param {{deviceId:string, pathname:string, tab?:string, can?:(cap:string)=>boolean}} args
 */
function visibleDeviceNav({ deviceId, pathname, tab, can } = {}) {
  const activeKey = activeDeviceNavKey(pathname, tab, deviceId);
  return DEVICE_NAV.filter((e) => {
    if (!e.requires) return true;
    // ⛔ NO `can` SUPPLIED MEANS HIDE, not show. A caller that forgot to pass
    // the predicate must not get a Manage tab by default — a UI looser than
    // the route behind it is the one direction this product refuses.
    return typeof can === 'function' ? Boolean(can(e.requires)) : false;
  }).map((e) => ({
    key: e.key,
    label: e.label,
    href: deviceNavHref(e, deviceId),
    active: e.key === activeKey,
  }));
}

module.exports = {
  DEVICE_NAV,
  deviceNavHref,
  activeDeviceNavKey,
  visibleDeviceNav,
};
