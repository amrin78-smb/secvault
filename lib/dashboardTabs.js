// lib/dashboardTabs.js
//
// The dashboard's tab model. Pure, dependency-free CommonJS — no DB, no React
// — so it can be unit-tested (tests/dashboardTabs.test.js) and imported by the
// Server Component alike.
//
// WHY THIS FILE EXISTS AT ALL, rather than an inline array in page.js:
// `app/(dashboard)/page.js`, `/vulnerability`, `/compliance` and
// `/devices/[id]/analysis` each grew their own copy of "whitelist the
// ?tab= value, fall back to a default". That is the exact shape of bug this
// codebase keeps finding — an unvalidated value flowing into a render
// decision — so the dashboard's version is written once, here, and tested.
//
// ── ADDING A TAB ──────────────────────────────────────────────────────────
// Add one entry to DASHBOARD_TABS and render it in page.js's switch. That is
// the whole change; the tab bar, the URL whitelist and the default all derive
// from this array.
//
// The Traffic tab was deliberately absent until there was something real to
// show; `services/collector.js` shipped on 2026-09-08 and now ingests ~1,400
// events/sec, so it was added. Its widgets read the ROLLUP tables, never raw
// syslog_events -- see lib/syslog/trafficStats.js for why that distinction is
// load-bearing at this volume.
//
// ⛔ `key` is a URL value. Changing one breaks any bookmark or dashboard link
// pointing at it, so treat these as a public contract: add and deprecate,
// don't rename in place.

const DASHBOARD_TABS = [
  {
    key: 'overview',
    label: 'Overview',
    // What needs attention right now, across every domain. Deliberately
    // duplicates widgets that also live on a specialised tab — a landing page
    // that makes you go hunting has failed at being a landing page.
    description: 'Fleet posture and what needs attention now',
  },
  {
    key: 'security',
    label: 'Security',
    description: 'CVE exposure, observed attacks, threats and critical alerts',
  },
  {
    key: 'rules',
    label: 'Rules',
    description: 'Ruleset composition and hygiene findings',
  },
  {
    key: 'compliance',
    label: 'Compliance',
    description: 'Scores against PCI DSS, ISO 27001, CIS v8, NIST and SANS',
  },
  {
    key: 'traffic',
    label: 'Traffic',
    description: 'Traffic volume, hosts, applications, geography, users and collector health',
  },
  {
    key: 'fleet',
    label: 'Fleet Health',
    description: 'Reachability, vendors, system health, licences and change history',
  },
];

const DEFAULT_DASHBOARD_TAB = 'overview';

/**
 * Resolve a raw `?tab=` value to a real tab key.
 *
 * ⛔ Always returns a VALID key — never the caller's input, and never
 * undefined. An unknown, missing, array-valued (`?tab=a&tab=b` parses to an
 * array in Next.js) or otherwise junk value falls back to the default rather
 * than rendering an empty page, because a URL is user-supplied input and a
 * blank dashboard is indistinguishable from an outage.
 *
 * @param {unknown} raw
 * @returns {string} a key guaranteed to be present in DASHBOARD_TABS
 */
function resolveDashboardTab(raw) {
  // Next.js gives an array when a param repeats. Take the first entry rather
  // than stringifying the array into "a,b" and failing the lookup.
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== 'string') return DEFAULT_DASHBOARD_TAB;
  const match = DASHBOARD_TABS.find((t) => t.key === value.trim().toLowerCase());
  return match ? match.key : DEFAULT_DASHBOARD_TAB;
}

/**
 * @param {string} key
 * @returns {{key: string, label: string, description: string}|null}
 */
function dashboardTabByKey(key) {
  return DASHBOARD_TABS.find((t) => t.key === key) || null;
}

module.exports = {
  DASHBOARD_TABS,
  DEFAULT_DASHBOARD_TAB,
  resolveDashboardTab,
  dashboardTabByKey,
};
