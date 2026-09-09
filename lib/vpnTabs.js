// lib/vpnTabs.js
//
// Tab models for the two VPN pages. Pure, dependency-free CommonJS — no DB, no
// React — so it is unit-testable and importable from a Server Component, the
// same shape and reasoning as lib/dashboardTabs.js.
//
// ── WHY THESE PAGES BECAME TABBED ─────────────────────────────────────────
// Two reasons, and the second is the one that matters.
//
//   1. Length. Both pages stacked every section vertically: fleet status AND
//      log activity; config summary AND users AND tunnels AND a trend chart.
//
//   2. ⛔ COST. Only the ACTIVE tab's data is fetched, so opening the page no
//      longer runs every query. Measured on the live fleet, the VPN log
//      queries take ~7s on a COLD cache — and they are always cold, because a
//      26 GB/day ingest evicts them from a 4 GB buffer pool long before an
//      operator next visits. Stacking them meant everyone paid that cost even
//      to look at the tunnel list. This is the same reason the dashboard
//      renders only its active tab.
//
// ⛔ `key` is a URL value, so treat these as a public contract: add and
// deprecate, never rename in place, or existing links break.

'use strict';

// Fleet /vpn. `status` first: it is the cheap, always-useful view, and it is
// what a bookmark to plain /vpn should still land on.
const FLEET_VPN_TABS = [
  {
    key: 'status',
    label: 'Fleet Status',
    description: 'Per-device VPN configuration and current session counts',
  },
  {
    key: 'activity',
    label: 'Log Activity',
    // The only VPN source that covers Palo Alto, and the expensive one.
    description: 'VPN events observed in firewall logs, including Palo Alto',
  },
  // ⛔ APPENDED, never inserted. `status` must stay first so it remains the
  // default and existing bookmarks keep their clean URL, and `key` is a URL
  // contract — add and deprecate, never rename.
  {
    key: 'locations',
    label: 'Login Locations',
    description: 'Where VPN logins come from, and which ones are failing',
  },
];

// Per-device /devices/[id]/vpn.
const DEVICE_VPN_TABS = [
  {
    key: 'overview',
    label: 'Overview',
    description: 'VPN configuration summary and session trend',
  },
  {
    key: 'users',
    label: 'Active Users',
    description: 'Currently connected remote-access users',
  },
  {
    key: 'tunnels',
    label: 'IPsec Tunnels',
    description: 'Site-to-site tunnel peers and status',
  },
];

const DEFAULT_FLEET_VPN_TAB = 'status';
const DEFAULT_DEVICE_VPN_TAB = 'overview';

/**
 * Resolve a raw `?vtab=` value against a tab set.
 *
 * ⛔ ALWAYS returns a valid key — never the caller's input, never undefined.
 * A URL is user input, and a page that renders nothing for an unknown tab is
 * indistinguishable from an outage. Handles the array Next.js produces for a
 * repeated param by taking the first entry.
 */
function resolveTab(raw, tabs, fallback) {
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== 'string') return fallback;
  const match = tabs.find((t) => t.key === value.trim().toLowerCase());
  return match ? match.key : fallback;
}

function resolveFleetVpnTab(raw) {
  return resolveTab(raw, FLEET_VPN_TABS, DEFAULT_FLEET_VPN_TAB);
}

function resolveDeviceVpnTab(raw) {
  return resolveTab(raw, DEVICE_VPN_TABS, DEFAULT_DEVICE_VPN_TAB);
}

/**
 * Build TabBar hrefs, preserving the rest of the query string.
 *
 * ⛔ Preserving it matters: these pages carry per-list page params (`page`,
 * `evPage`, `tunnelPage`) and a user filter (`vpnq`). Dropping them on a tab
 * click would silently reset the reader's position.
 *
 * ⛔ But the OTHER tabs' page params are dropped when switching, because a
 * page number from a list you are leaving means nothing in the list you are
 * arriving at — and carrying it would land you on page 7 of something you just
 * opened.
 */
function buildVpnTabHrefs(basePath, tabs, searchParams, activeKey, dropParams) {
  const drop = new Set(['vtab'].concat(dropParams || []));
  const base = new URLSearchParams();
  for (const [k, v] of Object.entries(searchParams || {})) {
    if (drop.has(k)) continue;
    if (v === undefined || v === null || v === '') continue;
    base.set(k, Array.isArray(v) ? v[0] : String(v));
  }

  const hrefFor = (key) => {
    const sp = new URLSearchParams(base);
    // The default tab gets a clean URL with no ?vtab= at all.
    if (key !== tabs[0].key) sp.set('vtab', key);
    const qs = sp.toString();
    return qs ? `${basePath}?${qs}` : basePath;
  };

  return {
    tabs: tabs.map((t) => ({ key: t.key, label: t.label, href: hrefFor(t.key) })),
    activeHref: hrefFor(activeKey),
  };
}

module.exports = {
  FLEET_VPN_TABS,
  DEVICE_VPN_TABS,
  DEFAULT_FLEET_VPN_TAB,
  DEFAULT_DEVICE_VPN_TAB,
  resolveFleetVpnTab,
  resolveDeviceVpnTab,
  buildVpnTabHrefs,
};
