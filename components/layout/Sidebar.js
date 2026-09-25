'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { PRODUCT_NAME } from '../../lib/branding';
import { useEffect, useState } from 'react';
import {
  IconDashboard,
  IconBell,
  IconDevices,
  IconShield,
  IconChart,
  IconSearch,
  IconSettings,
  IconChevronLeft,
  IconUser,
  IconTopology,
  IconLifecycle,
  IconDocument,
  IconAlertTriangle,
  IconGrid,
  IconChecklist,
  IconReport,
  IconApplications, IconEyeOff,
} from '../icons';

// ⛔ THE ACTIVE NAV CHIP IS ALWAYS THE BRAND ACCENT (2026-09-09, Phase 1).
//
// Each entry used to carry its own `color`/`bg` hex pair — cyan, amber, blue,
// red, gold, green, indigo, violet, lime, sky, rose, grey. Only the ACTIVE
// entry ever rendered coloured (`.sv-nav a.active .sv-nav-chip` in
// globals.css; every inactive chip is white-alpha), so this was never a
// twelve-hue rainbow on screen at once. The real defect was subtler and
// worse: the "you are here" signal was A DIFFERENT HUE ON EVERY PAGE, so it
// could not be learned — and on /vulnerability it was #f87171, a red, sitting
// three inches from severity badges that use red to mean "critically
// exposed". An interface element must never borrow the severity palette.
//
// The old comments here defended the hues on the grounds that the chip colour
// is "the ONLY wayfinding cue when the sidebar is collapsed". That was not
// true: collapsed or not, only one chip is ever coloured, so eleven of the
// twelve were already indistinguishable. The actual per-item cue is the
// GLYPH, and all twelve glyphs are distinct — which is the invariant worth
// keeping, and the one to check when adding a nav entry.
//
// Icon reuse note (Phase 7, Compliance): IconShield is already taken by
// "Vulnerability" (formerly "CVE Posture" -- merged with the separate
// "Advisories" entry, which used to take IconDocument, into one /vulnerability
// page in the Vulnerability merge), so Compliance reuses IconSearch (a
// magnifying glass reads reasonably as "audit/inspect") rather than inventing
// a new SVG icon file -- the same "reuse what's there even if not a perfect
// semantic match" call this file already made when Alerts reused IconBell.
// ⛔ GROUPS ARE THE STRUCTURE, LABELS ARE THE LANGUAGE (2026-09-09,
// redesign Phase 2). Twelve flat, equally-weighted destinations asked the
// operator to hold the whole product in their head. They answer four
// questions, and the groups are how people actually work: what is happening,
// what do I have, what is wrong with it, who is getting in.
//
// ⛔ HREFS ARE UNCHANGED. Only the LABELS were renamed. Every bookmark,
// every link in a sent notification, every URL pasted into a ticket still
// resolves. Renaming a route to match a renamed label would be a much larger
// and much less reversible change, and it buys nothing the label does not.
//
// The renames trade "what the engine does" for "what the operator gets":
//   Dashboard -> Overview          Devices -> Firewalls
//   Rule Analysis -> Rule hygiene  Vulnerability -> Vulnerabilities
//   VPN -> VPN & identity
// "Rule Analysis" describes our engine; "Rule hygiene" describes their
// problem. "Devices" is what the table is called internally; a customer with
// a fleet of firewalls calls them firewalls.
//
// ⛔ Settings is deliberately OUTSIDE the groups and pinned last. It is not
// one of the four questions, and filing it under any of them would make that
// group mean less.
const NAV_GROUPS = [
  { group: 'Monitor', items: [
    { href: '/', label: 'Overview', Icon: IconDashboard, exact: true },
    // ⛔ SECOND, not first. The Overview answers "how is the fleet"; this
    // answers "what do I do about it", and it reads as the follow-on rather
    // than the front door. Placing it above the dashboard would also make the
    // first thing a new evaluator sees a to-do list rather than a posture.
    { href: '/work', label: 'Work queue', Icon: IconChecklist },
    { href: '/alerts', label: 'Alerts', Icon: IconBell },
    // Where SecVault cannot see. Sits in Monitor rather than Risk because it
    // is not a finding about the firewalls -- it is a statement about how
    // much of everything else on this product is actually measured.
    { href: '/coverage', label: 'Coverage', Icon: IconEyeOff },
    // ⛔ The only nav entry with a capability requirement today. Log search
    // returns unredacted syslog; the Operator role does not include it. Hiding
    // it here stops discovery — app/(dashboard)/logs/page.js is what actually
    // refuses the request.
    { href: '/logs', label: 'Log search', Icon: IconDocument, requires: 'view_log_search' },
    // Sits with Overview and Work queue because it answers the same question
    // one step further on: what do I hand to someone else. Not filed under
    // Risk — a compliance PDF and a lifecycle PDF are not risk views.
    { href: '/reports', label: 'Reports', Icon: IconReport },
  ] },
  { group: 'Inventory', items: [
    { href: '/devices', label: 'Firewalls', Icon: IconDevices },
    { href: '/topology', label: 'Topology', Icon: IconTopology },
    { href: '/lifecycle', label: 'Lifecycle', Icon: IconLifecycle },
  ] },
  { group: 'Risk', items: [
    { href: '/vulnerability', label: 'Vulnerabilities', Icon: IconShield },
    { href: '/exposure', label: 'Exposure', Icon: IconAlertTriangle },
    { href: '/segmentation', label: 'Segmentation', Icon: IconGrid },
    // ⛔ FILED UNDER RISK, BESIDE SEGMENTATION, AND NOT UNDER INVENTORY.
    // It is tempting to read "applications" as a list of things you have.
    // What this page actually produces is VERDICTS: a declared flow that a
    // rule permits but should not, and a flow the application needs that a
    // rule blocks. That is the SAME MECHANIC as Segmentation, one grain
    // finer — declared intent re-checked against the collected rulebase,
    // honest about what it could not verify — and sitting the two together
    // is what makes the pair legible: zone-to-zone policy, then
    // application-to-flow. Inventory holds what SecVault COLLECTED
    // (firewalls, links, licences); everything here is something the
    // operator DECLARED and SecVault then judged.
    { href: '/applications', label: 'Applications', Icon: IconApplications },
    { href: '/analysis', label: 'Rule hygiene', Icon: IconChart },
    { href: '/compliance', label: 'Compliance', Icon: IconSearch },
  ] },
  { group: 'Access', items: [
    // No dedicated VPN/tunnel glyph exists in components/icons.js -- IconUser
    // is reused because VPN is fundamentally remote-USER access. Same "reuse
    // what exists" call already made for Compliance -> IconSearch and
    // Log search -> IconDocument (a log IS a record).
    { href: '/vpn', label: 'VPN & identity', Icon: IconUser },
  ] },
];

const SETTINGS_ITEM = { href: '/settings', label: 'Settings', Icon: IconSettings };

// Flat list for anything that needs every destination (the active-item lookup,
// and the command palette’s page results).
export const NAV = [...NAV_GROUPS.flatMap((g) => g.items), SETTINGS_ITEM];

const COLLAPSE_KEY = 'secvault-sidebar-collapsed';

function isActive(pathname, href, exact) {
  if (exact) return pathname === href;
  return pathname === href || pathname.startsWith(`${href}/`);
}

export default function Sidebar({ version, capabilities }) {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    try {
      setCollapsed(localStorage.getItem(COLLAPSE_KEY) === 'true');
    } catch (_err) {
      // ignore — collapse just won't persist
    }
  }, []);

  function toggle() {
    setCollapsed((c) => {
      const next = !c;
      try {
        localStorage.setItem(COLLAPSE_KEY, String(next));
      } catch (_err) {
        // ignore
      }
      return next;
    });
  }

  return (
    <aside className={`sv-sidebar${collapsed ? ' collapsed' : ''}`}>
      <nav className="sv-nav">
        {NAV_GROUPS.map(({ group, items: allItems }) => {
          // A group whose every entry is hidden must not leave its label behind.
          const items = allItems.filter(
            (it) => !it.requires || !capabilities || capabilities[it.requires]
          );
          if (items.length === 0) return null;
          return (
          <div key={group} className="sv-nav-group">
            {/* Hidden when collapsed: at 64px there is no room for a heading,
                and the grouping still reads from the gap between clusters. */}
            {!collapsed && <div className="sv-nav-group-label">{group}</div>}
            {items.map(({ href, label, Icon, exact }) => {
              const active = isActive(pathname, href, exact);
              return (
                <Link
                  key={href}
                  href={href}
                  className={active ? 'active' : ''}
                  title={collapsed ? label : undefined}
                >
                  <span className="sv-nav-chip">
                    <Icon width={16} height={16} />
                  </span>
                  <span>{label}</span>
                </Link>
              );
            })}
          </div>
          );
        })}
        <div className="sv-nav-group sv-nav-group-pinned">
          <Link
            href={SETTINGS_ITEM.href}
            className={isActive(pathname, SETTINGS_ITEM.href, false) ? 'active' : ''}
            title={collapsed ? SETTINGS_ITEM.label : undefined}
          >
            <span className="sv-nav-chip">
              <SETTINGS_ITEM.Icon width={16} height={16} />
            </span>
            <span>{SETTINGS_ITEM.label}</span>
          </Link>
        </div>
      </nav>

      <button
        type="button"
        className="sv-collapse-btn"
        onClick={toggle}
        title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        <IconChevronLeft width={18} height={18} />
        <span>Collapse</span>
      </button>

      <div className="sv-version">{PRODUCT_NAME}{version ? ` v${version}` : ''}</div>
    </aside>
  );
}
