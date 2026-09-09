'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
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
const NAV = [
  { href: '/', label: 'Dashboard', Icon: IconDashboard, exact: true },
  { href: '/alerts', label: 'Alerts', Icon: IconBell },
  { href: '/devices', label: 'Devices', Icon: IconDevices },
  { href: '/vulnerability', label: 'Vulnerability', Icon: IconShield },
  { href: '/analysis', label: 'Rule Analysis', Icon: IconChart },
  { href: '/compliance', label: 'Compliance', Icon: IconSearch },
  // No dedicated VPN/tunnel icon exists in components/icons.js -- reusing
  // IconUser (VPN is fundamentally remote-USER access) rather than inventing
  // a new SVG file, same 'reuse what exists even if not a perfect semantic
  // match' call this file already made for Compliance -> IconSearch.
  { href: '/vpn', label: 'VPN', Icon: IconUser },
  { href: '/topology', label: 'Topology', Icon: IconTopology },
  { href: '/exposure', label: 'Exposure', Icon: IconAlertTriangle },
  // IconDocument for Log Search: a log IS a record. Same reuse call again.
  { href: '/logs', label: 'Log Search', Icon: IconDocument },
  { href: '/lifecycle', label: 'Lifecycle', Icon: IconLifecycle },
  { href: '/settings', label: 'Settings', Icon: IconSettings },
];

const COLLAPSE_KEY = 'secvault-sidebar-collapsed';

function isActive(pathname, href, exact) {
  if (exact) return pathname === href;
  return pathname === href || pathname.startsWith(`${href}/`);
}

export default function Sidebar({ version }) {
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
      <div className="sv-nav-label">Navigation</div>
      <nav className="sv-nav">
        {NAV.map(({ href, label, Icon, exact }) => {
          const active = isActive(pathname, href, exact);
          return (
            <Link key={href} href={href} className={active ? 'active' : ''} title={collapsed ? label : undefined}>
              <span className="sv-nav-chip">
                <Icon width={16} height={16} />
              </span>
              <span>{label}</span>
            </Link>
          );
        })}
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

      <div className="sv-version">SecVault{version ? ` v${version}` : ''}</div>
    </aside>
  );
}
