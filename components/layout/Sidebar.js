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
  IconDocument,
  IconSearch,
  IconSettings,
  IconChevronLeft,
  IconUser,
} from '../icons';

// Icon reuse note (Phase 7, Compliance): IconShield is already taken by "CVE
// Posture" and IconDocument by "Advisories", so Compliance reuses IconSearch
// (a magnifying glass reads reasonably as "audit/inspect") rather than
// inventing a new SVG icon file -- the same "reuse what's there even if not
// a perfect semantic match" call this file already made when Alerts reused
// IconBell.
const NAV = [
  { href: '/', label: 'Dashboard', Icon: IconDashboard, exact: true, color: '#0891b2', bg: 'rgba(8,145,178,0.20)' },
  { href: '/alerts', label: 'Alerts', Icon: IconBell, color: '#fb923c', bg: 'rgba(251,146,60,0.20)' },
  { href: '/devices', label: 'Devices', Icon: IconDevices, color: '#60a5fa', bg: 'rgba(96,165,250,0.20)' },
  { href: '/cve', label: 'CVE Posture', Icon: IconShield, color: '#f87171', bg: 'rgba(248,113,113,0.22)' },
  { href: '/analysis', label: 'Rule Analysis', Icon: IconChart, color: '#fbbf24', bg: 'rgba(251,191,36,0.20)' },
  { href: '/advisories', label: 'Advisories', Icon: IconDocument, color: '#a78bfa', bg: 'rgba(167,139,250,0.20)' },
  { href: '/compliance', label: 'Compliance', Icon: IconSearch, color: '#34d399', bg: 'rgba(52,211,153,0.20)' },
  // No dedicated VPN/tunnel icon exists in components/icons.js — reusing
  // IconUser (VPN is fundamentally remote-USER access) rather than inventing
  // a new SVG file, same "reuse what's there even if not a perfect semantic
  // match" call this file already made for Compliance -> IconSearch.
  { href: '/vpn', label: 'VPN', Icon: IconUser, color: '#818cf8', bg: 'rgba(129,140,248,0.20)' },
  { href: '/settings', label: 'Settings', Icon: IconSettings, color: '#9ca3af', bg: 'rgba(156,163,175,0.20)' },
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
        {NAV.map(({ href, label, Icon, exact, color, bg }) => {
          const active = isActive(pathname, href, exact);
          return (
            <Link key={href} href={href} className={active ? 'active' : ''} title={collapsed ? label : undefined}>
              <span className="sv-nav-chip" style={{ '--chip-color': color, '--chip-bg': bg }}>
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
