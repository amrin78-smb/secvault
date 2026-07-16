// components/layout/Header.js
// Server component — queries feed_sync_log directly via lib/feedStatus.js for
// the sync-status pill (no client round-trip needed for that one value).
// Interactive pieces (search, bell, theme toggle, avatar dropdown) are their
// own 'use client' children.
import { pool } from '../../lib/db';
import { getSyncPillStatus } from '../../lib/feedStatus';
import HeaderSearch from './HeaderSearch';
import ThemeToggle from './ThemeToggle';
import NotificationBell from './NotificationBell';
import UserMenu from './UserMenu';

function SecVaultLogo() {
  return (
    <svg viewBox="0 0 190 40" style={{ height: 32, width: 'auto' }} aria-hidden="true">
      <path
        d="M19 3l13 5v8c0 9-5.5 15-13 18-7.5-3-13-9-13-18V8z"
        fill="none"
        stroke="var(--accent-teal)"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <path
        d="M13 19l4 4 8-9"
        fill="none"
        stroke="var(--accent-teal)"
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <text x="42" y="27" fontSize="22" fontWeight="700" letterSpacing="-0.3" fontFamily="Inter, system-ui, sans-serif">
        <tspan fill="#ffffff">Sec</tspan>
        <tspan fill="var(--accent-teal)">Vault</tspan>
      </text>
    </svg>
  );
}

export default async function Header({ session }) {
  let syncStatus = { ok: false, label: 'UNKNOWN' };
  try {
    syncStatus = await getSyncPillStatus(pool);
  } catch (_err) {
    // Sync status is informational only — never let a query failure here
    // break the whole header/page render.
  }

  return (
    <header className="sv-topbar">
      <div style={{ display: 'flex', alignItems: 'center', height: '100%' }}>
        <SecVaultLogo />
      </div>

      <div className="sv-topbar-divider" />

      <div className="sv-topbar-subtitle">FIREWALL SECURITY PLATFORM</div>

      <div className="sv-topbar-left">
        <HeaderSearch />
      </div>

      <div className="sv-topbar-right">
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 7,
            padding: '5px 12px',
            background: syncStatus.ok ? 'rgba(22,163,74,0.15)' : 'rgba(220,38,38,0.15)',
            borderRadius: 20,
            border: `1px solid ${syncStatus.ok ? 'rgba(22,163,74,0.3)' : 'rgba(220,38,38,0.3)'}`,
          }}
          title="Feed sync status (NVD + KEV)"
        >
          <div
            style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              background: syncStatus.ok ? 'var(--green)' : 'var(--red)',
              boxShadow: syncStatus.ok ? '0 0 6px var(--green)' : 'none',
              animation: syncStatus.ok ? 'pulse 2s infinite' : 'none',
            }}
          />
          <span
            style={{
              fontSize: 'var(--text-xs)',
              fontWeight: 600,
              color: syncStatus.ok ? '#86efac' : '#fca5a5',
              letterSpacing: '0.03em',
            }}
          >
            {syncStatus.label}
          </span>
        </div>

        <NotificationBell />
        <ThemeToggle />
        <UserMenu session={session} />
      </div>
    </header>
  );
}
