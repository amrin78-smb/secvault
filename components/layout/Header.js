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
import { PRODUCT_NAME_PARTS } from '../../lib/branding';

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
      {/* ⛔ fontFamily came through style, not the SVG presentation
          attribute, and it reads the token. It said "Inter, system-ui,
          sans-serif" until 2026-09-09 — a leftover from before the fonts
          were self-hosted, which meant the wordmark rendered in a
          DIFFERENT face from every other word in the product, in the one
          place a customer looks first. */}
      <text
        x="42"
        y="27"
        fontSize="22"
        fontWeight="700"
        letterSpacing="-0.3"
        style={{ fontFamily: 'var(--font-sans)' }}
      >
        <tspan fill="var(--shell-fg)">{PRODUCT_NAME_PARTS[0]}</tspan>
        <tspan fill="var(--accent-teal)">{PRODUCT_NAME_PARTS[1]}</tspan>
      </text>
    </svg>
  );
}

// ⛔ THE PILL IS TRI-STATE, because "is the advisory data complete" is.
// It was a boolean (green/red) and read green FEEDS OK over an NVD feed that
// had logged 464 'partial' runs and zero clean ones — see the ⛔ block at the
// top of lib/feedStatus.js. Amber is the state that was missing: the feeds ran,
// they came back INCOMPLETE, and every CVE number under this bar is computed
// from what arrived.
//
// ⛔ TOKENS. This pill sits on --navy, which is dark in BOTH themes, so the
// foreground colours are --shell-fg/--shell-fg-ok/--shell-fg-bad, which do NOT
// flip. A --tint-*-fg here would be a dark colour on a dark bar in light mode,
// i.e. invisible (gotchas.md, "The shell is dark in BOTH themes").
// There is no --shell-fg-warn, so the DEGRADED row carries its hue in the dot
// and the ring (--sev-med, the amber the severity ramp already uses for
// medium) and keeps --shell-fg for the words, which is legible on navy in both
// themes by construction. SYNCING is --unmeasured: an in-flight sync is not a
// verdict, and per the design system an unmeasured state gets no hue.
const PILL_TONE = {
  ok: {
    dot: 'var(--green)',
    fg: 'var(--shell-fg-ok)',
    bg: 'rgba(22,163,74,0.15)',
    ring: 'rgba(22,163,74,0.3)',
    pulse: true,
  },
  degraded: {
    dot: 'var(--sev-med)',
    fg: 'var(--shell-fg)',
    bg: 'rgba(183,121,31,0.20)',
    ring: 'rgba(183,121,31,0.45)',
    pulse: false,
  },
  error: {
    dot: 'var(--red)',
    fg: 'var(--shell-fg-bad)',
    bg: 'rgba(220,38,38,0.15)',
    ring: 'rgba(220,38,38,0.3)',
    pulse: false,
  },
  running: {
    dot: 'var(--unmeasured)',
    fg: 'var(--shell-fg)',
    bg: 'rgba(255,255,255,0.08)',
    ring: 'rgba(255,255,255,0.18)',
    pulse: false,
  },
};
// No advisory feed has ever run, or the status query itself failed. Both are
// gaps, not all-clears, and both keep the alarming treatment they already had.
PILL_TONE.none = PILL_TONE.error;

export default async function Header({ session }) {
  let syncStatus = {
    state: 'none',
    ok: false,
    label: 'FEEDS UNKNOWN',
    title: 'SecVault could not read feed_sync_log, so it cannot say whether advisory data is complete.',
  };
  try {
    syncStatus = await getSyncPillStatus(pool);
  } catch (_err) {
    // Sync status is informational only — never let a query failure here
    // break the whole header/page render. ⛔ The fallback above is NOT green:
    // failing to read the feed log tells us nothing good.
  }
  const tone = PILL_TONE[syncStatus.state] || PILL_TONE.none;

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
            borderRadius: 'var(--radius-pill)',
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
              // ⛔ --shell-fg-ok/bad, NOT --tint-success-fg: this pill sits on the
              // always-dark header, and a theme-flipping fg goes invisible there
              // in light mode.
              color: syncStatus.ok ? 'var(--shell-fg-ok)' : 'var(--shell-fg-bad)',
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
