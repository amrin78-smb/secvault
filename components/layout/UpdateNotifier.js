'use client';

// Dismissible top banner — polls GET /api/system/update-available (a cheap
// boolean check, distinct from the heavier GET /api/system/update-status used
// by UpdatePanel) on mount and every 6 hours. Mounted once in
// app/(dashboard)/layout.js so it shows on every authenticated page but never
// on /login (that route is outside the (dashboard) group).
//
// Dismissal is sessionStorage-keyed on the specific `latest` version string so
// a NEW patch released after a dismissed one re-shows the banner even within
// the same browser session — a plain "dismissed=true" flag would hide every
// future update too.

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { IconRefresh } from '../icons';

const DISMISS_KEY_PREFIX = 'sv-update-dismissed-';

export default function UpdateNotifier() {
  const [info, setInfo] = useState(null); // { available, current, latest }
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function check() {
      try {
        const res = await fetch('/api/system/update-available');
        const data = await res.json();
        if (cancelled) return;
        setInfo(data);
        if (data && data.available) {
          const key = data.latest || 'unknown';
          try {
            setDismissed(!!sessionStorage.getItem(DISMISS_KEY_PREFIX + key));
          } catch (_err) {
            // sessionStorage unavailable (private browsing etc.) — just show it.
            setDismissed(false);
          }
        }
      } catch (_err) {
        if (!cancelled) setInfo(null);
      }
    }

    check();
    const interval = setInterval(check, 6 * 60 * 60 * 1000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  function handleDismiss() {
    const key = (info && info.latest) || 'unknown';
    try {
      sessionStorage.setItem(DISMISS_KEY_PREFIX + key, '1');
    } catch (_err) {
      // Non-fatal — dismissal just won't persist for this session.
    }
    setDismissed(true);
  }

  if (!info || !info.available || dismissed) return null;

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 16,
        width: '100%',
        flexShrink: 0,
        padding: '10px 24px',
        background: 'var(--blue)',
        color: '#fff',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
        <IconRefresh width={16} height={16} style={{ flexShrink: 0 }} />
        <span style={{ fontSize: 'var(--text-base)', fontWeight: 500 }}>
          {info.latest ? `SecVault v${info.latest} is available` : 'A SecVault update is available'}
        </span>
        <Link
          href="/settings"
          style={{ color: '#fff', textDecoration: 'underline', fontWeight: 600, fontSize: 'var(--text-base)', whiteSpace: 'nowrap' }}
        >
          Go to Settings
        </Link>
      </div>
      <button
        type="button"
        onClick={handleDismiss}
        aria-label="Dismiss"
        style={{
          background: 'transparent',
          border: 'none',
          color: '#fff',
          cursor: 'pointer',
          fontSize: 18,
          lineHeight: 1,
          padding: 0,
          flexShrink: 0,
        }}
      >
        ×
      </button>
    </div>
  );
}
