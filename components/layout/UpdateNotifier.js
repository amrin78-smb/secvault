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
import { PRODUCT_NAME } from '../../lib/branding';

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
        /* ⛔ WHITE ON --blue IS 2.48:1 IN DARK THEME. --blue flips with the
           theme (#2F6FE0 light → #6BA5FF dark); white text passes at 4.70:1 on
           the light value and fails badly on the lighter dark one, so this
           banner was legible for exactly half its users. The --tint-* pairs are
           the tokens globals.css guarantees at >=4.5:1 in BOTH themes by
           construction — measured here at 5.97:1 light and 8.53:1 dark over
           --bg-primary. This banner sits in the content column, not on --navy,
           so --tint-info-fg (which flips) is correct; --shell-fg would be the
           right choice only on the header or sidebar. */
        background: 'var(--tint-info)',
        color: 'var(--tint-info-fg)',
        borderBottom: '1px solid var(--border)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
        <IconRefresh width={16} height={16} style={{ flexShrink: 0 }} />
        <span style={{ fontSize: 'var(--text-base)', fontWeight: 500 }}>
          {info.latest
            ? `${PRODUCT_NAME} v${info.latest} is available`
            : `A ${PRODUCT_NAME} update is available`}
        </span>
        <Link
          href="/settings"
          style={{ color: 'var(--tint-info-fg)', textDecoration: 'underline', fontWeight: 600, fontSize: 'var(--text-base)', whiteSpace: 'nowrap' }}
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
          color: 'var(--tint-info-fg)',
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
