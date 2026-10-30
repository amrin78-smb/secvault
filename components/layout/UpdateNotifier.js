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
import { NoticeRow } from './NoticeBar';
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

  // ⛔ RENDERS A ROW, NOT A BANNER (v2.215.0). The full-bleed --tint-info bar
  // this used to draw was 5.2% of the Overview's content pixels and one of the
  // seven surface levels that page was stacking; it now shares one quiet strip
  // with the subscription notice and carries its tone on a dot. The contrast
  // note that used to live here is obsolete in its specifics — the row is on
  // --bg-card with --text-secondary — but its RULE still holds: never put
  // white on a token that flips with the theme.
  return (
    <NoticeRow
      tone="info"
      onDismiss={handleDismiss}
      action={<Link href="/settings" className="notice-link">Go to Settings</Link>}
    >
      {info.latest
        ? `${PRODUCT_NAME} v${info.latest} is available`
        : `A ${PRODUCT_NAME} update is available`}
    </NoticeRow>
  );
}
