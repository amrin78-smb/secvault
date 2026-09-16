'use client';

// Top banner for the SecVault subscription. Mounted once in
// app/(dashboard)/layout.js, beside UpdateNotifier, so it shows on every
// authenticated page but never on /login.
//
// ⛔ IT STAYS QUIET WHILE THERE IS NOTHING TO DO. A healthy trial with three
// weeks left and a licence that renews in eight months both render NOTHING. A
// banner that is always present is a banner nobody reads, and this one has to
// still work on the day it says the subscription has lapsed.
//
// ⛔ IT IS NEVER THE ONLY WARNING AND NEVER A WALL. It links to the panel; it
// does not block the page. Nothing in this product interposes a paywall between
// an operator and a firewall finding.

import { useEffect, useState } from 'react';
import Link from 'next/link';
// ⛔ From licenceBanner, NOT productLicense. The latter requires child_process
// and crypto to fingerprint the machine, and pulling that into a client bundle
// fails the build outright. The rule is not duplicated here — two copies would
// eventually disagree about when to warn someone their subscription lapsed.
import { bannerFor } from '../../lib/licenceBanner';

const DISMISS_PREFIX = 'sv-subscription-dismissed-';

const TONE_STYLE = {
  warn: { bg: 'var(--tint-warn)', fg: 'var(--tint-warn-fg)' },
  bad: { bg: 'var(--tint-danger)', fg: 'var(--tint-danger-fg)' },
  info: { bg: 'var(--tint-info)', fg: 'var(--tint-info-fg)' },
};

export default function SubscriptionNotifier() {
  const [info, setInfo] = useState(null);
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function check() {
      try {
        const res = await fetch('/api/license');
        if (!res.ok) return;
        const data = await res.json();
        if (cancelled) return;
        setInfo(data);
        // ⛔ Keyed on the status AND the day count, so a dismissal made with ten
        // days left does not also hide the banner on the day it expires.
        const key = DISMISS_PREFIX + data.status + '-' + data.daysRemaining;
        try {
          setDismissed(!!sessionStorage.getItem(key));
        } catch {
          setDismissed(false);
        }
      } catch {
        // ⛔ A failed check shows NOTHING rather than an alarming banner. We do
        // not know the state; saying so in a red bar across every page would be
        // asserting a problem we have not established.
        if (!cancelled) setInfo(null);
      }
    }

    check();
    const t = setInterval(check, 6 * 60 * 60 * 1000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  const banner = bannerFor(info);
  if (!banner) return null;
  if (banner.dismissible && dismissed) return null;

  const style = TONE_STYLE[banner.tone] || TONE_STYLE.info;

  function dismiss() {
    try {
      sessionStorage.setItem(DISMISS_PREFIX + info.status + '-' + info.daysRemaining, '1');
    } catch { /* private browsing — it just reappears, which is fine */ }
    setDismissed(true);
  }

  return (
    <div
      role="status"
      style={{
        background: style.bg,
        color: style.fg,
        padding: 'var(--s3) var(--s5)',
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--s4)',
        fontSize: 'var(--text-sm)',
        lineHeight: 1.5,
        borderBottom: '1px solid var(--border)',
      }}
    >
      <span style={{ flex: 1, minWidth: 0 }}>{info.sentence.text}</span>
      <Link
        href="/settings?tab=subscription"
        style={{ color: 'inherit', fontWeight: 600, textDecoration: 'underline', whiteSpace: 'nowrap' }}
      >
        Subscription
      </Link>
      {banner.dismissible ? (
        <button
          type="button"
          onClick={dismiss}
          aria-label="Dismiss"
          style={{
            background: 'none', border: 'none', color: 'inherit', cursor: 'pointer',
            fontSize: 'var(--text-lg)', lineHeight: 1, padding: 0,
          }}
        >
          ×
        </button>
      ) : null}
    </div>
  );
}
