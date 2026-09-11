'use client';

// components/layout/NavProgress.js
//
// App-wide "this is loading" indicator: a thin bar under the header, shown from
// the moment a navigation starts until the new page's data has arrived.
//
// ⛔ WHY THIS EXISTS ALONGSIDE loading.js, NOT INSTEAD OF IT. Next's route-level
// `loading.js` only fires when the route SEGMENT changes. Every tab in this
// product is a SEARCH PARAM on the same segment — /vpn?vtab=tunnels,
// /vulnerability?tab=advisories, /devices/[id]/analysis?tab=cleanup — and a
// searchParams-only navigation does NOT remount the loading boundary. The old
// page just sits there, fully interactive, for as long as the server takes.
// Measured on this fleet: the VPN Log Activity tab is ~7s on a cold cache, which
// it always is (a 26 GB/day ingest evicts those rows long before anyone revisits).
// Seven seconds of an apparently-frozen page is exactly what this fixes.
//
// Hand-rolled rather than pulling in a progress-bar package: package.json has no
// devDependencies by deliberate policy and `npm ci` ships every runtime
// dependency to a firewall-management server. This is ~80 lines and no build
// step, the same reasoning behind the hand-rolled icons and the absence of a CSS
// framework.

import { useEffect, useRef, useState } from 'react';
import { usePathname, useSearchParams } from 'next/navigation';

// Don't flash for navigations the user never perceives as a wait.
const SHOW_AFTER_MS = 140;

// ⛔ A STUCK PROGRESS BAR IS ITS OWN LIE — it claims work is still happening when
// nothing is. If a navigation never completes (an aborted request, a download we
// failed to exclude, a route that throws), give up and clear rather than spin
// forever. 20s is well past the slowest measured page (~7s cold).
const GIVE_UP_MS = 20000;

export default function NavProgress() {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [visible, setVisible] = useState(false);
  const showTimer = useRef(null);
  const giveUpTimer = useRef(null);

  const clearAll = () => {
    if (showTimer.current) { clearTimeout(showTimer.current); showTimer.current = null; }
    if (giveUpTimer.current) { clearTimeout(giveUpTimer.current); giveUpTimer.current = null; }
  };

  // The destination has rendered — whatever we were waiting for is here.
  useEffect(() => {
    clearAll();
    setVisible(false);
  }, [pathname, searchParams]);

  useEffect(() => {
    const start = () => {
      clearAll();
      showTimer.current = setTimeout(() => setVisible(true), SHOW_AFTER_MS);
      giveUpTimer.current = setTimeout(() => { setVisible(false); }, GIVE_UP_MS);
    };

    const onClick = (e) => {
      // Let the browser do its own thing for anything that isn't a plain
      // left-click navigation in this tab.
      if (e.defaultPrevented || e.button !== 0) return;
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;

      const anchor = e.target instanceof Element ? e.target.closest('a') : null;
      if (!anchor) return;
      if (anchor.target && anchor.target !== '_self') return;
      if (anchor.hasAttribute('download')) return;

      const href = anchor.getAttribute('href');
      if (!href || href.startsWith('#')) return;

      let url;
      try { url = new URL(anchor.href, window.location.href); } catch { return; }
      if (url.origin !== window.location.origin) return;

      // ⛔ /api/* IS NOT A NAVIGATION. "Export CSV" and the compliance PDF are
      // plain <a href="/api/...">, and the browser downloads them without ever
      // changing pathname or searchParams — so the effect above would never
      // fire and the bar would sit there until the give-up timer, telling the
      // operator a page is loading when nothing is.
      if (url.pathname.startsWith('/api/')) return;

      // Same URL: no navigation, nothing to wait for.
      if (url.pathname === window.location.pathname && url.search === window.location.search) return;

      start();
    };

    // Back/forward are navigations too, and they can be slow for the same reason.
    const onPopState = () => start();

    document.addEventListener('click', onClick, { capture: true });
    window.addEventListener('popstate', onPopState);
    return () => {
      document.removeEventListener('click', onClick, { capture: true });
      window.removeEventListener('popstate', onPopState);
      clearAll();
    };
  }, []);

  if (!visible) return null;

  return (
    <div className="nav-progress" role="status" aria-live="polite">
      <div className="nav-progress-bar" />
      <span className="sr-only">Loading…</span>
    </div>
  );
}
