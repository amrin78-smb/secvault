'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

// Soft-refreshes the current route's Server Component data every
// `intervalMs`, matching the "dashboard reflects the DB every 60s" intent —
// without the pitfalls of a raw <meta http-equiv="refresh"> tag:
//   - router.refresh() re-fetches Server Component data in place; it does
//     NOT do a full document reload, so it never disturbs in-progress
//     client-side state (e.g. focus, unsaved form input) on THIS page.
//   - Being a real React effect, its cleanup (clearInterval) runs on
//     unmount — i.e. the moment the user navigates away, even via
//     client-side <Link>/router navigation. A <meta refresh> tag has no
//     such lifecycle: since Next.js App Router navigation doesn't reload
//     the document, that timer keeps ticking against whatever the browser
//     is CURRENTLY displaying and fires a full page reload there — which is
//     exactly what was wiping out in-progress input on the Add Device form
//     after visiting the dashboard first.
export default function AutoRefresh({ intervalMs = 60000 }) {
  const router = useRouter();

  useEffect(() => {
    const timer = setInterval(() => {
      router.refresh();
    }, intervalMs);
    return () => clearInterval(timer);
  }, [router, intervalMs]);

  return null;
}
