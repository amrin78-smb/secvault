import { Suspense } from 'react';
import { headers } from 'next/headers';
import { redirect } from 'next/navigation';
import { getServerSession } from 'next-auth';
import { authOptions } from '../api/auth/[...nextauth]/route';
import { capabilitiesOf } from '../../lib/rbac';
import { pool } from '../../lib/db';
import { loadScopeForSession } from '../../lib/deviceScope';
import { blockedSurfaceFor, pageRefusal, PATHNAME_HEADER } from '../../lib/deviceScopePaths';
import Sidebar from '../../components/layout/Sidebar';
import Header from '../../components/layout/Header';
import UpdateNotifier from '../../components/layout/UpdateNotifier';
import SubscriptionNotifier from '../../components/layout/SubscriptionNotifier';
import NavProgress from '../../components/layout/NavProgress';
import IdleTimeout from '../../components/layout/IdleTimeout';
import { EvidenceProvider } from '../../components/ui/Evidence';
import pkg from '../../package.json';

/**
 * ⛔ THE AUTHORITATIVE DEVICE-SCOPE CHECK FOR PAGES.
 *
 * middleware.js decides first and decides fast, but it reads `deviceScoped`
 * out of the JWT cookie — and `getToken()` only decrypts, it never runs the
 * jwt() callback, so that claim is as old as the last time NextAuth re-issued
 * the cookie (up to 30 days when SESSION_IDLE_MINUTES=0). A scope GRANTED
 * since then would not be enforced, which is the exact direction this feature
 * exists to prevent.
 *
 * Every dashboard page renders through this layout, so one live read closes it
 * for the whole page surface. ⛔ The read is per-request and deliberately not
 * cached: a cache keyed on anything other than the row itself would reintroduce
 * the staleness it is here to remove.
 *
 * ⛔ WHAT THIS DOES **NOT** COVER, STATED RATHER THAN IMPLIED: Next preserves a
 * SHARED layout across a client-side ("soft") navigation, so on a link click
 * between two dashboard pages this may not re-run. middleware DOES run on that
 * request — it is an ordinary HTTP fetch for the RSC payload — so the surface
 * is still decided, just from the possibly-stale cookie claim. So: a hard load,
 * a reload or a fresh sign-in is decided LIVE; a soft navigation inside an
 * already-open session is decided from the claim. That is why the PUT response
 * tells the administrator to sign the account out to apply a new restriction at
 * once, and it is the honest limit of this layer. Closing it means a
 * `template.js` (which does re-render per navigation) at the cost of remounting
 * every page subtree on every navigation — a real behavioural change across the
 * whole product, not worth making before a customer actually scopes an account.
 * ⛔ VERIFY THE SOFT-NAV BEHAVIOUR ON THE RUNNING SERVER before acting on this
 * paragraph; this codebase has been wrong before about Next's internal ordering
 * (see the /_next/image note in middleware.js) by reasoning instead of probing.
 *
 * ⛔ AN UNRESOLVABLE PATH REFUSES NOTHING, and that is not a fail-open. It
 * means middleware did not run for this request, in which case the whole
 * matcher is misconfigured and refusing here would lock every account out of
 * every page including /devices — a self-inflicted outage in place of a
 * boundary. The condition is LOGGED so it cannot be silent.
 */
async function refusedSurfaceFor(session) {
  const pathname = headers().get(PATHNAME_HEADER);
  if (typeof pathname !== 'string' || !pathname.startsWith('/')) {
    console.warn('[deviceScope] no forwarded pathname on a dashboard render — '
      + 'middleware did not run; the layout could not re-check device scope');
    return null;
  }
  // ⛔ The scope is read ONLY for a surface that could be refused. The
  // overwhelming majority of renders are not, and a database round-trip on
  // every one of them would be a real cost for no decision.
  if (!blockedSurfaceFor(pathname)) return null;

  const scope = await loadScopeForSession(session, pool);
  // ⛔ The verdict itself is pure and lives in lib/deviceScopePaths.js, so it
  // is tested by behaviour rather than by a test that reads this file looking
  // for the right words. A source-shaped test here would pass over an
  // if-block someone had commented out.
  return pageRefusal(pathname, scope).refused ? pathname : null;
}

export default async function DashboardLayout({ children }) {
  const session = await getServerSession(authOptions);

  const refusedPath = await refusedSurfaceFor(session);
  if (refusedPath) {
    // Same destination and same explanation as middleware's own redirect, so
    // the two layers are indistinguishable to the person looking at the screen.
    redirect(`/devices?scopeBlocked=${encodeURIComponent(refusedPath)}`);
  }

  // ⛔ Resolved SERVER-side and passed down, rather than re-fetched by the
  // client sidebar. The nav is defence in depth only — every page it links to
  // guards itself — but a nav derived from a client fetch would briefly show
  // entries the role cannot open, which reads as a broken link rather than a
  // boundary.
  const capabilities = capabilitiesOf(session);

  return (
    <div className="sv-shell">
      {/* ⛔ INSIDE THE DASHBOARD LAYOUT ONLY, so it never mounts on /login —
          a timeout modal over the sign-in page would be nonsense, and the
          component's own signOut() would loop. The server expires the token
          regardless of whether this renders; this is the warning, not the
          boundary. */}
      <IdleTimeout />
      <Header session={session} />
      <div className="sv-body">
        <Sidebar version={pkg.version} capabilities={capabilities} />
        <div className="sv-content-col">
          {/* ⛔ Suspense is REQUIRED: NavProgress calls useSearchParams(), which
              without a boundary opts the whole subtree into client rendering.
              fallback={null} because the bar is only ever shown mid-navigation. */}
          <Suspense fallback={null}>
            <NavProgress />
          </Suspense>
          <SubscriptionNotifier />
          <UpdateNotifier />
          {/* ⛔ Mounted ONCE, here, rather than per page. The drawer is a
              single global surface so the affordance is identical everywhere —
              a dashboard tile, a table cell and a report row all open the same
              panel. Server components below can hand it evidence as a prop
              because a descriptor from lib/evidence.js is plain JSON. */}
          <EvidenceProvider>
            <main className="sv-content">{children}</main>
          </EvidenceProvider>
        </div>
      </div>
    </div>
  );
}
