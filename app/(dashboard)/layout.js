import { Suspense } from 'react';
import { getServerSession } from 'next-auth';
import { authOptions } from '../api/auth/[...nextauth]/route';
import { capabilitiesOf } from '../../lib/rbac';
import Sidebar from '../../components/layout/Sidebar';
import Header from '../../components/layout/Header';
import UpdateNotifier from '../../components/layout/UpdateNotifier';
import SubscriptionNotifier from '../../components/layout/SubscriptionNotifier';
import NavProgress from '../../components/layout/NavProgress';
import IdleTimeout from '../../components/layout/IdleTimeout';
import { EvidenceProvider } from '../../components/ui/Evidence';
import pkg from '../../package.json';

export default async function DashboardLayout({ children }) {
  const session = await getServerSession(authOptions);
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
