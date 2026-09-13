import { Suspense } from 'react';
import { getServerSession } from 'next-auth';
import { authOptions } from '../api/auth/[...nextauth]/route';
import Sidebar from '../../components/layout/Sidebar';
import Header from '../../components/layout/Header';
import UpdateNotifier from '../../components/layout/UpdateNotifier';
import NavProgress from '../../components/layout/NavProgress';
import { EvidenceProvider } from '../../components/ui/Evidence';
import pkg from '../../package.json';

export default async function DashboardLayout({ children }) {
  const session = await getServerSession(authOptions);

  return (
    <div className="sv-shell">
      <Header session={session} />
      <div className="sv-body">
        <Sidebar version={pkg.version} />
        <div className="sv-content-col">
          {/* ⛔ Suspense is REQUIRED: NavProgress calls useSearchParams(), which
              without a boundary opts the whole subtree into client rendering.
              fallback={null} because the bar is only ever shown mid-navigation. */}
          <Suspense fallback={null}>
            <NavProgress />
          </Suspense>
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
