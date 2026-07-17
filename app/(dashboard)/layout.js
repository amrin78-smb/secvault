import { getServerSession } from 'next-auth';
import { authOptions } from '../api/auth/[...nextauth]/route';
import Sidebar from '../../components/layout/Sidebar';
import Header from '../../components/layout/Header';
import UpdateNotifier from '../../components/layout/UpdateNotifier';
import pkg from '../../package.json';

export default async function DashboardLayout({ children }) {
  const session = await getServerSession(authOptions);

  return (
    <div className="sv-shell">
      <Header session={session} />
      <div className="sv-body">
        <Sidebar version={pkg.version} />
        <div className="sv-content-col">
          <UpdateNotifier />
          <main className="sv-content">{children}</main>
        </div>
      </div>
    </div>
  );
}
