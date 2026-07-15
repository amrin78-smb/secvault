import { getServerSession } from 'next-auth';
import { authOptions } from '../api/auth/[...nextauth]/route';
import Sidebar from '../../components/layout/Sidebar';
import Header from '../../components/layout/Header';

export default async function DashboardLayout({ children }) {
  const session = await getServerSession(authOptions);

  return (
    <div className="flex min-h-screen bg-bg-base">
      <div className="w-[240px] shrink-0 bg-bg-sidebar border-r border-border">
        <Sidebar />
      </div>
      <div className="flex flex-1 flex-col min-w-0">
        <Header session={session} />
        <main className="flex-1 bg-bg-base p-6 overflow-auto">{children}</main>
      </div>
    </div>
  );
}
