import Link from 'next/link';
import PageHeader from '../../../components/ui/PageHeader';
import PathQueryTab from '../../../components/topology/PathQueryTab';
import FleetMap from '../../../components/topology/FleetMap';

// Fleet-wide multi-hop path simulation — server shell only for the "query"
// view (no DB query of its own there; the client component owns the fetch
// to /api/topology/path-query). The "map" view's FleetMap IS a server
// component with its own pool query, so this file still needs no
// `dynamic = 'force-dynamic'` itself — Next.js only requires that export on
// the file that actually touches the DB.
//
// Two views via ?view=, same toggle pattern as /compliance's
// ?view=cards|table (see that page's viewToggle() for the precedent this
// mirrors) — "query" stays the default so any existing bookmark/link to
// plain /topology keeps behaving exactly as it did before this view was
// added.

// Plain function returning JSX (not a nested component — CLAUDE.md's
// critical React rule), same "helper called imperatively" pattern as
// compliance/page.js's viewToggle().
function viewToggle(active) {
  const tabStyle = (key) => ({
    padding: '6px 14px',
    fontSize: 'var(--text-sm)',
    fontWeight: 600,
    borderRadius: 'var(--radius-sm)',
    textDecoration: 'none',
    color: active === key ? '#fff' : 'var(--text-secondary)',
    background: active === key ? 'var(--primary)' : 'transparent',
  });
  return (
    <div
      style={{
        display: 'inline-flex',
        gap: 4,
        padding: 4,
        background: 'var(--bg-primary)',
        borderRadius: 'var(--radius)',
        border: '1px solid var(--border)',
      }}
    >
      <Link href="/topology?view=query" style={tabStyle('query')}>
        Path Query
      </Link>
      <Link href="/topology?view=map" style={tabStyle('map')}>
        Fleet Map
      </Link>
    </div>
  );
}

export default function TopologyPage({ searchParams }) {
  const view = searchParams?.view === 'map' ? 'map' : 'query';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <PageHeader
        title="Topology"
        subtitle="Multi-hop path simulation across your managed firewall fleet."
        actions={viewToggle(view)}
      />
      {view === 'map' ? <FleetMap /> : <PathQueryTab />}
    </div>
  );
}
