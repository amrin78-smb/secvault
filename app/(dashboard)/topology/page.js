import PageHeader from '../../../components/ui/PageHeader';
import PathQueryTab from '../../../components/topology/PathQueryTab';

// Fleet-wide multi-hop path simulation — server shell only (no DB query of
// its own, so no `dynamic = 'force-dynamic'` needed here; the client
// component below owns the fetch to /api/topology/path-query). Mirrors the
// PageHeader/layout shell convention used by every other top-level page
// (vpn/page.js, compliance/page.js).
export default function TopologyPage() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <PageHeader
        title="Topology"
        subtitle="Multi-hop path simulation across your managed firewall fleet."
      />
      <PathQueryTab />
    </div>
  );
}
