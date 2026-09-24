import Link from 'next/link';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import DownloadButton from '../ui/DownloadButton';

// Shortcuts to things an operator actually does from the dashboard.
//
// ⛔ Every entry here points at a route that EXISTS. The mockup this layout
// came from listed "Generate Report" and "Export Data" as generic actions;
// "Export Data" has no fleet-wide equivalent in this app (only per-tab CSV on
// the Rule Analysis reorder tab), so it is deliberately absent rather than
// wired to something approximate. A dead shortcut is worse than a missing one.
const ACTIONS = [
  { label: 'Add device', href: '/devices/new', hint: 'Register a firewall' },
  { label: 'View devices', href: '/devices', hint: 'Inventory and health' },
  { label: 'Compliance report', href: '/api/compliance/report/pdf', hint: 'Download fleet PDF', external: true },
  { label: 'Open alerts', href: '/alerts', hint: 'Unacknowledged findings' },
  { label: 'Lifecycle & health', href: '/lifecycle', hint: 'Licences, HA, disk' },
];

const ITEM_STYLE = {
  display: 'flex',
  flexDirection: 'column',
  gap: 1,
  padding: '7px 9px',
  borderRadius: 'var(--radius-sm)',
  border: '1px solid var(--border)',
  textDecoration: 'none',
  color: 'var(--text-primary)',
};

export default function QuickActions() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Quick Actions</CardTitle>
      </CardHeader>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {ACTIONS.map((a) =>
            a.external ? (
              // A file download, not an app route — never next/link, which would
              // try to treat the PDF as a page.
              //
              // ⛔ CONVERTED TOGETHER WITH ITS TWIN ON /compliance, on purpose.
              // Both point at the same pdfkit route; leaving one as a bare link
              // would mean the same action gives feedback in one place and
              // nothing in the other, which reads as one of them being broken.
              <DownloadButton
                key={a.href}
                href={a.href}
                className=""
                wrapperStyle={{ display: 'flex', width: '100%' }}
                style={{ ...ITEM_STYLE, flex: 1, alignItems: 'flex-start' }}
                fallbackName="secvault-compliance-report.pdf"
                preparingLabel="Building…"
              >
                <span style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                  <span style={{ fontWeight: 600, fontSize: 'var(--text-base)' }}>{a.label}</span>
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{a.hint}</span>
                </span>
              </DownloadButton>
            ) : (
              <Link key={a.href} href={a.href} style={ITEM_STYLE}>
                <span style={{ fontWeight: 600, fontSize: 'var(--text-base)' }}>{a.label}</span>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{a.hint}</span>
              </Link>
            )
          )}
        </div>
      </CardBody>
    </Card>
  );
}
