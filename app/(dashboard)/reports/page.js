import { getServerSession } from 'next-auth';
import { authOptions } from '../../api/auth/[...nextauth]/route';
import { pool } from '../../../lib/db';
import { capabilitiesOf } from '../../../lib/rbac';
import { visibleReports, clientSafe, SCOPES } from '../../../lib/reports/catalogue';
import PageHeader from '../../../components/ui/PageHeader';
import Card, { CardBody } from '../../../components/ui/Card';
import EmptyState from '../../../components/ui/EmptyState';
import ReportCard from '../../../components/reports/ReportCard';

export const dynamic = 'force-dynamic';

// The report catalogue.
//
// ⛔ SERVER-RENDERED, and the list comes from lib/reports/catalogue.js — the
// same registry the download route resolves against. That is the whole point of
// having a registry: a report cannot appear here and 404 there, or be gated on
// one capability in the page and another in the route. Those three drifting
// apart is the same class of bug as the two PDF helper copies that Phase A
// merged, and it would surface as "the button does nothing".
//
// ⛔ THE DEVICE LIST IS FETCHED HERE so a device-scoped report can offer a real
// picker rather than asking an operator to paste a UUID. Only ACTIVE devices —
// a report about a decommissioned firewall is a document nobody wants and the
// picker should not imply it is available.

async function activeDevices() {
  try {
    const { rows } = await pool.query(
      `SELECT id, name, vendor, site
         FROM devices
        WHERE active
        ORDER BY name ASC`
    );
    return rows;
  } catch (_err) {
    // ⛔ The picker degrades to empty; it does not take the page down. A
    // catalogue that cannot be browsed because one dropdown failed to populate
    // is a worse outcome than a fleet report the operator can still run.
    return [];
  }
}

export default async function ReportsPage() {
  const session = await getServerSession(authOptions);
  const caps = capabilitiesOf(session);
  // ⛔ clientSafe() at the boundary. A catalogue entry carries a lazy `builder`
  // function so the registry stays cheap to require; React refuses to send a
  // function to a client component, and in a production build that failure is a
  // bare digest on an empty page. Serialise ONCE here rather than at each call
  // site, so a future section cannot forget.
  const reports = visibleReports(caps).map(clientSafe);
  const devices = await activeDevices();

  const fleet = reports.filter((r) => r.scope === SCOPES.FLEET);
  const perDevice = reports.filter((r) => r.scope === SCOPES.DEVICE);
  // ⛔ Entity-scoped reports (a specific change request) are deliberately NOT
  // listed here. They are reached from the record they describe, because this
  // page cannot offer a meaningful picker for "which of your change requests" —
  // and a catalogue entry that leads to a dead form is worse than its absence.
  const entity = reports.filter((r) => r.scope === SCOPES.ENTITY);

  return (
    <div>
      <PageHeader
        title="Reports"
        subtitle="Point-in-time PDFs you can hand to an auditor, a manager, or whoever edits the firewall."
      />

      {reports.length === 0 ? (
        <Card>
          <CardBody>
            <EmptyState message="Your role does not include access to any report." />
          </CardBody>
        </Card>
      ) : null}

      {fleet.length > 0 ? (
        <section style={{ marginBottom: 'var(--s5)' }}>
          <h2
            style={{
              fontSize: 'var(--text-xs)',
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
              color: 'var(--text-muted)',
              fontWeight: 600,
              margin: '0 0 var(--s3)',
            }}
          >
            Fleet-wide
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
            {fleet.map((r) => (
              <ReportCard key={r.id} report={r} devices={devices} />
            ))}
          </div>
        </section>
      ) : null}

      {perDevice.length > 0 ? (
        <section style={{ marginBottom: 'var(--s5)' }}>
          <h2
            style={{
              fontSize: 'var(--text-xs)',
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
              color: 'var(--text-muted)',
              fontWeight: 600,
              margin: '0 0 var(--s3)',
            }}
          >
            Per firewall
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
            {perDevice.map((r) => (
              <ReportCard key={r.id} report={r} devices={devices} />
            ))}
          </div>
        </section>
      ) : null}

      {entity.length > 0 ? (
        <Card>
          <CardBody>
            <div
              style={{
                fontSize: 'var(--text-sm)',
                color: 'var(--text-secondary)',
                borderLeft: '3px solid var(--border)',
                paddingLeft: 'var(--s3)',
              }}
            >
              <strong>
                {entity.map((r) => r.name).join(', ')}
              </strong>{' '}
              {entity.length === 1 ? 'is' : 'are'} produced from a specific record rather than
              from this page — open the change request itself and export it there, so the
              document is always tied to the request it describes.
            </div>
          </CardBody>
        </Card>
      ) : null}
    </div>
  );
}
