import { getServerSession } from 'next-auth';
import { authOptions } from '../../api/auth/[...nextauth]/route';
import { pool } from '../../../lib/db';
import { capabilitiesOf } from '../../../lib/rbac';
import { visibleReports, clientSafe } from '../../../lib/reports/catalogue';
import { getReportStats, tilesFor } from '../../../lib/reports/reportStats';
import PageHeader from '../../../components/ui/PageHeader';
import Card, { CardBody } from '../../../components/ui/Card';
import EmptyState from '../../../components/ui/EmptyState';
import ReportWorkspace from '../../../components/reports/ReportWorkspace';

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
//
// ⛔ THE HEADLINE FIGURES ARE FETCHED HERE TOO, in ONE query for all five
// reports rather than per report. The page previously described each report and
// showed nothing of it; the tiles are what make it a place you can decide from
// instead of a list of download links. See lib/reports/reportStats.js for why
// they are cheap counts and not the engines' own numbers.

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

  // ⛔ Both reads are independent and neither gates the other, so they run
  // together — a page that costs two serial round trips to show five static
  // descriptions would have been slower than the document it offers.
  const [devices, stats] = await Promise.all([activeDevices(), getReportStats(pool)]);

  // ⛔ clientSafe() at the boundary. A catalogue entry carries a lazy `builder`
  // function so the registry stays cheap to require; React refuses to send a
  // function to a client component, and in a production build that failure is a
  // bare digest on an empty page. Serialise ONCE here rather than at each call
  // site, so a future section cannot forget.
  //
  // ⛔ `tiles` is null, NOT an empty array, when the counts could not be read —
  // the panel renders those two cases differently, and an empty array would
  // collapse "we could not measure this" into "there is nothing to show".
  const reports = visibleReports(caps)
    .map(clientSafe)
    .map((r) => ({ ...r, tiles: tilesFor(r.id, stats) }));

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
      ) : (
        <ReportWorkspace reports={reports} devices={devices} />
      )}
    </div>
  );
}
