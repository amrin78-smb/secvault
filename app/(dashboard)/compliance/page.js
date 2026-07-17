import { pool } from '../../../lib/db';
import PageHeader from '../../../components/ui/PageHeader';
import ComplianceMatrix, { STANDARDS } from '../../../components/compliance/ComplianceMatrix';

export const dynamic = 'force-dynamic';

// Fleet-wide Compliance matrix -- the /compliance landing view. Per this
// app's established convention (server components query the DB directly for
// their initial render; API routes exist for client-triggered writes and any
// future client-side consumer -- see app/(dashboard)/alerts/page.js's own
// comment block, which documents the identical tradeoff for
// app/api/events/route.js), this page does NOT fetch its sibling
// GET /api/compliance/fleet route for its own render -- it duplicates the
// same fleet-aggregation query directly. If the aggregation/scorePct logic
// in one changes, check the other.
//
// standards is a TEXT[] on audit_checks (lib/schema.sql) -- one check can
// count toward multiple standards' scores -- so the per-standard
// pass/fail/warning/na tally can only be done after pulling each finding's
// own standards array in JS; a single SQL GROUP BY standards can't unnest
// a many-to-many array column into 4 independent per-standard buckets as
// cleanly as this loop does.

// Same scorePct formula the sibling GET /api/compliance/fleet route computes
// per the frozen API contract: pass / (pass+fail+warning) as a percentage,
// excluding 'na' findings from the denominator (an inapplicable check should
// not drag down a score it was never meant to affect). null -- not 0 --
// when nothing is measurable for that standard (no findings mapped to it, or
// every mapped finding is 'na'); see ComplianceMatrix.js's scoreColor for
// why null and 0% must render differently.
function scorePctFromCounts(counts) {
  const measurable = counts.pass + counts.fail + counts.warning;
  return measurable > 0 ? Math.round((counts.pass / measurable) * 100) : null;
}

function emptyStandardCounts() {
  const standards = {};
  for (const s of STANDARDS) standards[s.key] = { pass: 0, fail: 0, warning: 0, na: 0, total: 0 };
  return standards;
}

async function getFleetCompliance(dbPool) {
  const { rows } = await dbPool.query(
    `SELECT d.id AS device_id, d.name AS device_name, d.vendor AS vendor,
            af.status, af.detected_at, ac.standards
     FROM devices d
     LEFT JOIN audit_findings af ON af.device_id = d.id
     LEFT JOIN audit_checks ac ON ac.id = af.check_id
     WHERE d.active = true
     ORDER BY d.name ASC`
  );

  const byId = new Map();
  for (const row of rows) {
    let device = byId.get(row.device_id);
    if (!device) {
      device = {
        deviceId: row.device_id,
        deviceName: row.device_name,
        vendor: row.vendor,
        lastRunAt: null,
        standards: emptyStandardCounts(),
      };
      byId.set(row.device_id, device);
    }
    if (row.detected_at && (!device.lastRunAt || new Date(row.detected_at) > new Date(device.lastRunAt))) {
      device.lastRunAt = row.detected_at;
    }
    const list = Array.isArray(row.standards) ? row.standards : [];
    for (const key of list) {
      if (!device.standards[key]) continue; // ignore 'CUSTOM' / anything outside the 4-tab UI
      device.standards[key][row.status] = (device.standards[key][row.status] || 0) + 1;
      device.standards[key].total += 1;
    }
  }

  const devices = Array.from(byId.values());
  for (const device of devices) {
    for (const s of STANDARDS) {
      device.standards[s.key].scorePct = scorePctFromCounts(device.standards[s.key]);
    }
  }
  return devices;
}

export default async function CompliancePage() {
  const devices = await getFleetCompliance(pool);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <PageHeader
        title="Compliance"
        subtitle="PCI DSS, ISO 27001, CIS v8, and NIST posture across the fleet."
      />
      <ComplianceMatrix devices={devices} />
    </div>
  );
}
