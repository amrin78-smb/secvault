import Link from 'next/link';
import { pool } from '../../../lib/db';
import PageHeader from '../../../components/ui/PageHeader';
import ComplianceMatrix, { STANDARDS, STANDARD_META } from '../../../components/compliance/ComplianceMatrix';
import StandardCard from '../../../components/compliance/StandardCard';

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

// Fleet-wide per-standard totals, summed from the already-fetched `devices`
// array (each device's `.standards[key]` counts are computed by
// getFleetCompliance above) -- pure JS reduction, no new query needed.
function getFleetStandardTotals(devices) {
  const totals = {};
  for (const s of STANDARDS) totals[s.key] = { pass: 0, fail: 0, warning: 0, na: 0, total: 0 };
  let latestRunAt = null;
  for (const device of devices) {
    if (device.lastRunAt && (!latestRunAt || new Date(device.lastRunAt) > new Date(latestRunAt))) {
      latestRunAt = device.lastRunAt;
    }
    for (const s of STANDARDS) {
      const stat = device.standards[s.key];
      totals[s.key].pass += stat.pass;
      totals[s.key].fail += stat.fail;
      totals[s.key].warning += stat.warning;
      totals[s.key].na += stat.na;
      totals[s.key].total += stat.total;
    }
  }
  for (const s of STANDARDS) {
    totals[s.key].scorePct = scorePctFromCounts(totals[s.key]);
  }
  return { totals, latestRunAt };
}

// One row per (device, standard) where that device has at least one 'fail'
// finding mapped to that standard -- feeds each fleet-level StandardCard's
// "Failed" list. Distinct from the per-device StandardCard's list (which
// shows failed CHECK NAMES): at fleet scale, "which devices need attention
// for this standard" is the more directly actionable thing to show, since a
// single check can fail identically across many devices and a check-name
// list wouldn't say where. A separate, bounded query (not reused from
// getFleetCompliance's own findingRows -- that query doesn't join devices
// for names/select fail-only rows) -- same "some duplication accepted"
// tradeoff this codebase already takes elsewhere (see the Alerts/Compliance
// query-triplication notes in CLAUDE.md).
async function getFleetFailedDevicesByStandard(dbPool) {
  const { rows } = await dbPool.query(
    `SELECT DISTINCT af.device_id, d.name AS device_name, ac.standards
     FROM audit_findings af
     JOIN audit_checks ac ON ac.id = af.check_id
     JOIN devices d ON d.id = af.device_id
     WHERE af.status = 'fail' AND d.active = true
     ORDER BY d.name ASC`
  );

  const byStandard = {};
  for (const s of STANDARDS) byStandard[s.key] = [];
  const seen = {};
  for (const s of STANDARDS) seen[s.key] = new Set();

  for (const row of rows) {
    const list = Array.isArray(row.standards) ? row.standards : [];
    for (const key of list) {
      if (!byStandard[key] || seen[key].has(row.device_id)) continue;
      seen[key].add(row.device_id);
      byStandard[key].push({
        id: row.device_id,
        name: row.device_name,
        href: `/compliance/${row.device_id}#${key}`,
      });
    }
  }
  return byStandard;
}

// Plain function returning JSX (not a nested component -- CLAUDE.md's
// critical React rule), matching the tabLink()/scoreChip() "helper called
// imperatively" pattern already used elsewhere in this codebase.
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
    <div style={{ display: 'inline-flex', gap: 4, padding: 4, background: 'var(--bg-primary)', borderRadius: 'var(--radius)', border: '1px solid var(--border)' }}>
      <Link href="/compliance?view=cards" style={tabStyle('cards')}>
        Cards
      </Link>
      <Link href="/compliance?view=table" style={tabStyle('table')}>
        Compare Devices
      </Link>
    </div>
  );
}

export default async function CompliancePage({ searchParams }) {
  const view = searchParams?.view === 'table' ? 'table' : 'cards';
  const [devices, failedDevicesByStandard] = await Promise.all([
    getFleetCompliance(pool),
    getFleetFailedDevicesByStandard(pool),
  ]);
  const { totals, latestRunAt } = getFleetStandardTotals(devices);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <PageHeader
        title="Compliance"
        subtitle="PCI DSS, ISO 27001, CIS v8, and NIST posture across the fleet."
        actions={
          <a href="/api/compliance/fleet?format=csv" className="btn btn-secondary">
            Export CSV
          </a>
        }
      />

      {viewToggle(view)}

      {view === 'cards' ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 16 }}>
          {STANDARDS.map((s) => {
            const meta = STANDARD_META[s.key] || {};
            const failed = failedDevicesByStandard[s.key] || [];
            return (
              <StandardCard
                key={s.key}
                standard={s}
                description={meta.description}
                referenceUrl={meta.referenceUrl}
                stats={totals[s.key]}
                failedChecks={failed.slice(0, 5)}
                failedChecksTotal={failed.length}
                viewMoreHref="/compliance?view=table"
                lastRunAt={latestRunAt}
              />
            );
          })}
        </div>
      ) : (
        <ComplianceMatrix devices={devices} />
      )}
    </div>
  );
}
