import Link from 'next/link';
import { pool } from '../../../lib/db';
import PageHeader from '../../../components/ui/PageHeader';
import Badge from '../../../components/ui/Badge';
import Card, { CardBody } from '../../../components/ui/Card';
import EmptyState from '../../../components/ui/EmptyState';
import ComplianceMatrix, { STANDARDS, STANDARD_META } from '../../../components/compliance/ComplianceMatrix';
import StandardCard from '../../../components/compliance/StandardCard';
import ZoneClassificationBanner from '../../../components/compliance/ZoneClassificationBanner';
import DeviceSelect from '../../../components/compliance/DeviceSelect';
import { isValidUuid } from '../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

// /compliance has two views, chosen via ?view=:
//  - "cards" (default): ManageEngine-style donut cards for ONE selected
//    device at a time, chosen via ?device=<deviceId> + the DeviceSelect
//    dropdown. This used to render fleet-wide aggregated totals across every
//    active device -- replaced 2026-07-18 because that's not what an
//    operator auditing a specific firewall wants, and there was no way to
//    drill into a single device's posture from this view at all. The
//    per-device rendering here deliberately mirrors
//    compliance/[deviceId]/page.js's own query/aggregation/JSX pattern
//    (down to the query shapes and comments) rather than importing from it --
//    same "duplicate small per-page queries, don't extract a shared module"
//    convention this codebase already uses for the Alerts/Compliance query
//    triplication (see CLAUDE.md).
//  - "table" ("Compare Devices"): unchanged fleet-wide device x standard
//    comparison table (ComplianceMatrix) -- still the place to see every
//    device's score side by side.
//
// standards is a TEXT[] on audit_checks (lib/schema.sql) -- one check can
// count toward multiple standards' scores -- so the per-standard
// pass/fail/warning/na tally can only be done after pulling each finding's
// own standards array in JS; a single SQL GROUP BY standards can't unnest
// a many-to-many array column into 4 independent per-standard buckets as
// cleanly as this loop does.

// Same scorePct formula the sibling GET /api/compliance/fleet and
// GET /api/compliance/[deviceId] routes compute per the frozen API contract:
// pass / (pass+fail+warning) as a percentage, excluding 'na' findings from
// the denominator (an inapplicable check should not drag down a score it was
// never meant to affect). null -- not 0 -- when nothing is measurable (no
// findings mapped to that standard, or every mapped finding is 'na'); see
// ComplianceMatrix.js's scoreColor for why null and 0% must render
// differently.
function scorePctFromCounts(counts) {
  const measurable = counts.pass + counts.fail + counts.warning;
  return measurable > 0 ? Math.round((counts.pass / measurable) * 100) : null;
}

function emptyStandardCounts() {
  const standards = {};
  for (const s of STANDARDS) standards[s.key] = { pass: 0, fail: 0, warning: 0, na: 0, total: 0 };
  return standards;
}

// Only used by the "table" (Compare Devices) view now -- feeds
// ComplianceMatrix's device x standard grid. Still fleet-wide by design;
// that view is unchanged.
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

// Active devices for the DeviceSelect dropdown (Cards view). Deliberately
// slim (id/name/vendor only) -- this is all DeviceSelect and the "which
// device is selected" resolution below need.
async function getActiveDevicesForSelect(dbPool) {
  const { rows } = await dbPool.query(
    `SELECT id, name, vendor FROM devices WHERE active = true ORDER BY name ASC`
  );
  return rows;
}

// Slimmer than the standards page's own copy of this query -- mirrors
// compliance/[deviceId]/page.js's getFindings() exactly: this view only ever
// needs status/standards/name for the cards' aggregate stats and
// failed-check quick-list, never matched_rule_ids/rule evidence.
async function getFindings(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT af.id, ac.check_id AS check_slug, ac.name, ac.standards, af.status, af.detected_at
     FROM audit_findings af
     JOIN audit_checks ac ON ac.id = af.check_id
     WHERE af.device_id = $1`,
    [deviceId]
  );
  return result.rows.map((r) => ({
    id: r.id,
    checkSlug: r.check_slug,
    name: r.name,
    standards: Array.isArray(r.standards) ? r.standards : [],
    status: r.status,
    detectedAt: r.detected_at,
  }));
}

// Same zone-dependent check slug as compliance/[deviceId]/page.js's own
// constant -- see that file's comment.
const ZONE_DEPENDENT_CHECK_SLUG = 'rule-no-external-to-internal-access';

// Distinct zone names seen across this device's collected rules (src_zones +
// dst_zones, both JSONB). Mirrors compliance/[deviceId]/page.js's
// getDeviceZones() exactly, including its defensive posture: vendor parsers
// don't all guarantee these columns are a flat array of strings, so the
// query guards with jsonb_typeof(...) = 'array' before calling
// jsonb_array_elements_text() -- a non-array value would otherwise throw a
// raw SQL error and crash this page's render. Wrapped in try/catch as a
// second layer of defense; on any error this is logged as a warning and the
// caller simply omits the Network Details card -- a nice-to-have
// enrichment, not a required element.
async function getDeviceZones(dbPool, deviceId) {
  try {
    const result = await dbPool.query(
      `SELECT DISTINCT zone FROM (
         SELECT jsonb_array_elements_text(src_zones) AS zone FROM firewall_rules
         WHERE device_id = $1 AND jsonb_typeof(src_zones) = 'array'
         UNION
         SELECT jsonb_array_elements_text(dst_zones) AS zone FROM firewall_rules
         WHERE device_id = $1 AND jsonb_typeof(dst_zones) = 'array'
       ) z
       WHERE zone IS NOT NULL AND zone <> ''
       ORDER BY zone`,
      [deviceId]
    );
    return result.rows.map((r) => r.zone);
  } catch (err) {
    console.warn(`[compliance] getDeviceZones failed for device ${deviceId}, omitting Network Details card:`, err.message);
    return [];
  }
}

function aggregateStandards(findings) {
  const counts = {};
  for (const s of STANDARDS) counts[s.key] = { pass: 0, fail: 0, warning: 0, na: 0, total: 0 };
  for (const f of findings) {
    for (const key of f.standards) {
      if (!counts[key]) continue;
      counts[key][f.status] = (counts[key][f.status] || 0) + 1;
      counts[key].total += 1;
    }
  }
  const result = {};
  for (const s of STANDARDS) {
    result[s.key] = { ...counts[s.key], scorePct: scorePctFromCounts(counts[s.key]) };
  }
  return result;
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

  if (view === 'table') {
    const devices = await getFleetCompliance(pool);
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
        <PageHeader
          title="Compliance"
          subtitle="Compare PCI DSS, ISO 27001, CIS v8, NIST, and SANS scores across every active device. Switch to Cards to see one firewall's full donut breakdown."
          actions={
            <a href="/api/compliance/fleet?format=csv" className="btn btn-secondary">
              Export CSV
            </a>
          }
        />
        {viewToggle(view)}
        <ComplianceMatrix devices={devices} />
      </div>
    );
  }

  // Cards view -- exactly one device's compliance posture, chosen by
  // ?device=<deviceId> (via DeviceSelect) or defaulted to the first active
  // device alphabetically. Never falls back to a fleet-wide aggregate.
  const activeDevices = await getActiveDevicesForSelect(pool);

  if (activeDevices.length === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
        <PageHeader
          title="Compliance"
          subtitle="View one firewall's PCI DSS, ISO 27001, CIS v8, NIST, and SANS posture, or switch to Compare Devices for a fleet-wide table."
        />
        {viewToggle(view)}
        <EmptyState message="No active devices — add a device first." />
      </div>
    );
  }

  // Resolve the selected device defensively: a malformed query param must
  // never crash this render (same posture isValidUuid guards apply
  // everywhere else in this app), and a well-formed but stale/inactive
  // device id (deleted device, copy-pasted old link) falls back to the
  // default rather than surfacing a dead-end "not found" page -- the
  // dropdown only ever offers active devices, so any id outside that set is
  // treated the same as "no selection made". Reused directly from
  // activeDevices (which already carries id/name/vendor) rather than a
  // second getDevice() query -- no new data is needed beyond what the
  // dropdown's own list already fetched.
  const requestedId = typeof searchParams?.device === 'string' ? searchParams.device : null;
  const selected =
    (requestedId && isValidUuid(requestedId) && activeDevices.find((d) => d.id === requestedId)) ||
    activeDevices[0];

  const findings = await getFindings(pool, selected.id);
  const zones = await getDeviceZones(pool, selected.id);

  const standards = aggregateStandards(findings);
  const zoneCheck = findings.find((f) => f.checkSlug === ZONE_DEPENDENT_CHECK_SLUG);
  const zoneCheckIsNa = Boolean(zoneCheck) && zoneCheck.status === 'na';
  const lastRunAt = findings.reduce((latest, f) => {
    if (!f.detectedAt) return latest;
    return !latest || new Date(f.detectedAt) > new Date(latest) ? f.detectedAt : latest;
  }, null);

  // Derived from the already-fetched `findings` array -- no new query
  // needed. Feeds each StandardCard's "Failed Checks" quick-list, linking
  // straight to the per-check detail page, mirroring
  // compliance/[deviceId]/page.js's identical construction.
  const failedChecksByStandard = {};
  for (const s of STANDARDS) failedChecksByStandard[s.key] = [];
  for (const f of findings) {
    if (f.status !== 'fail') continue;
    for (const key of f.standards) {
      if (!failedChecksByStandard[key]) continue;
      failedChecksByStandard[key].push({
        id: f.id,
        name: f.name,
        href: `/compliance/${selected.id}/checks/${f.id}`,
      });
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <PageHeader
        title="Compliance"
        subtitle={
          <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span>Per-firewall PCI DSS, ISO 27001, CIS v8, NIST, and SANS posture.</span>
            <Badge color="info">{selected.vendor}</Badge>
          </span>
        }
        actions={
          <a href={`/api/compliance/${selected.id}?format=csv`} className="btn btn-secondary">
            Export CSV
          </a>
        }
      />

      {viewToggle(view)}

      <DeviceSelect devices={activeDevices} selectedId={selected.id} />

      {zoneCheckIsNa && <ZoneClassificationBanner standards={zoneCheck.standards} />}

      {zones.length > 0 && (
        <Card>
          <CardBody>
            <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
              Network Details
            </div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 8 }}>
              Zones seen across this device&apos;s collected firewall rules — referenced by the zone-based checks
              below (e.g. admin access restrictions).
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {zones.map((zone) => (
                <Badge key={zone} color="muted">
                  {zone}
                </Badge>
              ))}
            </div>
          </CardBody>
        </Card>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 16 }}>
        {STANDARDS.map((s) => {
          const meta = STANDARD_META[s.key] || {};
          const failed = failedChecksByStandard[s.key] || [];
          return (
            <StandardCard
              key={s.key}
              standard={s}
              description={meta.description}
              referenceUrl={meta.referenceUrl}
              stats={standards[s.key]}
              failedChecks={failed.slice(0, 5)}
              failedChecksTotal={failed.length}
              viewMoreHref={`/compliance/${selected.id}/standards#${s.key}`}
              lastRunAt={lastRunAt}
            />
          );
        })}
      </div>
    </div>
  );
}
