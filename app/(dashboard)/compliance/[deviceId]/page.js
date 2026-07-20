import Link from 'next/link';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../api/auth/[...nextauth]/route';
import { isAdmin } from '../../../../lib/rbac';
import { pool } from '../../../../lib/db';
import PageHeader from '../../../../components/ui/PageHeader';
import Badge from '../../../../components/ui/Badge';
import Card, { CardBody } from '../../../../components/ui/Card';
import RunAuditButton from '../../../../components/compliance/RunAuditButton';
import StandardCard from '../../../../components/compliance/StandardCard';
import { STANDARDS, STANDARD_META } from '../../../../components/compliance/ComplianceMatrix';
import { isValidUuid } from '../../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

// Per-device Compliance SUMMARY view — the StandardCard grid + Network
// Details only. Same "server component queries the DB directly for its own
// render" convention as the fleet page (app/(dashboard)/compliance/page.js)
// and app/(dashboard)/alerts/page.js -- deliberately duplicates the same
// scorePct/aggregation formula the sibling GET /api/compliance/[deviceId]
// route computes, rather than internally fetching that route for this
// page's initial render (no page in this app self-fetches its own paired
// API GET route -- checked across app/(dashboard) before writing this).
// RunAuditButton still POSTs to the sibling /run route -- that write path is
// exactly what API routes are for.
//
// ⛔ Split 2026-07-18: this page used to ALSO render the full multi-standard
// browsable table (StandardTabs) stacked below the cards -- a user reported
// that made the page require scrolling past 5 summary cards just to reach
// it. The table now lives on its own page
// (compliance/[deviceId]/standards/page.js), one click away via each card's
// "+N more" link or the "View All Checks" header action below. This page no
// longer needs matched_rule_ids/rule-evidence resolution at all (that only
// ever fed the table), so getFindings()/its query here is intentionally
// slimmer than the standards page's own copy.

function formatDateTime(value) {
  if (!value) return 'Never run';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'Never run';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

// Same formula as app/(dashboard)/compliance/page.js's scorePctFromCounts --
// see that file's comment for why 'na' is excluded from the denominator and
// why the result is null (not 0) when nothing is measurable.
function scorePctFromCounts(counts) {
  const measurable = counts.pass + counts.fail + counts.warning;
  return measurable > 0 ? Math.round((counts.pass / measurable) * 100) : null;
}

async function getDevice(dbPool, id) {
  const result = await dbPool.query('SELECT id, name, vendor FROM devices WHERE id = $1', [id]);
  return result.rows[0] || null;
}

// Slimmer than the standards page's own copy of this query — this page only
// ever needs status/standards/name for the cards' aggregate stats and
// failed-check quick-list, never matched_rule_ids/rule evidence.
async function getFindings(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT af.id, ac.name, ac.standards, af.status, af.detected_at
     FROM audit_findings af
     JOIN audit_checks ac ON ac.id = af.check_id
     WHERE af.device_id = $1`,
    [deviceId]
  );
  return result.rows.map((r) => ({
    id: r.id,
    name: r.name,
    standards: Array.isArray(r.standards) ? r.standards : [],
    status: r.status,
    detectedAt: r.detected_at,
  }));
}

// Distinct zone names seen across this device's collected rules (src_zones +
// dst_zones, both JSONB). Vendor parsers don't all guarantee these columns
// are a flat array of strings, so the query itself guards with
// jsonb_typeof(...) = 'array' before calling jsonb_array_elements_text() --
// a non-array value would otherwise throw a raw SQL error and crash this
// page's render. Wrapped in try/catch as a second layer of defense (e.g. an
// unexpected element shape inside an array that IS jsonb array-typed) --
// on any error this is logged as a warning and the caller simply omits the
// Network Details card; this is a nice-to-have enrichment, not a required
// element, so failing open (no card) is the right degrade.
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
    console.warn(`[compliance/${deviceId}] getDeviceZones failed, omitting Network Details card:`, err.message);
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

function notFound() {
  return (
    <div>
      <Link href="/compliance" style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
        ← Back to Compliance
      </Link>
      <p style={{ marginTop: 16, color: 'var(--text-secondary)' }}>Device not found.</p>
    </div>
  );
}

export default async function DeviceCompliancePage({ params }) {
  // A malformed deviceId in the URL (stale/hand-edited link) must never reach
  // pool.query() -- Postgres throws a raw "invalid input syntax for type
  // uuid" error for a UUID-typed column, which would crash this page's
  // render. Same guard app/(dashboard)/alerts/page.js applies to its
  // device_id query-param filter.
  if (!isValidUuid(params.deviceId)) {
    return notFound();
  }

  const device = await getDevice(pool, params.deviceId);
  if (!device) {
    return notFound();
  }

  // Defense in depth only -- POST /api/compliance/[deviceId]/run is already
  // server-side admin-only (lib/rbac.js). Hiding the button here just avoids
  // a viewer clicking it and getting a 403.
  const session = await getServerSession(authOptions);
  const canWrite = isAdmin(session);

  const findings = await getFindings(pool, device.id);
  const zones = await getDeviceZones(pool, device.id);

  const standards = aggregateStandards(findings);
  const lastRunAt = findings.reduce((latest, f) => {
    if (!f.detectedAt) return latest;
    return !latest || new Date(f.detectedAt) > new Date(latest) ? f.detectedAt : latest;
  }, null);

  // Derived from the already-fetched `findings` array -- no new query needed.
  // Feeds each StandardCard's "Failed Checks" quick-list, linking straight
  // to the per-check detail page (a REAL page navigation) -- see that
  // page's own header comment for why. `viewMoreHref` below ("+N more") now
  // points at the new dedicated /standards page (see that file's header
  // comment) instead of a same-page anchor -- this page no longer has an
  // in-page table to scroll to at all.
  const failedChecksByStandard = {};
  for (const s of STANDARDS) failedChecksByStandard[s.key] = [];
  for (const f of findings) {
    if (f.status !== 'fail') continue;
    for (const key of f.standards) {
      if (!failedChecksByStandard[key]) continue;
      failedChecksByStandard[key].push({
        id: f.id,
        name: f.name,
        href: `/compliance/${device.id}/checks/${f.id}`,
      });
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <Link href="/compliance" style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
          ← Back to Compliance
        </Link>
      </div>

      <PageHeader
        title={`Compliance — ${device.name}`}
        subtitle={
          <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Badge color="info">{device.vendor}</Badge>
            <span>Last run: {formatDateTime(lastRunAt)}</span>
          </span>
        }
        actions={
          <>
            <Link href={`/compliance/${device.id}/standards`} className="btn btn-secondary">
              View All Checks
            </Link>
            <a href={`/api/compliance/${device.id}?format=csv`} className="btn btn-secondary">
              Export CSV
            </a>
            <Link href={`/compliance/${device.id}/print`} className="btn btn-secondary">
              Print Report
            </Link>
            {canWrite && <RunAuditButton deviceId={device.id} />}
          </>
        }
      />

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
              viewMoreHref={`/compliance/${device.id}/standards#${s.key}`}
              lastRunAt={lastRunAt}
            />
          );
        })}
      </div>
    </div>
  );
}
