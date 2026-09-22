import Link from 'next/link';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../api/auth/[...nextauth]/route';
import { can, OPERATE } from '../../../../lib/rbac';
import { pool } from '../../../../lib/db';
import PageHeader from '../../../../components/ui/PageHeader';
import Badge from '../../../../components/ui/Badge';
import Card, { CardBody } from '../../../../components/ui/Card';
import RunAuditButton from '../../../../components/compliance/RunAuditButton';
import { complianceFreshness, ageLabel, freshnessNote, STATES } from '../../../../lib/engines/complianceFreshness';
import StandardCard from '../../../../components/compliance/StandardCard';
import ZoneClassificationBanner from '../../../../components/compliance/ZoneClassificationBanner';
import ExceptionsPanel from '../../../../components/compliance/ExceptionsPanel';
import { STANDARDS, STANDARD_META } from '../../../../components/compliance/ComplianceMatrix';
import { isValidUuid } from '../../../../lib/apiUtils';
import { vendorLabel } from '../../../../components/devices/vendorMeta';
import { getExceptionView } from '../../../../lib/engines/complianceExceptions';

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

// ⛔ 'Never run' and 'Never collected' are different facts and the compliance
// header shows both timestamps, so the empty wording cannot be shared.
function formatCollected(value) {
  if (!value) return 'never collected';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'collection time unreadable';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

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
// ⛔ THE EVIDENCE TIME, WHICH IS NOT THE AUDIT TIME.
// runComplianceAuditForDevice() reads getLatestConfigParsed() -- the newest
// device_configs row, whatever its age -- and stamps detected_at = now(). So
// the audit timestamp says when we last asked the question, and THIS says how
// old the answer's evidence is. Only the second is a freshness claim.
async function getLatestConfigCollectedAt(dbPool, deviceId) {
  const { rows } = await dbPool.query(
    `SELECT collected_at FROM device_configs
     WHERE device_id = $1 ORDER BY collected_at DESC LIMIT 1`,
    [deviceId]
  );
  return rows.length ? rows[0].collected_at : null;
}

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

// Slug of the one compliance check that depends on operator-supplied zone
// classification (Settings > Zones) -- see lib/auditChecksSeed.js and
// configAuditor.js's evaluateExternalToInternalExposure(). Finding this
// specific row's status in the already-fetched `findings` array (no new
// query) tells this page whether to show ZoneClassificationBanner.
const ZONE_DEPENDENT_CHECK_SLUG = 'rule-no-external-to-internal-access';

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

// Compliance exceptions for this device — the recorded "yes, and here is why
// that is mitigated" beside each failing check.
//
// ⛔ THIS DOES NOT FEED aggregateStandards() OR scorePctFromCounts() ABOVE, AND
// MUST NOT. The headline score is computed as if no exception existed: a
// failing check with an accepted exception is still a `fail`, because the
// firewall is still configured that way, and letting a label somebody typed
// move a measurement is how a compliance score becomes a number people manage
// instead of a fact they act on. The panel reports COUNTS beside the score and
// deliberately never a second percentage.
//
// ⛔ A LOAD FAILURE IS REPORTED, NOT SWALLOWED. getDeviceZones() above degrades
// to omitting its card because the zone list is a nice-to-have enrichment;
// accepted risk is not. Silently dropping this panel would render a device with
// three accepted exceptions identically to one with none, which is the
// short-queue-reads-as-a-clean-queue failure in miniature.
async function getExceptions(dbPool, deviceId) {
  try {
    // `now` is injected so expiry is a read-time computation with no cron job
    // and no stored state column — see lib/engines/complianceExceptions.js.
    return { view: await getExceptionView(dbPool, deviceId, new Date()), error: null };
  } catch (err) {
    console.warn(`[compliance/${deviceId}] getExceptionView failed:`, err.message);
    return { view: null, error: err.message || 'unknown error' };
  }
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
  // ⛔ OPERATE, not isAdmin(). The button this gates calls a route that now
  // accepts the Operator role, and a UI gate STRICTER than its API is its own
  // kind of bug: the action is permitted, the control is invisible, and the
  // operator concludes the product is broken rather than that they lack access.
  const canWrite = can(session, OPERATE);

  const findings = await getFindings(pool, device.id);
  const zones = await getDeviceZones(pool, device.id);
  const exceptions = await getExceptions(pool, device.id);

  const standards = aggregateStandards(findings);
  const zoneCheck = findings.find((f) => f.checkSlug === ZONE_DEPENDENT_CHECK_SLUG);
  const zoneCheckIsNa = Boolean(zoneCheck) && zoneCheck.status === 'na';
  const lastRunAt = findings.reduce((latest, f) => {
    if (!f.detectedAt) return latest;
    return !latest || new Date(f.detectedAt) > new Date(latest) ? f.detectedAt : latest;
  }, null);

  // ⛔ THE AGE OF THIS SCORE IS A SEPARATE FACT FROM THE SCORE. The audit
  // runs inside collectAndStore gated on `result.configCollected`, so a
  // firewall that stops being collectable stops being audited and every number
  // on this page simply freezes. Measured live 2026-09-22, TSR_EKC's page was
  // rendering a 27-day-old result with nothing on it saying so.
  const configCollectedAt = await getLatestConfigCollectedAt(pool, device.id);
  const freshness = complianceFreshness(
    { evidenceAt: configCollectedAt, evaluatedAt: lastRunAt }, new Date()
  );

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
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div>
        <Link href="/compliance" style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
          ← Back to Compliance
        </Link>
      </div>

      <PageHeader
        title={`Compliance — ${device.name}`}
        subtitle={
          <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Badge color="info" title={device.vendor}>{vendorLabel(device.vendor)}</Badge>
            <span title={freshnessNote(freshness, device.name)}>
              Configuration collected {ageLabel(freshness)}
              <span style={{ color: 'var(--text-muted)' }}>
                {' '}({formatCollected(configCollectedAt)}); checks last run{' '}
                {formatDateTime(lastRunAt)}
              </span>
            </span>
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

      {(freshness.state === STATES.STALE || freshness.state === STATES.AGEING) && (
        <div style={{
          padding: '10px 12px',
          borderRadius: 'var(--radius-sm)',
          background: 'var(--tint-warn)',
          color: 'var(--tint-warn-fg)',
          fontSize: 'var(--text-sm)',
          lineHeight: 1.6,
        }}>
          <strong>These checks describe a configuration collected {ageLabel(freshness)}.</strong>{' '}
          {freshnessNote(freshness, device.name)}
          {freshness.evaluatedAgainstOldConfig && (
            <>
              {' '}The checks themselves were last re-run{' '}
              {ageLabel(freshness.evaluation)}, but against that same old configuration — which
              is why the two dates differ.
            </>
          )}
          {' '}
          {/* ⛔ The useful action is RE-COLLECTION, not re-running the checks:
              the auditor reads the newest device_configs row whatever its age,
              so Run Audit would stamp a new date on the same old evidence. */}
          <Link href={`/devices/${device.id}`} style={{ color: 'inherit', fontWeight: 600 }}>
            Collect from {device.name}
          </Link>{' '}to refresh the configuration these checks read.
        </div>
      )}

      {zoneCheckIsNa && <ZoneClassificationBanner standards={zoneCheck.standards} deviceId={device.id} />}

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

      {/* ⛔ BELOW the score grid, deliberately: the score is the measurement and
          is read first; this panel annotates it and says in words that the
          score above ignores every exception in it. */}
      {exceptions.error ? (
        <Card>
          <CardBody>
            <div
              role="alert"
              style={{
                fontSize: 'var(--text-sm)',
                color: 'var(--tint-danger-fg)',
              }}
            >
              <strong>Accepted risk could not be loaded.</strong> Any exceptions recorded for
              this firewall are not shown, so a failing check above may already have an
              accepted exception you cannot see here. ({exceptions.error})
            </div>
          </CardBody>
        </Card>
      ) : (
        <ExceptionsPanel
          deviceId={device.id}
          exceptions={exceptions.view.exceptions}
          availableChecks={exceptions.view.availableChecks}
          summary={exceptions.view.summary}
          expiringWindowDays={exceptions.view.expiringWindowDays}
          canWrite={canWrite}
        />
      )}
    </div>
  );
}
