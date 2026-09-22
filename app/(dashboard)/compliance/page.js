import Link from 'next/link';
import { pool } from '../../../lib/db';
import PageHeader from '../../../components/ui/PageHeader';
import AnswerHeader from '../../../components/ui/AnswerHeader';
import { EvidenceMark } from '../../../components/ui/Evidence';
import { buildDeviceComplianceAnswer } from '../../../lib/answers';
import { deviceComplianceEvidence } from '../../../lib/evidence';
import { summariseFreshness } from '../../../lib/engines/complianceFreshness';
import {
  COVERAGE_CLAIM,
  buildStandardCoverage,
  coverageEvidence,
} from '../../../lib/engines/complianceCoverage';
import Badge from '../../../components/ui/Badge';
import Card, { CardBody } from '../../../components/ui/Card';
import EmptyState from '../../../components/ui/EmptyState';
import ComplianceMatrix, { STANDARDS, STANDARD_META } from '../../../components/compliance/ComplianceMatrix';
import StandardCard from '../../../components/compliance/StandardCard';
import ZoneClassificationBanner from '../../../components/compliance/ZoneClassificationBanner';
import DeviceSelect from '../../../components/compliance/DeviceSelect';
import { vendorLabel } from '../../../components/devices/vendorMeta';
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
//  - "table" ("Compare firewalls"): unchanged fleet-wide device x standard
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

// ⛔ THE DENOMINATOR BEHIND EVERY PER-STANDARD PERCENTAGE ON THIS PAGE.
//
// Until v2.163.0 this page printed "NIST 42%" and let it stand for that
// framework's posture. It never was: the curated library is 45 checks, a check
// carries a `standards` ARRAY, and the five mappings measured live are
// CIS_V8 44 / ISO_27001 35 / PCI_DSS 21 / SANS 12 / NIST 7. So the NIST figure
// is computed over SEVEN checks, three of which are vendor-scoped and can
// therefore never all run on one firewall. The arithmetic was always right; the
// claim the bare figure invited was not.
//
// `applicable` is counted against the vendors actually in scope, because a
// check scoped to another vendor can never run and must not sit in a
// denominator as though an audit might one day answer it.
//
// ⛔ A FAILED READ RETURNS null, NEVER `{mapped: 0}`. "0 of 45 checks map to
// PCI DSS" is a claim, and a false one that reads as "SecVault does not support
// this standard" — the same call lib/engines/complianceReport.js's
// standardCoverage() already makes for the scoped PDF.
async function getCheckLibraryCoverage(dbPool, vendors) {
  const scope = Array.isArray(vendors) ? vendors.filter(Boolean) : [];
  try {
    const { rows } = await dbPool.query(
      `SELECT s AS standard,
              count(*)::int AS mapped,
              count(*) FILTER (WHERE ac.vendor IS NULL OR ac.vendor = ANY($1::text[]))::int AS applicable,
              (SELECT count(*)::int FROM audit_checks) AS library_total
       FROM audit_checks ac, unnest(ac.standards) s
       GROUP BY s`,
      [scope]
    );
    if (rows.length === 0) return null;
    const byStandard = {};
    let libraryTotal = null;
    for (const r of rows) {
      if (typeof r.standard !== 'string' || !Number.isFinite(Number(r.mapped))) continue;
      byStandard[r.standard] = { mapped: Number(r.mapped), applicable: Number(r.applicable) };
      if (Number.isFinite(Number(r.library_total))) libraryTotal = Number(r.library_total);
    }
    if (libraryTotal === null) return null;
    return { libraryTotal, byStandard };
  } catch (err) {
    console.warn('[compliance] check-library coverage read failed, coverage will report as unread:', err.message);
    return null;
  }
}

// Turns whatever getCheckLibraryCoverage() returned (possibly null) plus the
// per-standard tallies this page already has into one coverage statement per
// standard. Pure assembly — the judgement lives in lib/engines/complianceCoverage.js
// so the page, the All Checks page and the PDF cannot word it three ways.
function buildCoverage({ library, stats, checkSets, scope, deviceCount }) {
  const out = {};
  for (const s of STANDARDS) {
    const lib = library && library.byStandard[s.key] ? library.byStandard[s.key] : null;
    const counts = stats[s.key] || {};
    const sets = checkSets ? checkSets[s.key] : null;
    out[s.key] = buildStandardCoverage({
      standard: s.key,
      label: s.label,
      scope,
      deviceCount,
      libraryTotal: library ? library.libraryTotal : null,
      mapped: lib ? lib.mapped : null,
      applicable: lib ? lib.applicable : null,
      evaluatedChecks: sets ? sets.evaluated.size : null,
      answeredChecks: sets ? sets.answered.size : null,
      findings: {
        pass: counts.pass,
        fail: counts.fail,
        warning: counts.warning,
        na: counts.na,
      },
      scorePct: counts.scorePct === undefined ? null : counts.scorePct,
    });
  }
  return out;
}

function emptyCheckSets() {
  const sets = {};
  for (const s of STANDARDS) sets[s.key] = { evaluated: new Set(), answered: new Set() };
  return sets;
}

// ⛔ DISTINCT CHECKS, NOT FINDING ROWS. On a fleet a finding is a (device,
// check) PAIR, so 91 NIST finding rows come from at most 7 distinct questions.
// Counting rows here would restate the library as fourteen times larger than it
// is — the same two-units trap lib/evidence.js's CVE builder documents.
function accumulateCheckSets(sets, standardsForRow, checkSlug, status) {
  if (!checkSlug) return;
  for (const key of standardsForRow) {
    if (!sets[key]) continue;
    sets[key].evaluated.add(checkSlug);
    if (status && status !== 'na') sets[key].answered.add(checkSlug);
  }
}

// Only used by the "table" (Compare firewalls) view now -- feeds
// ComplianceMatrix's device x standard grid. Still fleet-wide by design;
// that view is unchanged.
async function getFleetCompliance(dbPool) {
  const { rows } = await dbPool.query(
    // cfg.collected_at is the EVIDENCE time -- what these checks were actually
    // evaluated against. It is a separate fact from af.detected_at (when they
    // last ran) and it is the one freshness grades on; see
    // lib/engines/complianceFreshness.js for why the audit time flatters.
    // LATERAL rather than a join on device_configs: that table holds one row
    // per pull per device and we want exactly the newest.
    `SELECT d.id AS device_id, d.name AS device_name, d.vendor AS vendor,
            af.status, af.detected_at, ac.standards, ac.check_id AS check_slug,
            cfg.collected_at AS config_collected_at
     FROM devices d
     LEFT JOIN audit_findings af ON af.device_id = d.id
     LEFT JOIN audit_checks ac ON ac.id = af.check_id
     LEFT JOIN LATERAL (
       SELECT collected_at FROM device_configs
       WHERE device_id = d.id ORDER BY collected_at DESC LIMIT 1
     ) cfg ON true
     WHERE d.active = true
     ORDER BY d.name ASC`
  );

  // Fleet-wide per-standard totals and the DISTINCT set of checks behind them,
  // accumulated in the same pass as the per-device grid — no second query.
  const fleetStats = emptyStandardCounts();
  const fleetCheckSets = emptyCheckSets();
  const vendors = new Set();

  const byId = new Map();
  for (const row of rows) {
    if (row.vendor) vendors.add(row.vendor);
    let device = byId.get(row.device_id);
    if (!device) {
      device = {
        deviceId: row.device_id,
        deviceName: row.device_name,
        vendor: row.vendor,
        lastRunAt: null,
        configCollectedAt: row.config_collected_at || null,
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
      fleetStats[key][row.status] = (fleetStats[key][row.status] || 0) + 1;
      fleetStats[key].total += 1;
    }
    accumulateCheckSets(fleetCheckSets, list, row.check_slug, row.status);
  }

  const devices = Array.from(byId.values());
  for (const device of devices) {
    for (const s of STANDARDS) {
      device.standards[s.key].scorePct = scorePctFromCounts(device.standards[s.key]);
    }
  }
  for (const s of STANDARDS) fleetStats[s.key].scorePct = scorePctFromCounts(fleetStats[s.key]);
  return {
    devices,
    fleetStats,
    fleetCheckSets,
    vendors: Array.from(vendors),
  };
}

// Active devices for the DeviceSelect dropdown (Cards view). Deliberately
// slim (id/name/vendor only) -- this is all DeviceSelect and the "which
// device is selected" resolution below need.
// ⛔ A SCORE WITHOUT A DATE IS A CLAIM ABOUT TODAY. Compliance runs inside
// collectAndStore, gated on `result.configCollected` — so a firewall that stops
// being collectable stops being audited and its findings simply freeze. Live
// 2026-09-22: TSR_EKC's score was 28 days old and TSR-TL's 10, rendered beside
// fourteen ~12-hour-old ones with nothing to tell them apart.
//
// ⛔ IT NAMES THE DEVICES. "2 firewalls are behind" sends someone hunting
// through the table; naming them is the difference between a warning and a
// chore. And it says the score is still REAL evidence about an OLD config,
// because wording it as garbage pushes people to ignore the page rather than
// fix the collection.
function freshnessBanner(devices) {
  // ⛔ Graded on configCollectedAt, not lastRunAt -- an evaluation cannot be
  // more current than the configuration it read.
  const f = summariseFreshness(
    devices.map((d) => ({ deviceName: d.deviceName, lastRunAt: d.configCollectedAt })),
    new Date()
  );
  if (f.behind.length === 0) return null;
  const shown = f.behind.slice(0, 6).join(', ');
  const more = f.behind.length > 6 ? `, and ${f.behind.length - 6} more` : '';
  return (
    <div style={{
      margin: '0 0 var(--s4)',
      padding: '10px 12px',
      borderRadius: 'var(--radius-sm)',
      background: 'var(--tint-warn)',
      color: 'var(--tint-warn-fg)',
      fontSize: 'var(--text-sm)',
      lineHeight: 1.6,
    }}>
      <strong>{f.behind.length} of {f.total} firewalls were last collected some time ago</strong>
      {' — '}{shown}{more}. Compliance checks read the newest configuration on file, so these
      scores are real but describe those firewalls as they were then, not as they are now.
      Re-running the checks would only re-read the same old configuration — what needs fixing
      is the collection.
    </div>
  );
}

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

// One device: each check yields at most one finding, so the distinct-check
// count and the finding count coincide here. It is still computed as a SET,
// because the fleet path shares the same accumulator and the two must not
// answer the same question two ways.
function aggregateCheckSets(findings) {
  const sets = emptyCheckSets();
  for (const f of findings) accumulateCheckSets(sets, f.standards, f.checkSlug, f.status);
  return sets;
}

// ── Coverage rendering ────────────────────────────────────────────────────
//
// ⛔ Plain functions returning JSX, called imperatively, at module top level —
// never components defined inside a component (CLAUDE.md's React rule), the
// same pattern viewToggle() above and ComplianceMatrix's scoreChip() already
// use.

// The strength meter: how many checks the percentage rests on, in the product's
// existing HUELESS vocabulary. Filled pips are --unmeasured and empty ones are
// --hatch, because "how well do we know this" is a different axis from "how bad
// is it" — a green or red meter here would say the evidence grade is good or
// bad news, and it is neither. Nothing new is invented: --unmeasured, --hatch
// and the violet EvidenceMark are the three marks this product already uses for
// exactly this statement.
function coveragePips(coverage) {
  const pips = [];
  for (let i = 0; i < coverage.pipTotal; i += 1) {
    const on = i < coverage.pips;
    pips.push(
      <span
        key={i}
        style={{
          width: 13,
          height: 8,
          flex: 'none',
          borderRadius: 3,
          border: '1px solid var(--border)',
          background: on ? 'var(--unmeasured)' : 'var(--surface-subtle)',
          backgroundImage: on ? 'none' : 'var(--hatch)',
        }}
      />
    );
  }
  return (
    <span
      aria-hidden="true"
      title={`${coverage.gradeLabel}: ${coverage.answeredChecks === null ? 'an unknown number of' : coverage.answeredChecks} SecVault checks behind this figure`}
      style={{ display: 'inline-flex', gap: 3, alignItems: 'center', marginTop: 4 }}
    >
      {pips}
    </span>
  );
}

// ⛔ THE FIGURE MAY NEVER APPEAR NAKED. This sits in the same grid cell as the
// card whose percentage it qualifies, in the same reading motion — not in a
// footnote, not behind a tooltip, and not once at the top of the page for five
// different denominators. AnswerHeader's own coverage line established the
// rule; this applies it per standard.
function coverageStrip(coverage) {
  if (!coverage) return null;
  const evidence = coverageEvidence(coverage);
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: 'var(--s2)',
        padding: 'var(--s2) var(--s3)',
        fontSize: 'var(--text-xs)',
        lineHeight: 1.5,
        color: 'var(--text-muted)',
        borderLeft: '2px solid var(--unmeasured)',
        background: 'var(--surface-subtle)',
        borderRadius: 'var(--radius-sm)',
      }}
    >
      {coveragePips(coverage)}
      <span style={{ flex: '1 1 auto' }}>
        <b style={{ color: 'var(--unmeasured)', fontWeight: 600 }}>{coverage.gradeLabel}</b>
        {' · '}
        {coverage.headline}
        {coverage.detail ? '; ' : '. '}
        {coverage.detail}
        <span style={{ display: 'block', marginTop: 2 }}>{coverage.caveat}</span>
      </span>
      {evidence && <EvidenceMark evidence={evidence} subject={`${coverage.label} coverage`} />}
    </div>
  );
}

// The fleet table's version: five columns of bare percentages need their five
// denominators stated once, above the grid, because the column HEADER is the
// only place the standard is named there.
function coverageLegend(coverageByStandard) {
  return (
    <Card>
      <CardBody>
        <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
          What each column is computed over
        </div>
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 'var(--s3)' }}>
          {COVERAGE_CLAIM}
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 'var(--s3)' }}>
          {STANDARDS.map((s) => {
            const coverage = coverageByStandard[s.key];
            const evidence = coverage ? coverageEvidence(coverage) : null;
            return (
              <div key={s.key} style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--s2)' }}>
                {coverage && coveragePips(coverage)}
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                  <b style={{ color: 'var(--text-secondary)' }}>{s.label}</b>
                  {' — '}
                  {coverage ? coverage.cell : '—'}
                  {' library checks carry this mapping'}
                  <span style={{ display: 'block', color: 'var(--unmeasured)' }}>
                    {coverage ? coverage.gradeLabel : 'Evidence not known'}
                    {coverage && coverage.answeredChecks !== null
                      ? ` · ${coverage.answeredChecks} gradeable fleet-wide`
                      : ''}
                  </span>
                </span>
                {evidence && <EvidenceMark evidence={evidence} subject={`${s.label} coverage`} />}
              </div>
            );
          })}
        </div>
      </CardBody>
    </Card>
  );
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
        Compare firewalls
      </Link>
    </div>
  );
}

export default async function CompliancePage({ searchParams }) {
  const view = searchParams?.view === 'table' ? 'table' : 'cards';

  if (view === 'table') {
    const fleet = await getFleetCompliance(pool);
    const devices = fleet.devices;
    const library = await getCheckLibraryCoverage(pool, fleet.vendors);
    const fleetCoverage = buildCoverage({
      library,
      stats: fleet.fleetStats,
      checkSets: fleet.fleetCheckSets,
      scope: 'fleet',
      deviceCount: devices.length,
    });
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
        <PageHeader
          title="Compliance"
          subtitle="Compare PCI DSS, ISO 27001, CIS v8, NIST, and SANS scores across every active device. Switch to Cards to see one firewall's full donut breakdown."
          actions={
            <span style={{ display: 'flex', gap: 8 }}>
              <a href="/api/compliance/fleet?format=csv" className="btn btn-secondary">
                Export CSV
              </a>
              <a href="/api/compliance/report/pdf" className="btn btn-secondary">
                Download PDF Report
              </a>
            </span>
          }
        />
        {viewToggle(view)}
        {coverageLegend(fleetCoverage)}
        {freshnessBanner(devices)}
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
          subtitle="View one firewall's PCI DSS, ISO 27001, CIS v8, NIST, and SANS posture, or switch to Compare firewalls for a fleet-wide table."
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

  // ⛔ The denominator behind every donut below, computed against THIS
  // firewall's vendor — a check scoped to another vendor can never run here and
  // is stated as inapplicable rather than left to look like an unanswered
  // question. Best-effort: a failed library read leaves the coverage
  // statement reporting itself unread, never "0 of 45".
  const library = await getCheckLibraryCoverage(pool, [selected.vendor]);
  const coverage = buildCoverage({
    library,
    stats: standards,
    checkSets: aggregateCheckSets(findings),
    scope: 'device',
    deviceCount: 1,
  });

  // ⛔ Counted straight off the findings already fetched — no second query.
  // All four statuses are tallied, INCLUDING `na`, because the answer sentence
  // and the evidence drawer both need to say how many checks could not be asked
  // of this firewall at all. Dropping `na` here would silently rebuild the bug
  // the score already avoids: our inability to measure, invisible to the reader.
  const statusCounts = findings.reduce(
    (acc, f) => {
      if (Object.prototype.hasOwnProperty.call(acc, f.status)) acc[f.status] += 1;
      return acc;
    },
    { pass: 0, fail: 0, warning: 0, na: 0 }
  );
  const complianceAnswer = buildDeviceComplianceAnswer(statusCounts, selected.name);
  const complianceEvidence = deviceComplianceEvidence(statusCounts, selected.name);
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
            <Badge color="info" title={selected.vendor}>{vendorLabel(selected.vendor)}</Badge>
          </span>
        }
        actions={
          <a href={`/api/compliance/${selected.id}?format=csv`} className="btn btn-secondary">
            Export CSV
          </a>
        }
      />

      <AnswerHeader answer={complianceAnswer} evidence={complianceEvidence} />

      {viewToggle(view)}

      <DeviceSelect devices={activeDevices} selectedId={selected.id} />

      {zoneCheckIsNa && <ZoneClassificationBanner standards={zoneCheck.standards} deviceId={selected.id} />}

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
            // ⛔ The card and its coverage statement are ONE cell, deliberately.
            // The percentage and the number of checks it rests on have to be
            // read together or the figure goes back to standing alone.
            <div key={s.key} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
              <StandardCard
                standard={s}
                description={meta.description}
                referenceUrl={meta.referenceUrl}
                stats={standards[s.key]}
                failedChecks={failed.slice(0, 5)}
                failedChecksTotal={failed.length}
                viewMoreHref={`/compliance/${selected.id}/standards#${s.key}`}
                lastRunAt={lastRunAt}
              />
              {coverageStrip(coverage[s.key])}
            </div>
          );
        })}
      </div>
    </div>
  );
}
