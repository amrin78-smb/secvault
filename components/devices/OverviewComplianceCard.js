import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import EmptyState from '../ui/EmptyState';
import StandardDonut from '../compliance/StandardDonut';
import { STANDARDS, STANDARD_META, DeviceCoverageStrip } from '../compliance/ComplianceMatrix';
import { buildDeviceCoverage } from '../../lib/engines/complianceCoverage';
import { vendorLabel } from './vendorMeta';

// Overview-tab card: a CONDENSED version of the already-built per-device
// Compliance page (app/(dashboard)/compliance/[deviceId]/page.js) — same
// "widget owns its DB access" convention as the other Overview cards
// (OverviewCveCard.js, OverviewConfigChangesCard.js). Deliberately does NOT
// duplicate that page's full StandardCard (failed-checks lists, description
// blurbs, reference links) — this needs to fit as one card among several on
// a tab, not a whole page. Reuses StandardDonut directly rather than
// building a second gauge.
//
// Query/aggregation logic mirrored EXACTLY from
// compliance/[deviceId]/page.js's own getFindings()/aggregateStandards()/
// scorePctFromCounts() (same tri-state-honesty rule documented in CLAUDE.md
// under "Compliance Engine (Phase 7)": scorePct = round(100 * pass /
// (pass+fail+warning)), 'na' excluded from the denominator, null — never 0
// — when nothing is measurable for that standard). Not imported from that
// page (it has no exports) — duplicated per this app's established
// per-file-duplication convention for small per-page query/aggregation
// logic (see CLAUDE.md's Alerts/Compliance query-triplication notes).
//
// ⚠️ Previously this card deliberately rendered NO single blended "overall
// compliance score" — that concept didn't exist anywhere else in this app
// (only independent per-standard scores). A real, user-decided product
// change now adds one below: a simple, unweighted average of whichever
// standards currently have a real (non-null) scorePct, computed by
// computeOverallScore(). This was a deliberate decision made BY the user
// (not invented here) — see that function's own comment for the exact rule.

function scorePctFromCounts(counts) {
  const measurable = counts.pass + counts.fail + counts.warning;
  return measurable > 0 ? Math.round((counts.pass / measurable) * 100) : null;
}

// User-decided aggregation (2026-07-21): a simple, unweighted average across
// whichever standards currently have a real (non-null) scorePct. A standard
// that's null (never audited against, or nothing measurable — see
// scorePctFromCounts() above) is EXCLUDED from the average entirely, never
// treated as 0 and never blocking the average for the others. If every
// standard is null, the overall score is null too ("—", not a fabricated
// number) — reuses the same neverAudited signal the rest of this card
// already computes, rather than re-deriving it here.
function computeOverallScore(standards) {
  const scores = STANDARDS.map((s) => standards[s.key].scorePct).filter(
    (pct) => pct !== null && pct !== undefined
  );
  if (scores.length === 0) return null;
  return {
    scorePct: Math.round(scores.reduce((sum, pct) => sum + pct, 0) / scores.length),
    auditedCount: scores.length,
  };
}

async function getFindings(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT ac.check_id AS check_slug, ac.standards, af.status
     FROM audit_findings af
     JOIN audit_checks ac ON ac.id = af.check_id
     WHERE af.device_id = $1`,
    [deviceId]
  );
  return result.rows.map((r) => ({
    checkSlug: r.check_slug,
    standards: Array.isArray(r.standards) ? r.standards : [],
    status: r.status,
  }));
}

// ⛔ THE DENOMINATOR BEHIND THIS CARD'S SIX DONUTS, AND IT HAD NO READER HERE
// AT ALL — WHILE THE PAGE ONE CLICK AWAY HAS CARRIED IT SINCE v2.225.0.
//
// This card drew a 96px blended donut plus six per-standard donuts and said
// nothing about how many checks any of them rest on, although that number is a
// property of the VENDOR rather than of the firewall. Measured on the
// secvault_mock fleet (74-check library, 2026-11-15): MOCK-SANGFOR-Branch-06
// scores on 9 gradeable checks of 19 applicable and is the HIGHEST-scoring
// firewall on the fleet, while MOCK-CP-Perimeter-04 and MOCK-FP-DC-07 score on
// 10 of 20 — the three vendors the library covers least. Opening this tab gave
// a bare percentage; clicking "View full report" gave the SAME assessment WITH
// a "thin" grade and "9 of 19" beside it, so the two screens disagreed about
// what the number was worth.
//
// ⛔ NOTHING IS RECOMPUTED AND NO SECOND GRADING SCALE IS INVENTED. The
// judgement is buildDeviceCoverage()'s, byte for byte the call
// app/(dashboard)/compliance/[deviceId]/page.js makes, so this card and that
// page can never report a different basis for the same firewall. The bands,
// the absolute-count rule and the inconsistent -> `unknown` degrade live beside
// DEVICE_GRADE_THIN_MAX in lib/engines/complianceCoverage.js; do not copy the
// numbers here.
//
// ⛔ A FAILED READ RETURNS null, never a zeroed map. "0 checks apply to this
// firewall" is a claim, and a false one — the strip then reports the basis as
// unread rather than as zero.
async function getApplicableCheckCount(dbPool, vendor) {
  if (!vendor) return null;
  try {
    const { rows } = await dbPool.query(
      `SELECT count(*)::int AS applicable,
              (SELECT count(*)::int FROM audit_checks) AS library_total
       FROM audit_checks WHERE vendor IS NULL OR vendor = $1`,
      [vendor]
    );
    if (rows.length === 0) return null;
    const applicable = Number(rows[0].applicable);
    const libraryTotal = Number(rows[0].library_total);
    if (!Number.isFinite(applicable) || !Number.isFinite(libraryTotal)) return null;
    return { applicable, libraryTotal };
  } catch (err) {
    console.warn(
      `[overview-compliance/${vendor}] applicable check count read failed, coverage will report as unread:`,
      err.message
    );
    return null;
  }
}

// The vendor is what decides the denominator, so it has to be read. ⛔ A failed
// read returns null and the coverage strip says the basis could not be
// established — it must never fall back to a vendor, because the applicable
// count of the WRONG vendor is a confident number that cannot be right.
async function getDeviceVendor(dbPool, deviceId) {
  try {
    const { rows } = await dbPool.query('SELECT name, vendor FROM devices WHERE id = $1', [deviceId]);
    return rows[0] || null;
  } catch (err) {
    console.warn(
      `[overview-compliance/${deviceId}] device read failed, coverage will report as unread:`,
      err.message
    );
    return null;
  }
}

// ⛔ DISTINCT CHECKS, NEVER THE PER-STANDARD ROWS SUMMED. `audit_checks.standards`
// is an ARRAY, so aggregateStandards() above counts one check once per standard
// it is mapped to — summing those five tallies gives 26 for a firewall with 20
// applicable checks. buildDeviceCoverage() catches that shape and degrades to
// `unknown`; the point of computing it here is not to hand it that at all.
function deviceCheckCounts(findings) {
  const evaluated = new Set();
  const answered = new Set();
  const statusCounts = { pass: 0, fail: 0, warning: 0, na: 0 };
  for (const f of findings) {
    if (Object.prototype.hasOwnProperty.call(statusCounts, f.status)) statusCounts[f.status] += 1;
    if (!f.checkSlug) continue;
    evaluated.add(f.checkSlug);
    if (f.status && f.status !== 'na') answered.add(f.checkSlug);
  }
  return { evaluated: evaluated.size, answered: answered.size, statusCounts };
}

// Same zone-dependent check slug as the full Compliance page's own
// ZONE_DEPENDENT_CHECK_SLUG constant. This condensed card shows a small
// inline note instead of the full ZoneClassificationBanner (no room for a
// whole banner box among several Overview-tab cards) -- see that
// component's own header comment for the full reasoning.
const ZONE_DEPENDENT_CHECK_SLUG = 'rule-no-external-to-internal-access';

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

export default async function OverviewComplianceCard({ deviceId }) {
  const [findings, device] = await Promise.all([
    getFindings(pool, deviceId),
    getDeviceVendor(pool, deviceId),
  ]);
  const standards = aggregateStandards(findings);

  const neverAudited = STANDARDS.every((s) => standards[s.key].total === 0);
  const overall = neverAudited ? null : computeOverallScore(standards);
  const zoneCheck = findings.find((f) => f.checkSlug === ZONE_DEPENDENT_CHECK_SLUG);
  const zoneCheckIsNa = Boolean(zoneCheck) && zoneCheck.status === 'na';

  const counts = deviceCheckCounts(findings);
  const library = await getApplicableCheckCount(pool, device ? device.vendor : null);
  // ⛔ `scorePct` IS THE FIGURE ACTUALLY ON THIS CARD — the blended average, not
  // the device-wide pass/(pass+fail+warning) the per-device page qualifies.
  // Measured on secvault_mock: those two disagree by 9 points on
  // MOCK-SANGFOR-Branch-06 (blend 87%, device-wide 78%), so handing the strip
  // the device-wide figure would put a SECOND, different percentage on the same
  // screen as the donut — the one thing CLAUDE.md forbids a coverage statement
  // from doing. Passing the figure that is on screen makes the strip restate
  // ONE number with its denominator instead. ⛔ null exactly when `overall` is
  // null, which is exactly when nothing is gradeable — the state the engine
  // reads a null `scorePct` as.
  const deviceCoverage = buildDeviceCoverage({
    deviceId,
    deviceName: device ? device.name : null,
    vendor: device ? device.vendor : null,
    vendorLabel: device && device.vendor ? vendorLabel(device.vendor) : null,
    libraryTotal: library ? library.libraryTotal : null,
    applicable: library ? library.applicable : null,
    evaluatedChecks: counts.evaluated,
    answeredChecks: counts.answered,
    findings: counts.statusCounts,
    scorePct: overall ? overall.scorePct : null,
  });

  return (
    <Card>
      <CardBody>
        <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16 }}>
          Compliance Overview
        </div>

        {/* ⛔ ABOVE the donuts, not under them, and in BOTH branches: how many
            checks this firewall could be asked at all qualifies every
            percentage below, and the figure may never be read before its
            basis. In the never-audited branch it is the more informative of
            the two lines — the EmptyState says no audit has run, this says how
            many checks there would be to run. */}
        <div style={{ marginBottom: 16 }}>
          <DeviceCoverageStrip coverage={deviceCoverage} />
        </div>

        {neverAudited ? (
          <EmptyState
            message={
              'No compliance audit has run for this device, so every standard is unscored rather than scored zero. ' +
              'Checks are evaluated against a collected configuration — run Collect Now on the Manage tab, then an audit.'
            }
          />
        ) : (
          <>
            {/* Overall blended score — visually distinct (bordered panel, larger
                donut) from the per-standard grid below so it reads as ONE derived
                summary number, not a 6th independent standard sitting alongside
                real ones. */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 16,
                // Spacing scale, not a literal pair (--s3/--s4 are 12/16px).
                padding: 'var(--s3) var(--s4)',
                marginBottom: 16,
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                background: 'var(--bg-primary)',
              }}
            >
              <StandardDonut pct={overall ? overall.scorePct : null} size={96} />
              <div>
                <div style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Compliance Score
                </div>
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>
                  {overall
                    ? `Average of ${overall.auditedCount} audited standard${overall.auditedCount === 1 ? '' : 's'}`
                    : 'No standard currently has a measurable score'}
                </div>
              </div>
            </div>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(90px, 1fr))',
                gap: 12,
                justifyItems: 'center',
                textAlign: 'center',
              }}
            >
            {STANDARDS.map((s) => {
              const meta = STANDARD_META[s.key] || {};
              return (
                <div key={s.key} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
                  <StandardDonut pct={standards[s.key].scorePct} size={64} />
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', fontWeight: 600 }} title={meta.description}>
                    {s.label}
                  </div>
                </div>
              );
            })}
            </div>
          </>
        )}

        {zoneCheckIsNa && (
          <div style={{ marginTop: 12, fontSize: 'var(--text-xs)', color: 'var(--tint-warn-fg)' }}>
            Zones not classified — the External-to-Internal check is excluded.{' '}
            <Link href={`/devices/${deviceId}?tab=manage`} style={{ fontWeight: 600, color: 'inherit', textDecoration: 'underline' }}>
              Classify →
            </Link>
          </div>
        )}

        <div style={{ marginTop: 16 }}>
          <Link href={`/compliance/${deviceId}`} style={{ fontSize: 'var(--text-base)', color: 'var(--primary)', textDecoration: 'underline' }}>
            View full report →
          </Link>
        </div>
      </CardBody>
    </Card>
  );
}
