import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import EmptyState from '../ui/EmptyState';
import StandardDonut from '../compliance/StandardDonut';
import { STANDARDS, STANDARD_META } from '../compliance/ComplianceMatrix';

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
  const findings = await getFindings(pool, deviceId);
  const standards = aggregateStandards(findings);

  const neverAudited = STANDARDS.every((s) => standards[s.key].total === 0);
  const overall = neverAudited ? null : computeOverallScore(standards);
  const zoneCheck = findings.find((f) => f.checkSlug === ZONE_DEPENDENT_CHECK_SLUG);
  const zoneCheckIsNa = Boolean(zoneCheck) && zoneCheck.status === 'na';

  return (
    <Card>
      <CardBody>
        <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16 }}>
          Compliance Overview
        </div>

        {neverAudited ? (
          <EmptyState message="This device has not been audited yet." />
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
                padding: '12px 16px',
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
            <Link href="/settings?tab=zones" style={{ fontWeight: 600, color: 'inherit', textDecoration: 'underline' }}>
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
