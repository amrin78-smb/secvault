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
// Deliberately renders NO single blended "overall compliance score" number
// — that concept does not exist anywhere else in this app (only independent
// per-standard scores), so this card doesn't invent one either.

function scorePctFromCounts(counts) {
  const measurable = counts.pass + counts.fail + counts.warning;
  return measurable > 0 ? Math.round((counts.pass / measurable) * 100) : null;
}

async function getFindings(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT ac.standards, af.status
     FROM audit_findings af
     JOIN audit_checks ac ON ac.id = af.check_id
     WHERE af.device_id = $1`,
    [deviceId]
  );
  return result.rows.map((r) => ({
    standards: Array.isArray(r.standards) ? r.standards : [],
    status: r.status,
  }));
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

export default async function OverviewComplianceCard({ deviceId }) {
  const findings = await getFindings(pool, deviceId);
  const standards = aggregateStandards(findings);

  const neverAudited = STANDARDS.every((s) => standards[s.key].total === 0);

  return (
    <Card>
      <CardBody>
        <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16 }}>
          Compliance Overview
        </div>

        {neverAudited ? (
          <EmptyState message="This device has not been audited yet." />
        ) : (
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
