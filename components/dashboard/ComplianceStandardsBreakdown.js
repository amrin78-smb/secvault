import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import IconChip from '../ui/IconChip';
import { IconShield } from '../icons';
import { STANDARDS } from '../compliance/ComplianceMatrix';

export const dynamic = 'force-dynamic';

// Fleet compliance score per standard — the "which framework are we weakest
// against" view, which the single fleet-average ComplianceScoreWidget cannot
// answer.
//
// ⛔ STANDARDS is imported from ComplianceMatrix, never redeclared. A local
// copy is how the matrix ended up with 7 <col> elements for 8 columns; the
// list has five entries and every consumer must iterate the same five.
//
// ⛔ scorePct = 100 * pass / (pass + fail + warning), with `na` EXCLUDED from
// the denominator, and `null` (rendered as a dash) when nothing is measurable
// — never 0. This is the same formula as /api/compliance/fleet and
// /api/compliance/[deviceId]; the duplication is this app's established
// "server components query the DB directly" pattern, and ComplianceMatrix's
// own header comment documents it. A 0 here would report "nothing has been
// audited yet" as "you fail every control", which is the failed-read-as-a-
// measurement class CLAUDE.md now names as a Critical Rule.

function scorePctFrom(counts) {
  const denom = counts.pass + counts.fail + counts.warning;
  if (denom <= 0) return null;
  return Math.round((100 * counts.pass) / denom);
}

function toneFor(pct) {
  if (pct === null) return 'var(--text-muted)';
  if (pct >= 90) return 'var(--green)';
  if (pct >= 75) return 'var(--accent-teal)';
  if (pct >= 50) return 'var(--yellow)';
  return 'var(--red)';
}

async function getPerStandard(dbPool) {
  const { rows } = await dbPool.query(
    `SELECT af.status, ac.standards
       FROM audit_findings af
       JOIN audit_checks ac ON ac.id = af.check_id
       JOIN devices d ON d.id = af.device_id
      WHERE d.active = true`
  );

  const stats = {};
  for (const s of STANDARDS) {
    stats[s.key] = { pass: 0, fail: 0, warning: 0, na: 0 };
  }

  for (const row of rows) {
    const list = Array.isArray(row.standards) ? row.standards : [];
    for (const standard of list) {
      const bucket = stats[standard];
      // A standard present in the data but not in STANDARDS is curated-data
      // drift, not something to silently fold into another standard's score.
      if (!bucket) continue;
      if (row.status === 'pass') bucket.pass += 1;
      else if (row.status === 'fail') bucket.fail += 1;
      else if (row.status === 'warning') bucket.warning += 1;
      else if (row.status === 'na') bucket.na += 1;
    }
  }

  return STANDARDS.map((s) => ({
    key: s.key,
    label: s.label,
    counts: stats[s.key],
    scorePct: scorePctFrom(stats[s.key]),
  }));
}

export default async function ComplianceStandardsBreakdown() {
  const standards = await getPerStandard(pool);
  const anyMeasured = standards.some((s) => s.scorePct !== null);

  return (
    <Card>
      <CardHeader>
        <CardTitle style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <IconChip icon={IconShield} color="#4ade80" bg="rgba(74,222,128,0.20)" />
          Score by Standard (Fleet)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {!anyMeasured ? (
          <div style={{ fontSize: 'var(--text-base)', color: 'var(--text-muted)' }}>
            No compliance audit has run yet. Run one from a device&apos;s Compliance page.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {standards.map((s) => (
              <div key={s.key}>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'baseline',
                    gap: 8,
                    marginBottom: 3,
                  }}
                >
                  <span style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
                    {s.label}
                  </span>
                  <span
                    style={{
                      fontSize: 'var(--text-base)',
                      fontWeight: 700,
                      fontVariantNumeric: 'tabular-nums',
                      color: toneFor(s.scorePct),
                    }}
                  >
                    {/* Em-dash, never 0 — see this file's header. */}
                    {s.scorePct === null ? '—' : `${s.scorePct}%`}
                  </span>
                </div>
                <div
                  // Decorative: the number above is the accessible value.
                  aria-hidden="true"
                  style={{
                    height: 6,
                    borderRadius: 3,
                    background: 'var(--border)',
                    overflow: 'hidden',
                  }}
                >
                  <div
                    style={{
                      width: `${s.scorePct === null ? 0 : s.scorePct}%`,
                      height: '100%',
                      background: toneFor(s.scorePct),
                    }}
                  />
                </div>
                <div
                  style={{
                    marginTop: 2,
                    fontSize: 'var(--text-sm)',
                    color: 'var(--text-muted)',
                    fontVariantNumeric: 'tabular-nums',
                  }}
                >
                  {s.counts.pass} pass · {s.counts.fail} fail · {s.counts.warning} warning
                  {s.counts.na > 0 ? ` · ${s.counts.na} n/a (excluded)` : ''}
                </div>
              </div>
            ))}
            <div
              style={{
                marginTop: 4,
                paddingTop: 8,
                borderTop: '1px solid var(--border)',
                fontSize: 'var(--text-sm)',
              }}
            >
              <Link href="/compliance?view=table" style={{ color: 'var(--primary)' }}>
                Compare devices
              </Link>
            </div>
          </div>
        )}
      </CardBody>
    </Card>
  );
}
