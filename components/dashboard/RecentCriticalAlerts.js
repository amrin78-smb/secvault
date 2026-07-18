import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';
import CVEBadge from '../cve/CVEBadge';

// Dashboard widget: the most recent fleet-wide patch-now CVE assessments.
// Standalone, read-only, server component -- not wired into any page yet
// (a later assembly pass does that). Query mirrors app/api/events/route.js's
// fetchPatchNow() exactly: same JOINs, same `d.active = true` filter, and
// the same "open" definition (`caa.status IS NULL OR caa.status = 'new'` --
// only bare 'new'/unset counts as open, NOT 'acknowledged', per the
// 2026-07-18 bug-sweep fix documented there and in
// app/(dashboard)/alerts/page.js / app/api/notifications/summary/route.js).
// Copied intentionally, not reinvented -- this app's established
// "duplicated query, kept in step by inspection" convention (see CLAUDE.md's
// Fleet Alerts Page section).

function cvssBadgeColor(score) {
  if (score === null || score === undefined) return 'muted';
  const n = Number(score);
  if (Number.isNaN(n)) return 'muted';
  if (n >= 9) return 'danger';
  if (n >= 7) return 'warning';
  if (n >= 4) return 'info';
  return 'muted';
}

async function getRecentCriticalAlerts(dbPool, limit) {
  const { rows } = await dbPool.query(
    `SELECT dca.id, dca.device_id, d.name AS device_name, dca.advisory_id,
            a.cve_id, a.cvss_score, a.kev_listed, dca.assessed_at
     FROM device_cve_assessments dca
     JOIN advisories a ON a.id = dca.advisory_id
     JOIN devices d ON d.id = dca.device_id
     LEFT JOIN cve_assessment_acknowledgements caa
       ON caa.device_id = dca.device_id AND caa.advisory_id = dca.advisory_id
     WHERE dca.priority_band = 'patch_now'
       AND d.active = true
       AND (caa.status IS NULL OR caa.status = 'new')
     ORDER BY dca.assessed_at DESC
     LIMIT $1`,
    [limit]
  );
  return rows;
}

export default async function RecentCriticalAlerts({ limit = 5 }) {
  const items = await getRecentCriticalAlerts(pool, limit);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Critical Alerts</CardTitle>
      </CardHeader>
      <CardBody>
        {items.length === 0 ? (
          <EmptyState message="No urgent CVEs right now." />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {items.map((item) => (
              <Link
                key={item.id}
                href={`/alerts?type=patch_now&device_id=${item.device_id}`}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 12,
                  padding: '10px 12px',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border)',
                  color: 'inherit',
                  textDecoration: 'none',
                }}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
                  <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{item.cve_id}</span>
                  <span
                    style={{
                      fontSize: 'var(--text-sm)',
                      color: 'var(--text-muted)',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                    title={item.device_name}
                  >
                    {item.device_name}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                  <CVEBadge kevListed={item.kev_listed} />
                  <Badge color={cvssBadgeColor(item.cvss_score)}>
                    {item.cvss_score != null ? `CVSS ${item.cvss_score}` : 'CVSS —'}
                  </Badge>
                </div>
              </Link>
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
}
