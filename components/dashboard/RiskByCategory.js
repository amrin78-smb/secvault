import { pool } from '../../lib/db';
import Card from '../ui/Card';
import EmptyState from '../ui/EmptyState';
import IconChip from '../ui/IconChip';
import { IconGrid } from '../icons';
import { CATEGORIES } from '../../lib/engines/vulnerabilityCategory';

// Dashboard widget: fleet-wide count of assessed CVEs (active devices only)
// grouped by advisories.vulnerability_category. Async server component --
// does its own pool.query, same "server components query the DB directly"
// convention as RiskTab.js/CleanupTab.js/etc. Do not add 'use client' --
// plain CSS width-percentage bars need no client interactivity.

// Fixed display order, imported from vulnerabilityCategory.js's own
// CATEGORIES export rather than re-derived from whatever GROUP BY happens to
// return -- a category with 0 count still renders as a zero-width row, never
// hidden, so the widget's totals are always honest/complete at a glance.
const CATEGORY_ORDER = [
  CATEGORIES.RCE,
  CATEGORIES.PRIV_ESC,
  CATEGORIES.INFO_DISCLOSURE,
  CATEGORIES.DOS,
  CATEGORIES.OTHER,
];

// One color per category -- raw status hues, NOT the --sev-* aliases, because
// these are CWE CLASSES (what kind of vulnerability) rather than points on the
// severity ramp. --blue is safe here for exactly that reason: the 2026-09-09
// palette rewrite pulled blue out of the severity ramp entirely, which is what
// frees it for non-severity categories like this one.
//
// The tokens go straight into the inline style. (This file never had the
// getComputedStyle resolver the charts carried; that machinery is now deleted
// there too -- see components/analysis/chartGrammar.js's header for why it was
// a bug rather than a style preference.)
const CATEGORY_COLOR = {
  [CATEGORIES.RCE]: 'var(--red)',
  [CATEGORIES.PRIV_ESC]: 'var(--orange)',
  [CATEGORIES.INFO_DISCLOSURE]: 'var(--blue)',
  [CATEGORIES.DOS]: 'var(--purple)',
  [CATEGORIES.OTHER]: 'var(--text-muted)',
};

async function getCategoryCounts(dbPool) {
  const result = await dbPool.query(
    `SELECT COALESCE(a.vulnerability_category, 'Other') AS category, COUNT(*)::int AS count
     FROM device_cve_assessments dca
     JOIN advisories a ON a.id = dca.advisory_id
     JOIN devices d ON d.id = dca.device_id
     WHERE d.active = true
     GROUP BY category`
  );
  return result.rows;
}

export default async function RiskByCategory() {
  const rows = await getCategoryCounts(pool);

  const countByCategory = {};
  for (const row of rows) {
    countByCategory[row.category] = row.count;
  }
  const total = CATEGORY_ORDER.reduce((sum, c) => sum + (countByCategory[c] || 0), 0);
  const maxCount = Math.max(1, ...CATEGORY_ORDER.map((c) => countByCategory[c] || 0));

  return (
    <Card>
      <div className="card-body-compact">
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            fontSize: 'var(--text-xs)',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            color: 'var(--text-muted)',
          }}
        >
          <IconChip icon={IconGrid} color="var(--tint-danger-fg)" bg="var(--tint-danger)" />
          Risk by Category
        </div>
        <div style={{ marginTop: 2, marginBottom: 8, fontSize: 10, color: 'var(--text-muted)' }}>
          Derived from each CVE&apos;s CWE classification; uncategorized CVEs land under &quot;Other&quot;.
        </div>

        {total === 0 ? (
          <EmptyState message="No assessed CVEs for active devices yet." />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {CATEGORY_ORDER.map((category) => {
              const count = countByCategory[category] || 0;
              const widthPct = count === 0 ? 0 : Math.max(2, Math.round((count / maxCount) * 100));
              return (
                <div key={category}>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      fontSize: 'var(--text-xs)',
                      color: 'var(--text-secondary)',
                      marginBottom: 2,
                    }}
                  >
                    <span>{category}</span>
                    <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{count}</span>
                  </div>
                  <div
                    style={{
                      height: 6,
                      borderRadius: 'var(--radius-pill)',
                      background: 'var(--bg-primary)',
                      border: '1px solid var(--border)',
                      overflow: 'hidden',
                    }}
                  >
                    <div
                      style={{
                        height: '100%',
                        width: `${widthPct}%`,
                        background: CATEGORY_COLOR[category] || 'var(--text-muted)',
                        borderRadius: 'var(--radius-pill)',
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </Card>
  );
}
