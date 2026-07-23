import Link from 'next/link';
import { pool } from '../../lib/db';
import Card from '../ui/Card';
import StatCard from '../ui/StatCard';
import EmptyState from '../ui/EmptyState';
import IconChip from '../ui/IconChip';
import { IconChart } from '../icons';

// Fleet-wide rule totals (active devices only) -- mirrors the same
// `JOIN devices d ON d.id = fr.device_id WHERE d.active = true` filter used
// by app/api/analysis/fleet/route.js and app/(dashboard)/analysis/page.js.
async function getFleetRuleTotals(dbPool) {
  const { rows } = await dbPool.query(
    `SELECT COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE fr.enabled = true)::int AS enabled,
            COUNT(*) FILTER (WHERE fr.enabled = false)::int AS disabled
     FROM firewall_rules fr
     JOIN devices d ON d.id = fr.device_id
     WHERE d.active = true`
  );
  return rows[0];
}

// Fleet-wide finding-type counts (active devices only), for the 4 categories
// this widget surfaces. NOT mutually exclusive -- a single rule can carry
// more than one finding type at once (e.g. both `unused` AND `shadow`), so
// these 4 numbers do not partition `total` and must never be rendered as
// slices of one pie/donut (see the render below for how this is kept honest).
async function getFleetFindingCounts(dbPool) {
  const { rows } = await dbPool.query(
    `SELECT
       COUNT(*) FILTER (WHERE rar.finding_type = 'unused')::int AS unused,
       COUNT(*) FILTER (WHERE rar.finding_type = 'shadow')::int AS shadow,
       COUNT(*) FILTER (WHERE rar.finding_type = 'redundant')::int AS redundant,
       COUNT(*) FILTER (WHERE rar.finding_type = 'any_any')::int AS any_any
     FROM rule_analysis_results rar
     JOIN devices d ON d.id = rar.device_id
     WHERE d.active = true`
  );
  return rows[0];
}

const headingStyle = {
  fontSize: 'var(--text-xs)',
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
  color: 'var(--text-muted)',
  marginBottom: 4,
};

const subtextStyle = {
  fontSize: 10,
  color: 'var(--text-muted)',
  marginBottom: 8,
  lineHeight: 1.35,
};

// Fleet-wide "Ruleset Overview" widget (ManageEngine-style concept), rebuilt
// as absolute StatCard tiles rather than a donut/pie -- unlike VPN/CVE-
// severity breakdowns elsewhere in this app, `unused`/`shadow`/`redundant`/
// `any_any` findings are NOT a partition of the total ruleset (one rule can
// carry several finding types simultaneously), so a "percentage of whole"
// chart would misrepresent the data. Plain StatCard tiles with an explicit
// non-partition disclaimer is the honest choice CLAUDE.md's dashboard
// conventions favor over a misleading donut.
export default async function RulesetOverview() {
  const totals = await getFleetRuleTotals(pool);

  if (!totals || totals.total === 0) {
    return (
      <Card>
        <div className="card-body-compact">
          <div style={{ ...headingStyle, display: 'flex', alignItems: 'center', gap: 8 }}>
            <IconChip icon={IconChart} color="#fbbf24" bg="rgba(251,191,36,0.20)" />
            Ruleset Overview
          </div>
          <EmptyState message="No rules collected yet — add a device and run a collect to see fleet-wide rule health." />
        </div>
      </Card>
    );
  }

  const findings = await getFleetFindingCounts(pool);

  const tiles = [
    { label: 'Total Rules', value: totals.total, color: 'var(--text-primary)' },
    { label: 'Enabled', value: totals.enabled, color: 'var(--green)' },
    { label: 'Disabled', value: totals.disabled, color: 'var(--text-muted)' },
    { label: 'Unused', value: findings.unused, color: findings.unused > 0 ? 'var(--blue)' : 'var(--text-muted)' },
    { label: 'Shadow', value: findings.shadow, color: findings.shadow > 0 ? 'var(--yellow)' : 'var(--text-muted)' },
    {
      label: 'Redundant',
      value: findings.redundant,
      color: findings.redundant > 0 ? 'var(--yellow)' : 'var(--text-muted)',
    },
    { label: 'Any-Any', value: findings.any_any, color: findings.any_any > 0 ? 'var(--red)' : 'var(--text-muted)' },
  ];

  return (
    <Card>
      <div className="card-body-compact">
        <div style={{ ...headingStyle, display: 'flex', alignItems: 'center', gap: 8 }}>
          <IconChip icon={IconChart} color="#fbbf24" bg="rgba(251,191,36,0.20)" />
          Ruleset Overview
        </div>
        <div style={subtextStyle}>
          Fleet-wide rule counts. A rule can carry more than one finding type at once, so
          Unused/Shadow/Redundant/Any-Any won&apos;t sum to Total.
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(90px, 1fr))', gap: 8 }}>
          {tiles.map((t) => (
            <Link key={t.label} href="/analysis" style={{ textDecoration: 'none' }}>
              <StatCard label={t.label} value={t.value} color={t.color} compact />
            </Link>
          ))}
        </div>
      </div>
    </Card>
  );
}
