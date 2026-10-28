import Link from 'next/link';
import { pool } from '../../lib/db';
import Card from '../ui/Card';
import StatCard from '../ui/StatCard';
import EmptyState from '../ui/EmptyState';
import IconChip from '../ui/IconChip';
import { IconChart } from '../icons';
// ⛔ THE RAMP IS IMPORTED, NEVER RESTATED. severityRamp.js is the one place
// that maps a severity to a hue; this widget's tiles used to carry hand-written
// tokens and drifted off it twice (see the ⛔ on the tile list below).
import { SEVERITY_FILL } from '../analysis/severityRamp';

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
            <IconChip icon={IconChart} color="var(--tint-warn-fg)" bg="var(--tint-warn)" />
            Ruleset Overview
          </div>
          <EmptyState message="No rules collected yet — add a device and run a collect to see fleet-wide rule health." />
        </div>
      </Card>
    );
  }

  const findings = await getFleetFindingCounts(pool);

  // ⛔ THE FINDING TILES TAKE THEIR HUE FROM THE ENGINE'S OWN SEVERITY,
  // VIA THE SHARED RAMP. Nothing is hand-copied here any more: the key is the
  // severity lib/engines/ruleAnalysis.js writes for that finding_type, and the
  // colour comes from severityRamp.js's SEVERITY_FILL, which already holds the
  // semantic aliases. A hand-written token in this file is how the drift below
  // happened twice.
  //
  // ⛔ v2.202.0 MOVED "Unused" TO --sev-med AND ITS COMMENT CLAIMED ALL THREE
  // TILES NOW AGREED "with each other and with the engine". Both halves were
  // wrong. They agreed on HUE and not on TOKEN -- --sev-med IS var(--yellow),
  // so Shadow and Redundant rendered identically while sitting on the raw hue,
  // and moving the alias would have repainted one tile and left two behind with
  // no diff to explain it. And they did NOT agree with the engine: ruleAnalysis
  // files `shadow` at severity 'high', not 'medium' (line 658), so the comment
  // asserted a fact about the engine that the engine contradicts, and painting
  // shadow amber under-stated it by a whole band on the fleet's own dashboard.
  //
  // ⛔ THE GUARD COULD NOT SEE ANY OF IT, which is why it survived a release
  // looking straight at it. tests/designSystemRamp.test.js scanned
  // `<StatCard .../>` ELEMENTS for a literal label= and color=; these tiles are
  // an ARRAY rendered through .map(), so the scan matched nothing in this file
  // at all. It now reads object-literal tiles too -- see the "array-built tile"
  // case there.
  //
  // ⛔ A ZERO COUNT GETS NO HUE. "Colour means RISK", and zero findings of a
  // type is the absence of risk -- the same gate the /lifecycle tiles have
  // always had, and the one HeadlineStats' "Critical Alerts" was missing.
  const findingTile = (label, count, severity) => ({
    label,
    value: count,
    color: count > 0 ? SEVERITY_FILL[severity] : 'var(--text-muted)',
  });

  const tiles = [
    { label: 'Total Rules', value: totals.total, color: 'var(--text-primary)' },
    // ⛔ NO HUE ON "Enabled" (same call v2.202.0 made for "Devices" and
    // "Total Rules" on the Overview). A count of enabled rules is not a risk
    // measurement, and --green here was the severity vocabulary spent on
    // furniture -- one tile along from three that genuinely encode severity.
    // --text-primary is the neutral StatCard already falls back to.
    { label: 'Enabled', value: totals.enabled, color: 'var(--text-primary)' },
    { label: 'Disabled', value: totals.disabled, color: 'var(--text-muted)' },
    findingTile('Unused', findings.unused, 'medium'),
    findingTile('Shadow', findings.shadow, 'high'),
    findingTile('Redundant', findings.redundant, 'medium'),
    findingTile('Any-Any', findings.any_any, 'critical'),
  ];

  return (
    <Card>
      <div className="card-body-compact">
        <div style={{ ...headingStyle, display: 'flex', alignItems: 'center', gap: 8 }}>
          <IconChip icon={IconChart} color="var(--tint-warn-fg)" bg="var(--tint-warn)" />
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
