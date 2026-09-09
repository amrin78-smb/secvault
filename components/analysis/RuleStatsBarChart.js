'use client';

import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import Card, { CardBody } from '../ui/Card';
import {
  GRID_PROPS,
  X_AXIS_PROPS,
  COUNT_AXIS_PROPS,
  TOOLTIP_CURSOR_BAR,
  ChartTooltip,
  ChartNotMeasured,
  CHART_HEADING_STYLE,
} from './chartGrammar';

// Rule-COMPOSITION stats (distinct from FindingsBarChart.js's finding-TYPE
// stats) -- a mix of firewall_rules-derived counts (ruleStats) and two
// finding-type counts (findingTypeCounts) that are already surfaced as their
// own StatCards on the Summary tab (see devices/[id]/analysis/page.js).
// "Total Rules" is deliberately NOT a bar here -- it would dwarf every other
// bar on the same linear scale and isn't a meaningful comparison item; it
// already has its own StatCard elsewhere on the page.
//
// Colours are semantic: --green for allowed and --red for denied (the firewall
// allow/deny convention; these are COMPOSITION categories, not severities,
// hence the raw hues rather than the --sev-* aliases), --text-muted for
// inactive AND log_disabled (matches the "Logging Disabled" StatCard's muted
// treatment), --blue for NAT (a neutral informational hue -- and blue is no
// longer part of the severity ramp at all after the 2026-09-09 palette
// rewrite, which is exactly what makes it safe for a non-severity category
// here).
//
// any_any is the ONE bar that is a severity rather than a composition
// category -- it is a critical finding count (matching its severity=critical
// treatment elsewhere, e.g. SeverityBadge.js / the "Allowed Any-to-Any"
// StatCard) -- so it uses the semantic --sev-crit alias. Same hue as --red
// today; the alias is what keeps it correct if the ramp ever moves.
//
// ⛔ The token strings go STRAIGHT into recharts. The getComputedStyle-based
// resolveColor()/fallbackHex pair that used to live here is deleted — see the
// header of chartGrammar.js for the two bugs it caused.
const RULE_STAT_BARS = [
  { key: 'allowed', label: 'Allowed', color: 'var(--green)' },
  { key: 'denied', label: 'Denied', color: 'var(--red)' },
  { key: 'inactive', label: 'Inactive', color: 'var(--text-muted)' },
  { key: 'nat', label: 'NAT Enabled', color: 'var(--blue)' },
  { key: 'any_any', label: 'Any-to-Any', color: 'var(--sev-crit)' },
  { key: 'log_disabled', label: 'Logging Disabled', color: 'var(--text-muted)' },
];

/**
 * @param {{total_rules, allowed_count, denied_count, inactive_count, nat_count}} ruleStats
 * @param {{any_any: number, log_disabled: number}} findingTypeCounts
 */
export default function RuleStatsBarChart({ ruleStats, findingTypeCounts }) {
  const counts = {
    allowed: (ruleStats && ruleStats.allowed_count) || 0,
    denied: (ruleStats && ruleStats.denied_count) || 0,
    inactive: (ruleStats && ruleStats.inactive_count) || 0,
    nat: (ruleStats && ruleStats.nat_count) || 0,
    any_any: (findingTypeCounts && findingTypeCounts.any_any) || 0,
    log_disabled: (findingTypeCounts && findingTypeCounts.log_disabled) || 0,
  };

  const data = RULE_STAT_BARS.map((b) => ({ ...b, count: counts[b.key] }));

  // ⛔ FAILED READ RENDERED AS A VALUE. With no ruleset collected, every one of
  // these six numbers is 0 and the chart draws six zero-height bars against a
  // full axis and grid — indistinguishable from a firewall that genuinely has
  // zero allow rules, zero deny rules and zero NAT. It is the same class as
  // hit_count's old NOT NULL DEFAULT 0: our failure to collect, rendered as a
  // fact about the device.
  //
  // total_rules === 0 is the honest discriminator and it is safe to lean on:
  // per CLAUDE.md's adapter contract, getRules() THROWS on a retrieval failure
  // rather than returning [], so collectAndStore never wipes a ruleset it
  // failed to read. Zero rows here therefore means "nothing has been collected
  // for this device", not "the pull silently failed".
  const noRuleset = !ruleStats || !(Number(ruleStats.total_rules) > 0);

  return (
    <Card>
      <CardBody>
        <div style={CHART_HEADING_STYLE}>Rule Composition</div>
        {noRuleset ? (
          <ChartNotMeasured reason="No ruleset has been collected for this device yet — its rule composition is unmeasured, not empty." />
        ) : (
          <div style={{ width: '100%', height: 260 }}>
            <ResponsiveContainer>
              <BarChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
                <CartesianGrid {...GRID_PROPS} />
                <XAxis
                  {...X_AXIS_PROPS}
                  dataKey="label"
                  interval={0}
                  angle={-20}
                  textAnchor="end"
                  height={50}
                />
                <YAxis {...COUNT_AXIS_PROPS} width={28} />
                {/* Single series: no Legend — the card heading already names it. */}
                <Tooltip cursor={TOOLTIP_CURSOR_BAR} content={<ChartTooltip />} />
                <Bar dataKey="count" name="Rules" radius={[3, 3, 0, 0]} maxBarSize={40}>
                  {data.map((entry) => (
                    <Cell key={entry.key} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardBody>
    </Card>
  );
}
