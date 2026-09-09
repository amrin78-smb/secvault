'use client';

import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import Card, { CardBody } from '../ui/Card';

// Rule-COMPOSITION stats (distinct from FindingsBarChart.js's finding-TYPE
// stats) -- a mix of firewall_rules-derived counts (ruleStats) and two
// finding-type counts (findingTypeCounts) that are already surfaced as their
// own StatCards on the Summary tab (see devices/[id]/analysis/page.js).
// "Total Rules" is deliberately NOT a bar here -- it would dwarf every other
// bar on the same linear scale and isn't a meaningful comparison item; it
// already has its own StatCard elsewhere on the page.
//
// `varName` points at the CSS custom property that carries this bar's
// intended semantic color -- resolved from app/globals.css at render time
// (see resolveColor() below), matching this app's existing semantic color
// usage: --green for allowed and --red for denied (the firewall allow/deny
// convention; these are COMPOSITION categories, not severities, hence the raw
// hues rather than the --sev-* aliases), --text-muted for inactive AND
// log_disabled (matches the "Logging Disabled" StatCard's muted treatment),
// --blue for NAT (a neutral informational hue -- and blue is no longer part
// of the severity ramp at all after the 2026-09-09 palette rewrite, which is
// exactly what makes it safe for a non-severity category here).
//
// any_any is the ONE bar that is a severity rather than a composition
// category -- it is a critical finding count (matching its severity=critical
// treatment elsewhere, e.g. SeverityBadge.js / the "Allowed Any-to-Any"
// StatCard) -- so it uses the semantic --sev-crit alias. Same hue as --red
// today; the alias is what keeps it correct if the ramp ever moves.
//
// The fallback values are TOKEN REFERENCES, not hex (changed 2026-09-09 with
// the palette rewrite). Literal hex here meant the SSR pass painted the OLD
// palette regardless of app/globals.css; `var(--x)` is a valid SVG `fill`
// presentation-attribute value, so the browser resolves it against the live
// theme on that pass too.
const RULE_STAT_BARS = [
  { key: 'allowed', label: 'Allowed', varName: '--green', fallbackHex: 'var(--green)' },
  { key: 'denied', label: 'Denied', varName: '--red', fallbackHex: 'var(--red)' },
  { key: 'inactive', label: 'Inactive', varName: '--text-muted', fallbackHex: 'var(--text-muted)' },
  { key: 'nat', label: 'NAT Enabled', varName: '--blue', fallbackHex: 'var(--blue)' },
  { key: 'any_any', label: 'Any-to-Any', varName: '--sev-crit', fallbackHex: 'var(--sev-crit)' },
  { key: 'log_disabled', label: 'Logging Disabled', varName: '--text-muted', fallbackHex: 'var(--text-muted)' },
];

// Reads the app's own CSS custom properties (app/globals.css) rather than
// hardcoding color values a second time -- same pattern as
// FindingsBarChart.js's resolveSeverityColor(), with a fallback for the SSR
// case where window/document don't exist yet.
function resolveColor(varName, fallbackHex) {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return fallbackHex;
  }
  const value = getComputedStyle(document.documentElement).getPropertyValue(varName);
  return value ? value.trim() : fallbackHex;
}

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

  const data = RULE_STAT_BARS.map((b) => ({
    ...b,
    count: counts[b.key],
    color: resolveColor(b.varName, b.fallbackHex),
  }));

  return (
    <Card>
      <CardBody>
        <div
          style={{
            marginBottom: 12,
            fontSize: 'var(--text-xs)',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            color: 'var(--text-muted)',
          }}
        >
          Rule Composition
        </div>
        <div style={{ width: '100%', height: 260 }}>
          <ResponsiveContainer>
            <BarChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
              <XAxis
                dataKey="label"
                tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
                axisLine={{ stroke: 'var(--border)' }}
                tickLine={false}
                interval={0}
                angle={-20}
                textAnchor="end"
                height={50}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
                axisLine={{ stroke: 'var(--border)' }}
                tickLine={false}
                width={28}
              />
              <Tooltip
                cursor={{ fill: 'var(--bg-card)' }}
                contentStyle={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: 12,
                }}
                labelStyle={{ color: 'var(--text-primary)' }}
                itemStyle={{ color: 'var(--text-primary)' }}
              />
              <Bar dataKey="count" radius={[3, 3, 0, 0]} maxBarSize={40}>
                {data.map((entry) => (
                  <Cell key={entry.key} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardBody>
    </Card>
  );
}
