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
// usage: --green for allowed (StatCard "Allowed Rules"), --red for denied
// AND for any_any (matches its severity=critical treatment elsewhere, e.g.
// SeverityBadge.js / the "Allowed Any-to-Any" StatCard), --text-muted for
// inactive AND log_disabled (matches the "Logging Disabled" StatCard's
// muted treatment), --blue for NAT (a neutral informational hue, following
// this app's medium/info convention -- see SeverityBadge.js).
const RULE_STAT_BARS = [
  { key: 'allowed', label: 'Allowed', varName: '--green', fallbackHex: '#16a34a' },
  { key: 'denied', label: 'Denied', varName: '--red', fallbackHex: '#dc2626' },
  { key: 'inactive', label: 'Inactive', varName: '--text-muted', fallbackHex: '#64748b' },
  { key: 'nat', label: 'NAT Enabled', varName: '--blue', fallbackHex: '#2563eb' },
  { key: 'any_any', label: 'Any-to-Any', varName: '--red', fallbackHex: '#dc2626' },
  { key: 'log_disabled', label: 'Logging Disabled', varName: '--text-muted', fallbackHex: '#64748b' },
];

// Reads the app's own CSS custom properties (app/globals.css) rather than
// hardcoding hex values a second time -- same pattern as
// FindingsBarChart.js's resolveSeverityColor(), with a hardcoded fallback
// for the SSR case where window/document don't exist yet.
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
                  borderRadius: 6,
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
