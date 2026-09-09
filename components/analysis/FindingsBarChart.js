'use client';

import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import Card, { CardBody } from '../ui/Card';

// The finding types in the fixed severity order CLAUDE.md documents for the
// rule analysis engine (lib/engines/ruleAnalysis.js), each mapped to the
// severity it's always emitted at -- used to color bars the same way
// SeverityBadge.js colors severity pills, so this chart and that badge always
// agree on what "critical" looks like.
const FINDING_TYPE_ORDER = [
  { type: 'any_any', label: 'Any-Any', severity: 'critical' },
  { type: 'risky_service', label: 'Risky Svc', severity: 'high' },
  { type: 'shadow', label: 'Shadow', severity: 'high' },
  { type: 'reorder_candidate', label: 'Reorder', severity: 'high' },
  { type: 'redundant', label: 'Redundant', severity: 'medium' },
  { type: 'correlation', label: 'Correlation', severity: 'medium' },
  { type: 'overly_permissive', label: 'Overly Perm.', severity: 'medium' },
  { type: 'unused', label: 'Unused', severity: 'medium' },
  { type: 'expiring_soon', label: 'Expiring', severity: 'medium' },
  { type: 'generalization', label: 'Generalization', severity: 'medium' },
  { type: 'external_exposure', label: 'Ext. Exposure', severity: 'medium' },
  { type: 'log_disabled', label: 'Log Off', severity: 'info' },
];

// Reads the app's own CSS custom properties (app/globals.css) rather than
// hardcoding color values a second time -- stays correct if the palette ever
// changes, and automatically matches SeverityBadge/StatusDot/etc. Read at
// render time in a browser context (useEffect-free: getComputedStyle on
// document.documentElement is synchronous and cheap for 4 lookups), with a
// fallback for the (never-expected-in-practice) case of SSR-time evaluation
// before hydration.
//
// ⛔ These are the palette's SEMANTIC SEVERITY ALIASES (--sev-*), not raw hues
// (changed 2026-09-09 with the palette rewrite). Every bar here IS a severity,
// which is exactly what those aliases exist to say, so a future ramp change is
// one edit in app/globals.css rather than a hunt through the charts.
//
// ⛔ medium used to be --blue and that is now FORBIDDEN, not merely
// discouraged: the rewritten palette pulled blue OUT of the severity ramp
// (low severity is slate) precisely so the teal brand hue can never be
// mistaken for a severity. Putting blue back on a severity collapses that
// separation. medium is --sev-med (yellow) and high moved to --sev-high
// (orange) so the two stay distinguishable.
//
// ⛔ The fallback values are TOKEN REFERENCES, not hex. Literal hex here meant
// the SSR pass painted the OLD palette regardless of app/globals.css;
// `var(--x)` is a valid SVG `fill` presentation-attribute value, so the
// browser resolves it against the live theme on that pass too.
const SEVERITY_VAR = {
  critical: '--sev-crit',
  high: '--sev-high',
  medium: '--sev-med',
  info: '--sev-low',
};
const SEVERITY_FALLBACK_HEX = {
  critical: 'var(--sev-crit)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-med)',
  info: 'var(--sev-low)',
};

function resolveSeverityColor(severity) {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return SEVERITY_FALLBACK_HEX[severity] || SEVERITY_FALLBACK_HEX.info;
  }
  const varName = SEVERITY_VAR[severity] || SEVERITY_VAR.info;
  const value = getComputedStyle(document.documentElement).getPropertyValue(varName);
  return value ? value.trim() : SEVERITY_FALLBACK_HEX[severity] || SEVERITY_FALLBACK_HEX.info;
}

// counts: { [finding_type]: number } -- same shape devices/[id]/analysis/page.js
// already builds via getFindingTypeCounts(), zero-filled for every known type.
export default function FindingsBarChart({ counts }) {
  const data = FINDING_TYPE_ORDER.map((f) => ({
    ...f,
    count: (counts && counts[f.type]) || 0,
    color: resolveSeverityColor(f.severity),
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
          Findings by Type
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
                  <Cell key={entry.type} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardBody>
    </Card>
  );
}
