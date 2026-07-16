'use client';

import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

// The 9 finding types in the fixed severity order CLAUDE.md documents for the
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
  { type: 'overly_permissive', label: 'Overly Perm.', severity: 'medium' },
  { type: 'unused', label: 'Unused', severity: 'medium' },
  { type: 'expiring_soon', label: 'Expiring', severity: 'medium' },
  { type: 'log_disabled', label: 'Log Off', severity: 'info' },
];

// Reads the app's own CSS custom properties (app/globals.css) rather than
// hardcoding hex values a second time -- stays correct if the palette ever
// changes, and automatically matches SeverityBadge/StatusDot/etc. Read at
// render time in a browser context (useEffect-free: getComputedStyle on
// document.documentElement is synchronous and cheap for 4 lookups), with a
// hardcoded fallback for the (never-expected-in-practice) case of SSR-time
// evaluation before hydration.
const SEVERITY_VAR = {
  critical: '--danger',
  high: '--warning',
  medium: '--info',
  info: '--text-muted',
};
const SEVERITY_FALLBACK_HEX = {
  critical: '#ef4444',
  high: '#f59e0b',
  medium: '#3b82f6',
  info: '#64748b',
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
    <div className="rounded-lg border border-border bg-bg-surface p-4">
      <div className="mb-3 text-xs uppercase tracking-wide text-text-muted">Findings by Type</div>
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
              cursor={{ fill: 'var(--bg-elevated)' }}
              contentStyle={{
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border)',
                borderRadius: 6,
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
    </div>
  );
}
