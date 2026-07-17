'use client';

import { PieChart, Pie, Cell } from 'recharts';
import { scoreColor, SCORE_COLOR_VAR } from './ComplianceMatrix';

// Same "resolve a CSS custom property to its computed value at render time,
// with a hardcoded hex fallback for the SSR pass" pattern as
// components/analysis/FindingsBarChart.js's resolveSeverityColor() -- keeps
// this donut's arc color in sync with the exact same tokens
// ComplianceMatrix.js's scoreChip()/StatCard tiles already use, rather than
// hardcoding hex a second time. SCORE_COLOR_VAR values are 'var(--xxx)'
// strings (built for a CSS `color` prop, e.g. StatCard's `color`); the var
// name is pulled back out here so getComputedStyle can resolve it to a real
// value -- handing a raw 'var(--xxx)' string straight to recharts' `fill`
// prop only resolves correctly once mounted in a browser DOM, never during
// the SSR pass this component (imported by the server-rendered
// StandardCard.js) also runs through.
const VAR_FALLBACK_HEX = {
  '--green': '#16a34a',
  '--yellow': '#d97706',
  '--red': '#dc2626',
  '--text-muted': '#64748b',
  '--border': '#e2e8f0',
};

function resolveCssVar(varRef) {
  const match = /var\((--[\w-]+)\)/.exec(varRef || '');
  const varName = match ? match[1] : '--text-muted';
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return VAR_FALLBACK_HEX[varName] || VAR_FALLBACK_HEX['--text-muted'];
  }
  const value = getComputedStyle(document.documentElement).getPropertyValue(varName);
  return value ? value.trim() : VAR_FALLBACK_HEX[varName] || VAR_FALLBACK_HEX['--text-muted'];
}

// Single-value donut/radial gauge: one <Pie> with two segments (score,
// remainder) so the colored arc and the gray track always sum to exactly one
// full ring, rather than layering two separate <Pie> elements. `pct === null`
// (never audited / nothing measurable -- see CLAUDE.md's "null and 0% mean
// very different things" convention, already followed by ComplianceMatrix's
// scoreChip()) renders one flat muted ring with no colored arc at all, since
// there is nothing to show a proportion of.
//
// Fixed-size wrapper div (size x size px), NOT ResponsiveContainer -- this is
// a small fixed-size widget dropped into a two-column card layout
// (StandardCard.js), not a full-width chart like FindingsBarChart.js, and
// ResponsiveContainer needs a sized parent that this component can't assume.
export default function StandardDonut({ pct, size = 120 }) {
  const clamped = pct == null ? null : Math.max(0, Math.min(100, pct));
  const color = resolveCssVar(SCORE_COLOR_VAR[scoreColor(clamped)]);
  const track = resolveCssVar('var(--border)');

  const data =
    clamped == null
      ? [{ name: 'track', value: 100 }]
      : [
          { name: 'score', value: clamped },
          { name: 'remainder', value: Math.max(0, 100 - clamped) },
        ];

  const outerRadius = size / 2;
  const innerRadius = outerRadius * 0.72;
  const fontSize = Math.max(12, Math.round(size * 0.18));

  return (
    <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
      <PieChart width={size} height={size}>
        <Pie
          data={data}
          dataKey="value"
          cx="50%"
          cy="50%"
          innerRadius={innerRadius}
          outerRadius={outerRadius}
          startAngle={90}
          endAngle={-270}
          stroke="none"
          isAnimationActive={false}
        >
          {data.map((entry) => (
            <Cell key={entry.name} fill={entry.name === 'score' ? color : track} />
          ))}
        </Pie>
      </PieChart>
      <div
        style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize,
          fontWeight: 700,
          color: clamped == null ? 'var(--text-muted)' : 'var(--text-primary)',
          pointerEvents: 'none',
        }}
      >
        {clamped == null ? '—' : `${clamped}%`}
      </div>
    </div>
  );
}
