'use client';

import { PieChart, Pie, Cell } from 'recharts';

// Multi-slice categorical donut -- distinct from components/compliance/StandardDonut.js,
// which is a single-VALUE 2-segment gauge (score vs remainder, one fixed color driven by
// a score band). This component renders N independently-colored categories with a legend,
// for any caller that needs a categorical breakdown rather than a percentage gauge.
//
// Same "resolve a CSS custom property via getComputedStyle, with a hardcoded hex SSR
// fallback" pattern as StandardDonut.js's resolveCssVar()/VAR_FALLBACK_HEX, generalized:
// this component doesn't know ahead of time which --tokens a caller will pass as
// `categories[].color`, so resolveColor() only special-cases the `var(--x)` shape and
// otherwise passes the value straight through (a literal hex/rgb string works as-is,
// both server-rendered and once mounted).
const VAR_FALLBACK_HEX = {
  '--red': '#dc2626',
  '--orange': '#ea580c',
  '--yellow': '#d97706',
  '--purple': '#7c3aed',
  '--blue': '#2563eb',
  '--teal': '#0891b2',
  '--green': '#16a34a',
  '--text-muted': '#64748b',
  '--border': '#e2e8f0',
};

function resolveColor(colorValue) {
  const match = /^var\((--[\w-]+)\)/.exec(colorValue || '');
  if (!match) return colorValue;
  const varName = match[1];
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return VAR_FALLBACK_HEX[varName] || VAR_FALLBACK_HEX['--text-muted'];
  }
  const resolved = getComputedStyle(document.documentElement).getPropertyValue(varName);
  return resolved ? resolved.trim() : VAR_FALLBACK_HEX[varName] || VAR_FALLBACK_HEX['--text-muted'];
}

// Generic, reusable -- deliberately no domain wording ("unused rules", "shadow rules", ...)
// baked in here. The caller (OverviewRuleHygieneCard.js) owns every label/color; this file
// only knows how to render whatever `categories` shape it's handed.
export default function RuleHygieneDonut({ categories = [], total = 0, size = 140 }) {
  const track = resolveColor('var(--border)');
  const outerRadius = size / 2;
  const innerRadius = outerRadius * 0.62;
  const fontSize = Math.max(14, Math.round(size * 0.2));

  const data =
    total > 0
      ? categories.map((c) => ({ key: c.key, value: c.count, color: resolveColor(c.color) }))
      : [{ key: 'empty', value: 1, color: track }];

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 20 }}>
      <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
        <PieChart width={size} height={size}>
          <Pie
            data={data}
            dataKey="value"
            nameKey="key"
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
              <Cell key={entry.key} fill={entry.color} />
            ))}
          </Pie>
        </PieChart>
        <div
          style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            pointerEvents: 'none',
          }}
        >
          <div
            style={{
              fontSize,
              fontWeight: 700,
              color: total > 0 ? 'var(--text-primary)' : 'var(--text-muted)',
              lineHeight: 1.1,
            }}
          >
            {total > 0 ? total : '—'}
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', textAlign: 'center' }}>
            {total > 0 ? 'Total issues' : 'No findings'}
          </div>
        </div>
      </div>

      {categories.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, minWidth: 160, flex: '1 1 160px' }}>
          {categories.map((c) => (
            <div key={c.key} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 'var(--text-sm)' }}>
              <span
                style={{
                  width: 10,
                  height: 10,
                  borderRadius: 2,
                  background: resolveColor(c.color),
                  flexShrink: 0,
                }}
              />
              <span style={{ color: 'var(--text-secondary)', flex: 1 }}>{c.label}</span>
              <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{c.count}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
