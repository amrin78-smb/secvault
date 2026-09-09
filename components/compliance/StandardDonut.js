'use client';

import { PieChart, Pie, Cell } from 'recharts';
import { scoreColor, SCORE_COLOR_VAR } from './ComplianceMatrix';

// Same "resolve a CSS custom property to its computed value at render time,
// with a fallback for the SSR pass" pattern as
// components/analysis/FindingsBarChart.js's resolveSeverityColor() -- keeps
// this donut's arc color in sync with the exact same tokens
// ComplianceMatrix.js's scoreChip()/StatCard tiles already use, rather than
// hardcoding a color a second time. SCORE_COLOR_VAR values are 'var(--xxx)'
// strings (built for a CSS `color` prop, e.g. StatCard's `color`); the var
// name is pulled back out here so getComputedStyle can resolve it once mounted.
//
// ⛔ The fallback values below are TOKEN REFERENCES, not hex (changed with the
// 2026-09-09 palette rewrite). They used to be literal hex, which meant the
// server-rendered pass drew this gauge in the OLD palette no matter what
// app/globals.css says. `var(--xxx)` is a valid value for an SVG `fill`
// presentation attribute, so the browser resolves it against the live theme
// on that pass too.
const VAR_FALLBACK_HEX = {
  '--green': 'var(--green)',
  '--yellow': 'var(--yellow)',
  '--red': 'var(--red)',
  '--text-muted': 'var(--text-muted)',
  '--border': 'var(--border)',
  '--unmeasured': 'var(--unmeasured)',
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
// scoreChip()) renders one flat ring with no colored arc at all, since there
// is nothing to show a proportion of.
//
// ⛔ That null ring is drawn in --unmeasured, NOT in the --border track color
// (changed 2026-09-09 with the palette rewrite). A measured 0% also renders as
// a full track-colored ring, so painting "nothing was measurable" in the same
// color made the two states pixel-identical apart from the centre label --
// i.e. an unmeasured value rendered as a confident zero, which is exactly the
// failed-read-as-a-fact bug CLAUDE.md bans. --unmeasured is the palette's
// deliberately hue-less "not measured" token (--hatch, its sibling, is a
// repeating-linear-gradient and so cannot be used as an SVG fill).
//
// Fixed-size wrapper div (size x size px), NOT ResponsiveContainer -- this is
// a small fixed-size widget dropped into a two-column card layout
// (StandardCard.js), not a full-width chart like FindingsBarChart.js, and
// ResponsiveContainer needs a sized parent that this component can't assume.
// ⛔ `reason` is REQUIRED in spirit whenever `pct` can be null (the caller
// knows WHY — never audited vs. every check unanswerable; this component
// cannot tell). Without it the ring and the "—" are honest about the absence
// but silent about its cause, which components/ui/NotMeasured.js calls out as
// "only marginally better than a fabricated zero". The default below is a
// last-resort fallback, not a licence to omit it.
export default function StandardDonut({
  pct,
  size = 120,
  reason = 'Not measured — nothing scoreable was collected for this standard.',
}) {
  const clamped = pct == null ? null : Math.max(0, Math.min(100, pct));
  const color = resolveCssVar(SCORE_COLOR_VAR[scoreColor(clamped)]);
  const track = resolveCssVar(clamped == null ? 'var(--unmeasured)' : 'var(--border)');

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
    <div
      style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}
      title={clamped == null ? reason : `${clamped}% of scoreable checks pass`}
      role="img"
      aria-label={clamped == null ? reason : `Compliance score ${clamped} percent`}
    >
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
          {data.map((entry) =>
            // ⛔ The "nothing measurable" ring is HOLLOW AND DASHED, not just a
            // different grey. Colour alone separated it from a genuine 0% ring
            // only for a reader who knows both greys; texture separates it for
            // everyone, and it is the same dashed-ring vocabulary FleetMap uses
            // for a device with no collected interfaces. --hatch itself cannot
            // be used here: it is a CSS gradient, and an SVG fill needs a paint
            // server (see components/ui/NotMeasured.js).
            entry.name === 'track' ? (
              <Cell
                key={entry.name}
                fill="var(--surface-subtle)"
                stroke={track}
                strokeWidth={1.5}
                strokeDasharray="4 4"
              />
            ) : (
              <Cell key={entry.name} fill={entry.name === 'score' ? color : track} />
            )
          )}
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
          color: clamped == null ? 'var(--unmeasured)' : 'var(--text-primary)',
          pointerEvents: 'none',
        }}
      >
        {clamped == null ? '—' : `${clamped}%`}
      </div>
    </div>
  );
}
