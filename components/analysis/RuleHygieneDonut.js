'use client';

import { PieChart, Pie, Cell } from 'recharts';
import NotMeasured from '../ui/NotMeasured';

// Multi-slice categorical donut -- distinct from components/compliance/StandardDonut.js,
// which is a single-VALUE 2-segment gauge (score vs remainder, one fixed color driven by
// a score band). This component renders N independently-colored categories with a legend,
// for any caller that needs a categorical breakdown rather than a percentage gauge.
//
// ⛔ The caller's `categories[].color` tokens go STRAIGHT into recharts and into the
// legend swatch backgrounds. The getComputedStyle-based resolveColor()/VAR_FALLBACK_HEX
// pair that used to live here is deleted — see the header of chartGrammar.js for the two
// bugs it caused (an SSR pass painting the pre-redesign palette, and a live theme toggle
// leaving the ring on the old theme's hues until something re-rendered it). `var(--x)` is
// valid both as an SVG `fill` presentation attribute and as a DOM `background`, so the
// browser resolves it against the live theme on every paint.

// Generic, reusable -- deliberately no domain wording ("unused rules", "shadow rules", ...)
// baked in here. The caller (OverviewRuleHygieneCard.js) owns every label/color; this file
// only knows how to render whatever `categories` shape it's handed.
export default function RuleHygieneDonut({ categories = [], total = 0, size = 140 }) {
  const outerRadius = size / 2;
  const innerRadius = outerRadius * 0.62;
  const fontSize = Math.max(14, Math.round(size * 0.2));
  const hasFindings = total > 0;

  // ⛔ FAILED READ RENDERED AS A VALUE. With no findings this used to draw a
  // full, solid ring in --border and label it "No findings" — a confident
  // claim about the ruleset. But zero rows in rule_analysis_results means
  // either "analysis ran and this ruleset is clean" or "analysis has never
  // run here", and a solid ring said the first while meaning either.
  //
  // The empty ring is now --unmeasured with a DASHED stroke, which is the SVG
  // form NotMeasured.js prescribes (--hatch is a CSS gradient and cannot be an
  // SVG paint server), and the caption states what was actually observed — a
  // fact about the RECORD, not a verdict on the firewall.
  const data = hasFindings
    ? categories.map((c) => ({ key: c.key, value: c.count, color: c.color }))
    : [{ key: 'unmeasured', value: 1, color: 'var(--unmeasured)' }];

  const emptyReason =
    'No rule-analysis findings are recorded for this device. That is a clean ruleset only if analysis has actually run — otherwise nothing here has been measured.';

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--s5)' }}>
      <div
        style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}
        title={hasFindings ? undefined : emptyReason}
      >
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
            stroke={hasFindings ? 'none' : 'var(--unmeasured)'}
            strokeDasharray={hasFindings ? undefined : '4 3'}
            fill={hasFindings ? undefined : 'none'}
            isAnimationActive={false}
          >
            {data.map((entry) => (
              // ⛔ The unmeasured ring is an OUTLINE, not a fill. A flat grey
              // fill reads as a real category with a muted colour, which is the
              // exact confusion NotMeasuredBar's hatching exists to prevent.
              <Cell key={entry.key} fill={hasFindings ? entry.color : 'none'} />
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
              color: hasFindings ? 'var(--text-primary)' : 'var(--unmeasured)',
              lineHeight: 1.1,
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            {hasFindings ? total : '—'}
          </div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', textAlign: 'center' }}>
            {hasFindings ? 'Total issues' : 'None recorded'}
          </div>
        </div>
      </div>

      {categories.length > 0 && (
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: 'var(--s1)',
            minWidth: 160,
            flex: '1 1 160px',
          }}
        >
          {categories.map((c) => (
            <div
              key={c.key}
              style={{ display: 'flex', alignItems: 'center', gap: 'var(--s2)', fontSize: 'var(--text-sm)' }}
            >
              <span
                style={{
                  width: 10,
                  height: 10,
                  // The ONE deliberate exemption from the radius tokens (see
                  // the square-corners block in app/globals.css): --radius-sm
                  // is 6px, which on a 10px swatch renders as a circle and
                  // would change the rounded look. At 2px on 10px this reads
                  // as square already, so the corner switch has nothing to do.
                  borderRadius: 2,
                  background: hasFindings ? c.color : 'var(--unmeasured)',
                  flexShrink: 0,
                }}
              />
              <span style={{ color: 'var(--text-secondary)', flex: 1 }}>{c.label}</span>
              {/* ⛔ With nothing recorded, each legend row used to read a flat
                  "0" — six confident zeros claiming six checks came back
                  clean. They are em-dashes until something has actually been
                  measured. */}
              {hasFindings ? (
                <span style={{ color: 'var(--text-primary)', fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>
                  {c.count}
                </span>
              ) : (
                <NotMeasured reason={emptyReason} />
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
