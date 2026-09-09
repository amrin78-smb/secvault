'use client';

import NotMeasured from '../ui/NotMeasured';

// ONE CHART GRAMMAR (Phase 5 of the UI redesign).
//
// Every recharts chart in components/analysis/ and components/dashboard/ was
// written at a different time and each invented its own axis colour, tick
// size, grid dash, tooltip surface and legend. They now all import from here.
// Adding a chart means importing these; it does not mean inventing a seventh
// axis style.
//
// ⛔ NO getComputedStyle, EVER. Four of these files carried a
// `resolveColor(varName, hexFallback)` helper that read the resolved value off
// document.documentElement at render time. It was wrong twice over:
//
//   1. The hex fallbacks were PRE-REDESIGN values (the old suite red, the old
//      blue-for-medium ramp). The server render therefore painted a different
//      palette than the client did, and the swap was invisible because it
//      happened during hydration.
//   2. getComputedStyle BAKES the colour into the SVG attribute at render
//      time. Flipping the theme toggle re-stamps data-theme on <html> and
//      every token changes — but a chart that already rendered keeps the old
//      theme's hues until something happens to re-render it. Charts sat on
//      light-theme colours inside a dark page.
//
// `var(--token)` passed straight into a recharts `stroke`/`fill` prop is an
// SVG presentation attribute, which the browser resolves as CSS against the
// LIVE theme, on every paint, on both the server and client passes. It is
// already shipped and working elsewhere in this repo. Pass the token string.

/* ── Axes ────────────────────────────────────────────────────────────────
   Same tick treatment on every axis: --text-muted at --text-xs. Ticks are
   chrome, not data — they were competing with the series at --text-secondary.

   ⛔ axisLine={false} on BOTH axes, deliberately. With a horizontal-only grid
   the bottom-most grid line already draws the X baseline, so an axis line
   there is a second line on the same pixels; and a lone left-hand vertical
   rule with no vertical grid to belong to just boxes the plot in for no
   information. The grid is the frame. */
// ⛔ The shared primitives live in components/ui/chartGrammar.js — see the
// long note at the top of that file. This module keeps only what is specific
// to the analysis/dashboard charts, and re-exports the shared names so no
// call site in these two directories had to change.
import {
  AXIS_TICK,
  GRID_PROPS,
  TOOLTIP_SURFACE,
  // Hover affordance. A bar chart gets a faint filled column, a line chart
  // a vertical hairline — neither in a status hue, so neither can be
  // mistaken for data.
  TOOLTIP_CURSOR_BAR,
  TOOLTIP_CURSOR_LINE,
  LEGEND_PROPS,
  CHART_TITLE_STYLE,
} from '../ui/chartGrammar';

export {
  AXIS_TICK,
  GRID_PROPS,
  TOOLTIP_SURFACE,
  TOOLTIP_CURSOR_BAR,
  TOOLTIP_CURSOR_LINE,
  LEGEND_PROPS,
};

// The old name for the canonical CHART_TITLE_STYLE, kept so this module’s
// existing callers did not all have to change in the same commit.
export const CHART_HEADING_STYLE = CHART_TITLE_STYLE;
export const X_AXIS_PROPS = {
  tick: AXIS_TICK,
  axisLine: false,
  tickLine: false,
};

// ⛔ allowDecimals={false} belongs on every COUNT axis: recharts will happily
// label a 0-3 domain as 0, 0.75, 1.5, 2.25, 3, and "1.5 findings" is not a
// thing this product can report.
export const COUNT_AXIS_PROPS = {
  tick: AXIS_TICK,
  axisLine: false,
  tickLine: false,
  allowDecimals: false,
};

/* ── Tooltip ──────────────────────────────────────────────────────────── */

// The heading line inside a tooltip (the x-axis label for the hovered
// point). Separated from the rows below it by weight and colour rather than
// a rule, so a two-line tooltip does not need a divider.
//
// ⛔ RESTORED after being deleted by accident during the chartGrammar
// collapse: the merge removed a RANGE between two markers, and this
// constant happened to sit inside that range. `npm run build` passed, both
// lint tests passed, and the dashboard threw a ReferenceError the moment a
// tooltip rendered — a component-scope identifier that no longer exists is
// invisible to every static gate this repo has -- see gotchas.md.
const TOOLTIP_LABEL_STYLE = {
  marginBottom: 'var(--s1)',
  fontWeight: 600,
  color: 'var(--text-primary)',
};

export function ChartTooltip({
  active,
  payload,
  label,
  labelFormatter,
  valueFormatter,
  hideLabel = false,
  unmeasuredReason = 'No value recorded for this series at this point.',
}) {
  if (!active || !Array.isArray(payload) || payload.length === 0) return null;

  const heading = hideLabel ? null : labelFormatter ? labelFormatter(label, payload) : label;

  return (
    <div style={TOOLTIP_SURFACE}>
      {heading === null || heading === undefined || heading === '' ? null : (
        <div style={TOOLTIP_LABEL_STYLE}>{heading}</div>
      )}
      {payload.map((entry, i) => {
        const raw = entry.value;
        const measured = raw !== null && raw !== undefined && Number.isFinite(Number(raw));
        return (
          <div
            key={entry.dataKey ?? entry.name ?? i}
            style={{ display: 'flex', alignItems: 'center', gap: 'var(--s2)', color: 'var(--text-secondary)' }}
          >
            <span
              aria-hidden="true"
              style={{
                width: 8,
                height: 8,
                flex: 'none',
                borderRadius: 2,
                background: measured ? entry.color || 'var(--text-muted)' : 'var(--unmeasured)',
              }}
            />
            {payload.length > 1 || entry.name ? <span>{entry.name ?? entry.dataKey}</span> : null}
            <span
              style={{
                marginLeft: 'auto',
                color: 'var(--text-primary)',
                fontWeight: 600,
                fontVariantNumeric: 'tabular-nums',
              }}
            >
              {measured ? (
                valueFormatter ? valueFormatter(raw, entry) : Number(raw).toLocaleString()
              ) : (
                <NotMeasured reason={unmeasuredReason} />
              )}
            </span>
          </div>
        );
      })}
    </div>
  );
}

/* ── Legend ────────────────────────────────────────────────────────────
   ⛔ Only on a MULTI-series chart. A legend under a single line restates the
   card title in smaller type and eats 20px of plot height to do it; every
   single-series chart in these two directories now omits it. */
/* ── Card-internal chart heading ────────────────────────────────────────
   The four chart cards had four copies of this object inline. */
export function ChartNotMeasured({ reason, height = 260 }) {
  return (
    <div
      style={{
        width: '100%',
        height,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        padding: 'var(--s4)',
        borderRadius: 'var(--radius-sm)',
        border: '1px dashed var(--border)',
        background: 'var(--surface-subtle)',
        color: 'var(--unmeasured)',
        fontSize: 'var(--text-sm)',
      }}
    >
      {reason}
    </div>
  );
}
