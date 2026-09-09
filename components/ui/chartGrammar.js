// components/ui/chartGrammar.js
//
// The ONE chart grammar. Axis ticks, grid, tooltip surface, legend and line
// geometry, shared by every recharts surface in the app.
//
// ⛔ WHY THIS FILE EXISTS IN components/ui/. Phase 5 of the redesign was
// "one chart grammar", and it was carried out by two people working in
// parallel on different directories. Both independently wrote a
// `chartGrammar.js` — one under components/analysis/, one under
// components/snmp/ — with near-identical exports that disagreed in three
// places. Two grammars is precisely the drift the phase existed to remove, so
// the shared primitives live here, in the directory that belongs to no domain,
// and the two domain modules re-export from this one.
//
// ⛔ Do not add a third. If a chart needs something these constants do not
// give it, either the constant is wrong for everyone (change it here) or the
// need is genuinely domain-specific (put it in that domain's module, next to
// the thing that needs it). A second copy of AXIS_TICK is never the answer.
//
// The three conflicts, and how they were resolved:
//
//   1. TICK FONT SIZE. One version passed `fontSize: 'var(--text-xs)'` as a
//      prop; the other passed it through `style`. The `style` form wins, and
//      not as a coin toss: recharts' <Text> applies `style` BOTH to the
//      rendered <text> and to the off-screen element it measures to decide
//      label widths and tick spacing. Passed as a prop, the custom property
//      may resolve when painted but not when measured, so recharts computes
//      layout from the wrong width. Passed through `style`, both agree.
//
//   2. LEGEND ICON SIZE. 8 vs 10. Took 10 with the small top padding — the
//      difference is cosmetic and one of them had to go.
//
//   3. CHART_HEADING_STYLE vs CHART_TITLE_STYLE. Byte-identical bodies under
//      two names. CHART_TITLE_STYLE is canonical here; the other name is kept
//      as an alias in the analysis module so its callers did not all have to
//      change in the same commit as everything else.

/* ── Axes ─────────────────────────────────────────────────────────────── */

// ⛔ The size goes through `style` so the value can be the --text-xs TOKEN and
// still be honoured by recharts' width measurement. See note 1 above. A
// hardcoded 11 would opt every tick out of the type scale silently, exactly
// like a hardcoded hex opts out of the palette.
export const AXIS_TICK = {
  fill: 'var(--text-muted)',
  style: { fontSize: 'var(--text-xs)' },
};

// A hairline axis, for a chart that has no grid to draw its own baseline
// (sparklines). ⛔ A chart WITH a horizontal grid should pass axisLine={false}
// instead: the bottom grid line already is the baseline, and a lone left rule
// with no vertical grid just boxes the plot in.
export const AXIS_LINE = { stroke: 'var(--border)' };

/* ── Grid ─────────────────────────────────────────────────────────────── */

// Horizontal only. Vertical grid lines compete with the data in a time series
// and add nothing a tick label does not already say.
export const GRID_PROPS = {
  strokeDasharray: '3 3',
  stroke: 'var(--border)',
  vertical: false,
};

/* ── Tooltip ──────────────────────────────────────────────────────────── */

export const TOOLTIP_SURFACE = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)',
  boxShadow: 'var(--shadow-md)',
  padding: 'var(--s2) var(--s3)',
  fontSize: 'var(--text-sm)',
  lineHeight: 1.45,
};

// Hover affordance. A bar chart gets a faint filled column, a line chart a
// vertical hairline. ⛔ Neither may use a status hue: a cursor is chrome, and a
// red or amber hover band would read as a finding about the point under it.
export const TOOLTIP_CURSOR_BAR = { fill: 'var(--primary-light)' };
export const TOOLTIP_CURSOR_LINE = { stroke: 'var(--border)' };

/* ── Legend ───────────────────────────────────────────────────────────── */

// ⛔ Only on a chart with more than one series. A legend under a single-series
// chart restates the title and costs vertical space the chart could use.
export const LEGEND_PROPS = {
  iconType: 'plainline',
  iconSize: 10,
  wrapperStyle: {
    fontSize: 'var(--text-xs)',
    color: 'var(--text-muted)',
    paddingTop: 'var(--s1)',
  },
};

/* ── Lines ────────────────────────────────────────────────────────────── */

// Shared line geometry, so a sample dot is the same size on every chart.
export const LINE_PROPS = {
  type: 'monotone',
  strokeWidth: 2,
  isAnimationActive: false,
  // ⛔ NEVER REMOVE, and never set it true on a new chart. With connectNulls
  // on, a polling cycle that returned NULL is bridged by a straight
  // interpolated segment, pixel-identical to the real samples either side —
  // an invented reading where a measurement failed. That is hit_count's old
  // DEFAULT 0 rendered in a chart. A gap must look like a gap.
  //
  // ⛔ And note this is necessary but NOT sufficient: a failed poll often
  // stores no row at all rather than a NULL one, in which case there is no
  // null for this flag to protect and a categorical axis will happily put the
  // two sides of an outage next to each other. See withPollingGaps() in the
  // snmp module, which inserts the missing points so this flag has something
  // to act on.
  connectNulls: false,
};

/* ── Card-internal chart heading ──────────────────────────────────────── */

export const CHART_TITLE_STYLE = {
  marginBottom: 'var(--s3)',
  fontSize: 'var(--text-xs)',
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
  color: 'var(--text-muted)',
};
