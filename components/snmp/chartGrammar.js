// ONE chart grammar, shared by every recharts surface under components/snmp,
// components/vpn and components/compliance.
//
// ⛔ WHY THIS FILE EXISTS. Before it, four chart files each hand-rolled their
// own tooltip div, their own tick style (11px here, 10px there, --text-secondary
// in one file and --text-muted in the next) and their own grid stroke. Nothing
// was wrong in isolation; the effect was that two charts sitting on the SAME
// page read as two different instruments, so a reader comparing them had to
// re-learn the furniture before reading the data. Axes, grid, tooltip and
// legend are furniture: they must be invisible, and they are only invisible
// when they are identical everywhere.
//
// ⛔ LOCATION IS A CONSTRAINT, NOT A CHOICE. This belongs in components/ui/
// beside NotMeasured.js. It lives here because components/ui/ is owned by
// another session in the current redesign pass and this file had to land
// inside one of the four directories it serves. Promote it to
// components/ui/chartGrammar.js when the redesign lands and update the four
// import paths; nothing in it is SNMP-specific.
//
// ── The grammar ─────────────────────────────────────────────────────────────
//   axis ticks   --text-xs in --text-muted, no tick lines, hairline axis line
//   grid         HORIZONTAL ONLY, --border, 3 3 dashes. Vertical gridlines on a
//                time series add nothing a tick mark does not already say.
//   tooltip      card background, hairline border, --radius-sm, --text-sm
//   legend       ONLY when a chart has more than one series. A legend under a
//                single-series chart is a label pretending to be a key.
//
// ── ⛔ The rule that outranks the styling ────────────────────────────────────
// A null in a series is NOT a zero and NOT a point on the line. Every chart
// importing this passes connectNulls={false} so the gap stays a gap, and every
// tooltip built from these primitives renders a null through <NotMeasured/>
// with a REASON — never a bare em-dash, never "0". CLAUDE.md's most-repeated
// bug is a failed read rendered as an affirmative value, and a chart is the
// easiest place in the product to commit it invisibly.

import NotMeasured from '../ui/NotMeasured';

// ── Axis / grid / cursor props, spread into recharts elements ───────────────

// `style` carries the font size rather than a numeric `fontSize` prop so the
// value can be the --text-xs TOKEN. recharts' Text applies `style` both to the
// rendered <text> and to its own off-screen width measurement, so the token
// resolves in both places; a hardcoded 11 would opt every chart tick out of the
// type scale, silently, exactly like a hardcoded hex opts out of the palette.
// Horizontal-only. Spread as {...GRID_PROPS} onto <CartesianGrid/>.
// Shared line geometry, so a sample dot is the same size on every chart and a
// per-point mark (see ConfidenceDot in SnmpMetricsCharts.js) can be compared
// against a plain one across charts.
// ── Time formatting, shared so two charts on one page label time alike ──────

// ⛔ The shared primitives live in components/ui/chartGrammar.js — see the
// long note at the top of that file. This module keeps only what is specific
// to time-series polling data (gap detection, UTC formatters, the tooltip
// composition), and re-exports the shared names so no call site in the snmp/
// vpn directories had to change.
import {
  AXIS_TICK,
  AXIS_LINE,
  GRID_PROPS,
  LEGEND_PROPS,
  LINE_PROPS,
  TOOLTIP_SURFACE,
  TOOLTIP_CURSOR_LINE,
  CHART_TITLE_STYLE,
} from '../ui/chartGrammar';

export {
  AXIS_TICK,
  AXIS_LINE,
  GRID_PROPS,
  LEGEND_PROPS,
  LINE_PROPS,
  TOOLTIP_SURFACE,
  CHART_TITLE_STYLE,
};

// This module’s charts are all line/area, so its single cursor is the
// hairline one. Kept under the shorter local name its callers already use.
export const TOOLTIP_CURSOR = TOOLTIP_CURSOR_LINE;
export function utcMinute(value) {
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  return d.toISOString().slice(0, 16).replace('T', ' ');
}

export function utcHourMinute(value) {
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  return d.toISOString().slice(11, 16);
}

export function utcFull(value) {
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return String(value ?? '');
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

// ── Polling gaps ────────────────────────────────────────────────────────────

/**
 * Insert an explicit null sample wherever the poller MISSED a cycle.
 *
 * ⛔ THIS IS THE connectNulls BUG ONE LEVEL UP, and it is why this helper
 * exists. Both snmp_metric_snapshots and vpn_session_snapshots are written only
 * when a poll SUCCEEDS — a failed poll throws and stores no row at all. So the
 * "null sample" that connectNulls={false} protects against never appears in the
 * data; instead the failed cycle is simply ABSENT, and because these charts use
 * a categorical x-axis, a six-hour outage renders as one ordinary step between
 * two adjacent samples: a confident straight line across a period in which
 * SecVault measured nothing whatsoever. Same lie as an interpolated segment,
 * just harder to see.
 *
 * A synthetic row (all series keys explicitly null, `__gap: true`) is inserted
 * at the midpoint of any interval far longer than this device's own typical
 * polling interval, so the line breaks and the tooltip can say what happened.
 *
 * ⛔ The threshold is derived from the DATA (median interval), never from
 * SNMP_POLL_INTERVAL_MINUTES: the interval is configurable, the component
 * cannot read env vars, and guessing 15 minutes would manufacture gaps on a
 * fleet polled hourly. If the timestamps cannot be reasoned about at all, the
 * rows are returned untouched — no invented gaps, ever.
 *
 * @param {object[]} rows      samples, oldest-to-newest
 * @param {string}   timeKey   timestamp field
 * @param {string[]} valueKeys series fields to null out on the synthetic row
 */
export function withPollingGaps(rows, timeKey, valueKeys) {
  if (!Array.isArray(rows) || rows.length < 3) return Array.isArray(rows) ? rows : [];
  const times = rows.map((r) => new Date(r[timeKey]).getTime());
  if (times.some((t) => !Number.isFinite(t))) return rows;

  const deltas = [];
  for (let i = 1; i < times.length; i += 1) deltas.push(times[i] - times[i - 1]);
  const sorted = deltas.slice().sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];
  if (!Number.isFinite(median) || median <= 0) return rows;

  // 2.5x the usual cadence, and never less than a minute of slack — a poller
  // that runs a few seconds late has not missed a cycle.
  const threshold = Math.max(median * 2.5, median + 60000);

  const out = [];
  for (let i = 0; i < rows.length; i += 1) {
    if (i > 0 && times[i] - times[i - 1] > threshold) {
      const filler = { [timeKey]: new Date((times[i - 1] + times[i]) / 2).toISOString(), __gap: true };
      for (const k of valueKeys) filler[k] = null;
      filler.__gapFrom = rows[i - 1][timeKey];
      filler.__gapTo = rows[i][timeKey];
      out.push(filler);
    }
    out.push(rows[i]);
  }
  return out;
}

export function countPollingGaps(rows) {
  return Array.isArray(rows) ? rows.filter((r) => r && r.__gap).length : 0;
}

/**
 * Caption under a chart whose line is broken by missed polls. ⛔ A broken line
 * with no caption is ambiguous — it could equally be read as the metric itself
 * going to nothing.
 */
export function PollingGapNote({ gaps }) {
  if (!gaps) return null;
  return (
    <div style={{ marginTop: 'var(--s2)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
      Line broken at {gaps} point{gaps === 1 ? '' : 's'} where no poll was stored. Nothing was
      measured there — it is not a drop to zero.
    </div>
  );
}

/** Tooltip body for a synthetic gap sample. */
export function GapTooltipBody({ point }) {
  return (
    <TooltipShell>
      <TooltipHeading>No poll stored</TooltipHeading>
      <TooltipMeta>
        Nothing was measured between {utcFull(point.__gapFrom)} and {utcFull(point.__gapTo)}.
      </TooltipMeta>
    </TooltipShell>
  );
}

// ── Tooltip primitives. All module top level (CLAUDE.md's React rule). ──────

const SHELL_STYLE = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)',
  boxShadow: 'var(--shadow-md)',
  padding: 'var(--s2) var(--s3)',
  fontSize: 'var(--text-sm)',
  lineHeight: 1.5,
  color: 'var(--text-primary)',
  maxWidth: 280,
};

export function TooltipShell({ children }) {
  return <div style={SHELL_STYLE}>{children}</div>;
}

export function TooltipHeading({ children }) {
  return <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{children}</div>;
}

// Secondary line: the timestamp, the coverage caveat, the provenance note.
export function TooltipMeta({ children }) {
  return (
    <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>{children}</div>
  );
}

/**
 * One "swatch · label · value" row inside a tooltip.
 *
 * ⛔ `value == null` renders <NotMeasured/> with `reason`, NOT a zero and not a
 * bare dash. `reason` is therefore REQUIRED whenever a null is possible — the
 * reader has to be able to tell a gap in the device from a gap in SecVault.
 */
export function TooltipMetric({ color, label, value, unit = '', reason }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--s2)' }}>
      {color ? (
        <span
          aria-hidden="true"
          style={{
            width: 8,
            height: 8,
            flex: 'none',
            borderRadius: '50%',
            background: color,
          }}
        />
      ) : null}
      <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
      <span style={{ marginLeft: 'auto', fontVariantNumeric: 'tabular-nums', fontWeight: 600 }}>
        {value === null || value === undefined ? (
          <NotMeasured reason={reason || 'This sample carried no value.'} />
        ) : (
          `${value}${unit}`
        )}
      </span>
    </div>
  );
}

/**
 * Ready-made tooltip for the ordinary case: one row per series, plus a
 * timestamp line. Charts that need to say something extra per sample (SNMP's
 * per-sample confidence, for instance) compose TooltipShell/TooltipMetric
 * themselves instead — at module top level, never inside a component.
 *
 * @param {string} [unit]     appended to every value ('%', ' sessions', …)
 * @param {string} reason     why a null value is missing — required
 * @param {string} [labelKey] payload field holding the timestamp
 */
export function SeriesTooltip({ active, payload, unit = '', reason, labelKey = 'sampled_at' }) {
  if (!active || !Array.isArray(payload) || payload.length === 0) return null;
  const point = payload[0].payload || {};
  return (
    <TooltipShell>
      {payload.map((entry) => (
        <TooltipMetric
          key={entry.dataKey}
          color={entry.stroke || entry.color}
          label={entry.name || entry.dataKey}
          // ⛔ Read from the ROW, not from entry.value: recharts drops the
          // entry's own value for a null sample, and `undefined` there would be
          // indistinguishable from a series the tooltip simply did not receive.
          value={point[entry.dataKey] === undefined ? null : point[entry.dataKey]}
          unit={unit}
          reason={reason}
        />
      ))}
      {point[labelKey] ? <TooltipMeta>{utcFull(point[labelKey])}</TooltipMeta> : null}
    </TooltipShell>
  );
}

/**
 * Compact inline key for charts too short to carry a recharts <Legend/> (the
 * 90px sparklines). Same job, same order, a fraction of the height.
 *
 * ⛔ Two unlabelled lines in two colours is not a chart, it is a guess. If a
 * surface has more than one series it gets a key of some kind.
 */
export function SeriesKey({ items }) {
  return (
    <div
      style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: 'var(--s3)',
        fontSize: 'var(--text-xs)',
        color: 'var(--text-muted)',
      }}
    >
      {items.map((it) => (
        <span key={it.label} style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--s1)' }}>
          <span
            aria-hidden="true"
            style={{ width: 10, height: 2, flex: 'none', background: it.color, borderRadius: 1 }}
          />
          {it.label}
        </span>
      ))}
    </div>
  );
}

/**
 * The empty state for a chart. ⛔ Never render an empty axis pair: a chart
 * frame with no line in it is read as "measured, and the answer is nothing".
 * Say which question could not be answered, and why.
 */
export function ChartEmpty({ title, message, height = 220 }) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 'var(--s2)',
        height,
        padding: 'var(--s4)',
        textAlign: 'center',
        border: '1px dashed var(--border)',
        borderRadius: 'var(--radius)',
        background: 'var(--surface-subtle)',
      }}
    >
      {title ? (
        <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-secondary)' }}>
          {title}
        </div>
      ) : null}
      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', maxWidth: 420 }}>
        {message}
      </div>
    </div>
  );
}

// CHART_TITLE_STYLE now comes from components/ui/chartGrammar.js and is
// re-exported at the top of this file.
