'use client';

// Compliance score over time — the view for lib/engines/complianceTrend.js.
//
// ⛔ 'use client' ONLY BECAUSE RECHARTS FORCES IT. recharts touches the DOM and
// cannot render in a server component; every other chart in this repo
// (components/dashboard/VulnerabilityTrendChart.js, the analysis charts) is a
// client component for exactly this reason. Nothing else here needs a browser:
// there is no state, no effect and no event handler in this file, and the
// numbers are all computed by the pure engine before anything renders, which
// is what keeps them testable.
//
// ⛔ ALL JUDGEMENT LIVES IN THE ENGINE, NOT HERE. The window label, the gap
// counts, the deltas and every "we could not measure this" sentence come from
// lib/engines/complianceTrend.js, which is pure and exhaustively tested
// (tests/complianceTrend.test.js). A view that recomputed any of them would be
// a second opinion that could disagree with the first — and the one that
// disagreed would be the one on screen.

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import NotMeasured from '../ui/NotMeasured';
import {
  AXIS_TICK,
  GRID_PROPS,
  X_AXIS_PROPS,
  TOOLTIP_CURSOR_LINE,
  LEGEND_PROPS,
  ChartTooltip,
  ChartNotMeasured,
} from '../analysis/chartGrammar';
import {
  buildComplianceTrend,
  seriesStatus,
  pointReason,
  TREND_CLAIM,
  STANDARD_LABELS,
  OVERALL_KEY,
} from '../../lib/engines/complianceTrend';

// ── Colour ───────────────────────────────────────────────────────────────
//
// ⛔ NO CATEGORICAL RAINBOW, AND THAT IS A RULE RATHER THAN A PREFERENCE.
// Six series would normally get six hues. This palette forbids it three times
// over, and every one of those refusals matters more than legibility would
// have gained:
//
//   * CLAUDE.md's "Colour means RISK": red is reserved for danger and the
//     --sev-* ramp is a severity claim. PCI DSS is not a severity. Drawing it
//     in --sev-crit would say the fleet's PCI line IS the critical one.
//   * Violet is the EVIDENCE axis and nothing else in this product may use it
//     ("the moment a second thing uses it, the mark stops being learnable").
//   * v2.215.0 measured this product spending its colour across five families
//     with no dominant, against a comparator putting 85% in one. More hue
//     families here would walk straight back into that.
//
// So every line sits in the ONE cool family the brand already owns — teal,
// blue and the deliberate slate of --sev-low — and the two repeats are
// separated by a DASH PATTERN rather than by a sixth hue. Dash is a safe
// second channel here precisely because it carries no meaning anywhere else in
// this product, so it cannot be misread as a status.
//
// ⛔ Tokens, never hex. A literal would not flip with the theme, and these
// strokes are SVG presentation attributes resolved against the live theme on
// every paint (see the long note at the top of components/ui/chartGrammar.js).
const OVERALL_SERIES = {
  key: OVERALL_KEY,
  label: 'Overall',
  color: 'var(--primary)',
  strokeWidth: 2.5,
  dash: undefined,
};

const STANDARD_SERIES = [
  { key: 'PCI_DSS', color: 'var(--blue)', dash: undefined },
  { key: 'ISO_27001', color: 'var(--teal)', dash: undefined },
  { key: 'CIS_V8', color: 'var(--sev-low)', dash: undefined },
  { key: 'NIST', color: 'var(--blue)', dash: '6 4' },
  { key: 'SANS', color: 'var(--sev-low)', dash: '6 4' },
].map((s) => ({ ...s, label: STANDARD_LABELS[s.key], strokeWidth: 1.5 }));

const ALL_SERIES = [OVERALL_SERIES, ...STANDARD_SERIES];

// ⛔ A FIXED 0-100 DOMAIN, NEVER recharts' AUTO-FIT. A score is a percentage of
// a known whole, so the axis is known before the data arrives. Auto-fitting
// would scale a 71→73 fortnight to the full height of the card and draw a
// two-point wobble as a dramatic climb — the chart equivalent of a confident
// number built from nothing, and the reader has no way to see it happened.
const PCT_AXIS_PROPS = {
  tick: AXIS_TICK,
  axisLine: false,
  tickLine: false,
  domain: [0, 100],
  ticks: [0, 25, 50, 75, 100],
  allowDecimals: false,
  tickFormatter: (v) => `${v}%`,
  width: 44,
};

function formatDay(value) {
  if (!value) return '';
  const d = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(d.getTime())) return '';
  return d.toISOString().slice(5, 10); // MM-DD
}

// Module top level, never nested inside the component — CLAUDE.md's React
// rule: a component defined inside another remounts on every render.
function TrendTooltip(props) {
  // recharts clones this element with the hovered payload. The ORIGINAL row is
  // on payload[0].payload, which is what carries `states` and therefore which
  // KIND of absence this day is. ChartTooltip takes one reason string, so the
  // reason is resolved per hovered day here rather than hardcoded once — "no
  // snapshot was recorded" and "nothing was gradeable" are the two sentences
  // this whole feature exists to keep apart, and a static string would print
  // one of them over both.
  const point = props && Array.isArray(props.payload) && props.payload.length > 0 ? props.payload[0].payload : null;
  const reason = point ? pointReason(point, OVERALL_KEY) : 'No reading for this day.';
  return (
    <ChartTooltip
      {...props}
      labelFormatter={formatDay}
      valueFormatter={(v) => `${Number(v)}%`}
      unmeasuredReason={reason}
    />
  );
}

const CAPTION_STYLE = {
  fontSize: 'var(--text-xs)',
  color: 'var(--text-muted)',
  fontVariantNumeric: 'tabular-nums',
};

const CLAIM_STYLE = {
  fontSize: 'var(--text-xs)',
  color: 'var(--text-muted)',
  margin: 0,
  maxWidth: '72ch',
};

const PROSE_STYLE = {
  fontSize: 'var(--text-sm)',
  color: 'var(--text-secondary)',
  margin: 0,
};

const NO_DELTA_REASONS = {
  no_readings: 'No readable score in this window, so there is nothing to compare — this is not an unchanged score.',
  single_reading: 'Only one readable score in this window. A change needs two readings; one is not a trend.',
};

// A delta is a number OR an explicit statement that it could not be computed.
// ⛔ Never 0 for "we could not tell": a zero here reads as "compliance has not
// moved", which is a measurement, and the whole point is that nothing was
// measured.
function DeltaValue({ delta }) {
  if (!delta || delta.value === null) {
    return <NotMeasured reason={NO_DELTA_REASONS[delta && delta.reason] || 'No change could be computed.'} />;
  }
  const sign = delta.value > 0 ? '+' : '';
  return (
    <span style={{ fontVariantNumeric: 'tabular-nums' }}>
      {sign}
      {delta.value} pts
      {/* ⛔ The span travels with the number, always. "+6 pts" over 3 days and
          over 3 months are different claims and look identical without it. */}
      <span style={{ color: 'var(--text-muted)' }}> over {delta.spanDays}d</span>
    </span>
  );
}

function ScoreValue({ score, reason }) {
  if (score === null || score === undefined) return <NotMeasured reason={reason} />;
  return <span style={{ fontVariantNumeric: 'tabular-nums' }}>{score}%</span>;
}

const CELL = {
  padding: 'var(--s2) var(--s3)',
  borderBottom: '1px solid var(--border-light)',
  fontSize: 'var(--text-sm)',
  textAlign: 'left',
};
const HEAD_CELL = { ...CELL, color: 'var(--text-muted)', fontWeight: 500, fontSize: 'var(--text-xs)' };

// ⛔ THE PER-STANDARD TABLE IS NOT A DUPLICATE OF THE CHART, IT IS WHAT THE
// CHART CANNOT SAY. Five lines in one cool hue family are legible as a shape
// and not as five precise values, and three of the five standards on the
// reference fleet can be null for long stretches (27 of the 74 seeded checks
// are not_evaluable_from_config, and two standards have a single gradeable
// check). So the exact latest score, the change, how many readings it rests on
// and which kind of gap it has are stated as text, per standard, where they
// cannot be misread off a stroke.
function StandardRows({ trend }) {
  return (
    <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
      <colgroup>
        <col style={{ width: '26%' }} />
        <col style={{ width: '16%' }} />
        <col style={{ width: '24%' }} />
        <col style={{ width: '34%' }} />
      </colgroup>
      <thead>
        <tr>
          <th style={HEAD_CELL}>Standard</th>
          <th style={HEAD_CELL}>Latest</th>
          <th style={HEAD_CELL}>Change</th>
          <th style={HEAD_CELL}>Readings and gaps</th>
        </tr>
      </thead>
      <tbody>
        {[OVERALL_SERIES, ...STANDARD_SERIES].map((s) => {
          const sum = s.key === OVERALL_KEY ? trend.summary.overall : trend.summary.byStandard[s.key];
          const delta = s.key === OVERALL_KEY ? trend.delta.overall : trend.delta.byStandard[s.key];
          const status = seriesStatus(sum);
          return (
            <tr key={s.key}>
              <th scope="row" style={{ ...CELL, fontWeight: s.key === OVERALL_KEY ? 600 : 400 }}>
                <span
                  aria-hidden="true"
                  style={{
                    display: 'inline-block',
                    width: 14,
                    height: 0,
                    marginRight: 'var(--s2)',
                    verticalAlign: 'middle',
                    borderTop: `${s.strokeWidth}px ${s.dash ? 'dashed' : 'solid'} ${s.color}`,
                  }}
                />
                {s.label}
              </th>
              <td style={CELL}>
                <ScoreValue
                  score={sum.latest ? sum.latest.score : null}
                  reason={
                    status === 'none'
                      ? 'No readable score for this standard anywhere in this window.'
                      : 'No reading for this standard.'
                  }
                />
              </td>
              <td style={CELL}>
                <DeltaValue delta={delta} />
              </td>
              <td style={{ ...CELL, color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
                {/* ⛔ The two gaps are printed as two counts and never summed.
                    "Never recorded" is an engine problem (a lost nightly
                    tick); "nothing gradeable" is a compliance-coverage
                    problem. One combined number sends the operator nowhere. */}
                {sum.readings} reading{sum.readings === 1 ? '' : 's'}
                {sum.notRecorded > 0 ? ` · ${sum.notRecorded} never recorded` : ''}
                {sum.unmeasurable > 0 ? ` · ${sum.unmeasurable} nothing gradeable` : ''}
                {sum.unreadable > 0 ? ` · ${sum.unreadable} unreadable` : ''}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

/**
 * @param {object[]} rows  Raw fleet_dashboard_snapshots rows: snapshot_date,
 *   compliance_overall_score, compliance_by_standard. Any order.
 * @param {number} [requestedDays]  How many days the caller's query ASKED for.
 *   Used only to say so beside what actually exists; it never pads or trims.
 *
 * A caller that also wants these numbers outside the chart calls
 * buildComplianceTrend() itself — it is pure, cheap and deterministic, so two
 * calls on the same rows cannot disagree.
 */
export default function ComplianceTrendChart({ rows, requestedDays }) {
  const trend = buildComplianceTrend(rows, { requestedDays });

  // ⛔ NO ALL-CLEAR FROM AN ABSENT SERIES. An empty plot with axes on it reads
  // as a flat, unchanging score — the strongest possible reassurance drawn
  // from no evidence at all. The engine's own sentence is rendered instead,
  // and it distinguishes "the job has never run" from "the read failed".
  if (!trend.available) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
        <ChartNotMeasured reason={trend.unavailableReason} height={200} />
        <p style={CLAIM_STYLE}>{TREND_CLAIM}</p>
      </div>
    );
  }

  const plottable = ALL_SERIES.filter((s) => {
    const sum = s.key === OVERALL_KEY ? trend.summary.overall : trend.summary.byStandard[s.key];
    return seriesStatus(sum) === 'plotted';
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
      {/* ⛔ VISIBLE, NOT A TOOLTIP. The window covered, the number of real
          snapshots behind it, and each kind of gap. A 3-day window and a
          90-day window draw identically; the only thing that tells them apart
          is this line, so it cannot be something the reader has to hover to
          find. */}
      <span style={CAPTION_STYLE}>{trend.caption}</span>

      {plottable.length === 0 ? (
        // Two or more readable points are needed before a line means anything.
        // Say that, rather than drawing an axis with nothing on it.
        <ChartNotMeasured
          reason={
            trend.summary.overall.readings === 1
              ? 'Only one day in this window carries a readable score, so there is nothing to draw a line between yet.'
              : 'No day in this window carries a readable compliance score, so there is nothing to plot. This is a gap in the history, not a score of zero.'
          }
          height={200}
        />
      ) : (
        <div style={{ width: '100%', height: 220 }}>
          <ResponsiveContainer>
            {/* ⛔ `left: 0`, NOT A NEGATIVE MARGIN. At `left: -10` the YAxis'
                44px of label space became 34, and "100%" rendered CLIPPED as
                "00%" — an axis top that reads as zero on a chart whose whole
                point is a percentage. Found by looking at the rendered page;
                nothing in the build or the test suite can see it. */}
            <LineChart data={trend.points} margin={{ top: 6, right: 8, bottom: 0, left: 0 }}>
              <CartesianGrid {...GRID_PROPS} />
              <XAxis {...X_AXIS_PROPS} dataKey="day" tickFormatter={formatDay} minTickGap={24} />
              <YAxis {...PCT_AXIS_PROPS} />
              <Tooltip cursor={TOOLTIP_CURSOR_LINE} content={<TrendTooltip />} />
              {/* Six series that cannot be told apart without one. */}
              <Legend {...LEGEND_PROPS} />
              {plottable.map((s) => (
                <Line
                  key={s.key}
                  type="monotone"
                  dataKey={s.key}
                  name={s.label}
                  stroke={s.color}
                  strokeWidth={s.strokeWidth}
                  strokeDasharray={s.dash}
                  dot={false}
                  isAnimationActive={false}
                  /* ⛔ connectNulls={false}, WRITTEN OUT HERE even though
                     chartGrammar's LINE_PROPS already carries it. This is the
                     single property that decides whether the four nightly
                     snapshots the reference deployment permanently lost
                     (2026-10-11, -12, -13, -15) appear as the holes they are
                     or are bridged by a straight interpolated segment that is
                     pixel-identical to a real measurement. A day with no
                     reading carries null from the engine; with connectNulls on
                     recharts would draw straight over it and the chart would
                     assert a compliance score for four days nobody measured.
                     It is restated locally so that a future edit to the shared
                     constant cannot silently turn it on here. */
                  connectNulls={false}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      <StandardRows trend={trend} />

      {trend.unrecognisedStandards.length > 0 ? (
        // A standard present in the stored JSON that this engine does not know
        // is reported rather than dropped: the writer
        // (lib/engines/dashboardSnapshot.js) and this reader each carry their
        // own copy of the standard list, so a divergence between them has to
        // be visible or a whole standard's history disappears in silence.
        <p style={{ ...PROSE_STYLE, color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
          Not charted — this history also holds {trend.unrecognisedStandards.join(', ')}, which this view does not
          recognise.
        </p>
      ) : null}

      <p style={CLAIM_STYLE}>{TREND_CLAIM}</p>
    </div>
  );
}
