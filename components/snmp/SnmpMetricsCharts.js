'use client';

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import Card, { CardBody } from '../ui/Card';
import {
  AXIS_TICK,
  AXIS_LINE,
  GRID_PROPS,
  LEGEND_PROPS,
  LINE_PROPS,
  TOOLTIP_CURSOR,
  TooltipShell,
  TooltipMetric,
  TooltipMeta,
  ChartEmpty,
  CHART_TITLE_STYLE,
  utcMinute,
  utcFull,
  withPollingGaps,
  countPollingGaps,
  PollingGapNote,
  GapTooltipBody,
} from './chartGrammar';

// Series colours are design TOKENS handed straight to the SVG presentation
// attributes recharts renders (stroke/fill). This replaced the older "resolve
// a CSS custom property through getComputedStyle, with a hardcoded hex
// fallback for the SSR pass" pattern: the fallbacks had already drifted off
// the very tokens they named, and a literal opts a chart out of both the token
// layer and dark mode in the one code path nobody ever looks at.
// ⛔ --red/--blue here are SERIES colours, not severity -- they exist only to
// tell the CPU line from the Memory line, and they match the CPU/Memory
// StatCard tiles on this same page (devices/[id]/snmp/page.js).
const CPU_COLOR = 'var(--red)';
const MEM_COLOR = 'var(--blue)';
const SESSION_COLOR = 'var(--accent-teal)';

// ── ⛔ PER-SAMPLE CONFIDENCE. Fixed 2026-09-09; read this before changing a dot.
//
// The caller selects `source` and `low_confidence` PER ROW (getSnmpHistory in
// devices/[id]/snmp/page.js) because confidence is a property of the SAMPLE,
// not of the vendor — a Palo Alto read over the management transport and a
// generic MIB-II guess can sit next to each other in one series. This chart
// used to draw both identically, and the page's "Low confidence" badge
// describes only the LATEST sample, so a history that MIXES the two rendered as
// one uniform, equally-trustworthy line. That is the failed-read-as-a-fact bug
// in its quietest form: nothing is missing, the line just claims more than the
// data supports.
//
// Three sample states, three marks:
//   measured   low_confidence === false  solid filled dot in the series colour
//   qualified  low_confidence === true   HOLLOW ring in the series colour —
//                                        a real reading from a generic MIB
//   unknown    low_confidence is NULL    hollow DASHED ring in --unmeasured —
//                                        a pre-v2.55.0 row whose provenance was
//                                        never recorded. Hueless on purpose:
//                                        we do not know that it is bad, only
//                                        that we cannot vouch for it.
//
// ⛔ STILL NOT FULLY SOLVED, and deliberately so: recharts draws ONE path per
// series, so the SEGMENT between a measured sample and a qualified one is
// still a single uniform stroke. Splitting the series into per-confidence
// sub-series would fix the segments and break the line into misleading
// fragments wherever confidence alternates. The per-sample DOT plus the tooltip
// plus the mix caption below carry the fact instead; the line carries only the
// shape. If this is ever revisited, the honest fix is a custom segment
// renderer, not a second <Line>.
function sampleConfidence(row) {
  if (!row) return 'unknown';
  if (row.low_confidence === true) return 'qualified';
  if (row.low_confidence === false) return 'measured';
  return 'unknown';
}

const CONFIDENCE_WORDS = {
  measured: 'read over the management transport / a vendor MIB',
  qualified: 'low confidence — generic MIB only',
  unknown: 'provenance not recorded for this sample (pre-v2.55.0)',
};

// Custom recharts dot. Module top level, passed as an ELEMENT — recharts
// cloneElement()s it with cx/cy/value/payload per point (see Dots.js).
// ⛔ Never define this inside the chart component (CLAUDE.md's React rule).
function ConfidenceDot(props) {
  const { cx, cy, value, payload, color } = props;
  // A null sample has no dot at all. connectNulls={false} already leaves the
  // gap; drawing a marker on the axis would put a point where no reading exists.
  if (!Number.isFinite(cx) || !Number.isFinite(cy)) return null;
  if (value === null || value === undefined) return null;
  const conf = sampleConfidence(payload);
  if (conf === 'measured') {
    return <circle cx={cx} cy={cy} r={2.5} fill={color} stroke="none" />;
  }
  return (
    <circle
      cx={cx}
      cy={cy}
      r={3.4}
      fill="var(--bg-card)"
      stroke={conf === 'unknown' ? 'var(--unmeasured)' : color}
      strokeWidth={1.5}
      strokeDasharray={conf === 'unknown' ? '2 2' : undefined}
    />
  );
}

// Key for the marks above. Rendered only when the history actually contains a
// non-measured sample — a key for a distinction the reader cannot see on screen
// is just noise.
function ConfidenceKey({ qualified, unknown, total }) {
  if (qualified === 0 && unknown === 0) return null;
  return (
    <div
      style={{
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        gap: 'var(--s3)',
        marginTop: 'var(--s2)',
        fontSize: 'var(--text-xs)',
        color: 'var(--text-muted)',
      }}
    >
      {qualified > 0 ? (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--s1)' }}>
          <svg width={12} height={12} aria-hidden="true">
            <circle cx={6} cy={6} r={3.4} fill="var(--bg-card)" stroke="var(--text-secondary)" strokeWidth={1.5} />
          </svg>
          {qualified} of {total} samples read from a generic MIB (low confidence)
        </span>
      ) : null}
      {unknown > 0 ? (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--s1)' }}>
          <svg width={12} height={12} aria-hidden="true">
            <circle
              cx={6}
              cy={6}
              r={3.4}
              fill="var(--bg-card)"
              stroke="var(--unmeasured)"
              strokeWidth={1.5}
              strokeDasharray="2 2"
            />
          </svg>
          {unknown} of {total} samples have no recorded provenance
        </span>
      ) : null}
    </div>
  );
}

// ⛔ A poll that could not read a metric stores NULL -- which is not zero and
// not a measurement. Rendered through NotMeasured with a reason, never in the
// same colour as a real reading. Same tri-state rule as firewall_rules.hit_count.
const NO_READING = 'The poll ran but this device did not return this metric.';

function UsageTooltip({ active, payload }) {
  if (!active || !payload || !payload.length) return null;
  const point = payload[0].payload;
  if (point && point.__gap) return <GapTooltipBody point={point} />;
  const conf = sampleConfidence(point);
  return (
    <TooltipShell>
      <TooltipMetric color={CPU_COLOR} label="CPU" value={point.cpu_percent} unit="%" reason={NO_READING} />
      <TooltipMetric color={MEM_COLOR} label="Memory" value={point.memory_percent} unit="%" reason={NO_READING} />
      <TooltipMeta>{utcFull(point.sampled_at)}</TooltipMeta>
      {/* ⛔ Provenance travels with the sample, not with the device. */}
      <TooltipMeta>
        {point.source ? `${point.source} — ` : ''}
        {CONFIDENCE_WORDS[conf]}
      </TooltipMeta>
    </TooltipShell>
  );
}

function SessionTooltip({ active, payload }) {
  if (!active || !payload || !payload.length) return null;
  const point = payload[0].payload;
  if (point && point.__gap) return <GapTooltipBody point={point} />;
  const conf = sampleConfidence(point);
  return (
    <TooltipShell>
      <TooltipMetric
        color={SESSION_COLOR}
        label="Sessions"
        value={point.session_count}
        reason="The poll ran but this device did not report a session count."
      />
      <TooltipMeta>{utcFull(point.sampled_at)}</TooltipMeta>
      <TooltipMeta>
        {point.source ? `${point.source} — ` : ''}
        {CONFIDENCE_WORDS[conf]}
      </TooltipMeta>
    </TooltipShell>
  );
}

function allNull(data, keys) {
  return data.every((row) => keys.every((k) => row[k] === null || row[k] === undefined));
}

// points: [{ cpu_percent, memory_percent, session_count, uptime_seconds,
// sampled_at, source, low_confidence }], already ordered oldest-to-newest by
// the caller's query — same convention as VpnSessionTrendChart. Two separate
// charts (CPU/Memory share a 0-100% scale; session count does not) rather than
// one dual-axis chart, to keep each chart's y-axis honest without a
// secondary-axis reading trap.
export default function SnmpMetricsCharts({ points }) {
  const rows = Array.isArray(points) ? points : [];

  // ⛔ A failed poll stores NO ROW, so a polling outage arrives here as an
  // absence, not a null — and on a categorical axis an absence is invisible.
  // withPollingGaps() turns it back into a visible break. See its own comment.
  const data = withPollingGaps(rows, 'sampled_at', [
    'cpu_percent',
    'memory_percent',
    'session_count',
  ]);
  const gaps = countPollingGaps(data);

  // ⛔ A chart frame with no line in it reads as "measured, and the answer is
  // flat". A device that is polled but never returns a CPU figure produced
  // exactly that: empty axes, no explanation. Count the states instead and say
  // which question went unanswered. Measured over the REAL rows, never the
  // synthetic gap fillers.
  const usageMissing = rows.length === 0 || allNull(rows, ['cpu_percent', 'memory_percent']);
  const sessionsMissing = rows.length === 0 || allNull(rows, ['session_count']);

  let qualified = 0;
  let unknown = 0;
  for (const row of rows) {
    const c = sampleConfidence(row);
    if (c === 'qualified') qualified += 1;
    else if (c === 'unknown') unknown += 1;
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 'var(--s4)' }}>
      <Card>
        <CardBody>
          <div style={CHART_TITLE_STYLE}>CPU / Memory Utilization (%)</div>
          {usageMissing ? (
            <ChartEmpty
              title="Not measured"
              message={
                rows.length === 0
                  ? 'No polls have been stored for this device yet, so there is no CPU or memory history to draw.'
                  : `${rows.length} poll${rows.length === 1 ? '' : 's'} were stored, but none returned a CPU or memory reading — this device or transport does not report them. That is a gap in what SecVault can read, not a measured zero.`
              }
            />
          ) : (
            <>
              <div style={{ width: '100%', height: 220 }}>
                <ResponsiveContainer>
                  <LineChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
                    <CartesianGrid {...GRID_PROPS} />
                    <XAxis
                      dataKey="sampled_at"
                      tickFormatter={utcMinute}
                      tick={AXIS_TICK}
                      axisLine={AXIS_LINE}
                      tickLine={false}
                      minTickGap={40}
                    />
                    <YAxis domain={[0, 100]} tick={AXIS_TICK} axisLine={AXIS_LINE} tickLine={false} width={32} />
                    <Tooltip cursor={TOOLTIP_CURSOR} content={<UsageTooltip />} />
                    {/* Two series, so a legend. */}
                    <Legend {...LEGEND_PROPS} />
                    {/* ⛔ connectNulls={false} (in LINE_PROPS), deliberately. With
                        it on, a poll cycle that returned NULL was bridged by a
                        straight interpolated segment, pixel-identical to the real
                        samples either side — an invented reading where a
                        measurement failed. That is hit_count's old DEFAULT 0
                        rendered in a chart. The gap is now visibly a gap. */}
                    <Line
                      {...LINE_PROPS}
                      dataKey="cpu_percent"
                      name="CPU %"
                      stroke={CPU_COLOR}
                      dot={<ConfidenceDot color={CPU_COLOR} />}
                      activeDot={{ r: 5 }}
                    />
                    <Line
                      {...LINE_PROPS}
                      dataKey="memory_percent"
                      name="Memory %"
                      stroke={MEM_COLOR}
                      dot={<ConfidenceDot color={MEM_COLOR} />}
                      activeDot={{ r: 5 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
              <ConfidenceKey qualified={qualified} unknown={unknown} total={rows.length} />
              <PollingGapNote gaps={gaps} />
            </>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardBody>
          <div style={CHART_TITLE_STYLE}>Active Sessions (polled)</div>
          {sessionsMissing ? (
            <ChartEmpty
              title="Not measured"
              message={
                rows.length === 0
                  ? 'No polls have been stored for this device yet, so there is no session history to draw.'
                  : `${rows.length} poll${rows.length === 1 ? '' : 's'} were stored, but none returned a session count — this device or transport does not report one. Not the same as "nobody was connected".`
              }
            />
          ) : (
            <>
              <div style={{ width: '100%', height: 220 }}>
                <ResponsiveContainer>
                  <LineChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
                    <CartesianGrid {...GRID_PROPS} />
                    <XAxis
                      dataKey="sampled_at"
                      tickFormatter={utcMinute}
                      tick={AXIS_TICK}
                      axisLine={AXIS_LINE}
                      tickLine={false}
                      minTickGap={40}
                    />
                    <YAxis allowDecimals={false} tick={AXIS_TICK} axisLine={AXIS_LINE} tickLine={false} width={32} />
                    <Tooltip cursor={TOOLTIP_CURSOR} content={<SessionTooltip />} />
                    {/* Single series — no legend, by the shared grammar. */}
                    <Line
                      {...LINE_PROPS}
                      dataKey="session_count"
                      name="Sessions"
                      stroke={SESSION_COLOR}
                      dot={<ConfidenceDot color={SESSION_COLOR} />}
                      activeDot={{ r: 5 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
              <ConfidenceKey qualified={qualified} unknown={unknown} total={rows.length} />
              <PollingGapNote gaps={gaps} />
            </>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
