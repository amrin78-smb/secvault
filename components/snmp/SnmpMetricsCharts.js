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
  ConfidenceDot,
  ConfidenceKey,
  ConfidenceTooltipMeta,
  countConfidence,
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

// ── ⛔ PER-SAMPLE CONFIDENCE lives in ./chartGrammar. ────────────────────────
// sampleConfidence / ConfidenceDot / ConfidenceKey / ConfidenceTooltipMeta were
// defined in this file until 2026-09-09, when the device Overview sparkline
// (SnmpTrendMini.js) gained the same marks and the pair had to be ONE
// vocabulary rather than two copies that could drift apart about the same
// sample. The tri-state rules, the three marks and the "one path per series"
// caveat are documented there, above sampleConfidence(). This file only decides
// WHICH SERIES COLOUR each dot gets.
//
// The caller selects `source` and `low_confidence` PER ROW (getSnmpHistory in
// devices/[id]/snmp/page.js); the Overview's getRecentSnmpHistory now selects
// them too, which is what made the shared treatment possible.

// ⛔ A poll that could not read a metric stores NULL -- which is not zero and
// not a measurement. Rendered through NotMeasured with a reason, never in the
// same colour as a real reading. Same tri-state rule as firewall_rules.hit_count.
const NO_READING = 'The poll ran but this device did not return this metric.';

function UsageTooltip({ active, payload }) {
  if (!active || !payload || !payload.length) return null;
  const point = payload[0].payload;
  if (point && point.__gap) return <GapTooltipBody point={point} />;
  return (
    <TooltipShell>
      <TooltipMetric color={CPU_COLOR} label="CPU" value={point.cpu_percent} unit="%" reason={NO_READING} />
      <TooltipMetric color={MEM_COLOR} label="Memory" value={point.memory_percent} unit="%" reason={NO_READING} />
      <TooltipMeta>{utcFull(point.sampled_at)}</TooltipMeta>
      {/* ⛔ Provenance travels with the sample, not with the device. */}
      <ConfidenceTooltipMeta point={point} />
    </TooltipShell>
  );
}

function SessionTooltip({ active, payload }) {
  if (!active || !payload || !payload.length) return null;
  const point = payload[0].payload;
  if (point && point.__gap) return <GapTooltipBody point={point} />;
  return (
    <TooltipShell>
      <TooltipMetric
        color={SESSION_COLOR}
        label="Sessions"
        value={point.session_count}
        reason="The poll ran but this device did not report a session count."
      />
      <TooltipMeta>{utcFull(point.sampled_at)}</TooltipMeta>
      <ConfidenceTooltipMeta point={point} />
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

  // Counted over the REAL rows, never the synthetic gap fillers.
  const { qualified, unknown } = countConfidence(rows);

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
