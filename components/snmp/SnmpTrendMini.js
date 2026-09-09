'use client';

import { LineChart, Line, XAxis, Tooltip, ResponsiveContainer } from 'recharts';
import {
  AXIS_TICK,
  AXIS_LINE,
  LINE_PROPS,
  TOOLTIP_CURSOR,
  TooltipShell,
  TooltipMetric,
  TooltipMeta,
  SeriesKey,
  ChartEmpty,
  utcHourMinute,
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

// Compact version of SnmpMetricsCharts.js's two-chart layout (CPU/Memory
// share a 0-100% scale, session count does not -- same reasoning: a shared
// axis keeps each chart's y-axis honest, never a misleading secondary
// scale), sized for embedding inside the always-visible SNMP Monitoring
// summary card on the device Overview tab rather than a dedicated full
// page. No Y axis, no gridlines, minimal X axis -- this is a glanceable
// trend indicator sitting under the current-value StatCard tiles, not a
// replacement for the full /devices/[id]/snmp page's detailed charts
// (which keep their full axes/gridlines/220px height).
//
// Axis ticks, tooltip and line geometry come from ./chartGrammar so this
// sparkline and the full page's charts are the same instrument at two sizes.
//
// Series colours are design TOKENS handed straight to the SVG presentation
// attributes recharts renders (stroke/fill) -- not hexes resolved out of
// getComputedStyle. That older pattern needed a hardcoded hex fallback for the
// SSR pass, and those fallbacks had already drifted off the very tokens they
// named: a literal opts a chart out of both the token layer and dark mode, in
// the one code path nobody ever looks at.
// ⛔ --red/--blue here are SERIES colours, not severity -- they exist only to
// tell the CPU line from the Memory line, and they match the CPU/Memory
// StatCard tiles this trend sits directly under (devices/[id]/page.js).
const CPU_COLOR = 'var(--red)';
const MEM_COLOR = 'var(--blue)';
const SESSION_COLOR = 'var(--accent-teal)';

const CPU_MEM_KEY = [
  { label: 'CPU %', color: CPU_COLOR },
  { label: 'Memory %', color: MEM_COLOR },
];

// ⛔ A poll that could not read a metric stores NULL -- which is not zero and
// not a measurement. The tooltip renders it through NotMeasured (via
// TooltipMetric) with this reason, never as a 0 and never as a bare dash.
const NO_READING = 'The poll ran but this device did not return this metric.';

// ⛔ PROVENANCE IS SHOWN HERE, identically to the full SNMP page (fixed
// 2026-09-09). It used to be absent — not because the data lacked it, but
// because getRecentSnmpHistory() selected only the four value columns, so this
// summary drew every sample as equally trustworthy and carried a caption
// pointing at the full page instead. The Overview query now selects
// `source`/`low_confidence` too, and the marks, their key and the tooltip's
// provenance line all come from the SHARED ./chartGrammar vocabulary — the same
// components the full page uses, not a second copy at sparkline size. The two
// views therefore cannot disagree about the same sample.
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

const MINI_LABEL = { marginBottom: 'var(--s1)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' };

// points: [{ cpu_percent, memory_percent, session_count, sampled_at, source,
// low_confidence }], oldest-to-newest (same convention as SnmpMetricsCharts.js). Renders
// nothing (returns null) when there are fewer than 2 points -- a single
// snapshot can't show a trend, and the caller's StatCard tiles already
// cover the "just one number" case.
export default function SnmpTrendMini({ points }) {
  const rows = Array.isArray(points) ? points : [];
  if (rows.length < 2) return null;

  // ⛔ A failed poll stores NO ROW at all, so a polling outage arrives here as
  // an absence rather than a null — and on a categorical axis an absence is
  // invisible, drawn as one ordinary step. See withPollingGaps()'s own comment.
  const data = withPollingGaps(rows, 'sampled_at', [
    'cpu_percent',
    'memory_percent',
    'session_count',
  ]);
  const gaps = countPollingGaps(data);

  // ⛔ Two lines drawn from all-null data render as an empty box, which reads
  // as "measured, and flat at nothing". Say which metric was never returned.
  // Measured over the REAL rows, never the synthetic gap fillers.
  const usageMissing = allNull(rows, ['cpu_percent', 'memory_percent']);
  const sessionsMissing = allNull(rows, ['session_count']);

  // Same tally, same key wording, same marks as the full SNMP page. Counted
  // over the REAL rows, never the synthetic gap fillers.
  const { qualified, unknown } = countConfidence(rows);

  return (
    <div style={{ marginTop: 'var(--s3)', display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 'var(--s3)' }}>
        <div>
          <div style={MINI_LABEL}>CPU / Memory trend</div>
          {usageMissing ? (
            <ChartEmpty
              height={90}
              message={`None of the last ${rows.length} polls returned a CPU or memory reading.`}
            />
          ) : (
            <>
              {/* ⛔ Two series need a key. A 90px sparkline has no room for a
                  recharts <Legend/>, so the shared compact SeriesKey does the
                  same job — two unlabelled coloured lines is a guess, not a
                  chart. */}
              <SeriesKey items={CPU_MEM_KEY} />
              <div style={{ width: '100%', height: 90 }}>
                <ResponsiveContainer>
                  <LineChart data={data} margin={{ top: 4, right: 4, left: 4, bottom: 0 }}>
                    <XAxis
                      dataKey="sampled_at"
                      tickFormatter={utcHourMinute}
                      tick={AXIS_TICK}
                      axisLine={AXIS_LINE}
                      tickLine={false}
                      minTickGap={40}
                    />
                    <Tooltip cursor={TOOLTIP_CURSOR} content={<UsageTooltip />} />
                    {/* ⛔ connectNulls={false} (in LINE_PROPS), deliberately. With
                        it on, a poll cycle that returned NULL was bridged by a
                        straight interpolated segment, pixel-identical to the real
                        samples either side — an invented reading where a
                        measurement failed. That is hit_count's old DEFAULT 0
                        rendered in a chart. The gap is now visibly a gap. */}
                    {/* ⛔ dot={<ConfidenceDot/>}, not dot={false}. A sparkline
                        that hides provenance implies every sample is equally
                        trustworthy — the quiet form of the failed-read-as-a-fact
                        bug. Same element, same geometry as the full page. */}
                    <Line {...LINE_PROPS} strokeWidth={1.5} dataKey="cpu_percent" name="CPU %" stroke={CPU_COLOR} dot={<ConfidenceDot color={CPU_COLOR} />} activeDot={{ r: 4 }} />
                    <Line {...LINE_PROPS} strokeWidth={1.5} dataKey="memory_percent" name="Memory %" stroke={MEM_COLOR} dot={<ConfidenceDot color={MEM_COLOR} />} activeDot={{ r: 4 }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </>
          )}
        </div>

        <div>
          <div style={MINI_LABEL}>Sessions trend</div>
          {sessionsMissing ? (
            <ChartEmpty
              height={90}
              message={`None of the last ${rows.length} polls returned a session count — not the same as nobody being connected.`}
            />
          ) : (
            <div style={{ width: '100%', height: 90 }}>
              <ResponsiveContainer>
                <LineChart data={data} margin={{ top: 4, right: 4, left: 4, bottom: 0 }}>
                  <XAxis
                    dataKey="sampled_at"
                    tickFormatter={utcHourMinute}
                    tick={AXIS_TICK}
                    axisLine={AXIS_LINE}
                    tickLine={false}
                    minTickGap={40}
                  />
                  <Tooltip cursor={TOOLTIP_CURSOR} content={<SessionTooltip />} />
                  {/* Single series — no key, by the shared grammar. */}
                  <Line {...LINE_PROPS} strokeWidth={1.5} dataKey="session_count" name="Sessions" stroke={SESSION_COLOR} dot={<ConfidenceDot color={SESSION_COLOR} />} activeDot={{ r: 4 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* One key for both sparklines — they are drawn from the same rows, so a
          per-chart copy would just say the same sentence twice. Renders nothing
          at all when every sample is a plain measurement (ConfidenceKey's own
          rule: no key for a distinction the reader cannot see on screen). */}
      <ConfidenceKey qualified={qualified} unknown={unknown} total={rows.length} />

      <PollingGapNote gaps={gaps} />
    </div>
  );
}
