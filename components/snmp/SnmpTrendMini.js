'use client';

import { LineChart, Line, XAxis, Tooltip, ResponsiveContainer } from 'recharts';

// Compact version of SnmpMetricsCharts.js's two-chart layout (CPU/Memory
// share a 0-100% scale, session count does not -- same reasoning: a shared
// axis keeps each chart's y-axis honest, never a misleading secondary
// scale), sized for embedding inside the always-visible SNMP Monitoring
// summary card on the device Overview tab rather than a dedicated full
// page. No Y axis, no gridlines, minimal X axis -- this is a glanceable
// trend indicator sitting under the current-value StatCard tiles, not a
// replacement for the full /devices/[id]/snmp page's detailed charts
// (which keep their full axes/gridlines/220px height, untouched).
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

// ⛔ A poll that could not read a metric stores NULL -- which is not zero and
// not a measurement. Draw it hueless (--unmeasured), never in the same colour
// as a real reading. Same tri-state rule as firewall_rules.hit_count.
function MetricValue({ value, unit = '' }) {
  if (value === null || value === undefined) {
    return <span style={{ color: 'var(--unmeasured)' }}>—</span>;
  }
  return (
    <>
      {value}
      {unit}
    </>
  );
}

function formatFullTimestamp(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

function formatAxisTick(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  return d.toISOString().slice(11, 16);
}

function UsageTooltip({ active, payload }) {
  if (!active || !payload || !payload.length) return null;
  const point = payload[0].payload;
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '6px 10px', fontSize: 11 }}>
      <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
        CPU <MetricValue value={point.cpu_percent} unit="%" /> · Memory{' '}
        <MetricValue value={point.memory_percent} unit="%" />
      </div>
      <div style={{ color: 'var(--text-muted)' }}>{formatFullTimestamp(point.sampled_at)}</div>
    </div>
  );
}

function SessionTooltip({ active, payload }) {
  if (!active || !payload || !payload.length) return null;
  const point = payload[0].payload;
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '6px 10px', fontSize: 11 }}>
      <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
        <MetricValue value={point.session_count} /> sessions
      </div>
      <div style={{ color: 'var(--text-muted)' }}>{formatFullTimestamp(point.sampled_at)}</div>
    </div>
  );
}

// points: [{ cpu_percent, memory_percent, session_count, sampled_at }],
// oldest-to-newest (same convention as SnmpMetricsCharts.js). Renders
// nothing (returns null) when there are fewer than 2 points -- a single
// snapshot can't show a trend, and the caller's StatCard tiles already
// cover the "just one number" case.
export default function SnmpTrendMini({ points }) {
  const data = Array.isArray(points) ? points : [];
  if (data.length < 2) return null;

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12, marginTop: 12 }}>
      <div>
        <div style={{ marginBottom: 4, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>CPU / Memory trend</div>
        <div style={{ width: '100%', height: 90 }}>
          <ResponsiveContainer>
            <LineChart data={data} margin={{ top: 4, right: 4, left: 4, bottom: 0 }}>
              <XAxis
                dataKey="sampled_at"
                tickFormatter={formatAxisTick}
                tick={{ fill: 'var(--text-muted)', fontSize: 10 }}
                axisLine={{ stroke: 'var(--border)' }}
                tickLine={false}
                minTickGap={40}
              />
              <Tooltip cursor={{ stroke: 'var(--border)' }} content={<UsageTooltip />} />
              {/* ⛔ connectNulls={false}, deliberately. With it on, a poll
                  cycle that returned NULL was bridged by a straight
                  interpolated segment, pixel-identical to the real samples
                  either side — an invented reading where a measurement
                  failed. That is hit_count's old DEFAULT 0 rendered in a
                  chart. The gap is now visibly a gap; a broken line here means
                  the poll did not answer, and that is the true shape of the
                  data. */}
              <Line type="monotone" dataKey="cpu_percent" stroke={CPU_COLOR} strokeWidth={1.5} dot={false} activeDot={{ r: 4 }} isAnimationActive={false} connectNulls={false} />
              <Line type="monotone" dataKey="memory_percent" stroke={MEM_COLOR} strokeWidth={1.5} dot={false} activeDot={{ r: 4 }} isAnimationActive={false} connectNulls={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div>
        <div style={{ marginBottom: 4, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Sessions trend</div>
        <div style={{ width: '100%', height: 90 }}>
          <ResponsiveContainer>
            <LineChart data={data} margin={{ top: 4, right: 4, left: 4, bottom: 0 }}>
              <XAxis
                dataKey="sampled_at"
                tickFormatter={formatAxisTick}
                tick={{ fill: 'var(--text-muted)', fontSize: 10 }}
                axisLine={{ stroke: 'var(--border)' }}
                tickLine={false}
                minTickGap={40}
              />
              <Tooltip cursor={{ stroke: 'var(--border)' }} content={<SessionTooltip />} />
              <Line type="monotone" dataKey="session_count" stroke={SESSION_COLOR} strokeWidth={1.5} dot={false} activeDot={{ r: 4 }} isAnimationActive={false} connectNulls={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
