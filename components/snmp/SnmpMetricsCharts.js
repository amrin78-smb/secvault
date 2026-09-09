'use client';

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import Card, { CardBody } from '../ui/Card';

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

function formatAxisTick(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  return d.toISOString().slice(0, 16).replace('T', ' ');
}

function formatFullTimestamp(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

function UsageTooltip({ active, payload }) {
  if (!active || !payload || !payload.length) return null;
  const point = payload[0].payload;
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '6px 10px', fontSize: 12 }}>
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
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '6px 10px', fontSize: 12 }}>
      <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
        <MetricValue value={point.session_count} /> sessions
      </div>
      <div style={{ color: 'var(--text-muted)' }}>{formatFullTimestamp(point.sampled_at)}</div>
    </div>
  );
}

// points: [{ cpu_percent, memory_percent, session_count, uptime_seconds, sampled_at }],
// already ordered oldest-to-newest by the caller's query — same convention
// as VpnSessionTrendChart. Two separate charts (CPU/Memory share a 0-100%
// scale; session count does not) rather than one dual-axis chart, to keep
// each chart's y-axis honest without a secondary-axis reading trap.
//
// ⛔ NOT FIXED HERE, flagged: the caller's query selects source and
// low_confidence PER SAMPLE (see getSnmpHistory in devices/[id]/snmp/page.js),
// but this chart ignores both and draws every point in the same colour. A
// generic-MIB reading with no vendor-specific source is therefore pixel-
// identical to a management-transport reading, and the page's "Low
// confidence" badge only describes the LATEST sample -- so a history that
// mixes the two reads as one uniform, equally-trustworthy line. Distinguishing
// them needs a per-point mark, not a palette change, so it is out of scope for
// this pass; --unmeasured/--hatch are the tokens for it when it is done.
export default function SnmpMetricsCharts({ points }) {
  const data = Array.isArray(points) ? points : [];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
      <Card>
        <CardBody>
          <div style={{ marginBottom: 12, fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
            CPU / Memory Utilization (%)
          </div>
          <div style={{ width: '100%', height: 220 }}>
            <ResponsiveContainer>
              <LineChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                <XAxis
                  dataKey="sampled_at"
                  tickFormatter={formatAxisTick}
                  tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
                  axisLine={{ stroke: 'var(--border)' }}
                  tickLine={false}
                  minTickGap={40}
                />
                <YAxis
                  domain={[0, 100]}
                  tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
                  axisLine={{ stroke: 'var(--border)' }}
                  tickLine={false}
                  width={32}
                />
                <Tooltip cursor={{ stroke: 'var(--border)' }} content={<UsageTooltip />} />
                {/* ⛔ connectNulls={false}, deliberately. With it on, a poll
                    cycle that returned NULL was bridged by a straight
                    interpolated segment, pixel-identical to the real samples
                    either side — an invented reading where a measurement
                    failed. That is hit_count's old DEFAULT 0 rendered in a
                    chart. The gap is now visibly a gap; a broken line here
                    means the poll did not answer, and that is the true shape
                    of the data. */}
                <Line type="monotone" dataKey="cpu_percent" name="CPU %" stroke={CPU_COLOR} strokeWidth={2} dot={{ r: 2, fill: CPU_COLOR, strokeWidth: 0 }} activeDot={{ r: 5 }} isAnimationActive={false} connectNulls={false} />
                <Line type="monotone" dataKey="memory_percent" name="Memory %" stroke={MEM_COLOR} strokeWidth={2} dot={{ r: 2, fill: MEM_COLOR, strokeWidth: 0 }} activeDot={{ r: 5 }} isAnimationActive={false} connectNulls={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardBody>
          <div style={{ marginBottom: 12, fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
            Active Sessions (polled)
          </div>
          <div style={{ width: '100%', height: 220 }}>
            <ResponsiveContainer>
              <LineChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                <XAxis
                  dataKey="sampled_at"
                  tickFormatter={formatAxisTick}
                  tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
                  axisLine={{ stroke: 'var(--border)' }}
                  tickLine={false}
                  minTickGap={40}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
                  axisLine={{ stroke: 'var(--border)' }}
                  tickLine={false}
                  width={32}
                />
                <Tooltip cursor={{ stroke: 'var(--border)' }} content={<SessionTooltip />} />
                <Line type="monotone" dataKey="session_count" name="Sessions" stroke={SESSION_COLOR} strokeWidth={2} dot={{ r: 2, fill: SESSION_COLOR, strokeWidth: 0 }} activeDot={{ r: 5 }} isAnimationActive={false} connectNulls={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
