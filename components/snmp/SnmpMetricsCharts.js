'use client';

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import Card, { CardBody } from '../ui/Card';

// Same "resolve a CSS custom property to its computed value at render time,
// with a hardcoded hex fallback for the SSR pass" pattern as
// components/vpn/VpnSessionTrendChart.js / components/analysis/RiskTrendChart.js.
const CPU_FALLBACK_HEX = '#dc2626'; // --red
const MEM_FALLBACK_HEX = '#2563eb'; // --blue
const SESSION_FALLBACK_HEX = '#0891b2'; // --accent-teal

function resolveColor(varName, fallback) {
  if (typeof window === 'undefined' || typeof document === 'undefined') return fallback;
  const value = getComputedStyle(document.documentElement).getPropertyValue(varName);
  return value ? value.trim() : fallback;
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
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: '6px 10px', fontSize: 12 }}>
      <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
        CPU {point.cpu_percent ?? '—'}% · Memory {point.memory_percent ?? '—'}%
      </div>
      <div style={{ color: 'var(--text-muted)' }}>{formatFullTimestamp(point.sampled_at)}</div>
    </div>
  );
}

function SessionTooltip({ active, payload }) {
  if (!active || !payload || !payload.length) return null;
  const point = payload[0].payload;
  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: '6px 10px', fontSize: 12 }}>
      <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{point.session_count ?? '—'} sessions</div>
      <div style={{ color: 'var(--text-muted)' }}>{formatFullTimestamp(point.sampled_at)}</div>
    </div>
  );
}

// points: [{ cpu_percent, memory_percent, session_count, uptime_seconds, sampled_at }],
// already ordered oldest-to-newest by the caller's query — same convention
// as VpnSessionTrendChart. Two separate charts (CPU/Memory share a 0-100%
// scale; session count does not) rather than one dual-axis chart, to keep
// each chart's y-axis honest without a secondary-axis reading trap.
export default function SnmpMetricsCharts({ points }) {
  const data = Array.isArray(points) ? points : [];
  const cpuColor = resolveColor('--red', CPU_FALLBACK_HEX);
  const memColor = resolveColor('--blue', MEM_FALLBACK_HEX);
  const sessionColor = resolveColor('--accent-teal', SESSION_FALLBACK_HEX);

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
                <Line type="monotone" dataKey="cpu_percent" name="CPU %" stroke={cpuColor} strokeWidth={2} dot={{ r: 2, fill: cpuColor, strokeWidth: 0 }} activeDot={{ r: 5 }} isAnimationActive={false} connectNulls />
                <Line type="monotone" dataKey="memory_percent" name="Memory %" stroke={memColor} strokeWidth={2} dot={{ r: 2, fill: memColor, strokeWidth: 0 }} activeDot={{ r: 5 }} isAnimationActive={false} connectNulls />
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
                <Line type="monotone" dataKey="session_count" name="Sessions" stroke={sessionColor} strokeWidth={2} dot={{ r: 2, fill: sessionColor, strokeWidth: 0 }} activeDot={{ r: 5 }} isAnimationActive={false} connectNulls />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
