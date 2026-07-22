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
const CPU_FALLBACK_HEX = '#dc2626'; // --red
const MEM_FALLBACK_HEX = '#2563eb'; // --blue
const SESSION_FALLBACK_HEX = '#0891b2'; // --accent-teal

function resolveColor(varName, fallback) {
  if (typeof window === 'undefined' || typeof document === 'undefined') return fallback;
  const value = getComputedStyle(document.documentElement).getPropertyValue(varName);
  return value ? value.trim() : fallback;
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
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: '6px 10px', fontSize: 11 }}>
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
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: '6px 10px', fontSize: 11 }}>
      <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{point.session_count ?? '—'} sessions</div>
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

  const cpuColor = resolveColor('--red', CPU_FALLBACK_HEX);
  const memColor = resolveColor('--blue', MEM_FALLBACK_HEX);
  const sessionColor = resolveColor('--accent-teal', SESSION_FALLBACK_HEX);

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
              <Line type="monotone" dataKey="cpu_percent" stroke={cpuColor} strokeWidth={1.5} dot={false} activeDot={{ r: 4 }} isAnimationActive={false} connectNulls />
              <Line type="monotone" dataKey="memory_percent" stroke={memColor} strokeWidth={1.5} dot={false} activeDot={{ r: 4 }} isAnimationActive={false} connectNulls />
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
              <Line type="monotone" dataKey="session_count" stroke={sessionColor} strokeWidth={1.5} dot={false} activeDot={{ r: 4 }} isAnimationActive={false} connectNulls />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
