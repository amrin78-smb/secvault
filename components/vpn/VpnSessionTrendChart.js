'use client';

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import Card, { CardBody } from '../ui/Card';

// Same "resolve a CSS custom property to its computed value at render time,
// with a hardcoded hex fallback for the SSR pass" pattern as
// components/analysis/RiskTrendChart.js, which this component otherwise
// mirrors closely (same LineChart shape, same axis/tooltip styling).
const ACCENT_FALLBACK_HEX = '#0891b2'; // --accent-teal, this app's own identity color

function resolveAccentColor() {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return ACCENT_FALLBACK_HEX;
  }
  const value = getComputedStyle(document.documentElement).getPropertyValue('--accent-teal');
  return value ? value.trim() : ACCENT_FALLBACK_HEX;
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

function SessionTooltip({ active, payload }) {
  if (!active || !payload || !payload.length) return null;
  const point = payload[0].payload;
  return (
    <div
      style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border)',
        borderRadius: 6,
        padding: '6px 10px',
        fontSize: 12,
      }}
    >
      <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
        {point.active_session_count} active session{point.active_session_count === 1 ? '' : 's'}
      </div>
      <div style={{ color: 'var(--text-muted)' }}>{formatFullTimestamp(point.sampled_at)}</div>
    </div>
  );
}

// points: [{ active_session_count: number, sampled_at: ISO string }], already
// ordered oldest-to-newest by the caller's query. A coarse, polling-based
// approximation of VPN usage over time -- see lib/schema.sql's
// vpn_session_snapshots comment for why this isn't real per-session log
// data (that needs syslog ingestion, not built yet).
export default function VpnSessionTrendChart({ points }) {
  const data = Array.isArray(points) ? points : [];
  const lineColor = resolveAccentColor();

  return (
    <Card>
      <CardBody>
        <div
          style={{
            marginBottom: 12,
            fontSize: 'var(--text-xs)',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            color: 'var(--text-muted)',
          }}
        >
          Active VPN Sessions (polled)
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
                width={28}
              />
              <Tooltip cursor={{ stroke: 'var(--border)' }} content={<SessionTooltip />} />
              <Line
                type="monotone"
                dataKey="active_session_count"
                stroke={lineColor}
                strokeWidth={2}
                dot={{ r: 2, fill: lineColor, strokeWidth: 0 }}
                activeDot={{ r: 5 }}
                isAnimationActive={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </CardBody>
    </Card>
  );
}
