'use client';

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import Card, { CardBody } from '../ui/Card';

// Reads the app's own CSS custom properties (app/globals.css) rather than
// hardcoding hex values a second time -- same convention as
// FindingsBarChart.js's resolveSeverityColor(). Read at render time in a
// browser context, with a hardcoded fallback (app/globals.css's --primary,
// #C8102E) for the (never-expected-in-practice) case of SSR-time evaluation
// before hydration, where window/document don't exist yet. Reads --primary
// directly rather than the transitional --accent alias in app/globals.css's
// legacy block, which is slated for removal once nothing references it.
const PRIMARY_FALLBACK_HEX = '#C8102E';

function resolveAccentColor() {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return PRIMARY_FALLBACK_HEX;
  }
  const value = getComputedStyle(document.documentElement).getPropertyValue('--primary');
  return value ? value.trim() : PRIMARY_FALLBACK_HEX;
}

const RISK_BAND_LABEL = { low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' };

// Compact label for the X axis -- date only, since a device can accumulate
// many snapshots over time (one per analysis run, scheduled or manual) and a
// full timestamp per tick would overlap.
function formatAxisTick(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  return d.toISOString().slice(0, 10);
}

function formatFullTimestamp(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

function bandLabel(band) {
  return RISK_BAND_LABEL[band] || (band ? band[0].toUpperCase() + band.slice(1) : '—');
}

function RiskTooltip({ active, payload }) {
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
      <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>Score: {point.score}</div>
      <div style={{ color: 'var(--text-secondary)' }}>Band: {bandLabel(point.band)}</div>
      <div style={{ color: 'var(--text-muted)' }}>{formatFullTimestamp(point.recorded_at)}</div>
    </div>
  );
}

// points: [{ score: number, band: string, recorded_at: ISO string }], already
// ordered oldest-to-newest by the caller's query.
export default function RiskTrendChart({ points }) {
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
          Risk Score Trend
        </div>
        <div style={{ width: '100%', height: 260 }}>
          <ResponsiveContainer>
            <LineChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
              <XAxis
                dataKey="recorded_at"
                tickFormatter={formatAxisTick}
                tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
                axisLine={{ stroke: 'var(--border)' }}
                tickLine={false}
                minTickGap={24}
              />
              <YAxis
                domain={[0, 100]}
                allowDecimals={false}
                tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
                axisLine={{ stroke: 'var(--border)' }}
                tickLine={false}
                width={28}
              />
              <Tooltip cursor={{ stroke: 'var(--border)' }} content={<RiskTooltip />} />
              <Line
                type="monotone"
                dataKey="score"
                stroke={lineColor}
                strokeWidth={2}
                dot={{ r: 3, fill: lineColor, strokeWidth: 0 }}
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
