'use client';

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import Card, { CardBody } from '../ui/Card';
import NotMeasured from '../ui/NotMeasured';
import {
  GRID_PROPS,
  X_AXIS_PROPS,
  COUNT_AXIS_PROPS,
  TOOLTIP_CURSOR_LINE,
  TOOLTIP_SURFACE,
  CHART_HEADING_STYLE,
} from './chartGrammar';

// --primary is the right token here BECAUSE this line is not a severity: it is
// the single data series of a trend chart, so it takes the brand/interactive
// hue and leaves the severity ramp to mean risk. (The score it plots is 0-100
// higher-is-WORSE; the band label in the tooltip carries that, not the line
// colour.)
//
// ⛔ The token string goes STRAIGHT into recharts. The getComputedStyle-based
// resolveAccentColor() that used to live here is deleted — see the header of
// chartGrammar.js for the two bugs it caused. The theme toggle now repaints
// this line without a re-render.
const LINE_COLOR = 'var(--primary)';

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
  return RISK_BAND_LABEL[band] || (band ? band[0].toUpperCase() + band.slice(1) : null);
}

// Module top level, never nested inside RiskTrendChart — CLAUDE.md's React
// rule. Bespoke rather than the shared ChartTooltip because it carries two
// facts the generic one cannot know about (the risk BAND and the full
// timestamp), but it is built on the shared TOOLTIP_SURFACE so it agrees with
// every other tooltip in these two directories.
function RiskTooltip({ active, payload }) {
  if (!active || !payload || !payload.length) return null;
  const point = payload[0].payload;
  const band = bandLabel(point.band);
  return (
    <div style={TOOLTIP_SURFACE}>
      <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
        Score:{' '}
        {point.score === null || point.score === undefined ? (
          <NotMeasured reason="No risk score was recorded for this analysis run." />
        ) : (
          point.score
        )}
      </div>
      {/* ⛔ An absent band is an em-dash, not a guessed 'Low'. */}
      <div style={{ color: 'var(--text-secondary)' }}>
        Band: {band === null ? <NotMeasured reason="No risk band was recorded for this analysis run." /> : band}
      </div>
      <div style={{ color: 'var(--text-muted)' }}>{formatFullTimestamp(point.recorded_at)}</div>
    </div>
  );
}

// points: [{ score: number, band: string, recorded_at: ISO string }], already
// ordered oldest-to-newest by the caller's query.
//
// ⛔ The X axis is deliberately CATEGORICAL, not a time scale. device_risk_history
// is written once per analysis RUN (scheduled collect or a manual Run Analysis
// click), so there is no expected cadence and therefore no such thing as a
// "missing" sample to leave a gap for — every point on this axis is a real run.
// That is the opposite of the SNMP/VPN charts, which poll on a fixed interval
// and where a gap IS the signal.
export default function RiskTrendChart({ points }) {
  const data = Array.isArray(points) ? points : [];

  return (
    <Card>
      <CardBody>
        <div style={CHART_HEADING_STYLE}>Risk Score Trend</div>
        <div style={{ width: '100%', height: 260 }}>
          <ResponsiveContainer>
            <LineChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
              <CartesianGrid {...GRID_PROPS} />
              <XAxis
                {...X_AXIS_PROPS}
                dataKey="recorded_at"
                tickFormatter={formatAxisTick}
                minTickGap={24}
              />
              <YAxis {...COUNT_AXIS_PROPS} domain={[0, 100]} width={28} />
              {/* Single series: no Legend — the card heading already names it. */}
              <Tooltip cursor={TOOLTIP_CURSOR_LINE} content={<RiskTooltip />} />
              {/* ⛔ connectNulls={false}, stated explicitly rather than left to
                  recharts' default. A run that recorded no score must show as a
                  BREAK in the line; bridging it draws an interpolated segment
                  pixel-identical to real measurements, which is hit_count's old
                  DEFAULT 0 rendered as a chart. Same rule as the SNMP charts. */}
              <Line
                type="monotone"
                dataKey="score"
                name="Risk score"
                stroke={LINE_COLOR}
                strokeWidth={2}
                dot={{ r: 3, fill: LINE_COLOR, strokeWidth: 0 }}
                activeDot={{ r: 5 }}
                isAnimationActive={false}
                connectNulls={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </CardBody>
    </Card>
  );
}
