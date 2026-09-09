'use client';

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import Card, { CardBody } from '../ui/Card';
import {
  AXIS_TICK,
  AXIS_LINE,
  GRID_PROPS,
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
} from '../snmp/chartGrammar';

// Axes, grid, tooltip and line geometry come from the shared chart grammar
// (components/snmp/chartGrammar.js — it is not SNMP-specific, see that file's
// header for why it lives there for now), so this chart and the SNMP session
// chart on a device's own page read as the same instrument.
//
// The line colour is a design TOKEN handed straight to the SVG presentation
// attributes recharts renders (stroke/fill). This replaced the older "resolve
// a CSS custom property through getComputedStyle, with a hardcoded hex
// fallback for the SSR pass" pattern: the fallback had already drifted off the
// token it named, and a literal opts a chart out of both the token layer and
// dark mode in the one code path nobody ever looks at.
// --accent-teal is this app's own identity hue (and, since the palette
// rewrite, the same value as --primary). It is not a severity: nothing about a
// VPN session count is a risk reading.
const LINE_COLOR = 'var(--accent-teal)';

function SessionTooltip({ active, payload }) {
  if (!active || !payload || !payload.length) return null;
  const point = payload[0].payload;
  // ⛔ A missed poll is not a session count of zero — see below.
  if (point && point.__gap) return <GapTooltipBody point={point} />;
  return (
    <TooltipShell>
      <TooltipMetric
        color={LINE_COLOR}
        label="Active sessions"
        value={point.active_session_count}
        reason="This poll stored no session count."
      />
      <TooltipMeta>{utcFull(point.sampled_at)}</TooltipMeta>
    </TooltipShell>
  );
}

// points: [{ active_session_count: number, sampled_at: ISO string }], already
// ordered oldest-to-newest by the caller's query. A coarse, polling-based
// approximation of VPN usage over time -- see lib/schema.sql's
// vpn_session_snapshots comment for why this isn't real per-session log
// data (that needs syslog ingestion, not built yet).
export default function VpnSessionTrendChart({ points }) {
  const rows = Array.isArray(points) ? points : [];

  // ⛔ THE FAILED READ HERE IS AN ABSENT ROW, NOT A NULL. vpn_session_snapshots
  // is written only when the poll SUCCEEDS (services/engine-worker.js's
  // vpn-session-poll inserts inside the try), and active_session_count is NOT
  // NULL — so a device that was unreachable for six hours contributes no rows
  // at all, and this chart used to draw one confident straight line straight
  // across the outage. Nothing in the picture said "we did not look". The gap
  // is now an explicit break with a tooltip that says what is missing.
  const data = withPollingGaps(rows, 'sampled_at', ['active_session_count']);
  const gaps = countPollingGaps(data);

  return (
    <Card>
      <CardBody>
        <div style={CHART_TITLE_STYLE}>Active VPN Sessions (polled)</div>
        {rows.length === 0 ? (
          // ⛔ An empty axis pair would read as "measured, and nobody is
          // connected". Say which question went unanswered instead.
          <ChartEmpty
            title="Not measured"
            message="No session-count polls have been stored for this device. Session polling covers Fortinet, Palo Alto (GlobalProtect) and Cisco ASA — an absent trend means SecVault has not measured usage here, not that nobody connected."
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
                  <YAxis allowDecimals={false} tick={AXIS_TICK} axisLine={AXIS_LINE} tickLine={false} width={28} />
                  <Tooltip cursor={TOOLTIP_CURSOR} content={<SessionTooltip />} />
                  {/* Single series — no legend, by the shared grammar.
                      connectNulls={false} comes from LINE_PROPS and is what
                      makes the injected gap rows render as a break rather than
                      an interpolated segment. */}
                  <Line
                    {...LINE_PROPS}
                    dataKey="active_session_count"
                    name="Active sessions"
                    stroke={LINE_COLOR}
                    dot={{ r: 2, fill: LINE_COLOR, strokeWidth: 0 }}
                    activeDot={{ r: 5 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <PollingGapNote gaps={gaps} />
          </>
        )}
      </CardBody>
    </Card>
  );
}
