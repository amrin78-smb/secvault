'use client';

import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import Card, { CardBody } from '../ui/Card';
import {
  GRID_PROPS,
  X_AXIS_PROPS,
  COUNT_AXIS_PROPS,
  TOOLTIP_CURSOR_BAR,
  ChartTooltip,
  ChartNotMeasured,
  CHART_HEADING_STYLE,
} from './chartGrammar';

// The finding types in the fixed severity order CLAUDE.md documents for the
// rule analysis engine (lib/engines/ruleAnalysis.js), each mapped to the
// severity it's always emitted at -- used to color bars the same way
// SeverityBadge.js colors severity pills, so this chart and that badge always
// agree on what "critical" looks like.
const FINDING_TYPE_ORDER = [
  { type: 'any_any', label: 'Any-Any', severity: 'critical' },
  { type: 'risky_service', label: 'Risky Svc', severity: 'high' },
  { type: 'shadow', label: 'Shadow', severity: 'high' },
  { type: 'reorder_candidate', label: 'Reorder', severity: 'high' },
  { type: 'redundant', label: 'Redundant', severity: 'medium' },
  { type: 'correlation', label: 'Correlation', severity: 'medium' },
  { type: 'overly_permissive', label: 'Overly Perm.', severity: 'medium' },
  { type: 'unused', label: 'Unused', severity: 'medium' },
  { type: 'expiring_soon', label: 'Expiring', severity: 'medium' },
  { type: 'generalization', label: 'Generalization', severity: 'medium' },
  { type: 'external_exposure', label: 'Ext. Exposure', severity: 'medium' },
  { type: 'log_disabled', label: 'Log Off', severity: 'info' },
];

// ⛔ These are the palette's SEMANTIC SEVERITY ALIASES (--sev-*), not raw hues.
// Every bar here IS a severity, which is exactly what those aliases exist to
// say, so a future ramp change is one edit in app/globals.css rather than a
// hunt through the charts.
//
// ⛔ medium used to be --blue and that is now FORBIDDEN, not merely
// discouraged: the rewritten palette pulled blue OUT of the severity ramp (low
// severity is slate) precisely so the teal brand hue can never be mistaken for
// a severity. Putting blue back on a severity collapses that separation.
//
// ⛔ The token strings go STRAIGHT into recharts. The getComputedStyle-based
// resolveSeverityColor() that used to live here is deleted — see the header of
// chartGrammar.js for the two bugs it caused.
const SEVERITY_COLOR = {
  critical: 'var(--sev-crit)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-med)',
  info: 'var(--sev-low)',
};

// counts: { [finding_type]: number } -- same shape devices/[id]/analysis/page.js
// already builds via getFindingTypeCounts(), zero-filled for every known type.
//
// lastAnalyzedAt: OPTIONAL. Pass `null` when rule analysis has never run on
// this device, so the chart can say "not measured" instead of drawing twelve
// confident zeros. See the ⛔ note in the body.
export default function FindingsBarChart({ counts, lastAnalyzedAt }) {
  const data = FINDING_TYPE_ORDER.map((f) => ({
    ...f,
    count: (counts && counts[f.type]) || 0,
    color: SEVERITY_COLOR[f.severity] || SEVERITY_COLOR.info,
  }));

  // ⛔ FAILED READ RENDERED AS A VALUE. A recharts BarChart handed all-zero
  // counts does not look empty — it draws a full axis, a full grid and twelve
  // zero-height bars sitting on the baseline, which reads as "we checked all
  // twelve finding types and this ruleset is clean". That is a completely
  // different claim from "rule analysis has never run here", and the two used
  // to be pixel-identical.
  //
  // `counts` absent is unambiguous. An explicit `lastAnalyzedAt === null` is
  // the caller telling us the engine has never run. Either way this is not a
  // measurement, so it does not get drawn as one. (An all-zero count WITH a
  // real lastAnalyzedAt is a genuine, earned clean result and still charts.)
  const notMeasured =
    !counts || (lastAnalyzedAt === null && data.every((d) => d.count === 0));

  return (
    <Card>
      <CardBody>
        <div style={CHART_HEADING_STYLE}>Findings by Type</div>
        {notMeasured ? (
          <ChartNotMeasured reason="Rule analysis has not run on this device yet — no finding counts have been measured. This is not the same as a clean ruleset." />
        ) : (
          <div style={{ width: '100%', height: 260 }}>
            <ResponsiveContainer>
              <BarChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
                <CartesianGrid {...GRID_PROPS} />
                <XAxis
                  {...X_AXIS_PROPS}
                  dataKey="label"
                  interval={0}
                  angle={-20}
                  textAnchor="end"
                  height={50}
                />
                <YAxis {...COUNT_AXIS_PROPS} width={28} />
                {/* Single series: no Legend — the card heading already names it. */}
                <Tooltip cursor={TOOLTIP_CURSOR_BAR} content={<ChartTooltip />} />
                <Bar dataKey="count" name="Findings" radius={[3, 3, 0, 0]} maxBarSize={40}>
                  {data.map((entry) => (
                    <Cell key={entry.type} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardBody>
    </Card>
  );
}
