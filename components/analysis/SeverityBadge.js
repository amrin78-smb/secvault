import Badge from '../ui/Badge';

// Rule-analysis finding severity visual encoding — mirrors the PriorityBadge
// pattern (map value -> Badge color + human label).
//
// ⛔ REMAPPED 2026-09-09 and this file is not free to drift from
// FindingsBarChart.js, which colours the SAME severity values: a finding
// that is orange in the chart and yellow in the badge two inches away is
// the reader’s problem, not a style detail.
//
// medium was `info` (BLUE). Blue is now off the severity ramp entirely —
// that is what keeps the brand teal from reading as a severity (see the
// token block in globals.css). So the whole ramp shifts down one:
//   critical -> danger (red), high -> orange, medium -> warning (yellow),
//   info -> muted (slate)
const SEVERITY_MAP = {
  critical: { label: 'Critical', color: 'danger' },
  high: { label: 'High', color: 'orange' },
  medium: { label: 'Medium', color: 'warning' },
  info: { label: 'Info', color: 'muted' },
};

export default function SeverityBadge({ severity }) {
  const entry = SEVERITY_MAP[severity] || SEVERITY_MAP.info;
  return <Badge color={entry.color}>{entry.label}</Badge>;
}
