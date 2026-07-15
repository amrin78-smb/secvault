import Badge from '../ui/Badge';

// Rule-analysis finding severity visual encoding — mirrors the PriorityBadge
// pattern (map value -> Badge color + human label):
//   critical -> danger,  high -> warning,  medium -> info,  info -> muted
const SEVERITY_MAP = {
  critical: { label: 'Critical', color: 'danger' },
  high: { label: 'High', color: 'warning' },
  medium: { label: 'Medium', color: 'info' },
  info: { label: 'Info', color: 'muted' },
};

export default function SeverityBadge({ severity }) {
  const entry = SEVERITY_MAP[severity] || SEVERITY_MAP.info;
  return <Badge color={entry.color}>{entry.label}</Badge>;
}
