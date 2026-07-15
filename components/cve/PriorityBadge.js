import Badge from '../ui/Badge';

// Priority band visual encoding — per CLAUDE.md "Design System" section, do not
// change without updating that doc first:
//   patch_now -> danger,  label "Patch Now"
//   scheduled -> warning, label "Scheduled"
//   monitor   -> muted,   label "Monitor"
const BAND_MAP = {
  patch_now: { label: 'Patch Now', color: 'danger' },
  scheduled: { label: 'Scheduled', color: 'warning' },
  monitor: { label: 'Monitor', color: 'muted' },
};

export default function PriorityBadge({ band }) {
  const entry = BAND_MAP[band] || BAND_MAP.monitor;
  return <Badge color={entry.color}>{entry.label}</Badge>;
}
