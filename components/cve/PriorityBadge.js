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
  const entry = BAND_MAP[band];
  // ⛔ An unrecognised or missing band is NOT "Monitor". Falling back to the
  // lowest band rendered "we have not assessed this" as a confident "nothing
  // to do here" — the failed-read-as-a-fact rule, applied to the product's
  // headline judgement. Say we do not know instead.
  if (!entry) {
    return (
      <Badge color="muted" title="No priority band recorded for this assessment">
        Unassessed
      </Badge>
    );
  }
  return <Badge color={entry.color}>{entry.label}</Badge>;
}
