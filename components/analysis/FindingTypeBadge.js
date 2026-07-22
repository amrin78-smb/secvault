import Badge from '../ui/Badge';

// Neutral (muted) badge with a human-readable label per finding_type.
// finding_type values come from rule_analysis_results.finding_type — see lib/schema.sql.
const TYPE_LABELS = {
  unused: 'Unused',
  shadow: 'Shadowed',
  redundant: 'Redundant',
  any_any: 'Any-Any',
  risky_service: 'Risky Service',
  reorder_candidate: 'Reorder',
  expiring_soon: 'Expiring',
  log_disabled: 'Logging Off',
  overly_permissive: 'Overly Permissive',
  correlation: 'Correlation',
  generalization: 'Generalization',
  external_exposure: 'External Exposure',
};

export default function FindingTypeBadge({ type }) {
  const label = TYPE_LABELS[type] || type || 'Unknown';
  return <Badge color="muted">{label}</Badge>;
}
