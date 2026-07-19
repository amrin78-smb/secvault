import IconChip from './IconChip';

// Suite `.kpi-card` colored-left-border tile — the standard stat-grid unit
// used across every dashboard/summary page. `color` is any CSS color value
// (a var(--...) token or a literal hex), applied as the left border accent.
// `compact` swaps in the smaller `-compact` class variants (app/globals.css)
// for the main Dashboard's higher-density widget grid — every other page's
// StatCard usage is unaffected since compact defaults to false.
//
// `icon`/`iconColor`/`iconBg` are optional (all undefined by default) — only
// the main Dashboard's top 4 stat tiles pass them today, every other
// existing call site across the app renders pixel-identical to before.
// When provided, an IconChip (same colored-badge language as the sidebar's
// nav chips) renders pinned to the tile's top-right corner, positioned so it
// never disturbs the existing value/label/sub stack below it.
export default function StatCard({
  label,
  value,
  sub,
  color = 'var(--border)',
  className = '',
  compact = false,
  icon,
  iconColor,
  iconBg,
}) {
  const cardClass = compact ? 'kpi-card-compact' : 'kpi-card';
  const valueClass = compact ? 'stat-value-compact' : 'stat-value';
  const labelClass = compact ? 'stat-label-compact' : 'stat-label';
  const subClass = compact ? 'stat-sub-compact' : 'stat-sub';
  return (
    <div
      className={`${cardClass} ${className}`}
      style={{ borderLeftColor: color, position: 'relative' }}
    >
      {icon && (
        <div style={{ position: 'absolute', top: compact ? 6 : 12, right: compact ? 6 : 12 }}>
          <IconChip icon={icon} color={iconColor} bg={iconBg} />
        </div>
      )}
      <div className={valueClass} style={{ color }}>
        {value}
      </div>
      <div className={labelClass}>{label}</div>
      {sub && <div className={subClass}>{sub}</div>}
    </div>
  );
}
