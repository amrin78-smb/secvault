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
  // ⛔ The accent border and the VALUE TEXT are different jobs and must not
  // share a default. This was one `color` prop applied to BOTH, defaulting to
  // --border — so any call site that omitted it rendered its headline number
  // in the border token. Measured live: "24" on /vulnerability at 1.39:1
  // contrast in dark and 1.23:1 in light (28px/800 weight needs 3.0), i.e.
  // effectively invisible. Same on /devices/<id>/analysis?tab=summary for
  // "Total Rules", "Inactive Rules" and "Total Findings".
  color = 'var(--border)',
  className = '',
  compact = false,
  icon,
  iconColor,
  iconBg,
  delta,
}) {
  const cardClass = compact ? 'kpi-card-compact' : 'kpi-card';
  const valueClass = compact ? 'stat-value-compact' : 'stat-value';
  const labelClass = compact ? 'stat-label-compact' : 'stat-label';
  const subClass = compact ? 'stat-sub-compact' : 'stat-sub';
  const valueColor = color === 'var(--border)' ? 'var(--text-primary)' : color;
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
      {/* The value falls back to readable body text, NOT to the border accent.
          An explicit `color` from the caller still styles both, which is what
          every deliberate call site (red for Patch Now, green for a good score)
          relies on. */}
      <div className={valueClass} style={{ color: valueColor }}>
        {value}
      </div>
      <div className={labelClass}>{label}</div>
      {sub && <div className={subClass}>{sub}</div>}
      {/* Optional day-over-day change, rendered by DeltaBadge. Undefined by
          default, so every pre-existing call site is pixel-identical. ⛔ The
          CALLER decides the colour, because "up" is good for a compliance
          score and bad for a critical-alert count — see DeltaBadge. */}
      {delta && <div style={{ marginTop: 4 }}>{delta}</div>}
    </div>
  );
}
