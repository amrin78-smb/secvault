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
// Raw ramp hue -> its text-safe counterpart. These are the same --tint-*-fg tokens
// components/analysis/severityRamp.js maps the whole ramp to; the pairing lives
// there, this is just the lookup by raw value.
const TEXT_SAFE_VALUE = {
  'var(--red)': 'var(--tint-danger-fg)',
  'var(--orange)': 'var(--tint-orange-fg)',
  'var(--yellow)': 'var(--tint-warn-fg)',
  'var(--green)': 'var(--tint-success-fg)',
  'var(--blue)': 'var(--tint-info-fg)',
  'var(--purple)': 'var(--tint-purple-fg)',
  'var(--teal)': 'var(--tint-teal-fg)',
  'var(--accent-teal)': 'var(--tint-teal-fg)',
  'var(--sev-crit)': 'var(--tint-danger-fg)',
  'var(--sev-high)': 'var(--tint-orange-fg)',
  'var(--sev-med)': 'var(--tint-warn-fg)',
  'var(--sev-ok)': 'var(--tint-success-fg)',
};

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
  // "stack" (default, unchanged everywhere) or "row" -- number to the RIGHT of
  // the label rather than above it. See the layout note below.
  layout = 'stack',
  // ⛔ The accent BORDER and the value TEXT are different jobs with different
  // contrast requirements, and `color` was doing both. A raw severity hue is fine
  // as a 4px border or a dot; as 17px text it measured 3.64:1 on white for
  // --yellow and --orange, under WCAG 1.4.3’s 4.5:1 minimum. The old justification
  // ("32px/800 clears the large-text threshold") stopped holding when the compact
  // tiles shrank the value. Pass the text-safe counterpart here —
  // components/analysis/severityRamp.js’s SEVERITY_TEXT_COLOR already maps the
  // whole ramp to the --tint-*-fg tokens that exist for exactly this.
  // Omitted => falls back to `color`, so every existing call site is unchanged.
  textColor,
}) {
  const cardClass = compact ? 'kpi-card-compact' : 'kpi-card';
  const valueClass = compact ? 'stat-value-compact' : 'stat-value';
  const labelClass = compact ? 'stat-label-compact' : 'stat-label';
  const subClass = compact ? 'stat-sub-compact' : 'stat-sub';
  const accentColor = color;
  // ⛔ THE VALUE IS ALWAYS TEXT, so it always takes the text-safe form of the ramp.
  // Passing a raw severity hue is correct for the 4px accent border and wrong for
  // the number: measured on the live dashboard, --orange and --yellow both sat at
  // 3.63-3.64:1 against the card, under WCAG 1.4.3’s 4.5:1.
  //
  // ⛔ Mapped HERE rather than at each call site on purpose. Fixing only the six
  // dashboard headline tiles left the CVE-severity and ruleset tiles failing at the
  // same ratios — there are ~40 call sites and the next one added would have been
  // wrong again. An explicit  still wins, and anything not in the map is
  // passed through untouched.
  const valueColor = textColor
    || TEXT_SAFE_VALUE[color]
    || (color === 'var(--border)' ? 'var(--text-primary)' : color);

  // ⛔ ROW LAYOUT. The value moves out of the vertical stack and sits beside the
  // label, which removes one block of height. Measured on the dashboard headline
  // row: 114px -> see the commit. Two things differ from the stacked layout and
  // both are deliberate:
  //
  //   1. The icon is INLINE before the label, not absolutely positioned in the
  //      top-right corner -- that corner is now where the number lives, and two
  //      things cannot occupy it.
  //   2. `sub` and `delta` still span the FULL card width underneath, rather than
  //      being trapped in the narrower left column. A long sub (the Security
  //      Score tile reads "Needs attention — Vulnerability 49 · Rule 46 ·
  //      Compliance 51") would otherwise wrap MORE than before and give back the
  //      height this layout exists to save.
  if (layout === 'row') {
    return (
      <div className={`${cardClass} ${className}`} style={{ borderLeftColor: color }}>
        <div className="kpi-head-row">
          <div className="kpi-head-left">
            {icon && <IconChip icon={icon} color={iconColor} bg={iconBg} />}
            <div className={labelClass}>{label}</div>
          </div>
          <div className={valueClass} style={{ color: valueColor }}>
            {value}
          </div>
        </div>
        {sub && <div className={subClass}>{sub}</div>}
        {delta && <div className="stat-delta">{delta}</div>}
      </div>
    );
  }

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
      {delta && <div className="stat-delta">{delta}</div>}
    </div>
  );
}
