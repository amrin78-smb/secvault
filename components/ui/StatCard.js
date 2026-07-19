// Suite `.kpi-card` colored-left-border tile — the standard stat-grid unit
// used across every dashboard/summary page. `color` is any CSS color value
// (a var(--...) token or a literal hex), applied as the left border accent.
// `compact` swaps in the smaller `-compact` class variants (app/globals.css)
// for the main Dashboard's higher-density widget grid — every other page's
// StatCard usage is unaffected since compact defaults to false.
export default function StatCard({ label, value, sub, color = 'var(--border)', className = '', compact = false }) {
  const cardClass = compact ? 'kpi-card-compact' : 'kpi-card';
  const valueClass = compact ? 'stat-value-compact' : 'stat-value';
  const labelClass = compact ? 'stat-label-compact' : 'stat-label';
  const subClass = compact ? 'stat-sub-compact' : 'stat-sub';
  return (
    <div className={`${cardClass} ${className}`} style={{ borderLeftColor: color }}>
      <div className={valueClass} style={{ color }}>
        {value}
      </div>
      <div className={labelClass}>{label}</div>
      {sub && <div className={subClass}>{sub}</div>}
    </div>
  );
}
