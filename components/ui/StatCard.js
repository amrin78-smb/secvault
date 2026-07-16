// Suite `.kpi-card` colored-left-border tile — the standard stat-grid unit
// used across every dashboard/summary page. `color` is any CSS color value
// (a var(--...) token or a literal hex), applied as the left border accent.
export default function StatCard({ label, value, sub, color = 'var(--border)', className = '' }) {
  return (
    <div className={`kpi-card ${className}`} style={{ borderLeftColor: color }}>
      <div className="stat-value" style={{ color }}>
        {value}
      </div>
      <div className="stat-label">{label}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}
