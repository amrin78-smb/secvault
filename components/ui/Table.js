// Thin wrapper enforcing tableLayout:'fixed' (required by CLAUDE.md whenever a
// table uses percentage/colgroup column widths) plus the suite's bordered
// container + th/td styling, which app/globals.css applies to every <table>
// element globally (no .data-table class needed for the base look). Callers
// supply <thead>/<tbody> as children, same as a plain <table>.
export default function Table({ children, className = '' }) {
  return (
    <div style={{ overflowX: 'auto', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
      <table className={className} style={{ tableLayout: 'fixed', width: '100%', borderCollapse: 'collapse' }}>
        {children}
      </table>
    </div>
  );
}
