// Thin wrapper enforcing tableLayout:'fixed' (required by CLAUDE.md whenever a
// table uses percentage/colgroup column widths) plus the suite's bordered
// container + th/td styling, which app/globals.css applies to every <table>
// element globally (no .data-table class needed for the base look). Callers
// supply <thead>/<tbody> as children, same as a plain <table>.
// `layout` exists ONLY for the narrow case of a table with no colgroup and no
// percentage widths, where 'fixed' is actively wrong: it slices the width into
// N equal columns, so a many-column table truncates every heading ("RULE…",
// "SRC …") regardless of how little each cell actually holds. 'auto' sizes
// columns to their content instead. ⛔ Do NOT reach for this to "fix" a table
// that sets percentage/colgroup widths — CLAUDE.md requires 'fixed' there, and
// without it those columns collapse unpredictably on overflow. Pair 'auto' with
// `minWidth` so the table keeps its natural width and SCROLLS inside the
// wrapper below rather than compressing back down.
export default function Table({ children, className = '', layout = 'fixed', minWidth }) {
  return (
    <div style={{ overflowX: 'auto', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
      <table
        className={className}
        style={{ tableLayout: layout, width: '100%', minWidth, borderCollapse: 'collapse' }}
      >
        {children}
      </table>
    </div>
  );
}
