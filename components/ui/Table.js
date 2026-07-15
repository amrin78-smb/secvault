// Thin wrapper enforcing `table-fixed` / tableLayout:'fixed' (required by CLAUDE.md
// whenever a table uses percentage/colgroup column widths) plus consistent
// border + surface styling. Callers supply <thead>/<tbody> as children, same as a
// plain <table>.
export default function Table({ children, className = '' }) {
  return (
    <div className="overflow-x-auto rounded border border-border">
      <table
        className={`w-full table-fixed border-collapse text-sm ${className}`}
        style={{ tableLayout: 'fixed' }}
      >
        {children}
      </table>
    </div>
  );
}
