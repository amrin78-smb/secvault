// Thin wrapper enforcing tableLayout:'fixed' (required by CLAUDE.md whenever a
// table uses percentage/colgroup column widths) plus the suite's bordered
// container + th/td styling, which app/globals.css applies to every <table>
// element globally (no .data-table class needed for the base look). Callers
// supply <thead>/<tbody> as children, same as a plain <table>.
//
// `layout` exists ONLY for the narrow case of a table with no colgroup and no
// percentage widths, where 'fixed' is actively wrong: it slices the width into
// N equal columns, so a many-column table truncates every heading ("RULE…",
// "SRC …") regardless of how little each cell actually holds. 'auto' sizes
// columns to their content instead. ⛔ Do NOT reach for this to "fix" a table
// that sets percentage/colgroup widths — CLAUDE.md requires 'fixed' there, and
// without it those columns collapse unpredictably on overflow. Pair 'auto' with
// `minWidth` so the table keeps its natural width and SCROLLS inside the
// wrapper below rather than compressing back down.
//
// ── Density (2026-09-09, Phase 3) ─────────────────────────────────────────
// Row height and cell font come from --row-pad-y / --row-pad-x / --row-font,
// stamped by data-density on <html> (lib/density.js). This component does not
// opt in to anything — the global th/td rules already read those tokens, so
// every table in the app follows the switch. ⛔ A cell that hardcodes
// `padding: '12px 16px'` opts ITSELF out, silently, and will sit at one height
// while the table around it changes. That reads as a broken layout rather than
// a setting.
//
// ── Sticky header (2026-09-09, Phase 3) ───────────────────────────────────
// ⛔ `stickyHeader` needs a `maxHeight` to do anything, and that is not a
// quirk to work around — it is the whole mechanism. position:sticky resolves
// against the nearest SCROLLING ancestor, so without a bounded height the
// wrapper never scrolls, the page scrolls instead, and the header stays
// obediently stuck to a container that is entirely on screen. Passing
// stickyHeader without maxHeight is therefore a no-op, which is why they are
// documented together rather than as two independent props.
//
// This matters on real data here: one device on the reference fleet has 706
// firewall rules. Twenty rows down, an unlabelled column of IP addresses is
// unreadable.
export default function Table({
  children,
  className = '',
  layout = 'fixed',
  minWidth,
  stickyHeader = false,
  maxHeight,
}) {
  return (
    <div
      style={{
        overflowX: 'auto',
        overflowY: maxHeight ? 'auto' : undefined,
        maxHeight,
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
      }}
    >
      <table
        className={`${className}${stickyHeader ? ' sticky-header' : ''}`.trim()}
        style={{ tableLayout: layout, width: '100%', minWidth, borderCollapse: 'collapse' }}
      >
        {children}
      </table>
    </div>
  );
}
