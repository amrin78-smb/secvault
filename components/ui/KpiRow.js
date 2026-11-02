// A row of stat tiles with an EXPLICIT column count.
//
// ⛔ ═══ WHY THIS EXISTS RATHER THAN `repeat(auto-fit, minmax(…))` ════════
// v2.218.0 established the rule on the Overview and then left every other
// page re-implementing the broken version: twenty-odd `auto-fit` KPI grids,
// each with its own hand-picked minmax. `auto-fit` CANNOT be fixed by tuning
// that number, because it does not know how many tiles there are — any width
// that fits five will orphan a sixth, and an orphaned tile reads as a layout
// fault rather than as a group.
//
// Measured on the Overview before the fix: five across, one stranded, at a
// width the designer had tested. The same thing was happening on /devices
// (6+1 at 1440), and is latent on every page below.
//
// ⛔ ═══ THE RESPONSIVE STEPS MUST DIVIDE TOO ═════════════════════════════
// A four-tile row going 4 -> 3 -> 2 -> 1 orphans its fourth on the way down,
// which is the same defect one breakpoint later. So each count declares the
// steps it is allowed to take, and they all divide:
//
//     6 -> 3 -> 2 -> 1      5 -> 1 (nothing divides 5)
//     4 -> 2 -> 1           3 -> 1 (3 -> 2 orphans)
//     2 -> 1                1
//
// ⛔ FIVE IS THE AWKWARD ONE AND IS NOT SMOOTHED OVER. Nothing divides five,
// so it drops straight to one column rather than passing through a ragged
// 3+2. A caller with five tiles should ask whether it really has five
// headline figures — but it is never silently rendered ragged.
//
// ⛔ THIS COMPONENT DOES NOT COUNT ITS OWN CHILDREN. `cols` is declared,
// because React children can be conditional: a tile rendered only when a
// count is non-zero would silently change the column count with the data, and
// the layout would be correct in development and ragged in production.

const SUPPORTED = new Set([1, 2, 3, 4, 5, 6]);

export default function KpiRow({ cols, children, className = '', style }) {
  const n = SUPPORTED.has(Number(cols)) ? Number(cols) : null;
  if (n === null) {
    // ⛔ A BAD `cols` FALLS BACK TO ONE COLUMN, never to auto-fit. One column
    // is ugly and obviously wrong, which gets it fixed; auto-fit is subtly
    // wrong at some widths and on some data, which does not.
    return (
      <div className={`kpi-row ${className}`.trim()} data-cols="1" style={style}>
        {children}
      </div>
    );
  }
  return (
    <div className={`kpi-row ${className}`.trim()} data-cols={String(n)} style={style}>
      {children}
    </div>
  );
}

export { SUPPORTED as KPI_ROW_COLUMNS };
