import Link from 'next/link';

// A two-level tab bar: four task groups over the active group's views.
//
// Takes the rows `lib/analysisTabs.js`'s `analysisTabRows()` already computed,
// so the grouping decision lives in testable data and this file only draws it.
//
// ⛔ THE TWO ROWS LOOK DELIBERATELY DIFFERENT, and that is the whole reason
// this is one component rather than two <TabRow>s stacked. A primary row and a
// secondary row drawn identically read as one wrapped row of twenty tabs —
// which is the thing being fixed. The primary row carries the underline and
// the type weight; the secondary row is a lighter pill strip beneath it.
//
// ⛔ BOTH ROWS SCROLL RATHER THAN WRAP. A wrapped tab row changes the page's
// height depending on the viewport, which pushes the content down by an amount
// nothing in the markup predicts — and §7's acceptance criterion is explicitly
// "no wrapped or clipped tab rows".
export default function TabRows({ groups = [], leaves = [], ariaLabel = 'Sections' }) {
  return (
    <div className="tab-rows">
      <nav className="tab-rows-primary" aria-label={ariaLabel}>
        {groups.map((g) => (
          <Link
            key={g.key}
            href={g.href}
            className="tab-rows-tab"
            data-active={g.active ? '' : undefined}
            aria-current={g.active ? 'page' : undefined}
          >
            {g.label}
          </Link>
        ))}
      </nav>
      {/* ⛔ Rendered whenever the active group has leaves, including when it has
          exactly one. Suppressing it at one entry would make the tab row
          silently change shape as the operator moved between groups. */}
      {leaves.length > 0 && (
        <nav className="tab-rows-secondary" aria-label={`${ariaLabel} — views`}>
          {leaves.map((l) => (
            <Link
              key={l.tab}
              href={l.href}
              className="tab-rows-leaf"
              data-active={l.active ? '' : undefined}
              aria-current={l.active ? 'page' : undefined}
            >
              {l.label}
            </Link>
          ))}
        </nav>
      )}
    </div>
  );
}
