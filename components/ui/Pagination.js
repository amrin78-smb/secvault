import Link from 'next/link';
import { buildPageHref, describeRange, totalPages as calcTotalPages } from '../../lib/pagination';

// Shared pagination control. SERVER COMPONENT — real <Link>s, no client JS, so
// it works with the app's server-driven URL convention and survives
// AutoRefresh's router.refresh().
//
// ⛔ The range label is not decoration. "51–100 of 1,522" is what stops a
// reader taking the fifty rows on screen for the whole set — the same class of
// honesty as the truncation notice in log search. When the caller cannot count
// the rows it passes total={null} and this says so rather than implying the
// page is everything.
//
// Module top level, never nested inside another component (CLAUDE.md).

const btn = (enabled) => ({
  padding: '5px 11px',
  fontSize: 'var(--text-sm)',
  fontWeight: 600,
  borderRadius: 'var(--radius-sm)',
  border: '1px solid var(--border)',
  textDecoration: 'none',
  color: enabled ? 'var(--text-primary)' : 'var(--text-muted)',
  background: 'var(--bg-card)',
  opacity: enabled ? 1 : 0.45,
  cursor: enabled ? 'pointer' : 'default',
  whiteSpace: 'nowrap',
});

/**
 * @param {string}  basePath      e.g. "/alerts" or `/devices/${id}/rules`
 * @param {object}  searchParams  the page's own searchParams, preserved on every link
 * @param {number}  page          current 1-based page
 * @param {number}  pageSize
 * @param {number|null} total     row count, or null when genuinely unknown
 * @param {string}  [label]       what is being counted, e.g. "rules"
 * @param {number}  [pages]       optional explicit total pages (when total is null)
 * @param {string}  [paramName]   query param to drive, default "page"
 *
 * ⛔ `paramName` exists because ONE URL can carry several independently paged
 * lists — /lifecycle has three, the analysis Objects tab has two. With a
 * hardcoded `page` they would all move together, which is worse than no
 * controls at all: clicking "next" on one table silently repaginates another
 * the reader is not looking at. Give each list its own param and they stay
 * independent. The default keeps every single-list caller unchanged.
 */
// ⛔ WHY THE PAGE-SIZE PICKER IS A SET OF LINKS AND NOT A <select>.
// This whole control is a server component with real <Link>s — that is what
// lets it survive AutoRefresh’s router.refresh(), an F5 and a pasted URL. A
// <select> would need client JS and its own state, and the state it held
// would be a second copy of something the URL already says.
//
// ⛔ AND WHY PAGING STAYS SERVER-SIDE. It is tempting to fetch once and page
// in the browser, and for a small already-fetched list that is right. Log
// search is not that: this fleet ingests ~86M events/day, a one-hour window
// is 1.6M rows, and an exact COUNT of one hour was measured at 43 SECONDS.
// The browser cannot hold the set and the server must not count it, which is
// exactly why this control shows "Page 3" with a working Next rather than
// "Page 3 of 47". Client-side paging here would mean either fetching
// millions of rows or silently paging a truncated slice while implying it
// is everything.
//
// Changing size resets to page 1: page 4 of 50-row pages is not page 4 of
// 200-row pages, and keeping the number would land the reader somewhere
// arbitrary.
export default function Pagination({
  basePath, searchParams, page, pageSize, total, label, pages, paramName, hasMore,
  pageSizes, sizeParam,
}) {
  const param = paramName || 'page';
  const sizeKey = sizeParam || 'limit';

  // ⛔ UNKNOWN-TOTAL MODE. Some sets cannot be counted at all: log search runs
  // over ~86M rows/day and an exact COUNT of a ONE-HOUR window was measured at
  // 43 SECONDS. Those callers pass `hasMore` (from fetching limit+1) instead of
  // a total, and this renders "Page 3" with a working Next — never "Page 3 of
  // 4", which would be a claim about how much exists that nobody verified.
  const unknownTotal = (total === null || total === undefined) && hasMore !== undefined;

  const totalPages = pages || calcTotalPages(total, pageSize);
  const cur = unknownTotal
    ? Math.max(Number(page) || 1, 1)
    : Math.min(Math.max(Number(page) || 1, 1), totalPages);
  const range = describeRange(cur, pageSize, total);

  // A single page of results needs no controls, but the count is still worth
  // showing — it is the difference between "3 findings" and "3 shown".
  const showControls = unknownTotal ? (cur > 1 || hasMore) : totalPages > 1;
  const canNext = unknownTotal ? Boolean(hasMore) : cur < totalPages;

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 10,
        marginTop: 12,
        paddingTop: 12,
        borderTop: '1px solid var(--border)',
      }}
    >
      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
        {range === null ? (
          // ⛔ Never fabricate a total. "Showing 50" is true; "50 of 50" is not.
          <>Showing up to {pageSize} per page — total not counted</>
        ) : range === 'none' ? (
          <>No {label || 'rows'}</>
        ) : (
          <>
            {range}
            {label ? ` ${label}` : ''}
          </>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        {Array.isArray(pageSizes) && pageSizes.length > 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>Rows</span>
            {pageSizes.map((sz) => {
              const active = Number(sz) === Number(pageSize);
              return active ? (
                <span
                  key={sz}
                  aria-current="true"
                  style={{
                    padding: '3px 9px',
                    fontSize: 'var(--text-sm)',
                    fontWeight: 600,
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--primary)',
                    background: 'var(--primary-light)',
                    color: 'var(--primary)',
                  }}
                >
                  {sz}
                </span>
              ) : (
                <Link
                  key={sz}
                  href={buildPageHref(basePath, searchParams, { [sizeKey]: sz, [param]: null })}
                  style={btn(true)}
                >
                  {sz}
                </Link>
              );
            })}
          </div>
        ) : null}

        {showControls ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {cur > 1 ? (
            <Link href={buildPageHref(basePath, searchParams, { [param]: cur === 2 ? null : cur - 1 })} style={btn(true)}>
              ← Prev
            </Link>
          ) : (
            <span style={btn(false)}>← Prev</span>
          )}
          <span
            style={{
              fontSize: 'var(--text-sm)',
              color: 'var(--text-secondary)',
              padding: '0 6px',
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            Page {cur.toLocaleString()}{unknownTotal ? null : ` of ${totalPages.toLocaleString()}`}
          </span>
          {canNext ? (
            <Link href={buildPageHref(basePath, searchParams, { [param]: cur + 1 })} style={btn(true)}>
              Next →
            </Link>
          ) : (
            <span style={btn(false)}>Next →</span>
          )}
          </div>
        ) : null}
      </div>
    </div>
  );
}
