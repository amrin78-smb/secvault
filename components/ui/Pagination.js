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
export default function Pagination({
  basePath, searchParams, page, pageSize, total, label, pages, paramName,
}) {
  const param = paramName || 'page';
  const totalPages = pages || calcTotalPages(total, pageSize);
  const cur = Math.min(Math.max(Number(page) || 1, 1), totalPages);
  const range = describeRange(cur, pageSize, total);

  // A single page of results needs no controls, but the count is still worth
  // showing — it is the difference between "3 findings" and "3 shown".
  const showControls = totalPages > 1;

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
            Page {cur.toLocaleString()} of {totalPages.toLocaleString()}
          </span>
          {cur < totalPages ? (
            <Link href={buildPageHref(basePath, searchParams, { [param]: cur + 1 })} style={btn(true)}>
              Next →
            </Link>
          ) : (
            <span style={btn(false)}>Next →</span>
          )}
        </div>
      ) : null}
    </div>
  );
}
