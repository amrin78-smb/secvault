// lib/pagination.js
//
// Shared server-side pagination. Pure, dependency-free CommonJS — no DB, no
// React — so it is unit-testable and usable from both Server Components and
// API routes.
//
// ── WHY SERVER-SIDE, AND WHY THE URL ──────────────────────────────────────
// Every paginated view in this app keeps its page in the query string, the
// same convention as the dashboard's `?tab=`, `/topology`'s `?view=` and
// `/logs`'s filters. That makes a page linkable, pasteable into a ticket, and
// survivable across AutoRefresh's router.refresh(). Client-side slicing would
// also mean fetching every row to show fifty of them, which is what the
// unbounded pages were already doing.
//
// ⛔ A PAGE NUMBER IS USER INPUT. `resolvePage()` always returns a usable
// integer — never NaN, never negative, never the caller's raw string — because
// an unvalidated value flowing into a LIMIT/OFFSET is both a broken page and a
// query planner problem.
//
// ⛔ THE TOTAL MUST BE HONEST. `describeRange()` exists so a view says "51-100
// of 1,522" rather than implying the fifty rows on screen are everything. A
// list that silently shows its first page as though it were the whole set is
// the same class of lie as a truncated search result presented as complete.

'use strict';

const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 500;

/**
 * Resolve a raw `?page=` value to a usable 1-based page number.
 *
 * ⛔ Always returns >= 1. Handles the array Next.js produces for a repeated
 * param (`?page=2&page=9`) by taking the first, and anything unparseable
 * becomes page 1 rather than an empty view — a blank list is
 * indistinguishable from "no results".
 */
function resolvePage(raw) {
  const value = Array.isArray(raw) ? raw[0] : raw;
  const n = parseInt(value, 10);
  if (!Number.isFinite(n) || n < 1) return 1;
  return n;
}

function resolvePageSize(raw, def) {
  const fallback = Number.isFinite(Number(def)) ? Math.trunc(Number(def)) : DEFAULT_PAGE_SIZE;
  const value = Array.isArray(raw) ? raw[0] : raw;
  const n = parseInt(value, 10);
  if (!Number.isFinite(n) || n < 1) return fallback;
  return Math.min(n, MAX_PAGE_SIZE);
}

/** Total pages for a row count. Always >= 1, so "page 1 of 1" reads correctly on an empty list. */
function totalPages(total, pageSize) {
  const t = Number(total);
  const s = Number(pageSize) || DEFAULT_PAGE_SIZE;
  if (!Number.isFinite(t) || t <= 0) return 1;
  return Math.max(1, Math.ceil(t / s));
}

/**
 * LIMIT/OFFSET for a page, clamped so a page number past the end returns the
 * LAST page rather than an empty view.
 *
 * ⛔ Clamping matters: deleting rows can leave a bookmarked `?page=40` pointing
 * past the end, and an empty table there reads as "everything is gone".
 */
function pageWindow(page, pageSize, total) {
  const size = Number(pageSize) || DEFAULT_PAGE_SIZE;
  const pages = totalPages(total, size);
  const p = Math.min(Math.max(resolvePage(page), 1), pages);
  return { page: p, pageSize: size, limit: size, offset: (p - 1) * size, totalPages: pages };
}

/**
 * Build an href preserving every other query param.
 *
 * ⛔ Preserving them is the point: losing the active filter when you click
 * "next" silently changes what you are looking at halfway through reading it.
 * A null/undefined value REMOVES that param, which is how "page 1" drops the
 * `page=` noise from the URL.
 */
function buildPageHref(basePath, searchParams, overrides) {
  const sp = new URLSearchParams();
  const src = searchParams || {};
  for (const [k, v] of Object.entries(src)) {
    if (v === undefined || v === null || v === '') continue;
    sp.set(k, Array.isArray(v) ? v[0] : String(v));
  }
  for (const [k, v] of Object.entries(overrides || {})) {
    if (v === undefined || v === null || v === '') sp.delete(k);
    else sp.set(k, String(v));
  }
  const qs = sp.toString();
  return qs ? `${basePath}?${qs}` : basePath;
}

/**
 * Human range for the current page: "51-100 of 1,522".
 *
 * ⛔ Returns null when `total` is null/unknown rather than inventing a count.
 * A view that cannot count its rows must say so, not print "1-50 of 50" and
 * imply the first page is the whole set.
 */
function describeRange(page, pageSize, total) {
  if (total === null || total === undefined || !Number.isFinite(Number(total))) return null;
  const t = Number(total);
  if (t <= 0) return 'none';
  const size = Number(pageSize) || DEFAULT_PAGE_SIZE;
  const p = Math.min(Math.max(resolvePage(page), 1), totalPages(t, size));
  const from = (p - 1) * size + 1;
  const to = Math.min(p * size, t);
  return `${from.toLocaleString()}–${to.toLocaleString()} of ${t.toLocaleString()}`;
}

/**
 * In-memory pagination, for lists already fully loaded (an engine result, a
 * computed set) where a COUNT query is not available.
 *
 * ⛔ Prefer LIMIT/OFFSET in SQL wherever the rows come from a table. This
 * exists for genuinely computed collections, not as an excuse to keep fetching
 * everything.
 */
function paginateArray(items, page, pageSize) {
  const arr = Array.isArray(items) ? items : [];
  const w = pageWindow(page, pageSize, arr.length);
  return {
    rows: arr.slice(w.offset, w.offset + w.limit),
    page: w.page,
    pageSize: w.pageSize,
    totalPages: w.totalPages,
    total: arr.length,
  };
}

module.exports = {
  DEFAULT_PAGE_SIZE,
  MAX_PAGE_SIZE,
  resolvePage,
  resolvePageSize,
  totalPages,
  pageWindow,
  buildPageHref,
  describeRange,
  paginateArray,
};
