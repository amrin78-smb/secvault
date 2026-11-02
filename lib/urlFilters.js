/**
 * The URL is the filter state. This is the arithmetic on it.
 *
 * ⛔ WHY THIS IS PURE AND SHARED, WHEN FOUR PAGES EACH HAD THEIR OWN COPY.
 * `/devices`, `/alerts`, `/exposure` and `/vpn` each hand-rolled the same three
 * steps — merge a change into the query, drop the keys that went empty, push
 * the result — and each got a different subset of them right. The cost is
 * recorded in the codebase itself: `ExposureFilters.js` carries a comment
 * admitting that choosing a firewall silently reset a reader who had selected
 * 200 rows back to 50, because that copy REBUILT the query from the two
 * parameters it knew about instead of merging into the one that existed. Its
 * own header had claimed everything but `page` was carried over.
 *
 * ⛔ SO THE RULE IS MERGE, NEVER REBUILD. A filter control knows about its own
 * parameters and must not have an opinion about anybody else's — `limit`, a
 * `?tab=`, a sort column, a saved-view id. Rebuilding is how a control silently
 * discards state it was never told about, and the symptom is always the same
 * shape: something the operator deliberately chose quietly reverts, with no
 * error and nothing on screen to explain it.
 *
 * ⛔ `page` IS THE ONE EXCEPTION AND IT RESETS BY DEFAULT. A page number from a
 * larger result set lands past the end of a smaller one and renders an empty
 * table — which on `/exposure` reads as "no exposure found" rather than "wrong
 * page". Three of the four copies had worked this out independently; the
 * default here is what stops the fourth from having to.
 *
 * CommonJS so `node:test` can require it with no transform, like `rbac.js`.
 */

'use strict';

/**
 * Parameters that are not filters and must never appear as a removable chip.
 *
 * ⛔ `tab`/`vtab`/`view` ARE IN HERE BECAUSE A CHIP THAT REMOVES THEM IS A CHIP
 * THAT NAVIGATES SOMEWHERE ELSE. They choose which workspace you are looking
 * at, and clearing them from a "filters" row would dump the operator back on a
 * different tab while appearing to have narrowed a result set.
 */
// ⛔ `dHours` IS THE VPN DETECTION WINDOW, AND IT IS NOT A FILTER (v2.220.0).
// Every detection in lib/engines/vpnDetections.js is COMPUTED OVER it, and its
// baseline gates are expressed in days — so "clear" cannot mean "all of time".
// Measured before this line existed: without it, "Clear filters" dropped
// `dHours=168` and silently returned a 7-day investigation to the 24-hour
// default, changing every number on the page while appearing to do nothing but
// remove a chip. It also rendered as an UNKNOWN chip, which is the honest
// default for a parameter this module has never heard of and the wrong answer
// for one it should simply leave alone.
const NON_FILTER_PARAMS = new Set([
  'page', 'limit', 'tab', 'vtab', 'view', 'sort', 'dir', 'viewId', 'dHours',
  // ⛔ `cols` IS A COLUMN SELECTION, NOT A FILTER (v2.221.2) — AND THIS IS THE
  // SECOND TIME THIS EXACT MISTAKE HAS BEEN MADE IN TWO RELEASES. `dHours`
  // above was the first. A filter changes WHICH ROWS match; a column choice
  // changes what you can see OF a row, so it must neither render as a chip
  // ("cols: ha,vendor,rules ×" is meaningless to a reader) nor be dropped by
  // "Clear filters", which would silently restore three columns the operator
  // had deliberately hidden.
  //
  // ⛔ THE PATTERN IS WORTH NAMING: any parameter a new CONTROL writes is a
  // non-filter unless it narrows the result set. Both times the bug appeared
  // the moment a control adopted the shared FilterBar, and both times it was
  // found by looking at the rendered chips rather than by a test.
  'cols',

  // ⛔ A REDIRECT WRITES PARAMETERS TOO, AND THAT IS THE THIRD INSTANCE OF THIS
  // SAME MISTAKE. `dHours` was the first, `cols` the second, and both of those
  // were written by a CONTROL. These six are written by the SERVER — a
  // middleware refusal, a Server Action's redirect after a delete — which is
  // why extending the rule to "any parameter a control writes" still missed
  // them.
  //
  // Measured: `/devices?scopeBlocked=%2Fcompliance` (middleware.js, for every
  // scoped account refused a surface) rendered a chip reading
  // `scopeBlocked /compliance ×` plus a "Clear filters" link, over a table with
  // NO filter applied. The table IS short, because the account is
  // scope-narrowed — so the chip reads as the explanation, and clearing it
  // changes nothing. The operator concludes the page is broken. Same shape for
  // `?error=…&accounts=…` after a refused delete and `?confirmDelete=<uuid>`
  // while the delete modal is open.
  //
  // ⛔ THE REAL FIX IS THE GUARD, NOT THIS LIST. `tests/urlFilters.test.js` now
  // enumerates every `searchParams?.X` the FilterBar-adopting pages read and
  // requires each to be either one of that page's own filter defs or a member
  // of this set — so the FOURTH instance fails a build instead of shipping.
  'scopeBlocked', 'confirmDelete', 'error', 'accounts', 'deleteJob', 'deleteError',
]);

/** Keys reset whenever any filter changes. */
const DEFAULT_RESET = ['page'];

/**
 * Merge `changes` into an existing query string.
 *
 * @param {string|URLSearchParams} current  the query as it stands
 * @param {Object} changes  `{key: value}`; `''`/`null`/`undefined` REMOVES a key
 * @param {{reset?: string[]}} [opts]  keys to drop as well (default `['page']`)
 * @returns {string} the query string WITHOUT a leading '?'
 */
function mergeFilterQuery(current, changes, opts) {
  const params = new URLSearchParams(
    typeof current === 'string' ? current : (current ? current.toString() : '')
  );
  const reset = (opts && opts.reset) || DEFAULT_RESET;

  for (const [key, value] of Object.entries(changes || {})) {
    // ⛔ An EMPTY STRING deletes rather than being written through. "All" in a
    // select is the absence of a filter, not a filter whose value is nothing —
    // and `?vendor=` in a URL is a filter the server has to decide how to read.
    if (value === '' || value === null || value === undefined) params.delete(key);
    else params.set(key, String(value));
  }
  // Reset AFTER the merge, so an explicit `{page: 3}` cannot survive by being
  // applied first. A caller that genuinely wants to set a page passes
  // `{reset: []}`.
  for (const key of reset) {
    if (!Object.prototype.hasOwnProperty.call(changes || {}, key)) params.delete(key);
  }
  return params.toString();
}

/** `mergeFilterQuery` plus the path, ready for `router.push`. */
function filterHref(basePath, current, changes, opts) {
  const qs = mergeFilterQuery(current, changes, opts);
  return qs ? `${basePath}?${qs}` : basePath;
}

/**
 * The query with every filter removed — what "Clear filters" goes to.
 *
 * ⛔ IT KEEPS THE NON-FILTER PARAMETERS. Clearing filters must not also throw
 * away the tab you are on or the rows-per-page you chose; those are not
 * filters, and a control that resets them is doing something the operator did
 * not ask for. (Three of the four hand-rolled copies pushed a bare path here,
 * which did exactly that.)
 */
function clearedFilterQuery(current) {
  const params = new URLSearchParams(
    typeof current === 'string' ? current : (current ? current.toString() : '')
  );
  for (const key of [...params.keys()]) {
    if (!NON_FILTER_PARAMS.has(key)) params.delete(key);
  }
  params.delete('page');
  return params.toString();
}

/** Are any filters applied at all? Drives whether the summary row renders. */
function hasActiveFilters(current) {
  const params = new URLSearchParams(
    typeof current === 'string' ? current : (current ? current.toString() : '')
  );
  for (const [key, value] of params.entries()) {
    if (!NON_FILTER_PARAMS.has(key) && value !== '') return true;
  }
  return false;
}

/**
 * The applied filters, as removable chips.
 *
 * ⛔ A FILTER WITH NO DEFINITION IS STILL SHOWN, under its raw key. The
 * alternative — skipping it — hides an active filter from the one row whose job
 * is to say what is active, and the operator then cannot work out why the table
 * is short. This is the "unknown is not nothing" rule applied to the UI's own
 * state: an unrecognised filter is a filter we could not LABEL, never a filter
 * that is not there. The brief's own requirement is the same one: never leave
 * an active filter without an indicator.
 *
 * @param {string|URLSearchParams} current
 * @param {{key:string,label:string,options?:{value:string,label:string}[]}[]} defs
 * @returns {{key:string,label:string,value:string,valueLabel:string,known:boolean}[]}
 */
function activeFilterChips(current, defs) {
  const params = new URLSearchParams(
    typeof current === 'string' ? current : (current ? current.toString() : '')
  );
  const byKey = new Map((defs || []).map((d) => [d.key, d]));
  const out = [];
  for (const [key, value] of params.entries()) {
    if (NON_FILTER_PARAMS.has(key) || value === '') continue;
    const def = byKey.get(key);
    const opt = def && def.options && def.options.find((o) => o.value === value);
    out.push({
      key,
      label: def ? def.label : key,
      value,
      // The option's own wording where we have it, so the chip reads as the
      // control did ("Lapsed licence", not "expired").
      valueLabel: opt ? opt.label : value,
      known: Boolean(def),
    });
  }
  return out;
}

module.exports = {
  NON_FILTER_PARAMS,
  mergeFilterQuery,
  filterHref,
  clearedFilterQuery,
  hasActiveFilters,
  activeFilterChips,
};
