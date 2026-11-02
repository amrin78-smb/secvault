'use strict';

// COLUMN SELECTION FOR A WIDE TABLE — which columns are shown, and which
// ones a narrow viewport drops first.
//
// PURE. Takes a column registry and a URL value, returns what to render.
//
// ⛔ ═══ THE SELECTION LIVES IN THE URL, NOT IN localStorage ══════════════
// The obvious implementation is the theme/density/corners family: stamp a
// preference on the client and read it back. That is wrong here for three
// reasons, and the second is the decisive one:
//
//   1. These tables are SERVER-RENDERED. A localStorage value is not
//      available when the HTML is built, so the first paint would show every
//      column and then drop some — a layout shift on every page load.
//   2. ⛔ /devices ALREADY HAS SAVED VIEWS, and a saved view stores the query
//      string verbatim. Put the columns in the URL and "Fortinet, failing
//      collectors, just the four columns I care about" is nameable for free.
//      In localStorage it would be a second kind of state that saved views
//      silently do not capture — a view that restores the wrong table.
//   3. A column choice is then linkable and pasteable into a ticket, which is
//      this product's stated convention for every other table state.
//
// ⛔ ═══ A REQUIRED COLUMN CANNOT BE HIDDEN ══════════════════════════════
// The identity column is how a row is read at all, and the actions column is
// how anything is done to it. A chooser that can empty a table of meaning is
// a way for an operator to break their own page and not know why.
//
// ⛔ ═══ PRIORITY IS NOT THE SAME AS ORDER ═══════════════════════════════
// `priority` decides which columns a NARROW VIEWPORT drops; the registry's
// order decides where they sit. They are deliberately separate: Vendor sits
// second because that is where it reads best, and is among the first to go
// because it is the least load-bearing. Tying the two would force a column
// to be unimportant in order to be late.

const MAX_HIDDEN = 32; // a sanity bound on a URL-supplied list

/**
 * Resolve which columns to render.
 *
 * @param {Array<{key, label, required?, priority?}>} defs  in display order
 * @param {string} value  the `cols` query value: a comma-separated list of
 *                        the keys to HIDE.
 *
 * ⛔ THE PARAMETER NAMES WHAT IS HIDDEN, NOT WHAT IS SHOWN, and that choice
 * matters for links that outlive a release. If it named the visible set, a
 * column added later would be absent from every saved view and every pasted
 * URL — silently, because the list would simply not mention it. Naming the
 * hidden set means a new column appears for everyone by default, which is the
 * safe direction on a security product.
 */
function resolveColumns(defs, value) {
  const all = Array.isArray(defs) ? defs : [];
  const byKey = new Map(all.map((d) => [d.key, d]));
  const hidden = new Set();

  if (typeof value === 'string' && value !== '') {
    for (const raw of value.split(',').slice(0, MAX_HIDDEN)) {
      const key = raw.trim();
      if (!key) continue;
      const def = byKey.get(key);
      // ⛔ AN UNKNOWN KEY IS IGNORED, not an error and not a blank table. It
      // is what a link from an older release looks like after a column is
      // renamed, and refusing the whole selection would be worse than
      // honouring the part that still makes sense.
      if (!def) continue;
      // ⛔ A REQUIRED COLUMN IS NEVER HIDDEN, however the URL was written.
      // The guard is here rather than only in the chooser UI, because the URL
      // can be typed.
      if (def.required) continue;
      hidden.add(key);
    }
  }

  const columns = all.map((d) => ({ ...d, hidden: hidden.has(d.key) }));
  return {
    columns,
    visible: columns.filter((c) => !c.hidden),
    hidden: columns.filter((c) => c.hidden),
    hiddenCount: hidden.size,
  };
}

/**
 * The `cols` value after toggling one column.
 *
 * Returns '' when nothing is hidden, so the parameter DISAPPEARS from the URL
 * rather than lingering as `cols=` — `mergeFilterQuery` deletes an empty
 * value, and a bare `cols=` in a pasted link reads as a setting somebody made.
 */
function toggleColumn(defs, value, key) {
  const { columns } = resolveColumns(defs, value);
  const def = columns.find((c) => c.key === key);
  if (!def || def.required) return typeof value === 'string' ? value : '';
  const hidden = new Set(columns.filter((c) => c.hidden).map((c) => c.key));
  if (hidden.has(key)) hidden.delete(key);
  else hidden.add(key);
  // Emitted in REGISTRY ORDER, not insertion order, so the same selection
  // always produces the same string — otherwise two identical views save as
  // two different query strings.
  return columns.filter((c) => hidden.has(c.key)).map((c) => c.key).join(',');
}

/**
 * Which priority bands exist in a registry, so a stylesheet can be checked
 * against it rather than against a number somebody remembered.
 *
 * ⛔ 1 IS "NEVER DROP". A column with no priority is treated as 1, because
 * the safe default for an unclassified column on a security product is to
 * keep showing it.
 */
function priorityOf(def) {
  const p = Number(def && def.priority);
  return Number.isFinite(p) && p >= 1 ? Math.min(p, 4) : 1;
}

module.exports = { resolveColumns, toggleColumn, priorityOf, MAX_HIDDEN };
