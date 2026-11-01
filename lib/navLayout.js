/**
 * Where the navigation rail changes shape, in ONE place.
 *
 * ⛔ WHY THIS FILE EXISTS RATHER THAN THREE COPIES OF TWO NUMBERS.
 * The rail has three shapes (full, icon-only, off-canvas) and three parties
 * need to agree on which one is in force: the blocking inline script that sets
 * it before first paint, the stylesheet that lays it out, and the React
 * component that decides whether the collapse button means anything. Written
 * as literals that is 1024 and 1280 in three languages, and the failure is
 * silent and ugly — the stylesheet going off-canvas while the component still
 * thinks it is wide leaves the operator with no navigation and no trigger to
 * open any.
 *
 * So the breakpoints live here, the script is BUILT from them, and
 * `app/globals.css` contains NO WIDTHS AT ALL for the rail: it keys purely on
 * the `data-nav` attribute this sets. There is one width reader in the product.
 *
 * ⛔ AND THE READER IS `innerWidth`, NOT A MEDIA QUERY, DELIBERATELY. The two
 * disagree by the width of a scrollbar (a media query measures the viewport
 * including it, `innerWidth` does too, but `clientWidth` does not — and mixing
 * any two of them puts the boundary in two places). Keying the CSS on an
 * attribute instead of a `@media` rule means there is nothing for the script to
 * disagree WITH.
 *
 * ⛔ THE UNKNOWN WIDTH IS `wide`, WHICH HIDES NOTHING. This renders on the
 * server, where there is no viewport, and it runs for one paint before the
 * script executes. Guessing `drawer` there would serve a brief screen with the
 * navigation pushed off the side and, if the script then failed, permanently.
 * The safe direction for a navigation default is the one that shows every
 * destination.
 */

'use strict';

/** Below this, the rail cannot share the screen with content: it goes off-canvas. */
const NAV_DRAWER_BELOW = 1024;

/**
 * Below this the rail is icon-only.
 *
 * ⛔ 1280, i.e. it collapses on a 1280-wide laptop BEFORE anything is clipped,
 * not after. The complaint this answers is that dense workspaces — the 706-rule
 * table, the 14-tab analysis strip — became unusable at intermediate widths
 * while the rail still held its full 240px. A rail that waits until the content
 * is already broken has waited too long.
 */
const NAV_RAIL_BELOW = 1280;

/** The three shapes, widest first. */
const NAV_MODES = ['wide', 'rail', 'drawer'];

/** The attribute on <html> that every other party reads. */
const NAV_MODE_ATTR = 'data-nav';

/** Fired on `window` whenever the shape changes, so React can react to it. */
const NAV_MODE_EVENT = 'secvault:navmode';

/**
 * @param {number} width viewport width in CSS pixels
 * @returns {'wide'|'rail'|'drawer'}
 */
function navModeFor(width) {
  // ⛔ A non-number is not a narrow screen. See the note above: an unmeasurable
  // width falls back to the shape that conceals nothing, which is this
  // codebase's "a failed read is not a measurement" rule pointed at a layout.
  if (typeof width !== 'number' || !Number.isFinite(width) || width <= 0) return 'wide';
  if (width < NAV_DRAWER_BELOW) return 'drawer';
  if (width < NAV_RAIL_BELOW) return 'rail';
  return 'wide';
}

/** The shape currently in force, read off <html>. Safe on the server. */
function navModeFromDocument() {
  if (typeof document === 'undefined') return 'wide';
  const v = document.documentElement.getAttribute(NAV_MODE_ATTR);
  return NAV_MODES.includes(v) ? v : 'wide';
}

/**
 * Inline <script> body: stamps the shape before first paint and keeps it
 * current on resize. Same no-flash contract as THEME/CORNERS/DENSITY, and the
 * fourth member of that family — except this one also installs a listener,
 * because unlike a theme the right answer changes while the page is open.
 *
 * ⛔ The attribute is ALWAYS set, including for `wide`, so React can read one
 * value rather than treating "absent" as a fourth state to interpret.
 */
const NAV_MODE_INIT_SCRIPT =
  '(function(){try{var e=document.documentElement;'
  + 'function m(){var w=window.innerWidth;'
  + `return w<${NAV_DRAWER_BELOW}?'drawer':(w<${NAV_RAIL_BELOW}?'rail':'wide');}`
  + `function a(){var n=m();if(e.getAttribute('${NAV_MODE_ATTR}')!==n){`
  + `e.setAttribute('${NAV_MODE_ATTR}',n);`
  + `try{window.dispatchEvent(new CustomEvent('${NAV_MODE_EVENT}',{detail:n}));}catch(x){}}}`
  + 'a();window.addEventListener("resize",a,{passive:true});}catch(e){}})();';

module.exports = {
  NAV_DRAWER_BELOW,
  NAV_RAIL_BELOW,
  NAV_MODES,
  NAV_MODE_ATTR,
  NAV_MODE_EVENT,
  NAV_MODE_INIT_SCRIPT,
  navModeFor,
  navModeFromDocument,
};
