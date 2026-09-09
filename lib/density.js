'use client';

/**
 * Table density — the third member of the theme/corners family, and
 * deliberately a structural mirror of `lib/corners.js` (same storage,
 * attribute, event and no-flash-script shape), so there is one pattern to
 * learn for all three rather than three.
 *
 * Stored in localStorage, applied as a `data-density` attribute on <html>.
 *
 * ⛔ WHY THIS EXISTS. One row height cannot serve this product. A device on
 * this fleet has up to 706 firewall rules; an analyst auditing that ruleset
 * wants as many on screen as will fit, and every scroll is friction. The same
 * table shown to a manager reading a compliance score wants air. Shipping only
 * one of those is why tools feel wrong to half their users — and it is not a
 * preference we can guess from the data, so it is a control.
 *
 * `comfortable` is the DEFAULT and lives under `:root` in app/globals.css;
 * the other two override only the density tokens. That ordering matters: the
 * default must be the one that reads best to someone seeing the product for
 * the first time, because they have not found the switch yet.
 *
 * ⛔ This works ONLY because table padding and font-size resolve through
 * `var(--row-pad-y)` / `var(--row-pad-x)` / `var(--row-font)`. A table that
 * hardcodes `padding: '12px 16px'` opts itself out SILENTLY — it keeps one
 * height while every table around it changes, which reads as a broken layout
 * rather than a setting. Exactly the same failure mode as a hardcoded
 * border-radius under the corners switch. If you write a table cell, use the
 * tokens.
 *
 * ⛔ Density changes ROW GEOMETRY ONLY. It must never hide a column, truncate
 * a value, or drop a badge: a denser table has to show the same facts in less
 * space, not fewer facts. Losing information at a smaller size would make the
 * control a data-integrity setting, which is not something an operator should
 * be able to get wrong from a dropdown.
 */

export const DENSITY_KEY = 'secvault-density';

/** The default is first — a value not in this list is ignored, never guessed at. */
export const DENSITIES = ['comfortable', 'compact', 'dense'];

export const DENSITY_LABELS = {
  comfortable: 'Comfortable',
  compact: 'Compact',
  dense: 'Dense',
};

export function getDensity() {
  if (typeof document === 'undefined') return 'comfortable';
  const v = document.documentElement.getAttribute('data-density');
  return DENSITIES.includes(v) ? v : 'comfortable';
}

export function applyDensity(density) {
  if (typeof document === 'undefined') return;
  // An unrecognised value falls back to the default rather than being written
  // through — the same "never store a value you cannot render" instinct the
  // rest of this codebase applies to measurements.
  const next = DENSITIES.includes(density) ? density : 'comfortable';
  if (next === 'comfortable') document.documentElement.removeAttribute('data-density');
  else document.documentElement.setAttribute('data-density', next);
  try {
    localStorage.setItem(DENSITY_KEY, next);
  } catch (_err) {
    // ignore — the choice just won't persist across reloads
  }
  window.dispatchEvent(new CustomEvent('secvault:density', { detail: next }));
  return next;
}

/** Inline <script> body that sets data-density before first paint (no flash). */
export const DENSITY_INIT_SCRIPT =
  `(function(){try{var d=localStorage.getItem('${DENSITY_KEY}');`
  + `if(d==='compact'||d==='dense'){document.documentElement.setAttribute('data-density',d);}`
  + `}catch(e){}})();`;
