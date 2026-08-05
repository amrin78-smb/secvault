'use client';

/**
 * Corner-style handling — deliberately a byte-for-byte structural mirror of
 * lib/theme.js (same storage/attribute/event/no-flash-script shape), so there
 * is one pattern to learn for both, not two.
 *
 * Stored in localStorage, applied as a `data-corners` attribute on <html>.
 * Rounded is the default and lives under `:root` in app/globals.css; square
 * overrides ONLY the two radius tokens under `[data-corners="square"]`. A
 * no-flash inline script in the root layout applies the saved value before
 * paint, so this module only reads/toggles at runtime.
 *
 * ⛔ This works ONLY because every rounded surface resolves its radius through
 * `var(--radius)` / `var(--radius-sm)`. A component that hardcodes
 * `borderRadius: 8` opts itself out silently — it will stay rounded while
 * everything around it squares off, which reads as a rendering bug rather than
 * a style. If you add a rounded surface, use the token.
 *
 * Circles and pills are deliberately NOT covered: a status dot or avatar uses
 * `50%` and a KEV-style pill uses `--radius-pill`, none of which this switch
 * touches. Squaring those makes the UI look broken, not hard-edged.
 */

export const CORNERS_KEY = 'secvault-corners';

export function getCorners() {
  if (typeof document === 'undefined') return 'rounded';
  return document.documentElement.getAttribute('data-corners') === 'square' ? 'square' : 'rounded';
}

export function applyCorners(corners) {
  if (typeof document === 'undefined') return;
  if (corners === 'square') document.documentElement.setAttribute('data-corners', 'square');
  else document.documentElement.removeAttribute('data-corners');
  try {
    localStorage.setItem(CORNERS_KEY, corners);
  } catch (_err) {
    // ignore — the choice just won't persist across reloads
  }
  // Let any other mounted control re-sync its label.
  window.dispatchEvent(new CustomEvent('secvault:corners', { detail: corners }));
}

export function toggleCorners() {
  const next = getCorners() === 'square' ? 'rounded' : 'square';
  applyCorners(next);
  return next;
}

/** Inline <script> body that sets data-corners before first paint (no flash). */
export const CORNERS_INIT_SCRIPT =
  `(function(){try{var c=localStorage.getItem('${CORNERS_KEY}');if(c==='square'){document.documentElement.setAttribute('data-corners','square');}}catch(e){}})();`;
