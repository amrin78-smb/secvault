'use client';

/**
 * Dual-theme handling for SecVault, matching the NocVault suite's shared
 * pattern exactly (see e.g. netvault/lib/theme.ts). The theme is stored in
 * localStorage and applied as a `data-theme` attribute on <html>; light
 * tokens live under `:root` in app/globals.css, dark tokens under
 * `[data-theme="dark"]`. A no-flash inline script in the root layout
 * (app/layout.js) applies the saved theme before paint, so this module only
 * needs to read/toggle at runtime. Default is light.
 */

export const THEME_KEY = 'secvault-theme';

export function getTheme() {
  if (typeof document === 'undefined') return 'light';
  return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
}

export function applyTheme(theme) {
  if (typeof document === 'undefined') return;
  if (theme === 'dark') document.documentElement.setAttribute('data-theme', 'dark');
  else document.documentElement.removeAttribute('data-theme');
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch (_err) {
    // ignore — theme just won't persist across reloads
  }
  // Let any other mounted toggle re-sync its icon.
  window.dispatchEvent(new CustomEvent('secvault:theme', { detail: theme }));
}

export function toggleTheme() {
  const next = getTheme() === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  return next;
}

/** Inline <script> body that sets data-theme before first paint (no flash). */
export const THEME_INIT_SCRIPT =
  `(function(){try{var t=localStorage.getItem('${THEME_KEY}');if(t==='dark'){document.documentElement.setAttribute('data-theme','dark');}}catch(e){}})();`;
