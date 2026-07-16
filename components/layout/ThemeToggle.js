'use client';

import { useEffect, useState } from 'react';
import { getTheme, toggleTheme } from '../../lib/theme';
import { IconSun, IconMoon } from '../icons';

/**
 * Suite-standard sun/moon theme switcher. Lives in the navy header, so it
 * uses the navy-bar ghost-button style (38x38, radius 8) and white-on-navy
 * icon coloring rather than the page token colors. Theme persistence +
 * data-theme live in lib/theme.js.
 */
export default function ThemeToggle() {
  const [theme, setTheme] = useState('light');

  useEffect(() => {
    setTheme(getTheme());
    const onTheme = (e) => setTheme(e.detail);
    window.addEventListener('secvault:theme', onTheme);
    return () => window.removeEventListener('secvault:theme', onTheme);
  }, []);

  return (
    <button
      type="button"
      onClick={() => setTheme(toggleTheme())}
      aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
      title={theme === 'dark' ? 'Light mode' : 'Dark mode'}
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: 38,
        height: 38,
        borderRadius: 8,
        background: 'rgba(255,255,255,0.06)',
        border: '1px solid rgba(255,255,255,0.12)',
        color: 'rgba(255,255,255,0.85)',
        cursor: 'pointer',
        flexShrink: 0,
        transition: 'background 0.15s, color 0.15s',
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.background = 'rgba(255,255,255,0.14)';
        e.currentTarget.style.color = '#fff';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = 'rgba(255,255,255,0.06)';
        e.currentTarget.style.color = 'rgba(255,255,255,0.85)';
      }}
    >
      {theme === 'dark' ? <IconSun width={18} height={18} /> : <IconMoon width={18} height={18} />}
    </button>
  );
}
