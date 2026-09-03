import Link from 'next/link';

// Shared underline tab bar for server-driven `?tab=` / `?view=` navigation.
//
// This markup was copy-pasted inline into four pages before this component
// existed (`/vulnerability`, `/compliance`, `/topology`, and the 13-tab
// `/devices/[id]/analysis`), each with its own `tabLink()` helper and its own
// slightly-drifted padding and colours. New pages should use this instead.
//
// ⛔ NOT a client component and deliberately so. Each tab is a real <Link> to
// a real URL, which is what makes a tab bookmarkable, shareable, openable in a
// new tab, and restorable after the 60s AutoRefresh. A useState tab bar would
// lose the selection on every refresh — on a dashboard that polls, that is the
// difference between a usable page and one that keeps snapping back.
//
// ⛔ Defined at module top level, never nested inside another component. See
// CLAUDE.md's React rule: a component defined inside a component remounts on
// every render.
//
// @param {{href: string, label: string, key?: string}[]} tabs - already-built hrefs
// @param {string} activeHref - the href of the current tab
// @param {string} ariaLabel
export default function TabBar({ tabs, activeHref, ariaLabel = 'Sections' }) {
  if (!Array.isArray(tabs) || tabs.length === 0) return null;

  return (
    <nav
      aria-label={ariaLabel}
      style={{
        display: 'flex',
        gap: 4,
        borderBottom: '1px solid var(--border)',
        // Long tab sets scroll rather than wrapping into a ragged second row
        // or pushing the page into a horizontal scroll of its own.
        overflowX: 'auto',
        // Reserve the underline's own height so switching tabs never nudges
        // the content below by a pixel.
        marginBottom: 2,
      }}
    >
      {tabs.map((tab) => {
        const active = tab.href === activeHref;
        return (
          <Link
            key={tab.key || tab.href}
            href={tab.href}
            // aria-current is what tells a screen reader which tab is showing;
            // the colour and underline below only say it visually.
            aria-current={active ? 'page' : undefined}
            style={{
              padding: '8px 12px',
              fontSize: 'var(--text-base)',
              fontWeight: active ? 600 : 500,
              color: active ? 'var(--primary)' : 'var(--text-secondary)',
              borderBottom: active ? '2px solid var(--primary)' : '2px solid transparent',
              textDecoration: 'none',
              whiteSpace: 'nowrap',
            }}
          >
            {tab.label}
          </Link>
        );
      })}
    </nav>
  );
}
