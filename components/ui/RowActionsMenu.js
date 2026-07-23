'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import Link from 'next/link';
import { IconMoreVertical } from '../icons';

// Compact "⋮" overflow menu for a data-table row's actions -- replaces the
// stacked-underlined-text-link pattern (View / Collect / Test / Delete, one
// per line, wrapping to 2 lines per row) that made dense tables look dated.
// Click-outside-to-close is the same pattern as components/layout/UserMenu.js,
// but the panel itself is NOT a plain `position: absolute` child of the
// trigger the way UserMenu.js's is.
//
// ⛔ Bug found 2026-07-24, live-verified via Playwright against the deployed
// app the same day this component shipped: UserMenu.js's absolute-positioned-
// child pattern works fine in the header (no scrolling ancestor), but every
// real usage of THIS component is inside app/globals.css's `.table-container`
// (`overflow-x: auto; overflow-y: auto`) -- and `overflow: auto` on an
// ancestor clips ANY absolutely-positioned descendant that would render
// outside its bounds, full stop, regardless of z-index. The menu was
// rendering but completely invisible (confirmed via a real click-and-
// screenshot against the live server, not just a build check -- `npm run
// build` only verifies the JSX compiles, it can't catch a CSS clipping bug
// like this one). Fixed by portaling the panel to `document.body` and
// positioning it with `position: fixed` from the trigger's own
// getBoundingClientRect() -- `fixed` positioning escapes every ancestor's
// `overflow`, so this is now safe to use inside ANY scrollable container,
// not just this one table.
//
// ⛔ Found in the 2026-07-23 bug sweep: the commit that shipped this fix
// (c05811a) carried no package.json version bump and no matching entry in
// `releaseNotes` (app/api/system/update-status/route.js), violating this
// repo's own Versioning Policy ("bump patch on any push that touches UI or
// logic... update releaseNotes alongside every version bump"). Retroactively
// documented as a bullet under the 2.23.1 release notes entry (the next
// version that actually shipped after this fix) rather than cutting a new
// version number after the fact.
export default function RowActionsMenu({ actions }) {
  const [open, setOpen] = useState(false);
  const [coords, setCoords] = useState(null); // { top, right } in viewport px
  const triggerRef = useRef(null);
  const panelRef = useRef(null);

  const close = useCallback(() => setOpen(false), []);

  const openMenu = useCallback(() => {
    const rect = triggerRef.current?.getBoundingClientRect();
    if (rect) {
      setCoords({ top: rect.bottom + 4, right: window.innerWidth - rect.right });
    }
    setOpen(true);
  }, []);

  useEffect(() => {
    if (!open) return undefined;

    function onClickOutside(e) {
      if (
        panelRef.current &&
        !panelRef.current.contains(e.target) &&
        triggerRef.current &&
        !triggerRef.current.contains(e.target)
      ) {
        close();
      }
    }
    // Any scroll while open (the table container, the page, etc.) would
    // otherwise leave a fixed-position panel visually detached from the
    // trigger it belongs to -- simplest correct behavior is to close it,
    // the same way a native OS context menu closes on scroll.
    function onScroll() {
      close();
    }

    document.addEventListener('mousedown', onClickOutside);
    window.addEventListener('scroll', onScroll, true); // capture -- table scroll doesn't bubble to window
    window.addEventListener('resize', onScroll);
    return () => {
      document.removeEventListener('mousedown', onClickOutside);
      window.removeEventListener('scroll', onScroll, true);
      window.removeEventListener('resize', onScroll);
    };
  }, [open, close]);

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        aria-label="Row actions"
        onClick={() => (open ? close() : openMenu())}
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: 28,
          height: 28,
          padding: 0,
          background: open ? 'var(--bg-primary)' : 'transparent',
          border: '1px solid transparent',
          borderRadius: 'var(--radius-sm)',
          color: 'var(--text-muted)',
          cursor: 'pointer',
          transition: 'background 0.12s',
        }}
        onMouseEnter={(e) => {
          if (!open) e.currentTarget.style.background = 'var(--bg-primary)';
        }}
        onMouseLeave={(e) => {
          if (!open) e.currentTarget.style.background = 'transparent';
        }}
      >
        <IconMoreVertical width={16} height={16} />
      </button>

      {open &&
        coords &&
        createPortal(
          <div
            ref={panelRef}
            style={{
              position: 'fixed',
              top: coords.top,
              right: coords.right,
              background: 'var(--bg-card)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-sm)',
              boxShadow: 'var(--shadow-md)',
              minWidth: 160,
              overflow: 'hidden',
              zIndex: 1000,
              animation: 'fadeIn 0.12s ease',
            }}
          >
            {actions.map((action, i) => {
              const color = action.danger ? 'var(--red)' : 'var(--text-primary)';
              const itemStyle = {
                display: 'block',
                width: '100%',
                textAlign: 'left',
                padding: '8px 12px',
                fontSize: 'var(--text-base)',
                color,
                background: 'none',
                border: 'none',
                textDecoration: 'none',
                cursor: action.disabled ? 'not-allowed' : 'pointer',
                opacity: action.disabled ? 0.5 : 1,
                fontFamily: 'inherit',
              };
              if (action.type === 'link') {
                return (
                  <Link
                    key={i}
                    href={action.href}
                    style={itemStyle}
                    onClick={close}
                    onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-primary)')}
                    onMouseLeave={(e) => (e.currentTarget.style.background = 'none')}
                  >
                    {action.label}
                  </Link>
                );
              }
              return (
                <button
                  key={i}
                  type="button"
                  disabled={action.disabled}
                  style={itemStyle}
                  onClick={() => {
                    // Deliberately does NOT close the menu -- a caller
                    // reporting `pending`/`pendingLabel` (Collect/Test, which
                    // can run for up to ~2 minutes) needs somewhere to show
                    // that state, and this component has nowhere else to
                    // show it. Closes on the next outside click/scroll
                    // instead, same as any other dropdown.
                    action.onClick();
                  }}
                  onMouseEnter={(e) => {
                    if (!action.disabled) e.currentTarget.style.background = 'var(--bg-primary)';
                  }}
                  onMouseLeave={(e) => (e.currentTarget.style.background = 'none')}
                >
                  {action.pending ? action.pendingLabel || action.label : action.label}
                </button>
              );
            })}
          </div>,
          document.body
        )}
    </>
  );
}
