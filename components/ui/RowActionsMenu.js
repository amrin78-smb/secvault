'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { IconMoreVertical } from '../icons';

// Compact "⋮" overflow menu for a data-table row's actions -- replaces the
// stacked-underlined-text-link pattern (View / Collect / Test / Delete, one
// per line, wrapping to 2 lines per row) that made dense tables look dated.
// Same click-outside-to-close pattern as components/layout/UserMenu.js.
//
// `actions`: array of either
//   { type: 'link', label, href }
//   { type: 'button', label, onClick, disabled?, pending?, pendingLabel?, danger? }
// Rendered in the order given. A `danger: true` button/link (e.g. Delete)
// gets --red text instead of the default --text-primary, matching this
// app's "red is reserved for real danger, not decoration" convention.
export default function RowActionsMenu({ actions }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    function onClickOutside(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, []);

  return (
    <div ref={ref} style={{ position: 'relative', display: 'inline-block' }}>
      <button
        type="button"
        aria-label="Row actions"
        onClick={() => setOpen((o) => !o)}
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

      {open && (
        <div
          style={{
            position: 'absolute',
            top: 'calc(100% + 4px)',
            right: 0,
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)',
            boxShadow: 'var(--shadow-md)',
            minWidth: 140,
            overflow: 'hidden',
            zIndex: 50,
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
                  onClick={() => setOpen(false)}
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
                  // Deliberately does NOT close the menu -- a caller reporting
                  // `pending`/`pendingLabel` (Collect/Test, which can run for
                  // up to ~2 minutes) needs somewhere to show that state, and
                  // this component has nowhere else to show it. Closes on the
                  // next outside click instead, same as any other dropdown.
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
        </div>
      )}
    </div>
  );
}
