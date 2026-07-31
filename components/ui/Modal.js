'use client';

import { useEffect, useRef } from 'react';

// Elements a focus trap should cycle through inside the dialog panel.
const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

// Suite `.modal-overlay` class (app/globals.css) for the backdrop; the panel
// itself uses `.card`-equivalent surface styling inline (shadow-lg instead of
// shadow-sm, since a modal floats above everything).
// `maxWidth` (default 420) lets a caller widen the panel for a content-dense
// modal (e.g. the multi-field Edit Device form, which renders a 2-column grid
// that needs the extra width). The panel is ALWAYS height-capped to the
// viewport and scrolls internally — a long form must never clip its own
// submit button off-screen the way it did before this cap existed.
export default function Modal({ open, onClose, title, children, maxWidth = 420 }) {
  const panelRef = useRef(null);
  const previouslyFocusedRef = useRef(null);

  useEffect(() => {
    if (!open) return undefined;

    // Remember what had focus (the control that opened this modal) so it can
    // be restored on close, and move focus into the dialog itself — without
    // this, focus stays on the triggering element behind the overlay and Tab
    // continues through the rest of the page instead of the dialog.
    previouslyFocusedRef.current = document.activeElement;
    const initialFocusables = panelRef.current
      ? Array.from(panelRef.current.querySelectorAll(FOCUSABLE_SELECTOR))
      : [];
    (initialFocusables[0] || panelRef.current)?.focus();

    function handleKeyDown(e) {
      if (e.key === 'Escape') {
        onClose?.();
        return;
      }
      // Trap Tab/Shift+Tab inside the dialog so the underlying page's
      // controls (still visually present behind the translucent overlay)
      // can't be reached or activated via keyboard while the modal is open.
      if (e.key === 'Tab' && panelRef.current) {
        const nodes = Array.from(panelRef.current.querySelectorAll(FOCUSABLE_SELECTOR));
        if (nodes.length === 0) {
          e.preventDefault();
          return;
        }
        const first = nodes[0];
        const last = nodes[nodes.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    }

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      previouslyFocusedRef.current?.focus?.();
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        style={{
          width: '100%',
          maxWidth,
          // Overlay adds 16px padding each side (.modal-overlay) — cap the panel
          // to the remaining viewport height and scroll its own content so a
          // tall form is always fully reachable, submit button included.
          maxHeight: 'calc(100vh - 32px)',
          overflowY: 'auto',
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          boxShadow: 'var(--shadow-lg)',
          padding: 20,
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {title && (
          <h2 style={{ marginBottom: 16, fontSize: 'var(--text-lg)', fontWeight: 600, color: 'var(--text-primary)' }}>
            {title}
          </h2>
        )}
        {children}
      </div>
    </div>
  );
}
