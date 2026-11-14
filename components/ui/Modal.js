'use client';

import useFocusTrap from './useFocusTrap';

// Suite `.modal-overlay` class (app/globals.css) for the backdrop; the panel
// itself uses `.card`-equivalent surface styling inline (shadow-lg instead of
// shadow-sm, since a modal floats above everything).
// `maxWidth` (default 420) lets a caller widen the panel for a content-dense
// modal (e.g. the multi-field Edit Device form, which renders a 2-column grid
// that needs the extra width). The panel is ALWAYS height-capped to the
// viewport and scrolls internally — a long form must never clip its own
// submit button off-screen the way it did before this cap existed.
export default function Modal({ open, onClose, title, children, maxWidth = 420 }) {
  // ⛔ The focus trap lives in ./useFocusTrap so IdleTimeout cannot have a
  // second, different one — it previously had NONE at all. Escape closes here
  // because a Modal is something you opened and may abandon; see that file for
  // why the idle warning deliberately passes no handler.
  const panelRef = useFocusTrap({ active: open, onEscape: onClose });

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
