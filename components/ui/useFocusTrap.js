'use client';

import { useEffect, useRef } from 'react';

// components/ui/useFocusTrap.js
//
// ⛔ ONE FOCUS TRAP, BECAUSE TWO WOULD DRIFT. This was `Modal.js`'s private
// implementation and `components/layout/IdleTimeout.js` had NONE — it set
// `role="alertdialog" aria-modal="true"` and then did nothing about focus
// (`grep -c focus` returned 0). `aria-modal` is a PROMISE to assistive
// technology that everything outside the dialog is inert, so declaring it
// without moving focus in is worse than not declaring it at all: the user's
// focus point is still out in a page the screen reader has been told to ignore,
// and "Stay signed in" — the only control that saves their session — is
// unreachable. Extracted rather than copied, for the reason this repo gives
// every time it reuses an evaluator: two implementations of one question
// eventually disagree, and here the disagreement is somebody being signed out
// of a firewall console mid-sentence.
//
// Four mechanisms, and `aria-modal` is only honest with all four:
//   1. remember what had focus, so it can be given back on close;
//   2. move focus INTO the panel;
//   3. confine Tab/Shift+Tab to the panel while it is open;
//   4. restore focus on unmount.
//
// ⛔ ESCAPE IS OPT-IN, AND THAT IS NOT TIDINESS. `Modal` closes on Escape
// because its dialogs are things you opened and may abandon. `IdleTimeout`
// passes NO handler on purpose: there is nothing to close. The dialog reports a
// server-side expiry it does not own, so dismissing it would hide the warning
// while the session still ends — the countdown would run out behind a page that
// looked fine. A dialog with no dismissal is the correct shape for a deadline.

// Elements a focus trap should cycle through inside the dialog panel.
export const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * @param {{active: boolean, onEscape?: () => void}} opts
 * @returns {{current: HTMLElement|null}} attach to the dialog PANEL, not the
 *   backdrop — the panel is the dialog, and a trap anchored on the overlay
 *   would count the backdrop's own children as inside it.
 */
export default function useFocusTrap({ active, onEscape }) {
  const panelRef = useRef(null);
  const previouslyFocusedRef = useRef(null);

  useEffect(() => {
    if (!active) return undefined;

    // ⛔ Re-queried on every Tab rather than captured once: a dialog's
    // focusable set changes while it is open (a button becoming enabled, a
    // conditional field appearing), and a stale list would skip or trap on an
    // element that is no longer there.
    const focusables = () => (panelRef.current
      ? Array.from(panelRef.current.querySelectorAll(FOCUSABLE_SELECTOR))
      : []);

    previouslyFocusedRef.current = document.activeElement;
    (focusables()[0] || panelRef.current)?.focus();

    function handleKeyDown(e) {
      if (e.key === 'Escape') {
        onEscape?.();
        return;
      }
      if (e.key === 'Tab' && panelRef.current) {
        const nodes = focusables();
        // Nothing focusable inside: swallow Tab rather than letting it walk
        // out into a page we have declared inert.
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
  }, [active, onEscape]);

  return panelRef;
}
