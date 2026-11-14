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
//
// ⛔ `confineOnly` IS MECHANISM 3 ON ITS OWN, AND IT EXISTS FOR ONE CALLER
// (`components/ui/Evidence.js`). The evidence drawer already had 1, 2 and 4 —
// but in the `EvidenceProvider`, not in the panel, because the provider is what
// owns the open/close state and the identity of the mark that opened it across
// every page. Dropping the full hook into the panel would therefore have left
// TWO restores on close: the hook's captured `document.activeElement` and the
// provider's `openerRef`, with the winner decided by effect-cleanup order. That
// is a question you can only answer with the drawer open in a browser, so this
// mode removes the question instead of answering it: in `confineOnly` the hook
// NEVER reads focus, NEVER moves focus and NEVER restores focus. It adds the
// one mechanism that was missing and touches nothing that already worked.
// ⛔ It is NOT a lighter default. A caller passing it is claiming the other
// three mechanisms are implemented SOMEWHERE ELSE, and `aria-modal` is a lie
// without them — `tests/accessibleControls.test.js` pins both the default
// (all four) and this mode (confinement alone), in both directions.

// Elements a focus trap should cycle through inside the dialog panel.
export const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * The imperative half, with no React in it.
 *
 * ⛔ SPLIT OUT SO THE TRAP CAN BE EXERCISED RATHER THAN READ. Every dialog in
 * the product delegates here, and the only thing pinning that behaviour used to
 * be a handful of regexes over this file's own source — which is the shape of
 * guard that has been satisfied by a MENTION of the thing twice in this repo
 * already. There is no component render harness here and no devDependencies to
 * add one, so `win`/`doc` are injectable and the test drives this function
 * against a stand-in document. React is not involved in any of the four
 * mechanisms; it only decides WHEN they are armed.
 *
 * @param {() => (HTMLElement|null)} getPanel  Read LIVE on every key, not
 *   captured: a dialog's focusable set changes while it is open (a button
 *   becoming enabled, a conditional field appearing), and a stale panel or a
 *   stale node list would skip or trap on an element that is no longer there.
 * @param {{onEscape?: () => void, confineOnly?: boolean, win?: Window, doc?: Document}} [options]
 * @returns {() => void} release — removes the key handler and, unless
 *   `confineOnly`, restores focus to whatever had it when the trap was armed.
 */
export function installFocusTrap(getPanel, options = {}) {
  const {
    onEscape,
    confineOnly = false,
    win = typeof window === 'undefined' ? null : window,
    doc = typeof document === 'undefined' ? null : document,
  } = options;

  // No DOM at all (a server render, a test with nothing injected): arm nothing
  // and return a release that is safe to call. Never throw — a focus trap must
  // not be able to break the render of the dialog it is protecting.
  if (!win || !doc) return () => {};

  const focusables = () => {
    const panel = getPanel();
    return panel ? Array.from(panel.querySelectorAll(FOCUSABLE_SELECTOR)) : [];
  };

  // Mechanisms 1 and 2. Skipped entirely in `confineOnly` — see the header.
  let previouslyFocused = null;
  if (!confineOnly) {
    previouslyFocused = doc.activeElement;
    (focusables()[0] || getPanel())?.focus();
  }

  function handleKeyDown(e) {
    if (e.key === 'Escape') {
      onEscape?.();
      return;
    }
    // Mechanism 3, the one every caller gets.
    if (e.key === 'Tab' && getPanel()) {
      const nodes = focusables();
      // Nothing focusable inside: swallow Tab rather than letting it walk
      // out into a page we have declared inert.
      if (nodes.length === 0) {
        e.preventDefault();
        return;
      }
      const first = nodes[0];
      const last = nodes[nodes.length - 1];
      if (e.shiftKey && doc.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && doc.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  win.addEventListener('keydown', handleKeyDown);
  return () => {
    win.removeEventListener('keydown', handleKeyDown);
    // Mechanism 4.
    if (!confineOnly) previouslyFocused?.focus?.();
  };
}

/**
 * @param {{active: boolean, onEscape?: () => void, confineOnly?: boolean}} opts
 * @returns {{current: HTMLElement|null}} attach to the dialog PANEL, not the
 *   backdrop — the panel is the dialog, and a trap anchored on the overlay
 *   would count the backdrop's own children as inside it.
 *
 * ⛔ `active` MUST TRACK WHETHER THE DIALOG IS REACHABLE, not merely mounted.
 * `Modal` and `IdleTimeout` return null when shut, so for them the two are the
 * same thing. The evidence drawer stays MOUNTED and is hidden with a transform
 * plus `aria-hidden`/`inert`, so it must pass the SAME flag that gates those
 * attributes: a trap armed over a closed dialog would capture Tab for the whole
 * page, which is a worse defect than the missing confinement it was added to
 * fix.
 */
export default function useFocusTrap({ active, onEscape, confineOnly = false }) {
  const panelRef = useRef(null);

  useEffect(() => {
    if (!active) return undefined;
    return installFocusTrap(() => panelRef.current, { onEscape, confineOnly });
  }, [active, onEscape, confineOnly]);

  return panelRef;
}
