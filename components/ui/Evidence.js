'use client';

// components/ui/Evidence.js
//
// The interaction that carries SecVault's whole thesis: EVERY FIGURE CAN BE
// ASKED HOW IT KNOWS.
//
// ⛔ WHY THIS IS ONE GLOBAL DRAWER AND NOT A TOOLTIP PER TILE. A tooltip is
// sized for a sentence, cannot be read with a screen reader at leisure, cannot
// be scrolled, and closes the moment the pointer moves — none of which suits a
// formula, a table of inputs and a list of things that could not be measured.
// It also could not be reached from a table cell, which is where most of the
// product's numbers actually live. One drawer, one context, one affordance
// learned once and valid everywhere.
//
// ⛔ VIOLET, AND NOTHING ELSE IS VIOLET. Severity owns red through green;
// app/globals.css's design-system note reserves red for danger specifically so
// the product's most urgent signal is unambiguous. Evidence is not a severity —
// it is a different axis entirely (how well do we know this, rather than how
// bad is it), so it gets its own hue and keeps it. See --evidence in
// app/globals.css.
//
// ⛔ THE MARK NEVER RENDERS WITHOUT RENDERABLE EVIDENCE. isRenderableEvidence()
// is checked here rather than trusted from the call site, because a mark that
// opens onto an empty drawer is worse than no mark at all: it promises an
// explanation, delivers nothing, and teaches the operator that the affordance
// is decorative. After that, they stop clicking the ones that do work.

import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import useFocusTrap from './useFocusTrap';
import { isRenderableEvidence } from '../../lib/evidence';

const EvidenceContext = createContext(null);

/**
 * Mounted ONCE, in app/(dashboard)/layout.js, around the whole content area.
 * Server components below it can render <EvidenceMark evidence={...}/> because
 * an evidence descriptor is a plain serializable object — no functions, no
 * dates, nothing that cannot cross the server/client boundary as a prop.
 */
export function EvidenceProvider({ children }) {
  const [payload, setPayload] = useState(null);
  const openerRef = useRef(null);

  const open = useCallback((ev, opener) => {
    if (!isRenderableEvidence(ev)) return;
    openerRef.current = opener || null;
    setPayload(ev);
  }, []);

  const close = useCallback(() => {
    setPayload(null);
    // ⛔ Return focus to whatever opened the drawer. Without this, closing with
    // Escape drops keyboard focus to <body> and a keyboard user restarts their
    // traversal of the page from the top.
    // ⛔ THIS IS THE ONLY FOCUS RESTORE, AND IT STAYS HERE. The provider is what
    // knows WHICH mark opened the drawer — the panel cannot, because the same
    // panel serves every mark on every page. The trap in EvidenceDrawer is armed
    // with `confineOnly` for exactly that reason; see the comment there before
    // moving any of this into the panel.
    const el = openerRef.current;
    openerRef.current = null;
    if (el && typeof el.focus === 'function') el.focus();
  }, []);

  useEffect(() => {
    if (!payload) return undefined;
    const onKey = (e) => { if (e.key === 'Escape') close(); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [payload, close]);

  return (
    <EvidenceContext.Provider value={{ open, close }}>
      {children}
      <EvidenceDrawer payload={payload} onClose={close} />
    </EvidenceContext.Provider>
  );
}

export function useEvidence() {
  return useContext(EvidenceContext);
}

/**
 * The affordance. Sits beside a label, a heading or inside a table cell.
 *
 * @param {Object} evidence  A descriptor from lib/evidence.js.
 * @param {string} [subject] What the mark is attached to, for screen readers.
 */
export function EvidenceMark({ evidence, subject }) {
  const ctx = useContext(EvidenceContext);
  const ref = useRef(null);

  // Renders nothing at all if there is no real evidence to show, or if the
  // provider is absent (a page that has not been wired yet must not crash).
  if (!ctx || !isRenderableEvidence(evidence)) return null;

  const label = subject ? `How was "${subject}" measured?` : 'How was this measured?';

  return (
    <button
      ref={ref}
      type="button"
      className="ev-mark"
      title={label}
      aria-label={label}
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        ctx.open(evidence, ref.current);
      }}
    >
      {/* A question mark, not an info "i": the affordance answers a question
          the operator is already asking, rather than offering trivia. */}
      <span aria-hidden="true">?</span>
    </button>
  );
}

function Section({ title, children }) {
  return (
    <div className="ev-sec">
      <b>{title}</b>
      {children}
    </div>
  );
}

function EvidenceDrawer({ payload, onClose }) {
  const closeRef = useRef(null);
  const open = !!payload;

  // ⛔ CONFINE-ONLY, AND THE OTHER THREE MECHANISMS STAY WHERE THEY ARE.
  // `aria-modal` below promises assistive technology that the page behind this
  // panel is inert. Three of the four things that make that promise true were
  // already here — Escape closes (the provider's keydown effect), focus moves to
  // the close button on open (the effect below), focus returns to the mark that
  // opened it on close (`close()`'s `openerRef`) — and only Tab CONFINEMENT was
  // missing, so Tab walked straight out of a dialog that had declared the rest
  // of the page unreachable.
  //
  // ⛔ THE FULL HOOK WAS THE WRONG FIX. Its restore reads
  // `document.activeElement` at arm time; the provider's reads `openerRef`. Both
  // would have fired on close and which one won would depend on effect-cleanup
  // order — judgeable only with the drawer open in a browser, and silently wrong
  // the day React changes that order. `confineOnly` adds the missing mechanism
  // and touches neither focus nor Escape, so there is nothing to race.
  //
  // ⛔ `active: open` IS THE SAME `open` THAT DRIVES `aria-hidden` AND `inert`
  // BELOW, AND THAT MATTERS MORE THAN THE CONFINEMENT ITSELF. This drawer is
  // never unmounted — it is pushed off-screen with a transform — so a trap armed
  // on the closed panel would swallow Tab for every page in the product, which is
  // a far worse defect than the one being fixed. One flag, four readers (the
  // trap, `data-open`, `aria-hidden`, `inert`): there is no second expression
  // that can disagree with it.
  const panelRef = useFocusTrap({ active: open, confineOnly: true });

  useEffect(() => {
    if (payload && closeRef.current) closeRef.current.focus();
  }, [payload]);

  return (
    <>
      <div
        className="ev-scrim"
        data-open={open ? '1' : undefined}
        onClick={onClose}
        aria-hidden="true"
      />
      <aside
        ref={panelRef}
        className="ev-drawer"
        data-open={open ? '1' : undefined}
        role="dialog"
        aria-modal="true"
        aria-label={payload ? payload.title : 'Evidence'}
        // ⛔ Hidden from the accessibility tree AND from tab order when closed.
        // A transform-offscreen panel is still focusable, so without this a
        // keyboard user tabs into an invisible dialog at the end of every page.
        aria-hidden={open ? undefined : 'true'}
        inert={open ? undefined : ''}
      >
        {payload && (
          <>
            <div className="ev-head">
              <div className="ev-kick">
                <span>Evidence</span>
                <button
                  ref={closeRef}
                  type="button"
                  className="ev-close"
                  onClick={onClose}
                  aria-label="Close evidence"
                >
                  ESC ✕
                </button>
              </div>
              <div className="ev-title">{payload.title}</div>
              {payload.claim && <p className="ev-claim">{payload.claim}</p>}
            </div>

            {/* ⛔ FOCUSABLE BECAUSE IT SCROLLS, AND THE TAB TRAP IS WHAT MADE
                THAT NON-OPTIONAL. `.ev-body` is the drawer's scroll container
                (app/globals.css: `flex: 1; min-height: 0; overflow-y: auto`)
                and the close button sits OUTSIDE it, in `.ev-head`. So with
                focus where the provider puts it, the browser has no scrollable
                ancestor to act on. Measured in Chromium against the real
                stylesheet, 2,268px of content in a 398px viewport: PageDown and
                ArrowDown both left `scrollTop` at 0. 1,870px of evidence —
                including "What could not be measured", which is the entire point
                of this drawer — was unreachable by keyboard.
                ⛔ That was true before the Tab trap and the trap is what makes it
                intolerable: previously a keyboard user could at least Tab out of
                the dialog, so the fix for "focus escapes a dialog claiming to be
                modal" would otherwise have shipped as "pinned in front of
                content you cannot read". A `tabindex` here is also what puts the
                body INTO the confinement cycle, so Tab moves Close <-> detail.
                Re-measured with it: scrollTop 0 -> 348 on one PageDown. */}
            <div
              className="ev-body"
              tabIndex={0}
              role="region"
              aria-label="Evidence detail"
            >
              <Section title="How it was computed">
                <pre className="ev-formula">{payload.formula}</pre>
              </Section>

              <Section title="Inputs">
                {payload.inputs.map((row, i) => (
                  <div className="ev-kv" key={i}>
                    <span>
                      {row.label}
                      {row.note && <em className="ev-note"> — {row.note}</em>}
                    </span>
                    <span>{row.value}</span>
                  </div>
                ))}
              </Section>

              <Section title="What could not be measured">
                {/* ⛔ An empty list is a CLAIM, not a blank. "Everything this
                    number depends on was measured" is the strongest sentence
                    this product can print, and it has to be earned — so it is
                    rendered explicitly rather than by showing nothing. */}
                {payload.unmeasured.length === 0 ? (
                  <p className="ev-complete">
                    Everything this number depends on was measured. No gaps, no assumptions.
                  </p>
                ) : (
                  payload.unmeasured.map((u, i) => (
                    <div className="ev-gap" key={i}>
                      <b>{u.label}</b>
                      <p>{u.reason}</p>
                    </div>
                  ))
                )}
              </Section>

              <div className="ev-foot">
                <span>Computed by</span>
                <code>{payload.source}</code>
                {payload.rule && (
                  <>
                    <span>Governed by</span>
                    <code>{payload.rule}</code>
                  </>
                )}
              </div>
            </div>
          </>
        )}
      </aside>
    </>
  );
}

export default EvidenceMark;
