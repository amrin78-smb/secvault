'use client';

// The shell's navigation state, shared by the rail and the header trigger.
//
// ⛔ WHY A CONTEXT RATHER THAN STATE INSIDE THE SIDEBAR. Below 1024px the rail
// is off-canvas, so the control that opens it CANNOT live inside it — it has to
// be in the header, which is a different subtree and a server component. Two
// components, one fact. The alternative (a second copy of `drawerOpen` kept in
// sync by an event) is the shape of bug this codebase names most often: two
// readers of one truth, drifting, with the symptom being a trigger that says
// "closed" over an open drawer.
//
// ⛔ IT WRAPS THE SHELL BUT DOES NOT CLIENTIFY IT. `children` here is the
// already-rendered server tree (header, rail, page content). A client component
// receiving server children renders them as-is; nothing below becomes a client
// component. The only thing this adds to the client bundle is the <div> and the
// handful of state below.

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from 'react';
import { usePathname } from 'next/navigation';
import { NAV_MODE_EVENT, navModeFromDocument } from '../../lib/navLayout';

const NavContext = createContext(null);

/**
 * @returns {{mode: 'wide'|'rail'|'drawer', drawerOpen: boolean,
 *   openDrawer: Function, closeDrawer: Function,
 *   registerTrigger: Function, focusTrigger: Function}}
 */
export function useNavState() {
  const ctx = useContext(NavContext);
  // ⛔ A missing provider THROWS rather than returning a plausible default.
  // A silent `{drawerOpen:false}` would render a trigger that does nothing,
  // which on the one control that reaches the navigation at narrow widths is
  // indistinguishable from the product being broken.
  if (!ctx) throw new Error('useNavState() used outside <NavProvider>');
  return ctx;
}

export function NavProvider({ children }) {
  // ⛔ 'wide' on the first render, ALWAYS, and corrected in an effect. The
  // server has no viewport; initialising from `navModeFromDocument()` here
  // would read the attribute the inline script already set and hydrate against
  // a value the server never produced. Layout does not depend on this state
  // (the stylesheet keys on the attribute directly), so the one frame before
  // the effect runs is invisible.
  const [mode, setMode] = useState('wide');
  const [drawerOpen, setDrawerOpen] = useState(false);
  const triggerRef = useRef(null);
  const pathname = usePathname();

  useEffect(() => {
    const sync = () => setMode(navModeFromDocument());
    sync();
    window.addEventListener(NAV_MODE_EVENT, sync);
    return () => window.removeEventListener(NAV_MODE_EVENT, sync);
  }, []);

  const closeDrawer = useCallback(() => setDrawerOpen(false), []);
  const openDrawer = useCallback(() => setDrawerOpen(true), []);

  // ⛔ A NAVIGATION CLOSES THE DRAWER. Without this, following a link leaves
  // the panel sitting over the page it just opened, and the operator's next
  // action is to dismiss the navigation they just used — on a touch layout,
  // over content they cannot see.
  useEffect(() => {
    setDrawerOpen(false);
  }, [pathname]);

  // ⛔ WIDENING THE WINDOW CLOSES IT TOO. The drawer is only a drawer below
  // 1024px; left open while the rail becomes a normal column, `drawerOpen`
  // would still be true and the backdrop would still be over the page.
  useEffect(() => {
    if (mode !== 'drawer') setDrawerOpen(false);
  }, [mode]);

  // Escape closes transient surfaces — the same contract the evidence drawer
  // and every modal in this product already honour.
  useEffect(() => {
    if (!drawerOpen) return undefined;
    const onKey = (e) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        setDrawerOpen(false);
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [drawerOpen]);

  const registerTrigger = useCallback((el) => {
    triggerRef.current = el;
  }, []);

  // Focus goes back where it came from. The rail calls this when the drawer
  // closes; without it, dismissing the panel drops focus to the top of the
  // document and a keyboard user starts the page again.
  const focusTrigger = useCallback(() => {
    const el = triggerRef.current;
    if (el && typeof el.focus === 'function') el.focus();
  }, []);

  return (
    <NavContext.Provider
      value={{ mode, drawerOpen, openDrawer, closeDrawer, registerTrigger, focusTrigger }}
    >
      {/* The shell's own element, so the open state can be read by the
          stylesheet without a second attribute somewhere else. */}
      <div className="sv-shell" data-drawer-open={drawerOpen ? 'true' : 'false'}>
        {children}
      </div>
    </NavContext.Provider>
  );
}
