'use client';

// The control that reaches the navigation below 1024px, where the rail is
// off-canvas and there is nothing else to click.
//
// ⛔ ITS VISIBILITY IS CSS, NOT STATE. `html[data-nav]` is stamped before first
// paint (lib/navLayout.js), so the button is correctly present or absent on the
// very first frame. Gating it on React state instead would render it on every
// screen for one paint and then remove it — a control that flickers in and out
// of the header on every load — and, worse, would leave it in the tab order at
// wide widths where it does nothing.
//
// ⛔ IT IS NOT A DUPLICATE OF THE COLLAPSE BUTTON IN THE RAIL. That one is a
// preference (I want more room) and only applies at full width. This one is the
// only way in. They are never both visible.

import { useEffect, useRef } from 'react';
import { useNavState } from './NavState';
import { IconMenu } from '../icons';

export default function NavDrawerToggle() {
  const { drawerOpen, openDrawer, closeDrawer, registerTrigger } = useNavState();
  const ref = useRef(null);

  // Hand the element to the provider so focus can be returned here when the
  // drawer closes.
  useEffect(() => {
    registerTrigger(ref.current);
    return () => registerTrigger(null);
  }, [registerTrigger]);

  return (
    <button
      ref={ref}
      type="button"
      className="sv-icon-btn sv-nav-trigger"
      // aria-controls names the rail's own id, so the relationship survives the
      // two living in different subtrees.
      aria-controls="sv-primary-nav"
      aria-expanded={drawerOpen}
      aria-label={drawerOpen ? 'Close navigation' : 'Open navigation'}
      title={drawerOpen ? 'Close navigation' : 'Open navigation'}
      onClick={() => (drawerOpen ? closeDrawer() : openDrawer())}
    >
      <IconMenu width={20} height={20} />
    </button>
  );
}
