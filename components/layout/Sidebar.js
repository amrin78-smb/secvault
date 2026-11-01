'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { PRODUCT_NAME } from '../../lib/branding';
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  NAV_SECTIONS,
  SETTINGS_ITEM,
  NAV,
  visibleNavItems,
  isActive,
  sectionIsActive,
} from '../../lib/navRegistry';
import { useNavState } from './NavState';
import * as Icons from '../icons';
import { IconChevronLeft, IconChevronDown } from '../icons';

// ⛔ THE ACTIVE NAV CHIP IS ALWAYS THE BRAND ACCENT (2026-09-09, Phase 1).
//
// Each entry used to carry its own `color`/`bg` hex pair — cyan, amber, blue,
// red, gold, green, indigo, violet, lime, sky, rose, grey. Only the ACTIVE
// entry ever rendered coloured (`.sv-nav a.active .sv-nav-chip` in
// globals.css; every inactive chip is white-alpha), so this was never a
// twelve-hue rainbow on screen at once. The real defect was subtler and
// worse: the "you are here" signal was A DIFFERENT HUE ON EVERY PAGE, so it
// could not be learned — and on /vulnerability it was #f87171, a red, sitting
// three inches from severity badges that use red to mean "critically
// exposed". An interface element must never borrow the severity palette.
//
// ⛔ THE REGISTRY ITSELF NOW LIVES IN lib/navRegistry.js, as data. This file is
// the RENDERER: it maps icon names to components, owns the three rail shapes
// and the drawer's focus behaviour, and nothing else. The structure moved out
// so the tests could assert it by behaviour instead of by regex over this
// file's source — see that file's header for what the regexes could not see.

// ⛔ Re-exported so `components/layout/HeaderSearch.js` keeps its import. The
// palette's page results filter over this list, and a destination missing from
// it is a page the search quietly stops finding.
export { NAV };

/**
 * Icon name → component.
 *
 * ⛔ A NAME WITH NO COMPONENT RENDERS NOTHING RATHER THAN THROWING, and
 * `tests/navigation.test.js` fails the build on one. Crashing the whole shell
 * because a glyph was misspelled would take the navigation down with it; a
 * chip with no glyph is a legible row with a gap in it, and the test is what
 * stops that reaching a release.
 */
function glyph(name) {
  const Cmp = Icons[name];
  return typeof Cmp === 'function' ? Cmp : null;
}

function NavChip({ icon }) {
  const Icon = glyph(icon);
  return (
    <span className="sv-nav-chip">
      {Icon ? <Icon width={16} height={16} /> : null}
    </span>
  );
}

const COLLAPSE_KEY = 'secvault-sidebar-collapsed';
const GROUPS_KEY = 'secvault-nav-groups';

function readStoredGroups() {
  try {
    const raw = localStorage.getItem(GROUPS_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    // ⛔ Only genuine booleans are honoured. A corrupted or hand-edited value
    // falls back to the auto behaviour rather than being coerced — a truthy
    // string would pin a section open for ever with nothing to explain why,
    // and this file cannot render a value it does not understand.
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    const out = {};
    for (const [k, v] of Object.entries(parsed)) if (typeof v === 'boolean') out[k] = v;
    return out;
  } catch (_err) {
    return {};
  }
}

/**
 * One destination row.
 *
 * ⛔ Module top level, never nested inside Sidebar. CLAUDE.md's first Critical
 * Rule: a component defined inside a component remounts on every render.
 */
function NavLink({ item, active, showLabels }) {
  return (
    <Link
      href={item.href}
      className={active ? 'active' : ''}
      // aria-current is what tells a screen reader which destination is
      // showing; the glow, the chip and the left bar only say it visually.
      aria-current={active ? 'page' : undefined}
      // A title is the label's stand-in only while the label is hidden. Set
      // unconditionally it would produce a tooltip duplicating text already on
      // screen, which screen readers read twice.
      title={showLabels ? undefined : item.label}
    >
      <NavChip icon={item.icon} />
      <span className="sv-nav-text">{item.label}</span>
    </Link>
  );
}

export default function Sidebar({ version, capabilities }) {
  const pathname = usePathname();
  const { mode, drawerOpen, closeDrawer, focusTrigger } = useNavState();
  const [collapsed, setCollapsed] = useState(false);
  // ⛔ USER INTENT ONLY — an absent key means "no opinion", which resolves to
  // the active-section behaviour below. Seeding this with every section set to
  // false would make a stored preference indistinguishable from the default,
  // and the auto-expand would never be able to fire.
  const [openGroups, setOpenGroups] = useState({});
  const asideRef = useRef(null);
  const wasOpen = useRef(false);

  useEffect(() => {
    try {
      setCollapsed(localStorage.getItem(COLLAPSE_KEY) === 'true');
    } catch (_err) {
      // ignore — collapse just won't persist
    }
    setOpenGroups(readStoredGroups());
  }, []);

  // ⛔ FOCUS MOVES INTO THE DRAWER WHEN IT OPENS AND BACK WHEN IT CLOSES.
  // Without the first half, a keyboard user who activates the trigger is still
  // standing in the header and has to tab through it to reach a navigation
  // that is now covering the page. Without the second, dismissing the drawer
  // drops focus to the top of the document and the page starts again.
  useEffect(() => {
    if (drawerOpen && !wasOpen.current) {
      const first = asideRef.current && asideRef.current.querySelector('a, button');
      if (first) first.focus();
    } else if (!drawerOpen && wasOpen.current) {
      focusTrigger();
    }
    wasOpen.current = drawerOpen;
  }, [drawerOpen, focusTrigger]);

  function toggle() {
    setCollapsed((c) => {
      const next = !c;
      try {
        localStorage.setItem(COLLAPSE_KEY, String(next));
      } catch (_err) {
        // ignore
      }
      return next;
    });
  }

  const toggleGroup = useCallback((label, nextOpen) => {
    setOpenGroups((prev) => {
      const next = { ...prev, [label]: nextOpen };
      try {
        localStorage.setItem(GROUPS_KEY, JSON.stringify(next));
      } catch (_err) {
        // ignore — the choice just won't persist across reloads
      }
      return next;
    });
  }, []);

  // ⛔ THE COLLAPSE PREFERENCE ONLY APPLIES AT FULL WIDTH. Between 1024 and
  // 1279 the stylesheet forces the rail to icons regardless, and below 1024 it
  // is off-canvas; honouring a stored `collapsed` there would change nothing
  // visible while making the button inside the drawer lie about what it does.
  const railIsIcons = mode === 'rail' || (mode === 'wide' && collapsed);
  // Labels are present in the drawer exactly as at full width — a panel that
  // takes over the screen has room for them.
  const showLabels = !railIsIcons || mode === 'drawer';

  const settingsActive = isActive(pathname, SETTINGS_ITEM.href, false);

  return (
    <>
      {/* ⛔ A BACKDROP, NOT JUST A VISUAL WASH. It is what makes "click
          anywhere else to dismiss" true, and it is a real <button> so the same
          gesture exists for a keyboard and a screen reader rather than only
          for a mouse. Rendered only while open, so it is never in the tab
          order otherwise. */}
      {drawerOpen && (
        <button
          type="button"
          className="sv-nav-backdrop"
          aria-label="Close navigation"
          onClick={closeDrawer}
        />
      )}
      <aside
        ref={asideRef}
        // The id the header's trigger names in aria-controls. The two live in
        // different subtrees, so the relationship exists only through this.
        id="sv-primary-nav"
        className={`sv-sidebar${collapsed ? ' collapsed' : ''}`}
      >
        <nav className="sv-nav" aria-label="Primary">
          {NAV_SECTIONS.map((section) => {
            const active = sectionIsActive(pathname, section);

            // ── A leaf: one row that navigates.
            if (!section.items) {
              return (
                <div key={section.href} className="sv-nav-group">
                  <NavLink item={section} active={active} showLabels={showLabels} />
                </div>
              );
            }

            const items = visibleNavItems(section, capabilities);
            // A section whose every entry is hidden must not leave its header
            // behind — an expandable nothing.
            if (items.length === 0) return null;

            // ⛔ THE ACTIVE SECTION OPENS ITSELF, AND A STORED CHOICE STILL
            // WINS. `undefined` means the operator has no opinion about this
            // section, so it follows the page they are on; `false` means they
            // closed it, and that is honoured even here — which is only safe
            // BECAUSE a shut section carries its own active bar (see
            // `.sv-nav-group[data-expanded="false"] .sv-nav-section[data-active]`
            // in globals.css). Without that marker, honouring the collapse
            // would hide the current page from the navigation with no "you are
            // here" left anywhere on screen.
            const stored = openGroups[section.group];
            const expanded = typeof stored === 'boolean' ? stored : active;
            const bodyId = `sv-nav-${section.group.replace(/\s+/g, '-').toLowerCase()}`;

            return (
              <div key={section.group} className="sv-nav-group" data-expanded={expanded}>
                <button
                  type="button"
                  className="sv-nav-section"
                  data-active={active ? 'true' : undefined}
                  aria-expanded={expanded}
                  aria-controls={bodyId}
                  onClick={() => toggleGroup(section.group, !expanded)}
                >
                  <NavChip icon={section.icon} />
                  <span className="sv-nav-text">{section.group}</span>
                  <IconChevronDown className="sv-nav-caret" width={12} height={12} />
                </button>
                {/* ⛔ aria-label ON THE LIST, because at rail width the header
                    above is display:none and the grouping would otherwise be
                    announced as one undifferentiated run of links. */}
                <div className="sv-nav-items" id={bodyId} aria-label={section.group}>
                  {items.map((item) => (
                    <NavLink
                      key={item.href}
                      item={item}
                      active={isActive(pathname, item.href, item.exact, item.alsoActiveFor)}
                      showLabels={showLabels}
                    />
                  ))}
                </div>
              </div>
            );
          })}

          <div className="sv-nav-group sv-nav-group-pinned">
            <NavLink item={SETTINGS_ITEM} active={settingsActive} showLabels={showLabels} />
          </div>
        </nav>

        {/* ⛔ CHROME, BEHIND A HAIRLINE, NOT TWO MORE NAV ROWS. The collapse
            control and the version line used to sit flush under the last
            destination in the same type and the same rhythm, so the rail ended
            in three rows of which only one was a place you could go. The rule
            separates "where can I go" from "what is this, and how do I make it
            smaller". */}
        <div className="sv-sidebar-footer">
          <button
            type="button"
            className="sv-collapse-btn"
            onClick={toggle}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            <IconChevronLeft width={18} height={18} />
            <span className="sv-nav-text">Collapse</span>
          </button>
          <div className="sv-version">{PRODUCT_NAME}{version ? ` v${version}` : ''}</div>
        </div>
      </aside>
    </>
  );
}
