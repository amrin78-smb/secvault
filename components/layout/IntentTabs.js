// components/layout/IntentTabs.js
//
// The tab strip shared by /segmentation and /applications.
//
// ⛔ THESE ARE TWO ROUTES, NOT ONE ROUTE WITH A `?tab=`, AND THAT IS THE WHOLE
// POINT OF THE DESIGN. CLAUDE.md's navigation rule is that hrefs never change:
// both URLs already appear in sent notifications, pasted tickets and bookmarks.
// So nothing is merged at the routing layer — each page keeps its own URL, its
// own smoke marker and its own device-scope classification — and the "merge" is
// purely what the SIDEBAR renders. This strip is what makes the pair legible
// once they share one nav entry.
//
// ⛔ WHY THESE TWO AND NOT SOME OTHER PAIR. `app/(dashboard)/.../Sidebar.js`
// already argued it: Applications is "the SAME MECHANIC as Segmentation, one
// grain finer — declared intent re-checked against the collected rulebase,
// honest about what it could not verify". Zone-to-zone policy, then
// application-to-flow. They are one question at two grains, which is the only
// justification for tabbing two pages together; anything less and a tab just
// hides a destination behind a click.
//
// ⛔ The labels keep the OLD WORDS. The nav entry above them says "Intent", but
// an operator who has used this for a year calls these Segmentation and
// Applications, and `HeaderSearch`'s PAGE_KEYWORDS carries both for the same
// reason. Renaming the tabs too would leave the product's own vocabulary
// findable nowhere.

import Link from 'next/link';

export const INTENT_TABS = [
  { href: '/segmentation', label: 'Segmentation' },
  { href: '/applications', label: 'Applications' },
];

/**
 * ⛔ A PLAIN MODULE-LEVEL COMPONENT. CLAUDE.md: never define a React component
 * inside another React component — it remounts the subtree on every keystroke.
 * Living in its own file keeps that true even if a caller later inlines it.
 *
 * @param {string} active the href of the page rendering this strip
 */
export default function IntentTabs({ active }) {
  return (
    <div
      style={{
        display: 'flex',
        gap: 'var(--s2)',
        borderBottom: '1px solid var(--border)',
        marginBottom: 'var(--s4)',
      }}
    >
      {INTENT_TABS.map(({ href, label }) => {
        const isActive = href === active;
        return (
          <Link
            key={href}
            href={href}
            // Same visual contract as the /vulnerability strip, deliberately:
            // two tab strips that look different read as two mechanisms.
            style={{
              padding: '8px 12px',
              fontSize: 'var(--text-base)',
              color: isActive ? 'var(--primary)' : 'var(--text-secondary)',
              borderBottom: isActive ? '2px solid var(--primary)' : '2px solid transparent',
              textDecoration: 'none',
            }}
            aria-current={isActive ? 'page' : undefined}
          >
            {label}
          </Link>
        );
      })}
    </div>
  );
}
