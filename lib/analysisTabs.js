'use strict';

// THE RULE-HYGIENE WORKSPACE'S TAB STRUCTURE — four tasks over fourteen views.
//
// DATA, like lib/navRegistry.js and lib/deviceNav.js. The invariants worth
// pinning are "every one of the fourteen is still reachable", "every existing
// ?tab= value still resolves", and "exactly one group is active"; none of them
// can be asserted against a hand-written row of fourteen <Link>s.
//
// ⛔ ═══ WHAT WAS WRONG ═══════════════════════════════════════════════════
// /devices/[id]/analysis opened with FOURTEEN peer tabs in one row:
//
//   Summary · Security Rules · Findings · Cleanup · Optimization · Reorder ·
//   Consolidation · Risk · Risky Rules · Objects · Tracking · Reachability ·
//   Access Path · Relationships
//
// They are not fourteen tasks. They are fourteen ENGINES — Cleanup,
// Optimization, Reorder and Consolidation are four different finding-type
// filters over one findings table; Risk and Risky Rules are the same score at
// two grains; Reachability and Access Path are the same question at two
// resolutions. The row named the implementation and left the operator to work
// out which of four tabs held the thing they came for.
//
// ⛔ ═══ NOTHING IS DELETED AND NO URL CHANGES ════════════════════════════
// All fourteen views survive, with the same `?tab=` values they have always
// had. The four groups are a NAVIGATION layer on top: the group is DERIVED
// from the leaf, never stored in the URL, so there is no second parameter to
// keep in step and no mapping table to go stale.
//
// ⛔ THAT CHOICE IS WHAT MAKES EVERY OLD LINK WORK. The obvious alternative —
// `?tab=findings&sub=cleanup` — would have required rewriting every bookmark,
// every URL pasted into a ticket, and the sixteen internal links that already
// point at these tabs (the summary tiles link into `?tab=findings
// &finding_type=…`, the work queue links into `?tab=cleanup`). A remap table
// is a thing that can disagree with itself; a derivation cannot.

const ANALYSIS_GROUPS = [
  {
    key: 'overview',
    label: 'Overview',
    // ⛔ THE FIRST LEAF IS THE GROUP'S LANDING VIEW, the same rule the sidebar
    // registry follows: a group header must never be further away than its own
    // label, and `summary` is already this page's default tab.
    leaves: [
      { tab: 'summary', label: 'Summary' },
      { tab: 'risk', label: 'Risk trend' },
      // ⛔ The operator history lives here rather than being promoted to a
      // device-level destination (see lib/deviceNav.js): it is a log of the
      // analyses this page runs, so it belongs beside them.
      { tab: 'tracking', label: 'Activity' },
    ],
  },
  {
    key: 'findings',
    label: 'Findings',
    // ⛔ SIX LEAVES, AND THAT IS STILL THE RIGHT GROUPING. These are six
    // worklists over one findings table, differing only by which finding types
    // they select and what action they offer. As peers of "Objects" and
    // "Access Path" they looked like six unrelated features; as one group they
    // read as what they are — the remediation queue, sliced by the kind of fix.
    leaves: [
      { tab: 'findings', label: 'All findings' },
      { tab: 'risky-rules', label: 'Risky rules' },
      { tab: 'optimization', label: 'Optimization' },
      { tab: 'reorder', label: 'Reorder' },
      { tab: 'cleanup', label: 'Cleanup requests' },
      { tab: 'consolidation', label: 'Consolidation' },
    ],
  },
  {
    key: 'rules',
    label: 'Rules & Objects',
    leaves: [
      { tab: 'rules', label: 'Ruleset' },
      { tab: 'objects', label: 'Objects' },
      // ⛔ Relationships is finding-DERIVED but it is a browse view of rule
      // PAIRS, not a worklist — it offers no action and proposes no change. It
      // sits with the catalogue it describes rather than in the remediation
      // group, where it would be the one entry with nothing to do.
      { tab: 'relationships', label: 'Relationships' },
    ],
  },
  {
    key: 'simulation',
    label: 'Policy Simulation',
    leaves: [
      { tab: 'access-path', label: 'Access path' },
      { tab: 'reachability', label: 'Zone reachability' },
    ],
  },
];

// Every leaf tab value, in registry order. ⛔ THE VALIDATION LIST THE PAGE USES
// IS DERIVED FROM THIS, not maintained beside it — the page previously carried
// its own fourteen-element array, so adding a tab meant editing two places and
// forgetting the second silently fell through to `summary`.
const ANALYSIS_TABS = ANALYSIS_GROUPS.flatMap((g) => g.leaves.map((l) => l.tab));

const DEFAULT_ANALYSIS_TAB = ANALYSIS_GROUPS[0].leaves[0].tab;

/**
 * Validate a ?tab= value.
 *
 * ⛔ AN UNKNOWN VALUE FALLS BACK TO THE DEFAULT, which is what the page already
 * did. That is right here and would be wrong for a filter: a tab is a view
 * selector, so showing the default view is a complete, honest answer, whereas
 * an unrecognised FILTER value must match nothing rather than everything.
 */
function resolveAnalysisTab(tab) {
  return ANALYSIS_TABS.includes(tab) ? tab : DEFAULT_ANALYSIS_TAB;
}

/** Which group holds a given leaf. */
function groupForAnalysisTab(tab) {
  const t = resolveAnalysisTab(tab);
  const g = ANALYSIS_GROUPS.find((grp) => grp.leaves.some((l) => l.tab === t));
  return g ? g.key : ANALYSIS_GROUPS[0].key;
}

/**
 * The two rows a renderer needs: the four groups, and the active group's
 * leaves.
 *
 * ⛔ THE SECONDARY ROW SHOWS ONLY THE ACTIVE GROUP'S LEAVES, never all
 * fourteen under four headings. Rendering them all would be the original row
 * with extra labels on it — the thing it replaced.
 *
 * ⛔ AND IT IS RENDERED EVEN FOR A ONE-LEAF GROUP, which no group has today.
 * Suppressing it below two entries would mean a future single-leaf group's tab
 * row silently changed shape, and the operator would see the secondary row
 * appear and disappear as they moved between groups.
 *
 * @param {string} deviceId
 * @param {string} tab      the raw ?tab= value
 * @param {(tab:string) => string} [href]  builds a leaf href; defaults to the
 *        plain `?tab=` form. Supplied by the page so filter parameters on the
 *        current URL survive a tab change.
 */
function analysisTabRows(deviceId, tab, href) {
  const activeTab = resolveAnalysisTab(tab);
  const activeGroup = groupForAnalysisTab(activeTab);
  const build = typeof href === 'function'
    ? href
    : (t) => `/devices/${deviceId}/analysis?tab=${t}`;

  const groups = ANALYSIS_GROUPS.map((g) => ({
    key: g.key,
    label: g.label,
    // ⛔ A GROUP LINKS TO ITS FIRST LEAF, so clicking it has exactly one
    // outcome. The sidebar made the same call for the same reason: "navigates
    // AND expands" has two outcomes for one gesture and no explainable
    // keyboard behaviour.
    href: build(g.leaves[0].tab),
    active: g.key === activeGroup,
  }));

  const group = ANALYSIS_GROUPS.find((g) => g.key === activeGroup);
  const leaves = group.leaves.map((l) => ({
    tab: l.tab,
    label: l.label,
    href: build(l.tab),
    active: l.tab === activeTab,
  }));

  return { groups, leaves, activeTab, activeGroup };
}

module.exports = {
  ANALYSIS_GROUPS,
  ANALYSIS_TABS,
  DEFAULT_ANALYSIS_TAB,
  resolveAnalysisTab,
  groupForAnalysisTab,
  analysisTabRows,
};
