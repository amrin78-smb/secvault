'use strict';

// lib/analysisTabs.js — four tasks over the rule-hygiene workspace's fourteen
// views.
//
// ⛔ THE RISK THIS SUITE EXISTS FOR IS NOT "DID THE GROUPING LOOK NICE". It is
// that a consolidation silently drops a view, or breaks a `?tab=` value that
// is sitting in somebody's ticket. Both are invisible: a lost tab renders
// nothing and a broken param falls through to the default view, so the page
// looks fine and the operator just never finds the thing they came for.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { stripComments } = require('./stripComments');

const {
  ANALYSIS_GROUPS, ANALYSIS_TABS, DEFAULT_ANALYSIS_TAB,
  resolveAnalysisTab, groupForAnalysisTab, analysisTabRows,
} = require('../lib/analysisTabs');

const PAGE = fs.readFileSync(
  path.join(__dirname, '..', 'app', '(dashboard)', 'devices', '[id]', 'analysis', 'page.js'),
  'utf8'
);
const ID = 'dev-1';

// The fourteen tabs the page carried before the consolidation, verbatim from
// its own validation array. ⛔ THIS LIST IS THE CONTRACT. Every one of these
// strings may be sitting in a bookmark, a ticket, or an internal href.
const HISTORICAL_TABS = [
  'summary', 'rules', 'findings', 'cleanup', 'optimization', 'reorder',
  'consolidation', 'risk', 'risky-rules', 'objects', 'tracking',
  'reachability', 'access-path', 'relationships',
];

describe('nothing was deleted', () => {
  it('⛔ ALL FOURTEEN HISTORICAL TABS ARE STILL REGISTERED LEAVES', () => {
    for (const t of HISTORICAL_TABS) {
      assert.ok(ANALYSIS_TABS.includes(t), `lost view: ${t}`);
    }
  });

  it('⛔ and NO tab was invented — the set is exactly the fourteen', () => {
    assert.deepEqual([...ANALYSIS_TABS].sort(), [...HISTORICAL_TABS].sort());
  });

  it('⛔ EVERY LEAF IS STILL RENDERED BY THE PAGE', () => {
    for (const t of ANALYSIS_TABS) {
      assert.ok(
        PAGE.includes(`tab === '${t}'`),
        `${t} is in the registry but the page renders nothing for it — a nav entry `
        + 'that opens a blank page is worse than one that is missing'
      );
    }
  });

  it('⛔ and the page renders nothing for a tab that is NOT registered', () => {
    const rendered = [...PAGE.matchAll(/tab === '([a-z-]+)'/g)].map((m) => m[1]);
    for (const t of new Set(rendered)) {
      assert.ok(ANALYSIS_TABS.includes(t), `${t} is rendered but unreachable from any nav entry`);
    }
  });
});

describe('every ?tab= value still resolves', () => {
  it('⛔ NO SECOND PARAMETER WAS INTRODUCED — the group is DERIVED, not stored', () => {
    // `?tab=findings&sub=cleanup` would have required rewriting every
    // bookmark and every internal href. A derivation cannot disagree with
    // itself; a remap table can.
    const src = stripComments(
      fs.readFileSync(path.join(__dirname, '..', 'lib', 'analysisTabs.js'), 'utf8')
    );
    for (const param of ['sub', 'group', 'section', 'view']) {
      assert.equal(
        new RegExp(`searchParams[^\\n]*${param}|\\?${param}=`).test(src), false,
        `a '${param}' parameter would break every existing link`
      );
    }
    assert.equal(/searchParams/.test(src), false, 'the registry reads no URL at all');
  });

  it('every historical tab maps to exactly one group', () => {
    for (const t of HISTORICAL_TABS) {
      const owning = ANALYSIS_GROUPS.filter((g) => g.leaves.some((l) => l.tab === t));
      assert.equal(owning.length, 1, `${t}: ${owning.length} groups`);
      assert.equal(groupForAnalysisTab(t), owning[0].key);
    }
  });

  it('⛔ an unknown tab falls back to the default VIEW (correct for a tab, wrong for a filter)', () => {
    assert.equal(resolveAnalysisTab('nonsense'), DEFAULT_ANALYSIS_TAB);
    assert.equal(resolveAnalysisTab(undefined), DEFAULT_ANALYSIS_TAB);
    assert.equal(resolveAnalysisTab(''), DEFAULT_ANALYSIS_TAB);
    assert.equal(DEFAULT_ANALYSIS_TAB, 'summary', 'unchanged from the page\u2019s previous default');
  });

  it('⛔ the page validates through the registry, not its own copy of the list', () => {
    assert.match(PAGE, /resolveAnalysisTab\(searchParams\?\.tab\)/);
    // The fourteen-element literal must be gone, or there are two lists again.
    assert.equal(
      /\[\s*'summary',\s*\n\s*'rules',/.test(PAGE), false,
      'a second copy of the tab list is how a new view silently falls through to summary'
    );
  });
});

describe('the four groups', () => {
  it('⛔ FOUR, matching the brief: Overview / Findings / Rules & Objects / Policy Simulation', () => {
    assert.deepEqual(
      ANALYSIS_GROUPS.map((g) => g.label),
      ['Overview', 'Findings', 'Rules & Objects', 'Policy Simulation']
    );
  });

  it('every group key and label is unique, and every group has leaves', () => {
    const keys = ANALYSIS_GROUPS.map((g) => g.key);
    assert.equal(new Set(keys).size, keys.length);
    for (const g of ANALYSIS_GROUPS) {
      assert.ok(g.leaves.length >= 1, `${g.key} has no leaves`);
    }
  });

  it('⛔ leaf labels are unique ACROSS groups', () => {
    const labels = ANALYSIS_GROUPS.flatMap((g) => g.leaves.map((l) => l.label));
    assert.equal(new Set(labels).size, labels.length,
      'two views with one label is unexplainable in a secondary row');
  });

  it('⛔ NO GROUP IS BIG ENOUGH TO BE THE OLD ROW AGAIN', () => {
    // The defect was fourteen peers. A group holding most of them would be
    // the same row with a heading on it.
    for (const g of ANALYSIS_GROUPS) {
      assert.ok(g.leaves.length <= 6, `${g.key} has ${g.leaves.length} leaves`);
    }
  });

  it('⛔ a group links to its FIRST leaf, so one click has one outcome', () => {
    const { groups } = analysisTabRows(ID, 'summary');
    for (const g of groups) {
      const def = ANALYSIS_GROUPS.find((x) => x.key === g.key);
      assert.ok(g.href.endsWith(`?tab=${def.leaves[0].tab}`), `${g.key} -> ${g.href}`);
    }
  });

  it('the first group\u2019s first leaf IS the page default', () => {
    assert.equal(ANALYSIS_GROUPS[0].leaves[0].tab, DEFAULT_ANALYSIS_TAB);
  });
});

describe('the rendered rows', () => {
  it('⛔ EXACTLY ONE GROUP AND EXACTLY ONE LEAF ARE ACTIVE, on every one of the fourteen', () => {
    for (const t of ANALYSIS_TABS) {
      const { groups, leaves, activeTab } = analysisTabRows(ID, t);
      assert.equal(activeTab, t);
      assert.equal(groups.filter((g) => g.active).length, 1, `${t}: group`);
      assert.equal(leaves.filter((l) => l.active).length, 1, `${t}: leaf`);
      assert.equal(leaves.find((l) => l.active).tab, t);
    }
  });

  it('⛔ THE SECONDARY ROW SHOWS ONLY THE ACTIVE GROUP, never all fourteen', () => {
    const { leaves, activeGroup } = analysisTabRows(ID, 'cleanup');
    const def = ANALYSIS_GROUPS.find((g) => g.key === activeGroup);
    assert.deepEqual(leaves.map((l) => l.tab), def.leaves.map((l) => l.tab));
    assert.ok(leaves.length < ANALYSIS_TABS.length,
      'rendering all fourteen under four headings is the original row with extra labels');
  });

  it('an unknown tab still produces a complete, consistent pair of rows', () => {
    const { groups, leaves, activeTab } = analysisTabRows(ID, 'bogus');
    assert.equal(activeTab, DEFAULT_ANALYSIS_TAB);
    assert.equal(groups.filter((g) => g.active).length, 1);
    assert.equal(leaves.filter((l) => l.active).length, 1);
  });

  it('hrefs default to the plain ?tab= form, and a custom builder is honoured', () => {
    const { leaves } = analysisTabRows(ID, 'summary');
    assert.equal(leaves[0].href, `/devices/${ID}/analysis?tab=summary`);
    const custom = analysisTabRows(ID, 'summary', (t) => `/x?tab=${t}&keep=1`);
    assert.equal(custom.leaves[0].href, '/x?tab=summary&keep=1');
  });
});

describe('the renderer', () => {
  const SRC = fs.readFileSync(path.join(__dirname, '..', 'components', 'ui', 'TabRows.js'), 'utf8');
  // ⛔ A CSS file has no `//` comments, so the order cannot bite here — but it
  // goes through the shared helper anyway, because "this one is safe" is how
  // eleven files ended up with the wrong order.
  const CSS = stripComments(
    fs.readFileSync(path.join(__dirname, '..', 'app', 'globals.css'), 'utf8')
  );

  it('⛔ both rows are <nav> elements with DIFFERENT accessible names', () => {
    assert.match(SRC, /className="tab-rows-primary" aria-label=\{ariaLabel\}/);
    assert.match(SRC, /className="tab-rows-secondary" aria-label=\{`\$\{ariaLabel\} — views`\}/);
  });

  it('⛔ the active entry carries aria-current in BOTH rows', () => {
    const occurrences = [...SRC.matchAll(/aria-current=/g)];
    assert.equal(occurrences.length, 2);
  });

  it('⛔ NEITHER ROW WRAPS — \u00a77\u2019s acceptance criterion is explicit about this', () => {
    for (const sel of ['.tab-rows-primary', '.tab-rows-secondary']) {
      const i = CSS.indexOf(`${sel} {`);
      assert.ok(i > -1, `${sel} missing`);
      const block = CSS.slice(i, CSS.indexOf('}', i));
      assert.match(block, /overflow-x:\s*auto/, `${sel} must scroll`);
      assert.equal(/flex-wrap:\s*wrap/.test(block), false,
        `${sel}: a wrapped tab row changes the page height by an amount nothing in the markup predicts`);
    }
  });

  it('⛔ THE TWO ROWS ARE VISUALLY DISTINCT — drawn alike they read as one wrapped row', () => {
    const tab = CSS.slice(CSS.indexOf('.tab-rows-tab {'), CSS.indexOf('.tab-rows-tab:hover'));
    const leaf = CSS.slice(CSS.indexOf('.tab-rows-leaf {'), CSS.indexOf('.tab-rows-leaf:hover'));
    assert.match(tab, /border-bottom:\s*2px solid transparent/, 'primary owns the underline');
    assert.equal(/border-bottom/.test(leaf), false, 'a second rule two rows apart reads as a box');
    assert.match(leaf, /border-radius:\s*var\(--radius-pill\)/, 'secondary is a pill strip');
  });

  it('⛔ the active leaf uses a contrast-safe tint pair, not a raw hue', () => {
    const active = CSS.slice(CSS.indexOf('.tab-rows-leaf[data-active] {'));
    const block = active.slice(0, active.indexOf('}'));
    assert.match(block, /var\(--tint-teal\)/);
    assert.match(block, /var\(--tint-teal-fg\)/);
  });

  it('⛔ the secondary row renders at ONE leaf too — it must not change shape between groups', () => {
    assert.match(SRC, /leaves\.length > 0/);
  });

  it('the page mounts it with both rows and an accessible name', () => {
    assert.match(PAGE, /<TabRows groups=\{tabRows\.groups\} leaves=\{tabRows\.leaves\} ariaLabel=/);
  });
});
