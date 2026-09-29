'use strict';

// tests/navigation.test.js
//
// Pins the sidebar's nav registry and the command palette that reads it.
//
// ⛔ THE PROPERTY THAT NEARLY BROKE, AND WHY IT HAS NO VISIBLE SYMPTOM.
// `HeaderSearch`'s matchPages() filters over `NAV` — the flat list exported by
// Sidebar.js. When /segmentation and /applications were merged into ONE
// rendered entry (2026-09-29), the obvious implementation was to delete the
// Applications item. That would have removed it from `NAV` as well, so Ctrl+K
// would have answered "no results" to 'applications', 'apps', 'flows',
// 'cloud', 'office 365' and 'saas' — and nothing would have looked wrong: the
// page still renders, the URL still works, the sidebar looks tidier. The only
// symptom is a search that quietly stops finding a page.
//
// So the rule is: a destination may be hidden from the SIDEBAR, never from
// `NAV`. `navHidden` is the layout flag; `requires` is the authorisation one;
// they are deliberately different fields and this file asserts both.

const { describe, it, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { stripComments } = require('./stripComments');

const ROOT = path.join(__dirname, '..');
const SIDEBAR = path.join(ROOT, 'components', 'layout', 'Sidebar.js');
const SEARCH = path.join(ROOT, 'components', 'layout', 'HeaderSearch.js');
const TABS = path.join(ROOT, 'components', 'layout', 'IntentTabs.js');

const sidebarSrc = stripComments(fs.readFileSync(SIDEBAR, 'utf8'));
const searchSrc = stripComments(fs.readFileSync(SEARCH, 'utf8'));

/** Every `href: '...'` in the nav registry, in source order. */
function navHrefs() {
  return [...sidebarSrc.matchAll(/\{\s*href:\s*'([^']+)'/g)].map((m) => m[1]);
}

/** The hrefs the sidebar actually RENDERS (i.e. not navHidden). */
function renderedHrefs() {
  return [...sidebarSrc.matchAll(/\{\s*href:\s*'([^']+)'[^}]*\}/g)]
    .filter((m) => !/navHidden:\s*true/.test(m[0]))
    .map((m) => m[1]);
}

describe('⛔ a destination may leave the SIDEBAR, never the NAV registry', () => {
  test('/applications is still in the registry', () => {
    // If this fails, Ctrl+K has stopped finding the Applications page.
    assert.ok(navHrefs().includes('/applications'),
      'removing the entry also removes it from matchPages() — hide it with navHidden instead');
  });

  test('it is hidden from the rendered sidebar', () => {
    assert.ok(!renderedHrefs().includes('/applications'),
      'the merge did not take effect');
    assert.ok(renderedHrefs().includes('/segmentation'),
      'the surviving entry of the pair must still render');
  });

  test('⛔ EVERY registry href has palette keywords, including hidden ones', () => {
    // A hidden destination is reachable ONLY by URL, by a tab strip, and by
    // the palette. Of those three the palette is the one an operator reaches
    // for, and it is the one that fails silently.
    const missing = [];
    for (const href of navHrefs()) {
      const key = href.replace(/'/g, '');
      const re = new RegExp(`'${key.replace(/[/]/g, '\\/')}':\\s*\\[`);
      if (!re.test(searchSrc) && key !== '/settings') {
        // /settings is matched by its label alone, which is what people type.
        missing.push(key);
      }
    }
    assert.deepEqual(missing, [],
      'these destinations have no PAGE_KEYWORDS, so only their exact label finds them');
  });

  test('a navHidden destination keeps keywords that no longer match any label', () => {
    // The rendered label is now "Intent". Nobody types that for either page,
    // so these words are the only way the palette finds them.
    for (const word of ['applications', 'apps', 'flows', 'cloud', 'office 365', 'saas']) {
      assert.ok(searchSrc.includes(`'${word}'`),
        `'${word}' no longer reaches the Applications page`);
    }
    for (const word of ['segmentation', 'zones', 'east-west']) {
      assert.ok(searchSrc.includes(`'${word}'`),
        `'${word}' no longer reaches the Segmentation page`);
    }
  });
});

describe('⛔ navHidden and requires are different things', () => {
  test('both are honoured, separately, in the render filter', () => {
    // `requires` is authorisation — the page refuses too, this only stops
    // discovery. `navHidden` is layout for a page anyone entitled may still
    // open. Collapsing them into one flag eventually hides a page from
    // someone entitled to it, or advertises one they are not.
    assert.match(sidebarSrc, /!it\.navHidden/);
    assert.match(sidebarSrc, /it\.requires \|\| !capabilities \|\| capabilities\[it\.requires\]/);
  });

  test('the capability-gated entry is not the merged one', () => {
    // /logs is gated; /applications is merged. If these ever became the same
    // mechanism the distinction above would be untestable.
    assert.match(sidebarSrc, /'\/logs'[^}]*requires:/);
    assert.ok(!/'\/applications'[^}]*requires:/.test(sidebarSrc),
      'Applications is hidden for layout reasons, not authorisation ones');
  });
});

describe('⛔ the shared entry lights up for BOTH of its routes', () => {
  test('isActive takes and uses alsoActiveFor', () => {
    // Without this the Intent entry goes dark on /applications and the sidebar
    // claims you are nowhere — worse than an unmerged list, because the
    // operator cannot tell which section they are in.
    assert.match(sidebarSrc, /function isActive\(pathname, href, exact, alsoActiveFor\)/);
    assert.match(sidebarSrc, /alsoActiveFor\.some\(under\)/);
    assert.match(sidebarSrc, /isActive\(pathname, href, exact, alsoActiveFor\)/,
      'the render loop must pass the field through, or it is inert');
  });

  test('the surviving entry claims the hidden one', () => {
    assert.match(sidebarSrc, /alsoActiveFor:\s*\['\/applications'\]/);
  });

  test('a sub-path of either route still matches', () => {
    // `under()` must keep the startsWith behaviour the original had, or a
    // detail page below either route drops the highlight.
    assert.match(sidebarSrc, /pathname\.startsWith\(`\$\{base\}\/`\)/);
  });
});

describe('the tab strip is what makes the merge legible', () => {
  // ⛔ COMMENTS STRIPPED. The first draft read TABS raw, and the `?tab=`
  // test below failed on the word appearing in this file's own explanatory
  // comment — prose read as code, which is exactly what bit the device-scope
  // check on lib/notificationChannels.js.
  const tabsSrc = stripComments(fs.readFileSync(TABS, 'utf8'));

  test('it names both routes and keeps the OLD words as labels', () => {
    assert.match(tabsSrc, /href: '\/segmentation', label: 'Segmentation'/);
    assert.match(tabsSrc, /href: '\/applications', label: 'Applications'/);
  });

  test('⛔ it links to ROUTES, not to a ?tab= on one page', () => {
    // Both URLs already exist in sent notifications and pasted tickets.
    // CLAUDE.md's rule is that hrefs never change, so the merge happens in
    // the sidebar and nowhere else.
    assert.ok(!/\?tab=/.test(tabsSrc), 'this would change the URLs the merge promised not to');
  });

  test('both pages render it, each declaring which tab it is', () => {
    const seg = fs.readFileSync(path.join(ROOT, 'app', '(dashboard)', 'segmentation', 'page.js'), 'utf8');
    const app = fs.readFileSync(path.join(ROOT, 'app', '(dashboard)', 'applications', 'page.js'), 'utf8');
    assert.match(seg, /<IntentTabs active="\/segmentation" \/>/);
    assert.match(app, /<IntentTabs active="\/applications" \/>/);
    assert.match(seg, /import IntentTabs from/);
    assert.match(app, /import IntentTabs from/);
  });

  test('it is a module-level component, not defined inside one', () => {
    // CLAUDE.md's first Critical Rule.
    assert.match(tabsSrc, /^export default function IntentTabs/m);
  });
});

describe('the merge did not move anything at the routing layer', () => {
  test('both page files still exist', () => {
    // The whole safety property: no redirect, no route deletion, no change to
    // what any existing link resolves to.
    for (const p of [
      ['app', '(dashboard)', 'segmentation', 'page.js'],
      ['app', '(dashboard)', 'applications', 'page.js'],
    ]) {
      assert.ok(fs.existsSync(path.join(ROOT, ...p)), `${p.join('/')} was removed`);
    }
  });

  it('the rendered sidebar is shorter than the registry', () => {
    assert.ok(renderedHrefs().length < navHrefs().length,
      'nothing is hidden, so the sidebar did not actually get shorter');
  });
});
