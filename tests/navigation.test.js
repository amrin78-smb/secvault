'use strict';

// tests/navigation.test.js
//
// Pins the navigation registry, the seven-section structure built on it, and
// the command palette that reads it.
//
// ⛔ THESE USED TO BE REGEXES OVER components/layout/Sidebar.js, AND THAT IS
// WHY THEY COULD NOT SEE THE BUG THAT MATTERED. The registry was a flat list
// inside the component, so the guards scraped it:
//   /\{\s*href:\s*'([^']+)'/   — which silently required `href` to be the
//                                FIRST key in each object literal, so writing
//                                `label` first hid a destination from the very
//                                guard that exists to stop destinations going
//                                missing;
//   /Icon: (Icon\w+)/          — which could only express "every icon named
//                                anywhere in this file is different". Once the
//                                registry gained a second level that stopped
//                                being the invariant (a section header may
//                                share its own landing page's glyph) and the
//                                guard failed on correct code.
// The registry is `lib/navRegistry.js` now, as data, and these assert the
// structure. Testing the outcome rather than the shape of the source.
//
// ⛔ THE PROPERTY THAT NEARLY BROKE, AND WHY IT HAS NO VISIBLE SYMPTOM.
// `HeaderSearch`'s matchPages() filters over `NAV` — the flattened list. When
// /segmentation and /applications were merged into ONE rendered entry
// (2026-09-29), the obvious implementation was to delete the Applications
// item. That would have removed it from `NAV` as well, so Ctrl+K would have
// answered "no results" to 'applications', 'apps', 'flows', 'cloud',
// 'office 365' and 'saas' — and nothing would have looked wrong: the page
// still renders, the URL still works, the sidebar looks tidier. The only
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
const {
  NAV_SECTIONS,
  NAV_TOP_LEVEL,
  SETTINGS_ITEM,
  NAV,
  visibleNavItems,
  isActive,
  sectionIsActive,
} = require('../lib/navRegistry');
const { SETTINGS_TABS } = require('../lib/settingsTabs');

const ROOT = path.join(__dirname, '..');
const SIDEBAR = path.join(ROOT, 'components', 'layout', 'Sidebar.js');
const SEARCH = path.join(ROOT, 'components', 'layout', 'HeaderSearch.js');
const TABS = path.join(ROOT, 'components', 'layout', 'IntentTabs.js');
const ICONS = path.join(ROOT, 'components', 'icons.js');

const sidebarSrc = stripComments(fs.readFileSync(SIDEBAR, 'utf8'));
const searchSrc = stripComments(fs.readFileSync(SEARCH, 'utf8'));
const iconsSrc = fs.readFileSync(ICONS, 'utf8');

/** Every destination in the registry, hidden and gated ones included. */
const allItems = () => NAV_SECTIONS.flatMap((s) => (s.items ? s.items : [s])).concat([SETTINGS_ITEM]);

/** The destinations the sidebar RENDERS for a super_admin (every capability). */
const everyCapability = new Proxy({}, { get: () => true });
const renderedItems = () => NAV_SECTIONS
  .flatMap((s) => visibleNavItems(s, everyCapability))
  .concat([SETTINGS_ITEM]);

describe('⛔ seven primary destinations, and the hrefs did not move', () => {
  test('the top level is exactly the seven operator questions', () => {
    // Not a count — the ORDER and the WORDS, because this is the list the
    // operator scans. A regression here is a reorganisation nobody asked for.
    assert.deepEqual(NAV_TOP_LEVEL.map((t) => t.label), [
      'Overview',
      'Work queue',
      'Assets',
      'Investigate',
      'Risk',
      'Compliance',
      'Reports',
    ]);
  });

  test('Settings is pinned OUTSIDE the seven', () => {
    assert.ok(!NAV_TOP_LEVEL.some((t) => t.label === 'Settings'),
      'filing Settings under one of the seven makes that section mean less');
    assert.equal(SETTINGS_ITEM.href, '/settings');
  });

  test('⛔ Settings carries no capability gate', () => {
    // CLAUDE.md's licensing section: the Server ID lives there and is the one
    // thing a customer must read off the server to buy or renew anything, so
    // every role can OPEN the page even though most of its tabs refuse to
    // save. Gating the nav entry would hide the renewal path from the person
    // most likely to need it.
    assert.equal(SETTINGS_ITEM.requires, undefined);
  });

  test('⛔ every destination that existed before still exists', () => {
    // The whole safety property of three successive restructures: only what is
    // RENDERED moved. These are in sent notifications and pasted tickets.
    const hrefs = new Set(allItems().map((i) => i.href));
    for (const href of [
      '/', '/work', '/alerts', '/coverage', '/logs', '/reports',
      '/devices', '/topology', '/lifecycle',
      '/vulnerability', '/exposure', '/segmentation', '/conformance',
      '/applications', '/analysis', '/compliance', '/vpn', '/settings',
    ]) {
      assert.ok(hrefs.has(href), `${href} left the registry`);
    }
  });

  test('every href is unique', () => {
    const hrefs = allItems().map((i) => i.href);
    assert.equal(new Set(hrefs).size, hrefs.length, 'two entries point at one page');
  });

  test('⛔ a section is a leaf OR a group, never both', () => {
    // A header that both navigates and expands has two outcomes for one
    // gesture and cannot be given one accessible name.
    for (const s of NAV_SECTIONS) {
      if (s.items) {
        assert.equal(s.href, undefined, `${s.group} is a group AND a link`);
        assert.ok(s.items.length > 0, `${s.group} is an expandable nothing`);
      } else {
        assert.equal(s.items, undefined);
        assert.ok(typeof s.href === 'string' && s.href.startsWith('/'));
      }
    }
  });

  test('⛔ a group\'s landing page is its FIRST child', () => {
    // So nothing sits further away than its own label. If these ever reorder,
    // "Assets" stops meaning "the firewalls" and the disclosure costs a click
    // for no reason.
    const first = (g) => NAV_SECTIONS.find((s) => s.group === g).items[0].href;
    assert.equal(first('Work queue'), '/work');
    assert.equal(first('Assets'), '/devices');
  });
});

describe('⛔ two glyph layers, with different invariants', () => {
  // At rail width (1024-1279px) the stylesheet hides the section HEADERS and
  // shows every item flat as an icon — that is what keeps all fifteen
  // destinations one click away without a hover flyout. So the item glyphs are
  // the wayfinding cue and must all differ; the seven top-level glyphs are what
  // the operator scans in the wide and drawer shapes and must all differ; and a
  // header may reuse one of ITS OWN children's.

  test('every ITEM glyph is distinct — this is the wayfinding cue', () => {
    const glyphs = allItems().map((i) => i.icon);
    const dupes = glyphs.filter((g, n) => glyphs.indexOf(g) !== n);
    assert.deepEqual(dupes, [], 'two destinations share a glyph');
  });

  test('the seven TOP-LEVEL glyphs are distinct from each other', () => {
    const glyphs = NAV_TOP_LEVEL.map((t) => t.icon);
    assert.equal(new Set(glyphs).size, glyphs.length,
      'two of the seven rows the operator scans look identical');
  });

  test('⛔ a section header may only borrow from its OWN children', () => {
    // Assets and Firewalls are both IconDevices, which is correct: a header
    // only ever renders beside its label, and sharing the landing page's glyph
    // is what makes the pair read as one place. Borrowing an UNRELATED
    // section's glyph is the thing that would make the seven unreadable.
    for (const s of NAV_SECTIONS) {
      if (!s.items) continue;
      const own = new Set(s.items.map((i) => i.icon));
      const others = allItems().filter((i) => !own.has(i.icon)).map((i) => i.icon);
      if (others.includes(s.icon)) {
        assert.ok(own.has(s.icon),
          `${s.group} uses ${s.icon}, which belongs to a destination outside it`);
      }
    }
  });

  test('⛔ every icon name resolves to a real export of components/icons.js', () => {
    // The registry names icons as STRINGS so it can be required outside a JSX
    // pipeline. The cost is that a typo renders an empty chip instead of
    // failing to compile, so this is the guard that makes that trade safe.
    // ⛔ THE MODULE'S EXPORTS, NOT ITS DECLARATION KEYWORD. This used to assert
    // `export function <Name>`, which pins the FORM the file happens to use
    // today: converting any icon to `export const IconX = (p) => …` would
    // break the build with a message saying the icon "is not an icon" — the
    // same failure this file's own header records for the old
    // `/Icon: (Icon\w+)/` regex, and the reason the registry became data.
    const exported = new Set([
      ...iconsSrc.matchAll(/export\s+(?:function|const|class)\s+(Icon\w+)/g),
    ].map((m) => m[1]));
    // A scan that found nothing would make every assertion below vacuous.
    assert.ok(exported.size > 20,
      `expected the icon module's exports, found ${exported.size}`);
    for (const item of allItems().concat(NAV_TOP_LEVEL)) {
      assert.ok(exported.has(item.icon),
        `${item.icon} is not exported by components/icons.js`);
    }
  });
});

describe('⛔ a destination may leave the SIDEBAR, never the NAV registry', () => {
  test('/applications is still in the registry', () => {
    // If this fails, Ctrl+K has stopped finding the Applications page.
    assert.ok(NAV.some((i) => i.href === '/applications'),
      'removing the entry also removes it from matchPages() — hide it with navHidden instead');
  });

  test('it is hidden from the rendered sidebar', () => {
    const rendered = renderedItems().map((i) => i.href);
    assert.ok(!rendered.includes('/applications'), 'the merge did not take effect');
    assert.ok(rendered.includes('/segmentation'),
      'the surviving entry of the pair must still render');
  });

  test('the rendered sidebar is shorter than the registry', () => {
    assert.ok(renderedItems().length < allItems().length,
      'nothing is hidden, so the sidebar did not actually get shorter');
  });

  test('⛔ EVERY registry href has palette keywords, including hidden ones', () => {
    // A hidden destination is reachable ONLY by URL, by a tab strip, and by
    // the palette. Of those three the palette is the one an operator reaches
    // for, and it is the one that fails silently.
    const missing = [];
    for (const { href } of allItems()) {
      const re = new RegExp(`'${href.replace(/[/]/g, '\\/')}':\\s*\\[`);
      // /settings is matched by its label alone, which is what people type.
      if (!re.test(searchSrc) && href !== '/settings') missing.push(href);
    }
    assert.deepEqual(missing, [],
      'these destinations have no PAGE_KEYWORDS, so only their exact label finds them');
  });

  test('a navHidden destination keeps keywords that no longer match any label', () => {
    // The rendered label is "Intent". Nobody types that for either page, so
    // these words are the only way the palette finds them.
    for (const word of ['applications', 'apps', 'flows', 'cloud', 'office 365', 'saas']) {
      assert.ok(searchSrc.includes(`'${word}'`),
        `'${word}' no longer reaches the Applications page`);
    }
    for (const word of ['segmentation', 'zones', 'east-west']) {
      assert.ok(searchSrc.includes(`'${word}'`),
        `'${word}' no longer reaches the Segmentation page`);
    }
  });

  test('⛔ a RENAMED label keeps the words people still type', () => {
    // "Coverage" became "Data coverage" and "Topology" became
    // "Topology & paths" in the restructure. Someone who has used this for a
    // year types the old word, and the palette must still answer.
    assert.ok(searchSrc.includes("'coverage'"), "'coverage' no longer reaches /coverage");
    assert.ok(searchSrc.includes("'path'") || searchSrc.includes("'paths'"),
      'the topology page lost its path keyword');
  });
});

describe('⛔ navHidden and requires are different things', () => {
  test('both are honoured, separately, by the render filter', () => {
    // `requires` is authorisation — the page refuses too, this only stops
    // discovery. `navHidden` is layout for a page anyone entitled may still
    // open. Collapsing them into one flag eventually hides a page from
    // someone entitled to it, or advertises one they are not.
    const risk = NAV_SECTIONS.find((s) => s.group === 'Risk');
    const investigate = NAV_SECTIONS.find((s) => s.group === 'Investigate');

    // navHidden: hidden for EVERYONE, however privileged.
    assert.ok(!visibleNavItems(risk, everyCapability).some((i) => i.href === '/applications'));

    // requires: hidden only from an account without the capability.
    assert.ok(visibleNavItems(investigate, everyCapability).some((i) => i.href === '/logs'));
    assert.ok(!visibleNavItems(investigate, { view_log_search: false })
      .some((i) => i.href === '/logs'));
  });

  test('a null/absent capability set shows everything not navHidden', () => {
    // The server resolves capabilities and passes them down; an absent set
    // means "not resolved", and the nav is defence in depth only — every page
    // it links to guards itself. Hiding everything would make an unresolved
    // session look like a broken product.
    const investigate = NAV_SECTIONS.find((s) => s.group === 'Investigate');
    assert.ok(visibleNavItems(investigate, null).some((i) => i.href === '/logs'));
  });

  test('the capability-gated entry is not the merged one', () => {
    // /logs is gated; /applications is merged. If these ever became the same
    // mechanism the distinction above would be untestable.
    const logs = allItems().find((i) => i.href === '/logs');
    const apps = allItems().find((i) => i.href === '/applications');
    assert.equal(logs.requires, 'view_log_search');
    assert.equal(logs.navHidden, undefined);
    assert.equal(apps.navHidden, true);
    assert.equal(apps.requires, undefined,
      'Applications is hidden for layout reasons, not authorisation ones');
  });

  test('a section with no visible entries renders nothing at all', () => {
    // An expandable nothing is worse than an absent section.
    const fake = { group: 'Nothing', icon: 'IconGrid', items: [{ href: '/x', label: 'X', icon: 'IconGrid', requires: 'nope' }] };
    assert.deepEqual(visibleNavItems(fake, { nope: false }), []);
    assert.match(sidebarSrc, /if \(items\.length === 0\) return null;/);
  });
});

describe('⛔ active state, including nested and device-specific routes', () => {
  test('a sub-path lights its parent destination', () => {
    // /devices/<id>/analysis must light Firewalls, or every device page claims
    // you are nowhere.
    assert.ok(isActive('/devices/abc-123', '/devices'));
    assert.ok(isActive('/devices/abc-123/analysis', '/devices'));
    assert.ok(isActive('/compliance/abc-123', '/compliance'));
    assert.ok(isActive('/vulnerability/advisories/CVE-2026-1', '/vulnerability'));
  });

  test('⛔ a prefix that is not a path segment does NOT match', () => {
    // Without the `/` in the startsWith, /devices would light up for a future
    // /devices-archive, and /work for /workspaces.
    assert.ok(!isActive('/devices-archive', '/devices'));
    assert.ok(!isActive('/workspaces', '/work'));
  });

  test('⛔ Overview is EXACT, or it is active everywhere', () => {
    const overview = NAV_SECTIONS.find((s) => s.href === '/');
    assert.equal(overview.exact, true);
    assert.ok(isActive('/', '/', true));
    assert.ok(!isActive('/devices', '/', true));
  });

  test('the shared entry lights up for BOTH of its routes', () => {
    const intent = allItems().find((i) => i.href === '/segmentation');
    assert.deepEqual(intent.alsoActiveFor, ['/applications']);
    assert.ok(isActive('/applications', intent.href, intent.exact, intent.alsoActiveFor));
    assert.ok(isActive('/applications/anything', intent.href, intent.exact, intent.alsoActiveFor));
  });

  test('⛔ a section header is active for a HIDDEN child too', () => {
    // /applications is navHidden but IS a page you can be standing on. A
    // header that went dark there would tell the operator they are nowhere.
    const risk = NAV_SECTIONS.find((s) => s.group === 'Risk');
    assert.ok(sectionIsActive('/applications', risk));
    assert.ok(sectionIsActive('/devices/abc/analysis',
      NAV_SECTIONS.find((s) => s.group === 'Assets')));
  });

  test('⛔ exactly one section is active on any real page', () => {
    // Two active sections means the grouping overlaps and "where am I" has two
    // answers. Checked against every registered destination.
    for (const { href } of allItems()) {
      if (href === '/settings') continue; // pinned outside the seven
      const hits = NAV_SECTIONS.filter((s) => sectionIsActive(href, s)).length;
      assert.equal(hits, 1, `${href} lights ${hits} sections`);
    }
  });

  test('a non-string pathname matches nothing rather than throwing', () => {
    // usePathname() is typed as a string, but a nav that throws takes the whole
    // shell down with it. Fails closed to "nowhere", which renders fine.
    assert.equal(isActive(undefined, '/devices'), false);
    assert.equal(isActive(null, '/', true), false);
  });
});

describe('the renderer honours what the registry declares', () => {
  test('aria-current marks the active destination for a screen reader', () => {
    // The glow, the chip and the left bar only say it visually.
    assert.match(sidebarSrc, /aria-current=\{active \? 'page' : undefined\}/);
  });

  test('a section header is a real button with aria-expanded and aria-controls', () => {
    // A real <button> is why Enter and Space already work and why there is no
    // key handling in the component to get wrong.
    assert.match(sidebarSrc, /type="button"\s+className="sv-nav-section"/);
    assert.match(sidebarSrc, /aria-expanded=\{expanded\}/);
    assert.match(sidebarSrc, /aria-controls=\{bodyId\}/);
    assert.match(sidebarSrc, /id=\{bodyId\}/, 'aria-controls names nothing');
  });

  test('⛔ the ACTIVE section expands itself, and a stored choice still wins', () => {
    assert.match(sidebarSrc, /typeof stored === 'boolean' \? stored : active/);
  });

  test('the drawer trigger and the rail agree on one id', () => {
    const toggle = fs.readFileSync(
      path.join(ROOT, 'components', 'layout', 'NavDrawerToggle.js'), 'utf8');
    assert.match(sidebarSrc, /id="sv-primary-nav"/);
    assert.match(toggle, /aria-controls="sv-primary-nav"/);
  });

  test('⛔ focus enters the drawer on open and returns to the trigger on close', () => {
    assert.match(sidebarSrc, /first\.focus\(\)/);
    assert.match(sidebarSrc, /focusTrigger\(\)/);
  });

  test('every nav row is a module-level component, not defined inside one', () => {
    // CLAUDE.md's first Critical Rule.
    assert.match(sidebarSrc, /^function NavLink\(/m);
    assert.match(sidebarSrc, /^function NavChip\(/m);
    assert.match(sidebarSrc, /^export default function Sidebar\(/m);
  });

  test('⛔ NAV is still exported from Sidebar, where HeaderSearch imports it', () => {
    assert.match(sidebarSrc, /export \{ NAV \}/);
    assert.match(searchSrc, /import \{ NAV(, glyph)? \} from '\.\/Sidebar'/);
  });

  // ⛔ THE TEST ABOVE ASSERTED THE IMPORT AND NOTHING ABOUT WHAT CROSSES IT,
  // AND A CRASH SHIPPED THROUGH THE GAP. v2.216.0 moved the registry into
  // lib/navRegistry.js and renamed each entry's key from `Icon` (a component)
  // to `icon` (a string name). Sidebar was updated; HeaderSearch was not, and
  // kept rendering `<p.Icon />` — `undefined` for all 18 NAV rows, and the 11
  // SETTINGS_DESTINATIONS rows carried no icon field at all. React throws
  // "Element type is invalid" on `createElement(undefined)`, and there is no
  // error.js or global-error.js anywhere under app/, so the throw unmounted the
  // ROOT: a blank "Application error" page, for typing two characters into the
  // header search. 137 navigation tests passed with it live, because the only
  // guard aimed at this asserted that an `import` statement existed.
  //
  // ⛔ SO THIS PINS THE PRODUCER/CONSUMER CONTRACT, NOT THE IMPORT: every row
  // the palette can render must name a glyph that resolves to a real export.
  test('⛔ every palette row names a glyph that RESOLVES — the import is not the contract', () => {
    const exported = new Set(
      [...iconsSrc.matchAll(/export\s+(?:function|const)\s+(Icon\w+)/g)].map((m) => m[1])
    );
    assert.ok(exported.size > 20, `expected the icon module, found ${exported.size} exports`);

    const rows = [
      ...NAV.map((n) => ({ what: `NAV ${n.label}`, icon: n.icon })),
      // HeaderSearch builds one row per settings tab and gives them all the
      // same glyph; assert the name it uses is real.
      ...SETTINGS_TABS.map((t) => ({ what: `Settings › ${t.label}`, icon: 'IconSettings' })),
    ];
    const unresolvable = rows.filter((r) => !r.icon || !exported.has(r.icon));
    assert.deepEqual(unresolvable, [],
      'these palette rows would render React.createElement(undefined) and take the whole '
      + 'page down: ' + unresolvable.map((r) => `${r.what} (${r.icon})`).join(', '));

    // And the consumer must go through a resolver rather than reading a
    // component off the row, which is the shape that broke.
    assert.doesNotMatch(searchSrc, /<p\.Icon\b/,
      'HeaderSearch must resolve icon NAMES via glyph(), not render p.Icon');
  });
});

describe('the tab strip is what makes the Intent merge legible', () => {
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
    assert.match(tabsSrc, /^export default function IntentTabs/m);
  });
});

describe('the restructure did not move anything at the routing layer', () => {
  it('every registry href has a page file behind it', () => {
    // The whole safety property: no redirect, no route deletion, no change to
    // what any existing link resolves to.
    for (const { href } of allItems()) {
      const dir = href === '/' ? [] : href.slice(1).split('/');
      const p = path.join(ROOT, 'app', '(dashboard)', ...dir, 'page.js');
      assert.ok(fs.existsSync(p), `${href} has no page at ${path.relative(ROOT, p)}`);
    }
  });
});
