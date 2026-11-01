'use strict';

// tests/navLayout.test.js
//
// The three shapes of the navigation rail, and the one thing that decides
// which is in force.
//
// ⛔ WHAT THIS IS REALLY GUARDING. Three parties have to agree on the shape:
// the blocking inline script that stamps it before first paint, the stylesheet
// that lays it out, and the React component that decides whether the collapse
// button means anything. The dangerous disagreement is not cosmetic — if the
// stylesheet pushes the rail off-canvas while the component still thinks the
// viewport is wide, the header's drawer trigger is `display: none` and there is
// NO WAY to reach the navigation at all. So the assertions below are mostly
// about there being exactly ONE definition of each number.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  NAV_DRAWER_BELOW,
  NAV_RAIL_BELOW,
  NAV_MODES,
  NAV_MODE_ATTR,
  NAV_MODE_EVENT,
  NAV_MODE_INIT_SCRIPT,
  navModeFor,
  navModeFromDocument,
} = require('../lib/navLayout');

const ROOT = path.join(__dirname, '..');

// ⛔ COMMENTS STRIPPED, AND THE FIRST DRAFT PROVED WHY. The breakpoint guard
// below asserts that no width appears as a CSS breakpoint — and it failed on
// the sentence in globals.css that EXPLAINS why no width may appear there
// ("A `@media (max-width: 1280px)` here would be a third copy..."). Prose read
// as code: the same defect that made the device-scope check believe
// lib/notificationChannels.js held device data because a comment said it did
// not, and the same one that made the Intent tab test fail on its own comment.
// CSS has one comment form, so one regex covers it.
const stripCss = (src) => src.replace(/\/\*[\s\S]*?\*\//g, ' ');
const CSS = stripCss(fs.readFileSync(path.join(ROOT, 'app', 'globals.css'), 'utf8'));

describe('the breakpoints, and the shape each width resolves to', () => {
  test('the three shapes are ordered widest first', () => {
    assert.deepEqual(NAV_MODES, ['wide', 'rail', 'drawer']);
    assert.ok(NAV_DRAWER_BELOW < NAV_RAIL_BELOW,
      'the drawer boundary must be narrower than the rail boundary');
  });

  test('⛔ the rail collapses BEFORE content is clipped, not after', () => {
    // The complaint this answers is that dense workspaces became unusable at
    // intermediate widths while the rail still held its full 240px. 1280 is a
    // common laptop width and must already be collapsed.
    assert.equal(navModeFor(1280), 'wide');
    assert.equal(navModeFor(1279), 'rail');
    assert.equal(navModeFor(1024), 'rail');
    assert.equal(navModeFor(1023), 'drawer');
  });

  test('the named acceptance widths resolve as intended', () => {
    assert.equal(navModeFor(1440), 'wide');
    assert.equal(navModeFor(1920), 'wide');
    assert.equal(navModeFor(1100), 'rail');
    assert.equal(navModeFor(768), 'drawer');
    assert.equal(navModeFor(390), 'drawer');
  });

  test('⛔ AN UNMEASURABLE WIDTH IS `wide`, WHICH HIDES NOTHING', () => {
    // This renders on the server, where there is no viewport. Guessing
    // `drawer` there would serve a screen with the navigation pushed off the
    // side and — if the script then failed — permanently. A navigation's
    // failure mode must be "too much room taken", never "no way to get
    // anywhere". Same instinct as this codebase's failed-read rule, pointed at
    // a layout.
    for (const bad of [undefined, null, NaN, Infinity, -Infinity, 0, -800, '1024', {}]) {
      assert.equal(navModeFor(bad), 'wide', `${String(bad)} must fall back to the full rail`);
    }
  });

  test('navModeFromDocument is safe with no document and rejects junk', () => {
    assert.equal(navModeFromDocument(), 'wide');
    // An attribute someone hand-edited to a value this file cannot render
    // falls back rather than being passed through.
    global.document = { documentElement: { getAttribute: () => 'enormous' } };
    try {
      assert.equal(navModeFromDocument(), 'wide');
      global.document.documentElement.getAttribute = () => 'drawer';
      assert.equal(navModeFromDocument(), 'drawer');
    } finally {
      delete global.document;
    }
  });
});

describe('⛔ ONE definition of each number — the whole reason this file exists', () => {
  test('the init script is BUILT from the constants, not written out again', () => {
    assert.ok(NAV_MODE_INIT_SCRIPT.includes(String(NAV_DRAWER_BELOW)));
    assert.ok(NAV_MODE_INIT_SCRIPT.includes(String(NAV_RAIL_BELOW)));
    assert.ok(NAV_MODE_INIT_SCRIPT.includes(NAV_MODE_ATTR));
    assert.ok(NAV_MODE_INIT_SCRIPT.includes(NAV_MODE_EVENT));
  });

  test('the script and navModeFor() agree at every boundary', () => {
    // Runs the actual shipped script body against a fake window, so this
    // compares the STRING THAT SHIPS with the function, not two readings of
    // the same source.
    const stamped = [];
    const el = {
      attrs: {},
      getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; },
      setAttribute(k, v) { this.attrs[k] = v; stamped.push(v); },
    };
    const win = {
      innerWidth: 1440,
      addEventListener() {},
      dispatchEvent() {},
      CustomEvent: function CE() {},
    };
    const fn = new Function('window', 'document', 'CustomEvent', NAV_MODE_INIT_SCRIPT);

    for (const w of [320, 1023, 1024, 1279, 1280, 1920]) {
      el.attrs = {};
      stamped.length = 0;
      win.innerWidth = w;
      fn(win, { documentElement: el }, win.CustomEvent);
      assert.equal(el.getAttribute(NAV_MODE_ATTR), navModeFor(w),
        `the shipped script and navModeFor() disagree at ${w}px`);
    }
  });

  test('⛔ the script INSTALLS A RESIZE LISTENER — unlike its three siblings', () => {
    // THEME/CORNERS/DENSITY read a stored preference once. The right answer
    // here changes while the page is open, so without this the rail would hold
    // whatever shape the window had when it loaded.
    assert.match(NAV_MODE_INIT_SCRIPT, /addEventListener\("resize"/);
    assert.match(NAV_MODE_INIT_SCRIPT, /passive:\s*true/);
  });

  test('it is wired into the document head, before paint', () => {
    const rootLayout = fs.readFileSync(path.join(ROOT, 'app', 'layout.js'), 'utf8');
    assert.match(rootLayout, /NAV_MODE_INIT_SCRIPT/);
    assert.match(rootLayout, /from '\.\.\/lib\/navLayout'/);
    // In <head>, with the other three. Outside it the first paint would use
    // the wrong shape and visibly jump.
    const head = rootLayout.slice(rootLayout.indexOf('<head>'), rootLayout.indexOf('</head>'));
    assert.ok(head.includes('NAV_MODE_INIT_SCRIPT'), 'it is not in <head>');
  });

  test('⛔ THE STYLESHEET CONTAINS NO RAIL BREAKPOINT AT ALL', () => {
    // This is the assertion that keeps the single definition honest. A
    // `@media (max-width: 1280px)` touching the shell would be a third copy of
    // a number in a third language — and it would also measure the viewport
    // slightly differently from `innerWidth` (they disagree by a scrollbar),
    // putting the boundary in two places a few pixels apart.
    const shellMedia = [...CSS.matchAll(/@media[^{]*\(\s*(?:max|min)-width:\s*(\d+)px[^{]*\{([\s\S]{0,4000}?)\n\}/g)]
      .filter((m) => /\.sv-sidebar|\.sv-nav|\.sv-shell|\.sv-topbar/.test(m[2]));
    assert.deepEqual(shellMedia.map((m) => m[1]), [],
      'a width-based media query is styling the shell — the breakpoints have forked');

    for (const n of [NAV_DRAWER_BELOW, NAV_RAIL_BELOW]) {
      assert.ok(!new RegExp(`width:\\s*${n}px`).test(CSS),
        `${n}px appears as a CSS breakpoint — lib/navLayout.js is meant to be the only definition`);
    }
  });

  test('the stylesheet keys on the attribute instead', () => {
    for (const mode of ['rail', 'drawer']) {
      assert.ok(CSS.includes(`html[${NAV_MODE_ATTR}="${mode}"]`),
        `nothing in the stylesheet reacts to the ${mode} shape`);
    }
    // ⛔ And there must be NO rule for the wide shape alone beyond the
    // collapse preference: wide is the base stylesheet, so if the script never
    // runs the rail renders full-width with every label — the safe direction.
    assert.ok(!CSS.includes(`html:not([${NAV_MODE_ATTR}])`),
      'a no-attribute fallback rule would make a failed script change the layout');
  });
});

describe('⛔ the shapes are mutually exclusive in the stylesheet', () => {
  test('no icon-rail rule mentions the drawer shape', () => {
    // The drawer is the WIDE shape — a panel that takes over the screen has
    // room for labels. If a `[data-nav="drawer"]` ever appeared in the
    // icon-rail selector list, a stored `collapsed` preference would render a
    // 64px strip over a phone.
    const railRules = CSS.split('\n').filter((l) => l.includes('.sv-sidebar.collapsed'));
    assert.ok(railRules.length > 0, 'the icon-rail rules have moved or gone');
    for (const line of railRules) {
      assert.ok(!line.includes('drawer'),
        `an icon-rail rule is scoped to the drawer shape: ${line.trim()}`);
    }
  });

  test('the off-canvas panel is not focusable while closed', () => {
    // ⛔ A panel held off-screen by a transform alone is still in the tab order
    // and still read out, so a keyboard user at this width tabs into a
    // navigation they cannot see. `visibility` is what removes it.
    const drawerBlock = CSS.slice(CSS.indexOf(`html[${NAV_MODE_ATTR}="drawer"] .sv-sidebar {`));
    assert.match(drawerBlock.slice(0, 900), /visibility: hidden/);
    assert.match(drawerBlock.slice(0, 1600), /visibility: visible/);
    assert.match(drawerBlock.slice(0, 900), /transform: translateX\(-100%\)/);
  });

  test('the drawer trigger is absent, not merely invisible, at other widths', () => {
    assert.match(CSS, /\.sv-nav-trigger \{ display: none;/);
    assert.match(CSS, new RegExp(`html\\[${NAV_MODE_ATTR}="drawer"\\] \\.sv-nav-trigger \\{ display: flex;`));
  });
});
