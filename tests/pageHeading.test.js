'use strict';

// ⛔ EVERY PAGE HAS EXACTLY ONE h1, AND FOR THIRTY PAGES IT HAD NONE.
//
// components/ui/PageHeader.js rendered its title as `<div className=
// "page-title">`, so the document outline of the entire console was empty
// above card level. A screen-reader user asking for a page's headings got the
// names of the widgets and never the name of the page; "jump to the main
// heading", the first move a keyboard user makes on arrival, had nothing to
// land on.
//
// ⛔ NOTHING COULD HAVE CAUGHT IT BY LOOKING. The rendered pixels are
// identical either way — same size, same weight, same colour — which is the
// same property that let the MFA field ship with `hidden=""` and remain fully
// visible past a live check that asserted the attribute. So the guard has to
// read the MARKUP, and it has to read it from both ends: a page with no
// heading source and a page with two are different defects with the same
// invisible symptom.
//
// ⛔ AND THE SECOND END IS THE ONE WITH A LIVE TRAP IN IT. The six per-device
// routes mount DeviceContextHeader, whose `<h1>` is the FIREWALL'S NAME, and
// globals.css records of it: "a REAL <h1>, and the only one on the page" —
// written when the device name and a PageHeader title last competed as
// headings. Five of those six also mount a PageHeader. Defaulting PageHeader
// to h1 without demoting those five would have put the product straight back
// into the state that comment describes, one release after it was fixed.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

// Comments stripped first. tests/navLayout.test.js learned this the hard way:
// its breakpoint guard failed on the SENTENCE in globals.css explaining why no
// breakpoint may appear there. Prose that discusses <h1> is not an <h1>.
function code(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.name === 'page.js') out.push(full);
  }
  return out;
}

const PAGES = walk(path.join(ROOT, 'app')).sort();
const rel = (f) => path.relative(ROOT, f);

describe('⛔ the page title is a real heading', () => {
  it('PageHeader renders a heading element, never a div', () => {
    const src = code(fs.readFileSync(path.join(ROOT, 'components', 'ui', 'PageHeader.js'), 'utf8'));

    // The outcome, not the mechanism: whatever the element is called in
    // source, the thing carrying .page-title must not be a plain div.
    assert.doesNotMatch(src, /<div className="page-title"/,
      'PageHeader is back to rendering its title as a div — the page outline is empty again');
    assert.match(src, /<Title className="page-title"/,
      'nothing is rendering the title through the heading tag');

    // The default is the whole point. A `titleAs` that fell back to anything
    // other than a heading would reintroduce the defect silently for every
    // page that does not pass it — which is all thirty of them.
    assert.match(src, /HEADING_LEVELS\.has\(titleAs\)\s*\?\s*titleAs\s*:\s*'h1'/,
      "PageHeader's default heading level is not h1");
  });

  it('only heading levels are accepted', () => {
    const src = code(fs.readFileSync(path.join(ROOT, 'components', 'ui', 'PageHeader.js'), 'utf8'));
    const m = src.match(/HEADING_LEVELS = new Set\(\[([^\]]*)\]\)/);
    assert.ok(m, 'the allowed-level set has gone');
    const levels = m[1].split(',').map((x) => x.trim().replace(/['"]/g, '')).filter(Boolean);
    assert.ok(levels.length > 0, 'the allowed-level set is empty');
    for (const lvl of levels) {
      assert.match(lvl, /^h[1-6]$/,
        `${lvl} is not a heading level — a page title must not be able to render as anything else`);
    }
  });
});

describe('⛔ exactly one h1 per page', () => {
  // The two things that can put an h1 on a dashboard page, and the prop that
  // keeps them from doing it at the same time.
  const DEVICE_H1 = 'DeviceContextHeader';

  it('every page that mounts both heading sources demotes its PageHeader', () => {
    const offenders = [];
    for (const file of PAGES) {
      const src = code(fs.readFileSync(file, 'utf8'));
      if (!src.includes(DEVICE_H1) || !src.includes('<PageHeader')) continue;
      // Each such page renders ONE PageHeader; if that ever stops being true
      // the count below catches it rather than this test passing on the first.
      const headers = src.match(/<PageHeader/g) || [];
      const demoted = src.match(/titleAs="h2"/g) || [];
      if (demoted.length !== headers.length) {
        offenders.push(`${rel(file)} (${headers.length} PageHeader, ${demoted.length} demoted)`);
      }
    }
    assert.deepEqual(offenders, [],
      'these pages render the firewall name as an h1 AND a PageHeader title as an h1:\n  '
      + offenders.join('\n  '));
  });

  it('a page that does NOT mount the device header leaves its title an h1', () => {
    // The mirror of the rule above, and the reason it is worth writing: a
    // blanket `titleAs="h2"` would silence the test above while leaving every
    // fleet page with no h1 at all — the original defect, passing.
    const offenders = [];
    for (const file of PAGES) {
      const src = code(fs.readFileSync(file, 'utf8'));
      if (src.includes(DEVICE_H1)) continue;
      if (!src.includes('<PageHeader')) continue;
      if (/titleAs=/.test(src)) offenders.push(rel(file));
    }
    assert.deepEqual(offenders, [],
      'these pages demote their only heading, leaving no h1: ' + offenders.join(', '));
  });

  it('no page hand-rolls a second h1 beside a PageHeader', () => {
    // The CVE detail page and the compliance print page each carry their own
    // <h1> and deliberately render NO PageHeader. That is a valid shape; two
    // sources on one page is not.
    const offenders = [];
    for (const file of PAGES) {
      const src = code(fs.readFileSync(file, 'utf8'));
      if (!src.includes('<PageHeader')) continue;
      if (/<h1[\s>]/.test(src)) offenders.push(rel(file));
    }
    assert.deepEqual(offenders, [],
      'these pages render a literal <h1> as well as a PageHeader: ' + offenders.join(', '));
  });

  it('every page has a heading source — including the one with no visible title', () => {
    // ⛔ THE GAP THE FIRST DRAFT OF THIS FIX LEFT, found by loading the real
    // page rather than by reading the diff: 29 pages gained an h1 through
    // PageHeader and `/` — the route every session lands on — still had none,
    // because the Overview renders no PageHeader at all. A guard that only
    // watches PageHeader cannot see that, so this one asks the question from
    // the page's side: what marks this page's name?
    const sourceless = [];
    for (const file of PAGES) {
      const src = code(fs.readFileSync(file, 'utf8'));
      if (src.includes('<PageHeader') || src.includes(DEVICE_H1)) continue;
      if (/<h1[\s>]/.test(src)) continue;
      sourceless.push(rel(file));
    }
    assert.deepEqual(sourceless, [],
      'these pages have no h1 and no component that supplies one: ' + sourceless.join(', '));
  });

  it("the Overview's invisible h1 says what the sidebar says", () => {
    const { NAV_SECTIONS } = require('../lib/navRegistry');
    const leaves = [];
    for (const s of NAV_SECTIONS) {
      if (s.group) leaves.push(...s.items);
      else leaves.push(s);
    }
    const overview = leaves.find((l) => l.href === '/');
    assert.ok(overview, 'the registry no longer has a leaf for /');

    const src = fs.readFileSync(path.join(ROOT, 'app', '(dashboard)', 'page.js'), 'utf8');
    const m = src.match(/<h1 className="sr-only">([^<]+)<\/h1>/);
    assert.ok(m, 'the Overview has lost its sr-only h1');
    assert.equal(m[1].trim(), overview.label,
      `the Overview announces itself as "${m[1].trim()}" and the sidebar calls it `
      + `"${overview.label}" — the same drift pageTitles.test.js guards, one layer down`);

    // ⛔ sr-only, not display:none. A hidden heading is not in the
    // accessibility tree at all, which would make this element decorative
    // markup that looks like a fix. .sr-only clips it; it stays readable.
    const CSS = fs.readFileSync(path.join(ROOT, 'app', 'globals.css'), 'utf8');
    const block = CSS.slice(CSS.indexOf('\n.sr-only {'));
    const body = block.slice(0, block.indexOf('}'));
    assert.doesNotMatch(body, /display:\s*none/,
      '.sr-only now hides its content from assistive tech too');
    assert.match(body, /clip:\s*rect\(0, 0, 0, 0\)|clip-path/,
      '.sr-only no longer clips — the heading would be visible');
  });

  it('the device header still owns the h1 it claims to', () => {
    const src = code(fs.readFileSync(
      path.join(ROOT, 'components', 'devices', 'DeviceContextHeader.js'), 'utf8'));
    assert.match(src, /<h1 className="dev-ctx-name">/,
      'the firewall name is no longer an h1 — the five demotions above now leave those pages headless');
  });
});

describe('⛔ a heading carries a UA margin and .page-title must cancel it', () => {
  const CSS = fs.readFileSync(path.join(ROOT, 'app', 'globals.css'), 'utf8');

  it('.page-title resets its margin', () => {
    // Pinned because the symptom is a few pixels of drift on thirty pages,
    // which reads as "the spacing is slightly off" rather than as a bug, and
    // because the proof it was needed is still in the tree: the CVE page's own
    // h1 carries a hand-written `marginBottom: 0` for exactly this reason.
    const block = CSS.slice(CSS.indexOf('\n.page-title {'));
    const body = block.slice(0, block.indexOf('}'));
    assert.match(body, /margin:\s*0/,
      '.page-title does not reset the UA heading margin');
  });
});
