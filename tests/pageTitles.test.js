'use strict';

// ⛔ THE PAGE YOU LAND ON MUST BE THE ONE YOU CLICKED.
//
// Measured before this guard existed: NINE of seventeen nav destinations
// opened with a title that did not match the entry that led there.
//
//   "Intent"          -> a page headed "Segmentation"
//   "Data coverage"   -> "Coverage"
//   "Exposure"        -> "Internet Exposure"
//   "Topology & paths"-> "Topology"
//   "Rule hygiene"    -> "Rule hygiene — Fleet"
//   "Lifecycle"       -> "Lifecycle & Health"
//
// The worst is Intent/Segmentation, where the two words share nothing: an
// operator clicking "Intent" had no way to tell whether they had arrived.
// This is not cosmetic — it is the one check that a nav rename actually
// reached the thing it renamed, and v2.216.0's relabelling is exactly when
// the drift was introduced.
//
// ⛔ IT CHECKS BOTH DIRECTIONS AT ONCE, which is why it is worth having: a
// future change to either the registry or a page title fails here, so the
// pair can never be edited apart.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { NAV_SECTIONS } = require('../lib/navRegistry');

const REPO = path.join(__dirname, '..');

// ⛔ ENTITIES DECODED BEFORE COMPARING. A JSX title is written `&amp;` and the
// registry holds a literal `&`; comparing the raw strings would report a drift
// on every label containing an ampersand — three of them — and the obvious
// "fix" would be to put `&amp;` in the registry, which would then render
// literally in the sidebar.
const decode = (s) => String(s)
  .replace(/&amp;/g, '&')
  .replace(/&mdash;/g, '—')
  .replace(/&rsquo;/g, '’')
  .trim();

// ⛔ NAMED EXEMPTIONS WITH A REASON EACH, never a silent skip — the convention
// lib/deviceScopeCoverage.js's TRANSITIVE_ALLOWED follows.
const EXEMPT = Object.freeze({
  '/': 'the Overview builds its heading from the fleet answer, so there is no static title to compare',
  '/work': 'the leaf is "Queue" inside the group "Work queue"; the page title is the two read together',
});

function leaves() {
  const out = [];
  for (const s of NAV_SECTIONS) {
    if (s.group) out.push(...s.items);
    else out.push(s);
  }
  return out;
}

function pageTitleOf(href) {
  const file = path.join(REPO, 'app', '(dashboard)', href === '/' ? '' : href.slice(1), 'page.js');
  if (!fs.existsSync(file)) return null;
  const src = fs.readFileSync(file, 'utf8');
  // The FIRST PageHeader in the file. Several of these pages render a
  // different header on their no-data branch; both must agree, which the
  // second test below checks.
  const m = src.match(/<PageHeader[\s\S]{0,300}?title=(?:"([^"]+)"|\{`([^`]+)`\}|\{'([^']+)'\})/);
  return m ? decode(m[1] || m[2] || m[3]) : null;
}

describe('every nav destination opens with the title it was clicked by', () => {
  for (const leaf of leaves()) {
    if (EXEMPT[leaf.href]) continue;
    it(`${leaf.label} (${leaf.href})`, () => {
      const title = pageTitleOf(leaf.href);
      if (title === null) {
        // A navHidden entry or a page whose header is built elsewhere.
        assert.ok(
          fs.existsSync(path.join(REPO, 'app', '(dashboard)', leaf.href.slice(1), 'page.js')) === false
            || leaf.navHidden,
          `${leaf.href} has a page file but no findable PageHeader title`
        );
        return;
      }
      assert.equal(
        title, decode(leaf.label),
        `the sidebar says "${leaf.label}" and the page says "${title}" — an operator `
        + 'clicking the first cannot tell they arrived at the second'
      );
    });
  }

  it('⛔ every exemption still names a real destination', () => {
    const hrefs = new Set(leaves().map((l) => l.href));
    for (const href of Object.keys(EXEMPT)) {
      assert.ok(hrefs.has(href), `exemption for ${href} no longer matches any nav entry`);
    }
  });

  it('⛔ the exemption list has not grown into a way of avoiding the check', () => {
    assert.ok(
      Object.keys(EXEMPT).length <= 2,
      'each exemption is a destination this guard no longer protects'
    );
  });
});

describe('a page with two header branches titles them the same', () => {
  // ⛔ SEVERAL OF THESE PAGES RENDER A SEPARATE HEADER ON THEIR NO-DATA PATH
  // (coverage and conformance both do). If only one branch is renamed, the
  // page's name changes depending on whether the fleet has data — which is
  // the drift above, conditional on the database.
  for (const leaf of leaves()) {
    const file = path.join(REPO, 'app', '(dashboard)', leaf.href === '/' ? '' : leaf.href.slice(1), 'page.js');
    if (!fs.existsSync(file)) continue;
    const src = fs.readFileSync(file, 'utf8');
    const titles = [...src.matchAll(/<PageHeader[\s\S]{0,300}?title=(?:"([^"]+)"|\{'([^']+)'\})/g)]
      .map((m) => decode(m[1] || m[2]));
    if (titles.length < 2) continue;
    it(`${leaf.href} uses one title across ${titles.length} header branches`, () => {
      assert.equal(new Set(titles).size, 1,
        `branches disagree: ${JSON.stringify([...new Set(titles)])}`);
    });
  }
});

describe('the Data health rename reached both sides', () => {
  it('⛔ the nav says "Data health", not "Coverage"', () => {
    const all = leaves();
    const entry = all.find((l) => l.href === '/coverage');
    assert.ok(entry, '/coverage left the registry');
    assert.equal(entry.label, 'Data health');
  });

  it('⛔ THE ROUTE IS STILL /coverage — a rename must not break a bookmark', () => {
    assert.ok(
      fs.existsSync(path.join(REPO, 'app', '(dashboard)', 'coverage', 'page.js')),
      'renaming the route would break every saved link, every ticket and the '
      + 'deviceScopeCoverage register that classifies it'
    );
  });
});
