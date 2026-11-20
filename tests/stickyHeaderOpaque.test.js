// tests/stickyHeaderOpaque.test.js
//
// ⛔ WHY THIS EXISTS. A `position: sticky` table heading DETACHES and paints
// OVER the rows scrolling beneath it. It is therefore the one heading in the
// product that cannot be translucent — and the plain `th` ground IS
// translucent in dark theme:
//
//     [data-theme="dark"] th { background: rgba(255,255,255,0.03); }
//
// `table.sticky-header thead th` declared position, z-index and a border
// shadow and NO background, so it inherited that 3% wash and every sticky
// table in the app rendered its heading and its first data row on top of each
// other. Reported from production on /vulnerability.
//
// ⛔ IT WAS DARK-THEME ONLY, WHICH IS WHY IT SURVIVED EVERYTHING. In light
// theme the same cascade hands `th` an OPAQUE #F7F9FB, so the component
// renders perfectly in the default theme — and `tests/cardSurfaces.test.js`
// and the page-render sweep both exercise it there. A rule that is correct in
// one theme and broken in the other cannot be caught by a check that never
// asks which theme it is in.
//
// ⛔ SO THIS ASKS FOR AN OWN, OPAQUE BACKGROUND IN **BOTH** THEMES, rather
// than for the one token that happens to be right today. The next sticky
// heading is the one this is for, and the obvious wrong fix — reaching for
// --surface-subtle, which is rgba() in dark — is exactly the input this
// rejects.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const CSS_PATH = path.join(__dirname, '..', 'app', 'globals.css');

// ⛔ COMMENTS STRIPPED FIRST. This file's own prose quotes
// `background: rgba(255,255,255,0.03)` and the words `position: sticky`, so a
// scan of raw text reads a comment as the rule it is describing — the trap
// tests/buttonContrast.test.js and tests/dataDirAcl.test.js both record.
const CSS = fs.readFileSync(CSS_PATH, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');

function tokensFor() {
  const darkAt = CSS.indexOf('[data-theme="dark"] {');
  assert.notEqual(darkAt, -1, 'expected a [data-theme="dark"] block in globals.css');
  const darkEnd = CSS.indexOf('\n}', darkAt);
  assert.notEqual(darkEnd, -1, 'expected the dark block to be closed');
  const grab = (text) => {
    const out = {};
    const re = /(--[a-z0-9-]+):\s*([^;]+);/gi;
    let m;
    while ((m = re.exec(text))) out[m[1]] = m[2].trim();
    return out;
  };
  const light = grab(CSS.slice(0, darkAt));
  // A token absent from the dark block keeps its light value — how the cascade
  // actually resolves it.
  return { light, dark: { ...light, ...grab(CSS.slice(darkAt, darkEnd)) } };
}

const TOKENS = tokensFor();

// Resolves a background value to { opaque: bool, why: string }. Follows var()
// indirection, with a depth bound so a token cycle fails loudly rather than
// hanging the suite.
function opacityOf(value, theme, depth = 0) {
  const v = String(value || '').trim();
  if (!v) return { opaque: false, why: 'no background declared' };
  if (depth > 8) return { opaque: false, why: 'var() indirection too deep (cycle?)' };

  const varMatch = /^var\(\s*(--[a-z0-9-]+)\s*(?:,\s*([^)]+))?\)$/i.exec(v);
  if (varMatch) {
    const resolved = TOKENS[theme][varMatch[1]] ?? varMatch[2];
    if (resolved === undefined) {
      return { opaque: false, why: `${varMatch[1]} is not defined in the ${theme} theme` };
    }
    return opacityOf(resolved, theme, depth + 1);
  }

  if (/^transparent$/i.test(v) || /^none$/i.test(v)) return { opaque: false, why: v };

  const rgba = /^rgba?\(\s*[\d.]+[\s,]+[\d.]+[\s,]+[\d.]+(?:\s*[,/]\s*([\d.]+%?))?\s*\)$/i.exec(v);
  if (rgba) {
    if (rgba[1] === undefined) return { opaque: true, why: v };
    const a = rgba[1].endsWith('%') ? parseFloat(rgba[1]) / 100 : parseFloat(rgba[1]);
    return { opaque: a >= 1, why: `alpha ${a} in ${v}` };
  }

  const hex = /^#([0-9a-f]{3,8})$/i.exec(v);
  if (hex) {
    const h = hex[1];
    if (h.length === 4) return { opaque: h[3].toLowerCase() === 'f', why: v };
    if (h.length === 8) return { opaque: h.slice(6).toLowerCase() === 'ff', why: v };
    return { opaque: true, why: v };
  }

  return { opaque: false, why: `unrecognised colour "${v}" — cannot prove it is opaque` };
}

// Every `selector { decls }` pair. @media wrappers fold harmlessly into the
// selector text of the first rule inside them; nothing here keys on that.
function stickyHeadingRules() {
  const out = [];
  const re = /([^{}]+)\{([^{}]*)\}/g;
  let m;
  while ((m = re.exec(CSS))) {
    const selector = m[1].trim().split('\n').pop().trim();
    const decls = m[2];
    if (!/position\s*:\s*sticky/i.test(decls)) continue;
    // Selectors that end at a table heading cell.
    if (!/(^|[\s>,.#\]])th$/.test(selector)) continue;
    const bg = /(?:^|;)\s*background(?:-color)?\s*:\s*([^;]+)/i.exec(decls);
    out.push({ selector, background: bg ? bg[1].trim() : null });
  }
  return out;
}

describe('a sticky table heading is opaque in every theme', () => {
  const rules = stickyHeadingRules();

  it('⛔ the scan finds the sticky heading rules at all', () => {
    // Without this the whole file goes vacuously green the day a selector is
    // reworded — a guard that cannot fire, which is the defect class this
    // repo names most often.
    assert.ok(
      rules.length >= 2,
      `expected at least 2 sticky th rules in globals.css, found ${rules.length}`
    );
    assert.ok(
      rules.some((r) => /table\.sticky-header/.test(r.selector)),
      'expected the ui/Table stickyHeader rule (table.sticky-header thead th)'
    );
  });

  for (const theme of ['light', 'dark']) {
    it(`⛔ every sticky heading declares an opaque background — ${theme}`, () => {
      for (const rule of rules) {
        assert.ok(
          rule.background,
          `"${rule.selector}" is sticky and declares NO background of its own, so it ` +
            'inherits the plain th ground — which is translucent in dark theme and ' +
            'lets scrolled rows show through the heading'
        );
        const { opaque, why } = opacityOf(rule.background, theme);
        assert.ok(
          opaque,
          `"${rule.selector}" resolves to a non-opaque background in the ${theme} ` +
            `theme (${why}); rows scrolling under it will show through`
        );
      }
    });
  }

  it('⛔ --table-head-bg itself is opaque in both themes', () => {
    // The token the rules above point at. Pinned separately because the
    // tempting "simplification" is to alias it onto --surface-subtle, which is
    // rgba(255,255,255,0.045) in dark — reinstating the bug while every rule
    // above still reads as though it declares a background.
    for (const theme of ['light', 'dark']) {
      assert.ok(TOKENS[theme]['--table-head-bg'], `--table-head-bg missing in ${theme}`);
      const { opaque, why } = opacityOf('var(--table-head-bg)', theme);
      assert.ok(opaque, `--table-head-bg is not opaque in ${theme} (${why})`);
    }
  });
});
