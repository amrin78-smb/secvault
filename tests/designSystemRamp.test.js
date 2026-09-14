// tests/designSystemRamp.test.js
//
// The severity/risk-band ramp, pinned. Two questions, both of which have
// already been answered wrongly in production:
//
//   1. Does every surface agree on what "High" looks like?
//   2. Is the colour it agrees on actually READABLE where it is used?
//
// ⛔ WHY THIS EXISTS. v2.87.0 rewrote the palette and pulled BLUE off the
// severity ramp entirely, because --blue sits one step from --primary teal and
// a severity drawn in the brand hue destroys the one separation the palette is
// built on (CLAUDE.md, "Colour means RISK"). SeverityBadge.js and
// FindingsBarChart.js moved. SIX other places did not, and nothing caught it:
// two fleet pages, a printed compliance report, the risky-rules tab, the risk
// tab and the dashboard widget all kept rendering `medium` BLUE. On
// /devices/[id]/analysis the stale tiles sat DIRECTLY ABOVE the corrected
// chart, colouring the same numbers differently on one screen.
//
// A ramp drifting is invisible to every other check in this repo: it builds,
// it typechecks, it renders, and the wrong colour is a plausible colour.
//
// ⛔ SOURCE-TEXT AND ARITHMETIC ONLY. Nothing here renders a component. The
// maps are read out of the module source (the app is ESM, this runner is
// CommonJS) and the contrast ratios are computed from app/globals.css's own
// token values by the WCAG 2.x formula. That makes the numbers in the comments
// checkable rather than asserted.

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(REPO, rel), 'utf8');

// ── Loading the maps out of ESM source ───────────────────────────────────
// `npm test` is `node --test tests/` with no "type":"module", so these files
// cannot be require()d. They are plain const declarations, so stripping the
// `export` keyword and evaluating is exact, not an approximation.
function loadRamp() {
  const src = read('components/analysis/severityRamp.js').replace(/\bexport\s+const\b/g, 'const');
  const names = [
    'SEVERITY_LABEL',
    'SEVERITY_BADGE_COLOR',
    'SEVERITY_FILL',
    'SEVERITY_TEXT_COLOR',
    'BAND_LABEL',
    'BAND_BADGE_COLOR',
    'BAND_FILL',
  ];
  // eslint-disable-next-line no-new-func
  return new Function(`${src}\nreturn { ${names.join(', ')} };`)();
}

// Pulls a single object literal out of a source file by its const name.
function objectLiteral(src, name) {
  const start = src.indexOf(`const ${name} = {`);
  assert.notEqual(start, -1, `expected a "const ${name} = {" declaration`);
  const open = src.indexOf('{', start);
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') {
      depth--;
      if (depth === 0) {
        // eslint-disable-next-line no-new-func
        return new Function(`return ${src.slice(open, i + 1)};`)();
      }
    }
  }
  assert.fail(`unbalanced braces reading ${name}`);
}

// ── WCAG 2.x relative luminance / contrast ratio ─────────────────────────
function channel(v) {
  const c = v / 255;
  return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}
function rgb(hex) {
  const h = hex.replace('#', '');
  const full = h.length === 3 ? h.split('').map((c) => c + c).join('') : h;
  return [0, 2, 4].map((i) => parseInt(full.substr(i, 2), 16));
}
function luminance(hex) {
  const [r, g, b] = rgb(hex).map(channel);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function contrast(a, b) {
  const l1 = luminance(a);
  const l2 = luminance(b);
  return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
}
// A --tint-* token is an rgba() over the surface behind it, so the effective
// background has to be composited before it can be measured. Measuring the fg
// against the CARD colour instead would flatter the result.
function composite(rgbaHex, alpha, bgHex) {
  const f = rgb(rgbaHex);
  const b = rgb(bgHex);
  const out = f.map((v, i) => Math.round(v * alpha + b[i] * (1 - alpha)));
  return '#' + out.map((v) => v.toString(16).padStart(2, '0')).join('');
}

// ── globals.css token extraction ─────────────────────────────────────────
// The light values live on bare `:root`, the dark overrides in the
// [data-theme="dark"] block; a token absent from the dark block keeps its
// light value, which is exactly how the cascade resolves it.
function tokens() {
  const css = read('app/globals.css');
  const darkAt = css.indexOf('[data-theme="dark"]');
  assert.notEqual(darkAt, -1, 'expected a [data-theme="dark"] block in globals.css');
  const grab = (text) => {
    const out = {};
    const re = /(--[a-z0-9-]+):\s*([^;]+);/gi;
    let m;
    while ((m = re.exec(text))) out[m[1]] = m[2].trim();
    return out;
  };
  const light = grab(css.slice(0, darkAt));
  const dark = { ...light, ...grab(css.slice(darkAt)) };
  return { light, dark };
}

const HEX = /^#[0-9a-f]{3,8}$/i;
const RGBA = /^rgba\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*([\d.]+)\s*\)$/i;

function rgbaToHexAlpha(value) {
  const m = RGBA.exec(value);
  assert.ok(m, `expected an rgba() token, got "${value}"`);
  const hex =
    '#' + [m[1], m[2], m[3]].map((v) => Number(v).toString(16).padStart(2, '0')).join('');
  return { hex, alpha: Number(m[4]) };
}

// ─────────────────────────────────────────────────────────────────────────
// 1. One ramp. Every surface agrees.
// ─────────────────────────────────────────────────────────────────────────

test('the ramp module, SeverityBadge and FindingsBarChart agree on every severity', () => {
  const ramp = loadRamp();
  const badgeMap = objectLiteral(read('components/analysis/SeverityBadge.js'), 'SEVERITY_MAP');
  const chartMap = objectLiteral(read('components/analysis/FindingsBarChart.js'), 'SEVERITY_COLOR');

  for (const sev of ['critical', 'high', 'medium', 'info']) {
    assert.equal(
      ramp.SEVERITY_BADGE_COLOR[sev],
      badgeMap[sev].color,
      `severityRamp.js and SeverityBadge.js disagree on "${sev}" — a badge and a ` +
        'stat tile for the same finding would be different colours'
    );
    assert.equal(
      ramp.SEVERITY_FILL[sev],
      chartMap[sev],
      `severityRamp.js and FindingsBarChart.js disagree on "${sev}" — this is the ` +
        'exact defect the ramp module exists to end: on /devices/[id]/analysis the ' +
        'tiles sit directly above that chart'
    );
    assert.equal(
      ramp.SEVERITY_LABEL[sev],
      badgeMap[sev].label,
      `severityRamp.js and SeverityBadge.js disagree on the LABEL for "${sev}"`
    );
  }
});

test('risk bands reuse the severity ramp for the three shared steps', () => {
  const ramp = loadRamp();
  // A band is a severity seen from the other end. If critical/high/medium ever
  // diverge between the two, a "High" device and a "High" finding stop looking
  // alike and the reader has to learn two colour languages.
  for (const key of ['critical', 'high', 'medium']) {
    assert.equal(ramp.BAND_BADGE_COLOR[key], ramp.SEVERITY_BADGE_COLOR[key], `band "${key}"`);
    assert.equal(ramp.BAND_FILL[key], ramp.SEVERITY_FILL[key], `band fill "${key}"`);
  }
});

// ─────────────────────────────────────────────────────────────────────────
// 2. Blue is off the ramp, and the top two bands are distinguishable.
// ─────────────────────────────────────────────────────────────────────────

test('no severity or band is blue, in any of its three representations', () => {
  const ramp = loadRamp();
  const maps = {
    SEVERITY_BADGE_COLOR: ramp.SEVERITY_BADGE_COLOR,
    SEVERITY_FILL: ramp.SEVERITY_FILL,
    SEVERITY_TEXT_COLOR: ramp.SEVERITY_TEXT_COLOR,
    BAND_BADGE_COLOR: ramp.BAND_BADGE_COLOR,
    BAND_FILL: ramp.BAND_FILL,
  };
  for (const [name, map] of Object.entries(maps)) {
    for (const [key, value] of Object.entries(map)) {
      // 'info' is Badge's blue variant; --blue and --tint-info-* are the raw
      // and text-safe blues. All three are forbidden on a severity.
      assert.notEqual(value, 'info', `${name}.${key} is Badge's BLUE variant`);
      assert.ok(
        !/--blue|tint-info/.test(value),
        `${name}.${key} = "${value}" puts blue back on the ramp; --blue is one step ` +
          'from --primary teal and the palette rewrite pulled it off severity for that reason'
      );
    }
  }
});

test('--sev-low is slate, not blue — the token that keeps the brand hue unambiguous', () => {
  const { light, dark } = tokens();
  for (const [theme, t] of [['light', light], ['dark', dark]]) {
    const value = t['--sev-low'];
    assert.ok(HEX.test(value), `--sev-low should be a literal slate hex in ${theme}, got "${value}"`);
    const [r, g, b] = rgb(value);
    // Slate is very slightly blue-leaning by design; a real blue is not.
    // --blue in either theme has b - r > 100, slate has b - r ~= 30.
    assert.ok(
      b - r < 60,
      `--sev-low (${value}) has drifted toward blue in ${theme} theme. Dropping blue ` +
        'out of the severity ramp is what keeps --primary teal from reading as a severity.'
    );
  }
});

test('critical and high are visually distinct in every representation', () => {
  const ramp = loadRamp();
  // On /exposure both returned Badge `danger`, so the most exposed path on the
  // fleet was indistinguishable from the one below it and only the sort order
  // carried the difference.
  assert.notEqual(ramp.SEVERITY_BADGE_COLOR.critical, ramp.SEVERITY_BADGE_COLOR.high);
  assert.notEqual(ramp.SEVERITY_FILL.critical, ramp.SEVERITY_FILL.high);
  assert.notEqual(ramp.SEVERITY_TEXT_COLOR.critical, ramp.SEVERITY_TEXT_COLOR.high);
  assert.notEqual(ramp.BAND_BADGE_COLOR.critical, ramp.BAND_BADGE_COLOR.high);
  // ...and high must not borrow medium's hue either, which is what --yellow on
  // `high` used to do.
  assert.notEqual(ramp.SEVERITY_FILL.high, ramp.SEVERITY_FILL.medium);
  assert.notEqual(ramp.SEVERITY_TEXT_COLOR.high, ramp.SEVERITY_TEXT_COLOR.medium);
});

// ─────────────────────────────────────────────────────────────────────────
// 3. ⛔ THE NOT-MEASURED CASE. The one that regresses silently.
// ─────────────────────────────────────────────────────────────────────────

test('the unmeasured band has NO hue and is never a point on the ramp', () => {
  const ramp = loadRamp();
  // computeRuleRiskBand()'s 'attention': an enabled rule with no finding of its
  // own — "nothing wrong found, but nothing confirming this one is fine". That
  // is not a low severity and not a clean result. Colouring it anywhere on the
  // ramp, in EITHER direction, is a claim SecVault has not earned — the same
  // error as hit_count's old NOT NULL DEFAULT 0, in pixels.
  assert.equal(ramp.BAND_FILL.attention, 'var(--unmeasured)');
  assert.equal(ramp.BAND_BADGE_COLOR.attention, 'muted');
  const rampHues = new Set(Object.values(ramp.SEVERITY_FILL));
  assert.ok(
    !rampHues.has(ramp.BAND_FILL.attention),
    'the unmeasured band has been given a severity hue, which asserts a measurement'
  );
});

// ⛔ Resolves a surface token to a measurable hex. --surface-subtle is an
// opaque hex in light theme and an rgba() white wash in dark, so the dark value
// has to be composited over the card it actually sits on before it can be
// measured. Treating the dark wash as opaque white would flatter every result
// here by several points.
function surfaceHex(t, name) {
  const value = t[name];
  if (HEX.test(value)) return value;
  const { hex, alpha } = rgbaToHexAlpha(value);
  const card = t['--bg-card'];
  assert.ok(HEX.test(card), 'expected --bg-card to be a hex wherever a wash surface is used');
  return composite(hex, alpha, card);
}

// ⛔ THE PAIRING NOBODY WAS CHECKING, and the reason this case exists.
// Every --tint-*/-fg pair is pinned at 4.5:1 below, and --unmeasured was checked
// only for NEUTRALITY (no hue) above — so nothing measured whether the hueless
// state could actually be READ. It could not: #6D7784 on the light
// --surface-subtle was 4.12:1 and #7A8BA1 on the dark one was 4.48:1. Both under
// WCAG 1.4.3's 4.5:1, in opposite themes, for the same reason — the token had
// been eyeballed against --bg-card (4.54:1, a pass) while the chips that use it
// sit on the SUBTLE surface.
//
// That is the worst thing in this product to render unreadable. A number that is
// hard to read is still obviously a number; a faded "Not measured" chip or
// em-dash is indistinguishable from an EMPTY CELL, and an empty cell reads as
// "nothing to report". The whole point of the unmeasured vocabulary is that a
// gap announces itself, so this state needs MORE legibility than a measured one,
// not less.
//
// Both surfaces are checked because both are live call sites: --surface-subtle
// (the .ev-unmeasured strip, the no-status chips, NotMeasuredBar's swatch) and
// --bg-card (a bare NotMeasured em-dash in a table cell).
test('--unmeasured is READABLE on every surface it is used on, in BOTH themes', () => {
  const { light, dark } = tokens();
  for (const [theme, t] of [['light', light], ['dark', dark]]) {
    const fg = t['--unmeasured'];
    for (const surface of ['--surface-subtle', '--bg-card']) {
      const bg = surfaceHex(t, surface);
      const ratio = contrast(fg, bg);
      assert.ok(
        ratio >= 4.5,
        `--unmeasured (${fg}) on ${surface} is ${ratio.toFixed(2)}:1 in ${theme} theme, below ` +
          'WCAG 1.4.3’s 4.5:1. An unreadable "not measured" chip is worse than an unreadable ' +
          'number: it reads as an empty cell, i.e. as nothing to report, which is exactly the ' +
          'failed-read-as-a-fact error this state exists to prevent.'
      );
    }
  }
});

test('--unmeasured is a neutral, and --hatch exists for unmeasured graphics', () => {
  const { light, dark } = tokens();
  for (const [theme, t] of [['light', light], ['dark', dark]]) {
    const value = t['--unmeasured'];
    assert.ok(HEX.test(value), `--unmeasured should be a hex in ${theme}, got "${value}"`);
    const [r, g, b] = rgb(value);
    // A neutral: no channel may run away from the others. A hue here would let
    // "we could not measure this" read as good news or bad news.
    assert.ok(
      Math.max(r, g, b) - Math.min(r, g, b) < 40,
      `--unmeasured (${value}) has picked up a hue in ${theme} theme`
    );
  }
  assert.ok(light['--hatch'], '--hatch must exist: an unmeasured bar segment or swatch uses it');
});

// ─────────────────────────────────────────────────────────────────────────
// 4. Readable, not just consistent.
// ─────────────────────────────────────────────────────────────────────────

test('SEVERITY_TEXT_COLOR never uses a raw ramp hue', () => {
  const ramp = loadRamp();
  for (const [key, value] of Object.entries(ramp.SEVERITY_TEXT_COLOR)) {
    assert.ok(
      !/--red|--orange|--yellow|--green|--blue|--sev-/.test(value),
      `SEVERITY_TEXT_COLOR.${key} = "${value}" is a raw graphics hue. globals.css ` +
        'measures --yellow at 3.64:1 on white: it clears 1.4.11’s 3:1 for a ' +
        'graphical object and FAILS 1.4.3’s 4.5:1 for text.'
    );
    assert.ok(
      /--tint-[a-z]+-fg|--text-muted|--text-secondary|--text-primary/.test(value),
      `SEVERITY_TEXT_COLOR.${key} = "${value}" is not one of the text-safe tokens`
    );
  }
});

test('every --tint-* / --tint-*-fg pair clears 4.5:1 in BOTH themes', () => {
  const { light, dark } = tokens();
  const surfaces = { light: '#FFFFFF', dark: null }; // dark card resolved below
  surfaces.dark = dark['--bg-card'];
  assert.ok(HEX.test(surfaces.dark), 'expected --bg-card to be a hex in the dark block');

  const names = ['info', 'success', 'warn', 'danger', 'purple', 'teal', 'orange'];
  for (const [theme, t] of [['light', light], ['dark', dark]]) {
    for (const name of names) {
      const { hex, alpha } = rgbaToHexAlpha(t[`--tint-${name}`]);
      const fg = t[`--tint-${name}-fg`];
      assert.ok(HEX.test(fg), `--tint-${name}-fg should be a hex in ${theme}`);
      const bg = composite(hex, alpha, surfaces[theme]);
      const ratio = contrast(fg, bg);
      assert.ok(
        ratio >= 4.5,
        `--tint-${name}-fg on --tint-${name} is ${ratio.toFixed(2)}:1 in ${theme} theme, ` +
          'below WCAG 1.4.3’s 4.5:1. These pairs are what the rest of the app relies on ' +
          'for coloured TEXT; if one stops clearing the bar, every caller silently does too.'
      );
    }
  }
});

test('white on a raw --blue fails in dark theme — the reason UpdateNotifier moved off it', () => {
  const { light, dark } = tokens();
  // Not a regression guard on the token (it is a legitimate graphics hue in
  // both themes) but a guard on the REASONING: if --blue ever became dark
  // enough to carry white text, the comment in UpdateNotifier.js would be
  // wrong and someone would rightly revert the fix. It is not close today.
  const onLight = contrast('#FFFFFF', light['--blue']);
  const onDark = contrast('#FFFFFF', dark['--blue']);
  assert.ok(onLight >= 4.5, `white on light --blue is ${onLight.toFixed(2)}:1`);
  assert.ok(
    onDark < 4.5,
    `white on dark --blue is now ${onDark.toFixed(2)}:1. If this ever passes, revisit ` +
      'components/layout/UpdateNotifier.js — it was moved onto --tint-info for this reason.'
  );
});

// ─────────────────────────────────────────────────────────────────────────
// 5. No seventh local map.
// ─────────────────────────────────────────────────────────────────────────

// Every .js source file under the app. Shared by the two scans below so they
// cannot drift apart on which directories they look at.
function sourceFiles() {
  const SKIP = new Set(['node_modules', '.next', '.git', 'tests', 'installer', 'public', 'docs']);
  const files = [];
  (function walk(dir) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (SKIP.has(e.name)) continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.js')) files.push(p);
    }
  })(REPO);
  return files;
}

test('no page or component redeclares the ramp with blue on a severity', () => {
  const files = sourceFiles();

  // The exact shapes the six stale copies had. Comments are stripped first so
  // a file DOCUMENTING the old mapping (several deliberately do, to explain
  // what was wrong) is not mistaken for one still rendering it.
  const forbidden = [
    /\bmedium:\s*'info'/,
    /\bmedium:\s*(?:\{[^}]*)?'?var\(--blue\)'?/,
    /\bhigh:\s*'?var\(--yellow\)'?/,
  ];
  const offenders = [];
  for (const file of files) {
    const code = fs
      .readFileSync(file, 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
    for (const re of forbidden) {
      if (re.test(code)) offenders.push(`${path.relative(REPO, file)} matches ${re}`);
    }
  }
  assert.deepEqual(
    offenders,
    [],
    'a local severity/band map has reintroduced the pre-v2.87.0 ramp. Import from ' +
      'components/analysis/severityRamp.js instead of declaring a new one:\n' +
      offenders.join('\n')
  );
});

// ─────────────────────────────────────────────────────────────────────────
// 6. ⛔ THE SAME RAMP, WEARING A PROP INSTEAD OF A MAP.
// ─────────────────────────────────────────────────────────────────────────
//
// The scan above only ever matched the SHAPES the six stale copies had —
// `medium: 'info'`, `medium: var(--blue)`, `high: var(--yellow)`. A severity
// expressed as a JSX attribute instead of a map entry walked straight past it,
// which is exactly how components/analysis/ObjectsTab.js kept rendering its two
// findings tiles as `color="var(--yellow)"` and `color="var(--blue)"` for a full
// palette rewrite: amber beside blue, side by side, reading as a two-step ramp
// on findings that lib/engines/objectUsage.js assigns NO SEVERITY to at all.
//
// ⛔ SCOPED TO FINDING LABELS ON PURPOSE, and the scope is the whole design of
// this case. --blue and --yellow are legitimate accents for a NEUTRAL COUNT —
// "NAT Enabled", "Memory", "Total Rules", "Sessions" are all raw-hue tiles today
// and all of them are fine, because none of them is a risk level. What is
// forbidden is a raw ramp hue on a tile that counts a NAMED FINDING TYPE, where
// the colour is read as a severity whether or not one was measured. A blanket
// ban on the tokens would flag every metric tile in the app, everyone would
// learn to ignore the failure, and the one real offender would go back to being
// invisible.
//
// Two hues, two different reasons:
//   --blue    v2.87.0 pulled it off findings entirely: it sits one step from
//             --primary teal, and a finding drawn in the brand hue destroys the
//             separation the whole palette is built on.
//   --yellow  the raw graphics form. As the value TEXT of a tile it measures
//             3.64:1 on a card in light theme (StatCard maps the known raw hues
//             to their --tint-*-fg counterparts, but the semantic alias
//             --sev-med is what says what the colour MEANS).
//
// The fix for a hit is never to pick a different raw hue. It is either the
// semantic alias (--sev-med / --sev-high / ...) or, if the engine behind the
// tile does not produce a severity, one accent shared by every tile of that
// kind so no ranking is implied.

// A tile label naming a FINDING TYPE this product's engines actually emit,
// rather than a population or a metric.
const FINDING_TILE_LABEL =
  /^(unused|duplicate|shadow(ed)?|redundant|overly[\s-]?permissive|any[\s-]?any|reorder|risky|violations?|findings?)\b/i;

const RAW_RAMP_PROP = /\bcolor=(?:"(var\(--(?:blue|yellow)\))"|\{\s*'(var\(--(?:blue|yellow)\))'\s*\})/;

test('no tile counting a named FINDING TYPE wears a raw --blue or --yellow', () => {
  const offenders = [];
  for (const file of sourceFiles()) {
    const code = fs
      .readFileSync(file, 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/(^|[^:])\/\/[^\n]*/g, '$1');

    // Each <StatCard ... /> element, props-chunk only. Self-closing is the only
    // form this component is ever used in; the 900-char bound keeps a runaway
    // match from swallowing the rest of the file if that ever changes.
    const elements = code.match(/<StatCard\b[\s\S]{0,900}?\/>/g) || [];
    for (const el of elements) {
      const label = /\blabel="([^"]*)"/.exec(el);
      const hue = RAW_RAMP_PROP.exec(el);
      if (!label || !hue) continue;
      if (!FINDING_TILE_LABEL.test(label[1].trim())) continue;
      offenders.push(
        `${path.relative(REPO, file)}: <StatCard label="${label[1]}" color="${hue[1] || hue[2]}">`
      );
    }
  }
  assert.deepEqual(
    offenders,
    [],
    'a findings tile is painted with a raw ramp hue. Blue is off the findings ' +
      'vocabulary entirely (it sits one step from --primary teal); --yellow as a ' +
      'value colour measures 3.64:1 on a card. Use the semantic alias (--sev-med), ' +
      'or one shared accent for every tile of a kind whose engine produces no ' +
      'severity at all:\n' +
      offenders.join('\n')
  );
});
