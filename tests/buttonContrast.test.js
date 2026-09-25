// tests/buttonContrast.test.js
//
// Every button variant, both themes, both resting and hover, measured against
// its own ink by the WCAG 2.x formula.
//
// ⛔ WHY THIS EXISTS. .btn-primary was `background: var(--primary); color: #fff`
// for the whole life of the dark theme. In dark theme --primary is #22C1D6 and
// --primary-dark is #4FD8E8 (hover goes LIGHTER on a dark ground, correctly), so
// white on them measured 2.17:1 and 1.70:1 — against WCAG 1.4.3's 4.5:1 floor,
// on roughly a hundred buttons, i.e. on every primary action in the product.
// .btn-danger:hover had the identical defect for the identical reason: its
// hover fill is the raw --red, which in dark theme is the light salmon #FF6B70,
// and white on it measured 2.77:1. Nothing caught either one.
//
// ⛔ AND NOTHING COULD HAVE. This is the design-system analogue of the failure
// this codebase names most often: it builds, it renders, the button is plainly
// there and plainly clickable, and the label is simply hard to read. There is
// no crash, no console warning and no wrong number — only a legible-looking
// screenshot and an operator who squints. tests/designSystemRamp.test.js
// already pins every --tint-*-fg pair at 4.5:1 for exactly this reason; it
// simply never looked at a SOLID fill, because no token named one. The fix
// (--btn-primary-fg / --btn-danger-fg) created the tokens, and this file is
// what makes them arithmetic rather than a comment.
//
// ⛔ THE ARITHMETIC IS IN THE TEST, NOT A TABLE OF EXPECTED NUMBERS. Every
// ratio below is recomputed from app/globals.css's own token values on each
// run. A future nudge to --primary, --red, --primary-dark or either ink fails
// the build with the measured figure in the message, instead of silently
// dropping a hundred buttons under the floor. Pinning hardcoded ratios would
// only prove the constants still equal themselves.

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');
const CSS_PATH = path.join(REPO, 'app/globals.css');

// WCAG 1.4.3 Level AA, normal-size text.
const AA_TEXT = 4.5;

// ── WCAG 2.x relative luminance / contrast ratio ─────────────────────────
// Same formula as tests/designSystemRamp.test.js. Deliberately duplicated
// rather than shared: these are eight lines of published spec that will never
// change, and a helper module imported by two test files is a thing a future
// edit can quietly break for both at once.
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
function composite(hex, alpha, bgHex) {
  const f = rgb(hex);
  const b = rgb(bgHex);
  return '#' + f.map((v, i) => Math.round(v * alpha + b[i] * (1 - alpha)))
    .map((v) => v.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// ── Token extraction ─────────────────────────────────────────────────────
// ⛔ COMMENTS ARE STRIPPED FIRST, AND THAT IS NOT HYGIENE — IT IS LOAD-BEARING.
// globals.css contains, inside a comment, the literal text
//   "--primary. Now the SAME value as --primary: since --primary moved off ..."
// and a bare `(--[a-z-]+):\s*([^;]+);` regex reads that as a REDEFINITION of
// --primary. The first draft of this file did exactly that and measured
// .btn-primary against a sentence of English prose, which produced NaN:1 — a
// failure that happened to be loud. Had the comment held a plausible hex
// instead, every ratio here would have been confidently wrong, which is the
// failed-read-as-a-fact bug wearing a stylesheet.
const RAW_CSS = fs.readFileSync(CSS_PATH, 'utf8');
const CSS = RAW_CSS.replace(/\/\*[\s\S]*?\*\//g, '');

const HEX = /^#[0-9a-fA-F]{3,8}$/;
const RGBA = /^rgba\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*([\d.]+)\s*\)$/i;

function tokens() {
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
  // A token absent from the dark block keeps its light value — exactly how the
  // cascade resolves it.
  const dark = { ...light, ...grab(CSS.slice(darkAt, darkEnd)) };
  return { light, dark };
}

// Resolves a token to a measurable hex, following var() indirection and
// compositing an rgba() wash over the ground it actually sits on.
function resolve(t, name, ground) {
  let v = t[name];
  let guard = 0;
  while (v && /^var\(/.test(v) && guard++ < 10) v = t[v.replace(/^var\(\s*|\s*\)$/g, '')];
  assert.ok(v, `token ${name} is not defined`);
  if (HEX.test(v)) return v.toUpperCase();
  const m = RGBA.exec(v);
  assert.ok(m, `token ${name} = "${v}" is not a hex or rgba() and cannot be measured`);
  return composite(
    '#' + [m[1], m[2], m[3]].map((x) => Number(x).toString(16).padStart(2, '0')).join(''),
    Number(m[4]),
    ground
  );
}

// ── The variants under test ──────────────────────────────────────────────
// One row per (variant, state). `fill` and `ink` name TOKENS, resolved per
// theme, so this table says what the CSS says rather than restating its values.
function variants(t) {
  const card = resolve(t, '--bg-card', '#FFFFFF');
  const page = resolve(t, '--bg-primary', '#FFFFFF');
  return [
    // .btn / .btn-secondary sit on the page; their fills ARE surfaces.
    ['.btn            rest',  resolve(t, '--bg-card', page),      resolve(t, '--text-primary', card)],
    ['.btn            hover', resolve(t, '--bg-primary', page),   resolve(t, '--text-primary', page)],
    ['.btn-primary    rest',  resolve(t, '--primary', card),      resolve(t, '--btn-primary-fg', card)],
    ['.btn-primary    hover', resolve(t, '--primary-dark', card), resolve(t, '--btn-primary-fg', card)],
    ['.btn-secondary  rest',  resolve(t, '--bg-card', page),      resolve(t, '--text-secondary', card)],
    ['.btn-secondary  hover', resolve(t, '--bg-primary', page),   resolve(t, '--text-secondary', page)],
    ['.btn-navy       rest',  resolve(t, '--navy', page),         '#FFFFFF'],
    ['.btn-navy       hover', resolve(t, '--navy-light', page),   '#FFFFFF'],
    ['.btn-danger     rest',  resolve(t, '--tint-danger', card),  resolve(t, '--tint-danger-fg', card)],
    ['.btn-danger     hover', resolve(t, '--red', card),          resolve(t, '--btn-danger-fg', card)],
  ];
}

// ─────────────────────────────────────────────────────────────────────────
// 1. The floor. Every variant, every state, both themes.
// ─────────────────────────────────────────────────────────────────────────

test('every button variant clears 4.5:1 at rest AND on hover, in BOTH themes', () => {
  const { light, dark } = tokens();
  const failures = [];
  for (const [theme, t] of [['light', light], ['dark', dark]]) {
    for (const [name, fill, ink] of variants(t)) {
      const ratio = contrast(ink, fill);
      if (ratio < AA_TEXT) {
        failures.push(
          `${theme.padEnd(5)} ${name}  ink ${ink} on fill ${fill} = ${ratio.toFixed(2)}:1`
        );
      }
    }
  }
  assert.deepEqual(
    failures,
    [],
    'a button variant has dropped below WCAG 1.4.3’s 4.5:1 for normal text. This is ' +
      'the defect --btn-primary-fg and --btn-danger-fg were introduced to fix: white ' +
      'on dark theme’s --primary measured 2.17:1 and on its --red 2.77:1, and nothing ' +
      'crashed, rendered wrong or looked broken — the labels were simply hard to read ' +
      'on every primary and destructive action in the product.\n' +
      failures.join('\n')
  );
});

// ⛔ THE HOVER STATE IS HALF THE TEST AND IS THE HALF THAT WAS WORSE.
// In dark theme --primary-dark is LIGHTER than --primary (#4FD8E8 vs #22C1D6),
// which is correct on a dark ground and means the hover state was the LOWER
// contrast of the two: 1.70:1 against the resting 2.17:1. A guard that measured
// only the resting fill would have called the worse state clean, so the pairing
// is asserted rather than left to the table above.
test('hover is never less readable than rest by more than a hair', () => {
  const { light, dark } = tokens();
  for (const [theme, t] of [['light', light], ['dark', dark]]) {
    const card = resolve(t, '--bg-card', '#FFFFFF');
    const ink = resolve(t, '--btn-primary-fg', card);
    const rest = contrast(ink, resolve(t, '--primary', card));
    const hover = contrast(ink, resolve(t, '--primary-dark', card));
    assert.ok(
      hover >= AA_TEXT,
      `.btn-primary:hover is ${hover.toFixed(2)}:1 in ${theme} theme (rest is ` +
        `${rest.toFixed(2)}:1). In dark theme --primary-dark goes LIGHTER, so hover is ` +
        'the lower-contrast state and the one a rest-only check would miss.'
    );
  }
});

// ─────────────────────────────────────────────────────────────────────────
// 2. ⛔ THE FIX MUST NOT HAVE BEEN "DARKEN --primary".
// ─────────────────────────────────────────────────────────────────────────

test('--primary is untouched: it still drives links, focus rings and the nav chip', () => {
  const { light, dark } = tokens();
  // The cheap way to make white legible on the dark-theme button is to darken
  // --primary. That would fix ~100 buttons and silently repaint every link,
  // focus ring, active nav chip and accent in the product — and would undo the
  // v2.87.0 decision that the dark theme's brand hue is re-picked BRIGHT for a
  // near-black ground rather than reused from light. These two values are the
  // ones globals.css documents; if a change is genuinely wanted, change them
  // deliberately and update this test, do not let a contrast fix drag them.
  assert.equal(light['--primary'], '#098294', '--primary (light) moved');
  assert.equal(dark['--primary'], '#22C1D6', '--primary (dark) moved');
  // And the dark hover must stay LIGHTER than the dark rest — that is what
  // makes it a hover on a dark ground at all.
  assert.ok(
    luminance(dark['--primary-dark']) > luminance(dark['--primary']),
    'dark --primary-dark is no longer lighter than --primary; on a dark ground the ' +
      'hover state is supposed to lift, not sink'
  );
});

test('the ink flips per theme and the fill does not — the --tint-*-fg contract', () => {
  const { light, dark } = tokens();
  for (const name of ['--btn-primary-fg', '--btn-danger-fg']) {
    assert.ok(HEX.test(light[name]), `${name} should be a literal hex in light theme`);
    assert.ok(HEX.test(dark[name]), `${name} should be a literal hex in dark theme`);
    assert.notEqual(
      light[name],
      dark[name],
      `${name} is the same in both themes. Its whole purpose is to flip: the fills it ` +
        'sits on (--primary, --red) are DARK in light theme and LIGHT in dark theme, so ' +
        'a single fixed ink cannot be readable on both.'
    );
  }
  // Light theme: dark fill, light ink. Dark theme: light fill, dark ink.
  assert.ok(luminance(light['--btn-primary-fg']) > luminance(light['--primary']));
  assert.ok(luminance(dark['--btn-primary-fg']) < luminance(dark['--primary']));
});

// ─────────────────────────────────────────────────────────────────────────
// 3. ⛔ HIERARCHY. Contrast must not have been bought by flattening.
// ─────────────────────────────────────────────────────────────────────────
//
// The other cheap fix is to stop filling the primary button at all — make it
// an outline or a tint like .btn-secondary. Every ratio above would pass and
// the product would lose the thing that tells an operator which button is the
// action. On a firewall-management console "which button commits this change"
// is not decoration.

test('primary, secondary, navy and danger remain four DISTINGUISHABLE fills', () => {
  const { light, dark } = tokens();
  for (const [theme, t] of [['light', light], ['dark', dark]]) {
    const card = resolve(t, '--bg-card', '#FFFFFF');
    const page = resolve(t, '--bg-primary', '#FFFFFF');
    const fills = {
      primary: resolve(t, '--primary', card),
      secondary: resolve(t, '--bg-card', page),
      navy: resolve(t, '--navy', page),
      danger: resolve(t, '--tint-danger', card),
    };
    const seen = new Map();
    for (const [name, hex] of Object.entries(fills)) {
      assert.ok(
        !seen.has(hex),
        `${theme}: .btn-${name} and .btn-${seen.get(hex)} now have the SAME fill ` +
          `(${hex}). Contrast was bought by flattening the hierarchy — an operator can ` +
          'no longer tell which button is the action.'
      );
      seen.set(hex, name);
    }
    // The primary fill must remain a SOLID, high-emphasis fill: clearly
    // separated from the card it sits on, not a wash.
    const vsCard = contrast(fills.primary, card);
    assert.ok(
      vsCard >= 3,
      `${theme}: .btn-primary's fill is only ${vsCard.toFixed(2)}:1 against the card. ` +
        'It has stopped reading as a filled, primary-emphasis button (WCAG 1.4.11 ' +
        'wants 3:1 for a UI component boundary in any case).'
    );
  }
});

// ─────────────────────────────────────────────────────────────────────────
// 4. ⛔ THE RULES ACTUALLY USE THE TOKENS.
// ─────────────────────────────────────────────────────────────────────────
//
// Everything above measures TOKENS. A perfectly-contrasting token pair that no
// rule references proves nothing — that is the guard-that-cannot-fire pattern,
// and it is how a fix passes its own test while the screen is unchanged. These
// two cases read the declarations themselves.

test('.btn-primary and .btn-danger:hover consume the ink tokens, not a literal', () => {
  const rule = (selector) => {
    const re = new RegExp(`^\\s*\\${selector}\\s*\\{([^}]*)\\}`, 'm');
    const m = re.exec(CSS);
    assert.ok(m, `expected a "${selector} { ... }" rule in globals.css`);
    return m[1];
  };

  const primary = rule('.btn-primary');
  assert.match(
    primary,
    /color:\s*var\(--btn-primary-fg\)/,
    '.btn-primary no longer resolves its colour through --btn-primary-fg. If this ' +
      'reverted to `color: #fff`, dark theme is back to 2.17:1 on every primary button.'
  );

  const dangerHover = rule('.btn-danger:hover');
  assert.match(
    dangerHover,
    /color:\s*var\(--btn-danger-fg\)/,
    '.btn-danger:hover no longer resolves its colour through --btn-danger-fg. Its fill ' +
      'is the raw --red, which is #FF6B70 in dark theme — white on it is 2.77:1.'
  );

  // The fills are deliberately unchanged; if one of these ever stops being the
  // brand/danger token the measurements above quietly start testing something
  // other than the shipped button.
  assert.match(primary, /background:\s*var\(--primary\)/, '.btn-primary fill changed');
  assert.match(dangerHover, /background:\s*var\(--red\)/, '.btn-danger:hover fill changed');
});

// ⛔ .btn-navy IS THE EXCEPTION AND MUST STAY ONE. --navy is dark in BOTH themes
// (it is the shell colour), so its ink does NOT flip — exactly like --shell-fg,
// and for exactly the reason CLAUDE.md gives: a flipping fg on a non-flipping
// dark ground is a dark colour on a dark bar, i.e. invisible. Handing .btn-navy
// a --btn-*-fg token would look like consistency and would break it in light
// theme only, which is the half a dark-theme-focused fix is least likely to
// check.
test('.btn-navy keeps a fixed white ink, because its fill does not flip', () => {
  const { light, dark } = tokens();
  const m = /^\s*\.btn-navy\s*\{([^}]*)\}/m.exec(CSS);
  assert.ok(m, 'expected a ".btn-navy { ... }" rule');
  assert.match(
    m[1],
    /color:\s*#fff\b/i,
    '.btn-navy has been given a flipping ink token. --navy is dark in BOTH themes, so ' +
      'in light theme that resolves to a dark glyph on a dark fill — an invisible label. ' +
      'This is the --shell-fg rule: a fixed ground takes a fixed foreground.'
  );
  for (const [theme, t] of [['light', light], ['dark', dark]]) {
    const page = resolve(t, '--bg-primary', '#FFFFFF');
    for (const token of ['--navy', '--navy-light']) {
      const ratio = contrast('#FFFFFF', resolve(t, token, page));
      assert.ok(ratio >= AA_TEXT, `white on ${token} is ${ratio.toFixed(2)}:1 in ${theme}`);
    }
  }
});

// ⛔ .login-submit IS A SECOND, DELIBERATE EXCEPTION. The login page is a dark
// surface in BOTH themes, so nothing on it may resolve through a token that
// flips — .btn-primary now does. It pins its own fill and its own white ink.
// This case exists so the pin is measured rather than assumed, and so that a
// future session tidying "the last hardcoded button colour" has to read a
// failure explaining why it is not one.
test('.login-submit stays pinned to a non-flipping fill and clears the floor', () => {
  const m = /^\s*\.login-submit\s*\{([^}]*)\}/m.exec(CSS);
  assert.ok(m, 'expected a ".login-submit { ... }" rule');
  const body = m[1];
  const bg = /background:\s*(#[0-9a-fA-F]{3,8})/.exec(body);
  assert.ok(
    bg,
    '.login-submit no longer pins a literal background. The login card is dark in BOTH ' +
      'themes; resolving through --primary would swing the button on the theme toggle ' +
      'while the card behind it did not move.'
  );
  assert.match(body, /color:\s*#fff\b/i, '.login-submit should keep its fixed white ink');
  const ratio = contrast('#FFFFFF', bg[1].toUpperCase());
  assert.ok(
    ratio >= AA_TEXT,
    `.login-submit is ${ratio.toFixed(2)}:1 (white on ${bg[1]}), below 4.5:1`
  );
});

// ─────────────────────────────────────────────────────────────────────────
// 5. ⛔ THE EXTRACTOR ITSELF.
// ─────────────────────────────────────────────────────────────────────────
//
// Every number in this file depends on reading the right values out of the CSS.
// The comment-stripping step above is the difference between measuring a colour
// and measuring a sentence, and it is invisible if it silently stops working —
// so it gets its own case rather than being trusted.

test('token extraction ignores token-shaped text inside comments', () => {
  const { light } = tokens();
  assert.ok(
    /--primary:\s*since/.test(RAW_CSS),
    'the comment this guard exists for has been reworded. That is fine — but keep the ' +
      'comment-stripping step: any prose of the form "--token: some words" is read by a ' +
      'bare CSS token regex as a redefinition.'
  );
  assert.equal(
    light['--primary'],
    '#098294',
    '--primary resolved to something other than its declared value, which means the ' +
      'comment-stripping step is no longer working and every ratio in this file is being ' +
      'measured against prose.'
  );
});
