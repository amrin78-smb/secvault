'use strict';
// Pins the 2026-11-13 component-sweep fixes. Several are WCAG failures that
// were measured against a running instance, so the numbers in the comments are
// observations, not estimates.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const css = read('app', 'globals.css');

/** Every .js under components/ and app/, for the repo-wide scans. */
function sourceFiles() {
  const out = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.name.endsWith('.js')) out.push(full);
    }
  };
  walk(path.join(ROOT, 'components'));
  walk(path.join(ROOT, 'app'));
  return out;
}

describe('⛔ a shared primitive never silently swallows an unmapped key', () => {
  // Both StatusDot and Badge resolve their hue with `MAP[key] || MAP.<neutral>`,
  // so a key that is not in the map is indistinguishable from a deliberate
  // neutral. POLL_TONE.degraded passed 'yellow', which is not a StatusDot key,
  // so a MEASURED "Degraded" collector rendered the identical grey dot as
  // "no polls recorded at all" — this codebase's signature collapse, in the
  // cell that reports fleet reachability.

  function mapKeys(src, name) {
    const m = new RegExp(`const ${name} = \\{([\\s\\S]*?)\\n\\};`).exec(src);
    assert.ok(m, `${name} not found`);
    return [...m[1].matchAll(/^\s*([A-Za-z_][\w]*)\s*:/gm)].map((x) => x[1]);
  }

  it('⛔ every POLL_TONE colour is a real StatusDot key', () => {
    // The invariant is the PAIR, not either side: the producer's map and the
    // consumer's values must agree, and only a cross-check can say so.
    const statusKeys = mapKeys(read('components', 'ui', 'StatusDot.js'), 'STATUS_COLOR');
    const cells = read('components', 'devices', 'DevicePostureCells.js');
    const tone = /const POLL_TONE = \{([\s\S]*?)\n\};/.exec(cells);
    assert.ok(tone, 'POLL_TONE not found');
    const used = [...tone[1].matchAll(/color:\s*'([^']+)'/g)].map((m) => m[1]);
    assert.ok(used.length >= 5, `only ${used.length} POLL_TONE entries found`);
    for (const c of used) {
      assert.ok(
        statusKeys.includes(c),
        `POLL_TONE uses StatusDot status "${c}", which is not one of ${statusKeys.join('/')} — `
        + 'it falls back to grey, the same dot that means "never observed"',
      );
    }
  });

  it('⛔ "Degraded" and "Not observed" do not resolve to the same colour', () => {
    // The outcome, not the spelling: two different measured states must not
    // paint the same pixel.
    const statusSrc = read('components', 'ui', 'StatusDot.js');
    const m = /const STATUS_COLOR = \{([\s\S]*?)\n\};/.exec(statusSrc)[1];
    const colourFor = (key) => (new RegExp(`${key}:\\s*'([^']+)'`).exec(m) || [])[1];
    const cells = read('components', 'devices', 'DevicePostureCells.js');
    const tone = /const POLL_TONE = \{([\s\S]*?)\n\};/.exec(cells)[1];
    const toneColour = (band) => new RegExp(`${band}: \\{ color: '([^']+)'`).exec(tone)[1];
    assert.notEqual(
      colourFor(toneColour('degraded')),
      colourFor(toneColour('unknown')),
      'a measured Degraded renders the same dot as a device never polled',
    );
  });

  it('⛔ no call site anywhere passes a Badge colour the map lacks', () => {
    // The generalisable guard: `warn` reached three sites (TLS expiry under 30
    // days, and an MFA-required account) and rendered grey, so a certificate
    // 27 days from expiry was quieter than a healthy one.
    const badgeKeys = mapKeys(read('components', 'ui', 'Badge.js'), 'COLOR_CLASS');
    const bad = [];
    for (const file of sourceFiles()) {
      const src = fs.readFileSync(file, 'utf8');
      if (!/<Badge\b/.test(src)) continue;
      for (const m of src.matchAll(/<Badge[^>]*?\bcolor="([a-z]+)"/g)) {
        if (!badgeKeys.includes(m[1])) bad.push(`${path.relative(ROOT, file)}: color="${m[1]}"`);
      }
    }
    assert.deepEqual(
      bad, [],
      'Badge colours not in COLOR_CLASS (they silently render as muted grey):\n  '
      + bad.join('\n  '),
    );
  });
});

describe('⛔ a focus indicator a keyboard user cannot see is not an indicator', () => {
  it('⛔ the white shell ring is SCOPED to the shell', () => {
    // A bare `input[type='search']:focus-visible` matched FilterBar's search
    // box, which sits on --bg-primary: measured 1.05:1, against WCAG 1.4.11's
    // 3:1, on the primary search control of five pages. The !important meant
    // it also beat the correct ring.
    // ⛔ COMMENTS STRIPPED FIRST, and the check is that EVERY occurrence is
    // shell-scoped rather than that no bare one exists. A looser regex matched
    // the fixed selector itself (the space after `.sv-topbar`) and the comment
    // quoting the old one — so it failed on correct code, which is how a guard
    // gets relaxed until it stops guarding.
    const rules = css.replace(/\/\*[\s\S]*?\*\//g, '');
    const hits = [...rules.matchAll(/(\S*\s*)input\[type='search'\]:focus-visible/g)];
    assert.ok(hits.length > 0, "the input[type='search'] focus rule is gone entirely");
    for (const h of hits) {
      assert.match(
        h[1], /\.sv-topbar\s$/,
        "an UNSCOPED input[type='search']:focus-visible selector is back — it paints the "
        + "white shell ring on FilterBar's search box at 1.05:1",
      );
    }
  });

  it('⛔ --focus-ring carries no focus indicator — it is a 22%-alpha wash', () => {
    // rgba(10,143,163,0.22) composites to 1.30:1. CLAUDE.md already records
    // the number ("the login card's focus rings ... at 1.33:1"), and the
    // project fixed the login card and left these two.
    const offenders = [];
    for (const m of css.matchAll(/([^\n{}]*)\{[^}]*outline:[^;]*var\(--focus-ring\)[^;]*;/g)) {
      offenders.push(m[1].trim());
    }
    assert.deepEqual(
      offenders, [],
      'these selectors draw a focus outline in --focus-ring, which measures 1.30:1:\n  '
      + offenders.join('\n  '),
    );
  });

  it('the skip link and the reports rail both use --primary', () => {
    // Named, not just counted: the skip link is the FIRST tab stop on every
    // authenticated page, so a count alone could not say it was the one fixed.
    assert.match(css, /\.skip-link:focus \{[\s\S]{0,900}?outline: 2px solid var\(--primary\)/);
    assert.match(css, /\.rpt-rail-item:focus-visible \{ outline: 2px solid var\(--primary\)/);
  });
});

describe('⛔ --text-muted is not body text on the page canvas', () => {
  it('.page-subtitle uses --text-secondary', () => {
    // 4.27:1 on --bg-primary, under 4.5:1, on the 27 of 36 pages that pass a
    // subtitle. globals.css already recorded that exact number four lines
    // above, for .page-eyebrow, and only that selector was fixed.
    const m = /\.page-subtitle\s*\{[^}]*\}/.exec(css);
    assert.ok(m, '.page-subtitle rule not found');
    assert.ok(
      !/var\(--text-muted\)/.test(m[0]),
      '.page-subtitle is back on --text-muted (4.27:1 on --bg-primary)',
    );
    assert.match(m[0], /var\(--text-secondary\)/);
  });

  it('⛔ .page-eyebrow, the one that was already fixed, stays fixed', () => {
    const m = /\.page-eyebrow\s*\{[^}]*\}/.exec(css);
    assert.ok(m, '.page-eyebrow rule not found');
    assert.ok(!/var\(--text-muted\)/.test(m[0]));
  });
});

describe('⛔ the landing page has an h1 in EVERY branch, including a fresh install', () => {
  // The first-run early return sat thirty lines above the sr-only h1, so on
  // every freshly installed SecVault `/` had no h1 at all and its first
  // heading was FirstRun's <h2> — a skipped level with no outline root, in the
  // state every new customer sees first.
  const page = read('app', '(dashboard)', 'page.js');

  it('the first-run branch renders one', () => {
    const start = page.indexOf('if (firstRun) {');
    const end = page.indexOf('\n  }', start);
    assert.ok(start > 0, 'the first-run branch moved');
    assert.match(
      page.slice(start, end),
      /<h1 className="sr-only">Overview<\/h1>/,
      'the first-run early return still jumps over the page h1',
    );
  });

  it('⛔ and BOTH branches say the same thing', () => {
    // A page that announces itself by two different names depending on
    // whether a device exists is its own defect.
    const titles = [...page.matchAll(/<h1 className="sr-only">([^<]+)<\/h1>/g)].map((m) => m[1]);
    assert.equal(titles.length, 2, `expected an h1 in both branches, found ${titles.length}`);
    assert.equal(titles[0], titles[1]);
    assert.equal(titles[0], 'Overview');
  });
});
