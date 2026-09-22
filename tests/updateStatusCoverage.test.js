'use strict';
// Pins defects found in the whole-app sweeps, all of the same family: SecVault
// could not determine something, and said something affirmative instead. The
// last block is a different shape -- it enforces a documented policy that
// nothing but prose was enforcing, and that eight consecutive releases missed.
//
// These are SOURCE-LEVEL pins. The route and the config are not unit-testable
// without a Next server and a git repo, but each defect was a single decision
// expressed in one place, and each is worth failing a build over.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
// Comments in this repo quote the anti-patterns they forbid, so every
// assertion runs against comment-stripped source.
const stripComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

describe('update-status: an unreadable local commit is not "up to date"', () => {
  const src = stripComments(read('app/api/system/update-status/route.js'));

  it('takes an explicit branch when the local hash cannot be read', () => {
    // ⛔ The bug: `update_available = !!localHash && ...` returned the FULL
    // SUCCESS SHAPE with no error key, so Settings rendered a green
    // "UP TO DATE" forever on a server that could not read its own git HEAD.
    assert.match(src, /if\s*\(\s*!localHash\s*\)/);
  });

  it('never reports up_to_date true on that branch', () => {
    // ⛔ THE BRANCH IS BRACE-MATCHED, NOT A FIXED 700-CHARACTER WINDOW. A
    // window reads whatever follows the block once the block is shorter than
    // it — so `up_to_date: true` in the NEXT branch would fail this test, and
    // (the direction that matters) a guard that grew past 700 characters would
    // have its own `up_to_date: null` read out of the assertion's reach while
    // the surrounding code supplied a passing one.
    const i = src.search(/if\s*\(\s*!localHash\s*\)/);
    assert.ok(i > -1, 'the guard must exist');
    const branch = braceBlockFrom(src, i);
    assert.ok(branch, 'the guard must have a block');
    assert.match(branch, /up_to_date:\s*null/, 'unknown must be null, not true');
    assert.match(branch, /error:/, 'the branch must carry an error the UI can gate on');
    assert.ok(!/up_to_date:\s*true/.test(branch), 'must not claim up to date');
  });

  it('no longer conditions update_available on the local hash being truthy', () => {
    // With the guard above, `!!localHash &&` is dead — and leaving it would
    // re-create the silent fallthrough if the guard were ever removed.
    assert.ok(!/update_available\s*=\s*!!localHash/.test(src));
  });
});

describe('logs/search: page must reach the query builder', () => {
  const src = read('app/api/logs/search/route.js');

  it('whitelists the page parameter', () => {
    // ⛔ Without it clampPage(undefined) is always 1 and OFFSET is always 0,
    // while the response still says hasMore: true — so a consumer asks for
    // page 2 and gets page 1 back relabelled.
    assert.match(stripComments(src), /'page'/);
  });
});

describe('the image optimizer is disabled, not merely routed through middleware', () => {
  it('next.config disables it outright', () => {
    // ⛔ The previous control was a middleware matcher whose comment certified
    // it as "verified safe". Measured live: /_next/image returned the
    // optimizer's OWN 400 in 25-117ms, so middleware never ran for it.
    assert.match(stripComments(read('next.config.js')), /images:\s*\{\s*unoptimized:\s*true\s*\}/);
  });

  it('next/image is genuinely unused, which is what makes disabling it free', () => {
    // If this ever fails, `unoptimized: true` needs re-deciding on its merits
    // rather than being deleted as an obstacle.
    const hits = [];
    const walk = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) walk(p);
        else if (e.name.endsWith('.js') && /from\s+['"]next\/image['"]/.test(fs.readFileSync(p, 'utf8'))) {
          hits.push(p);
        }
      }
    };
    walk(path.join(ROOT, 'app'));
    walk(path.join(ROOT, 'components'));
    assert.deepEqual(hits, []);
  });
});

describe('every shipped version carries release notes', () => {
  // ⛔ THE ONLY PLACE RELEASE NOTES EXIST IS THIS ROUTE -- there is no
  // CHANGELOG.md -- and the in-app updater shows them to decide whether to
  // update. Eight consecutive versions shipped without an entry, and nothing
  // failed: the object simply had no key, the UI rendered no bullets, and the
  // gap was invisible from inside the product. A policy enforced only by a
  // sentence in a documentation file is not enforced.
  const pkg = JSON.parse(read('package.json'));
  const src = read('app/api/system/update-status/route.js');
  const keys = new Set([...src.matchAll(/^\s*'(\d+\.\d+\.\d+)':/gm)].map((m) => m[1]));

  it('found the notes object at all', () => {
    assert.ok(keys.size > 10, `expected many versions, found ${keys.size}`);
  });

  it(`the current version (${pkg.version}) has an entry`, () => {
    assert.ok(
      keys.has(pkg.version),
      `package.json is ${pkg.version} but app/api/system/update-status/route.js has no release notes for it`
    );
  });

  it('the entry is 3-6 bullets of real prose, not a placeholder', () => {
    // ⛔ THE FINDER IS STRING-AWARE AND BRACKET-MATCHED, because the previous
    // one failed VALID entries in three separate ways — each of which reads to
    // whoever hits it as "my release notes are wrong" when they are not:
    //   · it counted every LINE beginning with a quote as a bullet, so five
    //     real bullets with two wrapped continuation lines counted as seven
    //     and failed the 3-6 range;
    //   · it ended the block at `\n  ],`, so the LAST version block (written
    //     without a trailing comma) was never found at all — indexOf returned
    //     -1 and the slice ran to end of file;
    //   · any re-indentation of the object did the same.
    // A bullet is also allowed to QUOTE a bracket — v2.170.0's notes quote the
    // config path `...tag.entry[17], ...` that release exists to remove — which
    // is why the matcher skips string literals rather than counting brackets
    // blind.
    const body = arrayLiteralAfterKey(src, pkg.version);
    assert.ok(body !== null, `could not find the release-notes array for ${pkg.version}`);
    const bullets = elementsOf(body);
    assert.ok(bullets.length >= 3 && bullets.length <= 6, `${bullets.length} bullets`);
    for (const b of bullets) {
      assert.match(b, /^['"`]/, `every bullet must be a string literal, got: ${b.slice(0, 40)}`);
    }
    assert.ok(!/TODO|TBD|placeholder/i.test(body), 'a placeholder is worse than an omission');
  });
});

describe('⛔ the finder above, on the shapes that broke the last one', () => {
  // A test whose helper silently finds nothing is a test that passes for the
  // wrong reason, so the helper is driven directly with the three shapes that
  // defeated its predecessor — plus one it must still refuse.
  const sample = `const releaseNotes = {
  '2.170.0': [
    'A bullet that quotes a bracket: devices.entry.tag.entry[17], and keeps going '
      + 'onto a continuation line that starts with a quote.',
    'Second bullet.',
    'Third bullet.',
  ],
      '2.171.0': [
        'Re-indented, and the last entry in the object, with no trailing comma.',
        'Second.',
        'Third.',
      ]
};`;

  it('a wrapped continuation line is part of its bullet, not a bullet of its own', () => {
    const bullets = elementsOf(arrayLiteralAfterKey(sample, '2.170.0'));
    assert.equal(bullets.length, 3);
    assert.match(bullets[0], /entry\[17\]/, 'the quoted bracket must not have ended the block');
  });

  it('a re-indented last block with no trailing comma is still found', () => {
    const body = arrayLiteralAfterKey(sample, '2.171.0');
    assert.ok(body !== null, 'the last block in the object must be findable');
    assert.equal(elementsOf(body).length, 3);
  });

  it('and a version that is not there is reported as absent, not as empty', () => {
    assert.equal(arrayLiteralAfterKey(sample, '9.9.9'), null);
  });
});

// ─── source-shape helpers ───────────────────────────────────────────────────
//
// These read JavaScript source, so they skip string literals: every one of the
// defects above came from a regex reading structure out of prose.

/** The index just past the string literal starting at `i`. */
function endOfString(src, i) {
  const quote = src[i];
  let j = i + 1;
  while (j < src.length) {
    if (src[j] === '\\') { j += 2; continue; }
    if (src[j] === quote) return j + 1;
    j += 1;
  }
  return src.length;
}

/** The `{ … }` block that follows `from`, brace-matched and string-aware. */
function braceBlockFrom(src, from) {
  const open = src.indexOf('{', from);
  if (open === -1) return null;
  let depth = 0;
  let i = open;
  while (i < src.length) {
    const ch = src[i];
    if (ch === "'" || ch === '"' || ch === '`') { i = endOfString(src, i); continue; }
    if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) return src.slice(open + 1, i);
    }
    i += 1;
  }
  return null;
}

/** The body of the array literal assigned to `key`, or null if there is none. */
function arrayLiteralAfterKey(src, key) {
  const escaped = String(key).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp('(^|[\\s{,])[\'"`]' + escaped + '[\'"`]\\s*:\\s*\\[');
  const m = re.exec(src);
  if (!m) return null;
  const open = src.indexOf('[', m.index);
  let depth = 0;
  let i = open;
  while (i < src.length) {
    const ch = src[i];
    if (ch === "'" || ch === '"' || ch === '`') { i = endOfString(src, i); continue; }
    if (ch === '[' || ch === '(' || ch === '{') depth += 1;
    else if (ch === ']' || ch === ')' || ch === '}') {
      depth -= 1;
      if (depth === 0) return src.slice(open + 1, i);
    }
    i += 1;
  }
  return null;
}

/** Top-level, comma-separated elements of an array-literal body. */
function elementsOf(body) {
  const parts = [];
  let cur = '';
  let depth = 0;
  let i = 0;
  while (i < body.length) {
    const ch = body[i];
    if (ch === "'" || ch === '"' || ch === '`') {
      const end = endOfString(body, i);
      cur += body.slice(i, end);
      i = end;
      continue;
    }
    if (ch === '[' || ch === '(' || ch === '{') depth += 1;
    else if (ch === ']' || ch === ')' || ch === '}') depth -= 1;
    if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; i += 1; continue; }
    cur += ch;
    i += 1;
  }
  parts.push(cur);
  return parts.map((p) => p.trim()).filter((p) => p !== '');
}
