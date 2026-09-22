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
    const i = src.search(/if\s*\(\s*!localHash\s*\)/);
    assert.ok(i > -1, 'the guard must exist');
    const branch = src.slice(i, i + 700);
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
    const at = src.indexOf(`'${pkg.version}': [`);
    assert.ok(at > -1);
    // From after the opening bracket, so the key line itself is not counted.
    // ⛔ THE BLOCK ENDS AT THE CLOSING BRACKET ON ITS OWN LINE, not at the
    // first `],` in the text. A bullet is allowed to QUOTE one — v2.170.0's
    // notes quote the config path `devices.entry.vsys.entry.tag.entry[17], ...`
    // that release exists to remove — and matching inside a string truncated
    // the block to its first bullet and failed a perfectly good entry. The
    // indentation is what distinguishes structure from content here.
    const open = src.indexOf('[', at) + 1;
    const close = src.indexOf('\n  ],', open);
    assert.ok(close > open, 'could not find the closing bracket for this version block');
    const block = src.slice(open, close);
    const bullets = block.match(/^\s*['"]/gm) || [];
    assert.ok(bullets.length >= 3 && bullets.length <= 6, `${bullets.length} bullets`);
    assert.ok(!/TODO|TBD|placeholder/i.test(block), 'a placeholder is worse than an omission');
  });
});
