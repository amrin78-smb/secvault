'use strict';
// Pins three defects found in the 2026-09-09 whole-app sweep, all of the same
// family: SecVault could not determine something, and said something
// affirmative instead.
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
