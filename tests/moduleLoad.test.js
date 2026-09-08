// tests/moduleLoad.test.js
//
// ⛔ WHY THIS EXISTS. On 2026-09-09 a syntax error shipped in
// lib/syslog/trafficStats.js — a BACKTICK inside a SQL comment, inside a
// template literal, which silently terminated the string. Three separate gates
// missed it:
//
//   node --check   was chained after a script that exited non-zero, so the
//                  check never ran (an && chain is not a test suite)
//   npm test       no test imported the file
//   npm run build  the failure is inside a server-only module the build does
//                  not evaluate
//
// The file was broken in a released commit. This test closes that gap the
// cheapest possible way: REQUIRE every server-side module. A syntax error, a
// bad import path, or a throw at module scope all fail here, and it costs
// milliseconds.
//
// ⛔ This is a LOAD test, not a behaviour test. It proves the module parses and
// its top level runs — nothing about whether it is correct. Do not let its
// presence discourage a real test for the engine itself.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const REPO = path.join(__dirname, '..');

// Server-side only. app/ and components/ are JSX, which `require` cannot parse
// and which `npm run build` already covers.
const DIRS = ['lib', 'lib/syslog', 'lib/engines', 'lib/adapters', 'lib/feeds', 'services'];

function jsFilesIn(dir) {
  const full = path.join(REPO, dir);
  if (!fs.existsSync(full)) return [];
  return fs
    .readdirSync(full)
    .filter((f) => f.endsWith('.js'))
    .map((f) => path.join(dir, f).split(path.sep).join('/'));
}

// services/*.js start listeners / timers at module scope, so they are checked
// for PARSE validity only rather than being required.
const PARSE_ONLY = new Set(['services/collector.js', 'services/engine-worker.js']);

describe('every server-side module loads', () => {
  const files = DIRS.flatMap(jsFilesIn);

  it('found a plausible number of modules to check', () => {
    // Guards against the globbing silently finding nothing and the whole
    // suite passing vacuously — the exact failure shape this file exists to
    // prevent, applied to itself.
    assert.ok(files.length > 30, `expected >30 modules, found ${files.length}`);
  });

  for (const rel of files) {
    if (PARSE_ONLY.has(rel)) {
      it(`${rel} parses`, () => {
        const src = fs.readFileSync(path.join(REPO, rel), 'utf8');
        // new Function throws a SyntaxError on a parse failure without
        // executing anything — enough to catch an unterminated template.
        assert.doesNotThrow(() => new Function(src), SyntaxError);
      });
      continue;
    }
    it(`${rel} requires cleanly`, () => {
      assert.doesNotThrow(() => require(path.join(REPO, rel)));
    });
  }
});
