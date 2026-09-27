'use strict';

// tests/stripOrder.test.js
//
// ⛔ THE GUARD ON THE GUARDS. 44 test files in this repo scan source text,
// because several of its rules can only be checked that way. Every one of them
// must strip comments first — and the ORDER of the two strippers decides whether
// the scan sees the file or a mutilated fraction of it.
//
// Measured 2026-09-27: eleven test files stripped BLOCK comments before LINE
// comments, which lets a `/*` living inside a `//` comment open a phantom block
// that runs to the next real `*/`. `lib/feeds/paloalto.js:407` contains the
// phrase `feeds/*.js` in a line comment, and the phantom block ate 216 lines.
// Across 17 source files the wrong order discards 52,339 characters of REAL CODE.
//
// No security verdict flipped at the time, which is exactly why this file
// exists: a guard that is inert today and silently wrong is the defect this
// codebase names more often than any other.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { stripComments } = require('./stripComments');

const ROOT = path.join(__dirname, '..');

describe('⛔ the shared stripper survives the trigger that broke eleven tests', () => {
  // ⛔ A REAL FILE, NOT A FIXTURE. A synthetic string would pass forever while
  // the repo drifted; this asserts the property against the source that actually
  // demonstrated the bug.
  const PALOALTO = path.join(ROOT, 'lib', 'feeds', 'paloalto.js');

  it('the trigger still exists in the repo (or this test proves nothing)', () => {
    const raw = fs.readFileSync(PALOALTO, 'utf8');
    const triggerLine = raw.split('\n').find((l) => {
      const c = l.indexOf('//');
      return c > -1 && l.slice(c).includes('/*');
    });
    assert.ok(triggerLine, 'paloalto.js should still contain "/*" inside a line comment; '
      + 'if it no longer does, point this test at another file that does — do NOT delete it');
  });

  it('⛔ the shared stripper keeps the code the wrong order ate', () => {
    const raw = fs.readFileSync(PALOALTO, 'utf8');
    const good = stripComments(raw);
    // The wrong order, reproduced here so the difference is asserted, not asserted-about.
    const bad = raw
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/(^|[^:])\/\/.*$/gm, '$1');
    assert.ok(good.length > bad.length + 2000,
      `the wrong order should lose thousands of characters; good=${good.length} bad=${bad.length}`);
    // And specifically: real code that only the correct order retains.
    assert.match(good, /hasUsableFixBoundarySql/,
      'the fix-boundary guard must survive stripping');
    assert.ok(!/hasUsableFixBoundarySql\(/.test(bad.slice(bad.indexOf('ON CONFLICT'))),
      'the wrong order loses it, which is the bug being pinned');
  });

  it('it still removes what a scan must not see', () => {
    const src = [
      '// this comment says misconfigured and =cmd|calc',
      'const a = 1;',
      '/* a block comment saying device_id */',
      'const b = 2;',
      'const url = "https://example.com/x"; // trailing',
    ].join('\n');
    const out = stripComments(src);
    assert.ok(!out.includes('misconfigured'), 'line comments go');
    assert.ok(!out.includes('a block comment'), 'block comments go');
    assert.match(out, /const a = 1;/);
    assert.match(out, /const b = 2;/);
    assert.match(out, /https:\/\/example\.com\/x/, 'a URL is not a comment');
  });

  it('the SQL option strips embedded -- comments only when asked', () => {
    const src = 'const q = `SELECT 1\n  -- a sql comment saying device_id\n  FROM t`;';
    assert.match(stripComments(src), /a sql comment/, 'not stripped by default');
    assert.ok(!stripComments(src, { sql: true }).includes('a sql comment'));
  });

  it('tolerates junk', () => {
    for (const bad of [null, undefined, '', 42]) {
      assert.equal(typeof stripComments(bad), 'string');
    }
  });
});

describe('⛔ no test file may use the block-before-line order', () => {
  // ⛔ THE ASSERTION THAT FORCES MIGRATION. A test rolling its own stripper is
  // fine; rolling it in the order that silently eats code is not.
  //
  // ⛔ THESE ARE THE LITERAL CHARACTERS AS THEY APPEAR IN SOURCE, and the first
  // draft of this test got them wrong — it searched for `/\*[\s\S]*?\*/` while
  // the files contain `\/\*[\s\S]*?\*\/` (the slashes are escaped inside a regex
  // literal). `indexOf` found neither, both indices were -1, every file was
  // skipped by the `=== -1` guard, and the test PASSED over eleven known
  // offenders. A guard that cannot fire, in the test written to catch guards
  // that cannot fire. The fix is to match the distinctive INNER fragments, which
  // are written the same way whatever the surrounding escaping.
  const BLOCK_SIG = '[\\s\\S]*?';   // the lazy any-including-newline of a /* */ strip
  const LINE_SIG = '.*$';           // the to-end-of-line of a // strip

  // ⛔ NAMED EXEMPTIONS WITH A REASON EACH, never a silent skip — the convention
  // `deviceScopeCoverage.js`'s TRANSITIVE_ALLOWED follows.
  const EXEMPT = Object.freeze({
    'stripOrder.test.js':
      'this file deliberately reproduces the wrong order, to assert that it loses code',
    'objectUsage.test.js':
      'its only line-comment strip is SQL `--` inside a .map; there is no adjacent '
      + 'JS block/line pair to order, so the match is incidental',
  });

  it('every source-scanning test either shares the helper or orders it correctly', () => {
    const offenders = [];
    for (const f of fs.readdirSync(__dirname).filter((n) => n.endsWith('.test.js'))) {
      if (EXEMPT[f]) continue;
      const s = fs.readFileSync(path.join(__dirname, f), 'utf8');
      const bi = s.indexOf(BLOCK_SIG);
      const li = s.indexOf(LINE_SIG);
      if (bi === -1 || li === -1) continue;      // not both — nothing to order
      if (bi < li) offenders.push(f);
    }
    assert.deepEqual(offenders, [],
      'these strip BLOCK comments before LINE comments, so a "/*" inside a line '
      + 'comment eats everything to the next "*/". Require { stripComments } from '
      + `./stripComments instead, or swap the two replaces:\n  ${offenders.join('\n  ')}`);
  });
});
