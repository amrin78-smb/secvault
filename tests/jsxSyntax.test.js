// tests/jsxSyntax.test.js
//
// Every .js file in the app parses, INCLUDING its JSX.
//
// ⛔ WHY THIS EXISTS. `node --check` exits 0 on a component containing broken
// JSX — verified: appending `export function Broken() { return <div><span>oops
// </div>; }` to a component still passes. It parses the file as ESM and never
// reaches the JSX, so an unclosed tag, a stray brace inside a {...}
// expression, or a mismatched fragment all sail through. CLAUDE.md's
// pre-commit checklist is correct to scope `node --check` to the non-JSX
// directories, and `.ai-codex/gotchas.md` records the whole trap.
//
// That left `npm run build` as the only gate on JSX correctness. A build takes
// tens of seconds and cannot run while parallel agents are mid-edit, so in
// practice broken JSX was found late or by a person. This test is the same
// check in about a second.
//
// It uses the JSX-aware parser gotchas.md already names as the alternative:
// next/dist/build/swc. `next` is a runtime dependency, so this adds no
// devDependency — which matters, because package.json deliberately has none
// (every devDependency would ship to a firewall-management box via `npm ci`).
//
// ⛔ SYNTAX ONLY. This proves a file parses. It does not typecheck, does not
// resolve imports, and does not run a component. tests/importIntegrity.test.js
// covers the missing-import case; nothing here replaces `npm run build`.

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');

const SKIP_DIRS = new Set(['node_modules', '.next', '.git', 'tests', 'installer', 'public']);

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.name.endsWith('.js')) out.push(p);
  }
  return out;
}

test('every .js file parses, including its JSX', async () => {
  // Required lazily: the swc binding is native, and a require failure should
  // read as "this environment cannot run the check", not as a syntax error in
  // the app.
  let parse;
  try {
    ({ parse } = require('next/dist/build/swc'));
  } catch (err) {
    assert.fail(
      'Could not load next/dist/build/swc, so JSX was not checked: ' + err.message
    );
  }

  const failures = [];
  for (const file of walk(REPO)) {
    const src = fs.readFileSync(file, 'utf8');
    try {
      // isModule:true matches how Next compiles these. Every file in this repo
      // is ESM (components/pages) or CommonJS that still parses as a module.
      await parse(src, { filename: file, syntax: 'ecmascript', jsx: true, isModule: true });
    } catch (err) {
      // ⛔ swc's first message line is EMPTY and the useful text (the reason
      // and the line/column caret) is further down. Taking [0] the obvious way
      // produced a failure that named the file and said nothing else — a test
      // that tells you something broke but not what is barely better than the
      // build you were trying to avoid running. Keep the first few non-empty
      // lines instead.
      const detail = String(err.message)
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean)
        .slice(0, 3)
        .join(' | ');
      failures.push(path.relative(REPO, file) + ' — ' + (detail || 'parse failed'));
    }
  }
  assert.deepEqual(failures, [], '\n  ' + failures.join('\n  ') + '\n');
});
