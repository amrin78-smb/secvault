// tests/nextResponseImported.test.js
//
// ⛔ WHY THIS EXISTS. `app/api/devices/[id]/test/route.js` shipped in v2.236.0
// returning `NextResponse.json(...)` from its monitoring-only branch while
// importing no NextResponse and using a bare `Response.json(...)` at every
// other return. That is a ReferenceError on exactly that branch — and the
// branch is the one whose own comment reads:
//
//   ⛔ NOTHING WAS PROBED, SO NOTHING IS RECORDED. Without this the new
//   getAdapter throw landed in the catch below, which persists a
//   `reachable: false` row ... one click gave a log-only firewall a 0%
//   poll-success rate.
//
// The throw lands in that very catch, which calls recordConnectivity with
// `reachable: false`. So the guard produced the defect it was written to
// prevent, for every syslog-only firewall, on a button that is unconditional
// on the device page and on every /devices row.
//
// ⛔ `npm run build` PASSES AND SO DOES EVERY OTHER GATE. Next compiles a
// server module without resolving free identifiers, `node --check` is a no-op
// on a file with a top-level import, and tests/importIntegrity.test.js polices
// only names exported by lib/ modules — NextResponse comes from next/server,
// so it was outside that scan by design, not by accident.
//
// ⛔ COMMENTS AND LITERALS ARE STRIPPED FIRST. lib/notificationChannels.js and
// lib/credentialProfiles.js both say "safe to hand straight to
// NextResponse.json" in PROSE; a raw-text scan reports both as defects. That
// is the same trap tests/buttonContrast.test.js, tests/deviceScopeCoverage.js
// and tests/dataDirAcl.test.js each record — a guard that cries wolf gets
// waived, and then the check stops happening.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { stripComments } = require('./stripComments');

const REPO = path.join(__dirname, '..');
const ROOTS = ['app', 'lib', 'components', 'services'];

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, out);
    else if (e.name.endsWith('.js')) out.push(full);
  }
  return out;
}

// ⛔ THE SHARED STRIPPER, never a hand-rolled pair of replaces. Order is
// load-bearing: a `//` comment containing "/*" opens a phantom block for a
// block-first stripper, which then eats real code to the next "*/".
// tests/stripOrder.test.js enforces this and caught the first draft of this
// very file.
//
// ⛔ STRING LITERALS ARE DELIBERATELY NOT STRIPPED. The obvious regex for that
// backtracks catastrophically over this codebase (an apostrophe in prose, or a
// quote inside a regex literal, sends it scanning to EOF and back) and took
// this file past a 120s timeout. Comments are where the false positives
// actually live: both prose mentions of this identifier in lib/ are comments.
const code = stripComments;

describe('a Next helper is imported wherever it is used', () => {
  const files = ROOTS.flatMap((r) => walk(path.join(REPO, r)));

  it('⛔ the scan reaches the API routes at all', () => {
    // Without this the file goes vacuously green if a root is renamed.
    assert.ok(files.length > 200, `expected to scan the app, saw ${files.length} files`);
    assert.ok(
      files.some((f) => f.endsWith(path.join('app', 'api', 'devices', '[id]', 'test', 'route.js'))),
      'expected the device connectivity-test route to be in scope'
    );
  });

  for (const name of ['NextResponse', 'NextRequest']) {
    it(`⛔ every use of ${name} is imported from next/server`, () => {
      const offenders = [];
      for (const file of files) {
        const src = code(fs.readFileSync(file, 'utf8'));
        if (!new RegExp(`\\b${name}\\b`).test(src)) continue;
        const imported =
          new RegExp(`import[^;]*\\b${name}\\b[^;]*from\\s*["']next/server["']`).test(src) ||
          new RegExp(`\\b${name}\\b[^;]*=\\s*require\\(\\s*["']next/server["']`).test(src) ||
          new RegExp(`require\\(\\s*["']next/server["']\\s*\\)[^;]*\\b${name}\\b`).test(src);
        if (!imported) offenders.push(path.relative(REPO, file));
      }
      assert.deepEqual(
        offenders,
        [],
        `${name} is referenced without an import in:\n  ${offenders.join('\n  ')}\n` +
          'That is a ReferenceError the build cannot see. This repo returns bare ' +
          '`Response.json(...)` from route handlers — use that, or add the import.'
      );
    });
  }
});
