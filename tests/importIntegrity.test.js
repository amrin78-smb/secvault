// tests/importIntegrity.test.js
//
// ⛔ WHY THIS EXISTS. Twice now a page has referenced a helper it never
// imported, and BOTH times `npm run build` passed:
//
//   Sidebar.js       used IconAlertTriangle with no import — the nav entry
//                    landed but the import edit silently missed.
//   [cveId]/page.js  used parseCvssVector with no import — my own guard
//                    (`if (!s.includes('cvssVector'))`) matched the local
//                    function name cvssVectorChips and skipped.
//
// Next.js compiles server components without resolving every identifier, so an
// undefined reference is a RUNTIME crash on that one page — invisible until
// someone opens it. There is no linter in this repo by design (package.json has
// no devDependencies, deliberately), so this is the cheap substitute.
//
// It is a NARROW check, on purpose: for every name a lib/ module exports, if a
// page or component MENTIONS that name, it must also import it or define it
// locally. That catches the exact failure above without pretending to be a
// general "no-undef".

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const REPO = path.join(__dirname, '..');

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, out);
    else if (e.name.endsWith('.js')) out.push(full);
  }
  return out;
}

// Exported names worth policing: helpers a page would call by bare name.
// Deliberately excludes single-letter and very common words, which would make
// the mention-test noisy rather than useful.
function exportedNames(file) {
  const src = fs.readFileSync(file, 'utf8');
  const names = new Set();
  for (const m of src.matchAll(/^export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/gm)) {
    names.add(m[1]);
  }
  for (const m of src.matchAll(/^export\s+const\s+([A-Za-z_$][\w$]*)/gm)) names.add(m[1]);
  // CommonJS modules (lib/ is mostly CJS so the engine worker can require it)
  const me = src.match(/module\.exports\s*=\s*\{([\s\S]*?)\}/);
  if (me) {
    for (const m of me[1].matchAll(/([A-Za-z_$][\w$]*)\s*[,:}]/g)) names.add(m[1]);
  }
  return [...names].filter((n) => n.length >= 6);
}

describe('pages and components import what they use', () => {
  // ⛔ components/ IS A SOURCE OF EXPORTS TOO, not just a consumer. This walked
  // only lib/, so a name exported by a COMPONENT was never in the set to check
  // against — and that is exactly how TYPE_LABELS (exported by
  // components/analysis/FindingTypeBadge.js, used by the device analysis page)
  // shipped without its import and threw ReferenceError on every visit to the
  // findings tab. The guard existed and its scope was too narrow.
  const libFiles = [
    ...walk(path.join(REPO, 'lib')),
    ...walk(path.join(REPO, 'components')),
  ].filter((f) => !f.includes(`${path.sep}adapters${path.sep}`));

  const exported = new Map(); // name -> defining file (first wins)
  for (const f of libFiles) {
    for (const n of exportedNames(f)) if (!exported.has(n)) exported.set(n, f);
  }

  const uiFiles = [
    ...walk(path.join(REPO, 'app')),
    ...walk(path.join(REPO, 'components')),
  ];

  it('found lib exports and UI files to check', () => {
    // Guards against the walk silently finding nothing and the suite passing
    // vacuously — the same self-check tests/moduleLoad.test.js makes.
    assert.ok(exported.size > 20, `expected >20 lib exports, found ${exported.size}`);
    assert.ok(uiFiles.length > 50, `expected >50 UI files, found ${uiFiles.length}`);
  });

  for (const file of uiFiles) {
    const rel = path.relative(REPO, file).split(path.sep).join('/');
    it(`${rel}`, () => {
      const raw = fs.readFileSync(file, 'utf8');
      // ⛔ Strip comments and string/template literals FIRST. This codebase
      // comments heavily and names other modules' functions in prose
      // constantly ("see runAnalysisForDevice", "same shape as classifyDiff"),
      // so scanning raw text produced 26 false positives on the first run. A
      // guard that cries wolf gets deleted, which is worse than no guard.
      const src = raw
        .replace(/\/\*[\s\S]*?\*\//g, ' ')
        .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ')
        .replace(/`(?:\\.|[^`\\])*`/g, '``')
        .replace(/'(?:\\.|[^'\\])*'/g, "''")
        .replace(/"(?:\\.|[^"\\])*"/g, '""');
      const missing = [];
      for (const [name, definedIn] of exported) {
        // ⛔ A file is never checked against a name IT ITSELF exports. Once
        // components/ became an export SOURCE as well as a consumer, every
        // module that uses its own constant (vendorMeta.js reading
        // VENDOR_META) looked like a missing import. This is an exact test
        // against the defining file, not another heuristic.
        //
        // It also sidesteps a real weakness: the comment/string stripper above
        // mangles some files badly enough that a genuine `export const NAME`
        // disappears from `src`, so the "declared locally" regex below cannot
        // see it. That weakness can still cause a FALSE NEGATIVE elsewhere —
        // it is a known limit of this guard, not a solved problem.
        if (definedIn === file) continue;
        // Mentioned as a bare identifier (call, JSX use, or reference)?
        //
        // ⛔ `[` IS IN THIS SET AND MUST STAY. It was omitted, and that is a
        // systematic blind spot rather than a typo: a lookup MAP — which is
        // most of what this codebase exports as a constant — is consumed as
        // TYPE_LABELS[key], not TYPE_LABELS( or TYPE_LABELS. . So every
        // *_LABELS / *_MAP / *_COLOR export was invisible to this guard.
        // Missing that let TYPE_LABELS ship without its import and throw
        // ReferenceError on every visit to the device findings tab.
        const used = new RegExp(`(^|[^\\w$.'"\`])${name}\\s*[({.[]`).test(src);
        if (!used) continue;
        // Imported, destructured, or defined locally in this same file?
        const declared = new RegExp(
          `(import[^;]*\\b${name}\\b[^;]*from|` +
            `\\b(?:const|let|var|function|class)\\s+${name}\\b|` +
            `\\{[^}]*\\b${name}\\b[^}]*\\}\\s*=\\s*require|` +
            // A DESTRUCTURED FUNCTION PARAMETER — e.g.
            //   function ChecksPager({ page, totalPages, total }) { ... }
            // is a local binding, not a missing import. Without this the guard
            // flagged two files that were entirely correct, and a guard with
            // false positives gets deleted.
            `function\\s+\\w*\\s*\\(\\s*\\{[^}]*\\b${name}\\b|` +
            `\\(\\s*\\{[^}]*\\b${name}\\b[^}]*\\}\\s*\\)\\s*=>)`
        ).test(src);
        if (!declared) missing.push(name);
      }
      assert.deepEqual(
        missing,
        [],
        `${rel} references ${missing.join(', ')} without importing or defining it — ` +
          'this builds clean and crashes when the page is opened'
      );
    });
  }
});
