'use strict';

// ⛔ A PROP NOBODY IMPLEMENTED IS INVISIBLE, AND THAT IS WHY THIS FILE EXISTS.
//
// `components/ui/EmptyState.js` destructured `message` alone for its whole
// life while FOUR call sites passed a `title`. React does not warn about a
// prop a component ignores; `node --check` is a no-op on JSX; nothing rendered
// the panel. So four headings — including "Remediation velocity could not be
// measured", which is a statement that SecVault FAILED TO READ something —
// were dropped on the floor and those panels read as "nothing to report".
//
// Fixing the component fixed those four. This test is what stops the fifth: it
// scans every call site and fails the build on a prop the component does not
// accept, so the next `icon=` or `action=` somebody invents is a build failure
// rather than a silent omission.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const COMPONENT = path.join(ROOT, 'components', 'ui', 'EmptyState.js');
const SKIP_DIRS = new Set(['node_modules', '.next', '.git', '.playwright-mcp', 'dist', 'coverage']);

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(path.join(dir, entry.name), out);
    } else if (entry.name.endsWith('.js')) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

// ⛔ COMMENTS ARE STRIPPED BEFORE ANYTHING IS SCANNED, AND THE FIRST DRAFT OF
// THIS FILE PROVED WHY: the heading assertion below failed on CORRECT code,
// because `EmptyState.js`'s own comment explains why it must not emit an
// `<h2>` — and the scan read that sentence as the thing it forbids. Identical
// to the defect CLAUDE.md records against `lib/notificationChannels.js`, whose
// prose saying it holds no device data was read as evidence that it does.
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

// ⛔ BRACE-DEPTH AWARE, NOT A FLAT REGEX OVER THE TAG. A flat `/(\w+)\s*=/`
// reported `components/compliance/StandardTabs.js` as passing a `statusFilter`
// prop. It does not — it uses `statusFilter === 'all'` INSIDE its
// `message={...}` expression, and the regex read the `=` of a comparison as
// the `=` of an attribute. A guard that cries wolf gets deleted or waived,
// which loses the check altogether, so only depth-0 names count.
function propsOf(tag) {
  const names = [];
  let depth = 0;
  let pending = '';
  for (const c of tag) {
    if (c === '{') { depth += 1; pending = ''; continue; }
    if (c === '}') { depth -= 1; pending = ''; continue; }
    if (depth > 0) continue;
    if (/[a-zA-Z0-9_]/.test(c)) { pending += c; continue; }
    if (c === '=' && pending) { names.push(pending); pending = ''; continue; }
    pending = '';
  }
  return names;
}

function acceptedProps() {
  const src = stripComments(fs.readFileSync(COMPONENT, 'utf8'));
  const m = src.match(/export default function EmptyState\(\{([^}]*)\}/);
  assert.ok(m, 'could not find EmptyState’s destructured props — this guard reads them');
  return new Set(m[1].split(',').map((s) => s.trim().split(/[=:]/)[0].trim()).filter(Boolean));
}

function callSites() {
  const sites = [];
  for (const file of walk(ROOT)) {
    if (file === COMPONENT) continue;
    const raw = fs.readFileSync(file, 'utf8');
    if (!raw.includes('<EmptyState')) continue;
    const src = stripComments(raw);
    for (const m of src.matchAll(/<EmptyState\b([\s\S]*?)\/?>/g)) {
      sites.push({
        file: path.relative(ROOT, file),
        line: src.slice(0, m.index).split('\n').length,
        props: propsOf(m[1]),
      });
    }
  }
  return sites;
}

describe('EmptyState cannot silently swallow a prop', () => {
  it('finds call sites at all (a walk finding none would be vacuously green)', () => {
    assert.ok(callSites().length >= 10, 'expected many EmptyState call sites');
  });

  it('the scanner does not read a comparison inside an expression as a prop', () => {
    // Pins the false positive that the first draft produced, so the fix cannot
    // be regressed into a simpler regex later.
    assert.deepEqual(propsOf(` message={x === 'all' ? 'a' : 'b'} `), ['message']);
    assert.deepEqual(propsOf(` title="t" message={n > 0 ? a : b} `), ['title', 'message']);
  });

  it('every prop passed anywhere is one the component destructures', () => {
    const accepted = acceptedProps();
    const bad = [];
    for (const s of callSites()) {
      for (const p of s.props) {
        if (!accepted.has(p)) bad.push(`${s.file}:${s.line} passes \`${p}\``);
      }
    }
    assert.deepEqual(bad, [], 'these props are passed to EmptyState and silently dropped');
  });

  it('`title` is accepted AND rendered — not merely destructured', () => {
    // ⛔ Asserting the signature alone would pass on a component that
    // destructures `title` and never uses it: the same defect one layer in.
    const accepted = acceptedProps();
    assert.ok(accepted.has('title'), 'EmptyState must accept a title');
    const body = stripComments(fs.readFileSync(COMPONENT, 'utf8'));
    assert.match(body, /\{title &&/, 'title must be conditionally rendered');
    assert.match(body, /\{title\}/, 'title must actually be emitted');
  });

  it('the title is NOT a heading element', () => {
    // This panel mounts inside cards, inside tabs and directly under a page's
    // own h1, so an <h2> here would inject an outline entry whose LEVEL
    // depends on where the panel happens to be used — and tests/pageHeading.js
    // pins that outline at both ends.
    assert.doesNotMatch(stripComments(fs.readFileSync(COMPONENT, 'utf8')), /<h[1-6][\s>]/);
  });

  it('a message still renders when no title is given', () => {
    const src = stripComments(fs.readFileSync(COMPONENT, 'utf8'));
    assert.match(src, /message = 'Nothing to show\.'/);
    assert.match(src, /\{message\}/);
  });
});
