'use strict';

// tests/noHardcodedCredentials.test.js
//
// ⛔ WHY THIS EXISTS. CLAUDE.md's Security rules say "NEVER hardcode
// credentials in source files", and that rule has now been broken TWICE by the
// same mechanism:
//
//   1. lib/schema-grants.sql carried a hardcoded claude_readonly password, so
//      every installation in the field was created with the same password and
//      that password was in git. Fixed 2026-10-16 by generating one per
//      install.
//   2. scripts/dbCheck.js carried the SAME credential again, as a convenience
//      DEFAULT for READONLY_URL pointing at the production reference
//      deployment. The 2026-10-16 fix never looked at it, so it survived — and
//      because `npm run dbcheck` worked with no argument, nobody had to supply
//      a credential and nobody noticed one was baked in. Found 2026-11-12.
//
// The lesson is not "remember to grep". Both instances were a plausible
// convenience that removed the moment anyone would have had to think about a
// secret. So the guard is a BUILD FAILURE, not a convention.
//
// ⛔ IT ASSERTS THE ABSENCE OF A CLASS, AND PINS THE SPECIFIC REGRESSION TOO.
// A class scan alone would pass the day someone reintroduces the dbCheck
// default in a shape the regex does not match; a named assertion alone would
// pass the day a credential appears in a different file. Both, for the same
// reason tests/deviceScopeCoverage.test.js asserts a count AND names the
// surfaces.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');
const DIRS = ['lib', 'app', 'services', 'scripts', 'installer'];
const EXTS = new Set(['.js', '.sql', '.sh', '.ps1', '.py', '.json', '.cmd']);

// A value that is obviously standing in for a secret rather than being one.
// ⛔ Deliberately generous: a placeholder wrongly treated as a secret costs one
// renamed placeholder, while a secret wrongly treated as a placeholder is the
// defect this file exists to stop. Anything NOT matching is reported and a
// human decides.
const PLACEHOLDER = /^(\$|%|\{|<|\.\.\.|\*)|(\$|%|\}|>|\.\.\.|\*)$|^(PASSWORD|password|pass|pw|secret|REDACTED|changeme|xxx+|your[-_]?password)$/i;

function walk(dir, out = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === '.git' || e.name === '.next') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (EXTS.has(path.extname(e.name))) out.push(p);
  }
  return out;
}

test('⛔ no source file carries a database credential inline', () => {
  // postgresql://user:something@host — the shape every instance of this defect
  // has taken, in both of the files above.
  const RE = /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/([A-Za-z0-9_.-]+):([^@\s'"`)]+)@/g;
  const offenders = [];

  for (const file of walk(path.join(REPO, 'lib')).concat(
    ...DIRS.slice(1).map((d) => walk(path.join(REPO, d)))
  )) {
    const text = fs.readFileSync(file, 'utf8');
    for (const m of text.matchAll(RE)) {
      const password = m[2];
      if (PLACEHOLDER.test(password)) continue;
      // Which line, so the failure is actionable without printing the secret.
      const line = text.slice(0, m.index).split('\n').length;
      offenders.push(
        `${path.relative(REPO, file)}:${line} — connection string for user "${m[1]}" `
        + `carries an inline ${password.length}-character password`
      );
    }
  }

  assert.deepStrictEqual(
    offenders,
    [],
    'A credential is hardcoded in source. It is in git and readable by anyone '
    + 'holding a checkout or the distribution folder. Move it to '
    + '~/.secvault-local-secrets.json (mode 0600, outside the repo) and read it '
    + 'the way scripts/devdb.sh and scripts/dbcheckUrl.sh do.\n  '
    + offenders.join('\n  ')
  );
});

test('⛔ dbCheck.js has NO default connection string — the specific 2026-11-12 regression', () => {
  const src = fs.readFileSync(path.join(REPO, 'scripts', 'dbCheck.js'), 'utf8');

  // Find the declaration and assert it resolves to null, not to a fallback
  // string. `process.env.DBCHECK_URL || '<anything>'` is the defect.
  const m = src.match(/const\s+READONLY_URL\s*=\s*([^;]+);/);
  assert.ok(m, 'READONLY_URL declaration not found — did the variable get renamed?');
  const decl = m[1].replace(/\s+/g, ' ').trim();

  assert.equal(
    decl,
    'process.env.DBCHECK_URL || null',
    'READONLY_URL must have NO default. A convenience default is what hid a '
    + 'production credential in this file, and it also aimed the sweep at the '
    + 'live fleet from any dev box. It must be exactly '
    + '`process.env.DBCHECK_URL || null`.'
  );

  // ⛔ And the refusal must actually be wired, or the null silently becomes
  // libpq's own defaults: `new Pool({ connectionString: null })` is not an
  // error, it falls back to PGHOST/PGUSER and then the OS user against
  // localhost — which on a dev box is a role that can WRITE.
  assert.match(
    src,
    /if\s*\(\s*!READONLY_URL\s*\)\s*\{/,
    'READONLY_URL is allowed to be null but nothing refuses it. pg treats a '
    + 'null connectionString as "use libpq defaults", so an unset DBCHECK_URL '
    + 'would run the whole sweep as whatever local role answers.'
  );
});
