'use strict';
// tests/schemaOrder.test.js
//
// ⛔ SECVAULT COULD NOT BE INSTALLED FROM SCRATCH, AND NOTHING SAID SO.
//
// `lib/schema.sql` is sent to PostgreSQL by `lib/migrate.js` as ONE
// multi-statement batch, so any statement that needs a table which is declared
// LATER in the file aborts the entire migration and the installer stops with
// [FATAL] Schema migration failed. Two were found on 2026-09-24, by the first
// genuine fresh-install test:
//
//   cve_assessment_acknowledgements  REFERENCES advisories(id)      430 lines early
//   ALTER TABLE snmp_metric_snapshots ADD COLUMN ...                140 lines early
//
//     relation "advisories" does not exist            (SQLSTATE 42P01)
//     relation "snmp_metric_snapshots" does not exist (SQLSTATE 42P01)
//
// ⛔ BOTH WERE INVISIBLE ON EVERY DEPLOYED SERVER. `CREATE TABLE IF NOT EXISTS`
// guards CREATION and says nothing about ORDER, and `ADD COLUMN IF NOT EXISTS`
// tolerates a missing COLUMN, never a missing TABLE. Wherever the table already
// existed both statements ran clean — so the file was exercised on every deploy
// for months and the defect could only ever appear on a database that had never
// been migrated. CLAUDE.md records the sibling trap (a new column needs its own
// ALTER because the CREATE is a no-op on a deployed server); this is its mirror
// image.
//
// ⛔ AND THE FIRST VERSION OF THIS TEST ONLY CHECKED `REFERENCES`. It passed,
// and the very next live migration failed on the ALTER. A guard that covers one
// shape of a defect reports "clean" about the others, which is worse than no
// guard because the green is read as coverage. DEPENDS_ON_TABLE below is that
// correction: widen the list rather than narrow it.
//
// ⛔ This reads the DDL as TEXT, because the suite cannot reach a database (see
// tests/README.md). It checks the ORDER of declarations, not that the schema
// applies. `npm run dbcheck` executes SQL but runs against an ESTABLISHED
// database, which is exactly why it never caught either of these.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const SCHEMA = path.join(__dirname, '..', 'lib', 'schema.sql');

// Every way a statement can require a table to already exist.
const DEPENDS_ON_TABLE = [
  ['REFERENCES', /REFERENCES\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/gi],
  ['CREATE INDEX', /CREATE\s+(?:UNIQUE\s+)?INDEX[^;]*?\s+ON\s+([A-Za-z_][A-Za-z0-9_]*)/gi],
  ['ALTER TABLE', /ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?([A-Za-z_][A-Za-z0-9_]*)/gi],
  ['CREATE TRIGGER', /CREATE\s+TRIGGER[^;]*?\s+ON\s+([A-Za-z_][A-Za-z0-9_]*)/gi],
  ['COMMENT ON', /COMMENT\s+ON\s+TABLE\s+([A-Za-z_][A-Za-z0-9_]*)/gi],
  ['INSERT INTO', /INSERT\s+INTO\s+([A-Za-z_][A-Za-z0-9_]*)/gi],
];

function parseSchema() {
  const lines = fs.readFileSync(SCHEMA, 'utf8').split('\n');
  const created = new Map();   // table -> line of its CREATE TABLE
  const deps = [];             // { line, kind, target, text }

  lines.forEach((raw, i) => {
    const lineNo = i + 1;
    // Strip trailing comments so prose naming a table is never read as DDL.
    const code = raw.split('--')[0];
    if (!code.trim()) return;

    const create = /CREATE TABLE IF NOT EXISTS\s+([A-Za-z_][A-Za-z0-9_]*)/.exec(code);
    if (create && !created.has(create[1])) created.set(create[1], lineNo);

    for (const [kind, pattern] of DEPENDS_ON_TABLE) {
      for (const m of code.matchAll(pattern)) {
        // A table naming ITSELF on its own CREATE line is not a dependency.
        if (create && m[1] === create[1]) continue;
        deps.push({ line: lineNo, kind, target: m[1], text: code.trim() });
      }
    }
  });

  return { lines, created, deps };
}

describe('⛔ schema.sql applies to an EMPTY database, not just an established one', () => {
  const { lines, created, deps } = parseSchema();

  it('parsed the schema at all', () => {
    // A scan that found nothing passes vacuously — the same failure shape in a
    // different costume.
    assert.ok(lines.length > 1000, `only ${lines.length} lines read from schema.sql`);
    assert.ok(created.size > 40, `only ${created.size} tables found — the CREATE pattern is wrong`);
    assert.ok(deps.length > 80, `only ${deps.length} table dependencies found — the patterns are wrong`);
  });

  it('never depends on a table before it is created', () => {
    const forward = deps
      .filter((d) => created.has(d.target) && created.get(d.target) > d.line)
      .map((d) => `line ${d.line} ${d.kind} ${d.target} (created at line ${created.get(d.target)})\n      ${d.text}`);

    assert.deepEqual(
      forward,
      [],
      'A statement needs a table that schema.sql declares LATER. It runs fine on every '
        + 'server that already has the table, and on a FRESH database it fails with '
        + '\'relation "..." does not exist\' and aborts the whole migration — so the product '
        + 'cannot be installed at all. Move the statement after its target.'
    );
  });

  it('never depends on a table that is never created', () => {
    // A typo'd or removed target fails everywhere — but it would fail during a
    // customer's install rather than here.
    const unknown = [...new Set(deps.filter((d) => !created.has(d.target)).map((d) => d.target))];
    assert.deepEqual(unknown, [], 'statement(s) reference a table with no CREATE TABLE in schema.sql');
  });
});
