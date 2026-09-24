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
// ⛔ AND THIS GUARD HAS NOW BEEN TOO NARROW TWICE, THE SAME WAY BOTH TIMES.
//
//   1. The first version only checked `REFERENCES`. It passed, and the very
//      next live migration failed on the ALTER.
//   2. The second version checked six statement kinds but matched them ONE LINE
//      AT A TIME, requiring `INDEX` and `ON <table>` on the same physical line.
//      30 of schema.sql's 109 CREATE INDEX statements wrap:
//
//          CREATE INDEX IF NOT EXISTS idx_cloud_app_ranges_ip
//            ON cloud_app_ranges (range_start, range_end) WHERE kind = 'ip';
//
//      so it saw about 72% of the one shape it named, and nothing about the
//      rest. It also truncated each line at the first `--`, which cuts inside a
//      string literal (`DEFAULT 'a--b'`) and silently drops the DDL after it.
//
// A guard that covers one shape of a defect reports "clean" about the others,
// which is worse than no guard because the green is read as coverage. The
// correction each time is to WIDEN, so this version lexes the file into
// STATEMENTS — handling '' escapes, dollar-quoting, quoted identifiers and
// block comments — and matches against whole statements, at whatever line and
// across however many lines they happen to be written.
//
// ⛔ AND THE LEXER IS PINNED BY A SYNTHETIC FIXTURE, not only by the live file.
// The live file is (now) correct, so running against it only ever exercises the
// green path: a parser that silently matched nothing would pass exactly as
// loudly. The fixture below contains a wrapped, comment-interrupted forward
// dependency and asserts it is CAUGHT.
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

// Every way a statement can require a table to already exist. Matched against a
// whole statement with its whitespace collapsed, so wrapping is irrelevant.
const DEPENDS_ON_TABLE = [
  ['REFERENCES', /REFERENCES\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/gi],
  ['CREATE INDEX', /CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?[A-Za-z_][A-Za-z0-9_]*\s+ON\s+(?:ONLY\s+)?([A-Za-z_][A-Za-z0-9_]*)/gi],
  ['ALTER TABLE', /ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?([A-Za-z_][A-Za-z0-9_]*)/gi],
  ['CREATE TRIGGER', /CREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER\s+[A-Za-z_][A-Za-z0-9_]*[\s\S]*?\sON\s+([A-Za-z_][A-Za-z0-9_]*)/gi],
  ['COMMENT ON', /COMMENT\s+ON\s+TABLE\s+([A-Za-z_][A-Za-z0-9_]*)/gi],
  ['INSERT INTO', /INSERT\s+INTO\s+([A-Za-z_][A-Za-z0-9_]*)/gi],
  ['UPDATE', /\bUPDATE\s+(?:ONLY\s+)?([A-Za-z_][A-Za-z0-9_]*)\s+SET\b/gi],
  ['DELETE FROM', /\bDELETE\s+FROM\s+(?:ONLY\s+)?([A-Za-z_][A-Za-z0-9_]*)/gi],
  ['TRUNCATE', /\bTRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?([A-Za-z_][A-Za-z0-9_]*)/gi],
  ['PARTITION OF', /\bPARTITION\s+OF\s+([A-Za-z_][A-Za-z0-9_]*)/gi],
  ['ATTACH PARTITION', /\bATTACH\s+PARTITION\s+([A-Za-z_][A-Za-z0-9_]*)/gi],
  ['CREATE VIEW', /\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:MATERIALIZED\s+)?VIEW\s+[A-Za-z_][A-Za-z0-9_]*\s+AS[\s\S]*?\bFROM\s+([A-Za-z_][A-Za-z0-9_]*)/gi],
  ['GRANT ON', /\bGRANT\s+[\s\S]*?\sON\s+(?:TABLE\s+)?([A-Za-z_][A-Za-z0-9_]*)\s+TO\b/gi],
];

// ⛔ A REAL LEXER, NOT A LINE SPLIT. Comments, single-quoted strings with ''
// escapes, dollar-quoted bodies and double-quoted identifiers all suppress the
// meaning of the characters inside them, and every one of those can span lines.
// Returns whitespace-collapsed statements, each with the line it starts on.
function splitStatements(sql) {
  const out = [];
  let buf = '';
  let line = 1;
  let startLine = 1;
  let started = false;
  let i = 0;

  const push = () => {
    const text = buf.trim().replace(/\s+/g, ' ');
    if (text) out.push({ text, line: startLine });
    buf = '';
    started = false;
  };

  while (i < sql.length) {
    const ch = sql[i];

    // -- line comment: drop to end of line
    if (ch === '-' && sql[i + 1] === '-') {
      while (i < sql.length && sql[i] !== '\n') i += 1;
      continue;
    }
    // /* block comment */ (not nested — schema.sql has none, and a stray one
    // reads as CODE, which is the safe direction: a false positive, not a miss)
    if (ch === '/' && sql[i + 1] === '*') {
      i += 2;
      while (i < sql.length && !(sql[i] === '*' && sql[i + 1] === '/')) {
        if (sql[i] === '\n') line += 1;
        i += 1;
      }
      i += 2;
      buf += ' ';
      continue;
    }
    // 'string with '' escapes'
    if (ch === "'") {
      buf += "''";               // a harmless placeholder; contents never matter
      i += 1;
      while (i < sql.length) {
        if (sql[i] === "'" && sql[i + 1] === "'") { i += 2; continue; }
        if (sql[i] === "'") { i += 1; break; }
        if (sql[i] === '\n') line += 1;
        i += 1;
      }
      if (!started) { startLine = line; started = true; }
      continue;
    }
    // $tag$ dollar-quoted body $tag$
    if (ch === '$') {
      const m = /^\$[A-Za-z_][A-Za-z0-9_]*\$|^\$\$/.exec(sql.slice(i));
      if (m) {
        const tag = m[0];
        const end = sql.indexOf(tag, i + tag.length);
        const chunk = end === -1 ? sql.slice(i) : sql.slice(i, end + tag.length);
        for (const c of chunk) if (c === '\n') line += 1;
        buf += ' ';
        i = end === -1 ? sql.length : end + tag.length;
        continue;
      }
    }
    // "quoted identifier"
    if (ch === '"') {
      let id = '';
      i += 1;
      while (i < sql.length && sql[i] !== '"') {
        if (sql[i] === '\n') line += 1;
        id += sql[i];
        i += 1;
      }
      i += 1;
      if (!started) { startLine = line; started = true; }
      buf += id;
      continue;
    }
    if (ch === ';') { push(); i += 1; continue; }

    if (ch === '\n') line += 1;
    else if (!started && /\S/.test(ch)) { startLine = line; started = true; }
    buf += ch;
    i += 1;
  }
  push();
  return out;
}

// The order check itself, over any SQL text. Exposed to the fixture below so
// the parser is tested by BEHAVIOUR rather than by reading the live file and
// hoping the patterns bit.
function analyse(sql) {
  const statements = splitStatements(sql);
  const created = new Map();   // table -> index of the statement creating it
  const deps = [];             // { index, line, kind, target, text }

  statements.forEach((st, index) => {
    const create = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)/i.exec(st.text);
    if (create && !created.has(create[1])) created.set(create[1], index);

    for (const [kind, pattern] of DEPENDS_ON_TABLE) {
      pattern.lastIndex = 0;
      for (const m of st.text.matchAll(pattern)) {
        // A table naming ITSELF inside its own CREATE is not a dependency.
        if (create && m[1] === create[1]) continue;
        deps.push({ index, line: st.line, kind, target: m[1], text: st.text.slice(0, 160) });
      }
    }
  });

  const forward = deps
    .filter((d) => created.has(d.target) && created.get(d.target) > d.index)
    .map((d) => `line ${d.line} ${d.kind} ${d.target} (created later)\n      ${d.text}`);

  const unknown = [...new Set(deps.filter((d) => !created.has(d.target)).map((d) => d.target))];

  return { statements, created, deps, forward, unknown };
}

describe('⛔ schema.sql applies to an EMPTY database, not just an established one', () => {
  const sql = fs.readFileSync(SCHEMA, 'utf8');
  const { statements, created, deps, forward, unknown } = analyse(sql);

  it('parsed the schema at all', () => {
    // A scan that found nothing passes vacuously — the same failure shape in a
    // different costume.
    assert.ok(statements.length > 150, `only ${statements.length} statements lexed from schema.sql`);
    assert.ok(created.size > 40, `only ${created.size} tables found — the CREATE pattern is wrong`);
    assert.ok(deps.length > 80, `only ${deps.length} table dependencies found — the patterns are wrong`);
  });

  it('sees the statements that WRAP, not just the ones on one line', () => {
    // ⛔ THE SPECIFIC BLIND SPOT OF THE PREVIOUS VERSION. schema.sql writes most
    // of its indexes with `ON <table>` on a second line; a line-at-a-time scan
    // matched only the single-line ones and reported the file clean.
    const indexDeps = deps.filter((d) => d.kind === 'CREATE INDEX').length;
    // Counted from the LEXED statements, never the raw file: schema.sql's own
    // comments discuss CREATE INDEX in prose three times, and counting those
    // would assert against a number that is not DDL.
    const code = statements.map((st) => st.text).join('\n');
    const totalIndexes = (code.match(/CREATE\s+(?:UNIQUE\s+)?INDEX/gi) || []).length;
    assert.ok(totalIndexes > 90, `only ${totalIndexes} CREATE INDEX statements lexed?`);
    assert.equal(
      indexDeps,
      totalIndexes,
      `extracted a target from ${indexDeps} of ${totalIndexes} lexed CREATE INDEX statements — `
        + 'the dependency pattern is missing some, which is how the wrapped ones went unseen before'
    );
  });

  it('never depends on a table before it is created', () => {
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
    assert.deepEqual(unknown, [], 'statement(s) reference a table with no CREATE TABLE in schema.sql');
  });
});

describe('⛔ the order checker itself, against SQL written to defeat it', () => {
  it('catches a forward dependency that WRAPS across lines', () => {
    const { forward } = analyse(`
      CREATE INDEX IF NOT EXISTS idx_late
        ON arrives_later (col);
      CREATE TABLE IF NOT EXISTS arrives_later (id UUID PRIMARY KEY);
    `);
    assert.equal(forward.length, 1, 'a wrapped CREATE INDEX forward dependency was missed');
    assert.match(forward[0], /arrives_later/);
  });

  it('catches a forward dependency split by a comment', () => {
    const { forward } = analyse(`
      ALTER TABLE  -- moved here on purpose
        arrives_later ADD COLUMN IF NOT EXISTS x INT;
      CREATE TABLE IF NOT EXISTS arrives_later (id UUID PRIMARY KEY);
    `);
    assert.equal(forward.length, 1, 'a comment-interrupted ALTER forward dependency was missed');
  });

  it('is not fooled by a table name inside a string literal', () => {
    const { forward, unknown } = analyse(`
      CREATE TABLE IF NOT EXISTS t (k TEXT DEFAULT 'REFERENCES ghost(id)');
      CREATE TABLE IF NOT EXISTS ghost (id UUID PRIMARY KEY);
    `);
    assert.deepEqual(forward, [], 'prose inside a string literal was read as DDL');
    assert.deepEqual(unknown, []);
  });

  it('does not truncate DDL at a -- inside a string literal', () => {
    // ⛔ THE OTHER HALF OF THE OLD LINE SCAN: it did `raw.split('--')[0]`, so a
    // literal containing a double hyphen swallowed the rest of the line.
    const { forward } = analyse(`
      CREATE TABLE IF NOT EXISTS t (k TEXT DEFAULT 'a--b', fk UUID REFERENCES ghost(id));
      CREATE TABLE IF NOT EXISTS ghost (id UUID PRIMARY KEY);
    `);
    assert.equal(forward.length, 1, "a REFERENCES after a '--' inside a string literal was dropped");
  });

  it('accepts a correctly ordered file', () => {
    const { forward, unknown } = analyse(`
      CREATE TABLE IF NOT EXISTS first (id UUID PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS second (id UUID PRIMARY KEY, fk UUID REFERENCES first(id));
      CREATE INDEX IF NOT EXISTS idx_second
        ON second (fk);
      ALTER TABLE second ADD COLUMN IF NOT EXISTS extra INT;
    `);
    assert.deepEqual(forward, []);
    assert.deepEqual(unknown, []);
  });
});
