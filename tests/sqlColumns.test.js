// tests/sqlColumns.test.js
//
// Every SQL identifier in this repo names a column that exists.
//
// ⛔ WHY THIS EXISTS. On 2026-09-09 the dashboard home page threw a
// server-side exception for every user, on every load, because its
// feed-freshness query asked for `feed_sync_log.completed_at`. That column has
// never existed — it is called `finished_at`. Nothing caught it:
//
//   node --check  — a SQL string is an opaque string to the JS parser
//   npm test      — the pure-engine tests take stub pools and touch no schema
//   npm run build — a force-dynamic page's query is never executed at build
//
// So the only gate was loading the page, and the page that broke was the one
// route nobody clicks while verifying a feature, because you are already on
// it. A wrong column name is not a rare mistake — it is the cheapest way to
// take this app down, and it deserves a gate that is not human attention.
//
// ⛔ NO DATABASE. This reads lib/schema.sql, exactly like lib/migrate.js does,
// which keeps the test runnable on any checkout and keeps package.json free of
// devDependencies. It was cross-checked once against the live 52-table
// database and agreed on every table except the five whose grants deliberately
// hide them from the readonly role.
//
// ⛔ CONSERVATIVE BY CONSTRUCTION. A query this cannot understand is SKIPPED,
// never guessed at: an unknown table, a dynamic ${} fragment that changes the
// identifier set, an information_schema probe. A false failure here would
// train the next person to delete the test, which costs more than the coverage
// it gives up.

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');

// ── schema.sql -> table -> Set(column) ────────────────────────────────────
// The closing paren is `\n)` followed by anything up to the semicolon, NOT
// `\n);` — syslog_events ends `) PARTITION BY RANGE (received_at);` and the
// stricter pattern silently swallowed the NEXT table's body into it.
function parseSchema(sql) {
  const tables = new Map();
  for (const m of sql.matchAll(/CREATE TABLE IF NOT EXISTS\s+([a-z_][a-z0-9_]*)\s*\(([\s\S]*?)\n\)[^;]*;/gi)) {
    const body = m[2].replace(/--[^\n]*/g, '');
    const cols = new Set();
    // Split on top-level commas only: a column can carry its own parens
    // (NUMERIC(5,2), CHECK (...), DEFAULT ARRAY[]::text[]).
    let depth = 0;
    let cur = '';
    const parts = [];
    for (const ch of body) {
      if (ch === '(') depth++;
      else if (ch === ')') depth--;
      if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; continue; }
      cur += ch;
    }
    parts.push(cur);
    for (const part of parts) {
      const c = part.trim().match(/^([a-z_][a-z0-9_]*)\s+[A-Za-z]/);
      if (!c) continue;
      if (['primary', 'unique', 'foreign', 'constraint', 'check', 'exclude', 'like'].includes(c[1].toLowerCase())) continue;
      cols.add(c[1]);
    }
    tables.set(m[1], cols);
  }
  // A column added to an already-deployed table lives in an ALTER, not in the
  // CREATE body (CLAUDE.md's IF NOT EXISTS rule) — those count too.
  for (const m of sql.matchAll(/ALTER TABLE\s+(?:IF EXISTS\s+)?([a-z_][a-z0-9_]*)\s+ADD COLUMN IF NOT EXISTS\s+([a-z_][a-z0-9_]*)/gi)) {
    if (!tables.has(m[1])) tables.set(m[1], new Set());
    tables.get(m[1]).add(m[2]);
  }
  return tables;
}

// Words that appear in a query but are not columns. Deliberately generous:
// every entry here is coverage given up, and giving up coverage is the safe
// direction for a lint.
const NOT_A_COLUMN = new Set(
  ('select distinct on from where group by order having limit offset as and or not in is null '
    + 'true false case when then else end asc desc join left right inner outer full cross lateral '
    + 'union all except intersect with insert into values update set delete returning conflict do '
    + 'nothing exists between like ilike similar any some array interval now coalesce nullif greatest '
    + 'least count sum max min avg round abs cast text int integer bigint smallint boolean date '
    + 'timestamptz timestamp jsonb json uuid inet cidr numeric real float double precision char varchar '
    + 'extract date_trunc to_char to_timestamp age host masklen network family filter over partition '
    + 'rows range unbounded preceding following current row nulls first last using natural only recursive '
    + 'temp temporary table commit drop create index concurrently if not unnest generate_series '
    + 'percentile_cont within lower upper trim btrim split_part length position substring concat '
    + 'string_agg array_agg json_agg jsonb_agg json_build_object jsonb_build_object bool_or bool_and '
    + 'xmax ctid tableoid oid epoch second minute hour day week month year local session default '
    + 'analyze vacuum explain begin rollback savepoint declare fetch close cursor set_config').split(/\s+/)
);

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === '.next' || e.name === '.git' || e.name === 'tests') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.name.endsWith('.js')) out.push(p);
  }
  return out;
}

// Strip what is not identifier text: SQL comments, string literals, and
// ${...} interpolations (a fragment can introduce its own tables and columns,
// so anything it contributes is unknowable from here).
function normalize(lit) {
  return lit
    .replace(/--[^\n]*/g, ' ')
    .replace(/'(?:[^']|'')*'/g, " '' ")
    .replace(/\$\{[^{}]*\}/g, ' ');
}

// Aliases: `FROM t alias` and `JOIN t AS alias`.
function collectAliases(q, knownTables) {
  const aliasOf = new Map();
  for (const m of q.matchAll(/\b(?:FROM|JOIN|UPDATE|INTO)\s+([a-z_][a-z0-9_]*)(?:\s+AS)?\s+([a-z_][a-z0-9_]*)/gi)) {
    const [, table, alias] = m;
    if (!knownTables.has(table)) continue;
    if (NOT_A_COLUMN.has(alias.toLowerCase())) continue; // `FROM t WHERE ...`
    aliasOf.set(alias, table);
  }
  return aliasOf;
}

const schema = parseSchema(fs.readFileSync(path.join(REPO, 'lib', 'schema.sql'), 'utf8'));

test('lib/schema.sql parses into tables and columns', () => {
  assert.ok(schema.size > 40, `only ${schema.size} tables parsed — the CREATE TABLE regex has drifted`);
  // Two spot-checks, one of them the exact column this test was written for.
  assert.ok(schema.get('feed_sync_log').has('finished_at'));
  assert.ok(!schema.get('feed_sync_log').has('completed_at'));
  // A partitioned table must not have swallowed its neighbour's columns.
  assert.ok(schema.get('syslog_events').has('received_at'));
  assert.ok(!schema.get('syslog_events').has('bucket_hour'));
});

test('every SQL identifier names a column that exists', () => {
  const problems = [];
  for (const file of walk(REPO)) {
    const src = fs.readFileSync(file, 'utf8');
    for (const lit of src.match(/`[^`]*`/g) || []) {
      if (!/\b(SELECT|INSERT INTO|UPDATE|DELETE FROM)\b/.test(lit)) continue;
      const q = normalize(lit);
      // Catalog probes describe tables rather than reading them.
      if (/information_schema|pg_catalog|pg_class|pg_stat/i.test(q)) continue;

      // ⛔ `LATERAL` is a KEYWORD, not a table. Without skipping it, every
      // `LEFT JOIN LATERAL (...)` captured the literal word "lateral" as a
      // table reference; "lateral" is not in the schema, so the whole query was
      // treated as unverifiable and SKIPPED. deviceInventory.js's
      // getDeviceRows() has TEN of them, which meant the entire Devices-page
      // query — one of the largest in the app — was never checked at all.
      // Confirmed by renaming a real column to nonsense and watching this test
      // stay green.
      //
      // Same reasoning applies to the other join-shape keywords that can follow
      // JOIN: a bare `JOIN LATERAL`/`CROSS JOIN LATERAL` names its table after
      // the parenthesised subquery, not before it.
      const JOIN_KEYWORDS = new Set(['lateral', 'only']);
      const refs = [...q.matchAll(/\b(?:FROM|JOIN|INTO|UPDATE)\s+([a-z_][a-z0-9_]*)/gi)]
        .map((m) => m[1])
        .filter((t) => !JOIN_KEYWORDS.has(t.toLowerCase()));
      if (refs.length === 0) continue;
      // Any table this file does not know about (a CTE, a temp table, a
      // fragment-supplied name) makes the whole query unverifiable.
      if (refs.some((t) => !schema.has(t))) continue;

      const tables = new Set(refs);
      const aliasOf = collectAliases(q, schema);
      const allowed = new Set();
      for (const t of tables) for (const c of schema.get(t)) allowed.add(c);
      for (const m of q.matchAll(/\bAS\s+([a-z_][a-z0-9_]*)/gi)) allowed.add(m[1]);
      // A subquery alias — `... LIMIT 30 ) recent ORDER BY ...` — and a temp
      // table this query creates for itself (rollups.js's rollup_src).
      for (const m of q.matchAll(/\)\s*([a-z_][a-z0-9_]*)\b/g)) allowed.add(m[1]);
      for (const m of q.matchAll(/CREATE\s+(?:TEMP\s+|TEMPORARY\s+)?TABLE\s+([a-z_][a-z0-9_]*)/gi)) allowed.add(m[1]);

      // 1. Qualified refs are checked against THEIR OWN table — the strongest
      //    form, because `dca.finished_at` is wrong even when some other table
      //    in the same query happens to have a finished_at.
      for (const m of q.matchAll(/\b([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)\b/g)) {
        const [, qual, col] = m;
        const table = aliasOf.get(qual) || (schema.has(qual) ? qual : null);
        if (!table) continue;
        if (NOT_A_COLUMN.has(col.toLowerCase())) continue;
        if (!schema.get(table).has(col)) {
          problems.push(`${path.relative(REPO, file)}: ${qual}.${col} — ${table} has no such column`);
        }
      }

      // 2. Bare identifiers must exist somewhere in the referenced tables.
      //    This is the case that actually broke production: `completed_at` was
      //    unqualified.
      for (const m of q.matchAll(/(^|[^.\w])([a-z_][a-z0-9_]{2,})\b/g)) {
        const id = m[2];
        const at = m.index + m[1].length;
        if (NOT_A_COLUMN.has(id) || allowed.has(id) || schema.has(id) || aliasOf.has(id)) continue;
        if (/^\s*\(/.test(q.slice(at + id.length))) continue;       // function call
        if (/\bAS\s+$/i.test(q.slice(0, at))) continue;             // its own alias
        problems.push(`${path.relative(REPO, file)}: ${id} — not a column of ${[...tables].join(', ')}`);
      }
    }
  }
  assert.deepEqual(problems, [], '\n  ' + problems.join('\n  ') + '\n');
});
