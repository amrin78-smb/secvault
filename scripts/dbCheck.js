#!/usr/bin/env node
'use strict';
//
// scripts/dbCheck.js — does this product's SQL actually run against the schema?
//
// ⛔ THE GAP THIS FILLS. Every engine test in this repo hands the engine a STUB
// pool that returns canned rows and records the SQL it was given. That is
// deliberate, it is cheap, and it means NO TEST HAS EVER EXECUTED ANY OF THIS
// PRODUCT'S SQL AGAINST A REAL SCHEMA. What that blindness has cost:
//
//   v2.86.1   the dashboard threw for every user, on every load, because a
//             query asked for `feed_sync_log.completed_at`. The column is
//             `finished_at`. "The only real gate was loading the page."
//   2026-09-21 a `bool_or` on the OUTER side of a LEFT JOIN that could never
//             return NULL, and a `sum(...) FILTER (...)` returning NULL where
//             the caller believed it had a real zero. Neither is findable with
//             a stub: the stub returns whatever the test author expected.
//
//   node --check   a SQL string is an opaque string to the JS parser
//   npm test       stub pools, no schema
//   npm run build  every dashboard page is force-dynamic, so no query runs
//   npm run smoke  loads pages, but only the happy path a live fleet produces
//
// ── WHY IT CALLS THE REAL FUNCTIONS RATHER THAN A LIST OF SQL ───────────────
//
// ⛔ THERE IS NO COPY OF ANY QUERY IN THIS FILE, AND THERE MUST NEVER BE. A
// second copy of a query drifts from the one that ships and then proves
// something about itself instead of about the product. So this imports the real
// exported READ functions and calls them with the real `pg` driver. What gets
// executed is byte-for-byte what a page executes, including every `${}`
// fragment the query is assembled from — which is precisely the part a static
// checker (tests/sqlColumns.test.js) has to skip.
//
// It also checks the RETURN SHAPE, because the two 2026-09-21 findings above
// did not throw. A query that resolves with a column the caller destructures as
// `undefined` is the failed-read-as-a-fact bug with no error anywhere.
//
// ── THE SIX THINGS IT CHECKS ───────────────────────────────────────────────
//
//   1. every registered read function resolves without throwing;
//   2. it ISSUED AT LEAST ONE STATEMENT — a reader that short-circuits before
//      its query resolves perfectly and verifies nothing;
//   3. its result has the shape its callers destructure;
//   4. no result carries a SWALLOWED error (see harvestSwallowedErrors — this
//      is the most valuable check in the file);
//   5. every table and column named in lib/schema.sql exists on the live
//      database — the `CREATE TABLE IF NOT EXISTS` trap, where a column added
//      to an existing table's CREATE body never reaches a deployed server and
//      the diff still looks correct;
//   6. every declared table carries the per-table GRANT SELECT CLAUDE.md
//      requires, AND none of the six secret-bearing tables has become readable
//      — a regression in the second direction is a credential exposure, not a
//      cosmetic drift.
//
// ── WHAT IT DOES NOT CHECK ─────────────────────────────────────────────────
//
// Only READ paths, so every write path in this product (collectAndStore, the
// rollup writers, the assessment upserts, retention's DELETEs) is untouched —
// a readonly role cannot execute them and this tool will not try. It asserts
// SHAPE, not correctness: a query returning the wrong NUMBER passes here, and
// the pure-engine tests are what pin arithmetic. It does not exercise routes,
// pages, or React serialisation (`npm run smoke`), and it proves nothing about
// a table that is empty on this fleet — those lines are reported `unverified`
// rather than green.
//
// ── READ-ONLY, THREE INDEPENDENT GUARDS ────────────────────────────────────
//
// ⛔ 1. THE ROLE, AND IT IS NOW ASSERTED RATHER THAN ASSUMED. It connects as
//       `claude_readonly`, which holds SELECT and nothing else, so the
//       database itself refuses a write. ⛔ That was a CLAIM until v2.173.0:
//       `DBCHECK_URL` overrides the connection string, `current_user` was
//       PRINTED and never CHECKED, and an operator chasing a missing grant
//       types `DBCHECK_URL=$DATABASE_URL npm run dbcheck` — at which point
//       every registered function runs as the table OWNER against production
//       and guard 1 is a line of log output. `assertReadOnlyRole` now refuses
//       to run at all unless the connected role can write NOTHING, and it
//       tests the PRIVILEGE rather than the NAME (see its own comment).
// ⛔ 2. THE NAME GUARD (`assertReadOnlyRegistry`, pure and tested). A function
//       whose name implies a write — store/save/run/collect/dispatch/trim/
//       drop/create/update/delete/upsert/insert/set/enqueue/claim/activate/
//       record/seed/migrate/… — may not be REGISTERED. It fails closed: an
//       unrecognised verb is refused, because the cost of refusing a harmless
//       reader is one line in this file and the cost of the reverse is a write
//       against a production security database.
// ⛔ 3. THE POOL PROXY (`guardStatement`, pure and tested). EVERY statement in
//       the string is inspected before it leaves the process, and anything
//       that is not a read is refused. ⛔ It used to read only the LEADING
//       verb, and node-pg sends a multi-statement string as a simple query
//       whenever no parameter array is passed — so
//       `pool.query('SELECT 1; DELETE FROM advisories')` was a write that
//       walked past the guard. No registered function does that today; the
//       guard's job is to survive the day one does. Belt and braces on purpose, for the same reason
//       config retention expresses each delete protection twice: guard 1 is
//       the deployment's property and could be granted away by someone
//       tidying `schema-grants.sql`, and guard 2 rests on my reading of a
//       function name. Neither alone is the kind of guard this codebase
//       accepts on a write path.
//
// ⛔ `syslog_events` IS NEVER READ WITHOUT A `received_at` LOWER BOUND — the
// proxy refuses it. It ingests ~28M rows/day and a careless scan evicts the
// buffer cache out from under an ingest running at ~1,000 inserts/sec. ⛔ The
// test used to be that the word `received_at` appeared ANYWHERE in the
// statement, which `SELECT received_at, src_ip FROM syslog_events` satisfies
// with no predicate at all — a full scan of every retained partition, passed
// by a guard whose own comment claimed "an entirely unbounded read is refused
// outright". It now requires a COMPARISON that puts a floor under the
// partition key (`received_at >= …`, `> …`, `BETWEEN …`, or the reversed
// `… <= received_at`), which is the only shape that lets PostgreSQL skip the
// other 29 days. Every window argument below is the SMALLEST the function
// will accept, and `statement_timeout` is a hard ceiling under all of it.
//
// ── `blocked` IS ITS OWN STATE AND IS NEVER A PASS ─────────────────────────
//
// ⛔ `device_credentials`, `credential_profiles`, `notification_channels`,
// `user_mfa`, and the base `settings` and `users` tables are DELIBERATELY not
// readable by this role (the last two are exposed through the
// `settings_readonly` / `users_readonly` views instead). A permission error on
// one of those is a PASS FOR THE GRANTS POLICY and a FAILURE TO MEASURE the
// query — two different facts, and this reports both rather than collapsing
// them. A permission error on any OTHER table is a real defect: CLAUDE.md
// requires a per-table grant for every new table, and a missing one means the
// diagnostics role cannot see a table it is supposed to.
//
// ⛔ AND IT MAY NOT REPORT AN ALL-CLEAR WHILE ANYTHING IS BLOCKED OR
// UNVERIFIED — the same rule `lib/answers.js` enforces product-wide. A short
// clean run over a fleet with no rules collected would otherwise read as
// health.
//
// ── IT IS NOT PART OF `npm test`, AND MUST NOT BE ──────────────────────────
//
// CLAUDE.md is explicit that nothing in the suite talks to a database, and a
// test that SKIPS when it cannot reach one is the guard-that-cannot-fire
// pattern this codebase treats as worse than no guard. So this lives behind its
// own script and FAILS LOUDLY when it cannot connect. Its pure parts are
// exported and pinned by tests/dbCheckHarness.test.js, which feeds them the
// failure shapes a live run never produces.
//
// Usage:
//   npm run dbcheck
//   DBCHECK_URL=postgresql://user:pass@host:5432/secvault npm run dbcheck
//   npm run dbcheck -- --only=feedStatus     (one substring, name or module)
//   npm run dbcheck -- --no-raw              (skip the syslog_events readers)
//   npm run dbcheck -- --schema-only
//   npm run dbcheck -- --list
//
// ⛔ DBCHECK_URL MUST NAME A ROLE THAT CAN WRITE NOTHING. The sweep refuses to
// run otherwise — pointing it at DATABASE_URL to chase a missing grant would
// run every registered function as the table owner against production.
//
// Exit 0 = every registered read ran and returned the expected shape.
// Exit 1 = at least one did not.  Exit 2 = could not connect, the connection
//          is not read-only, or a harness error.

const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');

// ⛔ NOT `lib/db.js`. That singleton is built from DATABASE_URL, i.e. the
// read-WRITE application role. This tool connects as the readonly role on
// purpose, so it must build its own pool.
const READONLY_URL = process.env.DBCHECK_URL
  || 'postgresql://claude_readonly:ClaudeRead%402026%21@192.168.7.69:5432/secvault';

// A hard ceiling under every query, applied by the server, so no bug in the
// window arithmetic below can turn into a long scan against a live ingest.
const STATEMENT_TIMEOUT_MS = Number(process.env.DBCHECK_TIMEOUT_MS || 20000);

// The smallest raw-table window this tool will ever ask for.
const RAW_WINDOW_MINUTES = 20;

// A syntactically valid id that matches nothing. Used where a function needs an
// id only to parameterise its SQL: the statement still executes and is still
// validated, and a fabricated row is never required to prove a query parses.
const NO_SUCH_UUID = '00000000-0000-0000-0000-000000000000';

// ───────────────────────────────────────────────────────────────────────────
// 0. THE ROLE ASSERTION (pure) — guard 1, enforced
// ───────────────────────────────────────────────────────────────────────────

/**
 * May this connection run the sweep at all?
 *
 * ⛔ IT TESTS THE PRIVILEGE, NOT THE NAME. A role spelled `claude_readonly`
 * that has been granted INSERT by someone tidying `schema-grants.sql` is not
 * read-only, and a customer running their diagnostics role under another name
 * is not a defect. So the only question asked is the one that matters: can
 * this role write ANYTHING in `public`? One writable table is enough to
 * refuse — the registry is 100+ functions deep and this tool cannot read all
 * of their SQL for the operator.
 *
 * ⛔ IT FAILS CLOSED, INCLUDING ON AN UNREADABLE ANSWER. "We could not
 * determine who this is" is not "this is fine" — the same call every other
 * authorisation-shaped check in this product makes, and the opposite of the
 * licence guard, which fails open because it is only about billing.
 *
 * @param {{user?: string, superuser?: boolean, writableTables?: number, writableSample?: string}} who
 * @returns {{ok: true, user: string} | {ok: false, reason: string}}
 */
function assertReadOnlyRole(who) {
  const w = who || {};
  const user = typeof w.user === 'string' ? w.user.trim() : '';
  if (!user) {
    return {
      ok: false,
      reason: 'the database did not report a current_user, so WHO this is connected as is unknown — refusing to run rather than guessing',
    };
  }
  if (w.superuser === true) {
    return {
      ok: false,
      reason: `connected as "${user}", which is a SUPERUSER. This tool calls 100+ functions against a production security database and its read-only guarantee starts with the role. Point DBCHECK_URL at claude_readonly.`,
    };
  }
  if (w.superuser !== false) {
    return {
      ok: false,
      reason: `could not determine whether "${user}" is a superuser (pg_roles returned nothing for it), so this connection's read-only status is UNKNOWN — refusing to run`,
    };
  }
  // ⛔ NOT a bare `Number.isFinite(Number(x))`. `Number(null)` is 0 and 0 is
  // finite, so an UNREADABLE count would come out as "may write nothing" —
  // the same substitution CLAUDE.md names over the licence guard's maxDevices,
  // here turning "we could not check" into a clean bill of health on the one
  // check that decides whether this tool may talk to production at all.
  const raw = w.writableTables;
  const n = raw === null || raw === undefined || raw === '' || typeof raw === 'boolean'
    ? NaN
    : Number(raw);
  if (!Number.isFinite(n)) {
    return {
      ok: false,
      reason: `could not count the tables "${user}" may write, so this connection's read-only status is UNKNOWN — refusing to run`,
    };
  }
  if (n > 0) {
    const sample = w.writableSample ? ` (e.g. ${w.writableSample})` : '';
    return {
      ok: false,
      reason: `connected as "${user}", which holds INSERT/UPDATE/DELETE on ${n} table(s)${sample}. That is the application role, not the diagnostics role — `
        + 'most likely DBCHECK_URL was set to DATABASE_URL. Point it at claude_readonly, whose refusal is what makes this sweep safe to run against production.',
    };
  }
  return { ok: true, user };
}

// ───────────────────────────────────────────────────────────────────────────
// 1. THE READ-ONLY NAME GUARD (pure)
// ───────────────────────────────────────────────────────────────────────────

// ⛔ FAILS CLOSED. The test is not "does this look dangerous" but "is the
// leading verb one of the read verbs". A new export called `refreshFoo` is
// refused until someone reads it and decides.
const READ_VERBS = [
  'get', 'list', 'load', 'build', 'compute', 'gather', 'query', 'find',
  'resolve', 'summarise', 'summarize', 'evaluate', 'correlate', 'search',
  'count', 'read', 'describe', 'classify', 'attach', 'is', 'has',
  // Two non-verbs, admitted only after reading the functions. `window*` is
  // lib/reports/trafficWindow.js's deliberate prefix (lib.md: `timeline`/
  // `actions`/`protocols` collided with local variable names across the UI);
  // `standardCoverage` is complianceReport.js's per-standard count. Both are
  // pure SELECTs. ⛔ This list is the place a human decision is recorded, not
  // a place to silence the guard — the refusal message says so.
  'window', 'standard',
];

// Verbs that have actually appeared on a writer in this repo, named so the
// refusal message can say which one it objected to.
const WRITE_VERBS = [
  'store', 'save', 'run', 'collect', 'dispatch', 'trim', 'drop', 'create',
  'update', 'delete', 'upsert', 'insert', 'set', 'enqueue', 'claim', 'finish',
  'reap', 'activate', 'clear', 'record', 'seed', 'migrate', 'generate',
  'apply', 'write', 'remove', 'add', 'assess', 'verify', 'submit', 'abandon',
  'reconcile', 'notify', 'send', 'sync', 'ingest', 'prune', 'backfill',
];

function leadingVerb(fnName) {
  const m = String(fnName || '').match(/^[a-z]+/);
  return m ? m[0] : '';
}

/**
 * Is this export name safe to CALL against a production database?
 *
 * @returns {{ok: true} | {ok: false, reason: string}}
 */
function checkReadOnlyName(fnName) {
  const name = String(fnName || '');
  if (name === '') return { ok: false, reason: 'an empty function name' };
  const verb = leadingVerb(name);
  if (verb === '') {
    return { ok: false, reason: `"${name}" does not begin with a lower-case verb, so its intent cannot be read` };
  }
  if (WRITE_VERBS.includes(verb)) {
    return { ok: false, reason: `"${name}" begins with "${verb}", which names a write in this codebase` };
  }
  if (!READ_VERBS.includes(verb)) {
    // ⛔ THE FAIL-CLOSED BRANCH, and the one that earns the guard its place.
    return { ok: false, reason: `"${name}" begins with "${verb}", which is not a known read verb — refused rather than guessed at` };
  }
  return { ok: true };
}

/**
 * Every entry in the registry, checked at once, so a bad addition cannot run
 * even a single statement. ⛔ THROWS rather than skipping the entry: a skipped
 * entry is a silently shorter report, and a shorter report looks complete.
 */
function assertReadOnlyRegistry(registry) {
  const bad = [];
  for (const e of registry || []) {
    const verdict = checkReadOnlyName(e && e.fn);
    if (!verdict.ok) bad.push(`${(e && e.mod) || '?'} → ${verdict.reason}`);
  }
  if (bad.length) {
    throw new Error(
      `dbCheck refuses to run: ${bad.length} registered function(s) may write.\n  `
      + bad.join('\n  ')
      + '\n\nIf one of these is genuinely a reader, add its verb to READ_VERBS '
      + 'after reading the function — never to make this message go away.'
    );
  }
  return registry;
}

// ───────────────────────────────────────────────────────────────────────────
// 2. THE STATEMENT GUARD (pure)
// ───────────────────────────────────────────────────────────────────────────

// Statements a read-only sweep legitimately issues. `SET` is here because
// lib/syslog/logSearch.js sets a LOCAL statement_timeout inside its own
// transaction on a dedicated client, which is exactly the right thing for it to
// do and must not be broken by this tool.
const READ_STARTERS = ['select', 'with', 'show', 'explain', 'table', 'values', 'begin', 'start', 'commit', 'rollback', 'set', 'discard'];

// A data-modifying CTE is a WITH statement that writes. Matched on the SQL
// keyword shapes only, and against the literal-stripped copy below, so a
// string containing the word "delete" does not trip it.
const WRITING_CTE = /\b(insert\s+into|update\s+[a-z_."]+\s+set|delete\s+from|merge\s+into)\b/i;

// The raw partitioned table, and a partition of it by name — reading one
// partition directly is the same 28M rows with the guard spelled differently.
const RAW_TABLE = /(^|[^a-z0-9_])syslog_events(_\d{8})?([^a-z0-9_]|$)/i;

// A FLOOR under the partition key, in either direction it can be written.
// `received_at < $2` alone is not one: it bounds the recent end and scans
// every partition behind it.
const RECEIVED_AT_LOWER_BOUND = [
  /(^|[^a-z0-9_])received_at\s*(>=?|between\b)/i,
  /(<=?)\s*received_at([^a-z0-9_]|$)/i,
];

/**
 * Split SQL into its top-level statements, returning for each the raw text and
 * a `stripped` copy with comments, string literals and dollar-quoted blocks
 * blanked out — so no keyword test below can be fooled by text inside a
 * literal, and no `;` inside one can fake a statement break.
 *
 * ⛔ DOUBLE-QUOTED IDENTIFIERS ARE KEPT, not blanked. They are names, not
 * text, and blanking them would hide the table in `UPDATE "devices" SET …`
 * from WRITING_CTE.
 */
function splitStatements(sql) {
  const out = [];
  let raw = '';
  let stripped = '';
  const flush = () => {
    if (raw.trim() !== '') out.push({ text: raw, stripped });
    raw = '';
    stripped = '';
  };
  const take = (from, to, blank) => {
    const chunk = sql.slice(from, to);
    raw += chunk;
    stripped += blank ? ' '.repeat(chunk.length) : chunk;
  };

  let i = 0;
  const n = sql.length;
  while (i < n) {
    const ch = sql[i];
    const two = sql.slice(i, i + 2);

    if (two === '--') {
      const nl = sql.indexOf('\n', i);
      const stop = nl === -1 ? n : nl;
      take(i, stop, true);
      i = stop;
      continue;
    }
    if (two === '/*') {
      let depth = 1;
      let j = i + 2;
      while (j < n && depth > 0) {
        if (sql.slice(j, j + 2) === '/*') { depth += 1; j += 2; } else if (sql.slice(j, j + 2) === '*/') { depth -= 1; j += 2; } else j += 1;
      }
      take(i, j, true);
      i = j;
      continue;
    }
    if (ch === "'" || ch === '"') {
      let j = i + 1;
      while (j < n) {
        if (sql[j] === ch) {
          if (sql[j + 1] === ch) { j += 2; continue; } // a doubled quote is an escape
          j += 1;
          break;
        }
        j += 1;
      }
      take(i, j, ch === "'");
      i = j;
      continue;
    }
    if (ch === '$') {
      const m = /^(\$[a-zA-Z_][a-zA-Z0-9_]*\$|\$\$)/.exec(sql.slice(i));
      if (m) {
        const tag = m[0];
        const end = sql.indexOf(tag, i + tag.length);
        const stop = end === -1 ? n : end + tag.length;
        take(i, stop, true);
        i = stop;
        continue;
      }
    }
    if (ch === ';') {
      take(i, i + 1, true);
      flush();
      i += 1;
      continue;
    }
    take(i, i + 1, false);
    i += 1;
  }
  flush();
  return out;
}

/** One statement's verdict. `where` names its position when there are several. */
function guardOneStatement(st, where) {
  const head = st.stripped.replace(/^\s+/, '');
  const verb = (head.match(/^[a-zA-Z]+/) || [''])[0].toLowerCase();
  const at = where ? ` (${where})` : '';

  if (verb === '') return { ok: false, reason: `an empty statement${at}` };
  if (!READ_STARTERS.includes(verb)) {
    const V = verb.toUpperCase();
    const article = 'AEIOU'.includes(V[0]) ? 'an' : 'a';
    return { ok: false, reason: `${article} ${V} statement${at} — this tool only issues reads` };
  }
  // ⛔ CHECKED ON EVERY STATEMENT, not only on the `with` branch. A writing
  // CTE can sit in the second statement of a chain, or be reached through
  // `SELECT … FROM (WITH …)`; gating the check on the leading verb made it a
  // guard that fires in one shape of the thing it is guarding against.
  if (WRITING_CTE.test(st.stripped)) {
    return { ok: false, reason: `a data-modifying CTE (WITH … INSERT/UPDATE/DELETE)${at}` };
  }
  if (verb === 'set' && /^set\s+(role|session\s+authorization)\b/i.test(head)) {
    return { ok: false, reason: `a SET ROLE / SET SESSION AUTHORIZATION${at}, which would change who this is` };
  }
  // ⛔ THE RAW-TABLE BOUND. `syslog_events` at ~28M rows/day cannot be read
  // without a FLOOR on received_at; the partition key is the only thing that
  // lets PostgreSQL skip the other 29 days. This does not prove the bound is
  // NARROW — that comes from the arguments the registry passes and from
  // statement_timeout — but a read with no floor under it is refused outright.
  if (RAW_TABLE.test(st.stripped) && !RECEIVED_AT_LOWER_BOUND.some((re) => re.test(st.stripped))) {
    return {
      ok: false,
      reason: `a read of syslog_events with no received_at bound${at} — naming the column is not bounding it; `
        + 'the statement needs a floor (received_at >= …, BETWEEN …) or it scans every retained partition',
    };
  }
  return { ok: true, verb };
}

/**
 * Refuse anything that is not a read, BEFORE it reaches the socket.
 *
 * ⛔ EVERY STATEMENT IN THE STRING, NOT THE FIRST. node-pg sends a
 * multi-statement string as a simple query whenever no parameter array is
 * passed, and PostgreSQL executes all of it.
 *
 * @returns {{ok: true, verb: string, statements: number} | {ok: false, reason: string}}
 */
function guardStatement(text) {
  const sql = typeof text === 'string' ? text : (text && text.text) || '';
  const statements = splitStatements(sql);
  if (statements.length === 0) return { ok: false, reason: 'an empty statement' };

  let first = null;
  for (let i = 0; i < statements.length; i += 1) {
    const where = statements.length > 1 ? `statement ${i + 1} of ${statements.length} in one chained query` : '';
    const v = guardOneStatement(statements[i], where);
    if (!v.ok) return v;
    if (first === null) first = v.verb;
  }
  return { ok: true, verb: first, statements: statements.length };
}

/**
 * Wrap a pg Pool so every statement passes guardStatement first, including
 * statements issued on a client checked out with `connect()` — lib/syslog/
 * logSearch.js uses one, and a proxy that only covered `pool.query` would have
 * left the single largest table in the database outside the guard.
 */
function readOnlyPool(pool, onStatement) {
  const wrapQuery = (target, owner) => function guardedQuery(...args) {
    const verdict = guardStatement(args[0]);
    if (!verdict.ok) {
      return Promise.reject(new Error(
        `dbCheck blocked ${verdict.reason}. This tool is read-only; the function under test `
        + 'must not be a writer.'
      ));
    }
    if (onStatement) onStatement(verdict);
    return target.apply(owner, args);
  };

  return {
    query: wrapQuery(pool.query, pool),
    async connect() {
      const client = await pool.connect();
      return {
        query: wrapQuery(client.query, client),
        release: (...a) => client.release(...a),
      };
    },
    // Deliberately no `end` — the runner owns the real pool's lifetime.
  };
}

// ───────────────────────────────────────────────────────────────────────────
// 3. ERROR CLASSIFICATION (pure)
// ───────────────────────────────────────────────────────────────────────────

// Tables this role is SUPPOSED to be unable to read. A 42501 naming one of
// these is the grants policy working; a 42501 naming anything else is a missing
// grant, which CLAUDE.md requires for every new table.
const EXPECTED_UNREADABLE = [
  'device_credentials',      // AES-256-GCM device secrets
  'credential_profiles',     // reusable credential bundles
  'notification_channels',   // webhook URLs, SMTP passwords
  'user_mfa',                // encrypted TOTP secrets + recovery hashes
  'settings',                // bcrypt admin hash + licence key; settings_readonly view instead
  'users',                   // password_hash; users_readonly view instead
];

// PostgreSQL class-42 codes are all "your SQL is wrong", which is the entire
// point of this tool. Spelled out individually so the report says WHAT is
// wrong rather than printing a code.
const DEFECT_CODES = {
  '42703': 'names a column that does not exist',
  '42P01': 'names a table or view that does not exist',
  '42601': 'is a syntax error',
  '42883': 'calls a function that does not exist',
  '42804': 'has a datatype mismatch',
  '42P18': 'has a parameter whose type PostgreSQL cannot determine — the missing ::timestamptz cast',
  '42702': 'has an ambiguous column reference',
  '42P10': 'has an invalid column reference',
  '42809': 'uses an object of the wrong type',
  '42704': 'names an undefined object',
  '42P02': 'has an undefined parameter',
  '42846': 'requests an impossible cast',
  '22P02': 'passes a value the column type refuses (invalid text representation)',
};

/**
 * Turn a rejection into one of three states.
 *
 * ⛔ `blocked` IS NOT `ok`. It means the statement never ran, so nothing about
 * it was verified. Collapsing it into a pass is the failed-read-as-a-fact bug
 * applied to this tool's own reporting.
 */
function classifyError(err) {
  const code = err && err.code ? String(err.code) : '';
  const message = (err && err.message) || String(err);

  if (code === '42501') {
    const named = EXPECTED_UNREADABLE.find((t) => new RegExp(`\\b${t}\\b`).test(message));
    if (named) {
      return {
        state: 'blocked',
        reason: `needs ${named}, which this role is deliberately denied — the grants policy held, but the query was NOT verified`,
      };
    }
    return {
      state: 'fail',
      reason: `permission denied on a table that is not on the deliberately-denied list (${message}) — a missing per-table GRANT SELECT`,
    };
  }

  if (code === '57014') {
    return { state: 'fail', reason: `exceeded the ${STATEMENT_TIMEOUT_MS}ms statement timeout — on a page, this is an outage` };
  }

  if (DEFECT_CODES[code]) {
    return { state: 'fail', reason: `SQL ${DEFECT_CODES[code]}: ${message}` };
  }

  if (/ECONNREFUSED|ENOTFOUND|ETIMEDOUT|EHOSTUNREACH|Connection terminated/i.test(message)) {
    return { state: 'fail', reason: `lost the database connection: ${message}` };
  }

  // ⛔ AN UNRECOGNISED FAILURE IS A FAILURE. A rejection this tool cannot
  // classify is not evidence that things are fine.
  return { state: 'fail', reason: `${code ? code + ' ' : ''}${message}` };
}

// ───────────────────────────────────────────────────────────────────────────
// 4. SHAPE ASSERTIONS (pure)
// ───────────────────────────────────────────────────────────────────────────

/**
 * Check a result against a declarative spec.
 *
 * spec: { array?, nullable?, object?: string[], rowKeys?: string[] }
 *
 * ⛔ `rowKeys` ON AN EMPTY ARRAY IS `unverified`, NEVER `ok`. An empty table
 * proves nothing about the column names a row would have carried, and an
 * assertion that passes because there was nothing to check is this codebase's
 * signature bug wearing a test's clothes. The count of unverified shapes is
 * printed, and it blocks the all-clear.
 */
function checkShape(value, spec) {
  const problems = [];
  const unverified = [];
  const s = spec || {};

  if (value === null || value === undefined) {
    if (s.nullable) return { problems, unverified: ['returned null (permitted), so its shape was not verified'] };
    problems.push(`returned ${value === null ? 'null' : 'undefined'}, which no caller handles`);
    return { problems, unverified };
  }

  if (s.array) {
    if (!Array.isArray(value)) {
      problems.push(`returned ${typeof value}, but callers iterate it as an array`);
      return { problems, unverified };
    }
    if (s.rowKeys) {
      if (value.length === 0) {
        unverified.push(`returned 0 rows, so its row shape (${s.rowKeys.join(', ')}) was not verified`);
      } else {
        const row = value[0];
        if (!row || typeof row !== 'object') {
          problems.push(`its first row is ${typeof row}, not an object`);
        } else {
          const missing = s.rowKeys.filter((k) => !(k in row));
          if (missing.length) {
            problems.push(`its rows are missing ${missing.join(', ')} — present keys: ${Object.keys(row).join(', ')}`);
          }
        }
      }
    }
    return { problems, unverified };
  }

  if (s.object) {
    if (typeof value !== 'object' || Array.isArray(value)) {
      problems.push(`returned ${Array.isArray(value) ? 'an array' : typeof value}, but callers destructure it as an object`);
      return { problems, unverified };
    }
    const missing = s.object.filter((k) => !(k in value));
    if (missing.length) {
      problems.push(`is missing ${missing.join(', ')} — present keys: ${Object.keys(value).join(', ')}`);
    }
    // ⛔ A KEY PRESENT AND `undefined` IS THE 2026-09-21 SHAPE, and it is worse
    // than an absent one because `'k' in obj` is true and every reader reads a
    // confident undefined. Called out separately so the message names it.
    const undef = s.object.filter((k) => k in value && value[k] === undefined);
    if (undef.length) {
      problems.push(`has ${undef.join(', ')} present but undefined — a caller destructuring it gets no error and no value`);
    }
  }

  return { problems, unverified };
}

// ───────────────────────────────────────────────────────────────────────────
// 5. SWALLOWED-ERROR HARVEST (pure) — the most valuable check here
// ───────────────────────────────────────────────────────────────────────────

/**
 * Several engines deliberately ISOLATE their sections so one failing query
 * cannot take a whole page or document down. `gatherWorkQueue` reports
 * `{ok:false, error}` per source; the report builders collect `sectionErrors`;
 * `evaluateAllApplications` and `computeFleetExposure` return `errors[]`;
 * `buildTrafficActivityData` returns `failures[]`; `gatherExecutiveSummary`
 * returns `sections.<k>.ok`.
 *
 * ⛔ THAT ISOLATION IS CORRECT AND IT IS ALSO WHERE A SQL DEFECT HIDES. Every
 * one of those functions RESOLVES on a broken query. A checker that only
 * asserted "it did not throw" would report a green sweep over a page rendering
 * a named gap where a table should be — which is exactly the state the work
 * queue's own rules say must never read as clean.
 */
function harvestSwallowedErrors(value) {
  const found = [];
  if (!value || typeof value !== 'object') return found;

  const push = (where, e) => {
    const msg = e && typeof e === 'object'
      ? (e.message || e.error || e.reason || JSON.stringify(e))
      : String(e);
    found.push(`${where}: ${msg}`);
  };

  // ⛔ AN ARRAY-SHAPED RESULT CARRIES SWALLOWED ERRORS TOO, and this was blind
  // to every one of them. `serverHealth.getServiceLiveness` returns
  // `[{name, lastSeen, ageSeconds, error?}]` and catches PER ELEMENT, so
  // renaming a column on `feed_sync_log` or `syslog_ingest_stats` leaves both
  // of its queries throwing, both caught, the array the right length, its spec
  // (`{}`) satisfied — and this tool reporting `ok` for the function whose job
  // is telling the operator whether the Engine and the Collector are alive.
  // That is the v2.86.1 defect inside the liveness report.
  //
  // ⛔ `error` IS ONLY READ ON AN ELEMENT WITH NO `id`. Rows from
  // `background_jobs` and `compliance_report_log` carry a real `error` COLUMN
  // whose value is a fact about a job, not about our query — harvesting those
  // would be a false alarm, and a false alarm is what trains the next person
  // to delete the check. Every such row carries its primary key; a
  // status-report element like getServiceLiveness's does not.
  if (Array.isArray(value)) {
    value.forEach((el, i) => {
      if (!el || typeof el !== 'object' || Array.isArray(el)) return;
      const label = el.name || el.key || el.section || `#${i}`;
      if (el.ok === false) {
        push(`element "${label}"`, el.error || 'reported ok:false with no message');
      } else if (el.error && !('id' in el)) {
        push(`element "${label}"`, el.error);
      }
    });
    return found;
  }

  for (const key of ['errors', 'sectionErrors', 'failures']) {
    const list = value[key];
    if (Array.isArray(list)) for (const e of list) push(key, e);
  }

  // gatherWorkQueue: sources[] each with ok/error, plus a truncation
  // disclosure that this tool treats as a finding of its own (see below).
  if (Array.isArray(value.sources)) {
    for (const s of value.sources) {
      if (s && s.ok === false) push(`source "${s.key || '?'}"`, s.error || 'reported ok:false with no message');
    }
  }

  // gatherExecutiveSummary: sections is a keyed object of {ok, error}
  if (value.sections && typeof value.sections === 'object' && !Array.isArray(value.sections)) {
    for (const [k, sec] of Object.entries(value.sections)) {
      if (sec && sec.ok === false) push(`section "${k}"`, sec.error || 'reported ok:false with no message');
    }
  }

  return found;
}

/**
 * ⛔ TRUNCATION IS REPORTED, NOT FAILED. `PER_SOURCE_CAP` biting is the product
 * working as designed and disclosing it — but it is also the state in which a
 * list looks complete and is not, so this tool prints it rather than letting a
 * capped run read as an exhaustive one.
 */
function harvestTruncation(value) {
  const notes = [];
  if (value && Array.isArray(value.sources)) {
    for (const s of value.sources) {
      if (s && s.truncatedFrom) notes.push(`source "${s.key}" showed ${s.count} of ${s.truncatedFrom}`);
    }
  }
  return notes;
}

// ───────────────────────────────────────────────────────────────────────────
// 6. RESULT COMPOSITION (pure)
// ───────────────────────────────────────────────────────────────────────────

/**
 * One registry entry's verdict. Pure, so tests/dbCheckHarness.test.js can feed
 * it every failure shape a live green run never produces.
 */
function classifyResult({ name, ms, error, value, spec, statements }) {
  if (error) {
    const { state, reason } = classifyError(error);
    return { name, ms, state, reason, notes: [], statements: statements || 0 };
  }

  // ⛔ A FUNCTION THAT ISSUED NO STATEMENT VERIFIED NOTHING, and it resolves
  // perfectly while doing so. Several readers short-circuit before their query
  // on an empty argument (`windowAppBytes` returns EMPTY_APP_BYTES when handed
  // no summable device ids, which is correct behaviour and a green line in this
  // report that proves the SQL below it still parses — it does not). That is
  // the guard-that-cannot-fire pattern inside this tool's own output, so it is
  // `blocked`, never `ok`.
  if (statements === 0) {
    return {
      name,
      ms,
      state: 'blocked',
      reason: 'resolved without issuing a single statement — it short-circuited, so NO SQL was verified. Give it arguments that reach its query.',
      notes: [],
      statements: 0,
    };
  }

  const { problems, unverified } = checkShape(value, spec);
  const swallowed = harvestSwallowedErrors(value);
  const truncation = harvestTruncation(value);

  if (swallowed.length) {
    return {
      name,
      ms,
      state: 'fail',
      reason: `resolved, but carries ${swallowed.length} swallowed error(s): ${swallowed.join(' | ')}`,
      notes: [...unverified, ...truncation],
      statements,
    };
  }
  if (problems.length) {
    return { name, ms, state: 'fail', reason: problems.join('; '), notes: [...unverified, ...truncation], statements };
  }
  return { name, ms, state: 'ok', reason: null, notes: [...unverified, ...truncation], statements };
}

/**
 * The closing verdict.
 *
 * ⛔ IT MAY NOT SAY "all clear" WHILE ANYTHING IS BLOCKED OR UNVERIFIED — the
 * rule lib/answers.js enforces product-wide. An unmeasured check is not a
 * passing one, and this tool's own report is the last place that distinction
 * should be allowed to slip.
 *
 * ⛔ AND THE GRANTS AUDIT IS PART OF IT. `deniedNowReadable` — a secret-bearing
 * table this diagnostics role can suddenly SELECT, i.e. a blanket
 * `GRANT SELECT ON ALL TABLES` having made `device_credentials` readable — was
 * counted for the exit code and left OUT of the closing sentence, so the
 * last and loudest line of a credential-exposure run read "All 104 reads
 * executed and returned the expected shape…". It now LEADS the sentence:
 * nothing else in this report outranks it.
 */
function summariseRun(results, schema, grants) {
  const counts = { ok: 0, fail: 0, blocked: 0 };
  let unverified = 0;
  for (const r of results) {
    counts[r.state] = (counts[r.state] || 0) + 1;
    unverified += (r.notes || []).filter((n) => /not verified/.test(n)).length;
  }
  const g = grants || {};
  const exposed = g.deniedNowReadable || [];
  const ungranted = g.missingGrants || [];
  const schemaProblems = schema ? (schema.missingTables.length + schema.missingColumns.length) : 0;
  const grantProblems = exposed.length + ungranted.length;
  const clean = counts.fail === 0 && schemaProblems === 0 && grantProblems === 0;
  const complete = clean && counts.blocked === 0 && unverified === 0;

  return {
    counts,
    unverified,
    schemaProblems,
    grantProblems,
    exposed,
    exitCode: clean ? 0 : 1,
    tone: complete ? 'ok' : (clean ? 'unknown' : 'fail'),
    sentence: !clean
      ? [
        exposed.length
          ? `${exposed.length} secret-bearing table(s) are READABLE by this diagnostics role (${exposed.join(', ')}) — a credential-exposure regression in lib/schema-grants.sql`
          : null,
        counts.fail ? `${counts.fail} read(s) failed` : null,
        schemaProblems ? `${schemaProblems} declared schema item(s) are missing from the live database` : null,
        ungranted.length
          ? `${ungranted.length} declared table(s) have no GRANT SELECT for this role (${ungranted.join(', ')})`
          : null,
      ].filter(Boolean).join('; ') + '.'
      : (complete
        ? `All ${counts.ok} reads executed and returned the expected shape, lib/schema.sql matches the live database, and every grant is as lib/schema-grants.sql declares it.`
        : `${counts.ok} reads executed cleanly, but ${counts.blocked} could not run and ${unverified} shape(s) could not be verified — this is NOT an all-clear.`),
  };
}

// ───────────────────────────────────────────────────────────────────────────
// 7. SCHEMA DIFF (pure parse + pure diff)
// ───────────────────────────────────────────────────────────────────────────

/**
 * lib/schema.sql -> Map(table -> Set(column)).
 *
 * The CREATE-body regex closes on `\n)` followed by anything up to the
 * semicolon, NOT `\n);` — `syslog_events` ends `) PARTITION BY RANGE
 * (received_at);` and the stricter pattern swallows the next table's body.
 * (Same trap tests/sqlColumns.test.js documents; the two files read the same
 * file for different purposes and neither can replace the other.)
 *
 * ⛔ `ALTER TABLE … ADD COLUMN` IS PARSED TOO, and it is the whole reason this
 * check exists: `CREATE TABLE IF NOT EXISTS` guards the TABLE only, so a column
 * added to an existing table's CREATE body silently never reaches a deployed
 * server. Both spellings are collected and both are diffed.
 */
function parseSchemaSql(sql) {
  const tables = new Map();

  for (const m of sql.matchAll(/CREATE TABLE IF NOT EXISTS\s+([a-z_][a-z0-9_]*)\s*\(([\s\S]*?)\n\)[^;]*;/gi)) {
    const body = m[2].replace(/--[^\n]*/g, '');
    const cols = new Set();
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
    for (const p of parts) {
      const t = p.trim();
      if (!t) continue;
      if (/^(primary\s+key|unique|foreign\s+key|constraint|check|exclude|like)\b/i.test(t)) continue;
      const nm = t.match(/^"?([a-z_][a-z0-9_]*)"?\s/i);
      if (nm) cols.add(nm[1].toLowerCase());
    }
    tables.set(m[1].toLowerCase(), cols);
  }

  for (const m of sql.matchAll(/ALTER TABLE\s+(?:IF EXISTS\s+)?([a-z_][a-z0-9_]*)\s+ADD COLUMN(?:\s+IF NOT EXISTS)?\s+"?([a-z_][a-z0-9_]*)"?/gi)) {
    const t = m[1].toLowerCase();
    if (!tables.has(t)) tables.set(t, new Set());
    tables.get(t).add(m[2].toLowerCase());
  }

  return tables;
}

/**
 * Declared vs live.
 *
 * @param {Map<string, Set<string>>} declared
 * @param {Map<string, Set<string>>} live
 */
function diffSchema(declared, live) {
  const missingTables = [];
  const missingColumns = [];
  const undeclaredTables = [];

  for (const [t, cols] of declared) {
    if (!live.has(t)) { missingTables.push(t); continue; }
    for (const c of cols) if (!live.get(t).has(c)) missingColumns.push(`${t}.${c}`);
  }
  // ⛔ THE REVERSE DIRECTION IS INFORMATIONAL, NEVER A FAILURE. A live table
  // that schema.sql does not declare is usually a partition or a table a
  // migration created; failing on it would train the next person to delete this
  // check, which costs more than the coverage it gives up.
  for (const t of live.keys()) {
    if (!declared.has(t) && !/^syslog_events_\d{8}$/.test(t)) undeclaredTables.push(t);
  }

  return { missingTables, missingColumns, undeclaredTables };
}

// ───────────────────────────────────────────────────────────────────────────
// 8. THE REGISTRY
// ───────────────────────────────────────────────────────────────────────────
//
// `args` receives a context and returns the arguments AFTER `pool`.
// `spec` is what the function's own callers destructure — no more, so a
// tightened spec here can never be the reason a genuine query is reported
// broken.
//
// ⛔ WINDOW ARGUMENTS ARE THE SMALLEST THE FUNCTION ACCEPTS. Several clamp to a
// 1-hour / 1-day floor (`clampHours`, `clampDays`), which is then the bound;
// statement_timeout is the ceiling under all of them.

const RAW = { array: true };

const REGISTRY = [
  // ── feed status (the v2.86.1 query's own module) ────────────────────────
  { mod: 'lib/feedStatus.js', fn: 'getLastSyncs', args: () => [], spec: { array: true, rowKeys: ['feed_name', 'status', 'started_at', 'finished_at'] } },
  { mod: 'lib/feedStatus.js', fn: 'getLatestPerFeed', args: () => [], spec: { array: true } },
  { mod: 'lib/feedStatus.js', fn: 'getSyncPillStatus', args: () => [{}], spec: { object: ['state', 'ok', 'label', 'title', 'feeds', 'lastSyncs'] } },

  // ── the dashboard headline ──────────────────────────────────────────────
  { mod: 'lib/engines/fleetHeadline.js', fn: 'getDeviceRiskScores', args: () => [], spec: RAW },
  { mod: 'lib/engines/fleetHeadline.js', fn: 'getCveExposure', args: () => [], spec: { object: [] } },
  { mod: 'lib/engines/fleetHeadline.js', fn: 'getFleetHeadline', args: () => [], spec: { object: ['deviceCount', 'securityScore'] } },
  { mod: 'lib/engines/fleetHeadline.js', fn: 'getPreviousHeadline', args: () => [], spec: { nullable: true, object: [] } },

  { mod: 'lib/engines/dashboardSnapshot.js', fn: 'computeFleetCveSeverity', args: () => [], spec: { object: [] } },
  { mod: 'lib/engines/dashboardSnapshot.js', fn: 'computeFleetComplianceScores', args: () => [], spec: { object: ['overall', 'byStandard'] } },

  // ── inventory / device pages ────────────────────────────────────────────
  { mod: 'lib/engines/deviceInventory.js', fn: 'getDeviceInventory', args: () => [{ sort: 'name' }], spec: { object: ['rows', 'tiles'] } },
  { mod: 'lib/engines/deviceDiscovery.js', fn: 'getDiscoveredDevices', args: () => [], spec: { array: true } },
  { mod: 'lib/engines/connectivityHistory.js', fn: 'getFleetConnectivityNow', args: () => [], spec: { object: [] } },
  { mod: 'lib/engines/connectivityHistory.js', fn: 'getFleetConnectivityTrend', args: () => [1, 60], spec: RAW },
  { mod: 'lib/engines/connectivityHistory.js', fn: 'getDevicePollHealth', args: () => [{ days: 1 }], spec: {} },

  // ── rule hygiene / traffic correlation ──────────────────────────────────
  { mod: 'lib/engines/ruleHitCorrelation.js', fn: 'getDeviceLogCoverage', args: (c) => [1, c.now], spec: {} },
  { mod: 'lib/engines/ruleHitCorrelation.js', fn: 'getLoggedRuleHits', args: (c) => [c.deviceId, 1, c.now], needsDevice: true, spec: {} },
  { mod: 'lib/engines/ruleChangeRequests.js', fn: 'getCleanupCandidates', args: (c) => [c.deviceId], needsDevice: true, spec: { object: ['eligible', 'withheld'] } },
  { mod: 'lib/engines/ruleChangeRequests.js', fn: 'listRequests', args: (c) => [c.deviceId], needsDevice: true, spec: RAW },
  { mod: 'lib/engines/ruleChangeRequests.js', fn: 'getRequest', args: () => [NO_SUCH_UUID], spec: { nullable: true, object: [] } },

  // ── compliance ──────────────────────────────────────────────────────────
  { mod: 'lib/engines/complianceReport.js', fn: 'buildReportData', args: () => [{}], spec: { object: ['perDevice', 'fleet'] } },
  { mod: 'lib/engines/complianceReport.js', fn: 'standardCoverage', args: () => ['PCI_DSS'], spec: { object: ['total', 'mapped'] } },

  // ── CVE ─────────────────────────────────────────────────────────────────
  { mod: 'lib/engines/advisoryCuration.js', fn: 'getCurationWorklist', args: () => [], spec: {} },
  { mod: 'lib/reports/vulnerabilityPosture.js', fn: 'buildVulnerabilityReportData', args: () => [{}], spec: { object: ['errors'] } },

  // ── exposure / segmentation / applications ──────────────────────────────
  { mod: 'lib/engines/exposureQuery.js', fn: 'loadDeviceData', args: (c) => [c.deviceId], needsDevice: true, spec: { object: [] } },
  { mod: 'lib/engines/exposureQuery.js', fn: 'computeDeviceExposure', args: (c) => [c.deviceId, {}], needsDevice: true, spec: { object: [] } },
  { mod: 'lib/engines/exposureQuery.js', fn: 'computeFleetExposure', args: () => [{}], spec: { object: ['totals', 'devices', 'errors'] } },

  // ⛔ THE FOUR ANALYTICS DATA LAYERS SHIPPED 2026-09-25 (A1–A5). Every one of
  // them was outside this registry when it landed, which means `npm run dbcheck`
  // reported clean while their SQL had never once been executed against the real
  // schema — the gate whose entire purpose is catching schema drift, silently
  // not covering the newest code. `tests/dbcheckRegistry.test.js` now fails the
  // build on a `lib/engines/*Data.js` that is absent from here -- and it did,
  // catching fleetConformanceData the moment it landed.
  { mod: 'lib/engines/upgradePlanData.js', fn: 'getFleetUpgradePlan', args: () => [{}], spec: { object: [] } },
  { mod: 'lib/engines/coverageRegisterData.js', fn: 'getCoverageRegister', args: () => [{}], spec: { object: ['entries', 'summary', 'failures'] } },
  { mod: 'lib/engines/ruleConsolidationData.js', fn: 'getFleetConsolidation', args: () => [], spec: { object: [] } },
  { mod: 'lib/engines/fleetConformanceData.js', fn: 'getFleetConformance', args: () => [{}], spec: { object: ['cohorts', 'summary', 'failures'] } },

  { mod: 'lib/engines/segmentationData.js', fn: 'listFleetZones', args: () => [], spec: RAW },
  { mod: 'lib/engines/segmentationData.js', fn: 'listIntents', args: () => [], spec: RAW },
  { mod: 'lib/engines/segmentationData.js', fn: 'loadFleetRulesWithEvidence', args: (c) => [1, c.now], spec: { object: ['rules', 'rulesCollected', 'deviceCount'] } },
  { mod: 'lib/engines/segmentationData.js', fn: 'evaluateSegmentation', args: () => [{ windowDays: 1 }], spec: { object: ['intents', 'summary', 'rulesCollected'] } },

  { mod: 'lib/engines/applicationViewData.js', fn: 'listApplications', args: () => [], spec: RAW },
  { mod: 'lib/engines/applicationViewData.js', fn: 'getApplication', args: () => [NO_SUCH_UUID], spec: { nullable: true, object: [] } },
  { mod: 'lib/engines/applicationViewData.js', fn: 'loadFleet', args: () => [{ windowDays: 1 }], spec: { object: ['devices', 'devicesWithoutRules'] } },
  { mod: 'lib/engines/applicationViewData.js', fn: 'evaluateAllApplications', args: () => [{ windowDays: 1 }], spec: { object: ['applications', 'orphans', 'errors'] } },
  { mod: 'lib/engines/cloudAppsData.js', fn: 'loadFleetObjects', args: () => [], spec: {} },
  { mod: 'lib/engines/cloudAppsData.js', fn: 'summariseCloudUsage', args: () => [], spec: { object: [] } },

  // ── work queue: ten gathers, each its own query ─────────────────────────
  //
  // ⛔ Called with NO opts, exactly as notificationDispatch calls it, so the
  // two expensive sources stay on their cheap path. gatherWorkQueue isolates
  // each source, so harvestSwallowedErrors is what actually reads the verdict.
  { mod: 'lib/engines/workQueueData.js', fn: 'gatherWorkQueue', args: () => [], spec: { object: ['items', 'sources'] } },

  // ── licences / lifecycle ────────────────────────────────────────────────
  { mod: 'lib/reports/fleetLifecycle.js', fn: 'buildFleetLifecycleData', args: () => [{}], spec: { object: ['devices', 'sectionErrors'] } },

  // ── reports (each is a large multi-query gather) ─────────────────────────
  { mod: 'lib/reports/executiveSummary.js', fn: 'gatherExecutiveSummary', args: () => [{}], spec: { object: ['sections'] } },
  { mod: 'lib/reports/ruleHygiene.js', fn: 'buildRuleHygieneData', args: () => [{ windowDays: 1 }], spec: { object: ['sectionErrors'] } },
  { mod: 'lib/reports/segmentationPosture.js', fn: 'buildSegmentationPostureData', args: () => [{ windowDays: 1 }], spec: { object: ['sectionErrors'] } },
  { mod: 'lib/reports/changeAudit.js', fn: 'buildChangeAuditData', args: () => [{ days: 1 }], spec: { object: ['sectionErrors'] } },
  { mod: 'lib/reports/vpnAccessReview.js', fn: 'buildVpnAccessReviewData', args: () => [{ days: 1 }], spec: { object: ['sectionErrors'] } },
  { mod: 'lib/reports/ruleRiskByTraffic.js', fn: 'buildRuleRiskData', args: () => [{ days: 7 }], spec: { object: ['totals', 'busiest', 'concentration'] } },
  { mod: 'lib/reports/reportStats.js', fn: 'getReportStats', args: () => [], spec: { object: [] } },

  // ── traffic reporting over an arbitrary window (rollups only) ───────────
  { mod: 'lib/reports/trafficWindow.js', fn: 'windowTimeline', args: (c) => [c.window, null], spec: RAW },
  { mod: 'lib/reports/trafficWindow.js', fn: 'windowActions', args: (c) => [c.window, null], spec: RAW },
  { mod: 'lib/reports/trafficWindow.js', fn: 'windowTopHosts', args: (c) => [c.window, null, 5], spec: RAW },
  { mod: 'lib/reports/trafficWindow.js', fn: 'windowTopApplications', args: (c) => [c.window, null, 5], spec: RAW },
  { mod: 'lib/reports/trafficWindow.js', fn: 'windowProtocols', args: (c) => [c.window, null], spec: RAW },
  { mod: 'lib/reports/trafficWindow.js', fn: 'windowTopBlocked', args: (c) => [c.window, null, 5], spec: RAW },
  { mod: 'lib/reports/trafficWindow.js', fn: 'windowTopRules', args: (c) => [c.window, null, 5], spec: RAW },
  { mod: 'lib/reports/trafficWindow.js', fn: 'windowCoverage', args: (c) => [c.window], spec: {} },
  { mod: 'lib/reports/trafficWindow.js', fn: 'windowAppBytes', args: (c) => [c.window, null, c.deviceIds, 5], spec: {} },
  { mod: 'lib/reports/trafficWindow.js', fn: 'windowUrlCategories', args: (c) => [c.window, null, 5], spec: {} },
  { mod: 'lib/reports/trafficWindow.js', fn: 'windowAppCoverage', args: (c) => [c.window, null], spec: {} },
  { mod: 'lib/reports/trafficActivity.js', fn: 'buildTrafficActivityData', args: (c) => [{ from: c.window.from.toISOString(), to: c.window.to.toISOString() }], spec: { object: ['failures'] } },

  // ── syslog dashboards (rollups) ─────────────────────────────────────────
  { mod: 'lib/syslog/trafficStats.js', fn: 'getTrafficTimeline', args: () => [1, null], spec: RAW },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getTopTalkers', args: () => [1, 5], spec: RAW },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getActionBreakdown', args: () => [1, null], spec: {} },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getTopRules', args: () => [1, 5, null], spec: {} },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getIngestHealth', args: () => [15], spec: { object: [] } },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getThreatActivity', args: () => [1], spec: {} },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getClassTimeline', args: () => ['vpn', 1], spec: {} },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getTopHosts', args: () => [1, 5, null], spec: {} },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getTopApplications', args: () => [1, 5, null], spec: {} },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getWebActivity', args: () => [1, null, 5], spec: { object: ['identified', 'unattributed', 'categories', 'coverage'] } },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getProtocolBreakdown', args: () => [1, null], spec: {} },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getTopBlockedDestinations', args: () => [1, 5, null], spec: {} },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getDeviceTrafficStats', args: () => [1], spec: {} },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getTopCountries', args: () => [1, 5], spec: {} },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getTopUsers', args: () => [1, 5], spec: {} },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getTopUrlCategories', args: () => [1, 5], spec: {} },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getUserCoverageForClass', args: () => ['vpn', 1], spec: {} },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getVpnActivityByDeviceRollup', args: () => [1], spec: RAW },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getDeviceSyslogCoverage', args: (c) => [c.deviceId, 1], needsDevice: true, spec: {} },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getDeviceNamedThreats', args: (c) => [c.deviceId, 1, 5], needsDevice: true, spec: {} },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getDeviceInboundHits', args: (c) => [c.deviceId, 1, 5], needsDevice: true, spec: {} },

  // ⛔ THE TWO RAW-TABLE READS. Both carry a received_at bound and a selective
  // `log_class = 'vpn'` predicate against a partial index; the 1-hour floor is
  // the smallest `clampHours` permits. Measured at 250ms and 97ms.
  { mod: 'lib/syslog/trafficStats.js', fn: 'getVpnActivity', args: () => [1, 5], raw: true, spec: RAW },
  { mod: 'lib/syslog/trafficStats.js', fn: 'getVpnActivityByDevice', args: () => [1], raw: true, spec: RAW },

  { mod: 'lib/syslog/threatStats.js', fn: 'getTopAttackers', args: () => [1, 5], spec: {} },
  { mod: 'lib/syslog/threatStats.js', fn: 'getTopTargets', args: () => [1, 5], spec: {} },
  { mod: 'lib/syslog/threatStats.js', fn: 'getTopThreats', args: () => [1, 5], spec: {} },
  { mod: 'lib/syslog/threatStats.js', fn: 'getThreatsBySeverity', args: () => [1], spec: {} },
  { mod: 'lib/syslog/threatStats.js', fn: 'getThreatTimeline', args: () => [1], spec: {} },
  { mod: 'lib/syslog/threatStats.js', fn: 'getDeviceThreatSummary', args: () => [1], spec: {} },
  { mod: 'lib/syslog/threatStats.js', fn: 'getThreatCoverage', args: () => [1], spec: {} },

  // ── log search: the only registered reader of the raw partitioned table ──
  //
  // ⛔ A 20-MINUTE WINDOW, THE NARROWEST THIS TOOL EVER ASKS FOR, and it is the
  // one call that exercises logSearch's dedicated-client `SET LOCAL
  // statement_timeout` transaction — which is why the pool proxy wraps
  // `connect()` and not just `query`.
  { mod: 'lib/syslog/logSearch.js', fn: 'searchEvents', args: (c) => [{ from: c.window20.from.toISOString(), to: c.window20.to.toISOString(), limit: 5 }, c.now], raw: true, spec: { object: ['rows', 'timedOut'] } },
  { mod: 'lib/syslog/logSearch.js', fn: 'getFilterOptions', args: () => [1], raw: true, spec: {} },

  // ── VPN ─────────────────────────────────────────────────────────────────
  { mod: 'lib/syslog/vpnAuthStats.js', fn: 'getVpnLoginLocations', args: () => [1], spec: { object: [] } },
  { mod: 'lib/syslog/vpnPresence.js', fn: 'getVpnUserPresence', args: (c) => [{ days: 1, topUsers: 5, now: c.now }], spec: { object: [] } },
  { mod: 'lib/engines/vpnDetections.js', fn: 'getVpnDetections', args: (c) => [{ hours: 1, baselineDays: 1, now: c.now }], spec: { object: ['detections'] } },
  { mod: 'lib/engines/vpnTrafficAttribution.js', fn: 'getVpnUserTraffic', args: () => [{ days: 1, topUsers: 5 }], spec: { object: ['coverage'] } },
  { mod: 'lib/engines/vpnTunnelHealth.js', fn: 'getVpnTunnelHealth', args: (c) => [{ now: c.now, pollEvidenceLookbackDays: 1 }], spec: { object: [] } },

  // ── infrastructure / health ─────────────────────────────────────────────
  { mod: 'lib/serverHealth.js', fn: 'getDatabaseSize', args: () => [], spec: { object: [] } },
  { mod: 'lib/serverHealth.js', fn: 'getSyslogRetention', args: () => [], spec: { object: [] } },
  { mod: 'lib/serverHealth.js', fn: 'getIngestHealth', args: () => [15], spec: { object: [] } },
  { mod: 'lib/serverHealth.js', fn: 'getServiceLiveness', args: () => [], spec: {} },

  // ── per-user storage and directory mappings ─────────────────────────────
  //
  // A UUID that matches nothing still executes and still validates the SQL; no
  // fabricated row is needed to prove a query parses.
  { mod: 'lib/savedViews.js', fn: 'listSavedViews', args: () => [NO_SUCH_UUID, 'devices'], spec: RAW },
  { mod: 'lib/savedViews.js', fn: 'getDefaultView', args: () => [NO_SUCH_UUID, 'devices'], spec: { nullable: true, object: [] } },
  { mod: 'lib/ldapRoles.js', fn: 'loadMappings', args: () => [], spec: RAW },

  // ── background job ledger (readers only) ────────────────────────────────
  { mod: 'lib/engines/backgroundJobs.js', fn: 'getJob', args: () => [NO_SUCH_UUID], spec: { nullable: true, object: [] } },
  { mod: 'lib/engines/backgroundJobs.js', fn: 'getLiveJobForDevice', args: (c) => [c.deviceId, 'collect'], needsDevice: true, spec: { nullable: true, object: [] } },
  { mod: 'lib/engines/backgroundJobs.js', fn: 'getLatestJobForDevice', args: (c) => [c.deviceId, 'collect'], needsDevice: true, spec: { nullable: true, object: [] } },
];

// ───────────────────────────────────────────────────────────────────────────
// 9. THE RUNNER (impure)
// ───────────────────────────────────────────────────────────────────────────

function entryName(e) {
  return `${path.basename(e.mod, '.js')}.${e.fn}`;
}

async function liveSchema(pool) {
  // ⛔ pg_catalog, NOT information_schema. information_schema hides every table
  // the current role has no privilege on, so the six deliberately-denied tables
  // would read as MISSING FROM THE DATABASE — a confident, completely wrong
  // answer, and exactly the false alarm this tool must not produce.
  const { rows } = await pool.query(
    `SELECT c.relname AS t, a.attname AS c
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
       JOIN pg_attribute a ON a.attrelid = c.oid
      WHERE n.nspname = 'public'
        AND c.relkind IN ('r', 'p')
        AND a.attnum > 0
        AND NOT a.attisdropped`
  );
  const live = new Map();
  for (const r of rows) {
    if (!live.has(r.t)) live.set(r.t, new Set());
    live.get(r.t).add(r.c);
  }
  return live;
}

async function grantAudit(pool, declared) {
  const { rows } = await pool.query(
    `SELECT c.relname AS t, has_table_privilege(current_user, c.oid, 'SELECT') AS ok
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')`
  );
  const sel = new Map(rows.map((r) => [r.t, r.ok]));
  // A declared table this role cannot read AND that is not on the
  // deliberately-denied list is a missing per-table GRANT SELECT.
  const missingGrants = [...declared.keys()].filter(
    (t) => sel.has(t) && !sel.get(t) && !EXPECTED_UNREADABLE.includes(t)
  );
  // The reverse: a denied table that became readable is a policy REGRESSION and
  // is the more serious direction — device_credentials readable by a
  // diagnostics role is a credential exposure, not a cosmetic drift.
  const deniedNowReadable = EXPECTED_UNREADABLE.filter((t) => sel.get(t) === true);
  return { missingGrants, deniedNowReadable };
}

async function discoverContext(pool, now) {
  // ⛔ DISCOVERED, NEVER PINNED. A hardcoded device id rots the moment that
  // firewall is removed, and the sweep would then report a query as broken
  // because its fixture went away. Preferring a device that HAS rules is what
  // makes the join-heavy readers exercise a populated path.
  let deviceId = null;
  let deviceName = null;
  let deviceIds = [];
  try {
    const { rows } = await pool.query(
      `SELECT d.id, d.name, count(r.id)::int AS rules
         FROM devices d
         LEFT JOIN firewall_rules r ON r.device_id = d.id
        WHERE d.active = true
        GROUP BY d.id, d.name
        ORDER BY rules DESC, d.name`
    );
    deviceIds = rows.map((r) => r.id);
    if (rows[0]) { deviceId = rows[0].id; deviceName = rows[0].name; }
  } catch { /* reported below as a blocked per-device group, never silently */ }

  const to = now;
  return {
    now,
    deviceId,
    deviceName,
    deviceIds,
    // A 3-hour window for the hourly rollups: a 20-minute one can contain zero
    // `bucket_hour` buckets, which would leave every row shape unverified.
    window: { from: new Date(to.getTime() - 3 * 3600 * 1000), to, clamped: false },
    window20: { from: new Date(to.getTime() - RAW_WINDOW_MINUTES * 60 * 1000), to, clamped: false },
  };
}

async function runEntry(entry, makeGuarded, ctx) {
  const name = entryName(entry);
  const started = Date.now();
  let statements = 0;
  const guarded = makeGuarded(() => { statements++; });

  if (entry.needsDevice && !ctx.deviceId) {
    return {
      name,
      ms: 0,
      state: 'blocked',
      reason: 'no active device could be discovered, so this per-device query was NOT run',
      notes: [],
      statements: 0,
    };
  }

  let mod;
  try {
    mod = require(path.join(REPO, entry.mod));
  } catch (err) {
    return { name, ms: Date.now() - started, state: 'fail', reason: `could not require ${entry.mod}: ${err.message}`, notes: [], statements: 0 };
  }
  const fn = mod[entry.fn];
  if (typeof fn !== 'function') {
    return { name, ms: Date.now() - started, state: 'fail', reason: `${entry.mod} does not export ${entry.fn} — the registry is stale`, notes: [], statements: 0 };
  }

  try {
    const value = await fn(guarded, ...entry.args(ctx));
    return classifyResult({ name, ms: Date.now() - started, value, spec: entry.spec, statements });
  } catch (err) {
    return classifyResult({ name, ms: Date.now() - started, error: err, spec: entry.spec, statements });
  }
}

const MARK = { ok: 'ok     ', fail: 'FAIL   ', blocked: 'blocked' };

async function main(argv) {
  const only = (argv.find((a) => a.startsWith('--only=')) || '').slice(7);
  const schemaOnly = argv.includes('--schema-only');
  const skipRaw = argv.includes('--no-raw');

  assertReadOnlyRegistry(REGISTRY);

  if (argv.includes('--list')) {
    for (const e of REGISTRY) console.log(`${entryName(e)}   (${e.mod})`);
    console.log(`\n${REGISTRY.length} registered read functions.`);
    return 0;
  }

  const { Pool } = require(path.join(REPO, 'node_modules', 'pg'));
  const pool = new Pool({
    connectionString: READONLY_URL,
    statement_timeout: STATEMENT_TIMEOUT_MS,
    max: 4,
    application_name: 'secvault-dbcheck',
  });
  pool.on('error', () => { /* an idle-client error must not crash the sweep */ });

  const started = Date.now();
  let whoami;
  try {
    // ⛔ FAILS LOUDLY. A skip here is the guard-that-cannot-fire pattern.
    // The privilege columns are read in the SAME round trip as the identity
    // ones, so there is no window in which the sweep knows who it is and has
    // not yet asked what that role may do.
    const { rows } = await pool.query(
      `SELECT current_user AS who,
              current_database() AS db,
              version() AS version,
              (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS superuser,
              (SELECT count(*)::int FROM pg_class c
                 JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
                  AND (has_table_privilege(current_user, c.oid, 'INSERT')
                    OR has_table_privilege(current_user, c.oid, 'UPDATE')
                    OR has_table_privilege(current_user, c.oid, 'DELETE'))) AS writable_tables,
              (SELECT string_agg(t, ', ') FROM (
                 SELECT c.relname AS t FROM pg_class c
                   JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
                    AND (has_table_privilege(current_user, c.oid, 'INSERT')
                      OR has_table_privilege(current_user, c.oid, 'UPDATE')
                      OR has_table_privilege(current_user, c.oid, 'DELETE'))
                  ORDER BY c.relname LIMIT 5) s) AS writable_sample`
    );
    whoami = rows[0] || {};
  } catch (err) {
    console.error(`[dbcheck] CANNOT CONNECT: ${err.message}`);
    console.error('[dbcheck] Set DBCHECK_URL, or check that PostgreSQL is reachable. Nothing was checked.');
    await pool.end().catch(() => {});
    return 2;
  }

  // ⛔ GUARD 1, ENFORCED. Printing current_user and moving on is not a guard.
  const role = assertReadOnlyRole({
    user: whoami.who,
    superuser: whoami.superuser,
    writableTables: whoami.writable_tables,
    writableSample: whoami.writable_sample,
  });
  if (!role.ok) {
    console.error(`[dbcheck] REFUSING TO RUN: ${role.reason}`);
    console.error('[dbcheck] Nothing was checked. This tool calls the product\'s own read functions against a live database; the read-only role is the first of its three guards and it is not optional.');
    await pool.end().catch(() => {});
    return 2;
  }

  console.log(`[dbcheck] ${whoami.db} as "${whoami.who}" — ${String(whoami.version).split(',')[0]}`);
  console.log(`[dbcheck] role verified read-only: 0 writable tables in public, not a superuser`);
  console.log(`[dbcheck] statement_timeout ${STATEMENT_TIMEOUT_MS}ms, raw-table window ${RAW_WINDOW_MINUTES} min\n`);

  // ── schema ────────────────────────────────────────────────────────────
  const declared = parseSchemaSql(fs.readFileSync(path.join(REPO, 'lib', 'schema.sql'), 'utf8'));
  const live = await liveSchema(pool);
  const schema = diffSchema(declared, live);
  const grants = await grantAudit(pool, declared);

  console.log(`── schema: ${declared.size} tables declared in lib/schema.sql vs the live catalog`);
  if (schema.missingTables.length === 0 && schema.missingColumns.length === 0) {
    console.log('  ok      every declared table and column exists');
  } else {
    for (const t of schema.missingTables) {
      console.log(`  FAIL    table ${t} is declared in lib/schema.sql and DOES NOT EXIST on this database`);
    }
    for (const c of schema.missingColumns) {
      console.log(`  FAIL    column ${c} is declared and DOES NOT EXIST — the CREATE TABLE IF NOT EXISTS trap: add an ALTER TABLE ... ADD COLUMN IF NOT EXISTS`);
    }
    console.log('          (on a checkout ahead of the deployed server this is deploy lag: run node lib/migrate.js there and re-run.)');
  }
  for (const t of grants.missingGrants) {
    console.log(`  FAIL    table ${t} exists but the readonly role cannot SELECT it — add a per-table GRANT in lib/schema-grants.sql`);
  }
  for (const t of grants.deniedNowReadable) {
    console.log(`  FAIL    table ${t} is READABLE by the readonly role and must not be — this is a secret-exposure regression in lib/schema-grants.sql`);
  }
  if (schema.undeclaredTables.length) {
    console.log(`  note    ${schema.undeclaredTables.length} live table(s) are not declared in lib/schema.sql: ${schema.undeclaredTables.join(', ')}`);
  }
  console.log('');

  const schemaFailures = schema.missingTables.length + schema.missingColumns.length
    + grants.missingGrants.length + grants.deniedNowReadable.length;

  if (schemaOnly) {
    await pool.end().catch(() => {});
    console.log(`[dbcheck] --schema-only: ${schemaFailures} schema problem(s).`);
    return schemaFailures === 0 ? 0 : 1;
  }

  // ── the reads ─────────────────────────────────────────────────────────
  let statements = 0;
  const makeGuarded = (tick) => readOnlyPool(pool, (v) => { statements++; tick(v); });

  const ctx = await discoverContext(pool, new Date());
  console.log(ctx.deviceId
    ? `── reads: per-device queries use "${ctx.deviceName}" (${ctx.deviceId})`
    : '── reads: NO active device discovered — every per-device query will be reported blocked, not passed');

  const selected = REGISTRY
    .filter((e) => (only ? entryName(e).toLowerCase().includes(only.toLowerCase()) || e.mod.toLowerCase().includes(only.toLowerCase()) : true))
    .filter((e) => (skipRaw ? !e.raw : true));

  if (selected.length === 0) {
    console.error(`[dbcheck] --only=${only} matched nothing. Use --list.`);
    await pool.end().catch(() => {});
    return 2;
  }

  const results = [];
  // Sequential on purpose: this runs against a database carrying a live syslog
  // ingest, and a burst of concurrent aggregate queries is exactly the load
  // this tool must not add.
  for (const entry of selected) results.push(await runEntry(entry, makeGuarded, ctx));

  console.log('');
  const width = Math.max(...results.map((r) => r.name.length));
  for (const r of results) {
    console.log(`  ${MARK[r.state]} ${String(r.ms).padStart(6)}ms ${String(r.statements || 0).padStart(3)}q  ${r.name.padEnd(width)}${r.reason ? '  ' + r.reason : ''}`);
    for (const n of r.notes || []) console.log(`  ${' '.repeat(16)}  ${r.name.padEnd(width)}  note: ${n}`);
  }

  const slowest = [...results].sort((a, b) => b.ms - a.ms).slice(0, 5);
  console.log(`\n── slowest: ${slowest.map((r) => `${r.name} ${r.ms}ms`).join(' · ')}`);

  const verdict = summariseRun(
    results,
    { missingTables: schema.missingTables, missingColumns: schema.missingColumns },
    grants
  );
  const secs = ((Date.now() - started) / 1000).toFixed(1);
  console.log(`\n[dbcheck] ${results.length} read functions, ${statements} statements, ${secs}s`);
  console.log(`[dbcheck] ${verdict.counts.ok} ok · ${verdict.counts.fail} failed · ${verdict.counts.blocked} blocked · ${verdict.unverified} shape(s) unverified · ${verdict.grantProblems} grant problem(s)`);
  console.log(`[dbcheck] ${verdict.sentence}`);

  await pool.end().catch(() => {});
  return (verdict.exitCode === 0 && schemaFailures === 0) ? 0 : 1;
}

// Only sweep when RUN. `require`d (by its test) this file must open no socket.
if (require.main === module) {
  main(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((err) => {
      console.error(`[dbcheck] harness error: ${err && err.stack ? err.stack : err}`);
      process.exit(2);
    });
}

module.exports = {
  // pure, and exported so tests/dbCheckHarness.test.js can feed them the
  // failure shapes a live green run never produces
  assertReadOnlyRole,
  checkReadOnlyName,
  assertReadOnlyRegistry,
  splitStatements,
  guardStatement,
  classifyError,
  checkShape,
  harvestSwallowedErrors,
  harvestTruncation,
  classifyResult,
  summariseRun,
  parseSchemaSql,
  diffSchema,
  entryName,
  // data
  REGISTRY,
  READ_VERBS,
  WRITE_VERBS,
  EXPECTED_UNREADABLE,
  DEFECT_CODES,
  RAW_WINDOW_MINUTES,
};
