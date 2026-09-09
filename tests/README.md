# tests/

Regression tests for SecVault's **pure** engines.

## Running

```bash
npm test              # all
node --test tests/ruleAnalysis.test.js   # one file (npm test -- <file> does NOT filter)
```

## Why Node's built-in runner and not Jest/Vitest

`node --test` ships with Node 20, which is already the runtime this app requires.
That means **zero new dependencies**: nothing extra is installed on the production
server by `Update-SecVault.ps1`'s `npm ci`, there is no config file to drift, and
no transform step between the source and what runs in production. The engines
under test are plain CommonJS, so they load exactly as `services/engine-worker.js`
loads them.

`package.json` still has **no `devDependencies` at all**. Please keep it that way
unless there is a concrete reason — see CLAUDE.md's "NEVER use `npm install`" rule.

## What belongs in here

These engines are pure — same input, same output, no DB, no network, no clock
(except where a `now` is injectable). That is exactly what is cheap to pin and
what has actually broken:

| file | pins |
|---|---|
| `ruleAnalysis.test.js` | `hit_count` tri-state: `unused` requires a MEASURED zero |
| `configAuditor.test.js` | `warning` (device's limit) vs `na` (SecVault's limit) |
| `securityScore.test.js` | the ONE polarity inversion; unmeasurable → `null`, never 0 |
| `riskScore.test.js` | higher-is-WORSE polarity; band boundaries |
| `configRetention.test.js` | the four delete protections; never-throws |

## The rule these tests exist to enforce

Nearly every bug these cover is one class: **a failed read recorded as an
affirmative value** — `hit_count` defaulting to 0, `getRules()` returning `[]`,
an unanswerable check scored as a `warning`. See CLAUDE.md's Critical Rule.

So when adding a test, always include the "we could not measure this" case, not
just the pass and fail cases. That is the one that regresses silently, because
the wrong answer is a plausible number rather than a crash.

## Conventions

- One file per engine, named `<engine>.test.js`.
- `require` the engine by relative path from `tests/`.
- Use `node:test` (`describe`/`it`) + `node:assert/strict`.
- No DB. Where an engine takes a `pool`, pass a **stub** that returns canned rows
  and records the SQL it was handed (see `configRetention.test.js`).
- Name each test after the BEHAVIOUR, not the function, and reference the real
  incident where there was one — a test called "unused is not emitted when
  hit_count is null" survives a refactor that renames the function.

## The four lint-shaped tests

Most files here pin an engine's behaviour. Three do something different — they
read the whole repo and assert a property of it. Each was written after a bug
that every other gate let through:

- `moduleLoad.test.js` — `require()`s every module under `lib/` and
  `services/`. v2.82.0 shipped a syntax error inside a template literal that
  `npm run build` never evaluated, because a server-only module is not part of
  any client bundle.
- `importIntegrity.test.js` — an identifier a page uses must be imported or
  locally defined. Caught three live instances of a symbol used with no import.
- `jsxSyntax.test.js` — every .js file parses INCLUDING its JSX, via
  next/dist/build/swc. `node --check` exits 0 on broken JSX (it never reaches
  the JSX), so `npm run build` was the only gate — tens of seconds, and
  unrunnable while parallel agents are mid-edit. This is the same check in
  ~1.5s across the whole repo.
- `sqlColumns.test.js` — every SQL identifier names a column that exists in
  `lib/schema.sql`. The dashboard home page was down for every user on
  2026-09-09 asking `feed_sync_log` for a `completed_at` it has never had; a
  SQL string is opaque to `node --check`, no test touches a schema, and a
  `force-dynamic` page's query is not executed at build.

⛔ All three are CONSERVATIVE: anything they cannot parse with confidence is
SKIPPED, not guessed at. A false failure in a repo-wide lint gets the lint
deleted, which costs more than the coverage it gives up. If one starts firing
on a legal construct, widen the skip — do not lower the assertion.

## ⛔ "fail 0" in the summary is NOT proof the tests passed

A `describe()` block that throws while being CONSTRUCTED — most commonly a
`ReferenceError` from using `it()` in a file that imported `test()`, or a bad
`require` at the top of a block — is reported as `not ok N` for the suite but is
**not counted in the `# fail` tally**. The tail of the output reads:

```
not ok 7 - snapshotLogEnabled
    error: 'it is not defined'
...
# pass 36
# fail 0      <-- says zero, and four tests never ran
```

The process still **exits 1**, so `npm test` and any CI gate are correct. What
is wrong is reading the summary. Hit on 2026-09-09 while adding tests to
`ruleChangeRequestReport.test.js`: four new assertions silently never executed
and the tail said everything was fine.

So: check the **exit code**, or grep for `^not ok`, rather than trusting the
`# fail` line — and if you add tests to an existing file, match the import that
file already uses. Both `test()` and `describe()/it()` styles appear in here and
they are not interchangeable within a file.
