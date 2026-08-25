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
