'use strict';

// tests/dbcheckRegistry.test.js
//
// ⛔ THE GATE THAT VERIFIES READ SQL WAS NOT COVERING THE NEWEST CODE.
//
// `npm run dbcheck` calls every registered READ function against the real
// database, which is how a column that `schema.sql` declares but the live
// database lacks gets caught. CLAUDE.md describes it as "every READ function's
// SQL executes against the real schema".
//
// It is a HAND-MAINTAINED registry, and on 2026-09-25 FOUR data layers shipped
// in one day — `upgradePlanData` (A1), `coverageRegisterData` (A2),
// `ruleConsolidationData` (A4) and `fleetConformanceData` (A5) — and not one of
// them was in it. dbcheck reported clean the whole time, because a registry
// with no completeness test cannot tell "this function passed" from "nobody
// ever asked about this function".
//
// ⛔ That is the guard-that-cannot-fire pattern this codebase names more often
// than any other, aimed at the gate that exists to catch schema drift. It is
// not hypothetical here: A3's own build used `rule_analysis_results.created_at`,
// a column that does not exist (it is `analyzed_at`), and dbcheck was the gate
// that should have caught it. It did not, because that engine was outside the
// registry too.
//
// dbcheck itself already fails when a registered function has DISAPPEARED
// ("the registry is stale"). This is the other direction: a function that was
// never registered at all.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const ENGINES = path.join(ROOT, 'lib', 'engines');
const DBCHECK = path.join(ROOT, 'scripts', 'dbcheck.js');

// ⛔ `*Data.js` is the repo's own naming convention for "the pool-taking half of
// a pure engine" — segmentationData, applicationViewData, coverageRegisterData.
// Those are exactly the files whose SQL only ever runs in production unless
// dbcheck runs it, so they are what this test insists on.
const DATA_LAYER = /Data\.js$/;

// ⛔ NAMED EXEMPTIONS WITH A REASON EACH, never a silent suppression — the same
// convention `deviceScopeCoverage.js`'s TRANSITIVE_ALLOWED follows. A test below
// fails on an exemption that is no longer needed, so this list cannot rot into
// a place where things get hidden.
const EXEMPT = Object.freeze({
  // (none today — every *Data.js in lib/engines is registered)
});

function dataLayers() {
  return fs.readdirSync(ENGINES).filter((f) => DATA_LAYER.test(f)).sort();
}

function dbcheckSource() {
  return fs.readFileSync(DBCHECK, 'utf8');
}

describe('⛔ dbcheck covers every engine data layer', () => {
  it('there are data layers to check (the glob still matches something)', () => {
    // A convention change that stopped matching would make every assertion
    // below vacuously true — the failure mode this whole file is about.
    const files = dataLayers();
    assert.ok(files.length >= 5,
      `expected several lib/engines/*Data.js files, found ${files.length}`);
  });

  it('⛔ every lib/engines/*Data.js appears in the dbcheck registry', () => {
    const src = dbcheckSource();
    const missing = dataLayers().filter((f) => {
      if (EXEMPT[f]) return false;
      return !src.includes(`lib/engines/${f}`);
    });
    assert.deepEqual(missing, [],
      'these data layers ship SQL that dbcheck never executes against the real '
      + 'schema, so a column that does not exist would reach production with the '
      + 'gate reporting clean:\n  ' + missing.join('\n  '));
  });

  it('every exemption names a file that still exists and still needs one', () => {
    const files = new Set(dataLayers());
    const src = dbcheckSource();
    for (const [file, reason] of Object.entries(EXEMPT)) {
      assert.ok(files.has(file), `exemption for ${file}, which no longer exists — remove it`);
      assert.ok(typeof reason === 'string' && reason.length > 20,
        `exemption for ${file} needs a real reason, not "${reason}"`);
      assert.ok(!src.includes(`lib/engines/${file}`),
        `${file} IS registered now — its exemption is stale and should be removed`);
    }
  });

  it('the registry entries name functions the modules actually export', () => {
    // dbcheck fails at RUNTIME on a stale entry ("does not export"), but that
    // needs a database. This catches a typo in the same commit that makes it.
    const src = dbcheckSource();
    const entries = [...src.matchAll(/mod:\s*'(lib\/engines\/[^']+)'\s*,\s*fn:\s*'([^']+)'/g)];
    assert.ok(entries.length > 30, 'expected a substantial registry');

    const bad = [];
    for (const [, mod, fn] of entries) {
      const abs = path.join(ROOT, mod);
      if (!fs.existsSync(abs)) { bad.push(`${mod} (file missing)`); continue; }
      // ⛔ Source scan, not require(): requiring pulls in lib/db.js and would
      // open a real pool from a unit test.
      const text = fs.readFileSync(abs, 'utf8');
      if (!new RegExp(`\\b${fn}\\b`).test(text)) bad.push(`${mod} does not mention ${fn}`);
    }
    assert.deepEqual(bad, [], bad.join('\n  '));
  });
});
