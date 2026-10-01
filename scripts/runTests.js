#!/usr/bin/env node
'use strict';

// scripts/runTests.js — what `npm test` runs.
//
// ⛔ `node --test tests/` IS NODE-20-ONLY, AND THAT BROKE THE WHOLE SUITE.
// Measured 2026-10-01: on Node 22 and Node 24 the directory form is resolved as
// a MODULE, so the run dies with
// `Error: Cannot find module '<repo>/tests'` and reports `# fail 1` — zero
// tests executed, and a summary that looks like one ordinary failure rather
// than a suite that never started. The dev box runs Node 22; the production
// server runs Node 20. A script that only works on one of them is not a gate.
//
// ⛔ AND THE SHELL-GLOB FIX IS NOT PORTABLE EITHER. `node --test tests/*.test.js`
// relies on the SHELL expanding it: fine under bash, but npm runs scripts
// through cmd.exe on Windows, which does not glob — so Node 20 there would
// receive the literal pattern and fail again. Enumerating the files in JS has
// no shell and no Node-version dependence.
//
// ⛔ FINDING ZERO TEST FILES IS A FAILURE, NOT AN EMPTY PASS. `node --test` with
// no files exits 0, so a wrong directory or a renamed suffix would turn the
// repo's main gate into a green tick over nothing — the guard-that-cannot-fire
// pattern this codebase names more than any other. It exits non-zero with the
// path it looked in.
//
// Extra arguments are forwarded, so `npm test -- --test-name-pattern=foo` works.

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const TESTS_DIR = path.join(__dirname, '..', 'tests');
// A floor, not a count: it only has to be high enough that an empty or
// half-resolved directory cannot pass as a real run.
const MIN_EXPECTED_FILES = 20;

function testFiles(dir) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    console.error(`[runTests] cannot read ${dir}: ${err.message}`);
    process.exit(1);
  }
  const files = [];
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) files.push(...testFiles(full));
    else if (e.isFile() && e.name.endsWith('.test.js')) files.push(full);
  }
  return files.sort();
}

const files = testFiles(TESTS_DIR);

if (files.length < MIN_EXPECTED_FILES) {
  console.error(
    `[runTests] found only ${files.length} *.test.js under ${TESTS_DIR} — expected at least `
    + `${MIN_EXPECTED_FILES}. Refusing to report a pass over a suite that did not load. `
    + 'If the suite genuinely shrank, lower MIN_EXPECTED_FILES deliberately.'
  );
  process.exit(1);
}

const res = spawnSync(process.execPath, ['--test', ...files, ...process.argv.slice(2)], {
  stdio: 'inherit',
});

if (res.error) {
  console.error(`[runTests] could not start the test runner: ${res.error.message}`);
  process.exit(1);
}
process.exit(res.status === null ? 1 : res.status);
