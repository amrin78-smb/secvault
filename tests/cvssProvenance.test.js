// tests/cvssProvenance.test.js
//
// ⛔ WHY THIS EXISTS. The fleet CVE-severity histogram alternated between two
// states on IDENTICAL totals:
//
//     15 / 33 / 99 / 21  = 168
//      4 / 11 / 66 / 87  = 168
//
// The same 168 assessments, bucketed completely differently, day to day. The
// snapshot code was correct; the SCORES were changing underneath it.
//
// Cause: NVD and the CIRCL fallback both pick a score with the cascade
// v4 > v3.1 > v3.0 > v2, taking whichever version the record happens to carry.
// NVD frequently exposes only v3.1 for a CVE whose CNA record — which is what
// CIRCL returns — also carries v4.0. Different version, different number, same
// CVE. CIRCL is consulted only when an NVD request fails at the NETWORK level,
// so which source answered on a given day was effectively random, and the
// fleet's severity picture moved with it.
//
// The fix is precedence, not normalisation: a CIRCL score may FILL A GAP but
// may never overwrite one NVD supplied. This file pins that, because it lives
// in a 40-line SQL string where a future edit could quietly drop a clause and
// nothing would fail until a histogram started swinging again months later.
//
// ⛔ These are SQL-shape assertions, not a database test. Nothing here connects
// to Postgres (tests/README.md). What is being defended is the presence and
// direction of the precedence rule, which is exactly the part that would be
// lost in a careless edit.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const SRC = fs.readFileSync(
  path.join(__dirname, '..', 'lib', 'feeds', 'nvd.js'),
  'utf8'
);
const SCHEMA = fs.readFileSync(
  path.join(__dirname, '..', 'lib', 'schema.sql'),
  'utf8'
);

describe('CVSS provenance is recorded', () => {
  it('advisories carries cvss_source and cvss_version, added by ALTER', () => {
    // ⛔ ALTER, never a CREATE TABLE body edit: advisories exists on every
    // deployed server already, so a column added only to the CREATE body would
    // silently never appear there (CLAUDE.md's IF NOT EXISTS rule).
    assert.match(SCHEMA, /ALTER TABLE advisories ADD COLUMN IF NOT EXISTS cvss_source TEXT/);
    assert.match(SCHEMA, /ALTER TABLE advisories ADD COLUMN IF NOT EXISTS cvss_version TEXT/);
  });

  it('both pickers report the CVSS version they used', () => {
    // The version is the evidence that two sources disagreed. A picker that
    // returns only a number cannot explain why the number moved.
    assert.match(SRC, /\['cvssMetricV40', '4\.0'\]/);
    assert.match(SRC, /\['cvssV4_0', '4\.0'\]/);
    assert.match(SRC, /return \{ score: null, vector: null, version: null \}/);
  });

  it('each record is tagged with the source that produced it', () => {
    assert.match(SRC, /cvss_source: 'nvd'/);
    assert.match(SRC, /cvss_source: 'circl'/);
  });
});

describe('NVD outranks CIRCL', () => {
  it('⛔ a CIRCL score never overwrites an existing non-CIRCL score', () => {
    // The guard has three parts and all three are load-bearing:
    //   the incoming row is CIRCL, the stored row is NOT CIRCL, and a stored
    //   score actually exists. Drop any one and CIRCL starts winning again.
    assert.match(SRC, /WHEN EXCLUDED\.cvss_source = 'circl'/);
    assert.match(SRC, /AND advisories\.cvss_source IS DISTINCT FROM 'circl'/);
    assert.match(SRC, /AND advisories\.cvss_score IS NOT NULL/);
  });

  it('⛔ the guard is applied to score, vector AND provenance together', () => {
    // A score kept from NVD beside a vector taken from CIRCL would be a
    // record that contradicts itself — and cvss_source would then name the
    // wrong origin, which is worse than not recording it at all.
    const guards = SRC.match(/WHEN EXCLUDED\.cvss_source = 'circl'/g) || [];
    assert.equal(
      guards.length,
      4,
      'expected the CIRCL guard on cvss_score, cvss_vector, cvss_source and cvss_version'
    );
  });

  it('⛔ the cross-vendor guard still runs FIRST', () => {
    // advisories.cve_id is UNIQUE with a single vendor, so a shared-library CVE
    // stays with whichever vendor ingested it first. Source precedence must not
    // become a way around that: a different vendor's row is never touched,
    // whatever the source.
    const firstClause = /cvss_score = CASE\s*\n\s*WHEN advisories\.vendor <> EXCLUDED\.vendor THEN advisories\.cvss_score/;
    assert.match(SRC, firstClause);
  });

  it('CIRCL still fills a genuine gap', () => {
    // ⛔ The point is precedence, NOT ignoring CIRCL. When NVD never supplied a
    // score the fallback is the only source there is, and refusing it would
    // leave the CVE unscored — which the priority tree treats as "not scored",
    // losing a real signal. The guard requires a stored score to protect.
    assert.match(SRC, /AND advisories\.cvss_score IS NOT NULL\s*\n\s*THEN advisories\.cvss_score/);
  });
});
