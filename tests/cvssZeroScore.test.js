'use strict';
// tests/cvssZeroScore.test.js
//
// ⛔ THE DECISION THIS FILE PINS: A VENDOR-PUBLISHED 0.0 IS A SCORE, AND IT IS
// THE RIGHT ONE FOR THE QUESTION SECVAULT ASKS.
//
// Palo Alto publishes `baseScore: 0` with `baseSeverity: "NONE"` on advisories
// titled "Informational: Impact of <third-party CVE>" — documents whose entire
// purpose is to say PAN-OS is NOT impacted. Measured against the live bulk
// endpoint 2026-09-19: 47 of 350 records score 0, and 45 of those declare PAN-OS
// `status: "unaffected"`. Live in the database: 46 such rows, and **0 device
// assessments across all of them**.
//
// ⛔ SO THE OBVIOUS "FIX" IS THE DANGEROUS ONE. Importing CVE.org's 9.8 for
// CVE-2022-22963 over the vendor's 0 would file the Spring Framework's severity
// against a firewall whose own vendor says it is unaffected — manufacturing
// urgent work that is not real. That is the same trade already tested and
// REFUSED for the vendor-level CPE wildcard. The roadmap asserted this was a
// live mis-prioritisation ("sits in monitor when rule 3 should fire"); measured,
// there is no assessment for it at all, and the reason is the guard below.
//
// ⛔ TWO DIFFERENT GUARDS KEEP IT SAFE, AND THE FIRST VERSION OF THIS FILE
// CREDITED THE WRONG ONE. The 45 informational bulletins write `version: "All"`,
// so looksLikeVersion() rejects them whatever their status -- which is why the
// first draft of these tests PASSED WITH THE STATUS CHECK DELETED. The status
// check earns its place on different records: measured live, 261 PAN-OS version
// entries carry a non-affected status AND a real numeric version (CVE-2026-0308
// lists `unaffected: 12.2.0` beside three affected branches), and for those it
// is the only thing standing between an advisory that CLEARS a device and a
// finding against it. `mixedStatuses` is the fixture that makes the mutation
// fail; without it this file would be decoration.
//
// Fixtures are REAL CAPTURED RECORDS, per CLAUDE.md — never a hand-written
// approximation of what documentation claims a vendor returns.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  normalizePaloAltoRecord,
  extractAffectedRanges,
  matchingPanOsAffectedEntries,
  pickCvssFromPanOsRecord,
} = require('../lib/feeds/paloalto');

const F = require('./fixtures/paloAltoZeroScore');

const normalise = (rec) => normalizePaloAltoRecord(rec, matchingPanOsAffectedEntries(rec));

describe('the fixtures are the shapes this file claims they are', () => {
  // A test whose fixture silently stopped containing the case it tests is a
  // test that cannot fail. Assert the premises before asserting the behaviour.
  it('two informational records that score 0 and declare PAN-OS unaffected', () => {
    for (const key of ['informationalUnaffected', 'informationalImpactVector']) {
      const cna = F[key].containers.cna;
      assert.match(cna.title, /Informational:/i, `${key} must be an informational bulletin`);
      assert.equal(pickCvssFromPanOsRecord(F[key]).score, 0, `${key} must score 0`);
      const statuses = matchingPanOsAffectedEntries(F[key])
        .flatMap((e) => e.versions || [])
        .map((v) => v.status);
      assert.ok(statuses.length > 0, `${key} must carry a PAN-OS affected[] entry at all`);
      assert.deepEqual([...new Set(statuses)], ['unaffected']);
    }
  });

  it('one genuinely affected record, scored above zero — the positive control', () => {
    const rec = F.genuinelyAffected;
    assert.ok(pickCvssFromPanOsRecord(rec).score > 0);
    const statuses = matchingPanOsAffectedEntries(rec).flatMap((e) => e.versions || []).map((v) => v.status);
    assert.ok(statuses.includes('affected'));
  });
});

describe('⛔ an "unaffected" entry can never produce an affected range', () => {
  for (const key of ['informationalUnaffected', 'informationalImpactVector']) {
    it(`${key} (${F[key].cveMetadata.cveId}) yields no ranges`, () => {
      const ranges = extractAffectedRanges(matchingPanOsAffectedEntries(F[key]));
      assert.deepEqual(
        ranges,
        [],
        'a bulletin written to say PAN-OS is NOT affected must not match a device'
      );
      assert.deepEqual(normalise(F[key]).affected_version_ranges, []);
    });
  }

  it('and the positive control DOES produce ranges — otherwise the above proves nothing', () => {
    // Without this, deleting the whole range extractor would pass every
    // assertion in this describe block.
    const ranges = extractAffectedRanges(matchingPanOsAffectedEntries(F.genuinelyAffected));
    assert.ok(ranges.length > 0, 'a genuinely affected record must still yield ranges');
    assert.ok(ranges.every((r) => r && r.min), 'each range needs a lower bound');
  });
});

describe('⛔ an UNAFFECTED branch with a real version number is still excluded', () => {
  // THE MUTATION TEST FOR `status !== 'affected'`. The informational fixtures
  // above cannot provide it: they say version "All", which looksLikeVersion()
  // rejects on its own, so the status line can be deleted and they still pass.
  // CVE-2026-0308 says `unaffected: 12.2.0` in the same advisory as three
  // affected branches. Delete the status check and 12.2.0 becomes the range
  // 12.2.0-12.2.999 — every device on the branch the advisory explicitly
  // CLEARS would be filed as vulnerable by it.
  const rec = F.mixedStatuses;

  it('the fixture really does mix both statuses on numeric versions', () => {
    const vs = matchingPanOsAffectedEntries(rec).flatMap((e) => e.versions || []);
    const numeric = (v) => /^v?\d/i.test(String(v.version || ''));
    assert.ok(vs.some((v) => v.status === 'unaffected' && numeric(v)), 'needs a numeric unaffected');
    assert.ok(vs.some((v) => v.status === 'affected' && numeric(v)), 'needs a numeric affected');
  });

  it('only the affected branches become ranges', () => {
    const entries = matchingPanOsAffectedEntries(rec);
    const ranges = extractAffectedRanges(entries);
    const affectedVersions = entries
      .flatMap((e) => e.versions || [])
      .filter((v) => v.status === 'affected')
      .map((v) => v.version);
    const unaffectedVersions = entries
      .flatMap((e) => e.versions || [])
      .filter((v) => v.status !== 'affected')
      .map((v) => v.version);

    assert.equal(ranges.length, affectedVersions.length, 'one range per affected branch, no more');
    for (const v of unaffectedVersions) {
      assert.ok(
        !ranges.some((r) => r.min === v),
        `${v} is declared UNAFFECTED by this advisory and must not appear as a range`
      );
    }
    for (const v of affectedVersions) {
      assert.ok(ranges.some((r) => r.min === v), `${v} is affected and must appear`);
    }
  });
});

describe('⛔ the vendor score is stored as published, never repaired', () => {
  it('a 0 survives into the row as a real score with its source and scale', () => {
    const row = normalise(F.informationalUnaffected);
    assert.equal(row.cvss_score, 0, 'not null, not discarded, not replaced');
    assert.equal(row.cvss_source, 'psirt', 'so nothing downstream reads it as unscored');
    assert.equal(row.cvss_version, '3.1');
  });

  it('a 0 whose vector CONTRADICTS it is still stored verbatim', () => {
    // CVE-2021-28041 carries CVSS:4.0/.../VC:H/VI:H/VA:H with baseScore 0 — a
    // high-impact vector that cannot compute to zero. Verified against the live
    // endpoint: the vendor publishes exactly that, in one metric block. It is
    // not ours to "correct": recomputing a score from a vector would be
    // inventing a number the vendor did not publish, and pairing the score with
    // some other block's vector is the mismatch this picker exists to prevent.
    const { score, vector, version } = pickCvssFromPanOsRecord(F.informationalImpactVector);
    assert.equal(score, 0);
    assert.match(vector, /VC:H\/VI:H\/VA:H/);
    assert.equal(version, '4.0');
    const row = normalise(F.informationalImpactVector);
    assert.equal(row.cvss_score, 0);
    assert.equal(row.cvss_vector, vector, 'score and vector must leave as one triple');
  });
});

describe('⛔ the suspicious-zero report must be able to fire', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'feeds', 'cveorg.js'), 'utf8');
  const sql = src.slice(
    src.indexOf('const SUSPICIOUS_ZERO_SCORES_SQL'),
    src.indexOf('async function selectCandidates')
  );

  it('found the statement', () => {
    assert.ok(sql.length > 40 && /SELECT/i.test(sql));
  });

  it('no longer keys on cvss_source IS NULL — a condition nothing can satisfy', () => {
    // v2.104.0 stamped cvss_source on every row this feed writes, so
    // `cvss_score = 0 AND cvss_source IS NULL` has matched nothing since.
    // Measured live 2026-09-19: 0 rows, permanently. The summary reported an
    // empty list and read as clean.
    const statement = sql.replace(/^\s*\/\/.*$/gm, '');
    assert.doesNotMatch(statement, /cvss_source\s+IS\s+NULL/i);
  });

  it('reports the shape that can actually mis-band a real device', () => {
    // A severity of zero attached to a version range the advisory DOES claim.
    // Live: 3 rows, all with ranges below the current fleet.
    const statement = sql.replace(/^\s*\/\/.*$/gm, '');
    assert.match(statement, /cvss_score\s*=\s*0/i);
    assert.match(statement, /affected_version_ranges/);
  });
});
