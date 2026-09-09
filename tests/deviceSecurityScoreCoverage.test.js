'use strict';
// Pins the CVE-COVERAGE gate on the PER-DEVICE Security Score
// (lib/engines/deviceInventory.js's decorate()).
//
// ⛔ THE INCIDENT. Found live 2026-09-09 on the Devices page: OKF(F2) rendered
// **100 / 100** under the label "Not analysed". It was the one device in the
// fleet that had never been collected at all — no version, no rules, no
// config, no CVE assessment. The product showed a perfect security score for
// the device it knew nothing about, which is the most reassuring possible
// number in exactly the worst place: an operator scanning that column would
// skip the only firewall that needed attention.
//
// ⛔ ROOT CAUSE, and why it is invisible. Two of the three components were
// already honest — hygiene passes `[]` when no analysis rows exist, compliance
// passes `null` when nothing is measurable — so both correctly dropped out of
// the denominator. The vulnerability component did not. `patch_now_count` and
// `scheduled_count` are COALESCEd to 0 in the inventory query, and
// vulnerabilitySubscore reads "0 of 1 devices carry a patch_now finding" as a
// flawless 100. It then became the ONLY measurable component, so the weighted
// mean of one perfect component is 100. Nothing throws, nothing fails a build,
// and every intermediate value is a plausible integer.
//
// NEVER ASSESSED was being recorded as NO VULNERABILITIES FOUND —
// CLAUDE.md's most-repeated bug class ("a failed read is NOT a measurement"),
// the same shape as hit_count's old `NOT NULL DEFAULT 0`, one layer up from
// the SQL.
//
// ⛔ WHAT MUST NOT BE "FIXED" ALONG WITH IT, and is asserted below: a MEASURED
// zero is a real, good result. A device that WAS assessed and carries no
// patch_now/scheduled finding must keep scoring 100 on vulnerability. Making
// zero pessimistic is the same bug pointed the other way, and it is the
// tempting wrong fix because it also makes OKF(F2) stop reading 100.
//
// ⛔ NO DATABASE, same convention as every other test here (tests/README.md).
// decorate() is pure — it takes one already-fetched row and returns it
// decorated — so the rows below are canned. The one thing that needs the real
// file is the projection check at the bottom: decorate cannot read a coverage
// signal the query never SELECTs, and a missing projection is itself a failed
// read (see the licence_row_count ⛔ block in deviceInventory.js, where exactly
// that happened and silently made a tile lie about 15 devices).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { decorate } = require('../lib/engines/deviceInventory');
const { WEIGHTS } = require('../lib/engines/securityScore');

// --------------------------------------------------------------------------
// Row factory — the exact column set decorate() reads, defaulting to the
// live OKF(F2) shape: collected from, but never CVE-assessed.
// --------------------------------------------------------------------------
function row(overrides = {}) {
  return {
    id: 'b9bbf8db-77dd-472c-9af8-d985dd1194b1',
    name: 'OKF(F2)',
    critical_findings: 0,
    high_findings: 0,
    medium_findings: 0,
    info_findings: 0,
    patch_now_count: 0,
    scheduled_count: 0,
    monitor_count: 0,
    assessment_count: 0,
    last_cve_assessed_at: null,
    compliance_pct: null,
    ...overrides,
  };
}

const componentOf = (d, key) => d.securityComponents.find((c) => c.key === key);

describe('per-device security score: never-assessed is not "no vulnerabilities found"', () => {
  it('a device with NOTHING collected scores null, not 100 — the OKF(F2) incident', () => {
    // The original row exactly: no findings, no compliance, no assessment.
    const d = decorate(row());
    assert.equal(
      d.securityScore,
      null,
      'a device SecVault knows nothing about must render "not measured", never a perfect score'
    );
    assert.equal(d.securityBand, null, 'and it must not be labelled "excellent" either');
  });

  it('the vulnerability component itself reports not-measurable, so the 40% drops out', () => {
    const d = decorate(row());
    assert.equal(componentOf(d, 'vulnerability').score, null);
    assert.equal(componentOf(d, 'hygiene').score, null);
    assert.equal(componentOf(d, 'compliance').score, null);
  });

  it('an unmeasurable vulnerability component is DROPPED from the denominator, never scored 0', () => {
    // Rules analysed and compliance measured, but the CVE matcher has never
    // run. The composite must be the weighted mean of the TWO measurable
    // components only. Scoring vulnerability 0 would report a data gap as a
    // security problem; scoring it 100 is the bug this file exists for.
    const d = decorate(
      row({ critical_findings: 1, compliance_pct: '50' })
    );
    const hygiene = componentOf(d, 'hygiene').score;
    const compliance = componentOf(d, 'compliance').score;
    assert.equal(componentOf(d, 'vulnerability').score, null);
    assert.notEqual(hygiene, null);
    assert.equal(compliance, 50);

    const expected = Math.round(
      (hygiene * WEIGHTS.hygiene + compliance * WEIGHTS.compliance) /
        (WEIGHTS.hygiene + WEIGHTS.compliance)
    );
    assert.equal(d.securityScore, expected);
    assert.ok(
      d.securityScore > 0,
      'dropping the component must not be implemented as scoring it 0'
    );
  });
});

describe('per-device security score: a MEASURED zero still scores well', () => {
  it('assessed, and no patch_now/scheduled finding, scores vulnerability 100', () => {
    // ⛔ THE COUNTER-TEST. "0 CVEs" is a real, earned result when a match ran.
    // Only the ABSENCE OF A RUN is unmeasurable. If this ever fails, someone
    // has fixed the incident above by making zero pessimistic.
    const d = decorate(row({ last_cve_assessed_at: new Date('2026-09-09T02:00:00Z') }));
    assert.equal(componentOf(d, 'vulnerability').score, 100);
    assert.equal(d.securityScore, 100, 'nothing else is measurable, so the composite is that 100');
  });

  it('a device with real exposure still scores vulnerability 0 — the gate did not disarm the engine', () => {
    const d = decorate(
      row({ last_cve_assessed_at: new Date('2026-09-09T02:00:00Z'), patch_now_count: 3 })
    );
    assert.equal(componentOf(d, 'vulnerability').score, 0);
  });
});

describe('per-device security score: the two coverage signals are ORed, not ANDed', () => {
  it('assessment rows alone prove a run, even with no stamp — the already-deployed row', () => {
    // devices.last_cve_assessed_at is NULL on every row deployed before the
    // column shipped, until the matcher next runs. Requiring the stamp alone
    // would report the entire fleet as unmeasured on day one.
    const d = decorate(row({ assessment_count: 10, scheduled_count: 10 }));
    assert.notEqual(componentOf(d, 'vulnerability').score, null);
  });

  it('the stamp alone proves a run, even with zero rows — the assessed-and-clean device', () => {
    // The converse blind spot: matchDeviceToAdvisories() emits rows only for
    // advisories that still apply and the reconciliation DELETE removes the
    // rest, so a genuinely clean device holds zero rows. Without the stamp it
    // is byte-identical to a device never touched.
    const d = decorate(row({ last_cve_assessed_at: '2026-09-09T02:00:00.000Z' }));
    assert.equal(componentOf(d, 'vulnerability').score, 100);
  });

  it('monitor-band-only rows count as assessed', () => {
    // The CVE column shows patch_now + scheduled only, so a device holding
    // nothing but monitor-band rows has both visible counts at 0 and IS fully
    // assessed. assessment_count is what covers it.
    const d = decorate(row({ assessment_count: 7, monitor_count: 7 }));
    assert.equal(componentOf(d, 'vulnerability').score, 100);
  });

  it('only the absence of BOTH signals is unmeasurable', () => {
    assert.equal(componentOf(decorate(row()), 'vulnerability').score, null);
  });
});

describe('per-device security score: the coverage signals reach decorate() at all', () => {
  const SRC = fs.readFileSync(
    path.join(__dirname, '..', 'lib', 'engines', 'deviceInventory.js'),
    'utf8'
  );
  // Code only — a comment mentioning a column must not satisfy an assertion
  // about the query projecting it.
  const CODE = SRC.replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/^\s*\/\/[^\n]*$/gm, ' ')
    .replace(/\s+/g, ' ');

  it('getDeviceRows projects both signals', () => {
    // ⛔ decorate() cannot read a column the query never SELECTs, and an
    // unprojected column reads as `undefined`, which this gate would treat as
    // "never assessed" for the WHOLE FLEET. The mirror-image of the
    // licence_row_count incident, where a lateral computed a count that was
    // never projected and every row silently got 0.
    assert.match(CODE, /d\.last_cve_assessed_at/, 'query must select devices.last_cve_assessed_at');
    assert.match(CODE, /AS assessment_count/, 'query must project assessment_count');
  });

  it('decorate gates the vulnerability component on those signals, ORed', () => {
    assert.match(
      CODE,
      /row\.last_cve_assessed_at\s*\)?\s*\|\|\s*\(?\s*row\.assessment_count/,
      'the two signals must stay ORed — ANDing them reports the whole fleet as unmeasured'
    );
  });
});
