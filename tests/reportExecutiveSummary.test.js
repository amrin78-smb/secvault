'use strict';
// Pins lib/reports/executiveSummary.js — the R1 "Executive Security Posture"
// PDF.
//
// ⛔ WHY THIS FILE IS UNUSUALLY STRICT ABOUT WHAT THE DOCUMENT SAYS, rather
// than about what the functions return.
//
// Every other report in this product is an analyst's artefact. The reader of
// the compliance appendix knows the fleet and will notice a device missing from
// the list; the reviewer of a rule change request is being handed the evidence
// precisely so they can disagree with it. This report is read by someone who
// will not read page two, cannot audit it, and will act on the one number on
// the cover.
//
// So the failure mode worth pinning is not a crash. It is a report that is
// SHORTER, CLEANER AND MORE REASSURING THAN THE TRUTH:
//
//   - a security score of null printed as 0, or as nothing at all;
//   - a section whose query threw simply not appearing, which reads as
//     "nothing to report";
//   - a fleet figure printed without the coverage clause that qualifies it;
//   - a capped list presented as a complete one;
//   - "no change" printed for a period that was never observed.
//
// Each of those builds clean, renders beautifully, and is wrong. They are the
// same failed-read-as-a-fact class this repo keeps finding, aimed at the
// audience least equipped to catch it — which is why the assertions below
// mostly read the rendered TEXT rather than trusting an intermediate object.
//
// NO DATABASE. The renderer is exercised against hand-built data objects, which
// is the entire reason the module splits gather from render: a null score, a
// failed section and a capped list are states the live fleet does not
// reproduce on demand. The gather is exercised against a pool stub per
// tests/README.md.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  generateExecutiveSummaryPdf,
  gatherExecutiveSummary,
  renderExecutiveSummaryPdf,
  coverageOf,
  movementOf,
  gapsOf,
  scoreDisplay,
  countDisplay,
  numOrNull,
  fmtDay,
  daysBetween,
  MAX_WORK_ITEMS,
} = require('../lib/reports/executiveSummary');
const { rankItems, summarise } = require('../lib/engines/workQueue');
const { contentStreams } = require('../lib/reports/pdfCompare');

// ── Reading the document back ──────────────────────────────────────────────

/**
 * The rendered text of a PDF, as one string.
 *
 * ⛔ pdfkit writes glyph runs as HEX STRINGS INSIDE A `TJ` ARRAY, interleaved
 * with kerning adjustments — "SecVault" is emitted as `[<536563 56> 60 <61756c74>]`.
 * So a naive search of the decompressed stream finds neither the word nor most
 * multi-word phrases: the kern numbers sit in the middle of them. Concatenating
 * ONLY the decoded hex tokens reassembles the text and drops the geometry,
 * which is exactly the right trade for these assertions (pdfCompare.js is what
 * cares about geometry).
 */
function pdfText(buf) {
  let out = '';
  for (const stream of contentStreams(buf)) {
    for (const m of stream.matchAll(/<([0-9a-fA-F]+)>/g)) {
      const hex = m[1];
      if (hex.length % 2 !== 0) continue;
      for (let i = 0; i < hex.length; i += 2) {
        out += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
      }
    }
    out += ' ';
  }
  return out;
}

// ── Fixtures ───────────────────────────────────────────────────────────────

const GENERATED_AT = new Date('2026-09-15T03:00:00Z');

function headlineValue(over = {}) {
  // Shaped on the live 16-device reference fleet: security 49, compliance 51,
  // 3 patch_now assessments, 318 high-risk rule findings.
  return {
    deviceCount: 16,
    devicesOnline: 14,
    devicesCveAssessed: 16,
    rulesTotal: 1756,
    rulesEnabled: 1281,
    patchNowCount: 3,
    devicesWithPatchNow: 3,
    highRiskCount: 318,
    complianceScore: 51,
    securityScore: 49,
    securityComponents: [
      { key: 'vulnerability', label: 'Vulnerability posture', score: 62, weight: 40 },
      { key: 'hygiene', label: 'Rule hygiene', score: 34, weight: 30 },
      { key: 'compliance', label: 'Compliance', score: 51, weight: 30 },
    ],
    ...over,
  };
}

function previousRow(over = {}) {
  return {
    // ⛔ A JS Date at LOCAL midnight — exactly what node-postgres hands back for
    // a `DATE` column. See fmtDay's own note; this fixture exists so the
    // off-by-one is reproducible in a test rather than only on a UTC+7 server.
    snapshot_date: new Date(2026, 8, 13, 0, 0, 0),
    device_count: 16,
    devices_online: 15,
    rules_total: 1754,
    rules_enabled: 1281,
    patch_now_count: 5,
    high_risk_count: 320,
    security_score: 46,
    compliance_overall_score: 51,
    ...over,
  };
}

function workValue(items, sources) {
  const ranked = rankItems(items);
  return { ranked, summary: summarise(ranked, sources || [{ key: 'cve', ok: true, count: items.length }]) };
}

function cveItem(n, over = {}) {
  return {
    type: 'cve',
    key: `cve:CVE-2026-000${n}`,
    title: `Patch CVE-2026-000${n} on 3 firewalls`,
    severity: 'critical',
    urgency: 'now',
    evidence: 'reported',
    why: 'Listed in CISA KEV and an affected version is running here.',
    affects: 'TSR-TL, ITC-SLY and 1 more',
    deviceIds: ['a', 'b', 'c'],
    count: 3,
    magnitude: 3,
    ...over,
  };
}

function complianceValue(over = {}) {
  return {
    overall: 51,
    byStandard: { PCI_DSS: 62, ISO_27001: 48, CIS_V8: 55, NIST: 44, SANS: 50 },
    byStandardCounts: {
      PCI_DSS: { pass: 38, fail: 14, warning: 8 },
      ISO_27001: { pass: 24, fail: 20, warning: 6 },
      CIS_V8: { pass: 30, fail: 18, warning: 6 },
      NIST: { pass: 18, fail: 16, warning: 7 },
      SANS: { pass: 20, fail: 14, warning: 6 },
    },
    ...over,
  };
}

const ok = (key, value) => ({ key, ok: true, value, error: null });
const failed = (key, error) => ({ key, ok: false, value: null, error });

/** A complete, fully-measured report — the ONLY shape allowed to sound clean. */
function cleanData(over = {}) {
  return {
    generatedAt: GENERATED_AT,
    company: 'Acme Holdings',
    maxWorkItems: MAX_WORK_ITEMS,
    sections: {
      headline: ok('headline', headlineValue({
        // Nothing outstanding anywhere, and full coverage: the one combination
        // the answers engine is permitted to call an all-clear.
        patchNowCount: 0,
        devicesWithPatchNow: 0,
        highRiskCount: 0,
        devicesCveAssessed: 16,
      })),
      previous: ok('previous', previousRow({ patch_now_count: 0, high_risk_count: 0 })),
      work: ok('work', workValue([])),
      compliance: ok('compliance', complianceValue()),
    },
    ...over,
  };
}

// ══════════════════════════════════════════════════════════════════════════

describe('a null security score is "not measurable", never 0', () => {
  it('⛔ renders the not-measured mark and a reason, and never prints a score of 0', async () => {
    const data = cleanData();
    data.sections.headline = ok('headline', headlineValue({
      securityScore: null,
      securityComponents: [
        { key: 'vulnerability', label: 'Vulnerability posture', score: null, weight: 40 },
        { key: 'hygiene', label: 'Rule hygiene', score: null, weight: 30 },
        { key: 'compliance', label: 'Compliance', score: null, weight: 30 },
      ],
    }));

    const text = pdfText(await renderExecutiveSummaryPdf(data));

    assert.match(text, /Not measurable/, 'an unmeasurable score must say so in words');
    assert.ok(
      !/Score: 0 \/ 100/.test(text),
      'a null score printed as 0/100 tells a board the estate is maximally exposed '
      + 'when the truth is that nothing was measured'
    );
    assert.ok(!/\(poor\)/.test(text), 'a null score must not be banded at all');
    // Each dropped component is named, with the weight that left the denominator.
    assert.match(text, /its 40 points were dropped from the denominator/);
    assert.match(text, /0 of 100 weighting points were measurable/);
  });

  it('scoreDisplay never turns a null into a number, and never turns a real 0 into a dash', () => {
    // ⛔ Both halves matter. `score || '-'` passes the first and fails the
    // second, and a genuine fleet score of 0 rendered as "not measured" is the
    // same lie pointed the other way.
    assert.equal(scoreDisplay(null), '—');
    assert.equal(scoreDisplay(undefined), '—');
    assert.equal(scoreDisplay(0), '0');
    assert.equal(scoreDisplay(49), '49');
    assert.equal(countDisplay(0), '0');
    assert.equal(countDisplay(null), '—');
  });

  it('numOrNull keeps the strictness the score engine uses', () => {
    // Number('') === 0, Number(false) === 0, Number([]) === 0. In a document
    // where 0 is a meaningful value, that is a fabricated measurement.
    for (const bad of ['', false, true, [], {}, null, undefined, 'n/a']) {
      assert.equal(numOrNull(bad), null, `${JSON.stringify(bad)} must not become a number`);
    }
    assert.equal(numOrNull('0'), 0, 'node-postgres returns COUNT(*) as text');
    assert.equal(numOrNull(0), 0);
  });
});

describe('a section that failed to gather says so, in place', () => {
  it('⛔ the work-queue section stays on the page and states the failure', async () => {
    const data = cleanData();
    data.sections.work = failed('work', 'connection terminated unexpectedly');

    const text = pdfText(await renderExecutiveSummaryPdf(data));

    // The heading survives. A vanished section reads as "nothing to report",
    // and this document is shortest exactly when it is least trustworthy.
    assert.match(text, /What is being done/, 'the section must not disappear');
    assert.match(text, /could not be gathered/i);
    assert.match(text, /connection terminated unexpectedly/, 'the reason is printed, not swallowed');
    assert.match(
      text, /An empty work list here would mean nothing is outstanding/,
      'the reader must be told what the absence does NOT mean'
    );
    // And it is repeated in the closing gap list, so the two cannot drift.
    assert.match(text, /Outstanding work/);
  });

  it('⛔ a failed headline never reaches the sentence builder', async () => {
    // Handed a null headline the answers engine truthfully reports an empty
    // estate — "No firewalls are under management yet". Routing a FAILED READ
    // through it would print that sentence about a fleet of 16 firewalls whose
    // query happened to throw: a confident falsehood, in the one line of this
    // report anybody is guaranteed to read.
    const data = cleanData();
    data.sections.headline = failed('headline', 'relation "devices" does not exist');

    const text = pdfText(await renderExecutiveSummaryPdf(data));

    assert.ok(
      !/No firewalls are under management yet/.test(text),
      'a failed gather must never be phrased as a finding about the estate'
    );
    assert.match(text, /The fleet position could not be determined/);
    assert.match(text, /absence of measurement, not an absence of exposure/);
    assert.match(text, /It is not zero and it is not low/, 'the score section says the same');
  });

  it('⛔ every section fails independently — one outage does not blank the report', async () => {
    const data = cleanData();
    data.sections.compliance = failed('compliance', 'permission denied for table audit_findings');

    const text = pdfText(await renderExecutiveSummaryPdf(data));

    assert.match(text, /permission denied for table audit_findings/);
    // The other sections still rendered their real values.
    assert.match(text, /Security score, and what it is made of/);
    assert.match(text, /Movement since the last measured period/);
    assert.ok(
      !/Standard\s*Score/.test(text.replace(/\s+/g, ' ')),
      'no standard may be scored off a query that did not run'
    );
  });

  it('gapsOf lists one entry per failed section, naming it', () => {
    const data = cleanData();
    data.sections.work = failed('work', 'boom');
    data.sections.compliance = failed('compliance', 'bang');
    const labels = gapsOf(data).map((g) => g.label);
    assert.ok(labels.includes('Outstanding work'));
    assert.ok(labels.includes('Compliance breakdown'));
  });
});

describe('the cover states coverage, and the coverage clause always follows the claim', () => {
  it('⛔ an incomplete fleet is named on the cover AND under the sentence', async () => {
    const data = cleanData();
    data.sections.headline = ok('headline', headlineValue({
      deviceCount: 16,
      devicesCveAssessed: 13, // three firewalls never assessed
    }));

    const text = pdfText(await renderExecutiveSummaryPdf(data));

    // Cover: the gap is a labelled row, not a footnote.
    assert.match(text, /Firewalls assessed13 of 16/);
    assert.match(text, /3 - excluded from every figure in this report/);
    // Body: the answers engine's own coverage clause is rendered verbatim.
    assert.match(text, /Coverage/);
    assert.match(text, /3 of 16 firewalls have never been assessed/);
    // Closing: and it is counted as a gap.
    assert.match(text, /3 of 16 firewalls never assessed/);
    assert.match(text, /unknown, which is not the same as clean/);
  });

  it('⛔ complete coverage is stated explicitly, not by omitting the row', async () => {
    // An absent row reads as "not applicable"; a present one reads as checked.
    const text = pdfText(await renderExecutiveSummaryPdf(cleanData()));
    assert.match(text, /None - coverage is complete/);
  });

  it('coverageOf reports the gap, and refuses to compute one from a failed read', () => {
    assert.deepEqual(
      coverageOf(ok('headline', headlineValue({ deviceCount: 16, devicesCveAssessed: 13 }))),
      { ok: true, devices: 16, assessed: 13, gap: 3 }
    );
    // ⛔ A failed gather is not "gap 0". Zero is the reassuring answer and it is
    // the one thing we are not entitled to say.
    assert.deepEqual(
      coverageOf(failed('headline', 'boom')),
      { ok: false, devices: null, assessed: null, gap: null }
    );
  });
});

describe('an all-clear is forbidden while anything is unmeasured', () => {
  it('⛔ the completeness sentence appears ONLY when there is not a single gap', async () => {
    const clean = pdfText(await renderExecutiveSummaryPdf(cleanData()));
    assert.match(
      clean, /Every figure in this report rests on a completed measurement/,
      'the fully-measured fixture is the one case allowed to sound clean'
    );

    // Now break exactly one thing at a time. Each alone must remove it.
    const breakers = {
      'unassessed firewalls': (d) => {
        d.sections.headline = ok('headline', headlineValue({
          patchNowCount: 0, devicesWithPatchNow: 0, highRiskCount: 0, devicesCveAssessed: 12,
        }));
      },
      'an unmeasurable score component': (d) => {
        d.sections.headline = ok('headline', headlineValue({
          patchNowCount: 0,
          devicesWithPatchNow: 0,
          highRiskCount: 0,
          securityComponents: [
            { key: 'vulnerability', label: 'Vulnerability posture', score: 62, weight: 40 },
            { key: 'hygiene', label: 'Rule hygiene', score: null, weight: 30 },
            { key: 'compliance', label: 'Compliance', score: 51, weight: 30 },
          ],
        }));
      },
      'no prior period': (d) => { d.sections.previous = ok('previous', null); },
      'a failed source': (d) => { d.sections.compliance = failed('compliance', 'boom'); },
      'a failed work-queue source': (d) => {
        d.sections.work = ok('work', workValue([], [
          { key: 'cve', ok: true, count: 0 },
          { key: 'licence', ok: false, count: 0, error: 'timeout' },
        ]));
      },
      'an item nobody could measure': (d) => {
        d.sections.work = ok('work', workValue([
          cveItem(9, { evidence: 'unmeasured', title: 'Licence expiry could not be parsed' }),
        ]));
      },
    };

    for (const [name, apply] of Object.entries(breakers)) {
      const data = cleanData();
      apply(data);
      const text = pdfText(await renderExecutiveSummaryPdf(data));
      assert.ok(
        !/Every figure in this report rests on a completed measurement/.test(text),
        `${name} must revoke the completeness claim`
      );
    }
  });

  it('⛔ the green fleet sentence never survives an incomplete fleet', async () => {
    const data = cleanData();
    data.sections.headline = ok('headline', headlineValue({
      patchNowCount: 0, devicesWithPatchNow: 0, highRiskCount: 0, devicesCveAssessed: 12,
    }));
    const text = pdfText(await renderExecutiveSummaryPdf(data));
    assert.ok(
      !/and every one of them was assessed/.test(text),
      'the all-clear sentence belongs to a fully assessed fleet only'
    );
    assert.match(text, /but the fleet was not fully assessed/);
  });
});

describe('trend needs a real prior point', () => {
  it('⛔ no prior snapshot says so, and never prints a zero delta', async () => {
    const data = cleanData();
    data.sections.previous = ok('previous', null);

    const text = pdfText(await renderExecutiveSummaryPdf(data));

    assert.match(text, /no prior period to compare against/i);
    assert.match(text, /absence of a second data point/);
    assert.ok(
      !/No change/.test(text),
      '"no change" over a period nobody observed is an invented reassurance'
    );
    assert.match(text, /No prior period to compare/, 'and the cover says it too');
  });

  it('⛔ a NULL column in the prior row is "no prior value", not a delta', async () => {
    // Snapshot rows written before the headline columns existed carry NULLs.
    const data = cleanData();
    data.sections.previous = ok('previous', previousRow({ security_score: null }));

    const text = pdfText(await renderExecutiveSummaryPdf(data));
    assert.match(text, /No prior value recorded/);
  });

  it('a real movement is signed, and judged in the right direction per metric', () => {
    const move = movementOf(
      ok('headline', headlineValue()),
      ok('previous', previousRow()),
      GENERATED_AT
    );
    assert.equal(move.available, true);
    const by = Object.fromEntries(move.rows.map((r) => [r.metric, r]));
    // Score 46 -> 49: up, and up is better.
    assert.equal(by['Security score (0-100)'].change, '+3');
    assert.equal(by['Security score (0-100)'].direction, 'better');
    // ⛔ THE SAME SIGN, THE OPPOSITE JUDGEMENT. Urgent findings 5 -> 3 is -2 and
    // is GOOD; inferring direction from the sign alone would colour half this
    // table backwards, on the page an executive reads fastest.
    assert.equal(by['Findings needing patching now'].change, '-2');
    assert.equal(by['Findings needing patching now'].direction, 'better');
    // Reachable firewalls 15 -> 14 is a fall, and a fall here is worse.
    assert.equal(by['Firewalls reachable'].direction, 'worse');
    assert.equal(by['Compliance score (%)'].direction, 'flat');
  });

  it('⛔ a pg DATE keeps the calendar day it was stored with', () => {
    // node-postgres parses DATE to LOCAL midnight. Formatting that in UTC on a
    // positive-offset server (the reference deployment is UTC+7) prints the day
    // BEFORE the one the database holds — on the cover of a document nobody
    // will re-derive.
    const localMidnight = new Date(2026, 8, 14, 0, 0, 0); // 2026-09-14 local
    assert.equal(fmtDay(localMidnight), '2026-09-14');
    // A bare date string is already the stored day and must pass through
    // untouched rather than being re-parsed as UTC midnight.
    assert.equal(fmtDay('2026-09-14'), '2026-09-14');
    assert.equal(fmtDay(null), null);
    assert.equal(daysBetween('2026-09-13', '2026-09-15'), 2);
    assert.equal(daysBetween(null, '2026-09-15'), null);
  });

  it('movementOf reports WHICH side is missing, so the page can say why', () => {
    assert.equal(movementOf(failed('headline', 'x'), ok('previous', previousRow()), GENERATED_AT).reason, 'current');
    assert.equal(movementOf(ok('headline', headlineValue()), failed('previous', 'x'), GENERATED_AT).reason, 'failed');
    assert.equal(movementOf(ok('headline', headlineValue()), ok('previous', null), GENERATED_AT).reason, 'none');
  });
});

describe('no silent truncation', () => {
  it('⛔ a capped urgent list prints "showing N of M" BEFORE the table', async () => {
    const items = [1, 2, 3, 4, 5].map((n) => cveItem(n));
    const data = cleanData({ maxWorkItems: 2 });
    data.sections.work = ok('work', workValue(items));

    const text = pdfText(await renderExecutiveSummaryPdf(data));

    assert.match(text, /Showing 2 of 5 urgent items/);
    assert.match(text, /not because the list ends here/);
    // The disclosure precedes the table header, because the reader who stops at
    // the bottom of the list is the reader it is for.
    assert.ok(
      text.indexOf('Showing 2 of 5 urgent items') < text.indexOf('What needs doing'),
      'the cap must be disclosed above the table, not footnoted under it'
    );
  });

  it('an uncapped list carries no truncation claim', async () => {
    const data = cleanData({ maxWorkItems: MAX_WORK_ITEMS });
    data.sections.work = ok('work', workValue([cveItem(1), cveItem(2)]));
    const text = pdfText(await renderExecutiveSummaryPdf(data));
    assert.ok(!/Showing \d+ of \d+ urgent items/.test(text));
  });

  it('⛔ a source the queue itself capped is disclosed too', async () => {
    const data = cleanData();
    data.sections.work = ok('work', workValue(
      [cveItem(1)],
      [{ key: 'compliance', ok: true, count: 50, truncatedFrom: 74 }]
    ));
    const text = pdfText(await renderExecutiveSummaryPdf(data));
    assert.match(text, /was capped/);
    assert.match(text, /Showing 50 of 74/);
  });

  it('a cap of 0 is clamped, so the page cannot contradict its own heading', async () => {
    const data = await gatherExecutiveSummary(throwingPool('nope'), { maxWorkItems: 0 });
    assert.ok(data.maxWorkItems >= 1);
  });
});

describe('the urgent band is a claim about evidence', () => {
  it('⛔ an unmeasured item never appears in the urgent table — it is counted as verify', async () => {
    const data = cleanData();
    data.sections.work = ok('work', workValue([
      cveItem(1),
      cveItem(2, {
        evidence: 'unmeasured',
        title: 'Licence expiry on TSR-EKM could not be parsed',
        urgency: 'now', // ⛔ the source declares itself urgent and is overruled
      }),
    ]));

    const text = pdfText(await renderExecutiveSummaryPdf(data));

    assert.match(text, /Patch CVE-2026-0001/, 'the measured item is listed');
    assert.ok(
      !/Licence expiry on TSR-EKM could not be parsed/.test(text),
      'an item whose evidence is absent may not be presented as urgent work'
    );
    // But it is not dropped either — that would be the other half of the bug.
    assert.match(text, /1 item.? need a human to verify/);
  });

  it('renders the evidence word for each urgent item', async () => {
    const data = cleanData();
    data.sections.work = ok('work', workValue([
      cveItem(1, { evidence: 'measured' }),
      cveItem(2, { evidence: 'reported' }),
    ]));
    const text = pdfText(await renderExecutiveSummaryPdf(data));
    assert.match(text, /Measured/);
    assert.match(text, /Reported/);
  });
});

describe('gathering survives a database that is not answering', () => {
  function throwingPoolLocal(message) {
    return { query: () => Promise.reject(new Error(message)) };
  }

  it('⛔ a total outage still produces a readable PDF, and it is full of gaps, not empty', async () => {
    const pool = throwingPoolLocal('ECONNREFUSED 192.168.7.69:5432');
    const buf = await generateExecutiveSummaryPdf(pool, {
      generatedAt: GENERATED_AT,
      company: 'Acme Holdings',
    });

    assert.ok(Buffer.isBuffer(buf), 'must still return a Buffer');
    assert.ok(buf.length > 1000);
    const text = pdfText(buf);

    assert.match(text, /Executive Security Posture/);
    assert.match(text, /ECONNREFUSED/, 'the real reason is printed');
    assert.match(text, /The fleet position could not be determined/);
    assert.ok(
      !/Every figure in this report rests on a completed measurement/.test(text),
      'a report gathered from nothing may never certify completeness'
    );
    // ⛔ And the cover must not imply a fleet it could not count.
    assert.match(text, /Could not be read/);
  });

  it('each section is wrapped separately — one failure does not take the others', async () => {
    // Only the compliance query throws; everything else returns empty rows.
    const pool = {
      query: (sql) => (/audit_findings/.test(String(sql))
        ? Promise.reject(new Error('permission denied'))
        : Promise.resolve({ rows: [] })),
    };
    const data = await gatherExecutiveSummary(pool, { generatedAt: GENERATED_AT });

    // getFleetHeadline itself calls computeFleetComplianceScores, so the
    // headline legitimately fails with it; what must NOT happen is the whole
    // gather collapsing into one error.
    assert.equal(data.sections.compliance.ok, false);
    assert.match(data.sections.compliance.error, /permission denied/);
    assert.equal(data.sections.previous.ok, true, 'an unrelated section still gathered');
    assert.equal(data.sections.work.ok, true, 'the work queue gathers its own sources');
  });

  it('a failed work-queue SOURCE is reported rather than shortening the list silently', async () => {
    const pool = { query: () => Promise.reject(new Error('relation does not exist')) };
    const data = await gatherExecutiveSummary(pool, { generatedAt: GENERATED_AT });
    // gatherWorkQueue catches per source, so the section succeeds with an
    // honest account of nine dead sources rather than an empty, clean queue.
    assert.equal(data.sections.work.ok, true);
    assert.ok(data.sections.work.value.summary.sourcesFailed > 0);
    const text = pdfText(await renderExecutiveSummaryPdf(data));
    assert.match(text, /is missing/);
    assert.match(text, /shorter than the truth by an unknown amount/);
  });
});

describe('the document itself', () => {
  it('is a valid single-document PDF carrying the report title and the company', async () => {
    const buf = await renderExecutiveSummaryPdf(cleanData());
    assert.equal(buf.slice(0, 5).toString('latin1'), '%PDF-');
    const text = pdfText(buf);
    assert.match(text, /Executive Security Posture/);
    assert.match(text, /Acme Holdings/, 'the running header names the company');
    // ⛔ The stamp does not read as "UTC" here, and that is the assertion. The
    // comparison helper rewrites any rendered timestamp matching
    // `dd/mm/yyyy, hh:mm:ss UTC` to this marker so two runs a second apart can
    // be compared. Seeing the marker therefore PROVES the report drew a stamp
    // in the chassis' UTC-suffixed format — a local timestamp, or a stamp with
    // no zone marker, would survive here as itself and fail.
    assert.match(text, /TIMESTAMP-NORMALISED/, 'the generated stamp must be the UTC-suffixed format');
  });

  it('⛔ keeps a fixed section order, so a reader who stops early stops in the right place', async () => {
    const text = pdfText(await renderExecutiveSummaryPdf(cleanData()));
    const order = [
      'The position today',
      'Security score, and what it is made of',
      'Movement since the last measured period',
      'What is being done',
      'Compliance against the standards',
      'What could not be measured',
    ];
    let at = -1;
    for (const heading of order) {
      const next = text.indexOf(heading);
      assert.ok(next > at, `${heading} is out of order or missing`);
      at = next;
    }
  });

  it('⛔ a standard with nothing measurable is a dash, not 0%', async () => {
    const data = cleanData();
    data.sections.compliance = ok('compliance', complianceValue({
      overall: null,
      byStandard: { PCI_DSS: null, ISO_27001: null, CIS_V8: null, NIST: null, SANS: null },
      byStandardCounts: {},
    }));
    const text = pdfText(await renderExecutiveSummaryPdf(data));
    assert.ok(
      !/PCI DSS0%/.test(text.replace(/\s+/g, '')),
      'a board reading "PCI DSS 0%" concludes every card-data control fails; '
      + 'the truth may be that no check could be answered'
    );
    assert.match(text, /Not measurable/);
  });
});

// Shared by the cap-clamp test above.
function throwingPool(message) {
  return { query: () => Promise.reject(new Error(message)) };
}
