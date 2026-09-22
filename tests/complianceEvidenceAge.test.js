'use strict';
// tests/complianceEvidenceAge.test.js
//
// ⛔ NEITHER PRINTED COMPLIANCE SURFACE SAID HOW OLD ITS EVIDENCE WAS.
//
// The monthly auditor PDF (lib/engines/complianceReport.js) carried no
// freshness statement of any kind, and the per-device print page printed "Last
// audit run" — which is the FLATTERING timestamp, not the honest one. A
// compliance audit reads the newest `device_configs` row WHATEVER ITS AGE and
// stamps `detected_at = now()`, so re-running the checks on a firewall that
// stopped being collectable produces a brand-new timestamp over month-old
// evidence.
//
// Measured on the live fleet 2026-09-22: TSR_EKC's evidence was 1,116h old and
// its audit 669h old — an eighteen-day gap — and the printed report described
// it as a 27-day-old audit with no qualifier. Both surfaces are artefacts an
// auditor FILES and re-reads months later, where there is no hover, no tooltip
// and no second chance to ask.
//
// ⛔ NOTHING HERE MOVES A SCORE, and the tests below assert that too: a stale
// 60% is still 60% of what was measured. What was wrong was the absence of a
// date, not the arithmetic.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  collectionAges, evidenceAgeStatement, buildReportData, generateReportPdf, STANDARD_KEYS,
} = require('../lib/engines/complianceReport');
const { contentStreams } = require('../lib/reports/pdfCompare');

const REPO = path.join(__dirname, '..');
const NOW = new Date('2026-09-22T12:00:00Z');
const H = 3600000;
const hoursAgo = (h) => new Date(NOW.getTime() - h * H);
const ENV = { CONFIG_PULL_INTERVAL_HOURS: '24' };

// ── collectionAges: the read ────────────────────────────────────────────────

describe('collectionAges reads BOTH timestamps, at the scope being reported', () => {
  const okRows = [
    { device_id: 'd1', device_name: 'fw-a', collected_at: hoursAgo(12), evaluated_at: hoursAgo(12) },
  ];

  it('binds the device id rather than interpolating it', async () => {
    let seen = null;
    const pool = { query: async (sql, params) => { seen = { sql, params }; return { rows: okRows }; } };
    await collectionAges(pool, 'd1');
    assert.deepEqual(seen.params, ['d1']);
    assert.equal(seen.sql.includes("'d1'"), false, 'the device id must never be interpolated');
    assert.match(seen.sql, /device_configs/, 'the EVIDENCE time comes from device_configs');
    assert.match(seen.sql, /audit_findings/, 'the EVALUATION time comes from audit_findings');
    // ⛔ Only ACTIVE firewalls — a decommissioned one has not "gone stale".
    assert.match(seen.sql, /d\.active = true/);
  });

  it('asks for the whole fleet when no device is scoped, with no parameters', async () => {
    let seen = null;
    const pool = { query: async (sql, params) => { seen = { sql, params }; return { rows: okRows }; } };
    await collectionAges(pool);
    assert.deepEqual(seen.params, []);
    assert.equal(/AND d\.id = \$1/.test(seen.sql), false);
  });

  it('⛔ a FAILED read is null, never an empty list', async () => {
    // An empty list prints as "no firewall has ever been collected from", which
    // is a claim about the fleet. A failed read is not.
    const pool = { query: async () => { throw new Error('connection terminated'); } };
    assert.equal(await collectionAges(pool), null);
  });

  it('⛔ an UNRECOGNISABLE row set is null too, not a confident alarm', async () => {
    // Reading an absent `collected_at` as "never collected" would turn a wrong
    // answer into a loud one. The shape is checked, not trusted.
    for (const rows of [[{ device_id: 'd1', status: 'pass' }], [{}], 'nope', null]) {
      const pool = { query: async () => ({ rows }) };
      assert.equal(await collectionAges(pool), null, JSON.stringify(rows));
    }
  });

  it('a genuinely empty fleet is an empty list, which is a real answer', async () => {
    const pool = { query: async () => ({ rows: [] }) };
    assert.deepEqual(await collectionAges(pool), []);
  });
});

// ── the sentence ────────────────────────────────────────────────────────────

describe('⛔ the evidence-age statement never reads as an all-clear it has not earned', () => {
  it('an unreadable age SAYS SO rather than being omitted', () => {
    const s = evidenceAgeStatement(null, { now: NOW, env: ENV });
    assert.match(s, /could not read/i);
    assert.match(s, /failed read on SecVault/i, 'the limitation is ours, and is named as ours');
    // ⛔ It must not fall back to the reassuring wording.
    assert.equal(/within the expected cadence/.test(s), false);
  });

  it('⛔ the live fleet shape: the firewalls that are behind are NAMED', () => {
    // "2 firewalls are behind" sends somebody hunting through sixteen rows of
    // a printed table with no search box.
    const rows = [
      { deviceId: 'd1', deviceName: 'TSR_EKC', collectedAt: hoursAgo(1116), evaluatedAt: hoursAgo(669) },
      { deviceId: 'd2', deviceName: 'TSR-TL', collectedAt: hoursAgo(252), evaluatedAt: hoursAgo(252) },
      { deviceId: 'd3', deviceName: 'SMT', collectedAt: hoursAgo(12), evaluatedAt: hoursAgo(12) },
    ];
    const s = evidenceAgeStatement(rows, { now: NOW, env: ENV });
    assert.match(s, /2 of 3 firewalls/);
    assert.match(s, /TSR_EKC/);
    assert.match(s, /TSR-TL/);
    assert.equal(/SMT/.test(s), false, 'a fresh firewall is not on the chase list');
    // ⛔ And it says what the stale scores ARE still worth — wording them as
    // garbage pushes a reader to ignore the page rather than fix collection.
    assert.match(s, /real evidence/);
    assert.match(s, /frozen, not clean/);
  });

  it('a fleet collected on time gets the plain sentence, and names nobody', () => {
    const rows = [
      { deviceId: 'd1', deviceName: 'A', collectedAt: hoursAgo(6), evaluatedAt: hoursAgo(6) },
      { deviceId: 'd2', deviceName: 'B', collectedAt: hoursAgo(11), evaluatedAt: hoursAgo(11) },
    ];
    const s = evidenceAgeStatement(rows, { now: NOW, env: ENV });
    assert.match(s, /within the expected cadence/);
    assert.equal(/firewalls were last collected/.test(s), false);
  });

  it('⛔ a NEVER-collected firewall counts as behind, not quietly excluded', () => {
    const rows = [{ deviceId: 'd1', deviceName: 'NewFW', collectedAt: null, evaluatedAt: null }];
    const s = evidenceAgeStatement(rows, { now: NOW, env: ENV });
    assert.match(s, /1 of 1 firewalls/);
    assert.match(s, /NewFW/);
  });

  it('⛔ a truncated name list DISCLOSES that it is truncated', () => {
    // A shortened list reads as complete, which is the more insidious failure:
    // the reader works to the bottom and believes they are finished.
    const rows = Array.from({ length: 12 }, (_v, i) => ({
      deviceId: `d${i}`, deviceName: `fw-${i}`, collectedAt: hoursAgo(1000), evaluatedAt: hoursAgo(1000),
    }));
    const s = evidenceAgeStatement(rows, { now: NOW, env: ENV });
    assert.match(s, /12 of 12 firewalls/);
    assert.match(s, /and 4 more/);
  });

  it('a DEVICE-scoped report gets that firewall own sentence, not a statistic', () => {
    // ⛔ "1 of 1 firewalls" is arithmetically true and reads as a fact about an
    // estate. Scoped to one firewall the fact is simply how old its config is.
    const rows = [{ deviceId: 'd1', deviceName: 'TSR_EKC', collectedAt: hoursAgo(1116), evaluatedAt: hoursAgo(669) }];
    const s = evidenceAgeStatement(rows, { device: { id: 'd1', name: 'TSR_EKC' }, now: NOW, env: ENV });
    assert.equal(/\d+ of \d+ firewalls/.test(s), false);
    assert.match(s, /TSR_EKC's configuration was last collected/);
    // 1,116h / 24 = 46.5, rounded to 47 -- the EVIDENCE age. The audit age
    // (669h) would render as 28 days, which is the flattering number.
    assert.match(s, /47 days ago/, 'the EVIDENCE age, not the 669h audit age');
    assert.equal(/28 days ago/.test(s), false);
    // ⛔ The lag is stated: a "run checks now" press produces exactly this shape
    // and the reader has to be told the audit is newer than its own evidence.
    assert.match(s, /audit is more recent than the evidence/);
  });

  it('a healthy device-scoped report carries no lag caveat', () => {
    const rows = [{ deviceId: 'd1', deviceName: 'SMT', collectedAt: hoursAgo(11), evaluatedAt: hoursAgo(11) }];
    const s = evidenceAgeStatement(rows, { device: { id: 'd1', name: 'SMT' }, now: NOW, env: ENV });
    assert.equal(/audit is more recent than the evidence/.test(s), false);
    assert.match(s, /SMT/);
  });

  it('an empty scope is stated, never rendered as a clean fleet', () => {
    assert.match(evidenceAgeStatement([], { now: NOW, env: ENV }), /No active firewall is in scope/);
  });
});

// ── the PDF actually prints it ──────────────────────────────────────────────

const DEVICES = [
  { id: 'd1', name: 'fw-stale', vendor: 'fortinet' },
  { id: 'd2', name: 'fw-fresh', vendor: 'paloalto' },
];

function stubPool({ ages = 'ok' } = {}) {
  const findings = [
    { device_id: 'd1', status: 'pass', standards: STANDARD_KEYS },
    { device_id: 'd2', status: 'pass', standards: STANDARD_KEYS },
  ];
  return {
    query: async (sql, params = []) => {
      const s = String(sql);
      if (/FROM devices d\s/.test(s) && /device_configs/.test(s)) {
        if (ages === 'fail') throw new Error('nope');
        const rows = DEVICES.map((d, i) => ({
          device_id: d.id,
          device_name: d.name,
          collected_at: i === 0 ? hoursAgo(1116) : hoursAgo(11),
          evaluated_at: i === 0 ? hoursAgo(669) : hoursAgo(11),
        }));
        return { rows: params.length ? rows.filter((r) => r.device_id === params[0]) : rows };
      }
      if (s.includes('FROM devices WHERE id = $1')) return { rows: DEVICES.filter((d) => d.id === params[0]) };
      if (s.includes('FROM devices WHERE active')) {
        return { rows: params.length ? DEVICES.filter((d) => d.id === params[0]) : DEVICES };
      }
      if (s.includes('library_total')) return { rows: [] };
      if (s.includes('answered_checks')) return { rows: [] };
      if (s.includes('remediation_guidance')) return { rows: [] };
      if (s.includes('FROM audit_checks')) return { rows: [{ total: 45, mapped: 21 }] };
      return { rows: params.length ? findings.filter((f) => f.device_id === params[0]) : findings };
    },
  };
}

function pdfText(buf) {
  return contentStreams(buf).map((stream) => {
    let out = '';
    stream.replace(/<([0-9a-fA-F]+)>/g, (whole, hex) => {
      for (let i = 0; i < hex.length; i += 2) out += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
      return whole;
    });
    return out;
  }).join('');
}

describe('⛔ the monthly auditor PDF now carries the statement', () => {
  // Driven through the real pdfkit render, because the sentence is chosen
  // inside renderReportBody(), which is not exported — and a test reading the
  // source instead would pass on a branch that never executes.

  it('the fleet report names the firewall whose evidence stopped moving', async () => {
    const text = pdfText(await generateReportPdf(stubPool()));
    assert.match(text, /fw-stale/, 'the stale firewall must be named in the report body');
    assert.match(text, /longer ago than the/);
    assert.match(text, /frozen, not clean/);
  });

  it('a device-scoped report carries that firewall own age', async () => {
    // ⛔ The exact figure is pinned in the pure test above, where the clock is
    // injected. Here the render uses the real clock, so the assertion is on the
    // SHAPE -- and on the stale wording, which is what was missing entirely.
    const text = pdfText(await generateReportPdf(stubPool(), { deviceId: 'd1' }));
    assert.match(text, /fw-stale's configuration was last collected \d+ days ago/);
    assert.match(text, /describes an old configuration/);
  });

  it('⛔ an unreadable age prints as unreadable, and never silently vanishes', async () => {
    const text = pdfText(await generateReportPdf(stubPool({ ages: 'fail' })));
    assert.match(text, /could not read when these configurations were last collected/);
  });

  it('⛔ the statement changes NO number on the report', async () => {
    // The whole safety property: age is reported ALONGSIDE, never folded in.
    const withAges = await buildReportData(stubPool());
    const withoutAges = await buildReportData(stubPool({ ages: 'fail' }));
    assert.deepEqual(withAges.fleet, withoutAges.fleet);
    assert.deepEqual(
      withAges.perDevice.map((d) => d.standards),
      withoutAges.perDevice.map((d) => d.standards)
    );
  });

  it('the ages ride along on the report data, at the reported scope', async () => {
    const fleet = await buildReportData(stubPool());
    assert.equal(fleet.evidenceAges.length, 2);
    const scoped = await buildReportData(stubPool(), { deviceId: 'd1' });
    assert.equal(scoped.evidenceAges.length, 1);
    assert.equal(scoped.evidenceAges[0].deviceName, 'fw-stale');
  });
});

// ── the per-device print page ───────────────────────────────────────────────

describe('⛔ the per-device print page no longer prints the audit time alone', () => {
  // ⛔ WHY A SOURCE SCAN HERE AND NOT AN EXECUTION. This is an async React
  // SERVER COMPONENT; nothing in `npm test` renders a page, and the harness
  // that does (`npm run smoke`) needs a built app, a running server and a
  // database, so it lives behind its own script. The judgement itself —
  // complianceFreshness / ageLabel / freshnessNote — is pinned behaviourally
  // in tests/complianceFreshness.test.js and above; what is checked here is
  // only that this page reaches for it. Read over CODE ONLY, so the comment
  // explaining the rule can never satisfy the assertion.
  const PAGE = 'app/(dashboard)/compliance/[deviceId]/print/page.js';
  const code = () => fs.readFileSync(path.join(REPO, PAGE), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .split('\n')
    .map((l) => {
      const i = l.indexOf('//');
      if (i < 0) return l;
      if (i > 0 && l[i - 1] === ':') return l;
      return l.slice(0, i);
    })
    .join('\n');

  it('reads the EVIDENCE time from device_configs, not just the finding time', () => {
    const src = code();
    assert.match(src, /device_configs/, 'the page must read when the config was collected');
    assert.match(src, /collected_at/);
    assert.match(src, /complianceFreshness\(/);
    assert.match(src, /evidenceAt: configCollectedAt/, 'graded on the config time');
    assert.match(src, /evaluatedAt: lastRunAt/);
  });

  it('prints the collection time and its age in the header', () => {
    const src = code();
    assert.match(src, /Configuration collected/);
    assert.match(src, /ageLabel\(freshness\)/);
    // The audit time stays — it is a real fact, it was just never the only one.
    assert.match(src, /Checks last run/);
  });

  it('prints the stale caveat as WORDS, not as a colour a printer loses', () => {
    const src = code();
    assert.match(src, /freshnessNote\(freshness, device\.name\)/);
    // ⛔ THE RENDER CONDITION ITSELF, not merely that the variable exists. A
    // block left in place behind `{false && (` still mentions `needsCaveat`
    // everywhere a looser assertion would look.
    assert.match(src, /\{needsCaveat && \(/);
    // ⛔ Hueless, per the design system's "NOT MEASURED has no hue" rule, and
    // on paper an amber warning prints grey anyway.
    assert.match(src, /var\(--unmeasured\)/);
  });

  it('⛔ the caveat covers every not-fresh state AND the flattering-audit case', () => {
    // A caveat gated on `state === 'stale'` alone would print nothing for an
    // ageing device, a never-collected one, or the exact shape the "run checks
    // now" button creates.
    const src = code();
    assert.match(src, /freshness\.state !== STATES\.FRESH/);
    assert.match(src, /freshness\.evaluatedAgainstOldConfig/);
  });
});
