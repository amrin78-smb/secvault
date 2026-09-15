'use strict';
// Pins the per-standard scoping of the compliance report.
//
// ⛔ WHY THIS NEEDS ITS OWN GUARDS. Narrowing to PCI DSS is NOT a filter over
// the fleet — a check carries a `standards` ARRAY and most carry several, so
// scoping changes the DENOMINATOR. A PCI score and an overall score are both
// correct and are answers to different questions. Everything here exists to
// stop that difference being presented as though it were a disagreement, and
// to stop an unmeasurable standard being scored as a failing one.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  STANDARDS,
  STANDARD_KEYS,
  resolveStandard,
  standardCoverage,
  fleetForStandard,
  unassessedDevices,
  buildFleetSummaryTable,
  buildPerDeviceTable,
  generateReportPdf,
} = require('../lib/engines/complianceReport');
const { contentStreams } = require('../lib/reports/pdfCompare');

const { REPORTS } = require('../lib/reports/catalogue');

function device(name, counts) {
  const standards = {};
  for (const s of STANDARDS) {
    standards[s.key] = { pass: 0, fail: 0, warning: 0, na: 0, total: 0, scorePct: null };
  }
  for (const [k, v] of Object.entries(counts)) {
    const measurable = v.pass + v.fail + v.warning;
    standards[k] = {
      ...v, total: measurable + v.na,
      scorePct: measurable > 0 ? Math.round((100 * v.pass) / measurable) : null,
    };
  }
  return { deviceId: name, deviceName: name, vendor: 'fortinet', standards };
}

describe('resolveStandard', () => {
  it('passes through every standard the library actually defines', () => {
    for (const k of STANDARD_KEYS) assert.equal(resolveStandard(k), k);
  });

  it('treats absent / empty as unscoped rather than as an error', () => {
    for (const v of [undefined, null, '']) assert.equal(resolveStandard(v), null);
  });

  it('⛔ THROWS on an unknown standard — it must never widen to the whole fleet', () => {
    // Silently widening would answer a request for the PCI document with the
    // whole-fleet document, under a filename and a cover page saying PCI.
    // A mislabelled audit artefact is worse than an error page.
    for (const bad of ['HIPAA', 'pci_dss', 'PCI DSS', 'SOC2', ' PCI_DSS']) {
      assert.throws(() => resolveStandard(bad), /Unknown compliance standard/);
    }
  });
});

describe('fleetForStandard', () => {
  const fleet = [
    device('a', { PCI_DSS: { pass: 8, fail: 2, warning: 0, na: 3 } }),
    device('b', { PCI_DSS: { pass: 4, fail: 4, warning: 2, na: 1 } }),
  ];

  it('sums the per-device counts rather than re-querying', () => {
    const r = fleetForStandard(fleet, 'PCI_DSS');
    assert.deepEqual(
      { pass: r.pass, fail: r.fail, warning: r.warning, na: r.na },
      { pass: 12, fail: 6, warning: 2, na: 4 }
    );
  });

  it('excludes na from the denominator, per the scoring rule', () => {
    // 12 pass out of 20 measurable (12+6+2), NOT out of 24.
    assert.equal(fleetForStandard(fleet, 'PCI_DSS').scorePct, 60);
  });

  it('⛔ nothing measurable is NULL, never 0 — the case that must not regress', () => {
    // A standard no device can be assessed against is a gap in what SecVault
    // can ask, not total non-compliance. Scoring it 0 would report our own
    // inability to measure as a damning fact about the customer's firewalls —
    // the single most-repeated bug class in this codebase.
    const blind = [device('a', { NIST: { pass: 0, fail: 0, warning: 0, na: 7 } })];
    const r = fleetForStandard(blind, 'NIST');
    assert.equal(r.scorePct, null);
    assert.notEqual(r.scorePct, 0);
    assert.equal(r.na, 7);
  });

  it('a device missing the standard entirely contributes nothing and does not throw', () => {
    assert.equal(fleetForStandard([{ deviceName: 'x', standards: {} }], 'SANS').scorePct, null);
  });
});

describe('standardCoverage', () => {
  it('reports how much of the library the standard maps to', async () => {
    const pool = { query: async () => ({ rows: [{ total: 45, mapped: 21 }] }) };
    const c = await standardCoverage(pool, 'PCI_DSS');
    assert.equal(c.total, 45);
    assert.equal(c.mapped, 21);
    assert.equal(c.label, 'PCI DSS');
  });

  it('⛔ a failed read is NULL, not "0 of 45 checks map to PCI DSS"', async () => {
    // That sentence is a claim, and a false one — it would tell a reader the
    // standard is unsupported when in fact the count simply could not be read.
    const pool = { query: async () => { throw new Error('nope'); } };
    assert.equal(await standardCoverage(pool, 'PCI_DSS'), null);
  });

  it('is skipped entirely when unscoped', async () => {
    let called = false;
    const pool = { query: async () => { called = true; return { rows: [] }; } };
    assert.equal(await standardCoverage(pool, null), null);
    assert.equal(called, false, 'an unscoped report must not pay for a coverage query');
  });

  it('parameterises the standard — never interpolates it into the SQL', async () => {
    let seen = null;
    const pool = {
      query: async (sql, params) => { seen = { sql, params }; return { rows: [{ total: 1, mapped: 1 }] }; },
    };
    await standardCoverage(pool, 'PCI_DSS');
    assert.equal(seen.sql.includes('PCI_DSS'), false, 'the value is in the SQL text');
    assert.deepEqual(seen.params, [['PCI_DSS']]);
    assert.match(seen.sql, /\$1::text\[\]/, 'the placeholder must survive — a literal here casts an integer');
  });
});

describe('the scoped tables are a different shape, not the same one with columns hidden', () => {
  const fleetScores = {
    overall: 51,
    byStandard: { PCI_DSS: 60, ISO_27001: 44, CIS_V8: 52, NIST: null, SANS: 70 },
    byStandardCounts: {
      PCI_DSS: { pass: 12, fail: 6, warning: 2 },
      ISO_27001: { pass: 1, fail: 1, warning: 0 },
      CIS_V8: { pass: 1, fail: 1, warning: 0 },
      NIST: { pass: 0, fail: 0, warning: 0 },
      SANS: { pass: 1, fail: 1, warning: 0 },
    },
  };

  it('unscoped still lists every standard', () => {
    assert.equal(buildFleetSummaryTable(fleetScores).rows.length, STANDARDS.length);
  });

  it('⛔ scoped lists ONLY its own standard', () => {
    // Showing the other four invites a comparison between numbers computed
    // over different denominators, which is the confusion the coverage note
    // on the cover exists to prevent.
    const t = buildFleetSummaryTable(fleetScores, 'PCI_DSS');
    assert.equal(t.rows.length, 1);
    assert.equal(t.rows[0].standard, 'PCI DSS');
  });

  it('a null standard score prints as a dash, not 0%', () => {
    const t = buildFleetSummaryTable(fleetScores, 'NIST');
    assert.equal(t.rows[0].score, '-');
  });

  const perDevice = [device('fw-a', { PCI_DSS: { pass: 8, fail: 2, warning: 0, na: 3 } })];

  it('unscoped per-device keeps the five-standard matrix', () => {
    const t = buildPerDeviceTable(perDevice);
    for (const s of STANDARDS) {
      assert.ok(t.columns.some((c) => c.key === s.key), `missing column ${s.key}`);
    }
  });

  it('scoped per-device shows the counts behind the percentage', () => {
    const t = buildPerDeviceTable(perDevice, 'PCI_DSS');
    const keys = t.columns.map((c) => c.key);
    assert.deepEqual(keys, ['device', 'vendor', 'score', 'pass', 'fail', 'warning', 'na']);
    assert.equal(t.rows[0].score, '80%');
    assert.equal(t.rows[0].na, 3);
  });

  it('⛔ "not assessable" is drawn hueless — it is a coverage gap, not a result', () => {
    const t = buildPerDeviceTable(perDevice, 'PCI_DSS');
    const naCol = t.columns.find((c) => c.key === 'na');
    assert.equal(typeof naCol.color, 'function');
    assert.equal(naCol.color(t.rows[0]), '#6D7784', 'na must use the unmeasured grey');
  });

  it('⛔ a device with nothing measurable shows a dash, never 0%', () => {
    const blind = [device('fw-b', { PCI_DSS: { pass: 0, fail: 0, warning: 0, na: 9 } })];
    const t = buildPerDeviceTable(blind, 'PCI_DSS');
    assert.equal(t.rows[0].score, '-');
    assert.notEqual(t.rows[0].score, '0%');
  });
});

describe('⛔ the catalogue and the engine cannot drift on which standards exist', () => {
  // The UI offers exactly the choices the catalogue declares; the route
  // allow-lists against those same choices; the engine then validates again
  // and THROWS on anything it does not know. So a standard offered in the
  // dropdown but absent from the engine is a 500 on download — a button that
  // visibly does nothing, which is the least diagnosable failure available.
  const entry = REPORTS.find((r) => r.id === 'compliance-fleet');

  it('the compliance report declares a standard parameter', () => {
    assert.ok(entry, 'compliance-fleet is not registered');
    const p = (entry.params || []).find((x) => x.key === 'standard');
    assert.ok(p, 'no standard parameter declared');
    assert.ok(p.allLabel, 'the empty option needs its own words, not a blank row');
  });

  it('every offered choice is one the engine will accept', () => {
    const p = entry.params.find((x) => x.key === 'standard');
    for (const c of p.choices) {
      assert.doesNotThrow(() => resolveStandard(c.value), `engine rejects offered value ${c.value}`);
    }
  });

  it('every standard the engine knows is offered — none is silently unreachable', () => {
    const p = entry.params.find((x) => x.key === 'standard');
    const offered = new Set(p.choices.map((c) => c.value));
    for (const k of STANDARD_KEYS) {
      assert.ok(offered.has(k), `${k} exists in the engine but cannot be chosen`);
    }
  });

  it('the labels match the engine\'s own, so two places do not name one standard differently', () => {
    const p = entry.params.find((x) => x.key === 'standard');
    for (const c of p.choices) {
      const s = STANDARDS.find((x) => x.key === c.value);
      assert.equal(c.label, s.label, `${c.value} is labelled differently in the catalogue`);
    }
  });
});

// ── The sentence that must never be an unqualified all-clear ─────────────

describe('unassessedDevices', () => {
  it('counts a device with no findings at all in the scope', () => {
    const fleet = [
      device('assessed', { PCI_DSS: { pass: 1, fail: 0, warning: 0, na: 0 } }),
      device('never-collected', {}),
    ];
    assert.deepEqual(unassessedDevices(fleet, 'PCI_DSS').map((d) => d.deviceName),
      ['never-collected']);
    assert.deepEqual(unassessedDevices(fleet).map((d) => d.deviceName), ['never-collected']);
  });

  it('⛔ an ‘na’ row means ASSESSED — the device was asked and we could not answer', () => {
    // That is a fact about SecVault's reach, already reported as "not
    // assessable". Counting it as uncollected would double-report one gap and
    // overstate the caveat.
    const fleet = [device('asked', { PCI_DSS: { pass: 0, fail: 0, warning: 0, na: 4 } })];
    assert.equal(unassessedDevices(fleet, 'PCI_DSS').length, 0);
  });

  it('a device assessed against ANOTHER standard is still unassessed for this one', () => {
    const fleet = [device('iso-only', { ISO_27001: { pass: 3, fail: 1, warning: 0, na: 0 } })];
    assert.equal(unassessedDevices(fleet, 'NIST').length, 1);
    assert.equal(unassessedDevices(fleet).length, 0, 'unscoped, it HAS been assessed');
  });

  it('tolerates a malformed row rather than throwing mid-render', () => {
    assert.equal(unassessedDevices([{}, null], 'SANS').length, 2);
    assert.equal(unassessedDevices(null).length, 0);
  });
});

describe('⛔ the report never prints a bare all-clear over incomplete coverage', () => {
  // THE FAILURE THIS PINS. "No failing or warning findings across the fleet" is
  // the most reassuring sentence this document can print, and on a fleet
  // nothing has been collected from it is also the most wrong: a firewall with
  // no findings contributes no failures, so a total collection outage renders
  // identically to a clean estate. CLAUDE.md forbids an all-clear while
  // coverage is incomplete.
  //
  // Driven through the real pdfkit render and read back out of the PDF's own
  // content streams, because the sentence is chosen inside renderReportBody(),
  // which is not exported — and a test that read the source instead would pass
  // on a branch that never executes.

  function stubPool({ devices, findings }) {
    return {
      query: async (sql) => {
        if (sql.includes('FROM devices WHERE active')) return { rows: devices };
        if (sql.includes('FROM audit_checks')) return { rows: [{ total: 45, mapped: 21 }] };
        if (sql.includes('remediation_guidance')) {
          return { rows: findings.filter((f) => f.status === 'fail' || f.status === 'warning') };
        }
        return { rows: findings };
      },
    };
  }

  // pdfkit writes every glyph run as a hex string inside a TJ array, so the
  // rendered words are invisible to a plain search of the buffer.
  function pdfText(buf) {
    return contentStreams(buf).map((stream) => {
      let out = '';
      stream.replace(/<([0-9a-fA-F]+)>/g, (whole, hex) => {
        for (let i = 0; i < hex.length; i += 2) {
          out += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
        }
        return whole;
      });
      return out;
    }).join('');
  }

  const threeDevices = [
    { id: 'd1', name: 'fw-a', vendor: 'fortinet' },
    { id: 'd2', name: 'fw-b', vendor: 'paloalto' },
    { id: 'd3', name: 'fw-c', vendor: 'paloalto' },
  ];

  it('⛔ a fleet with NO findings at all says so, instead of reading as clean', async () => {
    const pdf = await generateReportPdf(stubPool({ devices: threeDevices, findings: [] }));
    const text = pdfText(pdf);
    assert.match(text, /No failing or warning findings/, 'the base sentence is still printed');
    assert.match(text, /NOT an all-clear/,
      'a fleet nothing has been assessed against must not read as a fleet with nothing wrong');
    assert.match(text, /3 of 3/, 'the caveat must state how much of the fleet it covers');
  });

  it('a genuinely clean, fully assessed fleet still gets the plain sentence', async () => {
    // The counterpart: the caveat must not fire when coverage IS complete, or
    // it becomes noise and stops being read.
    const findings = threeDevices.map((d) => ({
      device_id: d.id, status: 'pass', standards: ['PCI_DSS', 'ISO_27001', 'CIS_V8', 'NIST', 'SANS'],
    }));
    const pdf = await generateReportPdf(stubPool({ devices: threeDevices, findings }));
    const text = pdfText(pdf);
    assert.match(text, /No failing or warning findings/);
    assert.equal(/NOT an all-clear/.test(text), false, 'nothing was uncollected here');
  });

  it('scoped, the caveat counts devices unassessed AGAINST THAT STANDARD', async () => {
    // Every device is assessed — but none of it maps to NIST, so a NIST
    // document has nothing behind its silence.
    const findings = threeDevices.map((d) => ({
      device_id: d.id, status: 'pass', standards: ['ISO_27001'],
    }));
    const pdf = await generateReportPdf(
      stubPool({ devices: threeDevices, findings }), { standard: 'NIST' }
    );
    const text = pdfText(pdf);
    assert.match(text, /NOT an all-clear/);
    assert.match(text, /3 of 3/);
  });
});
