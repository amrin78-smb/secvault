'use strict';
// tests/complianceDeviceScope.test.js
//
// ⛔ SCOPING A REPORT TO ONE FIREWALL IS NOT FILTERING THE FLEET DOCUMENT.
// The Compliance Report has always been able to narrow to one FRAMEWORK
// (`options.standard`); v2.166.0 adds the other axis, one FIREWALL. The whole
// risk lives in the denominators: every coverage figure in this document --
// mapped / applicable / evaluated / answered -- is read from the database at
// the scope being reported, and a JS-side filter over a fleet read would leave
// them counted across all sixteen firewalls while the scores came from one.
// That is precisely the overclaim v2.163.0 removed, and it would come straight
// back wearing a device filter.
//
// The case this file exists for is the one CLAUDE.md names: the "we could not
// measure this" branch. A firewall with nothing assessed must not read as a
// firewall with nothing wrong.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  generateReportPdf, buildReportData, summaryFromPerDevice, STANDARD_KEYS,
} = require('../lib/engines/complianceReport');
// The shared extractor — pdfkit compresses its content streams, so a plain
// regex over the buffer finds nothing. Same helper the standard-scope tests use.
const { contentStreams } = require('../lib/reports/pdfCompare');

const DEVICES = [
  { id: 'd1', name: 'fw-forti', vendor: 'fortinet' },
  { id: 'd2', name: 'fw-palo', vendor: 'paloalto' },
];

// One stub for every read the report makes, recording the SQL and the params
// it was handed, so the tests can assert BOTH the shape of the query and that
// the device id never reaches it as text.
function stubPool({ devices = DEVICES, findings = [], library = null } = {}) {
  const seen = [];
  return {
    seen,
    query: async (sql, params = []) => {
      seen.push({ sql, params });
      if (sql.includes('FROM devices WHERE id = $1')) {
        return { rows: devices.filter((d) => d.id === params[0]) };
      }
      if (sql.includes('FROM devices WHERE active')) {
        return { rows: params.length ? devices.filter((d) => d.id === params[0]) : devices };
      }
      if (sql.includes('library_total')) {
        // ⛔ The stub APPLIES the vendor filter rather than echoing a constant.
        // A stub that returned the same `applicable` either way would let the
        // assertion below pass against a query that ignored its parameter.
        const vendors = params.length ? params[0] : devices.map((d) => d.vendor);
        const rows = library || [
          { standard: 'PCI_DSS', mapped: 21, vendor: null },
          { standard: 'NIST', mapped: 7, vendor: 'fortinet' },
        ];
        return {
          rows: rows.map((r) => ({
            standard: r.standard,
            mapped: r.mapped,
            applicable: r.vendor === null || vendors.includes(r.vendor) ? r.mapped : 0,
            library_total: 45,
          })),
        };
      }
      if (sql.includes('answered_checks')) {
        const scoped = params.length ? findings.filter((x) => x.device_id === params[0]) : findings;
        return {
          rows: STANDARD_KEYS.map((k) => ({
            standard: k,
            evaluated_checks: scoped.length,
            answered_checks: scoped.filter((x) => x.status !== 'na').length,
          })),
        };
      }
      if (sql.includes('remediation_guidance')) {
        const open = findings.filter((x) => x.status === 'fail' || x.status === 'warning');
        const last = params.length ? params[params.length - 1] : null;
        const scoped = typeof last === 'string' ? open.filter((x) => x.device_id === last) : open;
        return {
          rows: scoped.map((x) => ({
            device_id: x.device_id,
            device_name: (devices.find((d) => d.id === x.device_id) || {}).name,
            check_name: 'a check',
            severity: 'high',
            status: x.status,
            detail: 'detail',
            remediation_guidance: 'fix it',
          })),
        };
      }
      if (sql.includes('FROM audit_checks')) return { rows: [{ total: 45, mapped: 21 }] };
      // per-device findings
      return { rows: params.length ? findings.filter((x) => x.device_id === params[0]) : findings };
    },
  };
}

const ALL = ['PCI_DSS', 'ISO_27001', 'CIS_V8', 'NIST', 'SANS'];
const f = (device_id, status, standards = ALL) => ({ device_id, status, standards });

// pdfkit writes every glyph run as a hex string inside a TJ array, so the
// rendered words are invisible to a plain search of the buffer.
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

describe('an unresolvable device produces NO report, never the fleet one', () => {
  it('returns null for an id that is not an active device', async () => {
    assert.equal(await generateReportPdf(stubPool(), { deviceId: 'nope' }), null);
    assert.equal(await buildReportData(stubPool(), { deviceId: 'nope' }), null);
  });

  it('and the fleet report is still produced when NO device is asked for', async () => {
    // The null must come from an unresolvable REQUEST, never from the absence
    // of one -- that would take the whole report offline.
    const pdf = await generateReportPdf(stubPool({ findings: [f('d1', 'pass')] }));
    assert.ok(Buffer.isBuffer(pdf) && pdf.length > 1000);
  });
});

describe('the numbers are that firewall own, not the fleet ones', () => {
  // fw-forti passes everything, fw-palo fails everything. A scoped report that
  // reused the fleet read would print 50% under either name.
  const findings = [f('d1', 'pass'), f('d2', 'fail')];

  it('scores the scoped device alone', async () => {
    const d1 = await buildReportData(stubPool({ findings }), { deviceId: 'd1' });
    const d2 = await buildReportData(stubPool({ findings }), { deviceId: 'd2' });
    assert.equal(d1.fleet.overall, 100, 'fw-forti passes everything');
    assert.equal(d2.fleet.overall, 0, 'fw-palo fails everything');
    assert.equal(d1.perDevice.length, 1);
    assert.equal(d1.perDevice[0].deviceName, 'fw-forti');
  });

  it('and the unscoped report still reports the fleet', async () => {
    const fleet = await buildReportData(stubPool({ findings }));
    assert.equal(fleet.perDevice.length, 2);
    assert.equal(fleet.fleet.overall, 50);
  });

  it('summaryFromPerDevice reproduces the fleet formula, including its overall', async () => {
    // The product-wide `overall` sums the PER-STANDARD counts, so a check
    // mapped to three frameworks contributes to three of them. Recomputing it
    // over distinct findings here would print a different number under the
    // same word on one report out of eleven.
    const perDevice = [{
      standards: {
        PCI_DSS: { pass: 3, fail: 1, warning: 0, na: 0 },
        ISO_27001: { pass: 1, fail: 1, warning: 0, na: 0 },
        CIS_V8: { pass: 0, fail: 0, warning: 0, na: 2 },
        NIST: { pass: 0, fail: 0, warning: 0, na: 0 },
        SANS: { pass: 0, fail: 0, warning: 0, na: 0 },
      },
    }];
    const s = summaryFromPerDevice(perDevice);
    assert.equal(s.byStandard.PCI_DSS, 75);
    assert.equal(s.byStandard.ISO_27001, 50);
    assert.equal(s.byStandard.CIS_V8, null, 'na only is not a zero');
    assert.equal(s.byStandard.NIST, null, 'nothing measured is not a zero');
    assert.equal(s.overall, 67, '(3+1) pass of (4+2) measurable, summed per standard');
    assert.deepEqual(s.byStandardCounts.PCI_DSS, { pass: 3, fail: 1, warning: 0 });
  });
});

describe('the coverage denominator is re-read at the device scope', () => {
  const findings = [f('d1', 'pass'), f('d2', 'pass')];

  it('a vendor-scoped check is APPLICABLE on that vendor and not on another', async () => {
    // NIST's check here is fortinet-only. On the Palo Alto it can never run, so
    // crediting the device with it would be the fleet denominator under one
    // firewall's name.
    const forti = await buildReportData(stubPool({ findings }), { deviceId: 'd1' });
    const palo = await buildReportData(stubPool({ findings }), { deviceId: 'd2' });
    assert.equal(forti.library.byStandard.NIST.applicable, 7);
    assert.equal(palo.library.byStandard.NIST.applicable, 0,
      'a fortinet-only check cannot run on a Palo Alto');
    // `mapped` is a property of the LIBRARY and does not move with the scope.
    assert.equal(palo.library.byStandard.NIST.mapped, 7);
  });

  it('the library read is given THIS device vendor, as a bound parameter', async () => {
    const pool = stubPool({ findings });
    await buildReportData(pool, { deviceId: 'd2' });
    const lib = pool.seen.find((q) => q.sql.includes('library_total'));
    assert.deepEqual(lib.params, [['paloalto']], 'the vendor is bound, never interpolated');
  });

  it('the coverage statement is built at device scope, not fleet scope', async () => {
    const scoped = await buildReportData(stubPool({ findings }), { deviceId: 'd1' });
    const fleet = await buildReportData(stubPool({ findings }));
    assert.equal(scoped.coverageIndex.PCI_DSS.deviceCount, 1);
    assert.equal(fleet.coverageIndex.PCI_DSS.deviceCount, 2);
    assert.equal(scoped.coverageIndex.PCI_DSS.scope, 'device');
  });
});

describe('every scope-dependent noun follows the scope', () => {
  it('names the firewall in the title and never says across the fleet', async () => {
    const pdf = await generateReportPdf(
      stubPool({ findings: [f('d1', 'pass')] }), { deviceId: 'd1' }
    );
    const text = pdfText(pdf);
    // ⛔ THE TITLE SPECIFICALLY, not merely that the name appears somewhere.
    // A bare /fw-forti/ also matches the cover tile and the appendix heading, so
    // it passes with the title left as a bare "Compliance Report" -- which is
    // the exact confusion the device name is in the title to prevent.
    // (pdfkit transliterates the em dash to a hyphen.)
    assert.match(text, /fw-forti - Compliance Report/, 'the firewall names the document');
    assert.equal(/across the fleet/.test(text), false,
      'a one-firewall document must not make a claim about fifteen others');
    assert.equal(/Per-Device Scores/.test(text), false,
      'a single-row per-device table restates the summary cell for cell');
  });

  it('the fleet report keeps its fleet wording and its per-device table', async () => {
    const text = pdfText(await generateReportPdf(stubPool({ findings: [f('d1', 'pass')] })));
    assert.match(text, /Per-Device Scores/);
  });

  it('an unassessed firewall gets its own sentence, not 1 of 1 firewalls', async () => {
    // THE CASE THIS FILE EXISTS FOR. Nothing assessed on fw-palo, so the
    // all-clear must carry the gap that produced it.
    const text = pdfText(await generateReportPdf(
      stubPool({ findings: [f('d1', 'pass')] }), { deviceId: 'd2' }
    ));
    assert.match(text, /No failing or warning findings/);
    assert.match(text, /NOT an all-clear/,
      'a firewall nothing was assessed on must not read as one with nothing wrong');
    assert.match(text, /fw-palo has no findings recorded/);
    // ⛔ Anchored on the word, because "Page 1 of 1" also matches a bare /1 of 1/
    // -- a test that passed on the page footer would prove nothing about the sentence.
    assert.equal(/\d+ of \d+ firewalls/.test(text), false,
      'a statistic about an estate of one is not a fact');
  });

  it('the findings appendix carries ONLY the scoped firewall', async () => {
    // ⛔ The appendix is the half an auditor actually reads. A fleet-wide
    // appendix under one firewall's name would attribute another firewall's
    // failures to this one -- and a clean device would come back with a page of
    // findings it did not produce.
    const findings = [f('d1', 'pass'), f('d2', 'fail')];
    const scoped = pdfText(await generateReportPdf(stubPool({ findings }), { deviceId: 'd1' }));
    assert.equal(/fw-palo/.test(scoped), false,
      "fw-palo's failing check must not appear in fw-forti's report");
    assert.match(scoped, /No failing or warning findings on fw-forti/);

    // The counterpart: the fleet report still carries it, so the assertion
    // above is about SCOPE and not about the finding having vanished.
    const fleet = pdfText(await generateReportPdf(stubPool({ findings })));
    assert.match(fleet, /fw-palo/);
  });

  it('a genuinely assessed, clean firewall gets the plain sentence', async () => {
    const text = pdfText(await generateReportPdf(
      stubPool({ findings: [f('d1', 'pass')] }), { deviceId: 'd1' }
    ));
    assert.match(text, /No failing or warning findings on fw-forti/);
    assert.equal(/NOT an all-clear/.test(text), false, 'nothing was uncollected here');
  });
});

describe('both axes at once', () => {
  const findings = [
    f('d1', 'pass', ['PCI_DSS']),
    f('d1', 'fail', ['NIST']),
    f('d2', 'fail', ['PCI_DSS']),
  ];

  it('one firewall AND one standard narrows both', async () => {
    const data = await buildReportData(stubPool({ findings }), { deviceId: 'd1', standard: 'PCI_DSS' });
    assert.equal(data.standard, 'PCI_DSS');
    assert.equal(data.device.name, 'fw-forti');
    assert.equal(data.fleet.byStandard.PCI_DSS, 100, 'fw-forti PCI result alone');
    const text = pdfText(await generateReportPdf(stubPool({ findings }), { deviceId: 'd1', standard: 'PCI_DSS' }));
    // ⛔ Both axes in the title, and the standard half unchanged from what
    // already-filed fleet copies are named.
    assert.match(text, /fw-forti - PCI DSS Compliance Report/);
  });

  it('an unknown standard is still refused when a device is scoped', async () => {
    // The device axis must not become a way around the standard allow-list.
    await assert.rejects(
      () => buildReportData(stubPool(), { deviceId: 'd1', standard: 'HIPAA' }),
      /Unknown compliance standard/
    );
  });

  it('the device id is BOUND in every query that takes it', async () => {
    const pool = stubPool({ findings: [f('d1', 'pass')] });
    await buildReportData(pool, { deviceId: 'd1' });
    const touching = pool.seen.filter((q) => q.params.some((x) => x === 'd1'));
    assert.ok(touching.length >= 4, 'resolve + devices + findings + rollup all take it');
    for (const q of pool.seen) {
      assert.equal(q.sql.includes('d1'), false,
        `device id interpolated into SQL: ${q.sql.slice(0, 60)}`);
    }
  });
});
