'use strict';
// Pins lib/reports/chassis.js, lib/reports/catalogue.js and lib/reports/pdfCompare.js.
//
// ⛔ WHAT THIS EXTRACTION ACTUALLY FOUND, because it is the argument for the
// whole directory. complianceReport.js and ruleChangeRequestReport.js each
// carried a private copy of seven PDF helpers. The second file's header says
// they were "ported" from the first. Measured before extraction: ALL FOUR
// drawing helpers had diverged, and the second had grown three more the first
// never received.
//
// The consequential one is `ensureSpace`. Its comment records a real observed
// failure — a table header started 20px above the bottom margin produced FIVE
// pages each carrying a single column heading, with the rows on a sixth. That
// fix was written into the change-request report and never travelled back to
// the compliance report, which is the one emailed to stakeholders monthly.
//
// So: a fix applied to one copy of duplicated code is not applied to the other,
// and nobody finds out until the shape of the data changes.
//
// ⛔ THE SAFETY PROPERTY OF A REPORT REFACTOR IS "THE DOCUMENT DID NOT CHANGE."
// A report is an audit artefact; silently repaginating one is not a refactor,
// it is a new document with the old name. Passing unit tests do not prove that
// — every test in this repo could pass while the cover moved 6pt. That is what
// pdfCompare exists for, and why it compares DRAWING OPERATORS rather than
// extracted text: extracted text would pass a document whose words are right
// and whose coordinates are wrong.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const chassis = require('../lib/reports/chassis');
const { comparePdfs, contentStreams } = require('../lib/reports/pdfCompare');
const { REPORTS, reportById, visibleReports, SCOPES } = require('../lib/reports/catalogue');

const ENGINES = path.join(__dirname, '..', 'lib', 'engines');
const readEngine = (f) => fs.readFileSync(path.join(ENGINES, f), 'utf8');

describe('the chassis owns the helpers, and the copies are gone', () => {
  const HELPERS = [
    'pdfSafe', 'installPdfSafeText', 'fmtStamp',
    'drawCover', 'sectionTitle', 'drawTable', 'stampHeadersFooters',
  ];

  it('exports every helper both reports needed', () => {
    for (const h of HELPERS) {
      assert.equal(typeof chassis[h], 'function', `${h} must be exported`);
    }
    // The three that existed in only one copy, now available to both.
    for (const h of ['ensureSpace', 'paragraph', 'labelledNote', 'layoutOf']) {
      assert.equal(typeof chassis[h], 'function', `${h} must be exported`);
    }
  });

  for (const file of ['complianceReport.js', 'ruleChangeRequestReport.js']) {
    it(`${file} no longer defines its own copy`, () => {
      const src = readEngine(file);
      for (const h of HELPERS) {
        assert.equal(
          new RegExp(`^function ${h}\\s*\\(`, 'm').test(src), false,
          `${file} still defines its own ${h} — the copies are what drifted`
        );
      }
      assert.match(src, /require\('\.\.\/reports\/chassis'\)/, 'must import the chassis');
    });
  }

  it('⛔ the compliance report now has the page-break guard it never had', () => {
    // Before extraction this file contained zero occurrences of ensureSpace,
    // while the change-request report used it in four places.
    assert.equal(typeof chassis.ensureSpace, 'function');
    const src = readEngine('complianceReport.js');
    assert.match(src, /drawTable/, 'still draws tables');
    // It inherits the guard through the chassis rather than by having its own.
    assert.equal(/function ensureSpace/.test(src), false);
  });

  it('⛔ fmtStamp is UTC with an explicit marker', () => {
    // An earlier draft of the chassis REWROTE this helper from memory and
    // produced a different format with no UTC marker, which would have silently
    // restamped every report. A report is read in a different timezone from the
    // one that produced it; a bare local timestamp is ambiguous evidence.
    const out = chassis.fmtStamp(new Date('2026-09-15T00:22:18Z'));
    assert.match(out, /UTC$/, 'must carry the zone');
    assert.match(out, /00:22:18/, 'must be the UTC wall time, not a local one');
  });

  it('fmtStamp survives null and an unparseable value', () => {
    assert.equal(chassis.fmtStamp(null), '');
    assert.equal(chassis.fmtStamp(undefined), '');
    assert.equal(chassis.fmtStamp('not a date'), 'not a date');
  });

  it('pdfSafe strips the glyphs WinAnsi Helvetica cannot draw', () => {
    // A vendor rule name or an analyser detail string genuinely carries these,
    // and pdfkit renders a missing glyph as nothing at all — silently dropping
    // a character out of an audit document.
    assert.equal(chassis.pdfSafe('a–b—c'), 'a-b-c');
    assert.equal(chassis.pdfSafe('‘q’'), "'q'");
    assert.equal(chassis.pdfSafe('“q”'), '"q"');
    assert.equal(chassis.pdfSafe(null), '');
    assert.equal(chassis.pdfSafe(0), '0');
  });

  it('the palette carries no colour named for a colour it is not', () => {
    // complianceReport.js aliased `RED = ACCENT`, left over from when the brand
    // was red. That alias is not reproduced: a constant lying about its own hue
    // is how the palette rot in app/globals.css started.
    assert.equal(chassis.ACCENT, '#098294');
    assert.equal(chassis.RED, undefined, 'no RED alias may return');
  });
});

describe('⛔ pdfCompare proves a document did not change', () => {
  // A minimal, well-formed deflate-stream PDF is awkward to hand-write, so
  // these drive the comparator's own logic through contentStreams/comparePdfs
  // on real buffers produced below.
  const zlib = require('zlib');

  function fakePdf(ops) {
    const body = zlib.deflateSync(Buffer.from(ops, 'latin1'));
    const head = Buffer.from('%PDF-1.3\n5 0 obj\n<<\n/Filter /FlateDecode\n>>\nstream\n', 'latin1');
    const tail = Buffer.from('\nendstream\nendobj\n', 'latin1');
    return Buffer.concat([head, body, tail]);
  }

  it('identical drawing operators compare equal', () => {
    const a = fakePdf('BT\n1 0 0 1 50 700 Tm\n[<48656c6c6f> 0] TJ\nET');
    const b = fakePdf('BT\n1 0 0 1 50 700 Tm\n[<48656c6c6f> 0] TJ\nET');
    assert.equal(comparePdfs(a, b).equal, true);
  });

  it('⛔ a MOVED coordinate is caught, even though the text is unchanged', () => {
    // The failure that extracted-text comparison would wave through, and the
    // reason this compares operators.
    const a = fakePdf('BT\n1 0 0 1 50 700 Tm\n[<48656c6c6f> 0] TJ\nET');
    const b = fakePdf('BT\n1 0 0 1 50 694 Tm\n[<48656c6c6f> 0] TJ\nET');
    const r = comparePdfs(a, b);
    assert.equal(r.equal, false);
    assert.match(r.reason, /drawing operators differ/);
    assert.match(r.firstDifference.before, /700/);
    assert.match(r.firstDifference.after, /694/);
  });

  it('a changed page count is reported as such, not as an operator diff', () => {
    const one = fakePdf('BT\n[<41> 0] TJ\nET');
    const two = Buffer.concat([one, fakePdf('BT\n[<42> 0] TJ\nET')]);
    const r = comparePdfs(one, two);
    assert.equal(r.equal, false);
    assert.match(r.reason, /stream count changed/);
  });

  it('⛔ the report\'s OWN rendered timestamp is normalised, not the whole string', () => {
    // pdfkit writes text as hex inside TJ arrays, so the stamp is invisible to a
    // naive comparison. Two runs minutes apart are the same document.
    const hex = (s) => Buffer.from(s, 'latin1').toString('hex');
    const a = fakePdf(`BT\n[<${hex('Generated 15/09/2026, 00:22:18 UTC')}> 0] TJ\nET`);
    const b = fakePdf(`BT\n[<${hex('Generated 15/09/2026, 00:27:29 UTC')}> 0] TJ\nET`);
    assert.equal(comparePdfs(a, b).equal, true, 'only the clock moved');
  });

  it('⛔ but a change to the surrounding words is NOT normalised away', () => {
    const hex = (s) => Buffer.from(s, 'latin1').toString('hex');
    const a = fakePdf(`BT\n[<${hex('Generated 15/09/2026, 00:22:18 UTC')}> 0] TJ\nET`);
    const b = fakePdf(`BT\n[<${hex('Produced 15/09/2026, 00:22:18 UTC')}> 0] TJ\nET`);
    assert.equal(comparePdfs(a, b).equal, false, 'the label changed, not the clock');
  });

  it('ignores streams it cannot inflate rather than throwing', () => {
    // Font programmes and images are not deflate text streams.
    const junk = Buffer.from('%PDF-1.3\n1 0 obj\nstream\nNOT-DEFLATE\nendstream\n', 'latin1');
    assert.deepEqual(contentStreams(junk), []);
  });
});

describe('the catalogue is the single source of truth', () => {
  it('registers only reports that actually exist today', () => {
    // ⛔ An entry is a promise the UI will render and the route will serve. A
    // catalogue listing reports that return nothing is the same "looks
    // complete, is not" failure this codebase keeps finding.
    assert.equal(REPORTS.length, 2);
    assert.deepEqual(REPORTS.map((r) => r.id).sort(), ['compliance-fleet', 'rule-change-request']);
  });

  it('every entry is fully specified', () => {
    for (const r of REPORTS) {
      assert.ok(r.id && typeof r.id === 'string', 'needs an id');
      assert.ok(r.name && r.summary, `${r.id} needs a name and summary`);
      assert.ok(Object.values(SCOPES).includes(r.scope), `${r.id} has an unknown scope`);
      assert.ok(r.capability, `${r.id} must name the capability its route enforces`);
      assert.ok(Array.isArray(r.formats) && r.formats.length, `${r.id} needs formats`);
      assert.equal(typeof r.builder, 'function', `${r.id} needs a lazy builder`);
    }
  });

  it('every builder resolves to a real function', () => {
    // Catches a rename in an engine that would otherwise only surface when an
    // operator clicked Download.
    for (const r of REPORTS) {
      assert.equal(typeof r.builder(), 'function', `${r.id}'s builder does not resolve`);
    }
  });

  it('reportById returns null rather than a stub for an unknown id', () => {
    assert.equal(reportById('no-such-report'), null);
    assert.equal(reportById(''), null);
    assert.equal(reportById(undefined), null);
    assert.ok(reportById('compliance-fleet'));
  });

  it('⛔ visibleReports filters for DISCOVERY and is not a security boundary', () => {
    // It stops an operator being shown a report they cannot fetch. It does not
    // stop them fetching it — the route must call can() itself.
    assert.equal(visibleReports({}).length, 0, 'no capabilities, nothing listed');
    assert.equal(visibleReports({ operate: true }).length, 2);
    assert.equal(visibleReports(null).length, 0, 'a null capability set grants nothing');
  });
});
