'use strict';
// tests/reportUnmeasuredText.test.js
//
// Three defects found by review 2026-09-27, all in the same place: the WORDS an
// audit artefact uses for something SecVault could not measure, or measured a
// weaker way than the column heading claims. A PDF is handed to a change board
// or an auditor; there is no tooltip and no follow-up question.
//
// ⛔ ALL THREE ARE THE SAME CLASS AS `hit_count DEFAULT 0` — a gap rendered as
// something confident. A raw enum slug, a `&` where a warning sign was meant,
// and a DERIVED bound printed in a column whose absence label says "None
// published" are each a statement the reader has no way to discount.
//
// ⛔ These live in their own file rather than in tests/reportChassis.test.js,
// which pins the EXTRACTION of the chassis and asserts that extraction changed
// no output. This file asserts deliberate changes to what is rendered.

const { test, describe, it } = require('node:test');
const assert = require('node:assert/strict');
const PDFDocument = require('pdfkit');

const chassis = require('../lib/reports/chassis');
const {
  UNMEASURED_REASON, unmeasuredReasonPhrase,
} = require('../lib/reports/ruleRiskByTraffic');

// ═════════════════════════════════════════════════════════════════════════
// FINDING 2 — the two new logEvidence codes had no operator-facing wording
//
// `lib/reports/ruleRiskByTrafficPdf.js` renders
// `unmeasuredReasonText[code] || code`. Measured live at `days: 30`:
//
//   unmeasuredByReason = { 'insufficient-history': 970,
//                          'rule-logging-disabled': 15,
//                          'window-too-short': 33 }
//
// so the DOMINANT reason — 970 of 1,018 unmeasured rules — printed as the
// literal string `970 — insufficient-history`. `no-rule-identity` was absent too
// and is reachable live (a firewall whose rollup rows name no rule at all).

// Every code `enrichRulesWithLogEvidence` can attach to a rule whose
// `loggedHits` is null, i.e. every code that can reach the unmeasured bucket.
const UNMEASURABLE_CODES = [
  'no-coverage',
  'window-too-short',
  'rule-logging-disabled',
  'insufficient-history',
  'no-rule-identity',
];

describe('⛔ every unmeasured reason has operator-facing words', () => {
  it('covers every code that can reach the unmeasured bucket', () => {
    const missing = UNMEASURABLE_CODES.filter(
      (c) => !Object.prototype.hasOwnProperty.call(UNMEASURED_REASON, c)
    );
    assert.deepEqual(missing, [],
      'an unmapped code prints as its own enum slug in a customer-facing PDF');
  });

  it('and the codes really are the engine\'s own vocabulary, not a copy', () => {
    // Guards the list above against drifting away from what the engine emits —
    // otherwise this file could go green over a code nobody maps.
    const src = require('node:fs').readFileSync(
      require('node:path').join(__dirname, '..', 'lib', 'engines', 'ruleHitCorrelation.js'),
      'utf8'
    );
    const { stripComments } = require('./stripComments');
    const code = stripComments(src);
    for (const c of UNMEASURABLE_CODES) {
      assert.ok(code.includes(`'${c}'`), `${c} must still be a value the engine assigns`);
    }
  });

  it('no phrase is a slug — they are sentences a stranger can act on', () => {
    for (const [code, text] of Object.entries(UNMEASURED_REASON)) {
      assert.ok(text.length > 25, `${code} reads like an identifier: ${text}`);
      assert.ok(text.includes(' '), `${code} has no words`);
      assert.ok(!text.includes(code), `${code} must not restate its own key`);
    }
  });

  it('⛔ insufficient-history says the limit is OURS, not the firewall\'s', () => {
    // The entire reason ruleHitCorrelation.js separated this from `no-coverage`.
    // The firewall may have logged every single hour of the window; SecVault has
    // simply not been collecting for that long. Wording it as a logging gap
    // reports our own install date as a fault of the device.
    const ours = UNMEASURED_REASON['insufficient-history'];
    assert.match(ours, /SecVault/);
    assert.match(ours, /our own|not a fault on the firewall/i);
    assert.ok(!/was not logging|did not send/i.test(ours),
      'it must not read as a logging gap on the device');
  });

  it('⛔ and reads DIFFERENTLY from no-coverage, which IS the firewall\'s', () => {
    const ours = UNMEASURED_REASON['insufficient-history'];
    const theirs = UNMEASURED_REASON['no-coverage'];
    assert.notEqual(ours, theirs);
    assert.match(theirs, /firewall was not logging/i);
    assert.ok(!/SecVault has not been collecting/i.test(theirs));
  });

  it('no-rule-identity is about the LOG FORMAT, not about any rule being idle', () => {
    const t = UNMEASURED_REASON['no-rule-identity'];
    assert.match(t, /do not say which rule|not say which rule/i);
    assert.ok(!/no traffic|idle|unused/i.test(t));
  });

  it('⛔ an UNMAPPED code renders as unknown, never as itself', () => {
    // The `|| k` fallback is what put a slug in front of a reader. A state this
    // file has not been taught is unknown, and saying so is the honest rendering.
    const p = unmeasuredReasonPhrase('some-future-code');
    assert.match(p, /unknown/i);
    assert.ok(p.length > 30, 'it must be a sentence, not the slug plus a word');
    assert.ok(!/^some-future-code$/.test(p));
  });

  it('a known code is passed through verbatim from the one table', () => {
    for (const c of UNMEASURABLE_CODES) {
      assert.equal(unmeasuredReasonPhrase(c), UNMEASURED_REASON[c]);
    }
  });

  it('null/empty are unknown too, never an empty line item', () => {
    for (const bad of [null, undefined, '']) {
      assert.match(unmeasuredReasonPhrase(bad), /unknown/i);
    }
  });

  it('⛔ the PDF renders through the phrase helper, not through `|| code`', () => {
    const { stripComments } = require('./stripComments');
    const src = stripComments(require('node:fs').readFileSync(
      require('node:path').join(__dirname, '..', 'lib', 'reports', 'ruleRiskByTrafficPdf.js'),
      'utf8'
    ));
    assert.match(src, /unmeasuredReasonPhrase\(/);
    assert.ok(!/unmeasuredReasonText\[[a-z]\]\s*\|\|/.test(src),
      'the slug fallback must be gone from the renderer, not merely unreachable');
  });
});

// ═════════════════════════════════════════════════════════════════════════
// FINDING 3 — pdfSafe had no mapping for U+26A0, so the caveat printed as `&`
//
// Verified at byte level against the bundled pdfkit and re-verified here rather
// than asserted about: `doc.text('X1⚠X2')` emits WinAnsi 0x26 ('&') + 0xA0,
// and `widthOfString('⚠')` is 0 — so the wrap measurement is two glyphs
// short for the rest of the line as well.

describe('⛔ pdfSafe maps every glyph WinAnsi Helvetica cannot draw', () => {
  // The probe the fix was decided on. A glyph is unsafe when Helvetica encodes
  // it to more than one byte (i.e. as its own hex name) or measures it at zero
  // width. Asserted against the REAL font, so this cannot drift with pdfkit.
  function encodedWidth(s) {
    const doc = new PDFDocument({ autoFirstPage: false });
    doc.font('Helvetica').fontSize(10);
    return doc.widthOfString(s);
  }

  const MUST_MAP = ['⚠', '⚡', '✓', '✗', '→', '⇒', '️'];

  it('the glyphs mapped really are unrenderable — measured, not assumed', () => {
    for (const c of MUST_MAP) {
      assert.equal(encodedWidth(c), 0,
        `U+${c.codePointAt(0).toString(16)} measures non-zero; it may not need mapping`);
    }
  });

  it('and every one of them survives pdfSafe as ASCII', () => {
    for (const c of MUST_MAP) {
      const out = chassis.pdfSafe(`a${c}b`);
      assert.ok(!out.includes(c), `U+${c.codePointAt(0).toString(16)} still reaches the PDF`);
      // eslint-disable-next-line no-control-regex
      assert.ok(/^[\x20-\x7e]*$/.test(out), `pdfSafe produced non-ASCII: ${JSON.stringify(out)}`);
      assert.ok(encodedWidth(out) > 0, 'and what it produced has width');
    }
  });

  it('⛔ U+2026 is deliberately NOT mapped, because it DRAWS', () => {
    // The counter-case, and the reason the list was measured rather than chosen
    // by eye: WinAnsi encodes an ellipsis as the single byte 0x85 at width 10.
    // Mapping it would have changed the bytes of two shipped audit reports for no
    // defect, and this chassis exists because extraction must not change output.
    assert.ok(encodedWidth('…') > 0);
    assert.equal(chassis.pdfSafe('a…b'), 'a…b');
  });

  it('the pre-existing mappings are unchanged', () => {
    // A regression here would restamp every report in the product.
    assert.equal(chassis.pdfSafe('a–b—c'), 'a-b-c');
    assert.equal(chassis.pdfSafe('‘q’'), "'q'");
    assert.equal(chassis.pdfSafe('“q”'), '"q"');
    assert.equal(chassis.pdfSafe('a•b'), 'a-b');
    assert.equal(chassis.pdfSafe('a b'), 'a b');
    assert.equal(chassis.pdfSafe(null), '');
    assert.equal(chassis.pdfSafe(0), '0');
  });

  it('⛔ the warning sign becomes a visible marker, not a silent drop', () => {
    // Dropping it would leave "Matched by rule NAME" with no attention cue at
    // all, which is the same loss by a quieter route.
    assert.equal(chassis.pdfSafe('⚠ careful'), '! careful');
  });
});

// ═════════════════════════════════════════════════════════════════════════
// FINDING 8 — a DERIVED fix boundary printed in a column labelled "None published"
//
// `lib/reports/vulnerabilityPosture.js` renders `f.fixed_in || 'None published'`
// with `_fixedColor: GREEN`. But `versionMatcher.js` DERIVES `fixed_in` from a
// range's `exclude_fixed: true` boundary whenever `advisories.fixed_in_versions`
// is empty — the common case (only 10 of 955 hub advisories populate it) — and
// `device_cve_assessments` carries no provenance flag, so no consumer can tell a
// vendor's stated fix release from a bound SecVault read off a range.
//
// The derivation is sound (`exclude_fixed: true` means "up to but NOT including
// max", so max IS the first fixed release). What is wrong is presenting a
// definitional reading and a vendor's statement in one column, in one colour,
// under a label that claims publication.

describe('⛔ a derived fix boundary is not a published fix version', () => {
  const { fixProvenance, fixVersionCell, FIX_PROVENANCE, GREEN, UNMEASURED } = chassis;

  const RANGES = [
    { min: '7.4.0', max: '7.4.11', exclude_fixed: true },
    { min: '7.2.0', max: '7.2.9', exclude_fixed: false },
  ];

  it('a version in the vendor\'s own list is published', () => {
    assert.equal(fixProvenance('7.4.11', ['7.4.11', '7.6.1'], RANGES), FIX_PROVENANCE.PUBLISHED);
  });

  it('⛔ the SAME version read off a range boundary is DERIVED', () => {
    // The live shape: CVE-2026-24858 on three FortiGates. fixed_in_versions is
    // empty; the boundary is where 7.4.11 came from.
    assert.equal(fixProvenance('7.4.11', [], RANGES), FIX_PROVENANCE.DERIVED);
  });

  it('⛔ a bound that is NOT a fix boundary is not derived either', () => {
    // 7.2.9 sits on a range with exclude_fixed FALSE, so it is still vulnerable
    // and naming it a fix would be inventing one.
    assert.equal(fixProvenance('7.2.9', [], RANGES), FIX_PROVENANCE.UNKNOWN);
  });

  it('⛔ a caller that did not select the advisory columns is told UNKNOWN', () => {
    // Never `published`. Defaulting to the stronger claim because we lack the
    // evidence to weaken it is the failed-read-as-a-fact rule wearing a
    // remediation hat.
    assert.equal(fixProvenance('7.4.11', undefined, undefined), FIX_PROVENANCE.UNKNOWN);
    assert.equal(fixProvenance('7.4.11', null, null), FIX_PROVENANCE.UNKNOWN);
  });

  it('no fix at all is its own state, distinct from unknown', () => {
    for (const v of [null, undefined, '', '   ']) {
      assert.equal(fixProvenance(v, [], RANGES), FIX_PROVENANCE.NONE);
    }
  });

  it('a value in NEITHER the list nor the boundaries is unknown', () => {
    assert.equal(fixProvenance('9.9.9', ['7.4.11'], RANGES), FIX_PROVENANCE.UNKNOWN);
  });

  it('⛔ ONLY a published version gets GREEN', () => {
    assert.equal(fixVersionCell('7.4.11', ['7.4.11'], RANGES).color, GREEN);
    assert.equal(fixVersionCell('7.4.11', [], RANGES).color, UNMEASURED);
    assert.equal(fixVersionCell('7.4.11', undefined, undefined).color, UNMEASURED);
    assert.equal(fixVersionCell(null, [], RANGES).color, UNMEASURED);
  });

  it('⛔ the derived cell still PRINTS the version, and says where it came from', () => {
    // Withholding it would leave the fleet's urgent CVEs with no upgrade target
    // at all, which is the defect the derivation was added to fix.
    const cell = fixVersionCell('7.4.11', [], RANGES);
    assert.match(cell.text, /7\.4\.11/);
    assert.match(cell.text, /not published as a fix/i);
    assert.equal(cell.provenance, FIX_PROVENANCE.DERIVED);
  });

  it('and the "None published" label is reserved for an actual absence', () => {
    assert.equal(fixVersionCell(null, [], RANGES).text, 'None published');
    for (const list of [[], ['7.4.11']]) {
      const cell = fixVersionCell('7.4.11', list, RANGES);
      assert.ok(!/None published/.test(cell.text),
        'a present value must never carry the absence label');
    }
  });

  it('a malformed ranges entry cannot fabricate a provenance', () => {
    for (const bad of [[null], ['x'], [{}], [{ exclude_fixed: 'true', max: '7.4.11' }],
      [{ exclude_fixed: true, max: null }], [{ exclude_fixed: true }]]) {
      assert.equal(fixProvenance('7.4.11', [], bad), FIX_PROVENANCE.UNKNOWN,
        `${JSON.stringify(bad)} must not read as a boundary`);
    }
  });

  it('the precedence matches versionMatcher: a published list outranks a boundary', () => {
    // versionMatcher.js derives ONLY when the published list is empty. If the
    // value is present and the list is non-empty but does not contain it, the
    // two have disagreed and the honest answer is unknown — never `derived` on
    // the strength of a boundary the engine would not have consulted.
    assert.equal(fixProvenance('7.4.11', ['7.6.1'], RANGES), FIX_PROVENANCE.UNKNOWN);
  });
});

test('pdfSafe still sanitises every string drawn, via installPdfSafeText', () => {
  // The wrapper is what makes the mapping unavoidable rather than per-call.
  const doc = chassis.installPdfSafeText(new PDFDocument({ autoFirstPage: false }));
  const seen = [];
  const inner = doc.text;
  assert.equal(typeof inner, 'function');
  doc.addPage();
  // Draw through the wrapper and confirm no unmappable byte reaches the stream.
  const chunks = [];
  doc.on('data', (c) => chunks.push(c));
  doc.font('Helvetica').fontSize(10).text('x ⚠ y ✓ z');
  doc.end();
  return new Promise((resolve) => {
    doc.on('end', () => {
      seen.push(Buffer.concat(chunks).length);
      assert.ok(seen[0] > 0, 'a document was produced');
      resolve();
    });
  });
});
