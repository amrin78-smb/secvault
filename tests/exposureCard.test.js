'use strict';

// components/devices/OverviewExposureCard.js — the device Overview's
// exposure-risk widget.
//
// ⛔ THE DEFECT WAS NOT "THE LIST IS LONG". Each finding carried its own
// "Correlated with N open patch-now CVE(s) on this device: …" block, and
// `cves` is the SAME device-level set on every correlation — so the identical
// three lines rendered once per finding. Measured on the live fleet: IDC FW
// has 167 high/critical exposure findings against ONE patch-now CVE.
//
// ⛔ AND IT OVERCLAIMED AGAINST ITS OWN ENGINE. exposureCorrelation.js states
// that this is "a DEVICE-LEVEL correlation, not a claim that a specific rule
// and a specific CVE target the identical service/port". Printed under each
// rule, it read as precisely that per-rule claim.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { stripComments } = require('./stripComments');

const ROOT = path.join(__dirname, '..');
const CARD = stripComments(fs.readFileSync(path.join(ROOT, 'components/devices/OverviewExposureCard.js'), 'utf8'));
const ENGINE = fs.readFileSync(path.join(ROOT, 'lib/engines/exposureCorrelation.js'), 'utf8');
const PAGE = stripComments(fs.readFileSync(path.join(ROOT, 'app/(dashboard)/devices/[id]/page.js'), 'utf8'));
const CSS = stripComments(fs.readFileSync(path.join(ROOT, 'app/globals.css'), 'utf8'));

describe('⛔ the device-level correlation is stated ONCE', () => {
  it('the engine really does disclaim a per-rule link', () => {
    // If this ever stops being a device-level correlation, the layout below
    // is the thing that has to change with it.
    assert.match(ENGINE, /DEVICE-LEVEL correlation, not a claim that a specific rule/);
  });

  it('⛔ the per-finding "Correlated with …" block is GONE', () => {
    assert.equal(
      /Correlated with \{cves\.length\}/.test(CARD), false,
      'repeating the device-level CVE set under every rule reads as the '
      + 'per-rule claim the engine explicitly refuses to make'
    );
  });

  it('⛔ the CVE list is rendered OUTSIDE the per-finding loop', () => {
    const loop = CARD.slice(CARD.indexOf('shown.map('), CARD.indexOf('</ul>'));
    assert.equal(/cves\.map\(/.test(loop), false, 'the CVE set is back inside the loop');
    assert.equal(/CVEBadge/.test(loop), false);
    // ...and it IS rendered, once, above.
    const above = CARD.slice(0, CARD.indexOf('shown.map('));
    assert.match(above, /cves\.map\(\(cve\) =>/);
    assert.match(above, /<CVEBadge kevListed=\{cve\.kev_listed\} \/>/);
  });

  it('⛔ the summary sentence counts BOTH sides, so neither is implied', () => {
    assert.match(CARD, /\{correlations\.length\} rule/);
    assert.match(CARD, /\{cves\.length\} unpatched CVE/);
  });
});

describe('⛔ the list is capped and the remainder is counted', () => {
  it('a cap exists and is small enough for an overview widget', () => {
    const m = CARD.match(/const MAX_SHOWN = (\d+);/);
    assert.ok(m, 'the list is uncapped again — one live device has 167 findings');
    assert.ok(Number(m[1]) <= 8, `MAX_SHOWN is ${m[1]}, which is a findings table, not an overview`);
  });

  it('⛔ THE REMAINDER IS STATED, never silently dropped', () => {
    // A truncated list that looks complete is the more insidious failure:
    // the operator works to the bottom and believes they are finished.
    assert.match(CARD, /const more = correlations\.length - shown\.length;/);
    assert.match(CARD, /\{more > 0 && \(/);
    assert.match(CARD, /more exposure finding/);
  });

  it('the remainder links somewhere that holds the rest', () => {
    assert.match(CARD, /href=\{`\/devices\/\$\{deviceId\}\/analysis\?tab=findings`\}/);
  });
});

describe('⛔ nothing that was honest about the data was lost', () => {
  it('the three empty states are intact', () => {
    // A correlation is an intersection of two inputs, so an empty result has
    // three meanings and only one is good news.
    assert.match(CARD, /missingInputs/);
    assert.match(CARD, /Both inputs are present, so this is a real result/);
    assert.match(CARD, /That is not the same as "no exposure risk"/);
  });

  it('an unscored CVE is still NOT MEASURED, not a low score', () => {
    assert.match(CARD, /<NotMeasured\s+text="CVSS —"/);
    assert.match(CARD, /It is unscored, not low-severity/);
  });

  it('severity and finding type are still shown per row', () => {
    const loop = CARD.slice(CARD.indexOf('shown.map('), CARD.indexOf('</ul>'));
    assert.match(loop, /<SeverityBadge severity=\{finding\.severity\} \/>/);
    assert.match(loop, /<FindingTypeBadge type=\{finding\.finding_type\} \/>/);
    assert.match(loop, /\{finding\.detail\}/);
  });

  it('⛔ the rule detail WRAPS rather than truncating', () => {
    // It names the rule and the ports it opens; an ellipsis removes the only
    // identifying information on the row.
    const i = CSS.indexOf('.exp-detail {');
    const block = CSS.slice(i, CSS.indexOf('}', i));
    assert.match(block, /overflow-wrap: anywhere/);
    assert.equal(/text-overflow:\s*ellipsis|white-space:\s*nowrap/.test(block), false);
  });
});

describe('⛔ a short card is short', () => {
  it('the overview grid does not stretch its items', () => {
    const i = PAGE.indexOf('className="device-overview-grid"');
    const block = PAGE.slice(i, PAGE.indexOf('>', PAGE.indexOf('gap: 16', i)));
    assert.match(block, /alignItems: 'start'/,
      'a CSS grid stretches every item to the row height, padding the two '
      + 'four-figure cards beside Exposure Risk with hundreds of pixels of nothing');
  });
});
