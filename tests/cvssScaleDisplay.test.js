// tests/cvssScaleDisplay.test.js
//
// The CVSS SCALE is shown wherever a CVSS score is shown, and it is never
// guessed.
//
// ⛔ WHY THIS EXISTS. v2.90.3 recorded advisories.cvss_source/cvss_version
// because the same CVE was scored differently depending on which feed
// answered. The obvious follow-up — "pick one authoritative version and
// normalise" — is measurably impossible on this fleet: of 1,001 advisories
// exactly ONE carries both a v3 and a v4 metric, and of 159 live assessments
// 110 are banded on v4 with no v3 available at all. Normalising to v3 would
// leave those 110 unscored, which the priority tree reads as "not scored", and
// v3/v4 use different formulas over different metrics so no conversion exists.
//
// The mix is therefore STRUCTURAL, not a defect, and the only correct response
// is to make it visible. That makes this test the guard against the two ways a
// future session can quietly undo it:
//
//   1. inventing a conversion or a "normalised score" — the fabricated-value
//      bug this codebase exists to avoid, in its most plausible disguise; and
//   2. defaulting a NULL cvss_version to v3.1 so the column "looks complete".
//      cvss_version is NULL on EVERY advisory today (verified against the live
//      database) until each feed's next sync rewrites it, and stays NULL for
//      the 255 advisories that carry no vector at all. A default here would
//      label 110 v4 scores as v3 — worse than showing nothing.
//
// ⛔ NO DATABASE, NO JSX TRANSFORM. The scale helpers live inside component
// files (duplicated per file, the convention cvssStyle() already follows), so
// the pure ones are extracted from source and evaluated, and everything else is
// asserted against the source text. Same approach as tests/sqlColumns.test.js:
// conservative, and runnable on any checkout with no devDependencies.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');

// The four surfaces that render a CVSS number.
const LIST_FILES = [
  'components/cve/CVETable.js',
  'components/vulnerability/AdvisoriesTab.js',
];
const DETAIL_FILES = [
  'app/(dashboard)/vulnerability/advisories/[cveId]/page.js',
  'app/(dashboard)/vulnerability/cve/[cveId]/page.js',
];
const ALL_FILES = [...LIST_FILES, ...DETAIL_FILES];

const read = (rel) => fs.readFileSync(path.join(REPO, rel), 'utf8');

// Comments in these files argue AGAINST normalisation at length, so the source
// guards below have to look at code only.
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^[ \t]*\/\/[^\n]*$/gm, '');
}

// Pull one top-level `function name(...) { ... }` out of a component file by
// brace matching. Only used on helpers that contain no JSX.
function extractFunction(src, name) {
  const start = src.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name} must exist as a top-level function`);
  let i = src.indexOf('{', start);
  let depth = 0;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') {
      depth--;
      if (depth === 0) return src.slice(start, i + 1);
    }
  }
  throw new Error(`unbalanced braces extracting ${name}`);
}

// The source-label map is a module-level const the helper closes over.
function extractConstObject(src, name) {
  const start = src.indexOf(`const ${name} =`);
  if (start === -1) return '';
  let i = src.indexOf('{', start);
  let depth = 0;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') {
      depth--;
      if (depth === 0) return `${src.slice(start, i + 1)};`;
    }
  }
  throw new Error(`unbalanced braces extracting ${name}`);
}

function loadHelpers(rel, names) {
  const src = read(rel);
  const body = [
    extractConstObject(src, 'CVSS_SOURCE_LABELS'),
    ...names.map((n) => extractFunction(src, n)),
  ].join('\n');
  // eslint-disable-next-line no-new-func
  return new Function(`${body}\nreturn { ${names.join(', ')} };`)();
}

describe('cvssScaleLabel: the scale is reported, never assumed', () => {
  for (const rel of ALL_FILES) {
    const { cvssScaleLabel } = loadHelpers(rel, ['cvssScaleLabel']);
    const prefix = rel.includes('components/') ? 'v' : 'CVSS v';

    it(`${rel} labels a recorded version`, () => {
      assert.equal(cvssScaleLabel('4.0'), `${prefix}4.0`);
      assert.equal(cvssScaleLabel('3.1'), `${prefix}3.1`);
      assert.equal(cvssScaleLabel('2.0'), `${prefix}2.0`);
    });

    it(`${rel} ⛔ returns null when the scale was not recorded`, () => {
      // This is the case that regresses silently: NULL is the value on every
      // row in production today, and the caller's null-branch is what says
      // "not recorded" instead of printing a confident, wrong "v3.1".
      for (const v of [null, undefined, '', '   ']) {
        assert.equal(cvssScaleLabel(v), null, `input ${JSON.stringify(v)}`);
      }
    });

    it(`${rel} does not double the v prefix on a pre-prefixed value`, () => {
      assert.equal(cvssScaleLabel('v4.0'), `${prefix}4.0`);
      assert.equal(cvssScaleLabel('V3.1'), `${prefix}3.1`);
    });
  }
});

describe('cvssSourceLabel: which feed answered', () => {
  for (const rel of ALL_FILES) {
    const { cvssSourceLabel } = loadHelpers(rel, ['cvssSourceLabel']);
    it(`${rel} names the three real sources and nothing else`, () => {
      assert.match(cvssSourceLabel('nvd'), /NVD/);
      assert.match(cvssSourceLabel('circl'), /CIRCL/);
      assert.match(cvssSourceLabel('psirt'), /PSIRT/);
      // An unrecognised source is shown verbatim, not silently relabelled as
      // one of the known feeds.
      assert.equal(cvssSourceLabel('somethingelse'), 'somethingelse');
    });
    it(`${rel} ⛔ returns null when the source was not recorded`, () => {
      for (const v of [null, undefined, '']) {
        assert.equal(cvssSourceLabel(v), null, `input ${JSON.stringify(v)}`);
      }
    });
  }
});

describe('cvssScaleMix: the comparability caveat is conditional', () => {
  for (const rel of LIST_FILES) {
    const { cvssScaleMix } = loadHelpers(rel, ['cvssScaleLabel', 'cvssScaleMix']);

    it(`${rel} flags a genuine v3/v4 mix`, () => {
      const r = cvssScaleMix([
        { cvss_score: 9.8, cvss_version: '4.0' },
        { cvss_score: 7.5, cvss_version: '3.1' },
      ]);
      assert.equal(r.mixed, true);
    });

    it(`${rel} does not flag v3.0 alongside v3.1 — same formula family`, () => {
      const r = cvssScaleMix([
        { cvss_score: 9.8, cvss_version: '3.0' },
        { cvss_score: 7.5, cvss_version: '3.1' },
      ]);
      assert.equal(r.mixed, false);
      assert.equal(r.unrecorded, false, 'a recorded scale is not an unrecorded one');
    });

    it(`${rel} reports an unrecorded scale beside a real score`, () => {
      // Today's production state: every score present, every scale NULL.
      const r = cvssScaleMix([
        { cvss_score: 9.8, cvss_version: null },
        { cvss_score: 7.5, cvss_version: null },
      ]);
      assert.equal(r.unrecorded, true);
      assert.equal(r.mixed, false, 'one unknown scale is not two known ones');
    });

    it(`${rel} ⛔ an UNSCORED row contributes nothing either way`, () => {
      // No score means no scale to be missing. Counting it as "unrecorded"
      // would keep the caveat on screen forever for the 255 vectorless
      // advisories, which is how a real warning becomes furniture.
      const r = cvssScaleMix([
        { cvss_score: null, cvss_version: null },
        { cvss_score: undefined, cvss_version: null },
      ]);
      assert.equal(r.mixed, false);
      assert.equal(r.unrecorded, false);
    });

    it(`${rel} stays silent on a single consistent scale`, () => {
      const r = cvssScaleMix([
        { cvss_score: 9.8, cvss_version: '4.0' },
        { cvss_score: 5.3, cvss_version: '4.0' },
      ]);
      assert.equal(r.mixed, false);
      assert.equal(r.unrecorded, false);
    });
  }

  it('CVETable ⛔ ignores rows whose caller never SELECTed cvss_version', () => {
    // A caller that did not ask for the column is a gap in SecVault's own
    // query, not a fact about the advisory — claiming "scale not recorded"
    // there would be the failed-read-as-a-fact bug, one level up.
    const { cvssScaleMix } = loadHelpers('components/cve/CVETable.js', [
      'cvssScaleLabel',
      'cvssScaleMix',
    ]);
    const r = cvssScaleMix([{ cvss_score: 9.8 }, { cvss_score: 7.5 }]);
    assert.equal(r.mixed, false);
    assert.equal(r.unrecorded, false);
  });
});

describe('⛔ no normalisation, no assumed default, anywhere near a score', () => {
  for (const rel of ALL_FILES) {
    const code = stripComments(read(rel));

    it(`${rel} contains no v3<->v4 conversion or "normalised" score`, () => {
      assert.doesNotMatch(
        code,
        /normali[sz]/i,
        'there is no valid v3<->v4 conversion; a normalised score would be a fabricated value'
      );
    });

    it(`${rel} never defaults a missing scale to a version literal`, () => {
      // e.g. `cvss_version || '3.1'` or `cvss_version ?? "3.1"`.
      assert.doesNotMatch(
        code,
        /cvss_version\s*(\|\||\?\?)\s*['"`]/,
        'a NULL scale must render as "not recorded", never as an assumed version'
      );
      assert.doesNotMatch(
        code,
        /(version|scale)\s*=\s*['"`]v?[234]\.\d['"`]/i,
        'no hardcoded fallback CVSS version'
      );
    });

    it(`${rel} does not do arithmetic on cvss_score`, () => {
      // Presentation only. The priority tree bands on cvss_score alone
      // (CLAUDE.md rules 3 and 4); recording where a score came from must
      // never become a second way to move a band.
      assert.doesNotMatch(
        code,
        /cvss_score\s*[*/+-]\s*[\d(]/,
        'the displayed score must be the stored score'
      );
    });

    it(`${rel} renders absence through NotMeasured`, () => {
      assert.match(code, /NotMeasured/, 'absence has one visual vocabulary in this app');
    });
  }
});

describe('the queries actually ask for the scale', () => {
  it('AdvisoriesTab selects cvss_version and cvss_source', () => {
    const code = stripComments(read('components/vulnerability/AdvisoriesTab.js'));
    assert.match(code, /cvss_version/, 'a scale that is never SELECTed can never be shown');
    assert.match(code, /cvss_source/);
  });

  it('⛔ CVETable distinguishes "not selected" from "recorded as NULL"', () => {
    // Two of CVETable's three callers live outside this component and may not
    // have widened their queries yet. Those two states must not collapse.
    const code = stripComments(read('components/cve/CVETable.js'));
    assert.match(
      code,
      /hasOwnProperty\.call\(\s*(row|r)\s*,\s*'cvss_version'\s*\)/,
      'the presence check is what keeps a caller gap from reading as an advisory fact'
    );
  });
});

describe('CVETable colgroup still matches its header', () => {
  // tableLayout:'fixed' is enforced by ui/Table, so a <col> count that drifts
  // from the <th> count collapses columns rather than failing loudly.
  // Comments stripped first — the colgroup's own comment mentions the tag.
  const src = stripComments(read('components/cve/CVETable.js'));
  const colgroup = src.slice(src.indexOf('<colgroup>'), src.indexOf('</colgroup>'));
  const thead = src.slice(src.indexOf('<thead>'), src.indexOf('</thead>'));

  it('has one <col> per <th>, in both device and fleet modes', () => {
    const cols = (colgroup.match(/<col\b/g) || []).length;
    const ths = (thead.match(/<th>/g) || []).length;
    assert.equal(cols, ths, 'every column needs a width or the fixed layout collapses');
    // One of each is conditional on showDeviceColumn — they must stay paired.
    assert.equal((colgroup.match(/showDeviceColumn &&/g) || []).length, 1);
    assert.equal((thead.match(/showDeviceColumn &&/g) || []).length, 1);
  });

  it('gives the CVSS column room for the scale suffix', () => {
    // "9.8 v4.0" no longer fits the original 8%; a silent shrink back would
    // ellipsise the scale away and leave a bare number that looks comparable.
    const widths = [...colgroup.matchAll(/width:\s*'(\d+)%'/g)].map((m) => Number(m[1]));
    assert.ok(widths.includes(11), 'the CVSS column must keep its widened share');
  });
});
