'use strict';

// tests/changeOutcomeBoard.test.js
//
// Pins components/analysis/ChangeOutcomeBoard.js — the VIEW, not the engine.
// lib/engines/changeOutcome.js is pinned by tests/changeOutcome.test.js and its
// plumbing by tests/changeOutcomeData.test.js; what is tested here is what only
// the rendering can get wrong.
//
// ⛔ THE FAILURES THIS FILE EXISTS TO PREVENT:
//
//   1. IMPLYING CAUSATION. A firewall change and a traffic movement on the same
//      day are two facts in sequence. Every string this view emits is scanned
//      for the causal vocabulary, at rest AND at runtime, with comments stripped
//      first — and the stripper is PROVEN before it is trusted.
//   2. HIDING `window_incomplete`. It is the majority state (137 of 203 live)
//      and it is a limit of OURS. It must be visible, counted, explained, and it
//      must read differently from `no_traffic_window`.
//   3. A VERDICT WITH NO VISIBLE BASIS. The engine was rewritten twice to stop
//      exactly that, so the comparison a movement was judged against is asserted
//      to travel with it.
//   4. GIVING IT A SCORE'S SHAPE, or letting a zero read as an all-clear. Live,
//      NOTHING exceeded — and "none of the 66 judged" and "none judged at all"
//      are different sentences with different shapes.
//   5. RENDERING A COUNT OR A VERDICT OVER A BOARD THAT LOST A READ. A short
//      board reads as a firewall nothing has happened to.
//
// Loading technique is the one tests/coverageRegisterView.test.js already uses:
// `npm test` is `node --test` with no "type":"module", so an ESM component
// cannot be require()d. Everything pinned below is a plain const or a plain
// function with no imported identifier in its body, so stripping the `export`
// keyword and evaluating is exact, not an approximation.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');
const VIEW_PATH = path.join(REPO, 'components', 'analysis', 'ChangeOutcomeBoard.js');
const PAGE_PATH = path.join(REPO, 'app', '(dashboard)', 'devices', '[id]', 'changes', 'page.js');
const SRC = fs.readFileSync(VIEW_PATH, 'utf8');

const { VERDICTS, OUTCOME_CLAIM } = require('../lib/engines/changeOutcome');

// ⛔ COMMENTS STRIPPED BEFORE EVERY SOURCE SCAN. This repo has been bitten more
// than once by a scan satisfied by the comment explaining the thing it was
// hunting — and this file's subject documents, in prose, both the causal
// vocabulary it forbids and the severity hues it refuses. A scan that read those
// would fail on the documentation that exists to prevent the defect.
const BLOCK_COMMENT = new RegExp('/\\*[\\s\\S]*?\\*/', 'g');
const LINE_COMMENT = new RegExp('(^|[\\s{(;,])//[^\\n]*', 'g');
const stripComments = (src) =>
  String(src).replace(BLOCK_COMMENT, ' ').replace(LINE_COMMENT, '$1 ');

const CODE = stripComments(SRC);

// ⛔ CO-OCCURRENCE, NEVER CAUSATION.
const CAUSAL = [
  /\bcaused\b/i,
  /\bbecause\b/i,
  /\bdue to\b/i,
  /\bresulted in\b/i,
  /impact/i,
  /\bled to\b/i,
  /\bbroke\b/i,
];

// ⛔ NO SCORE, NO GRADE, NO SHARE OF CHANGES MARKED AS FINE, NO RISK NUMBER.
const SCORING = [/score/i, /grade/i, /\brisk/i, /\bsafe/i, /percent/i];

// ⛔ An all-clear is forbidden on this board in every shape.
const ALL_CLEAR = [
  /\bhealthy\b/i,
  /\ball[- ]clear\b/i,
  /\bno effect\b/i,
  /\bunaffected\b/i,
  /\bharmless\b/i,
  /\bnothing went wrong\b/i,
];

// ⛔ The severity ramp and the evidence hue, neither of which this view may
// touch: `exceeded` is not a fault, and violet belongs to EvidenceMark alone.
const FORBIDDEN_TOKENS = [
  /--sev-/,
  /--red\b/,
  /--orange\b/,
  /--yellow\b/,
  /--green\b/,
  /--blue\b/,
  /--purple\b/,
  /--evidence\b/,
  /--tint-danger/,
  /--tint-success/,
  /--tint-orange/,
];

function loadView() {
  const declarations = SRC
    .split('\n')
    .filter((line) => !/^\s*import\s/.test(line))
    .join('\n')
    .replace(/\bexport\s+(const|function)\b/g, '$1');

  // Cut the file at the first JSX-bearing piece: everything pinned here is
  // declared above it, and `new Function` cannot parse JSX.
  const cut = declarations.indexOf('function Swatch(');
  assert.notEqual(cut, -1, 'expected Swatch to mark the start of the JSX half');
  const pure = declarations.slice(0, cut);

  const names = [
    'VERDICT',
    'BOARD_PURPOSE',
    'CLAIM_MISSING_NOTE',
    'FAILURE_NOTE',
    'INCOMPLETE_COUNT_REASON',
    'INCOMPLETE_VERDICT_REASON',
    'WINDOW_INCOMPLETE_NOTE',
    'NO_TRAFFIC_NOTE',
    'INSUFFICIENT_BASELINE_NOTE',
    'BASELINE_DEGENERATE_NOTE',
    'UNKNOWN_VERDICT_NOTE',
    'MISSING_BASIS_NOTE',
    'NOTHING_JUDGED_NOTE',
    'HEADLINE_UNREADABLE_NOTE',
    'NONE_EXCEEDED_PREFIX',
    'NONE_EXCEEDED_SUFFIX',
    'SOME_EXCEEDED_SUFFIX',
    'OBSERVED_NONE_NOTE',
    'BASELINE_UNKNOWN_NOTE',
    'NO_CHANGES_NOTE',
    'EMPTY_BOARD_NOTE',
    'LIMITS_HEADING',
    'LIMITS_NOTE',
    'VERDICT_WEIGHT',
    'VERDICT_ORDER',
    'UNJUDGEABLE',
    'verdictWeight',
    'verdictNote',
    'numOrNull',
    'verdictCount',
    'judgedCount',
    'headline',
    'failureList',
    'boardIsIncomplete',
    'reportableCount',
    'claimText',
    'asOf',
    'stamp',
    'windowSentence',
    'deltaLabel',
    'basisSentence',
    'baselineSentence',
    'observedSentence',
    'changeList',
  ];
  // eslint-disable-next-line no-new-func
  return new Function(`${pure}\nreturn { ${names.join(', ')} };`)();
}

const V = loadView();

// ── fixtures, shaped exactly as the engine emits them ───────────────────────

const usableBaseline = {
  observations: 19,
  medianAbsPct: 12.4,
  mad: 8.1,
  bandPct: 68.4,
  deltas: [1, 2, 3],
  quantile: 0.95,
  resolutionPct: 5,
  usable: true,
  reason: null,
  needed: 10,
};

const thinBaseline = {
  observations: 3,
  medianAbsPct: null,
  mad: null,
  bandPct: null,
  deltas: [],
  quantile: 0.95,
  resolutionPct: null,
  usable: false,
  reason: VERDICTS.INSUFFICIENT_BASELINE,
  needed: 10,
};

const flatBaseline = { ...thinBaseline, observations: 19, reason: VERDICTS.BASELINE_DEGENERATE };

const judgedChange = (over = {}) => ({
  changeId: 'chg-1',
  detectedAt: '2026-09-10T12:00:00.000Z',
  summary: '3 rules modified',
  windowComplete: true,
  verdict: VERDICTS.INDISTINGUISHABLE,
  deltaPct: 4.2,
  largerThanDays: 12,
  ordinaryDays: 19,
  baseline: usableBaseline,
  ...over,
});

const unjudgedChange = (verdict) => ({
  changeId: `chg-${verdict}`,
  detectedAt: '2026-09-01T06:00:00.000Z',
  summary: '1 rule added',
  windowComplete: false,
  verdict,
  deltaPct: null,
  largerThanDays: null,
  ordinaryDays: null,
  baseline: usableBaseline,
});

const summaryOf = (by) => ({
  devices: 16,
  devicesWithUsableBaseline: 15,
  devicesWithoutBaseline: 1,
  changes: Object.values(by).reduce((n, v) => n + v, 0),
  byVerdict: {
    [VERDICTS.INDISTINGUISHABLE]: 0,
    [VERDICTS.EXCEEDED]: 0,
    [VERDICTS.WINDOW_INCOMPLETE]: 0,
    [VERDICTS.NO_TRAFFIC_WINDOW]: 0,
    [VERDICTS.INSUFFICIENT_BASELINE]: 0,
    [VERDICTS.BASELINE_DEGENERATE]: 0,
    ...by,
  },
  exceeded: [],
  claim: OUTCOME_CLAIM,
});

// The live shape, 2026-09-27: 203 changes, 137 incomplete, 66 judged, 0 exceeded.
const LIVE = summaryOf({
  [VERDICTS.INDISTINGUISHABLE]: 66,
  [VERDICTS.WINDOW_INCOMPLETE]: 137,
});

/** Every string this view can put on screen, for the vocabulary scans. */
function everyRuntimeString() {
  const out = [];
  for (const [key, value] of Object.entries(V)) {
    if (typeof value === 'string') out.push(`${key}: ${value}`);
  }
  for (const w of Object.values(V.VERDICT_WEIGHT)) out.push(w.label);
  for (const verdict of [...Object.values(VERDICTS), 'something_else', undefined]) {
    out.push(V.verdictWeight(verdict).label);
    const note = V.verdictNote(verdict);
    if (note) out.push(note);
  }
  for (const by of [
    {},
    { [VERDICTS.INDISTINGUISHABLE]: 66 },
    { [VERDICTS.INDISTINGUISHABLE]: 1 },
    { [VERDICTS.INDISTINGUISHABLE]: 64, [VERDICTS.EXCEEDED]: 2 },
    { [VERDICTS.EXCEEDED]: 1 },
  ]) {
    out.push(V.headline(summaryOf(by)).text);
  }
  out.push(V.headline({}).text);
  out.push(V.headline(null).text);
  for (const b of [usableBaseline, thinBaseline, flatBaseline, null, {}]) {
    out.push(V.baselineSentence({ baseline: b }));
  }
  for (const c of [
    judgedChange(),
    judgedChange({ verdict: VERDICTS.EXCEEDED, deltaPct: 214.9, largerThanDays: 19 }),
    unjudgedChange(VERDICTS.WINDOW_INCOMPLETE),
    null,
  ]) {
    out.push(V.basisSentence(c));
    out.push(V.deltaLabel(c));
  }
  out.push(V.observedSentence({ observedFrom: '2026-09-01T00:00:00.000Z', observedTo: '2026-09-22T00:00:00.000Z' }));
  out.push(V.observedSentence({}));
  out.push(V.windowSentence(24));
  out.push(V.windowSentence(null));
  out.push(V.asOf('2026-09-27T09:00:00.000Z'));
  out.push(V.asOf(null));
  out.push(V.asOf('not a date'));
  out.push(...V.failureList([{ source: 'traffic_series', error: 'relation does not exist' }]));
  return out.filter((s) => typeof s === 'string' && s !== '');
}

// ──────────────────────────────────────────────────────────────────────────

describe('ChangeOutcomeBoard — co-occurrence, never causation', () => {
  it('⛔ the comment stripper is proven before any scan trusts it', () => {
    assert.match(SRC, /because/, 'expected the prose to carry a word the scans ban');
    assert.doesNotMatch(CODE, /because/, 'the stripper must remove that prose');
    // And the same proof for a hue the weights may not carry but the prose names.
    assert.match(SRC, /Red would read as/);
    assert.doesNotMatch(CODE, /Red would read as/);
  });

  it('⛔ no causal vocabulary in the source', () => {
    for (const re of CAUSAL) assert.doesNotMatch(CODE, re, `causal vocabulary: ${re}`);
  });

  it('⛔ no causal vocabulary in any string it emits at runtime', () => {
    for (const s of everyRuntimeString()) {
      for (const re of CAUSAL) assert.doesNotMatch(s, re, `causal vocabulary in: ${s}`);
    }
  });

  it('⛔ renders the engine claim VERBATIM and holds no copy of it', () => {
    assert.equal(V.claimText({ claim: OUTCOME_CLAIM }), OUTCOME_CLAIM);
    // A second wording would be a second claim, so no distinctive phrase of the
    // engine's sentence may appear in this file's own code.
    assert.doesNotMatch(CODE, /two facts in sequence/);
    assert.doesNotMatch(CODE, /how much that firewall normally varies day to/);
  });

  it('⛔ an absent claim is admitted, never substituted', () => {
    assert.equal(V.claimText({}), null);
    assert.equal(V.claimText(null), null);
    assert.equal(V.claimText({ claim: '   ' }), null);
    assert.match(V.CLAIM_MISSING_NOTE, /not restated/i);
  });
});

describe('ChangeOutcomeBoard — no score, no grade, no all-clear', () => {
  it('⛔ no scoring vocabulary anywhere in the source', () => {
    for (const re of SCORING) assert.doesNotMatch(CODE, re, `scoring vocabulary: ${re}`);
  });

  it('⛔ no scoring or all-clear vocabulary in any runtime string', () => {
    for (const s of everyRuntimeString()) {
      for (const re of SCORING) assert.doesNotMatch(s, re, `scoring vocabulary in: ${s}`);
      for (const re of ALL_CLEAR) assert.doesNotMatch(s, re, `all-clear vocabulary in: ${s}`);
    }
  });

  it('⛔ does no arithmetic of its own — every figure is the engine’s', () => {
    assert.doesNotMatch(CODE, /Math\.round/);
    assert.doesNotMatch(CODE, /toFixed/);
    assert.doesNotMatch(CODE, /Math\.(?:min|max|abs|floor|ceil)/);
  });
});

describe('ChangeOutcomeBoard — the verdict vocabulary cannot drift from the engine', () => {
  it('its literal verdict strings are exactly the engine’s', () => {
    assert.deepEqual(
      Object.values(V.VERDICT).slice().sort(),
      Object.values(VERDICTS).slice().sort(),
    );
  });

  it('every engine verdict has a weight, plus an unknown fallback', () => {
    for (const verdict of Object.values(VERDICTS)) {
      assert.ok(V.VERDICT_WEIGHT[verdict], `no weight for ${verdict}`);
    }
    assert.ok(V.VERDICT_WEIGHT.unknown);
    assert.equal(Object.keys(V.VERDICT_WEIGHT).length, Object.values(VERDICTS).length + 1);
  });

  it('⛔ an unrecognised verdict falls to the hueless unknown weight, never to the quiet measured one', () => {
    for (const bad of ['something_else', undefined, null, '', 0, {}]) {
      assert.equal(V.verdictWeight(bad).kind, 'unknown');
    }
    assert.notEqual(V.verdictWeight('nope').kind, VERDICTS.INDISTINGUISHABLE);
    assert.equal(V.verdictNote('nope'), V.UNKNOWN_VERDICT_NOTE);
  });
});

describe('ChangeOutcomeBoard — visual weight', () => {
  it('⛔ carries no severity hue and no evidence violet, at rest or in the weights', () => {
    for (const re of FORBIDDEN_TOKENS) assert.doesNotMatch(CODE, re, `forbidden token: ${re}`);
    const flat = JSON.stringify(V.VERDICT_WEIGHT);
    for (const re of FORBIDDEN_TOKENS) assert.doesNotMatch(flat, re, `forbidden token in weights: ${re}`);
  });

  it('⛔ no hardcoded hex anywhere — tokens only', () => {
    assert.doesNotMatch(CODE, /#[0-9a-fA-F]{3,8}\b/);
  });

  it('⛔ no Tailwind, and no hardcoded row geometry', () => {
    assert.doesNotMatch(CODE, /tailwind/i);
    assert.doesNotMatch(CODE, /className="[^"]*\b(?:flex|grid|p-\d|px-\d|mt-\d|text-(?:sm|lg|xl))\b/);
    // Row geometry resolves through --row-pad-y / --row-pad-x / --row-font; a
    // cell that hardcodes its padding opts itself out of the density switch.
    assert.doesNotMatch(CODE, /padding:\s*['"][^'"]*\d+px/);
  });

  it('⛔ exactly one state is tinted, and it is the one movement that stands out', () => {
    const tinted = Object.values(V.VERDICT_WEIGHT).filter((w) => w.swatch === 'tint');
    assert.equal(tinted.length, 1);
    assert.equal(tinted[0].kind, VERDICTS.EXCEEDED);
    assert.match(tinted[0].color, /--tint-info-fg/);
  });

  it('⛔ every other state is hueless and hatched or outlined', () => {
    for (const [kind, w] of Object.entries(V.VERDICT_WEIGHT)) {
      if (kind === VERDICTS.EXCEEDED) continue;
      assert.ok(['hatch', 'outline'].includes(w.swatch), `${kind} swatch ${w.swatch}`);
      assert.match(w.color, /--unmeasured|--text-muted/, `${kind} colour ${w.color}`);
    }
  });

  it('⛔ the unjudgeable states rank ABOVE the quiet measured one', () => {
    const quiet = V.VERDICT_WEIGHT[VERDICTS.INDISTINGUISHABLE].rank;
    for (const verdict of V.UNJUDGEABLE) {
      assert.ok(
        V.VERDICT_WEIGHT[verdict].rank < quiet,
        `${verdict} must be louder than ${VERDICTS.INDISTINGUISHABLE}`,
      );
    }
    assert.equal(V.VERDICT_WEIGHT[VERDICTS.EXCEEDED].rank, 0);
  });

  it('VERDICT_ORDER is derived from the ranks and excludes the fallback', () => {
    assert.deepEqual(
      V.VERDICT_ORDER.slice().sort(),
      Object.values(VERDICTS).slice().sort(),
    );
    assert.ok(!V.VERDICT_ORDER.includes('unknown'));
    const ranks = V.VERDICT_ORDER.map((k) => V.VERDICT_WEIGHT[k].rank);
    assert.deepEqual(ranks, ranks.slice().sort((a, b) => a - b));
  });
});

describe('ChangeOutcomeBoard — window_incomplete is its own visible state', () => {
  it('⛔ it is one of the four counted, named, unjudgeable states', () => {
    assert.ok(V.UNJUDGEABLE.includes(VERDICTS.WINDOW_INCOMPLETE));
    assert.equal(V.UNJUDGEABLE.length, 4);
    assert.ok(V.UNJUDGEABLE.includes(VERDICTS.NO_TRAFFIC_WINDOW));
    assert.ok(V.UNJUDGEABLE.includes(VERDICTS.INSUFFICIENT_BASELINE));
    assert.ok(V.UNJUDGEABLE.includes(VERDICTS.BASELINE_DEGENERATE));
  });

  it('⛔ it reads DIFFERENTLY from no_traffic_window — label and explanation', () => {
    const a = V.VERDICT_WEIGHT[VERDICTS.WINDOW_INCOMPLETE];
    const b = V.VERDICT_WEIGHT[VERDICTS.NO_TRAFFIC_WINDOW];
    assert.notEqual(a.label, b.label);
    assert.notEqual(V.verdictNote(VERDICTS.WINDOW_INCOMPLETE), V.verdictNote(VERDICTS.NO_TRAFFIC_WINDOW));
    assert.equal(V.verdictNote(VERDICTS.WINDOW_INCOMPLETE), V.WINDOW_INCOMPLETE_NOTE);
    assert.equal(V.verdictNote(VERDICTS.NO_TRAFFIC_WINDOW), V.NO_TRAFFIC_NOTE);
  });

  it('⛔ its explanation says the limit is SecVault’s, not the firewall’s', () => {
    assert.match(V.WINDOW_INCOMPLETE_NOTE, /limit of what SecVault holds/i);
    assert.match(V.WINDOW_INCOMPLETE_NOTE, /not an observation about the firewall/i);
  });

  it('⛔ every unjudgeable state carries a sentence; the two judged ones carry none', () => {
    for (const verdict of V.UNJUDGEABLE) {
      assert.equal(typeof V.verdictNote(verdict), 'string');
      assert.ok(V.verdictNote(verdict).length > 40);
    }
    assert.equal(V.verdictNote(VERDICTS.EXCEEDED), null);
    assert.equal(V.verdictNote(VERDICTS.INDISTINGUISHABLE), null);
  });

  it('⛔ the panel that holds them is a named section, not a footnote', () => {
    assert.match(V.LIMITS_HEADING, /could not be judged/i);
    assert.match(V.LIMITS_NOTE, /counted and named/i);
    assert.match(CODE, /LIMITS_HEADING/);
    // Rendered above the per-firewall sections, not after them.
    assert.ok(
      CODE.indexOf('<LimitsPanel') < CODE.indexOf('<DeviceSection'),
      'the limits panel must precede the per-firewall lists',
    );
  });
});

describe('ChangeOutcomeBoard — insufficient_baseline and baseline_degenerate stay apart', () => {
  it('⛔ two distinct labels, two distinct explanations', () => {
    assert.notEqual(
      V.VERDICT_WEIGHT[VERDICTS.INSUFFICIENT_BASELINE].label,
      V.VERDICT_WEIGHT[VERDICTS.BASELINE_DEGENERATE].label,
    );
    assert.notEqual(V.INSUFFICIENT_BASELINE_NOTE, V.BASELINE_DEGENERATE_NOTE);
  });

  it('⛔ PAKFood’s live case: no band, and NOT "its changes were quiet"', () => {
    const said = V.baselineSentence({ baseline: thinBaseline });
    assert.match(said, /too few day-to-day observations/i);
    assert.match(said, /3 of the 10/, 'names what it has and what it needs');
    assert.match(said, /not a statement that its changes were uneventful/i);
  });

  it('a firewall whose traffic never varies says so in its own words', () => {
    const said = V.baselineSentence({ baseline: flatBaseline });
    assert.equal(said, V.BASELINE_DEGENERATE_NOTE);
    assert.match(said, /no spread/i);
  });

  it('⛔ a missing baseline is admitted, never treated as a usable one', () => {
    assert.equal(V.baselineSentence({}), V.BASELINE_UNKNOWN_NOTE);
    assert.equal(V.baselineSentence(null), V.BASELINE_UNKNOWN_NOTE);
    assert.equal(V.baselineSentence({ baseline: { usable: false } }), V.BASELINE_UNKNOWN_NOTE);
  });

  it('a usable band states the band, the observations behind it and its resolution floor', () => {
    const said = V.baselineSentence({ baseline: usableBaseline });
    assert.match(said, /68\.4%/);
    assert.match(said, /19 of its own day-to-day swings/);
    assert.match(said, /5%/);
  });
});

describe('ChangeOutcomeBoard — every verdict states what it was compared with', () => {
  it('⛔ a judged change names how many ordinary swings it is larger than, and the band', () => {
    const inside = V.basisSentence(judgedChange());
    assert.match(inside, /Larger than 12 of 19 ordinary daily swings/);
    assert.match(inside, /inside/);
    assert.match(inside, /68\.4%/);

    const outside = V.basisSentence(judgedChange({
      verdict: VERDICTS.EXCEEDED, deltaPct: 214.9, largerThanDays: 19,
    }));
    assert.match(outside, /Larger than 19 of 19 ordinary daily swings/);
    assert.match(outside, /outside/);
  });

  it('⛔ a change with no comparison gets the admission, not a bare verdict', () => {
    assert.equal(V.basisSentence(unjudgedChange(VERDICTS.WINDOW_INCOMPLETE)), null);
    assert.equal(V.basisSentence(null), null);
    assert.match(V.MISSING_BASIS_NOTE, /not compared against anything/i);
    assert.match(CODE, /MISSING_BASIS_NOTE/);
  });

  it('the movement is signed and is the engine’s own figure', () => {
    assert.equal(V.deltaLabel(judgedChange()), '+4.2%');
    assert.equal(V.deltaLabel(judgedChange({ deltaPct: -92.1 })), '-92.1%');
    assert.equal(V.deltaLabel(judgedChange({ deltaPct: 0 })), '0%');
  });

  it('⛔ an absent movement is null, never zero', () => {
    assert.equal(V.deltaLabel(unjudgedChange(VERDICTS.WINDOW_INCOMPLETE)), null);
    assert.equal(V.deltaLabel({}), null);
    assert.equal(V.deltaLabel(null), null);
    assert.equal(V.numOrNull(null), null);
    assert.equal(V.numOrNull(''), null);
    assert.equal(V.numOrNull(false), null);
    assert.equal(V.numOrNull('7'), null);
    assert.equal(V.numOrNull(0), 0);
  });

  it('the collected period and the window are both stated', () => {
    const said = V.observedSentence({
      observedFrom: '2026-09-01T00:00:00.000Z',
      observedTo: '2026-09-22T00:00:00.000Z',
    });
    assert.match(said, /2026-09-01/);
    assert.match(said, /2026-09-22/);
    assert.equal(V.observedSentence({}), V.OBSERVED_NONE_NOTE);
    assert.match(V.windowSentence(24), /24 hours either side/);
    assert.match(V.windowSentence(undefined), /did not travel/);
  });
});

describe('ChangeOutcomeBoard — the zero is a result, not an empty state', () => {
  it('⛔ the live shape: 66 judged, none exceeded, and the count is NAMED', () => {
    const answer = V.headline(LIVE);
    assert.equal(answer.kind, 'none_exceeded');
    assert.equal(answer.judged, 66);
    assert.equal(answer.exceeded, 0);
    assert.match(answer.text, /66 changes/);
    assert.match(answer.text, /inside/);
    assert.match(answer.text, /not an absence of data/i);
    // ⛔ And it does not extend itself over the changes nothing could be said
    // about — the 137 incomplete windows are not cleared by this sentence.
    assert.match(answer.text, /says nothing about the changes that could not be judged/i);
  });

  it('⛔ "none exceeded" and "none judged" are DIFFERENT sentences', () => {
    const none = V.headline(summaryOf({ [VERDICTS.WINDOW_INCOMPLETE]: 137 }));
    assert.equal(none.kind, 'nothing_judged');
    assert.equal(none.judged, 0);
    assert.notEqual(none.text, V.headline(LIVE).text);
    assert.match(none.text, /could be judged/i);
    assert.match(none.text, /Nothing below says these changes were uneventful/i);
  });

  it('⛔ unreadable counts produce neither sentence', () => {
    for (const bad of [{}, null, { byVerdict: null }, { byVerdict: { indistinguishable: 'x' } }]) {
      const answer = V.headline(bad);
      assert.equal(answer.kind, 'unreadable');
      assert.equal(answer.text, V.HEADLINE_UNREADABLE_NOTE);
    }
  });

  it('a real exceedance is reported as N of M, singular and plural', () => {
    const one = V.headline(summaryOf({ [VERDICTS.INDISTINGUISHABLE]: 65, [VERDICTS.EXCEEDED]: 1 }));
    assert.equal(one.kind, 'some_exceeded');
    assert.match(one.text, /1 of the 66 changes/);
    assert.match(one.text, /was followed by/);
    assert.match(one.text, /outside/);

    const many = V.headline(summaryOf({ [VERDICTS.INDISTINGUISHABLE]: 64, [VERDICTS.EXCEEDED]: 2 }));
    assert.match(many.text, /2 of the 66 changes/);
    assert.match(many.text, /were followed by/);
  });

  it('judgedCount is null when either half is unreadable', () => {
    assert.equal(V.judgedCount(LIVE), 66);
    assert.equal(V.judgedCount({ byVerdict: { [VERDICTS.EXCEEDED]: 0 } }), null);
    assert.equal(V.judgedCount({}), null);
    assert.equal(V.verdictCount(LIVE, VERDICTS.WINDOW_INCOMPLETE), 137);
    assert.equal(V.verdictCount(LIVE, 'nope'), null);
  });
});

describe('ChangeOutcomeBoard — a failed read is not an empty board', () => {
  it('any failure at all makes the board incomplete', () => {
    assert.equal(V.boardIsIncomplete([]), false);
    assert.equal(V.boardIsIncomplete(null), false);
    assert.equal(V.boardIsIncomplete([{ source: 'traffic_series', error: 'x' }]), true);
    // ⛔ TOLERANT: a shape this view does not recognise is itself evidence the
    // board is incomplete, and swallowing it would render the short list
    // silently.
    assert.equal(V.boardIsIncomplete('it went wrong'), true);
    assert.equal(V.boardIsIncomplete({ traffic_series: 'x' }), true);
  });

  it('names the source and the reason', () => {
    const lines = V.failureList([{ source: 'traffic_series', error: 'relation does not exist' }]);
    assert.equal(lines.length, 1);
    assert.match(lines[0], /traffic_series/);
    assert.match(lines[0], /relation does not exist/);
  });

  it('⛔ withholds every count while the board is incomplete', () => {
    assert.equal(V.reportableCount(137, true), null);
    assert.equal(V.reportableCount(137, false), 137);
    assert.equal(V.reportableCount(0, false), 0, 'a measured zero is still printed');
    assert.match(V.INCOMPLETE_COUNT_REASON, /withheld/i);
  });

  it('⛔ withholds every VERDICT too, and says why', () => {
    assert.match(V.INCOMPLETE_VERDICT_REASON, /No verdict is shown/i);
    assert.match(V.INCOMPLETE_VERDICT_REASON, /reads\s+exactly like a firewall nothing has happened to/i);
    // The render path branches on it rather than only tinting the numbers.
    assert.match(CODE, /incomplete \?/);
    assert.match(CODE, /INCOMPLETE_VERDICT_REASON/);
  });

  it('⛔ an empty board is an absence of comparison, not a quiet fleet', () => {
    assert.match(V.EMPTY_BOARD_NOTE, /absence of comparison/i);
    assert.match(V.NO_CHANGES_NOTE, /nothing to line up/i);
    assert.notEqual(V.EMPTY_BOARD_NOTE, V.NO_CHANGES_NOTE);
    assert.notEqual(V.EMPTY_BOARD_NOTE, V.NOTHING_JUDGED_NOTE);
  });

  it('⛔ the failures banner uses the warn pair, never the danger pair', () => {
    // `exceeded` is not a fault, so a danger hue anywhere on this board would be
    // carried down into the rows by the reader.
    assert.match(CODE, /--tint-warn-fg/);
    assert.doesNotMatch(CODE, /--tint-danger/);
  });

  it('⛔ a board with no timestamp says so rather than dropping it', () => {
    assert.match(V.asOf('2026-09-27T09:00:00.000Z'), /as of 2026-09-27 09:00 UTC/);
    assert.match(V.asOf(null), /not recorded/);
    assert.match(V.asOf('not a date'), /could not be read/);
    assert.equal(V.stamp(null), '—');
    assert.equal(V.stamp('nope'), '—');
  });
});

describe('ChangeOutcomeBoard — it is a props-only server component', () => {
  it('fetches nothing and holds no client hooks', () => {
    assert.doesNotMatch(CODE, /'use client'/);
    assert.doesNotMatch(CODE, /useState|useEffect|useMemo/);
    assert.doesNotMatch(CODE, /\bfetch\(/);
    assert.doesNotMatch(CODE, /require\(/);
    assert.doesNotMatch(CODE, /pool/);
  });

  it('⛔ defines no React component inside another', () => {
    // Every component is declared at module top level: a nested definition
    // remounts on every keystroke and loses input focus.
    // INDENTED only: `[ \t]` rather than `\s`, since `\s` matches the newline
    // before a perfectly ordinary top-level declaration.
    const nested = CODE.match(/\n[ \t]+function\s+[A-Z]\w*\s*\(/g) || [];
    assert.deepEqual(nested, []);
  });

  it('takes its icons from the shared set only', () => {
    assert.match(SRC, /from '\.\.\/icons'/);
    assert.doesNotMatch(SRC, /react-icons|lucide|feather-icons|@heroicons/);
  });
});

describe('ChangeOutcomeBoard — it is actually on a page', () => {
  const PAGE = fs.readFileSync(PAGE_PATH, 'utf8');

  it('the per-firewall Changes page renders it', () => {
    assert.match(PAGE, /ChangeOutcomeBoard/);
    assert.match(PAGE, /<ChangeOutcomeBoard/);
  });

  it('it is fed by the data layer, not by a query in the page', () => {
    assert.match(PAGE, /getDeviceChangeOutcome/);
    assert.match(PAGE, /changeOutcomeData/);
  });

  it('⛔ the page stays force-dynamic — it reads the database on every render', () => {
    assert.match(PAGE, /export const dynamic = 'force-dynamic'/);
  });

  it('⛔ the page passes failures through, so an unreadable board cannot render as a clean one', () => {
    assert.match(PAGE, /failures=\{[^}]*failures\}/);
  });
});
