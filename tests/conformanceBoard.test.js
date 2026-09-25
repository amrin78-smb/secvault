'use strict';

// tests/conformanceBoard.test.js — pins components/analysis/ConformanceBoard.js,
// the VIEW. lib/engines/fleetConformance.js is pinned by
// tests/fleetConformance.test.js and its plumbing by
// tests/fleetConformanceData.test.js; what is tested here is only what a
// RENDERING can get wrong.
//
// ⛔ THE FAILURE THIS FILE EXISTS TO PREVENT. The engine's one rule is that
// MAJORITY IS NOT CORRECTNESS. Live on the reference fleet,
// `global.admin-ssh-port` is 22 on four FortiGates and 5022 on OKF(F2) — the
// minority is the only firewall NOT on the default SSH port, i.e. the hardened
// one, and 18 of that cohort's 21 differences belong to it. Four ways a view
// hands that straight back, each asserted below rather than left to a review:
//
//   1. A DEVIATION DRAWN ON THE SEVERITY RAMP. Red means danger everywhere
//      else in this product, so a red row reads as "this firewall is exposed".
//   2. A SCORE'S SHAPE. A percentage, a grade or a band turns a count of
//      differences into a measure of quality by arithmetic.
//   3. VALUE AND PRESENCE SUMMED. The engine splits them because they are not
//      equally trustworthy, and there are more of the weaker ones.
//   4. A COHORT THAT PRODUCED NOTHING DRAWN AS A CLEAN ONE. TUG is a cohort of
//      one. Rendered as an empty measured cohort it is the best-behaved
//      firewall on the board.
//
// Loading technique is the one tests/coverageRegisterView.test.js and
// tests/upgradePlanView.test.js already use: `npm test` is `node --test` with
// no "type":"module", so an ESM component cannot be require()d. Everything
// pinned below is a plain const or a plain function with no imported identifier
// in its body, so stripping the `export` keyword and evaluating the pure half
// is exact rather than an approximation.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  buildCohorts,
  findDeviations,
  summariseConformance,
  CONFORMANCE_CLAIM,
  STATUS,
} = require('../lib/engines/fleetConformance');

const REPO = path.join(__dirname, '..');
const VIEW_PATH = path.join(REPO, 'components', 'analysis', 'ConformanceBoard.js');
const RAW_SRC = fs.readFileSync(VIEW_PATH, 'utf8');

// ⛔ COMMENTS STRIPPED BEFORE EVERY SOURCE SCAN. This repo has been bitten
// repeatedly by a scan satisfied by the comment explaining the thing it hunts —
// and this file's subject deliberately spells out, in prose, every word it
// refuses to emit. The stripper is PROVEN by its own test below.
const BLOCK_COMMENT = new RegExp('/\\*[\\s\\S]*?\\*/', 'g');
const LINE_COMMENT = new RegExp('(^|[\\s{(;,])//[^\\n]*', 'g');
const stripComments = (src) =>
  String(src).replace(BLOCK_COMMENT, ' ').replace(LINE_COMMENT, '$1 ');

const CODE = stripComments(RAW_SRC);

const EXPORTS = [
  'BOARD_PURPOSE',
  'FAILURE_NOTE',
  'INCOMPLETE_COUNT_REASON',
  'CLAIM_MISSING_NOTE',
  'VALUE_HEADING',
  'VALUE_NOTE',
  'PRESENCE_HEADING',
  'PRESENCE_NOTE',
  'NOT_COMPARED_HEADING',
  'NOT_COMPARED_NOTE',
  'EXCLUDED_HEADING',
  'EXCLUDED_NOTE',
  'RANKING_HEADING',
  'RANKING_NOTE',
  'NO_DEVIATIONS_NOTE',
  'EMPTY_BOARD_NOTE',
  'EMPTY_BOARD_BROKEN_NOTE',
  'COHORT_WEIGHT',
  'SIGNAL_WEIGHT',
  'TONE',
  'cohortWeight',
  'signalWeight',
  'countOf',
  'failureList',
  'boardIsIncomplete',
  'reportableCount',
  'claimText',
  'cohortLabel',
  'namesOf',
  'valueRows',
  'presenceKindLabel',
  'presenceRows',
  'limitText',
  'excludedRows',
  'unreportableRows',
  'rankingRows',
  'statTiles',
  'asOf',
  'depthNote',
];

function loadView() {
  const declarations = RAW_SRC
    .split('\n')
    .filter((line) => !/^\s*import\s/.test(line))
    .join('\n')
    .replace(/\bexport\s+(const|function)\b/g, '$1');

  // Cut at the first JSX-bearing piece: everything pinned here is declared
  // above it, and `new Function` cannot parse JSX.
  const cut = declarations.indexOf('function Swatch(');
  assert.notEqual(cut, -1, 'expected Swatch to mark the start of the JSX half');
  const pure = declarations.slice(0, cut);
  // eslint-disable-next-line no-new-func
  return new Function(`${pure}\nreturn { ${EXPORTS.join(', ')} };`)();
}

const V = loadView();

// ── fixtures, produced by the REAL engine ───────────────────────────────────
//
// ⛔ NOT HAND-WRITTEN SHAPES. A view test whose fixtures were typed by hand
// pins the view against a structure nothing produces, and would go on passing
// after the engine's output changed. These are the engine's own output over a
// fleet shaped like the live one.

const dev = (id, name, vendor, mgmt_method, config_parsed) =>
  ({ id, name, vendor, mgmt_method, config_parsed });

const fortinet = (odd) => ({
  dns: { protocol: odd ? 'cleartext' : 'dot' },
  global: {
    'admin-ssh-port': odd ? '5022' : '22',
    'admin-https-redirect': odd ? 'disable' : 'enable',
  },
  // Present on the four, absent from the odd one — a PRESENCE difference.
  system_info: odd ? undefined : { build: 1234 },
});

const FLEET = [
  dev('f1', 'OKF(F2)', 'fortinet', 'ssh', fortinet(true)),
  dev('f2', 'TSR-TL', 'fortinet', 'ssh', fortinet(false)),
  dev('f3', 'Vietnam-YCC', 'fortinet', 'ssh', fortinet(false)),
  dev('f4', 'HRIS', 'fortinet', 'ssh', fortinet(false)),
  dev('f5', 'PAKFood', 'fortinet', 'ssh', fortinet(false)),
  // ⛔ The cohort of one. It yields nothing, and that is the correct answer.
  dev('p1', 'TUG', 'paloalto', 'ssh', { tree: { sw_version: '11.1.2' } }),
  // A firewall nothing has been collected from: excluded, and COUNTED.
  dev('f6', 'DARK', 'fortinet', 'ssh', null),
];

const RESULTS = buildCohorts(FLEET).map(findDeviations);
const SUMMARY = summariseConformance(RESULTS);
const FORTINET = RESULTS.find((r) => r.cohortKey === 'fortinet/ssh');
const LONE = RESULTS.find((r) => r.cohortKey === 'paloalto/ssh');

const RAMP = /--sev-[a-z]+|--red\b|--orange\b|--yellow\b|--green\b|--blue\b|--purple\b|--teal\b|--accent-teal\b|--primary\b/;

// ────────────────────────────────────────────────────────────────────────────
// 1. ⛔ THE VISUAL WEIGHTS ARE DATA, AND THEIR RANKING IS THE FEATURE
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ the weights rank the unreportable states ABOVE `measured`', () => {
  it('every status the engine can emit has a declared weight', () => {
    for (const status of Object.values(STATUS)) {
      assert.ok(V.COHORT_WEIGHT[status], `no declared weight for ${status}`);
      assert.equal(V.COHORT_WEIGHT[status].kind, status);
      assert.equal(typeof V.COHORT_WEIGHT[status].rank, 'number');
    }
  });

  it('⛔ a cohort that yielded nothing is LOUDER than one that was compared', () => {
    // Drawn quieter, it is the best-behaved thing on the board — which is this
    // product's most-repeated inversion wearing this feature's clothes.
    assert.ok(
      V.COHORT_WEIGHT.insufficient_cohort.rank < V.COHORT_WEIGHT.measured.rank,
      'insufficient_cohort is quieter than measured',
    );
    assert.ok(
      V.COHORT_WEIGHT.threshold_unreachable.rank < V.COHORT_WEIGHT.measured.rank,
      'threshold_unreachable is quieter than measured',
    );
  });

  it('⛔ the unreportable states are HATCHED and hueless, never a reassuring grey fill', () => {
    for (const k of ['insufficient_cohort', 'threshold_unreachable', 'unknown']) {
      assert.equal(V.COHORT_WEIGHT[k].swatch, 'hatch', `${k} is drawn as a flat fill`);
      assert.equal(V.COHORT_WEIGHT[k].color, 'var(--unmeasured)');
    }
  });

  it('⛔ NOTHING in the weight tables carries a hue — a deviation is not a severity', () => {
    const all = JSON.stringify([V.COHORT_WEIGHT, V.SIGNAL_WEIGHT, V.TONE]);
    assert.doesNotMatch(all, RAMP, 'a weight borrowed the severity ramp');
    assert.doesNotMatch(all, /--tint-/, 'a weight took a tinted surface');
    assert.doesNotMatch(all, /#[0-9a-fA-F]{3,8}/, 'a weight hardcoded a colour');
  });

  it('⛔ an unrecognised status resolves to the hueless fallback, NEVER to `measured`', () => {
    // The asymmetry is the point: an unknown shape drawn as unassessed is
    // merely over-reported, while the same shape drawn as compared is an
    // all-clear derived from something the view could not read.
    for (const bad of ['nonsense', '', null, undefined, 0, 'MEASURED']) {
      assert.equal(V.cohortWeight(bad).kind, 'unknown', `${String(bad)} resolved elsewhere`);
    }
    assert.equal(V.cohortWeight('measured').kind, 'measured');
    assert.notEqual(V.COHORT_WEIGHT.unknown.label, V.COHORT_WEIGHT.measured.label);
  });

  it('⛔ VALUE outranks PRESENCE, and an unrecognised signal falls to the WEAKER one', () => {
    assert.ok(V.SIGNAL_WEIGHT.value.rank < V.SIGNAL_WEIGHT.presence.rank);
    assert.equal(V.signalWeight('presence').kind, 'presence');
    assert.equal(V.signalWeight('value').kind, 'value');
    // An unknown signal taking the STRONGER weight would let a data change
    // quietly promote an absent setting to a like-for-like disagreement.
    assert.equal(V.signalWeight('nonsense').kind, 'presence');
    assert.equal(V.signalWeight(undefined).kind, 'presence');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 2. ⛔ `insufficient_cohort` IS A VISIBLE STATE, NEVER AN EMPTY ALL-CLEAR
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ a cohort that yielded nothing says so', () => {
  it('the engine really does produce one here, so the rest of this block is real', () => {
    assert.equal(LONE.status, STATUS.INSUFFICIENT_COHORT);
    assert.equal(LONE.comparableCount, 1);
  });

  it('⛔ it is hoisted into its own list rather than left to be noticed', () => {
    const rows = V.unreportableRows(SUMMARY);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].cohortKey, 'paloalto/ssh');
    assert.equal(rows[0].kind, 'insufficient_cohort');
    assert.equal(rows[0].comparableCount, 1);
  });

  it('⛔ it carries the engine’s own limit sentence, not a local paraphrase', () => {
    const rows = V.unreportableRows(SUMMARY);
    assert.equal(rows[0].limit, SUMMARY.insufficientCohorts[0].limit);
    assert.match(rows[0].limit, /Nothing was compared/);
    assert.equal(V.limitText(LONE), LONE.limit);
  });

  it('⛔ its label says it cannot be compared, and never that it was', () => {
    const rows = V.unreportableRows(SUMMARY);
    assert.equal(rows[0].label, V.COHORT_WEIGHT.insufficient_cohort.label);
    assert.match(rows[0].label, /cannot be compared/i);
    assert.notEqual(rows[0].label, V.COHORT_WEIGHT.measured.label);
  });

  it('threshold_unreachable gets the same treatment, in the same list', () => {
    const three = [
      dev('a', 'A', 'checkpoint', 'api', { s: { p: 'x' } }),
      dev('b', 'B', 'checkpoint', 'api', { s: { p: 'x' } }),
      dev('c', 'C', 'checkpoint', 'api', { s: { p: 'y' } }),
    ];
    const summary = summariseConformance(buildCohorts(three).map(findDeviations));
    const rows = V.unreportableRows(summary);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].kind, 'threshold_unreachable');
    assert.match(rows[0].label, /no result is reportable/i);
    assert.ok(rows[0].limit.length > 0);
  });

  it('⛔ the note beside the list refuses the all-clear reading in words', () => {
    assert.match(V.NOT_COMPARED_NOTE, /absence of comparison/i);
    assert.match(V.NOT_COMPARED_NOTE, /not an absence of differences/i);
  });

  it('a summary with nothing unreportable produces no list at all', () => {
    assert.deepEqual(V.unreportableRows({}), []);
    assert.deepEqual(V.unreportableRows(null), []);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 3. ⛔ VALUE AND PRESENCE ARE NEVER SUMMED
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ the two signals are kept apart', () => {
  it('the fixture really produces both, so this block is not vacuous', () => {
    assert.ok(FORTINET.valueDeviations.length > 0);
    assert.ok(FORTINET.presenceDeviations.length > 0);
    assert.notEqual(FORTINET.valueDeviations.length, FORTINET.presenceDeviations.length);
  });

  it('⛔ each gets its own tile, and no tile holds the sum', () => {
    const tiles = V.statTiles(SUMMARY, false);
    const value = tiles.find((t) => t.key === 'valueDeviations');
    const presence = tiles.find((t) => t.key === 'presenceDeviations');
    assert.equal(value.value, SUMMARY.valueDeviations);
    assert.equal(presence.value, SUMMARY.presenceDeviations);
    const total = SUMMARY.valueDeviations + SUMMARY.presenceDeviations;
    assert.notEqual(value.value, total);
    for (const t of tiles) {
      assert.notEqual(t.value, total, `a tile prints the summed figure: ${t.label}`);
      // ⛔ AND A TILE CARRIES NO SECOND NUMBER. A combined figure smuggled in
      // beside the one the tile is named for would be read as the real total,
      // with the split relegated to detail.
      assert.deepEqual(
        Object.keys(t).sort(),
        ['key', 'label', 'reason', 'sub', 'tone', 'value'],
        `an extra field on the ${t.label} tile`,
      );
    }
  });

  it('⛔ the ranking has two columns and no total', () => {
    const rows = V.rankingRows(SUMMARY);
    const okf = rows.find((r) => r.deviceName === 'OKF(F2)');
    assert.ok(okf.valueCount > 0);
    assert.ok(okf.presenceCount > 0);
    for (const r of rows) {
      assert.deepEqual(
        Object.keys(r).sort(),
        ['cohortKey', 'deviceId', 'deviceName', 'key', 'presenceCount', 'valueCount'],
      );
      assert.notEqual(r.valueCount + r.presenceCount, undefined);
    }
    const json = JSON.stringify(rows);
    assert.doesNotMatch(json, /"(total|deviations|combined|sum)"/i);
  });

  it('presence rows are built separately and carry the weaker weight', () => {
    const vals = V.valueRows(FORTINET);
    const pres = V.presenceRows(FORTINET);
    assert.equal(vals.length, FORTINET.valueDeviations.length);
    assert.equal(pres.length, FORTINET.presenceDeviations.length);
    for (const r of vals) assert.equal(r.weight.kind, 'value');
    for (const r of pres) assert.equal(r.weight.kind, 'presence');
  });

  it('⛔ the note says presence is the weaker signal and is counted apart', () => {
    assert.match(V.PRESENCE_NOTE, /weaker/i);
    assert.match(V.PRESENCE_NOTE, /never added to it/i);
  });

  it('presence keys stay unique when two groups share one path', () => {
    const rows = V.presenceRows({
      presenceDeviations: [
        { kind: 'section_absent', path: 'system_info', absentDevices: [{ deviceName: 'A' }], absentCount: 1 },
        { kind: 'section_absent', path: 'system_info', absentDevices: [{ deviceName: 'B' }], absentCount: 1 },
      ],
    });
    assert.equal(new Set(rows.map((r) => r.key)).size, 2);
  });

  it('an unrecognised presence kind is named, never silently called the milder one', () => {
    assert.equal(V.presenceKindLabel('section_absent'), 'Whole section');
    assert.equal(V.presenceKindLabel('setting_absent'), 'One setting');
    assert.match(V.presenceKindLabel('nonsense'), /not recognised/i);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 4. ⛔ THE THREE DEVICE COUNTS ARE THREE DIFFERENT FACTS
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ compared / not compared / left out are never blended', () => {
  it('the fixture produces all three at once', () => {
    assert.equal(SUMMARY.devicesCompared, 5);
    assert.equal(SUMMARY.devicesInUnreportableCohorts, 1);
    assert.equal(SUMMARY.devicesExcluded, 1);
  });

  it('each gets its own tile, with its own label and its own value', () => {
    const tiles = V.statTiles(SUMMARY, false);
    const by = Object.fromEntries(tiles.map((t) => [t.key, t]));
    assert.equal(by.devicesCompared.value, 5);
    assert.equal(by.devicesInUnreportableCohorts.value, 1);
    assert.equal(by.devicesExcluded.value, 1);
    const labels = tiles.map((t) => t.label);
    assert.equal(new Set(labels).size, labels.length, 'two tiles share a label');
    // ⛔ No tile prints a firewall total: "16 firewalls" beside these three
    // would invite the reader to treat the other two as a share of it.
    for (const t of tiles) assert.notEqual(t.value, 7);
  });

  it('⛔ a firewall left out of its cohort is NAMED, with the engine’s own reason', () => {
    const rows = V.excludedRows(FORTINET);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].deviceName, 'DARK');
    assert.equal(rows[0].reason, 'no_parsed_config');
    assert.equal(rows[0].detail, FORTINET.excluded[0].detail);
    assert.ok(rows[0].detail.length > 50, 'the reason was paraphrased away');
  });

  it('the excluded note says why it is counted rather than dropped', () => {
    assert.match(V.EXCLUDED_NOTE, /counted and named/i);
    assert.match(V.EXCLUDED_NOTE, /better covered than it is/i);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 5. ⛔ A FAILED READ IS REPORTED DISTINCTLY FROM "NO DEVIATIONS"
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ an incomplete board never renders as a clean one', () => {
  const CLEAN = summariseConformance(
    buildCohorts([
      dev('a', 'A', 'fortinet', 'ssh', { g: { p: 'x' } }),
      dev('b', 'B', 'fortinet', 'ssh', { g: { p: 'x' } }),
      dev('c', 'C', 'fortinet', 'ssh', { g: { p: 'x' } }),
      dev('d', 'D', 'fortinet', 'ssh', { g: { p: 'x' } }),
      dev('e', 'E', 'fortinet', 'ssh', { g: { p: 'x' } }),
    ]).map(findDeviations),
  );

  it('the clean fixture really is clean — a measured zero', () => {
    assert.equal(CLEAN.valueDeviations, 0);
    assert.equal(CLEAN.presenceDeviations, 0);
    assert.equal(CLEAN.devicesCompared, 5);
  });

  it('⛔ THE SAME SUMMARY READS DIFFERENTLY WITH AND WITHOUT A FAILURE', () => {
    // This is the case that regresses silently. A broken read summarises an
    // EMPTY list, so every total is 0 — indistinguishable from a fleet that
    // agrees, unless the failure is what decides whether a count prints.
    const clean = V.statTiles(CLEAN, V.boardIsIncomplete([]));
    const broken = V.statTiles(CLEAN, V.boardIsIncomplete([{ source: 'conformance_configs', error: 'down' }]));
    assert.equal(clean.find((t) => t.key === 'valueDeviations').value, 0);
    assert.equal(broken.find((t) => t.key === 'valueDeviations').value, null);
    for (const t of broken) {
      assert.equal(t.value, null, `${t.label} printed a count over an incomplete board`);
      assert.equal(t.reason, V.INCOMPLETE_COUNT_REASON);
    }
  });

  it('⛔ the ranking withholds its counts too, for the same reason', () => {
    const rows = V.rankingRows(SUMMARY);
    assert.equal(V.reportableCount(rows[0].valueCount, true), null);
    assert.equal(V.reportableCount(rows[0].valueCount, false), rows[0].valueCount);
  });

  it('⛔ ANY failure at all counts — there is no threshold and no minor case', () => {
    assert.equal(V.boardIsIncomplete([]), false);
    assert.equal(V.boardIsIncomplete(null), false);
    assert.equal(V.boardIsIncomplete(undefined), false);
    assert.equal(V.boardIsIncomplete([{ source: 'x', error: 'y' }]), true);
    assert.equal(V.boardIsIncomplete(['a string']), true);
    // ⛔ A shape this file does not recognise is itself evidence the board is
    // incomplete. Swallowing it would render the short list silently.
    assert.equal(V.boardIsIncomplete({ configs: 'down' }), true);
    assert.equal(V.boardIsIncomplete('everything broke'), true);
  });

  it('failure lines name the source and the error', () => {
    assert.deepEqual(
      V.failureList([{ source: 'conformance_configs', error: 'timeout' }]),
      ['conformance_configs: timeout'],
    );
    assert.deepEqual(V.failureList([null, undefined, '']), []);
    assert.deepEqual(V.failureList({ a: 'b' }), ['a: b']);
  });

  it('the banner wording refuses the short-list reading', () => {
    assert.match(V.FAILURE_NOTE, /INCOMPLETE/);
    assert.match(V.FAILURE_NOTE, /has not been cleared/i);
    assert.match(V.FAILURE_NOTE, /floor rather than a total/i);
  });

  it('⛔ an EMPTY board says so in two different ways, and neither is an all-clear', () => {
    assert.notEqual(V.EMPTY_BOARD_NOTE, V.EMPTY_BOARD_BROKEN_NOTE);
    assert.match(V.EMPTY_BOARD_NOTE, /absence of\s+comparison/i);
    assert.match(V.EMPTY_BOARD_BROKEN_NOTE, /nothing about the fleet/i);
  });

  it('a count that did not arrive is null, never a zero', () => {
    assert.equal(V.countOf({ devicesCompared: 0 }, 'devicesCompared'), 0);
    assert.equal(V.countOf({}, 'devicesCompared'), null);
    assert.equal(V.countOf(null, 'devicesCompared'), null);
    assert.equal(V.countOf({ devicesCompared: '5' }, 'devicesCompared'), null);
    assert.equal(V.countOf({ devicesCompared: NaN }, 'devicesCompared'), null);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 6. ⛔ THE CLAIM IS RENDERED, NOT DUPLICATED
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ the engine’s one claim', () => {
  it('is rendered exactly as it arrived', () => {
    assert.equal(V.claimText(CONFORMANCE_CLAIM), CONFORMANCE_CLAIM);
  });

  it('⛔ has NO local copy and NO fallback wording', () => {
    // A second wording would be a second claim, and it would drift from the one
    // the engine's own tests pin.
    const fragment = CONFORMANCE_CLAIM.slice(0, 60);
    assert.doesNotMatch(CODE, new RegExp(fragment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'));
    assert.doesNotMatch(CODE, /may be the only one set deliberately/i);
    for (const missing of [undefined, null, '', '   ', 7, {}]) {
      assert.equal(V.claimText(missing), null, `${String(missing)} produced a claim`);
    }
  });

  it('⛔ an absent claim is said out loud rather than replaced', () => {
    assert.match(V.CLAIM_MISSING_NOTE, /not shown/i);
    assert.match(V.CLAIM_MISSING_NOTE, /second claim/i);
  });

  it('the board’s own line describes the mechanics, never the meaning', () => {
    assert.match(V.BOARD_PURPOSE, /cohort is one vendor collected one way/i);
    assert.doesNotMatch(V.BOARD_PURPOSE, /means|intended|deliberate/i);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 7. ⛔ NO SCORE, NO GRADE, NO PERCENTAGE, NO BAND
// ────────────────────────────────────────────────────────────────────────────

const PROSE = () => [
  ...EXPORTS.filter((k) => typeof V[k] === 'string').map((k) => V[k]),
  ...V.statTiles(SUMMARY, false).flatMap((t) => [t.label, t.sub, t.reason]),
  ...V.statTiles(SUMMARY, true).flatMap((t) => [t.label, t.sub, t.reason]),
  ...V.unreportableRows(SUMMARY).map((r) => r.label),
  ...Object.values(V.COHORT_WEIGHT).map((w) => w.label),
  ...Object.values(V.SIGNAL_WEIGHT).map((w) => w.label),
  V.presenceKindLabel('section_absent'),
  V.presenceKindLabel('setting_absent'),
  V.presenceKindLabel('nonsense'),
  V.cohortLabel(FORTINET),
  V.cohortLabel({}),
  V.asOf(null),
  V.asOf('not a date'),
  V.depthNote(FORTINET),
  V.depthNote({}),
].filter((s) => typeof s === 'string');

describe('⛔ a count of differences is given no score’s shape', () => {
  it('no string this view writes carries a percentage or a grade', () => {
    // ⛔ SCOPED TO THIS FILE'S OWN PROSE. The engine's `statement` passes
    // through verbatim and can quote a raw configuration value — a firewall
    // setting may legitimately BE "80%" — so a blanket scan over pass-through
    // text would fail on live data for the wrong reason.
    const prose = PROSE();
    assert.ok(prose.length > 40, `expected real prose, got ${prose.length}`);
    for (const s of prose) {
      assert.doesNotMatch(s, /%/, `carries a percentage: ${s}`);
      assert.doesNotMatch(s, /\bscore\b|\bgrade[ds]?\b|\brating\b|\bpercentile\b|\bout of 100\b/i, `carries a score: ${s}`);
    }
  });

  it('no emitted structure carries a score, grade or band FIELD', () => {
    const json = JSON.stringify({
      tiles: V.statTiles(SUMMARY, false),
      rows: V.rankingRows(SUMMARY),
      values: V.valueRows(FORTINET),
      presence: V.presenceRows(FORTINET),
      unreportable: V.unreportableRows(SUMMARY),
      excluded: V.excludedRows(FORTINET),
      weights: [V.COHORT_WEIGHT, V.SIGNAL_WEIGHT],
    });
    assert.doesNotMatch(json, /"score/i);
    assert.doesNotMatch(json, /"(grade|band|rating|health|pct|percent)"/i);
  });

  it('⛔ and the source computes none — no division by a cohort size anywhere', () => {
    // A conformance percentage is one `/` away, and arithmetic is how a count
    // of differences quietly becomes a measure of quality.
    assert.doesNotMatch(CODE, /\bpct\b|percent|toFixed|Math\.round\s*\(/i);
    assert.doesNotMatch(CODE, /minorityFraction/);
  });

  it('every tile value is a whole count or an honest absence', () => {
    for (const t of V.statTiles(SUMMARY, false)) {
      assert.ok(t.value === null || Number.isInteger(t.value), `${t.label} is not a count`);
    }
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 8. ⛔ MAJORITY IS NOT CORRECTNESS — the vocabulary of judgement is absent
// ────────────────────────────────────────────────────────────────────────────

const FORBIDDEN = [
  /\bmisconfig\w*/i,
  /\bwrong\b/i,
  /\bincorrect\w*/i,
  /\bnon-?compliant\b/i,
  /\bcompliant\b/i,
  /\bviolat\w*/i,
  /\bshould\b/i,
  /\bmust\b/i,
  /\bfix(es|ed|ing)?\b/i,
  /\bremediat\w*/i,
  /\bfault\w*/i,
  /\bbad\b/i,
  /\binvalid\b/i,
  /\bbreach\w*/i,
];

describe('⛔ nothing this view renders reads as a verdict', () => {
  it('no string this view writes carries the vocabulary of judgement', () => {
    for (const s of PROSE()) {
      for (const bad of FORBIDDEN) {
        assert.doesNotMatch(s, bad, `rendered string carries ${bad}: ${s}`);
      }
    }
  });

  it('⛔ and no string LITERAL or JSX text in the source carries it — comments stripped FIRST', () => {
    // ⛔ THIS COVERS THE JSX PROSE TOO, which is the half no exported constant
    // reaches and the half a reader actually reads.
    for (const bad of FORBIDDEN) {
      const hit = CODE.match(new RegExp(bad.source, 'gi'));
      assert.equal(hit, null, `source (comments stripped) carries ${bad}: ${hit}`);
    }
  });

  it('⛔ the stripper is proven, not assumed', () => {
    // The header explains the rule by naming the readings it refuses, in as
    // many words. If the stripper ever stopped working the scan above would go
    // red on that comment rather than green on nothing.
    assert.match(RAW_SRC, /misconfigured/i);
    assert.match(RAW_SRC, /\bwrong\b/i);
    assert.match(RAW_SRC, /\bfixing\b/i);
    assert.doesNotMatch(CODE, /misconfigured/i);
    assert.doesNotMatch(CODE, /\bwrong\b/i);
    assert.doesNotMatch(CODE, /\bfixing\b/i);
  });

  it('⛔ both sides of a difference are described by what they report', () => {
    const rows = V.valueRows(FORTINET);
    const port = rows.find((r) => r.path === 'global.admin-ssh-port');
    // The live case: the minority is the HARDENED firewall.
    assert.deepEqual(port.minorityNames, ['OKF(F2)']);
    assert.match(port.statement, /"22"/);
    assert.match(port.statement, /"5022"/);
    assert.equal(port.summary, '1 of 5 differ');
    // ⛔ PASSED THROUGH, NOT REWRITTEN. The engine's neutral wording is the
    // only wording; a local rephrasing is where a verdict creeps in.
    const src = FORTINET.valueDeviations.find((d) => d.path === 'global.admin-ssh-port');
    assert.equal(port.statement, src.statement);
    assert.equal(port.summary, src.summary);
  });

  it('the ranking note refuses the "worst firewall" reading', () => {
    assert.match(V.RANKING_NOTE, /not a measure of quality/i);
    assert.match(V.RANKING_NOTE, /deliberate standard/i);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 9. ⛔ THE DESIGN SYSTEM
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ tokens only, and no hue on a difference', () => {
  it('no hardcoded hex anywhere in the file', () => {
    const hex = CODE.match(/#[0-9a-fA-F]{3,8}\b/g);
    assert.equal(hex, null, `hardcoded colours: ${hex}`);
  });

  it('⛔ no severity-ramp token appears at all — red would be especially wrong here', () => {
    const hit = CODE.match(new RegExp(RAMP.source, 'g'));
    assert.equal(hit, null, `the severity ramp reached a board of differences: ${hit}`);
    assert.doesNotMatch(CODE, /--tint-danger/, 'the danger pair reached a board of differences');
  });

  it('⛔ --evidence is untouched — it belongs to EvidenceMark alone', () => {
    assert.doesNotMatch(CODE, /--evidence/);
    assert.doesNotMatch(CODE, /EvidenceMark/);
  });

  it('the one tinted surface is a --tint-*/--tint-*-fg PAIR', () => {
    const tints = [...new Set(CODE.match(/--tint-[a-z-]+/g) || [])].sort();
    assert.deepEqual(tints, ['--tint-warn', '--tint-warn-fg']);
  });

  it('spacing and type come from the token scales', () => {
    assert.match(CODE, /var\(--s[1-9]\)/);
    assert.match(CODE, /var\(--text-(xs|sm|base|lg)\)/);
    // ⛔ A component that invents its own gap opts itself out of every future
    // spacing change, silently — the same way a hardcoded hex opts out of the
    // palette. Only the two deliberate swatch dimensions are bare numbers.
    const gaps = CODE.match(/gap:\s*'[^']*'/g) || [];
    for (const g of gaps) assert.match(g, /var\(--s[1-9]\)/, `a hand-rolled gap: ${g}`);
    const pads = CODE.match(/padding:\s*'[^']*'/g) || [];
    for (const p of pads) assert.match(p, /var\(--s[1-9]\)/, `a hand-rolled padding: ${p}`);
  });

  it('⛔ no React component is defined inside another', () => {
    // A nested component remounts on every render and loses input focus —
    // CLAUDE.md's first Critical Rule.
    assert.doesNotMatch(CODE, /^[ \t]+function\s+[A-Z]/m);
  });

  it('⛔ it is a pure presentational component: props only, no fetching, no client state', () => {
    assert.doesNotMatch(CODE, /use client/);
    assert.doesNotMatch(CODE, /useState|useEffect|fetch\(|pool\b/);
    assert.match(CODE, /export default function ConformanceBoard\(\s*\{\s*cohorts,\s*summary,\s*failures,\s*generatedAt,\s*claim\s*\}/);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 10. The small helpers
// ────────────────────────────────────────────────────────────────────────────

describe('the helpers', () => {
  it('⛔ the cohort label keeps BOTH slugs — the access method is half the identity', () => {
    assert.equal(V.cohortLabel(FORTINET), 'fortinet / ssh');
    assert.equal(V.cohortLabel(LONE), 'paloalto / ssh');
    // TUG's whole story is that it is the only Palo Alto collected over SSH.
    assert.notEqual(V.cohortLabel(LONE), V.cohortLabel({ vendor: 'paloalto', mgmtMethod: 'api' }));
  });

  it('a cohort with no key is named, never left blank', () => {
    assert.match(V.cohortLabel({}), /no vendor or access method/i);
    assert.match(V.cohortLabel({ vendor: 'fortinet' }), /no vendor or access method/i);
  });

  it('device names fall back rather than rendering as nothing', () => {
    assert.deepEqual(V.namesOf([{ deviceName: 'A' }, { deviceId: 'b' }, {}]), ['A', 'b', 'an unnamed firewall']);
    assert.deepEqual(V.namesOf(null), []);
  });

  it('⛔ a board with no timestamp says so rather than dropping it', () => {
    assert.match(V.asOf(null), /was not recorded/);
    assert.match(V.asOf('nonsense'), /could not be read/);
    assert.match(V.asOf('2026-09-25T12:00:00.000Z'), /as of 2026-09-25 12:00 UTC/);
  });

  it('⛔ an unreadable "how much was compared" is stated, not defaulted to a number', () => {
    assert.match(V.depthNote({}), /did not arrive/i);
    assert.match(V.depthNote(FORTINET), new RegExp(`${FORTINET.comparedPaths} settings were compared`));
    assert.match(V.depthNote(FORTINET), /depth of 3/);
  });

  it('the identity skips are explained where they happen', () => {
    const withSkips = V.depthNote({ comparedPaths: 10, maxDepth: 3, identityPathsSkipped: 4 });
    assert.match(withSkips, /4 further settings/);
    assert.match(withSkips, /its own name, address, model, serial or clock/);
    // Zero skips says nothing rather than saying "0 settings were set aside".
    assert.doesNotMatch(V.depthNote({ comparedPaths: 10, maxDepth: 3, identityPathsSkipped: 0 }), /set aside/);
  });

  it('every row list tolerates a missing or misshapen input', () => {
    for (const bad of [null, undefined, {}, { valueDeviations: 'x' }, { presenceDeviations: 7 }]) {
      assert.deepEqual(V.valueRows(bad), []);
      assert.deepEqual(V.presenceRows(bad), []);
      assert.deepEqual(V.excludedRows(bad), []);
    }
    assert.equal(V.limitText({}), null);
    assert.equal(V.limitText({ limit: '  ' }), null);
    assert.deepEqual(V.rankingRows(null), []);
  });
});
