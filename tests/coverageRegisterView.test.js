'use strict';
// tests/coverageRegisterView.test.js
//
// Pins components/devices/CoverageRegister.js — the VIEW, not the engine.
// lib/engines/coverageRegister.js is pinned separately by
// tests/coverageRegister.test.js; what is tested here is what only the
// rendering can get wrong.
//
// ⛔ THE FAILURE THIS FILE EXISTS TO PREVENT. The engine's whole purpose is to
// say that a firewall nothing can be collected from is not a healthy firewall,
// it is an INVISIBLE one. Four ways a view hands that inversion straight back,
// each asserted below rather than left to a code review:
//
//   1. `absent` drawn in a reassuring grey, which reads as a real, minor,
//      muted category rather than as an absence of data.
//   2. `stale` drawn like `measured`. TSR_EKC's 22 `unused` findings are 49
//      days old and sit beside today's with nothing distinguishing them. A
//      stale answer is ACTED ON; a missing one is not, so stale must be the
//      LOUDER of the two — and SegmentationBoard.js shipped exactly this
//      ranking inverted while satisfying its own rule to the letter.
//   3. `fullyCovered` rendered as an all-clear. It means "we can see this
//      firewall" and nothing whatever about whether it is configured well.
//   4. A `failures` array that is not bannered, so an incomplete register
//      renders short — and a short register looks COMPLETE.
//
// Loading technique is the one tests/upgradePlanView.test.js already uses:
// `npm test` is `node --test` with no "type":"module", so an ESM component
// cannot be require()d. Everything pinned below is a plain const or a plain
// function with no imported identifier in its body, so stripping the `export`
// keyword and evaluating is exact, not an approximation.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');
const VIEW_PATH = path.join(REPO, 'components', 'devices', 'CoverageRegister.js');
const SRC = fs.readFileSync(VIEW_PATH, 'utf8');

// ⛔ COMMENTS STRIPPED BEFORE EVERY SOURCE SCAN. This repo has been bitten
// three separate times by a scan satisfied by the comment explaining the thing
// it was hunting — and this file's own header says "HEALTHIEST DEVICE ON THE
// FLEET" and "No green, no tick, no healthy, no clean" in order to forbid
// them. A scan that read those would fail on its own documentation.
const CODE = SRC
  .replace(/\/\*[\s\S]*?\*\//g, ' ')
  .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ');

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
    'REGISTER_CLAIM',
    'FAILURE_NOTE',
    'COVERED_LABEL',
    'COVERED_NOTE',
    'NOT_CHECKED_LABEL',
    'NOT_CHECKED_NOTE',
    'STALE_NOTE',
    'GATES_PREFIX',
    'CELL_WEIGHT',
    'cellWeight',
    'countOf',
    'failureList',
    'registerIsIncomplete',
    'reportableCount',
    'INCOMPLETE_COUNT_REASON',
    'isUnchecked',
    'chipLabel',
    'chipWeight',
    'gatesSentence',
    'ageLabel',
    'staleSentence',
    'staleCountLabel',
    'staleAgeLabel',
    'sourceIndex',
    'gapRows',
    'asOf',
  ];
  // eslint-disable-next-line no-new-func
  return new Function(`${pure}\nreturn { ${names.join(', ')} };`)();
}

const V = loadView();

// ── fixtures, shaped exactly as the engine emits them ───────────────────────

const cell = (over) => ({
  key: 'syslog',
  label: 'Syslog',
  state: 'absent',
  detail: 'This firewall sends no syslog to SecVault.',
  gates: ['log_hit (CVE priority rule 2)', 'traffic evidence'],
  weight: 4,
  certain: true,
  ageDays: null,
  ...over,
});

const entry = (over) => ({
  deviceId: 'd-1',
  deviceName: 'PAKFood',
  vendor: 'fortinet',
  cells: [cell(), cell({ key: 'config', label: 'Configuration', state: 'measured', gates: [], weight: 0 })],
  gaps: [cell()],
  gapCount: 1,
  answersWithheld: 4,
  blockedEngines: ['log_hit (CVE priority rule 2)', 'traffic evidence'],
  staleFindings: null,
  uncertainCount: 0,
  fullyCovered: false,
  ...over,
});

const RAMP = /--sev-|--red\b|--orange\b|--yellow\b|--green\b|--blue\b|--purple\b|--teal\b|--primary\b/;
const HUED = /--tint-(?:info|success|warn|danger|purple|teal|orange)/;

// ────────────────────────────────────────────────────────────────────────────
// 1. ⛔ THE VISUAL WEIGHTS ARE DATA, AND THEIR RANKING IS THE FEATURE.
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ the state weights rank stale above partial above measured', () => {
  it('every state the engine can emit has a declared weight', () => {
    for (const state of ['measured', 'partial', 'absent', 'stale']) {
      assert.ok(V.CELL_WEIGHT[state], `no declared weight for ${state}`);
      assert.equal(V.CELL_WEIGHT[state].kind, state);
      assert.equal(typeof V.CELL_WEIGHT[state].rank, 'number');
    }
  });

  it('⛔ stale > partial > measured in reading order', () => {
    // Rank is the eye's order, 0 loudest. Asserted as DATA rather than grepped
    // out of a CSS string, because SegmentationBoard.js satisfied a
    // do-not-share-a-colour rule to the letter while running its three tints in
    // the exact reverse of its own action order.
    const { stale, partial, measured } = V.CELL_WEIGHT;
    assert.ok(stale.rank < partial.rank, `stale rank ${stale.rank} must beat partial ${partial.rank}`);
    assert.ok(partial.rank < measured.rank, `partial rank ${partial.rank} must beat measured ${measured.rank}`);
  });

  it('⛔ stale is LOUDER than absent — a stale answer is acted on, a missing one is not', () => {
    const { stale, absent } = V.CELL_WEIGHT;
    assert.ok(stale.rank < absent.rank, `stale rank ${stale.rank} must beat absent ${absent.rank}`);
  });

  it('no two states share a rank', () => {
    const ranks = Object.values(V.CELL_WEIGHT).map((w) => w.rank);
    // `unknown` deliberately shares the absent family's loudness, so only the
    // four real states are compared for uniqueness.
    const real = ['measured', 'partial', 'absent', 'stale'].map((k) => V.CELL_WEIGHT[k].rank);
    assert.equal(new Set(real).size, real.length, 'two states rank equally and will read as equals');
    assert.ok(ranks.length >= real.length);
  });

  it('no two states share a label', () => {
    const labels = Object.values(V.CELL_WEIGHT).map((w) => w.label);
    assert.equal(new Set(labels).size, labels.length, 'two states share a word and are indistinguishable');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 2. ⛔ NOT MEASURED HAS NO HUE.
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ an absence of evidence is drawn hueless', () => {
  it('`absent` carries --unmeasured and hatching, and no hue at all', () => {
    const w = V.CELL_WEIGHT.absent;
    assert.match(JSON.stringify(w), /var\(--unmeasured\)/, 'absent must use the unmeasured token');
    assert.equal(w.swatch, 'hatch', 'a flat fill reads as a real, muted category — the texture is the statement');
    const blob = JSON.stringify(w);
    assert.equal(RAMP.test(blob), false, 'absent wears a hue from the ramp');
    assert.equal(HUED.test(blob), false, 'absent wears a tint pair');
  });

  it('`partial` is hueless too, and still distinguishable from absent', () => {
    const p = V.CELL_WEIGHT.partial;
    const a = V.CELL_WEIGHT.absent;
    const blob = JSON.stringify(p);
    assert.equal(RAMP.test(blob), false, 'partial wears a hue from the ramp');
    assert.equal(HUED.test(blob), false, 'partial wears a tint pair');
    assert.notEqual(p.label, a.label);
    assert.notEqual(p.border, a.border, 'partial and absent share a border and will read alike');
    assert.notEqual(p.color, a.color);
  });

  it('⛔ `measured` is never green and never a tick', () => {
    // Green on a coverage register is an all-clear it has not earned: the
    // engine measures VISIBILITY, and visibility is not safety.
    const blob = JSON.stringify(V.CELL_WEIGHT.measured);
    assert.equal(RAMP.test(blob), false, 'measured wears a hue from the ramp');
    assert.equal(HUED.test(blob), false, 'measured wears a tint pair');
    assert.equal(/✓|✔|check/i.test(blob), false, 'measured must not carry a tick');
  });

  it('⛔ stale is the ONLY hued state, and uses a --tint-* / --tint-*-fg PAIR', () => {
    const hued = Object.entries(V.CELL_WEIGHT)
      .filter(([, w]) => HUED.test(JSON.stringify(w)))
      .map(([k]) => k);
    assert.deepEqual(hued, ['stale'], `expected only stale to carry a hue, got ${hued.join(', ')}`);
    const w = V.CELL_WEIGHT.stale;
    assert.match(w.background, /var\(--tint-warn\)/);
    assert.match(w.color, /var\(--tint-warn-fg\)/, 'a tinted surface behind text needs its -fg partner');
  });

  it('⛔ an UNRECOGNISED state never resolves to `measured`', () => {
    // A state we cannot characterise, characterised as measured, is an
    // all-clear derived from something we could not read.
    for (const junk of ['', 'nope', undefined, null, 0, 'MEASURED', 'unknown']) {
      const w = V.cellWeight(junk);
      assert.notEqual(w.kind, 'measured', `cellWeight(${JSON.stringify(junk)}) fell to measured`);
      assert.ok(w.rank < V.CELL_WEIGHT.measured.rank, 'the fallback must be louder than measured');
      assert.equal(RAMP.test(JSON.stringify(w)), false);
    }
    assert.equal(V.cellWeight('measured').kind, 'measured');
    assert.equal(V.cellWeight('stale').kind, 'stale');
    assert.equal(V.cellWeight('partial').kind, 'partial');
    assert.equal(V.cellWeight('absent').kind, 'absent');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 3. ⛔ `certain: false` IS A THIRD THING, NOT A CONFIRMED GAP.
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ "we could not even check" never reads as a confirmed gap', () => {
  it('an uncertain cell is labelled "Not checked", not "Not measured"', () => {
    const c = cell({ certain: false, detail: 'Syslog coverage could not be read.' });
    assert.equal(V.isUnchecked(c), true);
    assert.equal(V.chipLabel(c), V.NOT_CHECKED_LABEL);
    assert.notEqual(V.chipLabel(c), V.CELL_WEIGHT.absent.label, 'an unread check is not a measured gap');
  });

  it('a certain cell keeps its own state label', () => {
    assert.equal(V.chipLabel(cell({ certain: true, state: 'absent' })), V.CELL_WEIGHT.absent.label);
    assert.equal(V.chipLabel(cell({ certain: true, state: 'stale' })), V.CELL_WEIGHT.stale.label);
  });

  it('⛔ an uncertain cell is drawn hueless WHATEVER state it claims', () => {
    // Its state came out of a read that failed, so the state is not evidence.
    const w = V.chipWeight(cell({ state: 'stale', certain: false }));
    assert.notEqual(w.kind, 'stale', 'an unread check must not borrow the stale hue');
    assert.equal(HUED.test(JSON.stringify(w)), false);
  });

  it('a missing cell is unchecked, not measured', () => {
    for (const junk of [null, undefined, 'x', 42]) {
      assert.equal(V.isUnchecked(junk), true, `${JSON.stringify(junk)} must not read as a real cell`);
      assert.equal(V.chipLabel(junk), V.NOT_CHECKED_LABEL);
    }
  });

  it('the note says plainly that it is neither a gap nor an answer', () => {
    assert.match(V.NOT_CHECKED_NOTE, /not a confirmed gap/i);
    assert.match(V.NOT_CHECKED_NOTE, /unanswered question/i);
  });

  it('⛔ the note is RENDERED beside the cell, not only defined', () => {
    assert.match(CODE, /\{NOT_CHECKED_NOTE\}/, 'the qualifier is declared and never shown');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 4. ⛔ A GAP STATES ITS CONSEQUENCE, NEVER JUST ITS NAME.
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ every gap renders what it withholds', () => {
  it('the gated answers are turned into a sentence, not a bare name', () => {
    const s = V.gatesSentence(cell());
    assert.match(s, /^Withholds:/);
    assert.match(s, /log_hit \(CVE priority rule 2\)/);
    assert.match(s, /traffic evidence/);
  });

  it('a measured cell gates nothing and produces no sentence', () => {
    assert.equal(V.gatesSentence(cell({ gates: [] })), null);
    assert.equal(V.gatesSentence(null), null);
    assert.equal(V.gatesSentence(cell({ gates: undefined })), null);
  });

  it("⛔ the engine's own `detail` and the gate sentence are BOTH rendered", () => {
    // "No hit counts" is a fact nobody acts on. The consequence is the feature.
    assert.match(CODE, /\{cell\.detail/, 'the detail sentence is never rendered');
    assert.match(CODE, /gatesSentence\(cell\)/, 'the gated answers are never rendered');
  });

  it('a detail that did not travel is said, not blanked', () => {
    assert.match(CODE, /No detail was recorded for this source/);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 5. ⛔ `staleFindings` GETS ITS OWN CALLOUT.
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ stale findings are called out with their age and their count', () => {
  const stale = {
    ageDays: 49,
    findingCount: 22,
    neverCollected: true,
    detail: 'Rule analysis last ran 49 days ago, and rule collection has never succeeded. '
      + 'Its 22 findings are shown elsewhere with nothing marking them as that old.',
  };

  it('the callout is rendered whenever staleFindings is present', () => {
    assert.match(CODE, /entry\.staleFindings \? <StaleCallout/, 'nothing renders the stale callout');
    assert.match(CODE, /function StaleCallout\(/);
  });

  it('it prints the age and the finding count', () => {
    assert.equal(V.staleAgeLabel(stale), '49 days old');
    assert.equal(V.staleCountLabel(stale), '22 findings');
    assert.match(CODE, /staleAgeLabel\(stale\)/);
    assert.match(CODE, /staleCountLabel\(stale\)/);
  });

  it("⛔ the engine's own sentence wins over a rebuilt one", () => {
    assert.equal(V.staleSentence(stale), stale.detail);
    assert.match(CODE, /\{staleSentence\(stale\)\}/, 'the sentence is never rendered');
  });

  it('it says plainly that these findings appear elsewhere unmarked', () => {
    assert.match(V.staleSentence(stale), /nothing marking them as that old/i);
    assert.match(V.STALE_NOTE, /nothing marking them as old/i);
    assert.match(CODE, /\{STALE_NOTE\}/);
  });

  it('⛔ an unreadable age or count is SAID, never printed as zero', () => {
    // A 0-day-old analysis and an unreadable one are opposite statements.
    assert.equal(V.staleAgeLabel({ ageDays: null, findingCount: 3 }), null);
    assert.equal(V.staleCountLabel({ ageDays: 3, findingCount: null }), null);
    assert.equal(V.staleAgeLabel({ ageDays: '49' }), null, 'a string is not a measurement here');
    const s = V.staleSentence({ ageDays: null, findingCount: null });
    assert.match(s, /longer ago than SecVault can read/i);
    assert.equal(/\b0\b/.test(s), false, 'an unreadable value must never render as 0');
  });

  it('a genuine zero count is still a real measurement', () => {
    assert.equal(V.staleCountLabel({ findingCount: 0 }), '0 findings');
  });

  it('no stale findings produces nothing rather than an empty callout', () => {
    assert.equal(V.staleSentence(null), null);
    assert.equal(V.staleSentence(undefined), null);
    assert.equal(V.staleSentence('49 days'), null);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 6. ⛔ `failures` IS BANNERED. A SHORT REGISTER LOOKS COMPLETE.
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ an incomplete register says so, above the numbers it qualifies', () => {
  it('any failure at all fires the banner — no threshold, no "minor" case', () => {
    assert.equal(V.registerIsIncomplete(['syslog counts unavailable']), true);
    assert.equal(V.registerIsIncomplete([{ source: 'objects', error: 'timeout' }]), true);
    assert.equal(V.registerIsIncomplete({ objects: 'timeout' }), true);
    assert.equal(V.registerIsIncomplete('everything failed'), true);
  });

  it('only a genuine absence of failures is silent', () => {
    assert.equal(V.registerIsIncomplete([]), false);
    assert.equal(V.registerIsIncomplete(null), false);
    assert.equal(V.registerIsIncomplete(undefined), false);
  });

  it('⛔ a failures shape this file does not recognise STILL banners', () => {
    // Swallowing an unparseable failures value would render the short list
    // silently, which is the exact failure the banner exists to prevent.
    assert.equal(V.registerIsIncomplete(42), true);
    assert.deepEqual(V.failureList(42), ['42']);
    assert.equal(V.failureList([{ source: 'objects', error: 'timeout' }])[0], 'objects: timeout');
    assert.equal(V.failureList([{}])[0], 'a source: unknown error');
  });

  it('empty-ish members are dropped without emptying the list', () => {
    assert.deepEqual(V.failureList([null, '', 'real', undefined]), ['real']);
  });

  it('⛔ the banner is actually rendered by the component', () => {
    assert.match(CODE, /function FailuresBanner\(/, 'no banner component');
    assert.match(CODE, /<FailuresBanner failures=\{failures\} \/>/, 'the banner is never rendered');
    assert.match(CODE, /\{FAILURE_NOTE\}/, 'the banner never states what an incomplete register means');
  });

  it('⛔ the banner sits ABOVE the summary tiles', () => {
    // Underneath them it reads as a footnote to counts that already looked
    // complete.
    const banner = CODE.indexOf('<FailuresBanner');
    const tiles = CODE.indexOf('<StatCard');
    assert.notEqual(banner, -1);
    assert.notEqual(tiles, -1);
    assert.ok(banner < tiles, 'the incompleteness banner must precede the numbers it qualifies');
  });

  it('⛔ NO COUNT IS PRINTED while the register is incomplete', () => {
    // The data layer summarises whatever survived, so on a failure every total
    // is 0. "0 firewalls with a blind spot" beside a live fleet is the single
    // most dangerous thing this page can print, and its own docblock says no
    // caller may render a count while `failures` is non-empty.
    assert.equal(V.reportableCount(16, true), null, 'a count survived an incomplete register');
    assert.equal(V.reportableCount(0, true), null, 'a zero is the dangerous one');
    assert.equal(V.reportableCount(16, false), 16, 'a complete register still reports');
    assert.equal(V.reportableCount(0, false), 0, 'a complete register still reports a real zero');
    assert.equal(V.reportableCount(null, false), null);
    assert.match(V.INCOMPLETE_COUNT_REASON, /floor rather than a total/i);
  });

  it('⛔ every headline count routes through that refusal', () => {
    const tiles = CODE.match(/<StatCard[\s\S]{0,700}?\/>/g) || [];
    assert.ok(tiles.length >= 5, `expected the summary tiles, found ${tiles.length}`);
    for (const tile of tiles) {
      assert.match(
        tile,
        /value=\{statValue\(reportableCount\(/,
        `a tile prints a raw count: ${tile.slice(0, 80)}`
      );
    }
    assert.match(CODE, /const incomplete = registerIsIncomplete\(failures\)/);
  });

  it('the note says the counts are a floor, not a total', () => {
    assert.match(V.FAILURE_NOTE, /INCOMPLETE/);
    assert.match(V.FAILURE_NOTE, /has not been cleared/i);
    assert.match(V.FAILURE_NOTE, /floor/i);
  });

  it('⛔ an empty register with failures does not read as an empty fleet', () => {
    assert.match(CODE, /registerIsIncomplete\(failures\)/, 'the empty state ignores the failures');
    assert.match(CODE, /absence of assessment, not an absence of blind spots/i);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 7. ⛔ NO ALL-CLEAR. `fullyCovered` IS VISIBILITY, NOT SAFETY.
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ full coverage is never rendered as a security verdict', () => {
  it('the covered label is muted and factual', () => {
    assert.match(V.COVERED_LABEL, /visible/i);
    assert.equal(/\b(healthy|clean|secure|safe|ok|good|pass)\b/i.test(V.COVERED_LABEL), false);
  });

  it('the note beside it says what it does NOT mean', () => {
    assert.match(V.COVERED_NOTE, /statement about visibility/i);
    assert.match(V.COVERED_NOTE, /says nothing about/i);
    assert.match(CODE, /\{COVERED_NOTE\}/, 'the qualifier is declared and never shown');
  });

  it('⛔ no rendered string in the file claims an all-clear', () => {
    // Comments are stripped above: this file's own header DISCUSSES the
    // forbidden words in order to forbid them.
    for (const forbidden of [
      /\bhealthy\b/i,
      /\bclean(ly)?\b/i,
      /\bsecure\b/i,
      /\ball[-\s]clear\b/i,
      /\bno (issues|problems)\b/i,
      /\ball good\b/i,
      /\bfully assessed\b/i,
      /✓|✔|✅/,
    ]) {
      assert.equal(forbidden.test(CODE), false, `a rendered string matches ${forbidden}`);
    }
  });

  it('⛔ the covered state wears no hue anywhere in the rendered source', () => {
    const block = CODE.slice(CODE.indexOf('entry.fullyCovered ?'), CODE.indexOf('entry.staleFindings ?'));
    assert.ok(block.length > 0, 'the fullyCovered branch was not found');
    assert.equal(RAMP.test(block), false, 'the covered state wears a hue');
    assert.equal(HUED.test(block), false, 'the covered state wears a tint pair');
  });

  it('the claim at the top of the page says the same thing once more', () => {
    assert.match(V.REGISTER_CLAIM, /statement about evidence/i);
    assert.match(V.REGISTER_CLAIM, /nothing here is a verdict/i);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 8. ⛔ THE ENGINE'S RANKING SURVIVES THE VIEW.
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ entries render in the order the engine ranked them', () => {
  it('nothing in the file sorts anything', () => {
    // The engine ranks by CONSEQUENCE — answers withheld, stale ahead of a
    // heavier pure gap. Every firewall on the reference fleet has at least one
    // gap, so a register re-sorted by name or by gap COUNT is a list of the
    // fleet rather than a to-do list.
    assert.equal(/\.sort\(/.test(CODE), false, 'the view sorts, and the engine already ranked');
  });

  it('the entries prop is mapped straight through', () => {
    assert.match(CODE, /entries\.filter\(Boolean\)/, 'entries must survive as given');
    assert.match(CODE, /list\.map\(\(entry\) =>/, 'entries are not rendered in order');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 9. ⛔ A COUNT THAT DID NOT ARRIVE IS NOT A ZERO.
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ an unreadable summary count renders as NOT MEASURED', () => {
  it('countOf returns null for anything that is not a real number', () => {
    for (const junk of [null, undefined, '', '3', [], false, {}, NaN, Infinity]) {
      assert.equal(V.countOf({ devices: junk }, 'devices'), null, `${JSON.stringify(junk)} was read as a count`);
    }
    assert.equal(V.countOf({ devices: 0 }, 'devices'), 0, 'a real zero is a measurement');
    assert.equal(V.countOf({ devices: 16 }, 'devices'), 16);
  });

  it('a missing summary yields null, never zero', () => {
    for (const junk of [null, undefined, 'x', 42]) {
      assert.equal(V.countOf(junk, 'devices'), null);
    }
  });

  it('⛔ a null count is rendered through NotMeasured, with a reason', () => {
    assert.match(CODE, /function statValue\(/);
    assert.match(CODE, /n === null \? <NotMeasured reason=\{reason\} \/> : n/);
    for (const m of CODE.matchAll(/<NotMeasured\b([^>]*)>/g)) {
      assert.match(m[1], /reason=/, 'every NotMeasured must carry a reason');
    }
  });

  it('a per-source gap count that failed to travel is null, not zero', () => {
    const rows = V.gapRows({ gapsBySource: { syslog: 3, objects: null } }, [entry()]);
    assert.deepEqual(rows.map((r) => r.key), ['syslog', 'objects']);
    assert.equal(rows[0].devices, 3);
    assert.equal(rows[1].devices, null);
  });

  it('the source labels and gates are DERIVED from the entries, not copied', () => {
    // A second copy of the engine's labels would drift the first time one is
    // reworded, and the fleet table would then disagree with the per-firewall
    // rows on the same screen about what a source gates.
    const index = V.sourceIndex([entry()]);
    assert.equal(index.syslog.label, 'Syslog');
    assert.deepEqual(index.syslog.gates, ['log_hit (CVE priority rule 2)', 'traffic evidence']);
    const rows = V.gapRows({ gapsBySource: { syslog: 1 } }, [entry()]);
    assert.equal(rows[0].label, 'Syslog');
    assert.ok(rows[0].gates.length > 0);
  });

  it('an unknown source key falls back to the key rather than throwing', () => {
    const rows = V.gapRows({ gapsBySource: { brandNew: 2 } }, [entry()]);
    assert.equal(rows[0].label, 'brandNew');
    assert.deepEqual(rows[0].gates, []);
  });

  it('a missing gapsBySource produces no table rather than an empty one', () => {
    assert.deepEqual(V.gapRows(null, []), []);
    assert.deepEqual(V.gapRows({}, []), []);
    assert.deepEqual(V.gapRows({ gapsBySource: 'x' }, []), []);
  });

  it('⛔ a register with no timestamp says so rather than implying freshness', () => {
    assert.match(V.asOf('2026-09-25T02:00:00.000Z'), /^as of 2026-09-25 02:00 UTC$/);
    assert.match(V.asOf(null), /not recorded/i);
    assert.match(V.asOf('whenever'), /could not be read/i);
  });

  it('an age that did not travel prints nothing rather than "0 days"', () => {
    assert.equal(V.ageLabel(cell({ ageDays: null })), null);
    assert.equal(V.ageLabel(cell({ ageDays: 49 })), '49 days old');
    assert.equal(V.ageLabel(cell({ ageDays: 1 })), '1 day old');
    assert.equal(V.ageLabel(null), null);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 10. Design-system discipline.
// ────────────────────────────────────────────────────────────────────────────

describe('the view obeys the design system', () => {
  it('⛔ no hardcoded hex colour anywhere', () => {
    const hex = CODE.match(/#[0-9a-fA-F]{3,8}\b/g);
    assert.equal(hex, null, `hardcoded colour(s): ${hex && hex.join(', ')}`);
  });

  it('⛔ violet belongs to EvidenceMark and nothing else', () => {
    // The moment a second thing wears it the mark stops being learnable at a
    // glance and the operator has to read every one to find out what it does.
    assert.equal(/--evidence/.test(CODE), false, 'the evidence axis is not this component\'s to spend');
  });

  it('⛔ red is danger only, and never an interactive affordance', () => {
    // The one danger surface here is the incompleteness banner, which is a
    // statement that the register cannot be trusted — not a control.
    const danger = [...CODE.matchAll(/--tint-danger/g)];
    assert.ok(danger.length > 0, 'the failures banner should carry the danger tint');
    const banner = CODE.slice(CODE.indexOf('function FailuresBanner('), CODE.indexOf('export default function'));
    const outside = CODE.replace(banner, ' ');
    assert.equal(/--tint-danger|--red\b|--sev-crit/.test(outside), false, 'danger leaked outside the banner');
  });

  it('every tinted surface behind text pairs --tint-* with --tint-*-fg', () => {
    for (const tint of ['warn', 'danger']) {
      const bg = new RegExp(`var\\(--tint-${tint}\\)`);
      const fg = new RegExp(`var\\(--tint-${tint}-fg\\)`);
      if (bg.test(CODE)) assert.match(CODE, fg, `--tint-${tint} is used with no -fg partner`);
    }
  });

  it('every gap value comes from the spacing token scale', () => {
    const gaps = [...CODE.matchAll(/gap:\s*'([^']+)'/g)].map((m) => m[1]);
    assert.ok(gaps.length > 0, 'expected some spacing');
    for (const g of gaps) {
      assert.match(g, /^var\(--s\d\)$/, `gap "${g}" is outside the spacing scale`);
    }
  });

  it('padding, radius and type all resolve through tokens', () => {
    for (const m of CODE.matchAll(/padding:\s*'([^']+)'/g)) {
      assert.match(m[1], /^var\(--s\d\)(\s+var\(--s\d\))?$/, `padding "${m[1]}" is outside the scale`);
    }
    for (const m of CODE.matchAll(/borderRadius:\s*'([^']+)'/g)) {
      assert.match(m[1], /^var\(--radius(-sm|-lg|-pill)?\)$/, `radius "${m[1]}" is hardcoded`);
    }
    for (const m of CODE.matchAll(/fontSize:\s*'([^']+)'/g)) {
      assert.match(m[1], /^var\(--text-[a-z0-9]+\)$/, `font size "${m[1]}" is hardcoded`);
    }
  });

  it('⛔ uses the shared Table, so Settings → Appearance → Density still applies', () => {
    assert.match(SRC, /from '\.\.\/ui\/Table'/);
    assert.equal(
      /<td[^>]*padding:\s*['"]?\d/.test(CODE) || /<th[^>]*padding:\s*['"]?\d/.test(CODE),
      false,
      'a cell hardcodes padding and opts itself out of the density switch'
    );
  });

  it('percentage column widths come with a colgroup, which needs the fixed layout', () => {
    assert.match(CODE, /<colgroup>/);
    assert.equal(/<Table[^>]*layout="auto"/.test(CODE), false, 'percentage widths collapse under auto layout');
  });

  it('reuses the shared primitives rather than hand-rolling them', () => {
    for (const mod of ['Card', 'Table', 'StatCard', 'Disclosure', 'EmptyState', 'NotMeasured']) {
      assert.match(SRC, new RegExp(`from '\\.\\./ui/${mod}'`), `${mod} is not reused`);
    }
    assert.match(SRC, /from '\.\.\/icons'/, 'icons must come from the hand-rolled set');
  });

  it('stays a server component with no client boundary', () => {
    assert.equal(/^\s*'use client'/m.test(SRC), false, 'this register needs no client JS');
    assert.equal(/\buseState\(|\buseEffect\(|\buseMemo\(/.test(CODE), false, 'no hooks are used');
  });

  it('⛔ defines no component inside another component', () => {
    // A component declared inside a component remounts on every render.
    const sig = 'export default function CoverageRegister';
    const body = CODE.slice(CODE.indexOf(sig) + sig.length);
    assert.equal(
      /function\s+[A-Z]/.test(body),
      false,
      'a component is declared inside CoverageRegister and will remount on every render'
    );
  });

  it('takes its data purely as props, so any page can host it', () => {
    assert.match(
      SRC,
      /export default function CoverageRegister\(\{ entries, summary, failures, generatedAt \}\)/,
      'the frozen contract changed'
    );
    assert.equal(/require\(|from '\.\.\/\.\.\/lib\//.test(SRC), false, 'the view must not fetch its own data');
  });

  it('⛔ names no internal document in a rendered string', () => {
    assert.equal(/CLAUDE\.md/.test(CODE), false, 'the drawer footer rule: never name an internal file');
  });
});
