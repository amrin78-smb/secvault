'use strict';
// tests/consolidationTab.test.js
//
// Pins components/analysis/ConsolidationTab.js — the VIEW, not the engine.
// lib/engines/ruleConsolidation.js is pinned by tests/ruleConsolidation.test.js
// and its plumbing by tests/ruleConsolidationData.test.js. What is tested here
// is the handful of things only a renderer can get wrong.
//
// ⛔ THE FAILURE THIS FILE EXISTS TO PREVENT, and it has happened here before.
// SegmentationBoard.js was corrected in v2.122.0 for giving the SAFE-to-close
// verdict the full danger tint and the "cannot tell" verdict only a warning
// tint — the reverse of its own action order and the reverse of its own hover
// text. The rule "they must not share a colour" was satisfied to the letter
// while the LOUDER of the two was the wrong one. An engine that falls closed is
// worth nothing if the view then shouts the cleared verdict: the operator reads
// the loud thing and acts on it, whatever the label says.
//
// ⛔ AND THE SECOND: `safe_to_merge` IS STILL A PROPOSAL. It means "no
// intervening rule was found that could match the same traffic" — a statement
// about rule ORDER, with negation only partially detectable and zones
// deliberately unmodelled. A view that renders it as a licence turns a
// conservative engine into an instruction to change a firewall.
//
// Loading technique is the one tests/upgradePlanView.test.js and
// tests/designSystemRamp.test.js already use: `npm test` is `node --test` with
// no "type":"module", so an ESM component cannot be require()d. The
// declarations pinned below are plain consts and plain functions whose bodies
// touch no imported identifier, so stripping the import block and evaluating is
// exact, not an approximation.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');
const read = (...parts) => fs.readFileSync(path.join(REPO, ...parts), 'utf8');

const VIEW_PATH = ['components', 'analysis', 'ConsolidationTab.js'];
const SRC = read(...VIEW_PATH);
const PAGE = read('app', '(dashboard)', 'devices', '[id]', 'analysis', 'page.js');

const ENGINE = require('../lib/engines/ruleConsolidation');
const DATA = require('../lib/engines/ruleConsolidationData');

// ⛔ COMMENTS ARE STRIPPED FIRST, EVERYWHERE THIS FILE SCANS SOURCE. Several
// comments in that file deliberately QUOTE the wording they exist to forbid
// ("safe to merge", "Safe"), and a scan that read them would fail on the very
// documentation that prevents the bug. This repo has had a source scan
// satisfied by the comment explaining the thing it hunts more than once.
function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1 ');
}

const CODE = stripComments(SRC);

// Everything above the first JSX-bearing component is pure and evaluable.
function loadView() {
  const declarations = SRC
    .split('\n')
    .filter((line) => !/^\s*import\s/.test(line))
    .join('\n')
    .replace(/\bexport\s+(const|function)\b/g, '$1');

  const cut = declarations.indexOf('function VerdictChip(');
  assert.notEqual(cut, -1, 'expected VerdictChip to mark the start of the JSX half');
  const pure = declarations.slice(0, cut);

  const names = [
    'VERDICT_WEIGHT',
    'verdictWeight',
    'EMPTY_STATE',
    'emptyState',
    'headlineFigures',
    'orderGroups',
    'UNDETERMINED_REASON',
    'undeterminedReason',
    'groupCaveats',
    'objectCaveat',
    'unplaceableCaveat',
    'mergedValueText',
    'MAX_MERGED_VALUES',
  ];
  // eslint-disable-next-line no-new-func
  return new Function(`${pure}\nreturn { ${names.join(', ')} };`)();
}

const V = loadView();

const group = (over = {}) => ({
  deviceId: 'dev-1',
  vdom: null,
  varyingField: 'dst_addresses',
  varyingFieldLabel: 'destination',
  verdict: ENGINE.VERDICTS.SAFE,
  rules: [
    { id: 'a', label: 'rule-a', sequenceNumber: 1 },
    { id: 'b', label: 'rule-b', sequenceNumber: 3 },
  ],
  ruleIds: ['a', 'b'],
  size: 2,
  removableRows: 1,
  distinctNames: ['rule-a', 'rule-b'],
  losesDistinctComments: false,
  mergedValue: ['10.2.2.0/24', '10.3.3.0/24'],
  sequenceSpan: 2,
  adjacent: false,
  mergePosition: 1,
  examined: 1,
  interfering: [],
  undetermined: [],
  ...over,
});

// ══════════════════════════════════════════════════════════════════════════
// 1. ⛔ THE TWO VERDICTS ARE DIFFERENT KINDS OF THING, AND REVIEW IS LOUDER
// ══════════════════════════════════════════════════════════════════════════

describe('⛔ needs_review and safe_to_merge cannot look alike, and review is the loud one', () => {
  const review = V.VERDICT_WEIGHT.needs_review;
  const checked = V.VERDICT_WEIGHT.safe_to_merge;

  it('the weight table names exactly the engine\'s verdicts — no more, no fewer', () => {
    assert.deepEqual(
      Object.keys(V.VERDICT_WEIGHT).sort(),
      Object.values(ENGINE.VERDICTS).sort(),
      'a verdict with no weight would render with the fallback, silently'
    );
  });

  it('⛔ needs_review outranks safe_to_merge — rank IS the reading order', () => {
    assert.ok(
      review.rank < checked.rank,
      `needs_review rank ${review.rank} must come before ${checked.rank}`
    );
  });

  it('⛔ they share no colour — background, foreground and border all differ', () => {
    assert.notEqual(review.background, checked.background);
    assert.notEqual(review.foreground, checked.foreground);
    assert.notEqual(review.border, checked.border);
  });

  it('⛔ they share no WEIGHT either — review is heavier and larger', () => {
    assert.ok(
      review.titleWeight > checked.titleWeight,
      'equal type weight is the same failure as an equal colour'
    );
    assert.notEqual(review.titleSize, checked.titleSize);
    // The border carries the loudness too: solid and thicker against dashed.
    assert.match(review.border, /\bsolid\b/);
    assert.match(checked.border, /\bdashed\b/);
  });

  it('⛔ every tinted surface carries its own -fg pair, never a bare hue', () => {
    for (const [name, w] of Object.entries(V.VERDICT_WEIGHT)) {
      assert.match(w.background, /^var\(--tint-[a-z]+\)$/, `${name} background is not a tint token`);
      assert.equal(
        w.foreground,
        w.background.replace(/\)$/, '-fg)'),
        `${name} must pair --tint-x with --tint-x-fg, or its text flips out from under it in dark mode`
      );
    }
  });

  it('⛔ neither verdict wears red, green, a severity hue, or the evidence violet', () => {
    // Red is danger (a security exposure) and green is an all-clear; a
    // consolidation candidate is neither. Violet is the EVIDENCE axis and
    // belongs to EvidenceMark alone — the moment a second thing uses it the
    // mark stops being learnable at a glance.
    for (const [name, w] of Object.entries(V.VERDICT_WEIGHT)) {
      const blob = JSON.stringify(w);
      assert.equal(/--red|--green|--sev-/.test(blob), false, `${name} borrows a severity hue`);
      assert.equal(/--evidence|--purple/.test(blob), false, `${name} borrows the evidence violet`);
      assert.equal(/#[0-9a-fA-F]{3,8}\b/.test(blob), false, `${name} hardcodes a hex colour`);
    }
  });

  it('⛔ the CLEARED verdict is never labelled "safe"', () => {
    // The engine's slug says safe_to_merge; the thing an operator READS must
    // not, because the sentence they finish in their head after it is
    // "…to merge".
    assert.equal(/safe/i.test(checked.label), false, `label "${checked.label}" says safe`);
    assert.equal(/safe/i.test(checked.help), false, 'the hover text must not either');
    assert.match(checked.help, /not a licence/i, 'it must say what it is NOT');
  });

  it('⛔ an unrecognised verdict falls to the LOUDER weight, never the quieter one', () => {
    for (const junk of ['', 'nope', undefined, null, 0, 'safe', 'SAFE_TO_MERGE']) {
      assert.equal(
        V.verdictWeight(junk).label,
        review.label,
        `verdictWeight(${JSON.stringify(junk)}) must fall to the review weight`
      );
    }
    assert.equal(V.verdictWeight(ENGINE.VERDICTS.SAFE).label, checked.label);
    assert.equal(V.verdictWeight(ENGINE.VERDICTS.REVIEW).label, review.label);
  });

  it('⛔ every declared field is actually RENDERED — a weight table nothing reads is a dead guard', () => {
    const chip = CODE.slice(CODE.indexOf('function VerdictChip('));
    const body = chip.slice(0, chip.indexOf('\nfunction '));
    for (const field of ['background', 'foreground', 'border', 'titleWeight', 'titleSize', 'label', 'help']) {
      assert.ok(body.includes(`w.${field}`), `VerdictChip never reads ${field}`);
    }
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 2. ⛔ THE LIST ORDER FOLLOWS THE SAME RANK THE COLOUR COMES FROM
// ══════════════════════════════════════════════════════════════════════════

describe('⛔ reading order and visual loudness are derived from ONE rank', () => {
  it('every needs_review group is listed before every safe_to_merge one', () => {
    const groups = [
      group({ verdict: ENGINE.VERDICTS.SAFE, removableRows: 40 }),
      group({ verdict: ENGINE.VERDICTS.REVIEW, removableRows: 1 }),
      group({ verdict: ENGINE.VERDICTS.SAFE, removableRows: 9 }),
      group({ verdict: ENGINE.VERDICTS.REVIEW, removableRows: 2 }),
    ];
    const verdicts = V.orderGroups(groups).map((g) => g.verdict);
    assert.deepEqual(verdicts, [
      ENGINE.VERDICTS.REVIEW,
      ENGINE.VERDICTS.REVIEW,
      ENGINE.VERDICTS.SAFE,
      ENGINE.VERDICTS.SAFE,
    ], 'a big cleared group must not outrank a small one needing review');
  });

  it('within one verdict, more candidate rows come first', () => {
    const ordered = V.orderGroups([
      group({ verdict: ENGINE.VERDICTS.REVIEW, removableRows: 1 }),
      group({ verdict: ENGINE.VERDICTS.REVIEW, removableRows: 7 }),
    ]);
    assert.equal(ordered[0].removableRows, 7);
  });

  it('an unreadable verdict sorts with the loud pile, matching the weight it gets', () => {
    const ordered = V.orderGroups([
      group({ verdict: ENGINE.VERDICTS.SAFE }),
      group({ verdict: 'something_new', removableRows: 1 }),
    ]);
    assert.equal(ordered[0].verdict, 'something_new');
  });

  it('does not mutate its input and survives a non-array', () => {
    const input = [group({ verdict: ENGINE.VERDICTS.SAFE }), group({ verdict: ENGINE.VERDICTS.REVIEW })];
    const copy = [...input];
    V.orderGroups(input);
    assert.deepEqual(input, copy);
    assert.deepEqual(V.orderGroups(null), []);
    assert.deepEqual(V.orderGroups(undefined), []);
  });

  it('⛔ the rendered list is the ORDERED one, not the engine order', () => {
    assert.match(CODE, /orderGroups\(result\.groups\)/);
    assert.match(CODE, /paginateArray\(\s*ordered/);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 3. ⛔ MERGE_CLAIM IS RENDERED, NOT REWRITTEN
// ══════════════════════════════════════════════════════════════════════════

describe('⛔ the one claim is imported and rendered verbatim', () => {
  it('it is imported from the engine', () => {
    assert.match(SRC, /import \{ MERGE_CLAIM \} from '\.\.\/\.\.\/lib\/engines\/ruleConsolidation'/);
  });

  it('it is rendered, as the constant', () => {
    assert.match(CODE, /\{MERGE_CLAIM\}/, 'the constant must reach the DOM');
  });

  it('⛔ the sentence is NOT duplicated as a literal anywhere in the view', () => {
    // A copy drifts, and the copy is the one on screen. Several distinctive
    // fragments, so a partial paraphrase is caught too.
    for (const fragment of [
      'identical except in one field, and no enabled rule',
      'not a verified-safe change',
      'the traffic a merge would move. Merging them is',
    ]) {
      assert.equal(
        SRC.includes(fragment),
        false,
        `the view restates the engine's claim: "${fragment}"`
      );
    }
    assert.ok(ENGINE.MERGE_CLAIM.includes('identical except in one field, and no enabled rule'));
  });

  it('⛔ it is NOT behind a disclosure — a reader who expands nothing must meet it', () => {
    const disclosure = CODE.slice(CODE.indexOf('<Disclosure'));
    assert.ok(disclosure.length > 0, 'expected a Disclosure in this file');
    assert.equal(
      disclosure.includes('MERGE_CLAIM'),
      false,
      'a load-bearing claim may not live inside a collapsed block'
    );
  });

  it('the view says in its own words that it proposes rather than acts', () => {
    assert.match(CODE, /proposal/i);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 4. ⛔ FORBIDDEN VOCABULARY, AND NO WRITE PATH AT ALL
// ══════════════════════════════════════════════════════════════════════════

describe('⛔ nothing on this screen promises safety or offers to act', () => {
  it('no rendered string claims a verified, riskless or automatic change', () => {
    for (const forbidden of [
      /verified[\s-]safe/i,
      /\bsafe to\b/i,
      /\bis safe\b/i,
      /\bno risk\b/i,
      /\bguarantee/i,
      /\bautomatically\b/i,
      /one[-\s]click/i,
      /\bwill not break\b/i,
      /\bsafely\b/i,
    ]) {
      assert.equal(forbidden.test(CODE), false, `a rendered string matches ${forbidden}`);
    }
  });

  it('⛔ there is NO form, NO button and NO write path — deliberately nothing to press', () => {
    // An apply control here would turn a partially-detectable negation into a
    // silent policy change on a live firewall.
    for (const forbidden of [
      /<form\b/i,
      /<button\b/i,
      /onClick=/,
      /onSubmit=/,
      /\bfetch\(/,
      /method=["']POST/i,
      /'use client'/,
      /useState|useEffect/,
    ]) {
      assert.equal(forbidden.test(CODE), false, `the view carries a write path: ${forbidden}`);
    }
  });

  it('⛔ no hardcoded hex colour anywhere', () => {
    assert.equal(
      /#[0-9a-fA-F]{3,8}\b/.test(CODE),
      false,
      'colour must come from a token, never a literal'
    );
  });

  it('⛔ the evidence violet is untouched — it belongs to EvidenceMark alone', () => {
    assert.equal(/--evidence/.test(CODE), false);
    assert.equal(/EvidenceMark/.test(CODE), false);
  });

  it('⛔ row geometry comes from the density tokens, never a hardcoded padding or size', () => {
    assert.equal(/padding:\s*['"]?\d/.test(CODE), false, 'a cell hardcoding padding opts itself out of the density switch');
    assert.equal(/fontSize:\s*['"]\d/.test(CODE), false);
  });

  it('the table is the shared one, so tableLayout:fixed is enforced for its colgroup', () => {
    assert.match(SRC, /import Table from '\.\.\/ui\/Table'/);
    assert.match(CODE, /<colgroup>/);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 5. ⛔ `undetermined` IS VISIBLE, WITH ITS COUNT
// ══════════════════════════════════════════════════════════════════════════

describe('⛔ a group says WHY it needs review', () => {
  it('groupCaveats counts undetermined checks and groups them by reason', () => {
    const c = V.groupCaveats(
      group({
        verdict: ENGINE.VERDICTS.REVIEW,
        undetermined: [
          { reason: 'overlap_could_not_be_determined', rule: { label: 'x' } },
          { reason: 'overlap_could_not_be_determined', rule: { label: 'y' } },
          { reason: 'member_has_no_sequence_number', rule: { label: 'z' } },
        ],
      })
    );
    assert.equal(c.undeterminedCount, 3);
    assert.equal(c.reasons.length, 2);
    assert.equal(c.reasons.find((r) => r.reason === 'overlap_could_not_be_determined').count, 2);
  });

  it('interference and undetermined are counted APART, never merged into one number', () => {
    // "A rule between them matches" and "we could not tell whether one does"
    // send an operator to different places — the engine keeps them apart and so
    // must the view.
    const c = V.groupCaveats(
      group({
        interfering: [{ rule: { label: 'deny-all' } }],
        undetermined: [{ reason: 'overlap_could_not_be_determined' }],
      })
    );
    assert.equal(c.interferingCount, 1);
    assert.equal(c.undeterminedCount, 1);
    assert.deepEqual(c.interferingRules, ['deny-all']);
  });

  it('⛔ an UNRECOGNISED reason slug is named on screen, never dropped or made generic', () => {
    const text = V.undeterminedReason('a_reason_added_later');
    assert.match(text, /a_reason_added_later/, 'the slug itself must survive to the reader');
    assert.match(text, /does not recognise/i);
    // A missing reason is still a reason to say something.
    assert.match(V.undeterminedReason(undefined), /no reason/i);
  });

  it('every engine reason slug has wording of its own', () => {
    for (const slug of [
      'member_has_no_sequence_number',
      'intervening_rule_has_no_sequence_number',
      'overlap_could_not_be_determined',
    ]) {
      assert.ok(V.UNDETERMINED_REASON[slug], `${slug} has no wording`);
      assert.equal(V.undeterminedReason(slug), V.UNDETERMINED_REASON[slug]);
    }
  });

  it('⛔ the count reaches the screen through NotMeasured, not a tooltip', () => {
    const checks = CODE.slice(CODE.indexOf('function GroupChecks('));
    const body = checks.slice(0, checks.indexOf('\nfunction GroupRow('));
    assert.ok(body.includes('undeterminedCount'), 'GroupChecks never renders the undetermined count');
    assert.ok(body.includes('<NotMeasured'), 'an undetermined check must be drawn hueless');
    assert.ok(body.includes('r.text'), 'the per-reason wording must render too');
  });

  it('⛔ every NotMeasured in the file carries a reason', () => {
    for (const m of SRC.matchAll(/<NotMeasured\b([\s\S]*?)\/>/g)) {
      assert.match(m[1], /reason=/, 'a bare em-dash with no tooltip hides the gap it exists to announce');
    }
  });

  it('a cleared group still states what was checked rather than saying nothing', () => {
    const c = V.groupCaveats(group({ adjacent: true, examined: 0 }));
    assert.equal(c.interferingCount, 0);
    assert.equal(c.undeterminedCount, 0);
    assert.equal(c.adjacent, true);
    assert.equal(c.examined, 0);
  });

  it('a malformed group produces zeros rather than a crash', () => {
    const c = V.groupCaveats(null);
    assert.equal(c.interferingCount, 0);
    assert.equal(c.undeterminedCount, 0);
    assert.equal(c.examined, null);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 6. ⛔ THE TWO ROW COUNTS ARE REPORTED SEPARATELY AND NEVER BLENDED
// ══════════════════════════════════════════════════════════════════════════

describe('⛔ checked and unchecked candidate rows never merge into one headline', () => {
  const figures = (over) =>
    V.headlineFigures({
      groups: 3,
      safeRemovableRows: 5,
      needsReviewRemovableRows: 7,
      // ⛔ DELIBERATELY NOT 12. If any figure were computed as safe + review
      // this test would read 12 here and fail.
      removableRows: 99,
      undeterminedGroups: 2,
      ...over,
    });

  it('the total is READ from the engine, never recomputed by adding the two parts', () => {
    const f = figures();
    const by = (k) => f.find((x) => x.key === k).value;
    assert.equal(by('safeRemovableRows'), 5);
    assert.equal(by('needsReviewRemovableRows'), 7);
    assert.equal(by('removableRows'), 99, 'the total was derived, not read');
  });

  it('they are three separate tiles with three distinct labels', () => {
    const f = figures();
    const keys = f.map((x) => x.key);
    assert.ok(keys.includes('safeRemovableRows'));
    assert.ok(keys.includes('removableRows'));
    assert.ok(keys.includes('needsReviewRemovableRows'));
    const labels = f.map((x) => x.label);
    assert.equal(new Set(labels).size, labels.length, 'two tiles sharing a label read as one number');
  });

  it('⛔ the source never adds the two counts together', () => {
    for (const forbidden of [
      /safeRemovableRows\s*\+/,
      /\+\s*(s\.)?safeRemovableRows/,
      /needsReviewRemovableRows\s*\+/,
      /\+\s*(s\.)?needsReviewRemovableRows/,
    ]) {
      assert.equal(forbidden.test(CODE), false, `a blended figure is built here: ${forbidden}`);
    }
  });

  it('⛔ the total tile says what it is NOT, so it cannot be read as an outcome', () => {
    const total = figures().find((x) => x.key === 'removableRows');
    assert.match(total.note, /never an outcome|not an? achievable/i);
  });

  it('⛔ a MISSING figure is null, never 0 — rendered as not measured', () => {
    const f = V.headlineFigures({});
    for (const entry of f) {
      assert.strictEqual(entry.value, null, `${entry.key} defaulted to a number nobody measured`);
    }
    assert.deepEqual(V.headlineFigures(null).map((x) => x.value), [null, null, null, null, null]);
    assert.strictEqual(figures({ safeRemovableRows: undefined })[1].value, null);
    // A real zero survives as a zero.
    assert.strictEqual(figures({ safeRemovableRows: 0 })[1].value, 0);
  });

  it('the undetermined tile is drawn hueless, not as a severity', () => {
    const undet = figures().find((x) => x.key === 'undeterminedGroups');
    assert.equal(undet.unmeasured, true);
    const grid = CODE.slice(CODE.indexOf('function FigureGrid('));
    assert.match(grid.slice(0, grid.indexOf('\nfunction ')), /var\(--unmeasured\)/);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 7. ⛔ THREE EMPTY SCREENS, NOT ONE
// ══════════════════════════════════════════════════════════════════════════

describe('⛔ a failed read, an uncollected ruleset and a tidy firewall look different', () => {
  it('a failed read is decided FIRST, before any coverage field is consulted', () => {
    // On a failure every coverage field is null, and `null !== true` would
    // otherwise report a broken query as an uncollected ruleset.
    assert.equal(
      V.emptyState({ ok: false, coverage: { rulesCollected: true } }),
      V.EMPTY_STATE.UNREADABLE
    );
    assert.equal(V.emptyState({ ok: false, coverage: null }), V.EMPTY_STATE.UNREADABLE);
    assert.equal(V.emptyState(null), V.EMPTY_STATE.UNREADABLE);
    assert.equal(V.emptyState({}), V.EMPTY_STATE.UNREADABLE);
  });

  it('an uncollected ruleset is its own state', () => {
    assert.equal(
      V.emptyState({ ok: true, coverage: { rulesCollected: false } }),
      V.EMPTY_STATE.NOT_COLLECTED
    );
  });

  it('only a collected, genuinely tidy firewall reports "no candidates"', () => {
    assert.equal(
      V.emptyState({ ok: true, coverage: { rulesCollected: true } }),
      V.EMPTY_STATE.NO_CANDIDATES
    );
  });

  it('the three states are three distinct strings', () => {
    const values = Object.values(V.EMPTY_STATE);
    assert.equal(new Set(values).size, 3);
  });

  it('⛔ the component returns the failure panel BEFORE it ever reads `groups`', () => {
    const guard = CODE.indexOf('if (!result.ok)');
    const use = CODE.indexOf('orderGroups(result.groups)');
    assert.notEqual(guard, -1, 'no ok guard in the component');
    assert.notEqual(use, -1);
    assert.ok(guard < use, 'a failed read must never reach the table or the figures');
  });

  it('⛔ the failure panel says a blank screen is not the same as no candidates', () => {
    const panel = CODE.slice(CODE.indexOf('function ReadFailurePanel('));
    const body = panel.slice(0, panel.indexOf('\nfunction '));
    assert.match(body, /could not be read/i);
    assert.match(body, /not the same as/i);
    assert.match(body, /<NotMeasured/);
  });

  it('⛔ the uncollected panel says a firewall with no rules is not a clean one', () => {
    const panel = CODE.slice(CODE.indexOf('function NoCandidatesPanel('));
    const body = panel.slice(0, panel.indexOf('\nfunction '));
    assert.match(body, /No ruleset has been collected/i);
    assert.match(body, /tidiest device on the fleet|not a result/i);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 8. Coverage caveats
// ══════════════════════════════════════════════════════════════════════════

describe('⛔ what limited the check is stated above the table, not discovered in it', () => {
  it('the caveat distinguishes an unread catalogue from an empty one', () => {
    const unread = V.objectCaveat({ objectCoverage: 'unreadable', objectError: 'boom' });
    const none = V.objectCaveat({ objectCoverage: 'none_collected' });
    assert.ok(unread && none);
    assert.notEqual(unread.text, none.text, 'two different facts must not share a sentence');
    assert.match(unread.text, /could not be read/i);
    assert.match(none.text, /have been collected|no address/i);
    assert.equal(unread.detail, 'boom');
  });

  it('both are drawn hueless — this is a gap, not a severity', () => {
    assert.equal(V.objectCaveat({ objectCoverage: 'unreadable' }).unmeasured, true);
    assert.equal(V.objectCaveat({ objectCoverage: 'none_collected' }).unmeasured, true);
  });

  it('⛔ the caveat slugs are the data layer\'s own, so they cannot drift apart', () => {
    assert.ok(V.objectCaveat({ objectCoverage: DATA.OBJECT_COVERAGE.UNREADABLE }));
    assert.ok(V.objectCaveat({ objectCoverage: DATA.OBJECT_COVERAGE.NONE }));
    assert.equal(V.objectCaveat({ objectCoverage: DATA.OBJECT_COVERAGE.AVAILABLE }), null);
    assert.equal(V.objectCaveat(null), null);
  });

  it('⛔ an unplaceable rule is reported, and a zero says nothing', () => {
    const one = V.unplaceableCaveat({ rulesWithoutSequence: 1 });
    assert.match(one.text, /1 enabled rule\b/);
    assert.match(one.text, /carries no/);
    assert.match(V.unplaceableCaveat({ rulesWithoutSequence: 4 }).text, /4 enabled rules\b/);
    assert.match(V.unplaceableCaveat({ rulesWithoutSequence: 4 }).text, /\bcarry no\b/);
    assert.equal(V.unplaceableCaveat({ rulesWithoutSequence: 0 }), null);
    assert.equal(V.unplaceableCaveat({}), null);
    assert.equal(V.unplaceableCaveat(null), null);
  });

  it('both caveats render above the table, never after it', () => {
    const caveat = CODE.indexOf('<CaveatLine caveat={objectCaveat(coverage)}');
    const table = CODE.indexOf('<Table>');
    assert.notEqual(caveat, -1);
    assert.ok(caveat < table, 'a limit discovered after the numbers is a limit nobody read');
  });
});

// ══════════════════════════════════════════════════════════════════════════
// 9. Value truncation, and the tab's registration
// ══════════════════════════════════════════════════════════════════════════

describe('the merged value is truncated visibly, never silently', () => {
  it('a short list renders whole', () => {
    const m = V.mergedValueText(group({ mergedValue: ['a', 'b'] }));
    assert.equal(m.shown, 'a, b');
    assert.equal(m.full, 'a, b');
  });

  it('a long list SAYS how many it is not showing, and keeps the full list for the tooltip', () => {
    const values = Array.from({ length: V.MAX_MERGED_VALUES + 5 }, (_, i) => `v${i}`);
    const m = V.mergedValueText(group({ mergedValue: values }));
    assert.match(m.shown, /\+5 more$/, 'a truncated list that looks complete is the worse failure');
    assert.equal(m.full, values.join(', '));
  });

  it('an empty or missing value is an em-dash, not a crash', () => {
    assert.equal(V.mergedValueText(group({ mergedValue: [] })).shown, '—');
    assert.equal(V.mergedValueText(group({ mergedValue: null })).shown, '—');
    assert.equal(V.mergedValueText(null).shown, '—');
  });
});

describe('the tab is registered on the analysis page', () => {
  it('the component is imported, the slug is accepted, and the tab link exists', () => {
    assert.match(PAGE, /import ConsolidationTab from/);
    assert.match(PAGE, /'consolidation',/);
    assert.match(PAGE, /tabLink\(device\.id, tab, 'consolidation'/);
    assert.match(PAGE, /tab === 'consolidation' &&/);
  });

  it('⛔ searchParams is passed — a paginated tab without it pages forever on page 1', () => {
    const block = PAGE.slice(PAGE.indexOf("tab === 'consolidation' &&"));
    assert.match(block.slice(0, 300), /searchParams=\{searchParams\}/);
  });

  it('⛔ the page keeps force-dynamic — this tab queries the database on every render', () => {
    assert.match(PAGE, /export const dynamic = 'force-dynamic'/);
  });

  it('⛔ no canWrite is passed, because there is nothing to gate', () => {
    const block = PAGE.slice(PAGE.indexOf("tab === 'consolidation' &&"));
    assert.equal(
      /canWrite/.test(block.slice(0, 300)),
      false,
      'a capability prop on a read-only tab invites a control that should not exist'
    );
  });

  it('pagination re-asserts its own tab, so a page link cannot navigate away', () => {
    assert.match(CODE, /tab:\s*'consolidation'/);
  });
});
