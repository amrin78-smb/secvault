'use strict';
// tests/upgradePlanView.test.js
//
// Pins components/vulnerability/UpgradePlan.js — the VIEW, not the engine.
// lib/engines/upgradePlan.js is pinned separately; what is tested here is the
// one thing only the view can get wrong.
//
// ⛔ THE FAILURE THIS FILE EXISTS TO PREVENT. The engine deliberately refuses
// to recommend a branch move even when it clears more — three live FortiGates
// on 7.4.9 where 7.4.12 clears three (including their KEV) and 7.6.7 clears
// five more. That refusal is worth nothing if the view then draws both options
// with the same weight in one ranked list: an operator reads the bigger number
// and acts on it, whatever the label above it says. The recommendation and the
// offer must therefore be visibly different KINDS of thing, and that is
// asserted here rather than left to a code review.
//
// ⛔ AND THE SECOND: `unplannable` must be rendered whenever it is non-zero.
// 27 assessments fleet-wide carry no recorded fix version. A plan that
// silently omits what it could not plan looks COMPLETE, which is the exact
// failed-read-as-a-fact shape this codebase names most often — here wearing a
// project-management hat.
//
// Loading technique is the one tests/designSystemRamp.test.js already uses:
// `npm test` is `node --test` with no "type":"module", so an ESM component
// cannot be require()d. The declarations pinned below are plain consts and
// plain functions with no imported identifiers in their bodies, so stripping
// the `export` keyword and evaluating is exact, not an approximation.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');
const read = (...parts) => fs.readFileSync(path.join(REPO, ...parts), 'utf8');

const VIEW_PATH = ['components', 'vulnerability', 'UpgradePlan.js'];
const SRC = read(...VIEW_PATH);
const PAGE = read('app', '(dashboard)', 'vulnerability', 'page.js');

// Everything the view exports that is pure enough to evaluate.
function loadView() {
  // Imports cannot survive into a Function body; nothing evaluated below
  // touches one. The import block is dropped, every `export` keyword removed,
  // and the JSX (which starts at the first component) is never reached because
  // only the declarations named here are returned.
  const declarations = SRC
    .split('\n')
    .filter((line) => !/^\s*import\s/.test(line))
    .join('\n')
    .replace(/\bexport\s+(const|function)\b/g, '$1');

  // Cut the file at the first JSX-bearing component: everything the test needs
  // is declared above it, and `new Function` cannot parse JSX.
  const cut = declarations.indexOf('function OptionPanel(');
  assert.notEqual(cut, -1, 'expected OptionPanel to mark the start of the JSX half');
  const pure = declarations.slice(0, cut);

  const names = [
    'CLEARS_CLAIM',
    'CROSS_BRANCH_CAVEAT',
    'UNPLANNABLE_NOTE',
    'COVERAGE_STATE',
    'UNCOVERED_REASON',
    'OPTION_WEIGHT',
    'optionWeight',
    'unplannableCountOf',
    'showsUnplannable',
    'clearsSentence',
    'crossBranchOffer',
    'noPlanReason',
    'uncoveredReason',
    'partitionPlans',
    'coverageIsComplete',
    'assessedAsOf',
  ];
  // eslint-disable-next-line no-new-func
  return new Function(`${pure}\nreturn { ${names.join(', ')} };`)();
}

const V = loadView();

// ── fixtures ────────────────────────────────────────────────────────────────

const inBranchOption = { target: '7.4.12', clears: 3, kevCleared: 1, patchNowCleared: 1 };
const crossOption = { branch: '7.6', target: '7.6.7', clears: 8, kevCleared: 1 };

function plan(over) {
  return {
    deviceId: 'd1',
    deviceName: 'FW-BRANCH-01',
    vendor: 'fortinet',
    coverage: 'assessed',
    lastAssessedAt: '2026-09-24T02:00:00.000Z',
    runningVersion: '7.4.9',
    currentBranch: '7.4',
    openCount: 27,
    kevOpen: 1,
    inBranch: inBranchOption,
    crossBranch: [crossOption],
    recommendation: 'in_branch',
    crossBranchWouldAdd: 5,
    remainingAfterRecommended: 24,
    unplannableCount: 0,
    unplannable: [],
    ...over,
  };
}

// ────────────────────────────────────────────────────────────────────────────
// 1. ⛔ A BRANCH JUMP IS NOT A PATCH — the two options cannot look alike.
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ the recommendation and the branch-move offer are different kinds of thing', () => {
  const rec = V.OPTION_WEIGHT.in_branch;
  const offer = V.OPTION_WEIGHT.cross_branch;

  it('both weights exist and name themselves differently', () => {
    assert.ok(rec, 'in_branch weight missing');
    assert.ok(offer, 'cross_branch weight missing');
    assert.notEqual(
      rec.kind,
      offer.kind,
      'a recommendation and an offer that share a kind will end up sharing a style'
    );
    assert.equal(rec.kind, 'recommended');
    assert.equal(offer.kind, 'offer');
  });

  it('the recommendation outranks the offer in reading order', () => {
    // Rank is the eye's order. Equal ranks are two rows of one ranked list,
    // which is precisely the presentation the engine's refusal exists to avoid.
    assert.ok(
      rec.rank < offer.rank,
      `in-branch rank ${rec.rank} must be louder than cross-branch rank ${offer.rank}`
    );
  });

  it('⛔ they cannot share a border — the offer is dashed, the recommendation solid', () => {
    assert.notEqual(rec.border, offer.border, 'the two options share a border style');
    assert.match(rec.border, /\bsolid\b/, 'the recommendation must read as a solid, committed panel');
    assert.match(offer.border, /\bdashed\b/, 'the branch move must read as provisional');
  });

  it('⛔ the brand accent belongs to the recommendation ALONE', () => {
    // --primary is the product's one "do this" hue. Spending it on a platform
    // migration makes the two options read as equals.
    assert.match(rec.border, /var\(--primary\)/);
    assert.match(rec.labelColor, /var\(--primary\)/);
    assert.equal(
      /--primary/.test(offer.border) || /--primary/.test(offer.labelColor),
      false,
      'the branch-move offer must not wear the brand accent'
    );
  });

  it('the offer is quieter in type as well as in border', () => {
    assert.ok(
      rec.titleWeight > offer.titleWeight,
      'the recommendation must carry more typographic weight than the offer'
    );
    assert.notEqual(rec.titleSize, offer.titleSize, 'same title size = same visual weight');
    assert.notEqual(rec.background, offer.background);
  });

  it('⛔ neither option borrows a colour from the SEVERITY RAMP', () => {
    // An upgrade option is not a severity. Ranking two kinds of change on a
    // scale that measures neither is a claim SecVault has not earned — the
    // same call components/analysis/severityRamp.js makes for `attention`.
    for (const [name, weight] of Object.entries(V.OPTION_WEIGHT)) {
      const blob = JSON.stringify(weight);
      assert.equal(/--sev-/.test(blob), false, `${name} uses a severity hue`);
      assert.equal(/--red|--orange|--yellow|--green/.test(blob), false, `${name} uses a raw ramp hue`);
    }
  });

  it('⛔ an UNRECOGNISED kind falls to the QUIETER weight, never the louder one', () => {
    // The asymmetry is the whole point: an unknown shape drawn as an offer is
    // merely under-sold; drawn as a recommendation it is an instruction
    // derived from something we could not read.
    for (const junk of ['', 'nope', undefined, null, 'recommended', 0]) {
      assert.equal(
        V.optionWeight(junk).kind,
        'offer',
        `optionWeight(${JSON.stringify(junk)}) must fall to the offer weight`
      );
    }
    assert.equal(V.optionWeight('in_branch').kind, 'recommended');
    assert.equal(V.optionWeight('cross_branch').kind, 'offer');
  });

  it('⛔ the "no in-branch target" panel is NOT drawn at recommendation weight', () => {
    // When there is no patch available the card must not promote the branch
    // move into the vacated slot by styling. Both non-recommendation panels
    // resolve through optionWeight() with a key that is not `in_branch`.
    const calls = [...SRC.matchAll(/optionWeight\(\s*'([^']*)'\s*\)/g)].map((m) => m[1]);
    assert.ok(calls.length >= 3, 'expected at least three optionWeight() call sites');
    assert.equal(
      calls.filter((k) => k === 'in_branch').length,
      1,
      'exactly one panel may be drawn at recommendation weight'
    );
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 2. ⛔ THE OFFER IS STATED AS WHAT IT WOULD ADD.
// ────────────────────────────────────────────────────────────────────────────

describe('the branch move is offered, never recommended', () => {
  it('reports what it would ADD over the recommended patch', () => {
    const offer = V.crossBranchOffer(plan());
    assert.equal(offer.adds, 5, 'the offer must carry crossBranchWouldAdd, not its own total');
    assert.equal(offer.clears, 8);
    assert.equal(offer.branch, '7.6');
  });

  it('⛔ `adds` is NULL when there is no in-branch baseline to add to', () => {
    // "would additionally clear 8" is meaningless with nothing to be additional
    // to, and printing the raw total there quietly promotes the branch move
    // into the position the recommendation vacated.
    const offer = V.crossBranchOffer(plan({ inBranch: null, recommendation: 'cross_branch_only' }));
    assert.equal(offer.adds, null);
    assert.equal(offer.clears, 8);
  });

  it('returns null rather than an empty offer when no other branch carries a fix', () => {
    assert.equal(V.crossBranchOffer(plan({ crossBranch: [] })), null);
    assert.equal(V.crossBranchOffer(plan({ crossBranch: undefined })), null);
    assert.equal(V.crossBranchOffer(null), null);
    assert.equal(V.crossBranchOffer(plan({ crossBranch: [{ branch: '7.6' }] })), null);
  });

  it('counts the branches it is NOT showing rather than dropping them', () => {
    const offer = V.crossBranchOffer(plan({
      crossBranch: [crossOption, { branch: '8.0', target: '8.0.1', clears: 2, kevCleared: 0 }],
    }));
    assert.equal(offer.alternatives, 1);
  });

  it('⛔ the caveat names the cost and is not hidden behind a disclosure', () => {
    assert.match(V.CROSS_BRANCH_CAVEAT, /not a patch/i);
    assert.match(V.CROSS_BRANCH_CAVEAT, /maintenance window/i);
    // Rendered inside the offer panel, not inside <Disclosure>. A reader who
    // never expands anything must still meet it.
    const panel = SRC.slice(SRC.indexOf('{offer ? ('), SRC.indexOf('{/* ── ⛔ What could not'));
    assert.ok(
      panel.includes('CROSS_BRANCH_CAVEAT'),
      'the caveat must render inside the offer panel, beside the number it qualifies'
    );
    const disclosure = SRC.slice(SRC.indexOf('<Disclosure'));
    assert.equal(
      disclosure.includes('CROSS_BRANCH_CAVEAT'),
      false,
      'a load-bearing caveat may not live inside a collapsed block'
    );
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 3. ⛔ `unplannable` IS RENDERED WHENEVER IT IS NON-ZERO.
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ what could not be planned is counted and named, never folded away', () => {
  it('any non-zero count is shown — there is no threshold and no "minor" case', () => {
    for (const n of [1, 2, 27, 1000]) {
      assert.equal(V.showsUnplannable(plan({ unplannableCount: n })), true, `${n} must render`);
    }
  });

  it('a genuine zero is the only thing that hides it', () => {
    assert.equal(V.showsUnplannable(plan({ unplannableCount: 0, unplannable: [] })), false);
  });

  it('⛔ a MISSING count falls back to the named list, never to zero', () => {
    // A count that failed to travel beside a populated list must not read as
    // "nothing here" — the failed-read-as-a-fact rule, on this page's most
    // important number.
    const rows = [{ cve_id: 'CVE-2024-1', kev_listed: true, priority_band: 'patch_now', reason: 'no_known_fix' }];
    assert.equal(V.unplannableCountOf({ unplannable: rows }), 1);
    assert.equal(V.unplannableCountOf({ unplannableCount: undefined, unplannable: rows }), 1);
    assert.equal(V.unplannableCountOf({ unplannableCount: 'seven', unplannable: rows }), 1);
    assert.equal(V.showsUnplannable({ unplannable: rows }), true);
  });

  it('an absent plan is 0, not a crash', () => {
    assert.equal(V.unplannableCountOf(null), 0);
    assert.equal(V.unplannableCountOf(undefined), 0);
    assert.equal(V.showsUnplannable(null), false);
  });

  it('⛔ it is drawn HUELESS — --unmeasured / --hatch, never the severity ramp', () => {
    const block = SRC.slice(
      SRC.indexOf('{showsUnplannable(plan) ? ('),
      SRC.indexOf('</Card>')
    );
    assert.ok(block.length > 0, 'the per-device unplannable block was not found');
    assert.match(block, /var\(--unmeasured\)/, 'the count must carry the unmeasured token');
    assert.equal(
      /--sev-|--red|--orange|--yellow|--green/.test(block),
      false,
      'an absence of a recorded fix is not a severity and must not be drawn as one'
    );
  });

  it('⛔ the hueless treatment comes from components/ui/NotMeasured.js, not a local copy', () => {
    assert.match(SRC, /from '\.\.\/ui\/NotMeasured'/);
    assert.match(SRC, /<NotMeasured\b/, 'the missing target version must render as NOT MEASURED');
    // ⛔ ALWAYS with a reason — a bare em-dash with no tooltip leaves the reader
    // unable to tell a gap in the device from a gap in SecVault.
    for (const m of SRC.matchAll(/<NotMeasured\b([^>]*)>/g)) {
      assert.match(m[1], /reason=/, 'every NotMeasured must carry a reason');
    }
  });

  it('⛔ it is surfaced at FLEET level too, above the per-firewall plans', () => {
    const fleetBlock = SRC.indexOf('fleetUnplannable.length > 0');
    const planList = SRC.indexOf('actionable.map((plan)');
    assert.notEqual(fleetBlock, -1, 'no fleet-level unplannable section');
    assert.ok(
      fleetBlock < planList,
      'below the plans it reads as a footnote to a list that already looked complete'
    );
  });

  it('the fleet tile counting it is hueless as well', () => {
    const tile = SRC.slice(SRC.indexOf('label="Cannot be planned"'));
    const end = tile.indexOf('/>');
    const props = tile.slice(0, end);
    assert.match(props, /var\(--unmeasured\)/);
    assert.equal(/--sev-|--red|--orange|--yellow/.test(props), false);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 4. ⛔ WORDING — "clears" is a claim about our advisory set, not about safety.
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ the view never promises a firewall becomes safe', () => {
  it('CLEARS_CLAIM says what clears MEANS and what it does not', () => {
    assert.match(V.CLEARS_CLAIM, /recorded fixed version/i);
    assert.match(V.CLEARS_CLAIM, /at or below this target/i);
    assert.match(V.CLEARS_CLAIM, /does not mean/i);
  });

  it('the sentence under a target says CLEARS and REMAIN, and nothing stronger', () => {
    const s = V.clearsSentence(inBranchOption, 27);
    assert.match(s, /^Clears 3 of 27 open assessments/);
    assert.match(s, /including 1 known exploited/);
    assert.match(s, /24 would remain open afterwards/);
    for (const forbidden of [/\bsafe\b/i, /\bsecure\b/i, /\bfixes\b/i, /\bpatched\b/i, /\bresolved\b/i, /\bprotected\b/i]) {
      assert.equal(forbidden.test(s), false, `the sentence must not say ${forbidden}`);
    }
  });

  it('⛔ "0 would remain" is STATED, never left to silence', () => {
    // Silence there reads as the stronger claim — that nothing is left at all.
    const s = V.clearsSentence({ target: '9.9', clears: 4, kevCleared: 0 }, 4);
    assert.match(s, /0 would remain open afterwards/);
    assert.equal(/known exploited/.test(s), false, 'no KEV cleared means no KEV clause');
  });

  it('a singular open count reads correctly', () => {
    assert.match(V.clearsSentence({ clears: 1, kevCleared: 0 }, 1), /1 of 1 open assessment\./);
  });

  it('a missing option produces nothing rather than a sentence about zero', () => {
    assert.equal(V.clearsSentence(null, 27), null);
    assert.equal(V.clearsSentence(undefined, 27), null);
  });

  it('⛔ no rendered string in the whole file claims safety or completeness', () => {
    // Comments are stripped: several deliberately DISCUSS the wrong wording in
    // order to forbid it, and a scan that read those would fail on its own
    // documentation.
    const code = SRC
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ');
    for (const forbidden of [
      /no longer vulnerable/i,
      /fully patched/i,
      /becomes secure/i,
      /all vulnerabilities/i,
      /remediat/i,
      /\bguarantee/i,
    ]) {
      assert.equal(forbidden.test(code), false, `a rendered string says ${forbidden}`);
    }
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 5. ⛔ THREE REASONS FOR "NO PLAN", not one.
// ────────────────────────────────────────────────────────────────────────────

describe('a firewall with no plan says WHY', () => {
  it('no collected version is its own reason', () => {
    const r = V.noPlanReason(plan({ runningVersion: null, currentBranch: null, inBranch: null }));
    assert.match(r, /No firmware version has been collected/i);
  });

  it('an unreadable version is a different reason from an absent one', () => {
    const r = V.noPlanReason(plan({ runningVersion: 'build-xyz', currentBranch: null, inBranch: null }));
    assert.match(r, /could not be read as a/i);
    assert.match(r, /build-xyz/, 'the operator needs to see the value we could not read');
  });

  it('everything unplannable is its own reason again', () => {
    const r = V.noPlanReason(plan({ inBranch: null, unplannableCount: 27 }));
    assert.match(r, /missing a recorded fix version/i);
  });

  it('and "nothing to upgrade to" is stated as that, not as a clean bill of health', () => {
    const r = V.noPlanReason(plan({ inBranch: null, unplannableCount: 0, unplannable: [] }));
    assert.match(r, /no upgrade target to propose/i);
    assert.equal(/\bsafe\b|\bsecure\b|up to date/i.test(r), false);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 6. ⛔ A FIREWALL WITH NO PLAN IS NOT A FIREWALL WITH NOTHING TO DO.
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ the view honours the coverage states the data layer computes', () => {
  const { COVERAGE } = require('../lib/engines/upgradePlanData');

  it('the copied coverage literals are identical to the data layer\'s', () => {
    // The view keeps its own copy so its pure half stays evaluable. A copy is
    // only acceptable while it cannot drift, which is what this asserts.
    assert.deepEqual(V.COVERAGE_STATE, COVERAGE);
  });

  it('only an explicitly ASSESSED plan reaches the plan list', () => {
    const { actionable } = V.partitionPlans([
      plan({ deviceId: 'a', coverage: COVERAGE.ASSESSED }),
      plan({ deviceId: 'b', coverage: COVERAGE.ASSESSED_CLEAR }),
      plan({ deviceId: 'c', coverage: COVERAGE.NEVER_ASSESSED }),
    ]);
    assert.deepEqual(actionable.map((p) => p.deviceId), ['a']);
  });

  it('⛔ only the literal assessed_clear may be rendered as "nothing outstanding"', () => {
    const { clear } = V.partitionPlans([
      plan({ deviceId: 'a', coverage: COVERAGE.ASSESSED_CLEAR }),
      plan({ deviceId: 'b', coverage: COVERAGE.NEVER_ASSESSED }),
      plan({ deviceId: 'c', coverage: COVERAGE.ASSESSED_NO_VERSION }),
    ]);
    assert.deepEqual(clear.map((p) => p.deviceId), ['a']);
  });

  it('⛔ an UNRECOGNISED or MISSING coverage falls to `uncovered`, never to `clear`', () => {
    // A plan we cannot characterise, characterised as clear, is the exact
    // failure upgradePlanData.js exists to prevent — re-committed by the view.
    for (const junk of [undefined, null, '', 'assessed_probably', 'clear', 0]) {
      const { clear, actionable, uncovered } = V.partitionPlans([plan({ coverage: junk })]);
      assert.equal(clear.length, 0, `coverage ${JSON.stringify(junk)} must not read as clear`);
      assert.equal(actionable.length, 0, `coverage ${JSON.stringify(junk)} must not read as planned`);
      assert.equal(uncovered.length, 1);
    }
  });

  it('the two uncovered causes are kept apart and both say what to do', () => {
    assert.match(V.uncoveredReason(COVERAGE.NEVER_ASSESSED), /never been CVE-assessed/i);
    assert.match(V.uncoveredReason(COVERAGE.ASSESSED_NO_VERSION), /No firmware version/i);
    assert.notEqual(
      V.uncoveredReason(COVERAGE.NEVER_ASSESSED),
      V.uncoveredReason(COVERAGE.ASSESSED_NO_VERSION),
      'one merged reason sends the operator to neither fix'
    );
    // And an unknown state still says something honest rather than nothing.
    assert.match(V.uncoveredReason('brand_new_state'), /cannot say/i);
  });

  it('⛔ coverage completeness is STRICTLY true — an absent flag is not an all-clear', () => {
    assert.equal(V.coverageIsComplete({ coverageComplete: true }), true);
    for (const junk of [{}, { coverageComplete: false }, { coverageComplete: 'yes' }, { coverageComplete: 1 }, null, undefined]) {
      assert.equal(
        V.coverageIsComplete(junk),
        false,
        `${JSON.stringify(junk)} must not authorise an unqualified headline`
      );
    }
  });

  it('⛔ the coverage caveat renders when coverage is incomplete', () => {
    assert.match(SRC, /\{!complete && \(/, 'nothing qualifies the headline when coverage is partial');
    const guard = SRC.slice(SRC.indexOf('{!complete && ('));
    assert.match(guard.slice(0, 600), /<CoverageNote/);
  });

  it('⛔ the summary from the data layer is USED, not recomputed over it', () => {
    // summarisePlans() knows nothing about coverage, so recomputing here would
    // silently drop coverageComplete and leave the headline unqualified.
    assert.match(SRC, /raw && raw\.summary/, 'the data layer summary must win');
  });

  it('⛔ "nothing outstanding" is never said without its date', () => {
    assert.match(V.assessedAsOf({ lastAssessedAt: '2026-09-24T02:00:00.000Z' }), /^as of 2026-09-24$/);
    // A missing or unreadable stamp is stated, not dropped — "clear" whose age
    // is unknown is a weaker claim and the reader has to be able to tell.
    assert.match(V.assessedAsOf({}), /not recorded/i);
    assert.match(V.assessedAsOf({ lastAssessedAt: 'whenever' }), /not readable/i);
    assert.match(V.assessedAsOf(null), /not recorded/i);
    const block = SRC.slice(SRC.indexOf('{clear.length > 0 ? ('));
    assert.match(block.slice(0, 900), /assessedAsOf\(p\)/, 'the clear list must print the stamp');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 7. ⛔ THE TAB KEY IS A URL CONTRACT — append only.
// ────────────────────────────────────────────────────────────────────────────

describe('⛔ /vulnerability tab registry', () => {
  function tabList() {
    const m = PAGE.match(/const VULN_TABS = \[([^\]]*)\]/);
    assert.ok(m, 'expected a VULN_TABS registry on the page');
    return m[1].split(',').map((s) => s.trim().replace(/^'|'$/g, '')).filter(Boolean);
  }

  it('keeps the existing keys in their existing positions', () => {
    // A bookmark carrying ?tab=advisories must still resolve. Inserting ahead
    // of these, or renaming one, silently breaks every link already sent.
    const keys = tabList();
    assert.equal(keys[0], 'posture');
    assert.equal(keys[1], 'advisories');
  });

  it('appends the new key at the END', () => {
    const keys = tabList();
    assert.equal(keys[keys.length - 1], 'upgrade');
    assert.equal(keys.indexOf('upgrade'), 2, 'upgrade was inserted rather than appended');
  });

  it('every key is unique and URL-safe', () => {
    const keys = tabList();
    assert.equal(new Set(keys).size, keys.length, 'a duplicate key makes one tab unreachable');
    for (const k of keys) {
      assert.equal(k, k.toLowerCase());
      assert.equal(k, encodeURIComponent(k), `${k} would need escaping in a URL`);
    }
  });

  it('an unrecognised ?tab= still lands on a real tab', () => {
    // The fallback is the FIRST entry, which is why its position is pinned above.
    assert.match(PAGE, /const DEFAULT_VULN_TAB = VULN_TABS\[0\]/);
    assert.match(PAGE, /VULN_TABS\.includes\(searchParams\?\.tab\)/);
  });

  it('the new tab is actually reachable — a link AND a render branch', () => {
    assert.match(PAGE, /tabLink\(tab, 'upgrade', '[^']+'\)/, 'no link in the tab strip');
    assert.match(PAGE, /tab === 'upgrade' && <UpgradePlan/, 'nothing renders for the new key');
    assert.match(PAGE, /import UpgradePlan from/, 'the component is referenced but not imported');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// 8. Server component, shared primitives, no reinvented ramp.
// ────────────────────────────────────────────────────────────────────────────

describe('the view stays a server component built from shared primitives', () => {
  it('declares no client boundary', () => {
    assert.equal(/^\s*'use client'/m.test(SRC), false, 'this tab needs no client JS');
  });

  it('⛔ uses the shared Table, so Settings → Appearance → Density still applies', () => {
    assert.match(SRC, /from '\.\.\/ui\/Table'/);
    // A hardcoded cell padding opts the table out of the density tokens
    // silently, and sits at one height while everything around it changes.
    assert.equal(
      /<td[^>]*padding:\s*['"]?\d/.test(SRC) || /<th[^>]*padding:\s*['"]?\d/.test(SRC),
      false,
      'a cell hardcodes padding and opts itself out of the density switch'
    );
  });

  it('reuses the shared band and KEV badges rather than mapping hues locally', () => {
    assert.match(SRC, /from '\.\.\/cve\/PriorityBadge'/);
    assert.match(SRC, /from '\.\.\/cve\/CVEBadge'/);
  });

  it('⛔ a failed read renders a refusal, never an empty plan', () => {
    // "Nothing to upgrade" over a query that threw is the failed-read-as-a-fact
    // bug at its most expensive: a fleet reported current because nothing asked.
    assert.match(SRC, /catch \(err\)/);
    const guard = SRC.slice(SRC.indexOf('if (failure !== null)'));
    assert.match(guard.slice(0, 900), /absence of a plan, not an absence of work/i);
  });

  it('every spacing value comes from the token scale', () => {
    // A component that invents its own 7px gap opts itself out of every future
    // spacing change, exactly the way a hardcoded hex opts out of the palette.
    const gaps = [...SRC.matchAll(/gap:\s*'([^']+)'/g)].map((m) => m[1]);
    assert.ok(gaps.length > 0);
    for (const g of gaps) {
      assert.match(g, /^var\(--s\d\)$/, `gap "${g}" is outside the spacing scale`);
    }
  });
});
