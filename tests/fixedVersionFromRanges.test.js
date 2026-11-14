'use strict';
// tests/fixedVersionFromRanges.test.js
//
// ⛔ THE FLEET'S ONLY THREE `patch_now` FINDINGS HAD NOWHERE TO GO.
//
// Measured 2026-09-25: CVE-2026-24858 — KEV-listed, CVSS 9.8 at NVD — was open
// on TSR_EKC / TSR_EKM / TSR-TL, all running FortiOS v7.4.9, with
// `fixed_in = NULL`. An urgent, known-exploited CVE and no version to upgrade
// to. Nothing was broken enough to notice: the match was right, the band was
// right, the evidence was right, and the one field that turns a finding into an
// action was empty.
//
// The fix version existed in three places at once and reached none of them:
//
//   NVD          cpe:2.3:o:fortinet:fortios 7.4.0 -> versionEndExcluding 7.4.11
//   the hub      {min: 7.4.0, max: 7.4.11, exclude_fixed: true}
//   SecVault     {min: 7.4.0, max: 7.4.10, exclude_fixed: false}   <- July CSAF
//
// TWO independent defects, and neither alone would have been enough:
//
//   1. `hubIsBetter()` repaired a local row ONLY when its ranges were BLANK.
//      Ours were not blank, merely worse — a prose range decremented to an
//      inclusive bound — so the hub's strictly better data was refused for ever.
//   2. Nothing derived a fix version from `exclude_fixed: true`, even though
//      that flag means "vulnerable up to but NOT INCLUDING max", i.e. max IS
//      the first fixed release. Across the hub feed only 10 of 955 advisories
//      populate `fixed_in_versions`, while many carry the boundary in a range.
//
// ⛔ THIS IS A DEFINITION, NOT AN INFERENCE. `versionEndExcluding` is NVD's own
// semantics and CLAUDE.md already states it ("up to BUT NOT INCLUDING").
// Nothing here guesses a version or invents one that was never published.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { hubIsBetter } = require('../lib/feeds/cveHub');
const { matchDeviceToAdvisories } = require('../lib/engines/versionMatcher');

const DEVICE = { id: 'dev-1', vendor: 'fortinet', name: 'TSR-TL' };
// v7.4.9 -> [7,4,9,0] per VENDOR_PARSERS.
const V749 = [7, 4, 9, 0];

// The four ranges exactly as the hub's feed carries them for CVE-2026-24858.
const HUB_RANGES = [
  { min: '7.0.0', max: '7.0.18', vulnerable: true, exclude_fixed: false },
  { min: '7.2.0', max: '7.2.12', vulnerable: true, exclude_fixed: false },
  { min: '7.4.0', max: '7.4.11', vulnerable: true, exclude_fixed: true },
  { min: '7.6.0', max: '7.6.6', vulnerable: true, exclude_fixed: true },
];
// The same CVE as SecVault actually stored it, from the July FortiGuard CSAF.
const LOCAL_RANGES = [
  { min: '7.0.0', max: '7.0.18', vulnerable: true, exclude_fixed: false },
  { min: '7.2.0', max: '7.2.12', vulnerable: true, exclude_fixed: false },
  { min: '7.4.0', max: '7.4.10', vulnerable: true, exclude_fixed: false },
  { min: '7.6.0', max: '7.6.5', vulnerable: true, exclude_fixed: false },
];

const advisory = (over = {}) => ({
  id: 'adv-1',
  cve_id: 'CVE-2026-24858',
  vendor: 'fortinet',
  kev_listed: true,
  cvss_score: 9.8,
  matchability: 'matched',
  affected_version_ranges: HUB_RANGES,
  fixed_in_versions: [],
  ...over,
});

const assess = (adv, tuple = V749) =>
  matchDeviceToAdvisories(DEVICE, tuple, [adv], [])[0];

// ── 1. The derivation ────────────────────────────────────────────────────

describe('⛔ a fix version is derived from exclude_fixed when none is published', () => {
  it('the live case: FortiOS 7.4.9 gets the target 7.4.11', () => {
    const a = assess(advisory());
    assert.ok(a, 'the device should still be assessed as affected');
    assert.equal(a.version_affected, true);
    assert.equal(a.fixed_in, '7.4.11');
  });

  it('picks the NEAREST fix strictly above the running version, not the highest', () => {
    // 7.6.6 is also a fix boundary. Telling a 7.4.9 device to jump a major
    // branch would be a bigger change than the CVE requires.
    assert.equal(assess(advisory()).fixed_in, '7.4.11');
  });

  it('⛔ a PUBLISHED list still wins over a derived boundary', () => {
    // A vendor that states its fixed releases outranks a boundary read off a
    // range. Palo Alto's PSIRT lists several per advisory; a single range max
    // would narrow that to one branch and understate the operator's options.
    const a = assess(advisory({ fixed_in_versions: ['7.4.10', '7.6.4'] }));
    assert.equal(a.fixed_in, '7.4.10');
  });

  it('⛔ derives NOTHING from exclude_fixed: false', () => {
    // That flag means max is the last AFFECTED version, so the fix is some
    // unknown release above it. Reporting max as the fix would send an operator
    // to a version that is still vulnerable — strictly worse than no target.
    const a = assess(advisory({ affected_version_ranges: LOCAL_RANGES }));
    assert.equal(a.version_affected, true, 'still affected — only the target is unknown');
    assert.equal(a.fixed_in, null);
  });

  it('a range with exclude_fixed but no max contributes nothing', () => {
    const a = assess(advisory({
      affected_version_ranges: [{ min: '7.4.0', max: null, vulnerable: true, exclude_fixed: true }],
    }));
    assert.equal(a && a.fixed_in, null);
  });

  it('never throws on a malformed ranges value', () => {
    for (const bad of [null, undefined, 'nope', 42, {}, [null], [{ exclude_fixed: true }]]) {
      assert.doesNotThrow(() => matchDeviceToAdvisories(
        DEVICE, V749, [advisory({ affected_version_ranges: bad })], []
      ));
    }
  });
});

// ── 2. The hub repair gate ───────────────────────────────────────────────

describe('⛔ hubIsBetter accepts strictly better data, never merely different', () => {
  const remote = { matchability: 'matched', affected_version_ranges: HUB_RANGES };

  it('repairs a BLANK local row, as it always did', () => {
    for (const blank of [null, undefined, []]) {
      assert.equal(hubIsBetter({ affected_version_ranges: blank }, remote), true);
    }
  });

  it('⛔ NOW repairs a local row that states no fix boundary at all', () => {
    // The whole defect: ours was not blank, merely worse.
    assert.equal(hubIsBetter({ affected_version_ranges: LOCAL_RANGES }, remote), true);
  });

  it('⛔ REFUSES when we already state a fix boundary', () => {
    // Then the hub is not adding knowledge, it is offering a second opinion —
    // and rule 3 exists because trading one for the other is how a matched
    // advisory silently becomes unmatchable.
    assert.equal(hubIsBetter({ affected_version_ranges: HUB_RANGES }, remote), false);
  });

  it('⛔ REFUSES a hub row with FEWER ranges, even when it adds a boundary', () => {
    // Otherwise "more informative" would be a licence to narrow our coverage:
    // three branches replaced by one, with a fix version as the sweetener.
    const narrow = {
      matchability: 'matched',
      affected_version_ranges: [{ min: '7.4.0', max: '7.4.11', exclude_fixed: true }],
    };
    assert.equal(hubIsBetter({ affected_version_ranges: LOCAL_RANGES }, narrow), false);
  });

  it('⛔ rules 1 and 3 are untouched: unmatchable or rangeless remote is refused', () => {
    assert.equal(hubIsBetter({ affected_version_ranges: [] },
      { matchability: 'unmatchable', affected_version_ranges: HUB_RANGES }), false);
    assert.equal(hubIsBetter({ affected_version_ranges: LOCAL_RANGES },
      { matchability: 'matched', affected_version_ranges: [] }), false);
  });

  it('⛔ an UNRECOGNISED local shape is still refused, not filled', () => {
    // The original comment records why: `!hasRanges()` was true for a jsonb
    // object, a string or an absent key, and the UPDATE then raised "cannot get
    // array length of a non-array" — which flipped the sync to partial and
    // silently re-enabled the doomed local NVD path every cycle. An
    // unrecognised shape is not a gap we may fill; it is a row we do not
    // understand.
    for (const weird of [{ a: 1 }, 'ranges', 42, true]) {
      assert.equal(hubIsBetter({ affected_version_ranges: weird }, remote), false,
        `an unrecognised local shape ${JSON.stringify(weird)} was treated as repairable`);
    }
  });

  it('never throws on junk', () => {
    for (const bad of [null, undefined, {}, 'x', 0]) {
      assert.doesNotThrow(() => hubIsBetter(bad, remote));
      assert.doesNotThrow(() => hubIsBetter({ affected_version_ranges: LOCAL_RANGES }, bad));
    }
  });
});

// ── 3. The vendor feed must not undo the hub's repair ────────────────────
//
// ⛔ THIS SECTION READ THE FILE'S TEXT AND WAS DEMONSTRATED INERT (2026-11-15).
// It sliced `lib/feeds/fortinet.js` from `affected_version_ranges = CASE` and
// regex-matched the CALL-SITE SPELLING of the guard. Five edits to a scratchpad
// copy, each run through the old assertions verbatim:
//
//   edit                                                  behaviour   old §3
//   reflow the guard to one line, reword a comment         unchanged   PASS
//   hoist the two jsonb expressions into constants         unchanged   FAIL  <- cries wolf
//   delete the guard arm outright                          GUARD GONE  FAIL
//   `THEN advisories.…` -> `THEN EXCLUDED.…` (one word)    INVERTED    PASS  <- INERT
//   `AND NOT` -> `AND NOT NOT`                             INVERTED    PASS  <- INERT
//
// The two inert rows are the dangerous ones. Both are valid SQL, both are
// one-token regressions, and both restore the 2026-09-25 incident exactly: the
// vendor feed, running NINE SECONDS after cve_hub, overwriting the fix boundary
// the hub had just repaired — 80 rows repaired at 12:56:27, not one surviving
// the cycle. A guard that stays green while the thing it guards is INVERTED is
// the guard-that-cannot-fire pattern; and the same assertions failed on a
// refactor that changed no behaviour at all, which is how a check gets waived
// and then deleted.
//
// ⛔ WHAT IS EXECUTABLE HERE, AND WHAT IS NOT. The decision lives in a SQL
// `CASE`, and nothing in `npm test` may touch a database. So this section does
// the two things that CAN be executed, following tests/fixBoundary.test.js:
//
//   (a) the DECISION is run in JS over real inputs, from the SAME shared
//       definition the SQL is generated from (`hasUsableFixBoundary`), and the
//       value it protects is read back through the real matcher — so the cost
//       of losing it is measured, not asserted; and
//   (b) the STATEMENT IS OBTAINED BY CALLING THE REAL EXPORTED
//       `upsertAdvisory` with a stub pool. That is the artefact actually sent
//       to PostgreSQL, with SQL comments stripped, and the arm it must contain
//       is GENERATED by `hasUsableFixBoundarySql` here rather than spelled out
//       — so a rename or a reflow of the call site cannot disarm it and cannot
//       cry wolf, because neither changes a byte of the emitted statement.
//
// ⛔ NO SQL EVALUATOR IS WRITTEN. Interpreting the `CASE` in JS would be a
// second parser disagreeing with the authoritative one — the trap this repo
// names about brace-counting regexes. What is asserted instead is the structural
// property that makes the arm unambiguous: the INCOMING value may win in
// EXACTLY ONE place, the `ELSE`.

describe('⛔ the Fortinet upsert never trades a fix boundary for none', () => {
  const {
    hasUsableFixBoundary, isUnrecognisedRanges, hasUsableFixBoundarySql,
  } = require('../lib/feeds/fixBoundary');
  const { upsertAdvisory } = require('../lib/feeds/fortinet');

  // The decision, expressed ONCE from the shared definition. This is the rule
  // the SQL arm has to implement, and it is the only place this file states it.
  const isStrictDowngrade = (local, incoming) =>
    hasUsableFixBoundary(local) && !hasUsableFixBoundary(incoming);

  // ── (a) the decision, executed ──────────────────────────────────────────

  it('⛔ the live pair IS a strict downgrade: hub-repaired local, July CSAF incoming', () => {
    // This is the real 2026-09-25 pair. HUB_RANGES carries 7.4.11 with
    // exclude_fixed, which by NVD's own semantics IS the first fixed release;
    // LOCAL_RANGES is the same CVE parsed out of FortiGuard's prose CSAF, an
    // inclusive 7.4.10 naming no fix at all.
    assert.equal(isStrictDowngrade(HUB_RANGES, LOCAL_RANGES), true);
  });

  it('⛔ the value the guard protects is the whole remediation target', () => {
    // Measured through the real matcher rather than asserted in prose: losing
    // the boundary does not degrade the finding, it empties the one field that
    // turns it into an action.
    assert.equal(assess(advisory({ affected_version_ranges: HUB_RANGES })).fixed_in, '7.4.11');
    assert.equal(assess(advisory({ affected_version_ranges: LOCAL_RANGES })).fixed_in, null);
  });

  it('⛔ stays ONE-DIRECTIONAL — an incoming row WITH a boundary still wins', () => {
    // Not a preference for the hub over the vendor. FortiGuard keeps authority
    // wherever it actually has the better data; only the strict downgrade is
    // refused. A guard that always kept ours would freeze the vendor out of its
    // own advisories.
    assert.equal(isStrictDowngrade(LOCAL_RANGES, HUB_RANGES), false, 'vendor adds a boundary');
    assert.equal(isStrictDowngrade(HUB_RANGES, HUB_RANGES), false, 'both carry one');
    assert.equal(isStrictDowngrade(LOCAL_RANGES, LOCAL_RANGES), false, 'neither carries one');
  });

  it('⛔ WE COULD NOT MEASURE THIS: an unreadable or absent range is not an empty one', () => {
    // The guard must never read our own failure to parse a row as "we hold no
    // boundary" — and must never read it as a boundary either. `jsonb`
    // legitimately holds a string, a number or an object where this code expects
    // an array, and passing one to the statement raises "cannot get array length
    // of a non-array", which lands in stats.errors and flips the sync to partial.
    for (const unreadable of ['n/a', 42, { a: 1 }]) {
      assert.equal(isUnrecognisedRanges(unreadable), true, JSON.stringify(unreadable));
      assert.equal(hasUsableFixBoundary(unreadable), false,
        'an unreadable value must not be read as a boundary');
      assert.equal(isStrictDowngrade(unreadable, HUB_RANGES), false,
        'and must never block a vendor row that does carry one');
    }
    // Absent is a THIRD state, distinct from both: nothing was stored, which is
    // not the same as something we could not read.
    for (const absent of [null, undefined]) {
      assert.equal(isUnrecognisedRanges(absent), false, 'absent is not unrecognised');
      assert.equal(hasUsableFixBoundary(absent), false);
    }
    // ⛔ And the shape THIS codebase produces: expandWildcardMax('*') returns
    // {max: null, exclude_fixed: true}, which satisfied the old jsonb
    // containment test while naming no release. It is NOT a boundary, so it must
    // not be able to refuse a real vendor update.
    const uselessBoundary = [{ min: '7.4.0', max: null, vulnerable: true, exclude_fixed: true }];
    assert.equal(hasUsableFixBoundary(uselessBoundary), false);
    assert.equal(isStrictDowngrade(uselessBoundary, LOCAL_RANGES), false);
  });

  // ── (b) the statement the feed actually executes ────────────────────────

  // Calls the REAL exported upsert and returns the statement it handed the pool,
  // SQL comments stripped and whitespace normalised. Comments are stripped
  // FIRST because `--`-ing the arm out leaves every regex over the raw text
  // matching while the guard is gone — one of the five edits above.
  async function emitted(rec) {
    const calls = [];
    const pool = {
      query: async (sql, params) => {
        calls.push({ sql, params });
        return { rows: [{ inserted: false }], rowCount: 1 };
      },
    };
    await upsertAdvisory(pool, {
      cve_id: 'CVE-2026-24858', vendor: 'fortinet', source_tier: 'advisory_page',
      affected_version_ranges: LOCAL_RANGES, fixed_in_versions: [], raw_data: {},
      ...rec,
    });
    assert.ok(calls.length >= 1, 'the upsert issued no statement at all');
    const sql = calls[0].sql.replace(/^[^\S\n]*--.*$/gm, '');
    const from = sql.indexOf('affected_version_ranges = CASE');
    const to = sql.indexOf('fixed_in_versions = CASE');
    assert.ok(from !== -1 && to > from, 'the affected_version_ranges CASE arm is gone');
    return {
      params: calls[0].params,
      arm: sql.slice(from, to).replace(/\s+/g, ' ').trim(),
    };
  }

  const norm = (s) => s.replace(/\s+/g, ' ').trim();

  it('⛔ the emitted statement composes exactly that decision, from the shared generator', async () => {
    const { arm } = await emitted();
    // Generated here, never spelled out: if fortinet.js hand-writes the
    // predicate — the blind-to-max containment form it used to — this text will
    // not be in the statement.
    const guard = norm(
      `WHEN ${hasUsableFixBoundarySql('advisories.affected_version_ranges')}`
      + ` AND NOT ${hasUsableFixBoundarySql('EXCLUDED.affected_version_ranges')}`
      + ' THEN advisories.affected_version_ranges'
    );
    assert.ok(arm.includes(guard),
      'the executed statement must keep OUR ranges exactly when ours carry a usable '
      + 'boundary and the incoming row does not. Emitted arm:\n' + arm);
  });

  it('⛔ the INCOMING value may win in exactly ONE place, the ELSE', async () => {
    // This is what makes the arm unambiguous without interpreting it, and it is
    // the assertion the old section could not make: `THEN EXCLUDED.…` in place
    // of `THEN advisories.…` is a one-word inversion that PERFORMS the downgrade
    // the guard exists to refuse, and every regex over the source still matched.
    const { arm } = await emitted();
    assert.equal((arm.match(/THEN EXCLUDED\.affected_version_ranges/g) || []).length, 0,
      'a WHEN arm hands the incoming value back — the downgrade is being performed');
    assert.equal((arm.match(/ELSE EXCLUDED\.affected_version_ranges END/g) || []).length, 1,
      'the vendor must still win in every case that is not a downgrade, and in only that way');
  });

  it('⛔ the EXCLUDED side really is this record’s ranges, and $17 is the degraded flag', async () => {
    // Ties the structural assertion to real inputs: the arm above is only about
    // the downgrade if `EXCLUDED.affected_version_ranges` is what the caller
    // passed, and if the degraded-source arm in front of it is driven by
    // source_tier rather than by something else.
    const page = await emitted({ source_tier: 'advisory_page' });
    assert.equal(page.params[7], JSON.stringify(LOCAL_RANGES),
      '$8 must carry the incoming ranges');
    assert.equal(page.params[16], false, 'an advisory-page record is not degraded');

    const rss = await emitted({ source_tier: 'rss' });
    assert.equal(rss.params[16], true, 'an rss record is degraded and may only fill a gap');
  });
});

// ── 4. The doubled guard must not drift ──────────────────────────────────

describe('⛔ hubIsBetter and the UPDATE’s WHERE clause express the SAME rule', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'feeds', 'cveHub.js'), 'utf8');

  it('the WHERE clause is GENERATED from the same definition as the predicate', () => {
    // ⛔ THIS COST THREE DEPLOYS, AND THE TEST THAT WAS SUPPOSED TO STOP IT
    // RECURRING COULD NOT FIRE. Rule 3 is expressed twice -- a JS predicate and
    // a statement WHERE -- so an unsafe repair is impossible rather than merely
    // unreached. v2.186.0 widened the predicate and left the statement behind;
    // v2.186.2 fixed that pair; and on 2026-09-27 review found the halves STILL
    // disagreed, because the SQL used jsonb containment, which is blind to
    // `max`:  local {exclude_fixed:true, max:null}  ->  JS repair, SQL refuse.
    //
    // ⛔ THE OLD TEST HERE WAS FOUR REGEXES OVER THE SQL STRING'S TEXT,
    // asserting each half's WORDING separately. It never built an input where
    // the halves disagreed, which is why the disagreement above passed a green
    // suite -- and it was demonstrated inert: wrapping the widened disjunct in
    // a block comment left all four assertions passing.
    //
    // The halves are now one definition, so this asserts that property and
    // tests/fixBoundary.test.js asserts the behaviour.
    // ⛔ Slice from the WHERE to the end of the template literal rather than to
    // a hand-written marker containing a newline — the previous form embedded a
    // literal line break in a single-quoted JS string, which does not parse.
    const whereStart = src.indexOf('WHERE cve_id = $1');
    // 3000 chars comfortably spans the WHERE through its last disjunct; the
    // first attempt used 1200 and fell ~100 chars short of the blank-row case,
    // which failed as "the blank-row case must survive" — a false alarm about
    // the code caused by the window, exactly the kind of misdirection a
    // hand-tuned slice invites.
    const where = whereStart === -1 ? '' : src.slice(whereStart, whereStart + 3000);
    assert.ok(where.length > 0, 'the UPDATE WHERE clause is gone');
    assert.match(where, /jsonb_array_length\(affected_version_ranges\) = 0/,
      'the blank-row case must survive');
    assert.ok(!/@> '\[\{"exclude_fixed": true\}\]'/.test(where),
      'the hand-written containment test must be gone -- it is the blind-to-max form');
  });

  it('⛔ the repair counts what the DATABASE did, not what we asked', () => {
    // `stats.repaired++` fired whether or not the WHERE matched, so
    // feed_sync_log reported repairs that never happened -- and that number is
    // what made the failure look like a different bug entirely. This file
    // already states the rule forty lines up, for the INSERT.
    assert.match(src, /stats\.repaired \+= Number\(res && res\.rowCount\) \|\| 0/,
      'stats.repaired is a blind increment again — it will report repairs the database refused');
    // ⛔ COMMENTS STRIPPED FIRST. The only remaining `stats.repaired++` in that
    // file is inside the comment EXPLAINING why it is gone, so a raw scan reads
    // its own explanation as the defect. Third time this exact trap has bitten
    // in one day: deviceScopeCoverage's transitive check read prose as
    // evidence, and the button-contrast extractor read a token name out of a
    // comment and produced NaN:1.
    const code = src.replace(/^\s*\/\/.*$/gm, ' ').replace(/\/\*[\s\S]*?\*\//g, ' ');
    assert.doesNotMatch(code, /stats\.repaired\+\+/,
      'a blind increment came back');
    // And the INSERT half, which was always right, must stay right.
    assert.match(src, /stats\.inserted \+= Number\(res && res\.rowCount\) \|\| 0/);
  });
});
