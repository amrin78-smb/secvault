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

describe('⛔ the Fortinet upsert never trades a fix boundary for none', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const src = fs.readFileSync(
    path.join(__dirname, '..', 'lib', 'feeds', 'fortinet.js'), 'utf8'
  );

  it('refuses a strict downgrade of affected_version_ranges', () => {
    // ⛔ THIS FEED RUNS NINE SECONDS AFTER cve_hub. Measured 2026-09-25: the
    // hub repaired 80 advisory rows at 12:56:27 and not one survived the
    // cycle, because a resolved CSAF takes the ELSE branch and overwrites.
    // The vendor is normally the better source; FortiGuard's CSAF is PROSE,
    // and "7.4.0 through 7.4.10" parses to an inclusive bound with no fix
    // version where NVD's versionEndExcluding gives 7.4.11.
    const clause = src.slice(
      src.indexOf('affected_version_ranges = CASE'),
      src.indexOf('fixed_in_versions = CASE')
    );
    assert.ok(clause.length > 0, 'the affected_version_ranges CASE is gone');
    assert.match(
      clause,
      /advisories\.affected_version_ranges\s*@>\s*'\[\{"exclude_fixed":\s*true\}\]'/,
      'the downgrade guard is gone — the vendor feed can overwrite a fix boundary again'
    );
    assert.match(
      clause,
      /NOT\s*\(\s*EXCLUDED\.affected_version_ranges\s*@>/,
      'the guard must test the INCOMING row too, or it becomes an unconditional refusal'
    );
  });

  it('⛔ stays ONE-DIRECTIONAL — an incoming row WITH a boundary still wins', () => {
    // This is not a preference for the hub over the vendor. FortiGuard keeps
    // authority wherever it actually has the better data; only the strict
    // downgrade is refused. A guard that always kept ours would freeze the
    // vendor out of its own advisories.
    const clause = src.slice(
      src.indexOf('affected_version_ranges = CASE'),
      src.indexOf('fixed_in_versions = CASE')
    );
    assert.match(clause, /ELSE EXCLUDED\.affected_version_ranges END/,
      'the vendor must still win in every case that is not a downgrade');
  });
});
