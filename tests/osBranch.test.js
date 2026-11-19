'use strict';
// Pins lib/osBranch.js — the OS-branch matching contract and the four-state
// support verdict.
//
// ⛔ THE CONTRACT LIVES ON BOTH SIDES OF A NETWORK, WHICH IS WHY IT IS PINNED
// HERE AT ALL. The hub reduces a running version to a branch key with its own
// `branchOf` (lib/eol/os-cycles.ts) and keys the corpus on the result; this
// file reduces the version SecVault collected from the firewall. If the two
// disagree by one character the join MISSES — and it misses silently, rendering
// "branch unknown" on firewalls the corpus covers perfectly well. A whole
// feature degrading to nothing, with no error anywhere.
//
// ⛔ SO THE VECTORS BELOW ARE THE HUB'S OWN, COPIED FROM ITS VERIFIER
// (scripts/verify-os-cycles.ts), not cases invented here. A test written from
// this side's behaviour would pass on a drifted implementation.
//
// ⛔ AND THE CONTENT ASSERTIONS RUN AGAINST THE REAL PUBLISHED CORPUS
// (tests/fixtures/osFeedSigned.js), so "PAN-OS 10.0 is end-of-life" is a
// statement about what the publisher actually shipped, verified under its real
// signature, rather than about a fixture this test wrote to suit itself.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  OS_BRANCH_VERSION, BRANCH_STATES, UNKNOWN_REASONS, PRODUCT_FOR_VENDOR, UNCOVERED_VENDORS,
  BRANCH_CLAIM,
  branchOf, branchState, classifyBranch, cycleIsMatchable, normaliseConfidence,
  isVendorConfirmed, summariseBranchStates, todayLocal,
} = require('../lib/osBranch');
const osFixture = require('./fixtures/osFeedSigned');

// The real corpus, parsed from the signed bytes.
const CORPUS = JSON.parse(osFixture.BODY.toString('utf8')).cycles;
const lookup = ({ vendor, product, cycle }) =>
  CORPUS.find((c) => c.vendor === vendor && c.product === product && c.cycle === cycle) || null;

describe('branchOf — the hub\'s own vectors', () => {
  it('⛔ the version pin matches the hub\'s OS_BRANCH_VERSION', () => {
    assert.equal(OS_BRANCH_VERSION, 1);
  });

  const vectors = [
    ['PAN-OS point release', '10.1.2', '10.1'],
    ['PAN-OS hotfix suffix', '10.1.2-h3', '10.1'],
    ['FortiOS build suffix', '7.4.4 build2662', '7.4'],
    ['v-prefixed', 'v7.2.8', '7.2'],
    ['Cisco zero-padded minor', '17.09.01a', '17.9'],
    ['Cisco unpadded', '17.9.1', '17.9'],
    ['already a branch', '11.1', '11.1'],
    ['garbage', 'not-a-version', null],
    ['null', null, null],
  ];
  for (const [name, input, expected] of vectors) {
    it(`${name}: ${JSON.stringify(input)} -> ${JSON.stringify(expected)}`, () => {
      assert.equal(branchOf(input), expected);
    });
  }

  it('⛔ LEADING ZEROS ARE STRIPPED, so "17.09" and "17.9" are ONE key', () => {
    // Cisco publishes both spellings for one branch. Two keys would miss half
    // the lookups, and miss them silently.
    assert.equal(branchOf('17.09.01a'), branchOf('17.9.1'));
    assert.equal(branchOf('17.09'), '17.9');
  });

  it('⛔ an unreadable version is null, NEVER a fabricated "0.0"', () => {
    // parseVersion() in versionComparator.js returns [0,0,0,0] for exactly this
    // input and CLAUDE.md records what that cost on the CVE path. A "0.0"
    // branch key matches nothing today and would be a live mis-attribution the
    // day a vendor ships a 0.x branch.
    for (const bad of ['', '   ', 'unknown', 'R81.20 Take 41', 'x7.4']) {
      assert.equal(branchOf(bad), null, `${JSON.stringify(bad)} must not produce a branch`);
    }
  });

  it('trims surrounding whitespace rather than failing on it', () => {
    assert.equal(branchOf('  11.2.1  '), '11.2');
  });
});

describe('branchState — FOUR states, never three', () => {
  const pan101 = { support_end_date: '2024-12-01', extended_end_date: '2026-03-31' };

  it('inside standard support', () => {
    assert.equal(branchState(pan101, '2024-11-30'), 'supported');
  });

  it('⛔ ON the support-end date it is still SUPPORTED (inclusive)', () => {
    // The vendor publishes the last supported day, not the first unsupported
    // one. An exclusive comparison would call a branch dead a day early — which
    // on this axis is the whole answer on exactly the day somebody checks.
    assert.equal(branchState(pan101, '2024-12-01'), 'supported');
  });

  it('⛔ the day after standard support is `extended_only`, NOT `eol`', () => {
    assert.equal(branchState(pan101, '2024-12-02'), 'extended_only');
  });

  it('⛔ and NOT `supported` either — that would hide a contract the customer may not hold', () => {
    assert.notEqual(branchState(pan101, '2025-06-01'), 'supported');
    assert.equal(branchState(pan101, '2026-03-31'), 'extended_only');
  });

  it('past extended support it is `eol`', () => {
    assert.equal(branchState(pan101, '2026-04-01'), 'eol');
  });

  it('a branch with NO extended date goes straight from supported to eol', () => {
    const pan100 = { support_end_date: '2022-07-16', extended_end_date: null };
    assert.equal(branchState(pan100, '2022-07-16'), 'supported');
    assert.equal(branchState(pan100, '2022-07-17'), 'eol');
  });

  it('⛔ a row with NEITHER date is `unknown`, NOT `eol`', () => {
    // The defensive arm, and the one where "default it to the bad case"
    // survives review. An absent statement is not a statement that support has
    // ended.
    assert.equal(branchState({ support_end_date: null, extended_end_date: null }, '2026-01-01'), 'unknown');
    assert.equal(branchState({}, '2026-01-01'), 'unknown');
    assert.equal(branchState(null, '2026-01-01'), 'unknown');
  });

  it('⛔ an extended date with no standard date is `extended_only` while live', () => {
    const odd = { support_end_date: null, extended_end_date: '2027-01-01' };
    assert.equal(branchState(odd, '2026-01-01'), 'extended_only');
    assert.equal(branchState(odd, '2027-01-02'), 'eol');
  });

  it('⛔ an unreadable `asOf` is `unknown` — never silently "today"', () => {
    assert.equal(branchState(pan101, 'not-a-day'), 'unknown');
    assert.equal(branchState(pan101, null), 'unknown');
  });

  it('accepts a full timestamp for asOf and reads its DAY', () => {
    assert.equal(branchState(pan101, '2024-12-01T23:59:59Z'), 'supported');
  });
});

describe('the REAL published corpus', () => {
  it('⛔ PAN-OS 11.1 ends 2027-05-03 standard / 2027-08-31 extended', () => {
    const row = lookup({ vendor: 'Palo Alto', product: 'PAN-OS', cycle: '11.1' });
    assert.ok(row, 'PAN-OS 11.1 must be in the corpus');
    assert.equal(row.support_end_date, '2027-05-03');
    assert.equal(row.extended_end_date, '2027-08-31');
    assert.equal(row.confidence, 'high');
  });

  it('⛔ a firewall on PAN-OS 10.0 classifies as eol', () => {
    const v = classifyBranch({
      vendor: 'paloalto', version: '10.0.12-h3', lookup, asOf: '2026-11-16',
    });
    assert.equal(v.state, 'eol');
    assert.equal(v.branch, '10.0');
    assert.equal(v.product, 'PAN-OS');
    assert.equal(v.supportEnd, '2022-07-16');
    assert.equal(v.vendorConfirmed, true);
    assert.match(v.sentence, /left vendor support on 2022-07-16/);
  });

  it('a firewall on PAN-OS 11.1 classifies as supported, with the end date', () => {
    const v = classifyBranch({ vendor: 'paloalto', version: '11.1.4-h1', lookup, asOf: '2026-11-16' });
    assert.equal(v.state, 'supported');
    assert.equal(v.supportEnd, '2027-05-03');
    assert.equal(v.extendedEnd, '2027-08-31');
    assert.match(v.sentence, /supported until 2027-05-03/);
  });

  it('⛔ a firewall on PAN-OS 10.1 is `extended_only` today, and the sentence says CONTRACT', () => {
    const v = classifyBranch({ vendor: 'paloalto', version: '10.1.14', lookup, asOf: '2026-01-15' });
    assert.equal(v.state, 'extended_only');
    assert.match(v.sentence, /requires a contract/);
  });

  it('⛔ a FortiOS verdict is marked as an AGGREGATOR date, not vendor-confirmed', () => {
    // Every FortiOS and Cisco IOS-XE row in the live corpus is endoflife.date.
    // Rendering one like Palo Alto's own table is this codebase's signature bug
    // with an upgrade budget attached.
    const v = classifyBranch({
      vendor: 'fortinet', version: 'v7.0.14,build0601', lookup, asOf: '2026-11-16',
    });
    assert.equal(v.state, 'eol');
    assert.equal(v.confidence, 'low');
    assert.equal(v.vendorConfirmed, false);
    assert.match(v.sentence, /not confirmed by the vendor/);
  });

  it('⛔ every corpus row carries a confidence, and PAN-OS is the only `high` product', () => {
    const byConfidence = new Map();
    for (const c of CORPUS) {
      assert.ok(c.confidence, `${c.product} ${c.cycle} must state a confidence`);
      const k = `${c.product}/${c.confidence}`;
      byConfidence.set(k, (byConfidence.get(k) || 0) + 1);
    }
    assert.ok(byConfidence.get('PAN-OS/high') > 0);
    assert.equal(byConfidence.get('FortiOS/high'), undefined);
    assert.equal(byConfidence.get('Cisco IOS-XE/high'), undefined);
  });

  it('⛔ the corpus holds cycle keys branchOf can NEVER return, and they are detectable', () => {
    // PAN-OS "9.0-XFR" and "9.0-xfr" are both in the live corpus. They are
    // valid lifecycle statements about a branch this product cannot match a
    // device to, so they are inert — and a row that can never join looks
    // exactly like a row that joins and is never hit.
    const unmatchable = CORPUS.filter((c) => !cycleIsMatchable(c.cycle));
    assert.ok(unmatchable.length >= 1, 'the live corpus has at least one');
    for (const c of unmatchable) assert.notEqual(branchOf(c.cycle), c.cycle);
    assert.ok(cycleIsMatchable('11.1'));
    assert.ok(!cycleIsMatchable('9.0-xfr'));
    assert.ok(!cycleIsMatchable(''));
  });
});

describe('classifyBranch — the five ways of being unknown', () => {
  it('⛔ a vendor the corpus does not cover: product_not_covered', () => {
    for (const vendor of ['checkpoint', 'forcepoint', 'sangfor']) {
      const v = classifyBranch({ vendor, version: '8.0.85', lookup, asOf: '2026-11-16' });
      assert.equal(v.state, 'unknown');
      assert.equal(v.reason, 'product_not_covered');
    }
  });

  it('⛔ cisco_asa IS NOT Cisco IOS-XE, and the refusal is explicit', () => {
    // An ASA runs ASA Software; IOS-XE is the Catalyst/ISR OS. Today the two
    // version spaces happen not to overlap, so this looks cosmetic — it is the
    // only thing standing between this feature and a confident lifecycle
    // verdict for the wrong operating system.
    assert.equal(PRODUCT_FOR_VENDOR.cisco_asa, undefined);
    const v = classifyBranch({ vendor: 'cisco_asa', version: '9.18(4)15', lookup, asOf: '2026-11-16' });
    assert.equal(v.state, 'unknown');
    assert.equal(v.reason, 'product_not_covered');
    assert.match(v.sentence, /IOS-XE/);
    assert.match(v.sentence, /not the ASA operating system/);
  });

  it('⛔ and it does NOT accidentally match an IOS-XE cycle', () => {
    // branchOf('9.18(4)15') is '9.18'. If cisco_asa were mapped to IOS-XE this
    // would answer from somebody else's lifecycle table the moment either side
    // shipped a colliding branch number.
    assert.equal(branchOf('9.18(4)15'), '9.18');
    const asIfMapped = lookup({ vendor: 'Cisco', product: 'Cisco IOS-XE', cycle: '9.18' });
    assert.equal(asIfMapped, null, 'no collision TODAY — which is luck, not the guard');
  });

  it('no collected version: no_version', () => {
    for (const version of [null, undefined, '', '  ']) {
      const v = classifyBranch({ vendor: 'paloalto', version, lookup, asOf: '2026-11-16' });
      assert.equal(v.reason, 'no_version');
      assert.match(v.sentence, /no version has been collected/);
    }
  });

  it('an unreadable version: unreadable_version, and it QUOTES the string', () => {
    const v = classifyBranch({ vendor: 'paloalto', version: 'unknown', lookup, asOf: '2026-11-16' });
    assert.equal(v.reason, 'unreadable_version');
    assert.match(v.sentence, /"unknown"/);
  });

  it('⛔ a covered product on an UNCOVERED branch: branch_absent, and the branch is still reported', () => {
    const v = classifyBranch({ vendor: 'paloalto', version: '99.9.1', lookup, asOf: '2026-11-16' });
    assert.equal(v.state, 'unknown');
    assert.equal(v.reason, 'branch_absent');
    assert.equal(v.branch, '99.9', 'the branch we computed is carried, so the gap is nameable');
    assert.match(v.sentence, /PAN-OS 99\.9 is not in the branch/);
  });

  it('⛔ a corpus row with no usable date: cycle_unreadable, NOT eol', () => {
    const v = classifyBranch({
      vendor: 'paloalto', version: '7.7.7',
      lookup: () => ({ support_end_date: null, extended_end_date: null, confidence: 'high' }),
      asOf: '2026-11-16',
    });
    assert.equal(v.state, 'unknown');
    assert.equal(v.reason, 'cycle_unreadable');
  });

  it('⛔ the product check runs BEFORE the version check', () => {
    // A Check Point running a perfectly readable R81.20 is not a parsing
    // problem and must not be reported as one — "we do not cover this OS" and
    // "we could not read this version" send an operator to different places.
    const v = classifyBranch({ vendor: 'checkpoint', version: null, lookup, asOf: '2026-11-16' });
    assert.equal(v.reason, 'product_not_covered');
  });

  it('⛔ an unknown verdict NEVER carries a date or a confidence', () => {
    // A date beside "unknown" is the half a renderer would reach for, and it
    // would be a date for nothing.
    for (const args of [
      { vendor: 'checkpoint', version: '1.2.3' },
      { vendor: 'paloalto', version: null },
      { vendor: 'paloalto', version: 'nope' },
      { vendor: 'paloalto', version: '99.9.1' },
    ]) {
      const v = classifyBranch({ ...args, lookup, asOf: '2026-11-16' });
      assert.equal(v.state, 'unknown');
      assert.equal(v.supportEnd, null);
      assert.equal(v.extendedEnd, null);
      assert.equal(v.vendorConfirmed, false);
    }
  });

  it('every reason it can produce is a declared reason', () => {
    const produced = [
      classifyBranch({ vendor: 'checkpoint', version: '1.0', lookup, asOf: '2026-11-16' }),
      classifyBranch({ vendor: 'paloalto', version: null, lookup, asOf: '2026-11-16' }),
      classifyBranch({ vendor: 'paloalto', version: 'nope', lookup, asOf: '2026-11-16' }),
      classifyBranch({ vendor: 'paloalto', version: '99.9', lookup, asOf: '2026-11-16' }),
    ].map((v) => v.reason);
    for (const r of produced) assert.ok(UNKNOWN_REASONS.includes(r), `${r} must be declared`);
  });

  it('an unrecognised vendor is unknown, with a generic reason rather than a throw', () => {
    const v = classifyBranch({ vendor: 'brand_new_vendor', version: '1.2.3', lookup, asOf: '2026-11-16' });
    assert.equal(v.reason, 'product_not_covered');
    assert.match(v.sentence, /not in the branch lifecycle corpus/);
  });

  it('a missing lookup function is unknown, not a crash', () => {
    const v = classifyBranch({ vendor: 'paloalto', version: '11.1.1', asOf: '2026-11-16' });
    assert.equal(v.reason, 'branch_absent');
  });

  it('the vendor slug is trimmed and matched case-insensitively', () => {
    // `devices.vendor` is a slug by contract, but a stray case or space must
    // not silently cost a firewall its lifecycle verdict — the failure mode
    // would be "branch unknown" with nothing naming the cause.
    for (const spelling of ['paloalto', 'PaloAlto', ' PALOALTO ', 'Paloalto']) {
      const v = classifyBranch({ vendor: spelling, version: '11.1.1', lookup, asOf: '2026-11-16' });
      assert.equal(v.state, 'supported', `${JSON.stringify(spelling)} must resolve to the slug`);
    }
    // A genuinely different vendor name is still not a slug.
    const other = classifyBranch({ vendor: 'palo alto', version: '11.1.1', lookup, asOf: '2026-11-16' });
    assert.equal(other.state, 'unknown');
  });
});

describe('confidence', () => {
  it('⛔ an unrecognised confidence is the WEAKEST, never the strongest', () => {
    for (const raw of ['unverified', 'estimated', '', null, undefined, 'HIGHEST', 42]) {
      assert.equal(normaliseConfidence(raw), 'low', `${JSON.stringify(raw)} must read as low`);
      assert.equal(isVendorConfirmed(raw), false);
    }
  });

  it('is case- and whitespace-insensitive for the real values', () => {
    assert.equal(normaliseConfidence(' HIGH '), 'high');
    assert.equal(normaliseConfidence('Medium'), 'medium');
    assert.equal(isVendorConfirmed('HIGH'), true);
  });

  it('⛔ `medium` is NOT vendor-confirmed', () => {
    // Only the vendor's own published table earns the unqualified rendering.
    assert.equal(isVendorConfirmed('medium'), false);
  });
});

describe('BRANCH_CLAIM — what this feature refuses to say', () => {
  it('⛔ it says the vendor no longer COMMITS to fixes', () => {
    assert.match(BRANCH_CLAIM, /no longer carries a vendor commitment to fixes/);
    assert.match(BRANCH_CLAIM, /moving to a\s+supported branch/);
  });

  it('⛔ and it never claims a fix is IMPOSSIBLE', () => {
    // A vendor can issue an out-of-cycle fix for a dead branch under enough
    // pressure. The absolute form is an overclaim, and an overclaim an operator
    // catches us in once is how they stop trusting the honest statements beside
    // it — the same trade IMPACT_CLAIM and COVERAGE_CLAIM already make.
    for (const forbidden of [/never/i, /guarantee/i, /unpatchable/i, /impossible/i, /cannot be fixed/i]) {
      assert.ok(!forbidden.test(BRANCH_CLAIM), `BRANCH_CLAIM must not say ${forbidden}`);
    }
  });
});

describe('summariseBranchStates', () => {
  it('counts the four states and breaks unknown down BY REASON', () => {
    const s = summariseBranchStates([
      { state: 'eol' }, { state: 'eol' }, { state: 'supported' },
      { state: 'unknown', reason: 'product_not_covered' },
      { state: 'unknown', reason: 'no_version' },
      { state: 'unknown', reason: 'no_version' },
    ]);
    assert.equal(s.total, 6);
    assert.equal(s.counts.eol, 2);
    assert.equal(s.counts.unknown, 3);
    assert.equal(s.unknownByReason.no_version, 2);
    assert.equal(s.unknownByReason.product_not_covered, 1);
    assert.equal(s.unknownByReason.branch_absent, 0);
  });

  it('⛔ the unknown reasons are never summed into the other three states', () => {
    const s = summariseBranchStates([{ state: 'unknown', reason: 'no_version' }]);
    const sum = s.counts.supported + s.counts.extended_only + s.counts.eol + s.counts.unknown;
    assert.equal(sum, s.total);
    assert.equal(s.counts.supported, 0, 'an unknown must not land in supported');
  });

  it('an unrecognised state is counted as unknown, not dropped', () => {
    const s = summariseBranchStates([{ state: 'probably-fine' }, null, {}]);
    assert.equal(s.counts.unknown, 3);
    assert.equal(s.total, 3);
  });

  it('every state it reports is a declared state', () => {
    for (const k of Object.keys(summariseBranchStates([]).counts)) {
      assert.ok(BRANCH_STATES.includes(k));
    }
  });
});

describe('todayLocal', () => {
  it('⛔ formats from LOCAL parts, never toISOString()', () => {
    // CLAUDE.md records this exact trap costing every day on the compliance
    // chart a day on this product's own UTC+7 deployment. Here it would move a
    // support-end boundary, which is the whole answer on the day somebody looks.
    const d = new Date(2026, 10, 16, 1, 30, 0); // 16 Nov 2026 01:30 LOCAL
    assert.equal(todayLocal(d), '2026-11-16');
    // Under a positive UTC offset the UTC day is the PREVIOUS one, so a
    // toISOString() implementation returns 2026-11-15 and this assertion is
    // what catches it.
    if (-d.getTimezoneOffset() > 90) {
      assert.notEqual(d.toISOString().slice(0, 10), todayLocal(d));
    }
  });

  it('defaults to now and returns a YYYY-MM-DD key', () => {
    assert.match(todayLocal(), /^\d{4}-\d{2}-\d{2}$/);
  });
});

describe('⛔ sophos — a vendor the corpus does not cover', () => {
  // Real historical Sophos Firewall major.minor branches. SFOS 22.0.3 is the
  // release the adapter was verified against; the older lines matter because a
  // fleet does not upgrade all at once.
  const SFOS_BRANCHES = ['17.0', '17.1', '17.5', '18.0', '18.5', '19.0', '19.5', '20.0', '21.0', '22.0'];
  // The device's own string, stored verbatim by adapters/sophos/console.js.
  const SFOS_VERSION = 'SFOS 22.0.3 MR-3-Build576';
  const COVERED_PRODUCTS = ['PAN-OS', 'FortiOS', 'Cisco IOS-XE'];

  it('⛔ the corpus premise: exactly three products, and SFOS is not one of them', () => {
    // The measured fact the refusal rests on. If this ever fails because the
    // hub ADDED Sophos, the refusal has stopped applying and the fix is a
    // deliberate PRODUCT_FOR_VENDOR entry plus a re-derivation of branchOf
    // against SFOS's own version grammar — NOT a relaxed assertion here.
    const products = [...new Set(CORPUS.map((c) => c.product))].sort();
    assert.deepEqual(products, [...COVERED_PRODUCTS].sort(),
      'the corpus covers three products; if this changed, revisit the sophos refusal');
    assert.equal(CORPUS.filter((c) => /sophos|sfos/i.test(`${c.vendor} ${c.product}`)).length, 0,
      'the hub now publishes Sophos cycles — map the vendor deliberately');
  });

  it('⛔ sophos is NOT mapped, and is never resolved to a covered product', () => {
    assert.equal(PRODUCT_FOR_VENDOR.sophos, undefined, 'sophos must not be in the product map');
    // ⛔ THE INVARIANT IS ATTRIBUTION, NOT MENTION. The reason string names the
    // three covered products deliberately — "the corpus covers X, Y and Z only"
    // is the useful half of the sentence. What must never happen is the
    // firewall being ATTRIBUTED to one of them, so the assertions below are the
    // three verdict forms `branchSentence` can emit plus the
    // "<product> <branch>" adjacency that is the mis-attribution shape itself.
    // A blanket "must not mention PAN-OS" passed on nothing useful and failed
    // on correct code — it was a proxy for this, and the wrong one.
    const VERDICT_FORMS = [/is supported until/, /left standard support on/, /left vendor support on/];
    for (const branch of SFOS_BRANCHES) {
      const v = classifyBranch({ vendor: 'sophos', version: `${branch}.3`, lookup, asOf: '2026-11-19' });
      assert.equal(v.state, 'unknown', `SFOS ${branch} must not get a support verdict`);
      assert.equal(v.product, null, `SFOS ${branch} must not be attributed to a product`);
      assert.ok(!COVERED_PRODUCTS.includes(v.product));
      for (const form of VERDICT_FORMS) {
        assert.ok(!form.test(v.sentence), `SFOS ${branch}: sentence must not assert ${form}`);
      }
      for (const p of COVERED_PRODUCTS) {
        assert.ok(!v.sentence.includes(`${p} ${branch}`),
          `the sentence must never read "${p} ${branch}" — that is the wrong-OS verdict`);
      }
    }
  });

  it('⛔ the cisco_asa trap is ALREADY SPRUNG for sophos — SFOS 17.1/17.5 hit real IOS-XE rows', () => {
    // For an ASA the refusal can honestly say the version spaces "happen not to
    // overlap" (9.18 matches no IOS-XE cycle). For Sophos that luck has already
    // run out: these are real Sophos branches AND real Cisco IOS-XE cycles, so
    // a mapping would mis-report TODAY, not on some future release.
    const collisions = SFOS_BRANCHES
      .map((b) => ({ b, row: lookup({ vendor: 'Cisco', product: 'Cisco IOS-XE', cycle: b }) }))
      .filter((x) => x.row);
    assert.ok(collisions.length >= 2,
      'SFOS 17.1 and 17.5 collide with IOS-XE rows in the live corpus');
    assert.deepEqual(collisions.map((x) => x.b).sort(), ['17.1', '17.5']);
    // And the colliding rows carry a real, actionable-looking end date, which
    // is exactly what makes a wrong mapping dangerous rather than merely untidy.
    for (const { b, row } of collisions) {
      assert.ok(row.support_end_date, `IOS-XE ${b} states an end date`);
      // Despite the collision, the refusal holds.
      const v = classifyBranch({ vendor: 'sophos', version: `${b}.3`, lookup, asOf: '2026-11-19' });
      assert.equal(v.state, 'unknown');
      assert.equal(v.supportEnd, null, `SFOS ${b} must not inherit IOS-XE ${b}'s date`);
      assert.notEqual(v.supportEnd, row.support_end_date);
    }
  });

  it('⛔ the reason is exactly product_not_covered, and it is a DECLARED reason', () => {
    const v = classifyBranch({ vendor: 'sophos', version: SFOS_VERSION, lookup, asOf: '2026-11-19' });
    assert.equal(v.state, 'unknown');
    assert.equal(v.reason, 'product_not_covered');
    assert.ok(UNKNOWN_REASONS.includes(v.reason), 'must be one of the five named states');
    // ⛔ Never a fabricated verdict. These are the two answers that would send
    // an operator to schedule or defer an upgrade on no evidence at all.
    assert.notEqual(v.state, 'supported');
    assert.notEqual(v.state, 'eol');
    assert.notEqual(v.state, 'extended_only');
  });

  it('⛔ it is a COVERAGE reason, not a parse reason, although the version is unparseable', () => {
    // branchOf cannot read SFOS's own string, so if sophos were mapped the
    // reason would be `unreadable_version` — pointing an operator at the parser
    // instead of at the coverage gap. The product check running FIRST is what
    // keeps the reason honest.
    assert.equal(branchOf(SFOS_VERSION), null, 'the real SFOS string yields no branch');
    const v = classifyBranch({ vendor: 'sophos', version: SFOS_VERSION, lookup, asOf: '2026-11-19' });
    assert.equal(v.reason, 'product_not_covered');
    assert.notEqual(v.reason, 'unreadable_version');
    // ...and it is not reported as a collection gap either.
    assert.notEqual(v.reason, 'no_version');
  });

  it('⛔ the verdict NEVER consults the corpus, so it is structural and not luck', () => {
    // A lookup that hits on everything, and one that throws. Both must be
    // unreachable: the refusal cannot depend on what the corpus happens to hold.
    const greedy = () => ({ support_end_date: '2020-01-01', extended_end_date: '2021-01-01', confidence: 'high' });
    const hostile = () => { throw new Error('lookup must never be called for an uncovered vendor'); };
    for (const fn of [greedy, hostile]) {
      const v = classifyBranch({ vendor: 'sophos', version: SFOS_VERSION, lookup: fn, asOf: '2026-11-19' });
      assert.equal(v.state, 'unknown');
      assert.equal(v.reason, 'product_not_covered');
      assert.equal(v.supportEnd, null);
    }
  });

  it('⛔ an unknown verdict carries NO date and NO confidence', () => {
    // A date beside "unknown" is a date for nothing, and a confidence beside it
    // grades a judgement that was never made.
    for (const version of [SFOS_VERSION, '22.0.3', '17.5.1', null, '']) {
      const v = classifyBranch({ vendor: 'sophos', version, lookup, asOf: '2026-11-19' });
      assert.equal(v.state, 'unknown');
      assert.equal(v.supportEnd, null, 'no support date');
      assert.equal(v.extendedEnd, null, 'no extended date');
      assert.equal(v.confidence, null, 'no confidence');
      assert.equal(v.vendorConfirmed, false);
      assert.equal(v.vendorLink, null);
      assert.equal(v.source, null);
      assert.equal(v.lts, null, 'lts is tri-state and must stay null, never false');
      assert.equal(v.branch, null);
      // The sentence must not carry a date the fields refuse to carry.
      assert.ok(!/\d{4}-\d{2}-\d{2}/.test(v.sentence), 'the sentence states no date');
    }
  });

  it('⛔ it counts as product_not_covered in the fleet summary, never as a gap it is not', () => {
    const v = classifyBranch({ vendor: 'sophos', version: SFOS_VERSION, lookup, asOf: '2026-11-19' });
    const s = summariseBranchStates([v]);
    assert.equal(s.counts.unknown, 1);
    assert.equal(s.unknownByReason.product_not_covered, 1);
    assert.equal(s.unknownByReason.unreadable_version, 0, 'not a parser problem');
    assert.equal(s.unknownByReason.branch_absent, 0, 'not a missing-branch problem');
    assert.equal(s.counts.supported + s.counts.extended_only + s.counts.eol, 0);
  });

  it('⛔ the sentence explains WHY, rather than restating the generic fallback', () => {
    const v = classifyBranch({ vendor: 'sophos', version: SFOS_VERSION, lookup, asOf: '2026-11-19' });
    assert.ok(UNCOVERED_VENDORS.sophos, 'sophos has an explicit reason');
    assert.match(v.sentence, /SFOS/, 'it names the operating system the operator runs');
    assert.notEqual(
      v.sentence,
      'Branch support is unknown — this vendor is not in the branch lifecycle corpus.',
      'an entry that merely restates the fallback would not earn its place'
    );
  });

  it('⛔ the reason does not claim no Sophos lifecycle source EXISTS — nobody measured that', () => {
    // The checkpoint/forcepoint/sangfor entries make that claim because it was
    // established for them. Borrowing it here would be a failed read recorded
    // as a fact, in the sentence an operator reads to decide whether to ask the
    // publisher for this product.
    assert.ok(!/no machine-readable/i.test(UNCOVERED_VENDORS.sophos));
    assert.ok(!/does not (exist|publish)/i.test(UNCOVERED_VENDORS.sophos));
    // What it says instead is a statement about OUR corpus.
    assert.match(UNCOVERED_VENDORS.sophos, /corpus/i);
  });

  it('the slug is still trimmed and matched case-insensitively', () => {
    for (const spelling of ['sophos', 'Sophos', ' SOPHOS ']) {
      const v = classifyBranch({ vendor: spelling, version: SFOS_VERSION, lookup, asOf: '2026-11-19' });
      assert.equal(v.reason, 'product_not_covered');
      assert.match(v.sentence, /SFOS/, `${JSON.stringify(spelling)} must reach the explicit reason`);
    }
  });
});
