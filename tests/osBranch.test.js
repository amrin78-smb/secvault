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
  OS_BRANCH_VERSION, BRANCH_STATES, UNKNOWN_REASONS, PRODUCT_FOR_VENDOR, BRANCH_CLAIM,
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
