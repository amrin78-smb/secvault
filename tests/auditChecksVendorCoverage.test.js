'use strict';
// Guards the curated compliance library's VENDOR COVERAGE and its curated-data
// invariants (lib/auditChecksSeed.js), added 2026-11-12 alongside the first
// checkpoint / sangfor / forcepoint rows.
//
// THE SITUATION THIS CLOSES: until that change the library had 45 checks and
// vendor-scoped counts of fortinet 18, paloalto 14, cisco_asa 3 and **zero**
// for checkpoint, sangfor and forcepoint. Those three firewalls were not
// healthier, they were thinly measured — and an ABSENT check is invisible: it
// looks exactly like a concept nobody cares about, so nothing on any screen
// said the coverage was missing. A count that can silently fall back to zero
// recreates that hole.
//
// ⛔ WHY A FLOOR AND NOT JUST A COUNT. CLAUDE.md records what happened to
// tests/deviceScopeCoverage.test.js's AWARE_FLOOR: it was left at the SHIPPED
// figure (4) while the real count had grown to 6, so two surfaces could be
// demoted with the suite still green, and the named-surface assertion beside
// it covered only the original four. Both halves are needed, because a count
// alone cannot say WHICH — six other checks going gradeable while these
// regressed would satisfy a bare number. So every floor below is the REAL
// measured figure and the gradeable checks are NAMED.
//
// ⛔ AND WHY SANGFOR'S GRADEABLE FLOOR IS HONESTLY ZERO. Sangfor's
// config_parsed carries four things (hostname, version, interface names and an
// unverified tri-state ssl_vpn flag — lib/adapters/sangfor/parser.js's
// parseConfigSections), none of them a hardening setting, and no live NGAF,
// captured CLI sample or documentation trail exists anywhere in this
// repository to ground a field name against. Every Sangfor row is therefore
// `not_evaluable_from_config`: nine named, operator-readable
// manual-verification items that are EXCLUDED from the score denominator
// rather than nine fabricated findings. A zero gradeable floor is vacuous on
// its own, so the Sangfor guard works the other way round — it names the nine
// `na` rows, so deleting them (which would restore the invisible hole) fails
// the build, while ADDING a real Sangfor predicate later never does.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { CHECKS } = require('../lib/auditChecksSeed');
const { evaluateCheck } = require('../lib/engines/configAuditor');

// The six supported vendor slugs. Load-bearing per CLAUDE.md: the slug must
// match across devices.vendor, VENDOR_PARSERS, ADAPTERS, VENDOR_CPES and
// VENDOR_META, so a typo here is a check that can never match a device —
// silently, because a vendor-scoped check simply does not appear in an
// assessment rather than erroring.
const VENDOR_SLUGS = [
  'forcepoint',
  'fortinet',
  'paloalto',
  'checkpoint',
  'cisco_asa',
  'sangfor',
];

// The five standards this library scores against. CLAUDE.md forbids
// introducing a sixth (and forbids inventing a framework requirement count to
// go with one) — lib/engines/complianceCoverage.js reports a per-standard
// share of OUR OWN checks, and a standard nothing maps to would print a
// denominator of zero.
const KNOWN_STANDARDS = ['CIS_V8', 'ISO_27001', 'NIST', 'PCI_DSS', 'SANS'];

const NOT_EVALUABLE = 'not_evaluable_from_config';

// The two predicate types that deliberately carry NO pass_when, because their
// polarity is fixed ("zero matching rules is always a pass") and they are
// routed to evaluateRuleScanCheck()/evaluateRulesetPropertyCheck() rather than
// through evaluateCheck()'s pass_when guard. Every OTHER predicate type is
// evaluated by evaluateCheck(), which turns a missing or misspelled pass_when
// into a `warning` — a curated-data bug that would silently stop measuring the
// check it is attached to.
const FIXED_POLARITY_TYPES = ['rule_scan', 'ruleset_property'];

function predicateType(check) {
  return check.predicateConfig && check.predicateConfig.predicate_type;
}

function isGradeable(check) {
  return predicateType(check) !== NOT_EVALUABLE;
}

function forVendor(slug) {
  return CHECKS.filter((c) => c.vendor === slug);
}

function idsOf(checks) {
  return checks.map((c) => c.checkId).sort();
}

// ── The floors. Each is the REAL measured figure at the time it was set, not
// the figure the feature shipped with — see the header. Raising one is a CODE
// change on purpose: writing the gap down is what does not close it.
//
// When a vendor gains a genuinely gradeable check, raise its floor AND add it
// to GRADEABLE_BY_VENDOR in the SAME commit.
const VENDOR_FLOORS = {
  checkpoint: { total: 10, gradeable: 1 },
  forcepoint: { total: 10, gradeable: 1 },
  // Honestly zero — see the header. The protection for Sangfor is
  // NOT_EVALUABLE_BY_VENDOR below, not this number.
  sangfor: { total: 9, gradeable: 0 },
};

// Named, not merely counted. A future edit that demotes one of these to
// `not_evaluable_from_config` while adding an unrelated gradeable check
// elsewhere would satisfy the count and still remove the only real measurement
// this vendor has.
const GRADEABLE_BY_VENDOR = {
  checkpoint: ['checkpoint-admin-access-untrusted-zone'],
  forcepoint: ['forcepoint-admin-access-untrusted-zone'],
  sangfor: [],
};

// Sangfor's nine manual-verification items, named so they cannot be quietly
// deleted. Deleting them restores the invisible coverage hole this whole change
// exists to close; converting one into a REAL predicate is an improvement and
// is handled by the gradeable floor above, not here.
const NOT_EVALUABLE_BY_VENDOR = {
  sangfor: [
    'sangfor-admin-access-untrusted-zone',
    'sangfor-dns-configured',
    'sangfor-https-only-not-http',
    'sangfor-logging-enabled',
    'sangfor-ntp-configured',
    'sangfor-password-min-length',
    'sangfor-session-timeout',
    'sangfor-ssh-mgmt-untrusted-iface',
    'sangfor-sslvpn-posture',
  ],
};

describe('audit check library — curated-data invariants', () => {
  it('every check carries a real vendor slug or null', () => {
    for (const check of CHECKS) {
      const ok = check.vendor === null || check.vendor === undefined
        ? true
        : VENDOR_SLUGS.includes(check.vendor);
      assert.equal(
        ok,
        true,
        `${check.checkId}: vendor "${check.vendor}" is not one of the six supported slugs ` +
          `(${VENDOR_SLUGS.join(', ')}) — a vendor-scoped check with an unknown slug never ` +
          'matches a device and fails silently.'
      );
    }
  });

  it('no two checks share a checkId', () => {
    const seen = new Map();
    for (const check of CHECKS) {
      assert.equal(
        seen.has(check.checkId),
        false,
        `duplicate checkId "${check.checkId}" — seedAuditChecks() upserts ON CONFLICT ` +
          '(check_id) DO UPDATE, so a duplicate means the LATER row silently overwrites the ' +
          'earlier one and one of the two concepts disappears from the library with no error.'
      );
      seen.set(check.checkId, true);
    }
    assert.equal(seen.size, CHECKS.length);
  });

  it('every checkId is a non-empty slug and every check has a name', () => {
    for (const check of CHECKS) {
      assert.match(check.checkId, /^[a-z0-9][a-z0-9-]*$/, `${check.checkId}: not a stable slug`);
      assert.equal(typeof check.name, 'string');
      assert.equal(check.name.trim().length > 0, true, `${check.checkId}: empty name`);
    }
  });

  it('pass_when is exactly "yes" or "no" on every check evaluateCheck() grades', () => {
    for (const check of CHECKS) {
      if (FIXED_POLARITY_TYPES.includes(predicateType(check))) continue;
      const passWhen = check.predicateConfig.pass_when;
      assert.equal(
        passWhen === 'yes' || passWhen === 'no',
        true,
        `${check.checkId}: pass_when is ${JSON.stringify(passWhen)}. It decides which ` +
          'predicate outcome means PASS, so a missing or misspelled value makes ' +
          'evaluateCheck() return `warning` for every device — the check stops measuring ' +
          'anything while still appearing in the library.'
      );
    }
  });

  it('the two fixed-polarity predicate types deliberately carry no pass_when', () => {
    const fixed = CHECKS.filter((c) => FIXED_POLARITY_TYPES.includes(predicateType(c)));
    assert.equal(fixed.length > 0, true, 'expected rule_scan/ruleset_property checks to exist');
    for (const check of fixed) {
      assert.equal(
        check.predicateConfig.pass_when,
        undefined,
        `${check.checkId}: a ${predicateType(check)} check has a fixed polarity, so a ` +
          'pass_when here is dead curated data that reads as if it were consulted.'
      );
    }
  });

  it('every check maps to at least one standard, and only to the five known ones', () => {
    for (const check of CHECKS) {
      assert.equal(
        Array.isArray(check.standards) && check.standards.length > 0,
        true,
        `${check.checkId}: no standards mapped — it would be invisible in every per-standard score.`
      );
      for (const standard of check.standards) {
        assert.equal(
          KNOWN_STANDARDS.includes(standard),
          true,
          `${check.checkId}: unknown standard "${standard}". Only ${KNOWN_STANDARDS.join(', ')} ` +
            'are scored; a sixth would print a per-standard figure nothing else in the product ' +
            'can explain.'
        );
      }
    }
  });

  it('every not_evaluable_from_config check carries a non-empty reason', () => {
    const naChecks = CHECKS.filter((c) => !isGradeable(c));
    assert.equal(naChecks.length > 0, true, 'expected not_evaluable_from_config checks to exist');
    for (const check of naChecks) {
      const reason = check.predicateConfig.reason;
      assert.equal(
        typeof reason === 'string' && reason.trim().length > 0,
        true,
        `${check.checkId}: no reason. configAuditor.evaluateCheck() surfaces the reason in the ` +
          'finding detail, so without one the operator is shown a manual-verification item with ' +
          'nothing saying what to verify or why SecVault could not.'
      );
    }
  });

  it('a not_evaluable_from_config check really does resolve to na, not warning', () => {
    // Pins the WHOLE POINT of these rows against the engine rather than
    // against their own shape: `na` is excluded from the score denominator,
    // `warning` counts toward it. If this ever regressed, 27 of the 29 new
    // rows would start scoring three vendors down for SecVault's own coverage
    // gap — the hit_count NOT NULL DEFAULT 0 bug, wearing a compliance hat.
    const sample = CHECKS.filter((c) => !isGradeable(c)).slice(0, 5);
    assert.equal(sample.length, 5);
    for (const check of sample) {
      const result = evaluateCheck(
        { name: check.name, check_id: check.checkId, predicate_config: check.predicateConfig },
        { some: 'collected config' }
      );
      assert.equal(result.status, 'na', `${check.checkId} should resolve na`);
      assert.match(result.detail, /excluded/, `${check.checkId}: detail should say it is excluded`);
    }
  });
});

describe('audit check library — vendor coverage floors', () => {
  it('all six supported vendors have at least one vendor-scoped check', () => {
    for (const slug of VENDOR_SLUGS) {
      assert.equal(
        forVendor(slug).length > 0,
        true,
        `vendor "${slug}" has no vendor-scoped checks at all. A firewall with no vendor checks ` +
          'is not healthier than its neighbours, it is thinly measured — and an absent check is ' +
          'invisible, which is the hole this guard exists to keep closed.'
      );
    }
  });

  for (const [slug, floor] of Object.entries(VENDOR_FLOORS)) {
    it(`${slug}: at least ${floor.total} checks, at least ${floor.gradeable} gradeable`, () => {
      const checks = forVendor(slug);
      assert.equal(
        checks.length >= floor.total,
        true,
        `${slug} has ${checks.length} checks, floor is ${floor.total}. Lowering it removes ` +
          'named manual-verification items and makes the coverage gap invisible again.'
      );
      const gradeable = checks.filter(isGradeable);
      assert.equal(
        gradeable.length >= floor.gradeable,
        true,
        `${slug} has ${gradeable.length} gradeable checks, floor is ${floor.gradeable}. ` +
          'Raising a floor is a code change on purpose — when a vendor gains a gradeable ' +
          'check, raise it AND name the check in GRADEABLE_BY_VENDOR in the same commit.'
      );
    });
  }

  for (const [slug, named] of Object.entries(GRADEABLE_BY_VENDOR)) {
    it(`${slug}: the named gradeable checks are still gradeable`, () => {
      const gradeable = idsOf(forVendor(slug).filter(isGradeable));
      for (const checkId of named) {
        assert.equal(
          gradeable.includes(checkId),
          true,
          `${checkId} is no longer a gradeable ${slug} check. A count alone cannot say WHICH: ` +
            'another check going gradeable elsewhere would satisfy the floor while this ' +
            "vendor's only real measurement was demoted."
        );
      }
      // The reverse direction too: an unnamed gradeable check means the
      // floor and the names have drifted apart, which is exactly how
      // AWARE_FLOOR went stale for three releases.
      for (const checkId of gradeable) {
        assert.equal(
          named.includes(checkId),
          true,
          `${checkId} is a gradeable ${slug} check but is not named in GRADEABLE_BY_VENDOR. ` +
            'Add it there and raise the floor in the same commit.'
        );
      }
    });
  }

  for (const [slug, named] of Object.entries(NOT_EVALUABLE_BY_VENDOR)) {
    it(`${slug}: the named manual-verification items are still present`, () => {
      const ids = idsOf(forVendor(slug));
      for (const checkId of named) {
        assert.equal(
          ids.includes(checkId),
          true,
          `${checkId} has been removed. These rows are what makes ${slug}'s coverage gap ` +
            'visible and counted; deleting one returns it to being invisible. Converting it ' +
            'into a real predicate is an improvement and is covered by the gradeable floor ' +
            'instead.'
        );
      }
    });
  }

  it('the gradeable checks for the three thin vendors use a miss-safe predicate', () => {
    // ⛔ THE ONE PROPERTY THAT MAKES THOSE TWO ROWS HONEST. Every path-lookup
    // predicate (config_key_exists / config_value_equals / config_value_matches
    // / feature_enabled) maps an UNRESOLVED path to 'no', so with pass_when
    // 'yes' it is a confident FAIL — SecVault's own collection gap recorded as
    // a fact about the customer's firewall. admin_access_from_zone returns
    // found ? 'yes' : 'unknown' (lib/engines/applicability.js), so a wrong
    // zone literal or an unexpected config shape degrades to `warning`, never
    // to a fabricated finding. None of these three vendors has a live device
    // anywhere in this deployment, so a gradeable check on a guessed path
    // would be exactly that fabrication.
    const MISS_SAFE = ['admin_access_from_zone', 'port_exposed'];
    for (const slug of ['checkpoint', 'sangfor', 'forcepoint']) {
      for (const check of forVendor(slug).filter(isGradeable)) {
        assert.equal(
          MISS_SAFE.includes(predicateType(check)),
          true,
          `${check.checkId} uses "${predicateType(check)}", whose miss resolves to 'no'. ` +
            `No live ${slug} device exists in this deployment to confirm a field path against, ` +
            'so this would report a confident FAIL wherever the path was simply never ' +
            'collected. Either ground the path against live output and record that here, or ' +
            'make the row not_evaluable_from_config with a reason.'
        );
      }
    }
  });

  it('the three thin vendors are still graded by the vendor-null rule checks', () => {
    // Why their scores are not empty: the rule_scan / ruleset_property checks
    // read already-normalised firewall_rules / rule_analysis_results rows and
    // carry vendor: null, so they apply to every vendor regardless of what its
    // config_parsed holds. If these ever became vendor-scoped, the three thin
    // vendors would have nothing left to score on at all.
    const shared = CHECKS.filter((c) => FIXED_POLARITY_TYPES.includes(predicateType(c)));
    assert.equal(shared.length >= 10, true, `expected >= 10 shared rule checks, got ${shared.length}`);
    for (const check of shared) {
      assert.equal(
        check.vendor === null || check.vendor === undefined,
        true,
        `${check.checkId} is a ${predicateType(check)} check scoped to "${check.vendor}". ` +
          'These are the only checks that grade checkpoint/sangfor/forcepoint devices today; ' +
          'scoping one to a vendor removes it from the other five.'
      );
    }
  });
});
