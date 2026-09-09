'use strict';
// Pins the three 2026-09-09 fixes for one bug class: SecVault answering
// "nothing found" to a question it never actually asked.
//
// All three shipped confidently-wrong values that passed every static check:
//
//   1. lib/feeds/nvd.js       — an advisory whose version ranges could not be extracted was
//                               stored with affected_version_ranges = [], which versionMatcher
//                               reads as an affirmative "this device is not affected".
//   2. lib/engines/configAuditor.js — a rule_scan compliance check reported PASS for an O(n^2)
//                               analysis ruleAnalysis.js deliberately skipped, and that pass
//                               COUNTED in the score denominator.
//   3. lib/engines/ruleAnalysis.js — `unused` fired on a device-reported hit_count of 0 even
//                               when SecVault's own syslog recorded traffic on that rule.
//
// Every case below therefore includes the "we could not measure this" state, not just the
// pass and fail states — that is the one that regresses silently, because the wrong answer is
// a plausible value rather than a crash.
//
// ⛔ The CVE fixtures are the SHAPE OF REAL RECORDS read off the live corpus (CVE-2019-6696,
// CVE-2026-20025, CVE-2023-30806 and the Fortinet sibling-product rows), not invented ones —
// per CLAUDE.md's "documentation lies" rule, the product strings are exactly what CIRCL
// returns, including "Cisco Secure Firewall Adaptive Security Appliance (ASA) Software" and
// Sangfor's own "Net-Gen Application Firewall".

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  VENDOR_CPES,
  cpePrefixes,
  matchingAffectedEntriesFromCveRecord,
  extractAffectedRangesFromCveRecord,
  classifyCveRecordMatchability,
} = require('../lib/feeds/nvd');
const { evaluateRuleScanCheck } = require('../lib/engines/configAuditor');
const {
  analyzeRules,
  PAIRWISE_FINDING_TYPES,
  skippedPairwiseFindingTypes,
  DEFAULT_OPTIONS,
} = require('../lib/engines/ruleAnalysis');

const FORTINET = cpePrefixes(VENDOR_CPES.fortinet);
const CISCO = cpePrefixes(VENDOR_CPES.cisco_asa);
const PALOALTO = cpePrefixes(VENDOR_CPES.paloalto);
const SANGFOR = cpePrefixes(VENDOR_CPES.sangfor);

// Minimal CVE Record Format 5.x envelope around one or more affected[] entries.
function record(affected) {
  return { cveMetadata: { cveId: 'CVE-0000-0000' }, containers: { cna: { affected } } };
}

function affectedEntry(vendor, product, versions) {
  return { vendor, product, versions: versions || [{ status: 'affected', version: '1.0.0' }] };
}

function productsMatched(rec, prefixes) {
  return matchingAffectedEntriesFromCveRecord(rec, prefixes).map((e) => e.product);
}

describe('nvd.js: CVE-Record vendor/product fallback', () => {
  it('matches the real product strings that exact equality never could', () => {
    // Live spellings. Under the old exact-equality rule NONE of these matched the CPE product
    // token, which is why 100% of cisco_asa/checkpoint/sangfor/forcepoint advisories and 108
    // fortinet ones carried empty affected_version_ranges.
    const cases = [
      [FORTINET, 'Fortinet', 'Fortinet FortiOS'],
      [FORTINET, 'Fortinet, Inc.', 'FortiOS'],
      [FORTINET, 'Fortinet', 'Fortinet FortiOS, FortiProxy'],
      [FORTINET, 'Fortinet', 'Fortinet FortiSwitch, FortiRecorder, FortiVoiceEnterprise, FortiOS, FortiProxy'],
      [CISCO, 'Cisco', 'Cisco Adaptive Security Appliance (ASA) Software'],
      [CISCO, 'Cisco', 'Cisco Secure Firewall Adaptive Security Appliance (ASA) Software'],
      [PALOALTO, 'Palo Alto Networks', 'PAN-OS'],
      [PALOALTO, 'n/a', 'Palo Alto Networks PAN-OS'],
    ];
    for (const [prefixes, vendor, product] of cases) {
      const rec = record([affectedEntry(vendor, product)]);
      assert.deepEqual(productsMatched(rec, prefixes), [product], `should match: ${product}`);
    }
  });

  it('⛔ still refuses every sibling product in the same corpus', () => {
    // Widening past the real product is the OPPOSITE failure and just as bad: it would attach
    // another product's version ranges to this vendor's firewalls, fabricating a vulnerability.
    // Every string here is live, sitting in the same CIRCL responses as the matches above.
    const rejects = [
      [FORTINET, 'Fortinet', 'FortiAnalyzer'],
      [FORTINET, 'Fortinet', 'FortiManager'],
      [FORTINET, 'Fortinet', 'FortiWeb'],
      [FORTINET, 'Fortinet', 'FortiVoice'],
      [FORTINET, 'Fortinet', 'FortiRecorder'],
      [FORTINET, 'Fortinet', 'FortiSandbox'],
      [FORTINET, 'Fortinet', 'FortiClient for Windows'],
      [FORTINET, 'Fortinet', 'Fortinet FortiProxy'],
      [CISCO, 'Cisco', 'Cisco Firepower Threat Defense Software'],
      [CISCO, 'Cisco', 'Cisco Secure Firewall Threat Defense (FTD) Software'],
      [CISCO, 'Cisco', 'Cisco IOS XR Software'],
      [PALOALTO, 'Palo Alto Networks', 'Prisma Access'],
      [PALOALTO, 'Palo Alto Networks', 'Cortex XDR Agent'],
      [PALOALTO, 'Palo Alto Networks', 'Panorama'],
      [PALOALTO, 'Palo Alto Networks', 'GlobalProtect App'],
    ];
    for (const [prefixes, vendor, product] of rejects) {
      const rec = record([affectedEntry(vendor, product)]);
      assert.deepEqual(productsMatched(rec, prefixes), [], `must NOT match: ${product}`);
    }
  });

  it('takes only the matching entry out of a multi-product record', () => {
    const rec = record([
      affectedEntry('Fortinet', 'FortiManager'),
      affectedEntry('Fortinet', 'Fortinet FortiOS'),
      affectedEntry('OpenSSL', 'OpenSSL'),
    ]);
    assert.deepEqual(productsMatched(rec, FORTINET), ['Fortinet FortiOS']);
  });

  it('⛔ never lets a placeholder product stand in for a real one', () => {
    // 166 live cisco_asa records are literally vendor 'n/a' / product 'n/a'. A placeholder is
    // the absence of an answer; treating it as a match would attach an arbitrary advisory to
    // this vendor's devices.
    for (const product of ['n/a', 'unknown', '', 'unspecified']) {
      const rec = record([affectedEntry('n/a', product)]);
      assert.deepEqual(productsMatched(rec, CISCO), [], `placeholder must not match: "${product}"`);
    }
  });

  it('rejects another organisation’s product bundled into the same advisory', () => {
    const rec = record([affectedEntry('The Linux Foundation', 'kernel')]);
    assert.deepEqual(productsMatched(rec, PALOALTO), []);
  });

  it('extracts real ranges from a live-shaped FortiOS record', () => {
    const rec = record([
      affectedEntry('Fortinet', 'Fortinet FortiOS', [
        { status: 'affected', version: '6.2.1' },
        { status: 'affected', version: '6.2.0' },
      ]),
    ]);
    const ranges = extractAffectedRangesFromCveRecord(rec, 'fortinet', FORTINET);
    assert.equal(ranges.length, 2);
    assert.equal(ranges[0].min, '6.2.1');
  });
});

describe('nvd.js: classifyCveRecordMatchability — empty ranges must never mean "not affected"', () => {
  it('stores a record whose ranges were actually extracted', () => {
    const rec = record([affectedEntry('Fortinet', 'Fortinet FortiOS')]);
    const ranges = extractAffectedRangesFromCveRecord(rec, 'fortinet', FORTINET);
    assert.ok(ranges.length > 0);
    assert.equal(classifyCveRecordMatchability(rec, FORTINET, ranges).status, 'matched');
  });

  it('⛔ refuses to store a record that DECLARES affected versions we could not parse', () => {
    // The load-bearing case. "All versions"/config-scenario text is rejected by looksLikeVersion,
    // so extraction yields nothing — but the record plainly says this product is affected.
    // Storing [] here would read as an affirmative "not affected" for every device.
    const rec = record([
      affectedEntry('Fortinet', 'Fortinet FortiOS', [{ status: 'affected', version: 'All' }]),
    ]);
    const ranges = extractAffectedRangesFromCveRecord(rec, 'fortinet', FORTINET);
    assert.deepEqual(ranges, []);
    const verdict = classifyCveRecordMatchability(rec, FORTINET, ranges);
    assert.equal(verdict.status, 'unmatchable');
    assert.match(verdict.reason, /no version range could be extracted/);
  });

  it('skips a sibling product’s advisory instead of filing it under this product', () => {
    const rec = record([affectedEntry('Palo Alto Networks', 'Prisma Access')]);
    const verdict = classifyCveRecordMatchability(rec, PALOALTO, []);
    assert.equal(verdict.status, 'other_product');
  });

  it('⛔ reports, not silently skips, a record that identifies no product at all', () => {
    // vendor 'n/a' / product 'n/a' is not evidence that the advisory belongs to someone else.
    // Claiming "other product" there would be a conclusion we cannot support.
    const rec = record([affectedEntry('n/a', 'n/a', [{ status: 'affected', version: 'n/a' }])]);
    assert.equal(classifyCveRecordMatchability(rec, CISCO, []).status, 'unmatchable');
  });

  it('keeps an honestly-empty record: the source says this product is NOT affected', () => {
    // Matching entry, no affected version declared anywhere in it. Empty ranges are the source's
    // own answer here, not a failed read — so this row is safe to store.
    const rec = record([
      affectedEntry('Fortinet', 'Fortinet FortiOS', [{ status: 'unaffected', version: '7.4.9' }]),
    ]);
    assert.equal(classifyCveRecordMatchability(rec, FORTINET, []).status, 'matched');
  });

  it('does not fuzzy-match a product name the vendor spells differently', () => {
    // Live: Sangfor's own record says "Net-Gen Application Firewall" while NVD's CPE dictionary
    // says next-gen_application_firewall. Guessing across that gap is exactly the fabrication
    // this matcher must not do — it stays unstored rather than becoming a Sangfor advisory with
    // ranges that were never verified.
    const rec = record([
      affectedEntry('Sangfor', 'Net-Gen Application Firewall', [
        { status: 'affected', version: '8.0.17' },
      ]),
    ]);
    assert.deepEqual(productsMatched(rec, SANGFOR), []);
    assert.notEqual(classifyCveRecordMatchability(rec, SANGFOR, []).status, 'matched');
  });
});

describe('configAuditor: a skipped O(n^2) pass is `na`, never `pass`', () => {
  const check = {
    check_id: 'rule-no-shadowed-rules',
    name: 'No shadowed rules',
    predicate_config: { predicate_type: 'rule_scan', finding_types: ['shadow'] },
  };

  it('still passes when the pass RAN and found nothing', () => {
    assert.equal(evaluateRuleScanCheck(check, {}, []).status, 'pass');
  });

  it('still fails when the pass ran and matched rules', () => {
    const out = evaluateRuleScanCheck(check, { shadow: ['r1', 'r2'] }, []);
    assert.equal(out.status, 'fail');
    assert.deepEqual(out.matchedRuleIds, ['r1', 'r2']);
  });

  it('⛔ returns `na` — not `pass` — when the pass was never run', () => {
    // SecVault's own O(n^2) cap is a fact about SECVAULT, so it leaves the score denominator
    // entirely. A `pass` would credit the device for an analysis nobody performed; a `warning`
    // would penalise it for our limitation. Both are wrong in opposite directions.
    const out = evaluateRuleScanCheck(check, {}, PAIRWISE_FINDING_TYPES);
    assert.equal(out.status, 'na');
    assert.deepEqual(out.matchedRuleIds, []);
    assert.match(out.detail, /NOT MEASURED/);
  });

  it('⛔ `na` even when only PART of the check’s finding_types was skipped', () => {
    const both = {
      check_id: 'rule-no-redundant-rules',
      name: 'No redundant rules',
      predicate_config: { predicate_type: 'rule_scan', finding_types: ['redundant', 'any_any'] },
    };
    assert.equal(evaluateRuleScanCheck(both, {}, ['redundant']).status, 'na');
  });

  it('leaves checks on non-pairwise finding types untouched', () => {
    const anyAny = {
      check_id: 'rule-no-any-any-allow',
      name: 'No any-any allow rules',
      predicate_config: { predicate_type: 'rule_scan', finding_types: ['any_any'] },
    };
    assert.equal(evaluateRuleScanCheck(anyAny, {}, PAIRWISE_FINDING_TYPES).status, 'pass');
  });

  it('keeps the curated-data guard ahead of everything (empty finding_types -> warning)', () => {
    const broken = { check_id: 'x', name: 'x', predicate_config: { predicate_type: 'rule_scan' } };
    assert.equal(evaluateRuleScanCheck(broken, {}, PAIRWISE_FINDING_TYPES).status, 'warning');
  });

  it('is unchanged for callers that pass no skipped list at all', () => {
    assert.equal(evaluateRuleScanCheck(check, {}).status, 'pass');
  });
});

describe('ruleAnalysis: skippedPairwiseFindingTypes', () => {
  it('reports nothing skipped at or below the cap, everything above it', () => {
    const cap = DEFAULT_OPTIONS.maxRulesForShadow;
    assert.deepEqual(skippedPairwiseFindingTypes(cap), []);
    assert.deepEqual(skippedPairwiseFindingTypes(cap + 1), PAIRWISE_FINDING_TYPES.slice());
  });

  it('covers exactly the finding types produced inside the pairwise block', () => {
    assert.deepEqual(PAIRWISE_FINDING_TYPES.slice(), [
      'shadow',
      'redundant',
      'correlation',
      'generalization',
      'reorder_candidate',
    ]);
  });
});

describe('ruleAnalysis: `unused` must yield to contradicting log evidence', () => {
  function rule(overrides) {
    return Object.assign(
      {
        id: 'r1',
        rule_name: 'rule-1',
        sequence_number: 1,
        action: 'allow',
        enabled: true,
        src_addresses: ['10.0.0.0/8'],
        dst_addresses: ['10.1.0.0/16'],
        services: ['TCP/443'],
        log_enabled: true,
        hit_count: 0,
      },
      overrides
    );
  }

  const unusedIn = (findings) => findings.filter((f) => f.finding_type === 'unused');

  it('still reports a device-measured zero with no contradicting evidence', async () => {
    const findings = await analyzeRules([rule({})], {});
    assert.equal(unusedIn(findings).length, 1);
  });

  it('⛔ suppresses `unused` when syslog recorded hits on that rule', async () => {
    // Live: 6 rules on TSR_EKC report hit_count = 0 while carrying up to 126,300 logged hits,
    // and the stored finding says "has zero recorded hits". A counter is a claim; a log line is
    // an observation — when they disagree the honest output is NO finding.
    const findings = await analyzeRules(
      [rule({ hit_count: 0, logEvidence: 'hits', loggedHits: 126300 })],
      {}
    );
    assert.deepEqual(unusedIn(findings), []);
  });

  it('⛔ suppresses it for the log-derived zero path too', async () => {
    const findings = await analyzeRules(
      [rule({ hit_count: null, logEvidence: 'hits', loggedHits: 5 })],
      {}
    );
    assert.deepEqual(unusedIn(findings), []);
  });

  it('does NOT suppress on a weaker/absent log state — that is unmeasured, not a contradiction', async () => {
    for (const evidence of ['no-coverage', 'window-too-short', 'rule-logging-disabled', undefined]) {
      const findings = await analyzeRules(
        [rule({ hit_count: 0, logEvidence: evidence, loggedHits: null })],
        {}
      );
      assert.equal(unusedIn(findings).length, 1, `evidence=${evidence}`);
    }
  });

  it('does not suppress on a log-measured zero (both sources agree it is unused)', async () => {
    const findings = await analyzeRules(
      [rule({ hit_count: null, logEvidence: 'measured-zero', loggedHits: 0 })],
      {}
    );
    assert.equal(unusedIn(findings).length, 1);
  });

  it('⛔ a NULL hit count with no log evidence is still never `unused`', async () => {
    // The original tri-state rule: a vendor that cannot report hit counts has not measured zero.
    const findings = await analyzeRules([rule({ hit_count: null })], {});
    assert.deepEqual(unusedIn(findings), []);
  });
});
