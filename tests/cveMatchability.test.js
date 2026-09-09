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
  CURATED_PRODUCT_ALIASES,
  cpePrefixes,
  matchingAffectedEntriesFromCveRecord,
  extractAffectedRangesFromCveRecord,
  classifyCveRecordMatchability,
  classifyNvdNativeMatchability,
  parseProseVersionRange,
} = require('../lib/feeds/nvd');
const {
  matchDeviceToAdvisories,
  countUnassessableAdvisories,
} = require('../lib/engines/versionMatcher');
const { backfillAdvisoryMatchability } = require('../lib/migrate');
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

  it('matches Sangfor NGAF through the CURATED alias, and extracts its real range', () => {
    // ⛔ Live: Sangfor's own CNA records (all 5 of them, CVE-2023-30802 … CVE-2023-30806) say
    // "Net-Gen Application Firewall" while NVD's CPE dictionary says
    // next-gen_application_firewall. One product, two spellings, one letter apart.
    //
    // This match comes from CURATED_PRODUCT_ALIASES — an audited table — and NOT from fuzzy
    // string distance. That distinction is the whole safety property: 'net-gen' is one edit
    // from 'next-gen', and a distance threshold loose enough to bridge it is loose enough to
    // attach some other product's advisory to a device.
    const rec = record([
      affectedEntry('Sangfor', 'Net-Gen Application Firewall', [
        { status: 'affected', version: '8.0.17' },
      ]),
    ]);
    assert.deepEqual(productsMatched(rec, SANGFOR), ['Net-Gen Application Firewall']);
    const ranges = extractAffectedRangesFromCveRecord(rec, 'sangfor', SANGFOR);
    assert.deepEqual(
      ranges.map((r) => [r.min, r.max]),
      [['8.0.17', '8.0.17']]
    );
    assert.equal(classifyCveRecordMatchability(rec, SANGFOR, ranges).status, 'matched');
  });

  it('⛔ the alias is an ALIAS TABLE, not a similarity threshold', () => {
    // Everything here is as "close" to next-gen_application_firewall as Net-Gen is, or closer
    // in the ways a fuzzy matcher measures. None of it is in the table, so none of it matches.
    const rejects = [
      'Nxt-Gen Application Firewall',   // also one edit from the CPE token — and not in the table
      'Net Gen Application Gateway',
      'Sangfor VDI Client',             // the vendor's other CPE — deliberately not queried at all
      'Application Firewall',
      'NGAF',
    ];
    for (const product of rejects) {
      const rec = record([affectedEntry('Sangfor', product)]);
      assert.deepEqual(productsMatched(rec, SANGFOR), [], `must NOT match: ${product}`);
    }
    // ...and the alias must never leak across vendors: it is registered under Sangfor's CPE
    // product token, so no other vendor's prefixes can pick it up.
    const ngaf = record([affectedEntry('Sangfor', 'Net-Gen Application Firewall')]);
    for (const prefixes of [FORTINET, CISCO, PALOALTO]) {
      assert.deepEqual(productsMatched(ngaf, prefixes), []);
    }
  });

  it('every curated alias entry is keyed to a real CPE product token', () => {
    // Guards the table against a typo'd key, which would silently do nothing forever.
    const knownProducts = new Set(
      Object.values(VENDOR_CPES)
        .flat()
        .map((cpe) => cpe.split(':')[4].toLowerCase().replace(/[^a-z0-9]/g, ''))
    );
    for (const key of Object.keys(CURATED_PRODUCT_ALIASES)) {
      assert.ok(knownProducts.has(key), `alias key "${key}" matches no VENDOR_CPES product`);
    }
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

describe('nvd.js: classifyNvdNativeMatchability — the same rule on the NVD-native path', () => {
  // ⛔ This path was checked before it was changed, per the "report the finding rather than
  // inventing work" rule. The ambiguity IS present here: extractAffectedRanges() explicitly
  // `continue`s on a cpeMatch that is vulnerable:true for our product but carries no version
  // bound and no usable version in its criteria — its own comment calls that "missing data" —
  // and the record was then stored with [] anyway.
  const nvdRecord = (cpeMatch) => ({ id: 'CVE-0000-0000', configurations: [{ nodes: [{ cpeMatch }] }] });
  const OURS = 'cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*';
  const THEIRS = 'cpe:2.3:a:fortinet:fortianalyzer:*:*:*:*:*:*:*:*';

  it('stores a record whose ranges were extracted', () => {
    const rec = nvdRecord([{ criteria: OURS, vulnerable: true, versionEndExcluding: '7.4.5' }]);
    assert.equal(
      classifyNvdNativeMatchability(rec, FORTINET, [{ min: null, max: '7.4.5' }]).status,
      'matched'
    );
  });

  it('⛔ refuses to store a cpeMatch that says vulnerable with no derivable bound', () => {
    const rec = nvdRecord([{ criteria: OURS, vulnerable: true }]);
    const verdict = classifyNvdNativeMatchability(rec, FORTINET, []);
    assert.equal(verdict.status, 'unmatchable');
    assert.match(verdict.reason, /no version bound/);
  });

  it('keeps an honestly-empty record: our product listed only as NOT vulnerable', () => {
    const rec = nvdRecord([{ criteria: OURS, vulnerable: false }]);
    assert.equal(classifyNvdNativeMatchability(rec, FORTINET, []).status, 'matched');
  });

  it('skips a sibling product’s applicability statement', () => {
    const rec = nvdRecord([{ criteria: THEIRS, vulnerable: true, versionEndExcluding: '7.0.0' }]);
    assert.equal(classifyNvdNativeMatchability(rec, FORTINET, []).status, 'other_product');
  });

  it('⛔ a record with no CPE applicability data at all is unmatchable, not "not affected"', () => {
    assert.equal(
      classifyNvdNativeMatchability({ id: 'CVE-0000-0000' }, FORTINET, []).status,
      'unmatchable'
    );
  });
});

describe('nvd.js: prose version bounds — widen to the source’s words, never guess', () => {
  // ⛔ These strings are live, off the corpus. They were being stored as {min:"5.6.7 and
  // below", max:"5.6.7 and below"}, which parseVersion collapses to the single point 5.6.7 —
  // an UNDER-report. Under-reporting is the safe direction, which is why the fix may only
  // widen to what the sentence literally says.
  it('reads the three whitelisted shapes', () => {
    assert.deepEqual(parseProseVersionRange('5.6.7 and below'), { min: null, max: '5.6.7' });
    assert.deepEqual(parseProseVersionRange('5.2 and below versions'), { min: null, max: '5.2.999' });
    assert.deepEqual(parseProseVersionRange('5.2 and all earlier versions.'), { min: null, max: '5.2.999' });
    assert.deepEqual(parseProseVersionRange('6.4.0 - 6.4.6'), { min: '6.4.0', max: '6.4.6' });
    assert.deepEqual(parseProseVersionRange('5.2.0 to 5.2.12'), { min: '5.2.0', max: '5.2.12' });
    assert.deepEqual(parseProseVersionRange('5.2 all versions'), { min: '5.2', max: '5.2.999' });
  });

  it('⛔ refuses every multi-clause sentence — that is where a bound belongs to another product', () => {
    // Pulling "7.0.2 and below" out of the FortiSwitch string means deciding from prose which
    // clause is FortiOS's. Guessing there applies another product's ceiling to this one, which
    // is the fabrication direction. These keep today's narrow, under-reporting behaviour.
    const leaveAlone = [
      'FortiSwitch 7.0.2 and below, 6.4.9 and below, 6.2.x, 6.0.x; FortiOS 7.0.2 and below',
      'FortiGate 6.0.0 through 6.0.4, 5.6.0 through 5.6.7, 5.2 and earlier and FortiProxy versions 2.0.0',
      'FortiOS 6.0.7 and below',
      'FortiOS before 7.0.1',
      '6.0.8 and below until 5.4.0',
      '5.0.0-5.0.14, 5.2.0-5.2.10',
      '5.0.x, 5.2.x',
      'All',
      'n/a',
      'unspecified',
      '',
    ];
    for (const s of leaveAlone) {
      assert.equal(parseProseVersionRange(s), null, `must not parse: ${s}`);
    }
    assert.equal(parseProseVersionRange(null), null);
    assert.equal(parseProseVersionRange(undefined), null);
  });

  it('a plain version string is not prose and is untouched', () => {
    for (const s of ['8.0.17', '7.4.9', '10.1.14-h11', 'v6.2.0']) {
      assert.equal(parseProseVersionRange(s), null, `must not parse: ${s}`);
    }
  });

  it('turns the collapsed point into the range the record actually stated', () => {
    const rec = record([
      affectedEntry('Fortinet', 'Fortinet FortiOS', [{ status: 'affected', version: '5.6.7 and below' }]),
    ]);
    const ranges = extractAffectedRangesFromCveRecord(rec, 'fortinet', FORTINET);
    assert.deepEqual(ranges.map((r) => [r.min, r.max]), [[null, '5.6.7']]);
  });

  it('⛔ a structured lessThan always outranks the sentence', () => {
    const rec = record([
      affectedEntry('Fortinet', 'Fortinet FortiOS', [
        { status: 'affected', version: '5.6.0 to 5.6.2', lessThan: '5.6.9' },
      ]),
    ]);
    const ranges = extractAffectedRangesFromCveRecord(rec, 'fortinet', FORTINET);
    assert.deepEqual(ranges.map((r) => [r.min, r.max, r.exclude_fixed]), [['5.6.0', '5.6.9', true]]);
  });
});

describe('versionMatcher: an unmatchable advisory is never an assessment, in either direction', () => {
  const device = { id: 'd1', name: 'fw1', vendor: 'fortinet' };
  const tuple = [6, 0, 0, 0];
  const advisory = (over) =>
    Object.assign(
      { id: 'a1', affected_version_ranges: [{ min: '5.0.0', max: '7.0.0' }], fixed_in_versions: [] },
      over
    );

  it('still assesses a normal matching advisory', () => {
    const out = matchDeviceToAdvisories(device, tuple, [advisory({ matchability: 'matched' })], []);
    assert.equal(out.length, 1);
    assert.equal(out[0].version_affected, true);
  });

  it('⛔ emits NOTHING for an unmatchable advisory — not affected, and not clean either', () => {
    // Even with ranges present (a half-repaired row), the ingest pipeline's own verdict wins:
    // we could not evaluate this record, so no assessment may claim we did.
    const out = matchDeviceToAdvisories(device, tuple, [advisory({ matchability: 'unmatchable' })], []);
    assert.deepEqual(out, []);
  });

  it('⛔ NULL matchability is still assessed — it means "not yet classified", not "unknowable"', () => {
    // Treating NULL as unassessable would make every pre-column advisory vanish on first deploy.
    const out = matchDeviceToAdvisories(device, tuple, [advisory({ matchability: null })], []);
    assert.equal(out.length, 1);
  });

  it('counts what it skipped, with the same predicate it skipped on', () => {
    const list = [
      advisory({ id: 'a1', matchability: 'matched' }),
      advisory({ id: 'a2', matchability: 'unmatchable' }),
      advisory({ id: 'a3', matchability: 'unmatchable' }),
      advisory({ id: 'a4', matchability: 'other_product' }),
      advisory({ id: 'a5', matchability: null }),
    ];
    assert.equal(countUnassessableAdvisories(list), 2);
    // Skipping and counting must agree: 5 advisories in, 2 unassessable, 3 assessed.
    assert.equal(matchDeviceToAdvisories(device, tuple, list, []).length, 3);
    assert.equal(countUnassessableAdvisories([]), 0);
    assert.equal(countUnassessableAdvisories(null), 0);
  });
});

describe('migrate: matchability backfill only ever ADDS information', () => {
  // A stub pool: returns canned advisory rows for the SELECT and records every UPDATE.
  function stubPool(rows) {
    const updates = [];
    return {
      updates,
      query: async (sql, args) => {
        if (/^\s*SELECT/i.test(sql)) return { rows };
        updates.push({ sql: sql.replace(/\s+/g, ' '), args });
        return { rowCount: 1, rows: [] };
      },
    };
  }

  const sangforRow = (over) =>
    Object.assign(
      {
        id: 'r1',
        cve_id: 'CVE-2023-30806',
        vendor: 'sangfor',
        matchability: null,
        affected_version_ranges: [],
        fixed_in_versions: [],
        raw_data: record([
          affectedEntry('Sangfor', 'Net-Gen Application Firewall', [
            { status: 'affected', version: '8.0.17' },
          ]),
        ]),
      },
      over
    );

  it('recovers the ranges a row could always have had, and labels it matched', async () => {
    const pool = stubPool([sangforRow()]);
    const out = await backfillAdvisoryMatchability(pool);
    assert.equal(out.rangesRepaired, 1);
    assert.equal(out.byStatus.matched, 1);
    assert.match(pool.updates[0].sql, /affected_version_ranges/);
    assert.deepEqual(JSON.parse(pool.updates[0].args[0]).map((r) => [r.min, r.max]), [
      ['8.0.17', '8.0.17'],
    ]);
  });

  it('⛔ NEVER writes an empty range list over a stored non-empty one', async () => {
    // The row's raw_data is about somebody else entirely, so a re-derivation would yield [].
    // Overwriting real stored ranges with that is the original bug, produced by the fix for it.
    const pool = stubPool([
      sangforRow({
        affected_version_ranges: [{ min: '1.0.0', max: '2.0.0' }],
        raw_data: record([affectedEntry('Fortinet', 'FortiManager')]),
      }),
    ]);
    await backfillAdvisoryMatchability(pool);
    for (const u of pool.updates) {
      assert.ok(!/affected_version_ranges/.test(u.sql), 'must not touch ranges here');
    }
  });

  it('⛔ never issues a DELETE — an advisory is evidence, the column is what makes it honest', async () => {
    const pool = stubPool([sangforRow(), sangforRow({ id: 'r2' })]);
    await backfillAdvisoryMatchability(pool);
    for (const u of pool.updates) assert.ok(!/DELETE/i.test(u.sql));
  });

  it('labels a genuinely unextractable row unmatchable, and re-running writes nothing', async () => {
    const unextractable = sangforRow({
      raw_data: record([
        affectedEntry('Sangfor', 'Net-Gen Application Firewall', [
          { status: 'affected', version: 'All' },
        ]),
      ]),
    });
    const first = stubPool([unextractable]);
    const out = await backfillAdvisoryMatchability(first);
    assert.equal(out.byStatus.unmatchable, 1);
    assert.equal(first.updates.length, 1);
    assert.equal(first.updates[0].args[0], 'unmatchable');

    // Idempotence: with the label already stored, a second pass writes nothing at all.
    const second = stubPool([Object.assign({}, unextractable, { matchability: 'unmatchable' })]);
    await backfillAdvisoryMatchability(second);
    assert.deepEqual(second.updates, []);
  });

  it('leaves a vendor slug with no verified CPE strings NULL rather than guessing', async () => {
    const pool = stubPool([sangforRow({ vendor: 'not_a_vendor' })]);
    const out = await backfillAdvisoryMatchability(pool);
    assert.equal(out.checked, 0);
    assert.deepEqual(pool.updates, []);
  });
});
