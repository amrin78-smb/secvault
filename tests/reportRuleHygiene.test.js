'use strict';
// Pins lib/reports/ruleHygiene.js — the R3 "Rule Hygiene & Policy Audit" PDF.
//
// ⛔ WHAT THESE TESTS ARE ACTUALLY FOR.
//
// This report's whole competitive claim is that it can tell three things apart
// that every comparable product collapses into two:
//
//     a rule with traffic · a rule measured at zero · a rule NEVER MEASURED
//
// The third one is the claim. A firewall that cannot report a hit counter, or
// one whose logs never arrived, must not appear in this document as a confident
// deletion candidate — and the failure mode is silent: printing `0` where the
// truth is NULL renders a perfectly plausible page that manufactures the exact
// evidence a deletion rests on. Nothing crashes, nothing looks wrong, and the
// document outlives the session that produced it.
//
// So every test below is a variant of one question: DOES THE DOCUMENT STILL SAY
// "WE DID NOT MEASURE THIS"? The pass and fail cases are cheap; the unmeasured
// case is the one that regresses quietly.
//
// No database. The stub pool returns canned rows and records every statement it
// was handed, so the ORDER BY that keeps NULLs out of a "least used" ranking is
// asserted as text rather than hoped for.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { contentStreams } = require('../lib/reports/pdfCompare');
const {
  NOT_MEASURED_MARK,
  countCell,
  truncationNote,
  headlineSentence,
  deviceCaveats,
  buildRuleHygieneData,
  renderRuleHygienePdf,
  generateRuleHygienePdf,
} = require('../lib/reports/ruleHygiene');

// ── reading the PDF back ──────────────────────────────────────────────────

/**
 * pdfkit writes every glyph run as a HEX STRING inside a TJ array, so the words
 * are not visible as ASCII anywhere in the file. Decode each `<hex>` token in
 * document order and concatenate.
 *
 * ⛔ Concatenated with no separator ON PURPOSE. Kerning splits a single word
 * across several tokens with a number between them; inserting a space here
 * would break every phrase assertion below into unmatchable fragments.
 */
function pdfText(buf) {
  let out = '';
  for (const stream of contentStreams(buf)) {
    const re = /<([0-9a-fA-F]+)>/g;
    let m;
    while ((m = re.exec(stream)) !== null) {
      const hex = m[1];
      if (hex.length % 2 !== 0) continue;
      for (let i = 0; i < hex.length; i += 2) {
        out += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
      }
    }
  }
  return out;
}

/** Whitespace-insensitive contains, because pdfkit breaks lines where it likes. */
function says(text, phrase) {
  const norm = (s) => s.replace(/\s+/g, ' ');
  return norm(text).includes(norm(phrase));
}

// ── the fixture ───────────────────────────────────────────────────────────
//
// Shaped after the live reference fleet, which is genuinely tri-state: Palo
// Alto over the API reports hit counters, every Fortinet-SSH device reports
// none at all, and one device has never had a successful rule collection.

const DEV_BIG = '11111111-1111-1111-1111-111111111111';
const DEV_SSH = '22222222-2222-2222-2222-222222222222';
const DEV_NONE = '33333333-3333-3333-3333-333333333333';

function fixture(overrides = {}) {
  return Object.assign({
    devices: [
      // Above the 1,000-rule pairwise cap: shadow/redundant/correlation/
      // generalization/reorder_candidate never ran for this one.
      { id: DEV_BIG, name: 'IDC FW', vendor: 'paloalto', mgmt_method: 'api', mgmt_ip: '10.0.0.1', site: 'IDC', active: true, last_rules_collected_at: new Date('2026-09-14T17:11:14Z') },
      { id: DEV_SSH, name: 'TSR_EKM', vendor: 'fortinet', mgmt_method: 'ssh', mgmt_ip: '10.0.0.2', site: 'TSR', active: true, last_rules_collected_at: new Date('2026-09-14T17:12:51Z') },
      // Never collected: its counts are UNKNOWN, not zero.
      { id: DEV_NONE, name: 'Vietnam-YCC', vendor: 'fortinet', mgmt_method: 'ssh', mgmt_ip: '10.0.0.3', site: 'VN', active: true, last_rules_collected_at: null },
    ],
    counts: [
      { device_id: DEV_BIG, rules: 1200, not_measured: 0, measured_zero: 400, with_hits: 800, disabled: 10, logging_off: 2, collected_at: new Date('2026-09-14T17:11:14Z') },
      { device_id: DEV_SSH, rules: 5, not_measured: 5, measured_zero: 0, with_hits: 0, disabled: 0, logging_off: 2, collected_at: new Date('2026-09-14T17:12:51Z') },
      // DEV_NONE deliberately absent — no firewall_rules rows at all.
    ],
    findings: [
      { device_id: DEV_BIG, finding_type: 'any_any', severity: 'critical', detail: 'Rule "chotruycap" allows any source to any destination on any service.', remediation: 'Narrow it.', analyzed_at: new Date(), rule_id_vendor: '17', rule_name: 'chotruycap', sequence_number: 17, enabled: true, hit_count: '900', log_enabled: true, vdom: null, ack_status: null, ack_note: null, ack_at: null },
      // ⛔ A MEASURED zero. node-pg hands BIGINT back as the string '0', which is
      // truthy — the exact value a naive check turns into "not measured".
      { device_id: DEV_BIG, finding_type: 'unused', severity: 'medium', detail: 'No traffic has matched this rule.', remediation: 'Remove it.', analyzed_at: new Date(), rule_id_vendor: '42', rule_name: 'legacy-ftp', sequence_number: 42, enabled: true, hit_count: '0', log_enabled: true, vdom: null, ack_status: null, ack_note: null, ack_at: null },
      // ⛔ NULL. This is the row the whole file exists to protect.
      { device_id: DEV_SSH, finding_type: 'overly_permissive', severity: 'medium', detail: 'Rule "LAN-AllowVLAN-WAN" allows any destination on any service.', remediation: 'Restrict it.', analyzed_at: new Date(), rule_id_vendor: '3', rule_name: 'LAN-AllowVLAN-WAN', sequence_number: 3, enabled: true, hit_count: null, log_enabled: true, vdom: 'root', ack_status: null, ack_note: null, ack_at: null },
      { device_id: DEV_SSH, finding_type: 'risky_service', severity: 'high', detail: 'Rule "FD-Mgmt" allows high-risk service(s): snmp-v1 (161).', remediation: 'Use SNMPv3.', analyzed_at: new Date(), rule_id_vendor: '4', rule_name: 'FD-Mgmt', sequence_number: 4, enabled: true, hit_count: null, log_enabled: true, vdom: 'root', ack_status: 'acknowledged', ack_note: 'Accepted by network team', ack_at: new Date('2026-09-01T00:00:00Z') },
    ],
    coverage: [
      { device_id: DEV_SSH, hours_with_events: 720, first_seen: new Date('2026-08-16T00:00:00Z'), last_seen: new Date('2026-09-15T00:00:00Z'), events: '1000000' },
    ],
    nullRules: {
      [DEV_SSH]: [
        { rule_id_vendor: '1', rule_name: 'R1', sequence_number: 1, enabled: true, log_enabled: true, hit_count: null, vdom: 'root' },
        // Logging off: its absence from the logs measures the setting, not the rule.
        { rule_id_vendor: '2', rule_name: 'R2', sequence_number: 2, enabled: true, log_enabled: false, hit_count: null, vdom: 'root' },
        { rule_id_vendor: '3', rule_name: 'LAN-AllowVLAN-WAN', sequence_number: 3, enabled: true, log_enabled: true, hit_count: null, vdom: 'root' },
        { rule_id_vendor: '4', rule_name: 'FD-Mgmt', sequence_number: 4, enabled: false, log_enabled: false, hit_count: null, vdom: 'root' },
        { rule_id_vendor: '5', rule_name: 'R5', sequence_number: 5, enabled: true, log_enabled: true, hit_count: null, vdom: 'root' },
      ],
    },
    loggedHits: [
      { rule_id: '3', rule_name: 'LAN-AllowVLAN-WAN', hits: '4231', first_hit: new Date('2026-09-01T00:00:00Z'), last_hit: new Date('2026-09-14T00:00:00Z') },
    ],
    // Set to a message to make getDeviceLogCoverage throw.
    coverageThrows: null,
  }, overrides);
}

/**
 * The stub pool. Matches on the statement text and records everything it saw,
 * so an ORDER BY can be asserted rather than trusted.
 *
 * ⛔ Order of the branches matters: three of these statements read
 * `firewall_rules` and two of them mention `hit_count IS NULL`.
 */
function makePool(f) {
  const seen = [];
  return {
    seen,
    async query(text, params) {
      seen.push({ text, params });
      if (/FROM rule_analysis_results/.test(text)) return { rows: f.findings };
      if (/FROM syslog_rollup_hourly/.test(text)) {
        if (f.coverageThrows) throw new Error(f.coverageThrows);
        return { rows: f.coverage };
      }
      if (/FROM syslog_rule_hits_hourly/.test(text)) {
        return { rows: params && params[0] === DEV_SSH ? f.loggedHits : [] };
      }
      if (/FROM devices/.test(text)) {
        if (params && params[0]) return { rows: f.devices.filter((d) => d.id === params[0]) };
        return { rows: f.devices };
      }
      if (/FROM firewall_rules/.test(text) && /FILTER/.test(text)) return { rows: f.counts };
      if (/FROM firewall_rules/.test(text)) {
        return { rows: (f.nullRules[params[0]] || []) };
      }
      throw new Error(`stub pool: unexpected statement\n${text}`);
    },
  };
}

const NOW = new Date('2026-09-15T00:00:00Z');

// ── the tri-state ─────────────────────────────────────────────────────────

describe('the usage tri-state survives from the database to the page', () => {
  it('counts a real hit, a measured zero and a NULL as three different things', async () => {
    const data = await buildRuleHygieneData(makePool(fixture()), { now: NOW });

    assert.equal(data.totals.rules, 1205);
    assert.equal(data.totals.rulesWithHits, 800);
    assert.equal(data.totals.rulesMeasuredZero, 400);
    // ⛔ The headline number. 5 rules on the SSH-managed Fortinet have no hit
    // counter at all; none of the 400 measured zeroes may leak into this count
    // and none of these 5 may leak into the zeroes.
    assert.equal(data.totals.rulesNotMeasured, 5);
    assert.equal(
      data.totals.rulesWithHits + data.totals.rulesMeasuredZero + data.totals.rulesNotMeasured,
      data.totals.rules,
      'the three states must partition the ruleset exactly'
    );
  });

  it('⛔ a NULL hit_count renders as "Not measured", never as 0', async () => {
    const data = await buildRuleHygieneData(makePool(fixture()), { now: NOW });
    const nullRow = data.findings.find((x) => x.ruleName === 'LAN-AllowVLAN-WAN');
    assert.equal(nullRow.hit.state, 'not_measured');
    assert.equal(nullRow.hit.text, 'Not measured');
    assert.equal(nullRow.hit.value, null);
    assert.notEqual(nullRow.hit.text, '0');
  });

  it("⛔ the string '0' node-pg returns for a BIGINT stays a MEASURED zero", async () => {
    // A `Number(v) || null` here would turn real evidence into "not measured"
    // and silently withdraw the only basis an `unused` finding ever has.
    const data = await buildRuleHygieneData(makePool(fixture()), { now: NOW });
    const zeroRow = data.findings.find((x) => x.ruleName === 'legacy-ftp');
    assert.equal(zeroRow.hit.state, 'measured_zero');
    assert.equal(zeroRow.hit.value, 0);
    assert.match(zeroRow.hit.text, /measured zero/);
  });

  it('⛔ the page itself says "Not measured" and explains that it is not zero', async () => {
    const buf = await generateRuleHygienePdf(makePool(fixture()), { now: NOW });
    const text = pdfText(buf);
    assert.ok(says(text, 'Not measured'), 'the words must reach the page');
    assert.ok(says(text, 'This does NOT mean zero'), 'the legend must say so in as many words');
    assert.ok(
      says(text, 'Rules with NO usage data'),
      'the cover must carry the coverage figure, not only the findings count'
    );
    assert.ok(
      says(text, 'THIS IS NOT A FINDING AND IT IS NOT A ZERO'),
      'the unmeasurable section must refuse both readings explicitly'
    );
  });

  it('⛔ an unknown count is a dash, and a dash is not a zero', () => {
    // A firewall with no ruleset has not got zero rules; it has an unanswered
    // question, and the two must never share a glyph.
    assert.equal(countCell(0, false), NOT_MEASURED_MARK);
    assert.equal(countCell(7, false), NOT_MEASURED_MARK);
    assert.equal(countCell(0, true), '0');
    assert.equal(countCell(1205, true), '1,205');
  });

  it('⛔ NULL hit counts are sorted NULLS LAST, never ranked as zeroes', async () => {
    const pool = makePool(fixture());
    await buildRuleHygieneData(pool, { now: NOW });
    const findingSql = pool.seen.find((s) => /FROM rule_analysis_results/.test(s.text)).text;
    // PostgreSQL's ASC default is NULLS FIRST, which would put every unmeasured
    // rule at the head of a "least used" list — the rules that are NOT evidence
    // of being unused, presented as the best deletion candidates.
    assert.match(findingSql, /hit_count ASC NULLS LAST/);
  });
});

// ── a skipped pass is not a clean result ──────────────────────────────────

describe('a skipped analysis pass is reported, not rendered as zero findings', () => {
  it('names the passes that did not run for an over-cap ruleset', async () => {
    const data = await buildRuleHygieneData(makePool(fixture()), { now: NOW });
    const big = data.devices.find((d) => d.name === 'IDC FW');
    assert.equal(big.rules, 1200);
    assert.deepEqual(
      big.pairwiseSkipped,
      ['shadow', 'redundant', 'correlation', 'generalization', 'reorder_candidate'],
      'the five quadratic passes are skipped above the cap'
    );
    assert.equal(data.totals.devicesPairwiseSkipped, 1);
    const small = data.devices.find((d) => d.name === 'TSR_EKM');
    assert.deepEqual(small.pairwiseSkipped, [], 'a 5-rule device ran every pass');
  });

  it('⛔ gives the skipped types a row even though they found nothing', async () => {
    const data = await buildRuleHygieneData(makePool(fixture()), { now: NOW });
    const shadow = data.byType.find((t) => t.findingType === 'shadow');
    assert.ok(shadow, 'shadow must appear even with zero findings — an absent row hides the caveat');
    assert.equal(shadow.total, 0);
    assert.equal(shadow.notRunOn, 1);
  });

  it('⛔ the caveat travels with the device counts, not in a footnote', () => {
    const caveat = deviceCaveats(
      { hasRuleset: true, rules: 1200, rulesNotMeasured: 0, pairwiseSkipped: ['shadow', 'redundant'], lastRulesCollectedAt: new Date(), logEvidenceError: null },
      1000
    );
    assert.match(caveat, /did NOT run/);
    assert.match(caveat, /not measured, not clean/);
  });

  it('⛔ the rendered document says the pass did not run', async () => {
    const text = pdfText(await generateRuleHygienePdf(makePool(fixture()), { now: NOW }));
    assert.ok(says(text, 'NOT RUN on 1 firewall'), 'the by-type table must carry the coverage caveat');
    assert.ok(says(text, 'A zero here is not a clean result.'));
    assert.ok(says(text, 'comparisons did NOT run'), 'the per-firewall row must repeat it beside the counts');
  });

  it('⛔ a firewall with no ruleset is reported as unknown, not as clean', async () => {
    const data = await buildRuleHygieneData(makePool(fixture()), { now: NOW });
    const none = data.devices.find((d) => d.name === 'Vietnam-YCC');
    assert.equal(none.hasRuleset, false);
    assert.equal(data.totals.devicesNoRuleset, 1);

    const text = pdfText(await generateRuleHygienePdf(makePool(fixture()), { now: NOW }));
    assert.ok(says(text, 'The counts are unknown, not zero.'));
    assert.ok(says(text, 'Firewalls with no ruleset collected'), 'the cover must state it');
  });
});

// ── truncation ────────────────────────────────────────────────────────────

describe('no silent truncation', () => {
  it('discloses the cap, worst first', async () => {
    const buf = await generateRuleHygienePdf(makePool(fixture()), { now: NOW, maxFindingRows: 1 });
    const text = pdfText(buf);
    // 3 open findings (the fourth is acknowledged), 1 shown.
    assert.ok(says(text, 'Showing 1 of 3 findings'), 'a shorter table must say it is shorter');
    assert.ok(says(text, 'Open findings (3)'), 'the true total stays in the heading');
  });

  it('says nothing when nothing was dropped', () => {
    assert.equal(truncationNote(3, 3, 'findings'), null);
    assert.match(truncationNote(1, 9, 'findings'), /^Showing 1 of 9 findings/);
  });

  it('⛔ a cap of 0 cannot silently empty a section', async () => {
    // An empty table is indistinguishable on the page from "nothing was found",
    // so the cap clamps to 1 rather than honouring a zero.
    const data = await buildRuleHygieneData(makePool(fixture()), { now: NOW, maxFindingRows: 0, maxUnmeasuredRows: -5 });
    assert.equal(data.caps.maxFindingRows, 1);
    assert.equal(data.caps.maxUnmeasuredRows, 1);
  });
});

// ── log evidence: the second opinion, and its absence ─────────────────────

describe('log evidence for rules the device cannot measure', () => {
  it('separates the rules the logs CAN answer from the ones nothing can', async () => {
    const data = await buildRuleHygieneData(makePool(fixture()), { now: NOW });
    const ssh = data.devices.find((d) => d.name === 'TSR_EKM');
    // 5 unmeasured rules: 2 have logging switched off (unanswerable), 1 has
    // logged hits, 2 are a covered measured-zero.
    assert.equal(ssh.unmeasuredAnsweredByLogs, 3);
    assert.equal(ssh.unmeasuredStillUnknown, 2);
    assert.equal(data.totals.unmeasuredAnsweredByLogs, 3);
    assert.equal(data.totals.unmeasuredStillUnknown, 2);
    assert.equal(data.unmeasured.length, 5, 'every unmeasured rule is listed, answerable or not');
  });

  it('⛔ a rule with logging switched off is NOT MEASURED, not silent', async () => {
    const data = await buildRuleHygieneData(makePool(fixture()), { now: NOW });
    const r2 = data.unmeasured.find((u) => u.ruleIdVendor === '2');
    assert.equal(r2.log.state, 'not_measured');
    assert.match(r2.log.text, /logging is switched off/);
    assert.equal(r2.hit.text, 'Not measured');
  });

  it('⛔ a failed log read is recorded, never reported as "the logs were silent"', async () => {
    const f = fixture({ coverageThrows: 'connection refused' });
    const data = await buildRuleHygieneData(makePool(f), { now: NOW });

    // ⛔ null, NOT 0. "The logs answered none of them" and "we never asked the
    // logs" are opposite claims, and only one of them is a measurement.
    assert.equal(data.totals.unmeasuredAnsweredByLogs, null);
    assert.equal(data.totals.unmeasuredStillUnknown, null);
    assert.equal(data.sectionErrors.length, 1);
    assert.match(data.sectionErrors[0].message, /connection refused/);

    // ⛔ ...and the rules themselves are still counted. Losing the second
    // opinion must not lose the question.
    assert.equal(data.totals.rulesNotMeasured, 5);

    const text = pdfText(await renderRuleHygienePdf(data));
    assert.ok(says(text, 'Parts of this report could not be gathered'));
    assert.ok(says(text, 'The firewall logs could not be consulted for this run'));
    assert.ok(!says(text, 'can answer for 0'), 'must never claim the logs answered none');
  });
});

// ── acknowledged findings ─────────────────────────────────────────────────

describe('acknowledged findings are excluded from the counts and stated', () => {
  it('counts them separately rather than dropping them', async () => {
    const data = await buildRuleHygieneData(makePool(fixture()), { now: NOW });
    assert.equal(data.findings.length, 3);
    assert.equal(data.acknowledged.length, 1);
    assert.equal(data.totals.findingsAcknowledged, 1);
    assert.equal(data.acknowledged[0].ruleName, 'FD-Mgmt');
    // Still visible in the by-type rollup, so the type's total and its
    // acknowledged count cannot be confused for one another.
    const risky = data.byType.find((t) => t.findingType === 'risky_service');
    assert.equal(risky.total, 0);
    assert.equal(risky.acknowledged, 1);
  });

  it('⛔ the document states how many were excluded and lists them', async () => {
    const text = pdfText(await generateRuleHygienePdf(makePool(fixture()), { now: NOW }));
    assert.ok(says(text, 'Findings acknowledged and excluded'), 'stated on the cover');
    assert.ok(says(text, 'Acknowledged findings, excluded from the counts above (1)'));
    assert.ok(says(text, 'It is not deleted and it is not hidden'));
  });
});

// ── the headline ──────────────────────────────────────────────────────────

describe('the headline sentence', () => {
  const clean = {
    devices: 2, devicesNoRuleset: 0, devicesPairwiseSkipped: 0,
    rules: 100, rulesNotMeasured: 0, findings: 0, findingsCritHigh: 0,
  };

  it('⛔ refuses an all-clear while any coverage gap exists', () => {
    const s = headlineSentence(Object.assign({}, clean, { rulesNotMeasured: 5 }));
    assert.match(s, /not a complete picture/);
    assert.match(s, /NO usage data/);
    assert.ok(!/no issues/i.test(s), 'a gap must never be summarised as "no issues"');
  });

  it('names a skipped pass and an uncollected firewall as gaps too', () => {
    const s = headlineSentence(Object.assign({}, clean, { devicesNoRuleset: 1, devicesPairwiseSkipped: 1 }));
    assert.match(s, /no ruleset collected at all/);
    assert.match(s, /did not run there/);
  });

  it('only gives an unqualified clean sentence when every gap is genuinely zero', () => {
    const s = headlineSentence(clean);
    assert.match(s, /every analysis pass ran to completion/);
    assert.ok(!/not a complete picture/.test(s));
  });

  it('leads with the finding count when there are findings', () => {
    const s = headlineSentence(Object.assign({}, clean, { findings: 12, findingsCritHigh: 3 }));
    assert.match(s, /12 open hygiene findings, 3 of them critical or high/);
  });

  it('⛔ the empty findings table repeats the caveat for a reader who skipped page one', async () => {
    const f = fixture({ findings: [] });
    const text = pdfText(await generateRuleHygienePdf(makePool(f), { now: NOW }));
    assert.ok(says(text, 'No open findings - but coverage is incomplete'));
  });
});

// ── scope ─────────────────────────────────────────────────────────────────

describe('scope', () => {
  it('fleet-wide by default, and the firewall column is present', async () => {
    const data = await buildRuleHygieneData(makePool(fixture()), { now: NOW });
    assert.equal(data.scope, 'fleet');
    assert.equal(data.device, null);
    assert.equal(data.devices.length, 3);
  });

  it('a deviceId narrows to one firewall', async () => {
    const data = await buildRuleHygieneData(makePool(fixture()), { now: NOW, deviceId: DEV_SSH });
    assert.equal(data.scope, 'device');
    assert.equal(data.device.name, 'TSR_EKM');
    assert.equal(data.devices.length, 1);
    assert.equal(data.totals.rulesNotMeasured, 5);
    assert.equal(data.findings.length, 1, 'only this firewall\'s open findings');
  });

  it('a deviceId that does not exist returns null, not an empty report', async () => {
    // ⛔ An empty report for a missing device would render as a clean firewall.
    const out = await generateRuleHygienePdf(makePool(fixture()), { now: NOW, deviceId: '99999999-9999-9999-9999-999999999999' });
    assert.equal(out, null);
  });
});

// ── the document itself ───────────────────────────────────────────────────

describe('the rendered artefact', () => {
  it('is a PDF with the methodology and the measured-zero rule stated', async () => {
    const buf = await generateRuleHygienePdf(makePool(fixture()), { now: NOW });
    assert.ok(Buffer.isBuffer(buf));
    assert.equal(buf.slice(0, 5).toString('latin1'), '%PDF-');
    const text = pdfText(buf);
    assert.ok(says(text, 'Rule Hygiene & Policy Audit'));
    // ⛔ The sentence that makes the deletion list trustworthy rather than
    // merely confident. It is the difference between this report and every
    // comparable one, so it is pinned.
    assert.ok(says(text, 'requires a MEASURED zero from one of them - never the absence of a number'));
    assert.ok(says(text, 'How these findings were produced'));
    assert.ok(says(text, 'It does not claim a packet would or would not pass'));
  });

  it('⛔ never leaks the internal developer documentation into the prose', async () => {
    // The same boundary tests/noInternalRefs.test.js guards for app/ and lib/:
    // a customer-facing document must not name the file this product is built
    // from. Cheap to assert here too, because a report is the likeliest place
    // for an explanatory sentence to be pasted out of a comment.
    const text = pdfText(await generateRuleHygienePdf(makePool(fixture()), { now: NOW }));
    assert.ok(!/CLAUDE\.md/i.test(text));
  });
});
