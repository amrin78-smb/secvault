'use strict';
// Pins lib/reports/segmentationPosture.js — the R6 "Segmentation Posture" PDF.
//
// ⛔ WHAT THESE TESTS ARE ACTUALLY FOR.
//
// This report makes two claims that are easy to overstate and expensive to get
// wrong, because the document leaves the building and outlives the session that
// produced it:
//
//   1. "A rule permits this zone pair" — which is NOT "a packet would pass".
//      Addresses, services, profiles and rule order are not modelled. An
//      overclaim in print cannot be corrected by a refresh.
//
//   2. "And did anything use it" — which is TRI-STATE. Fortinet over SSH
//      reports no per-rule hit counter at all, so `null` is the COMMON answer
//      on the reference fleet, not a corner case. Folding it into "no traffic"
//      would hand a change board a deletion list containing rules that may be
//      carrying production traffic right now.
//
// So every test below is a variant of one question: DOES THE DOCUMENT STILL SAY
// "WE COULD NOT MEASURE THIS"? The pass and fail cases are cheap; the
// unmeasured case is the one that regresses quietly, because the wrong answer
// is a plausible verdict rather than a crash.
//
// No database. The stub pool returns canned rows for each statement the engines
// issue, so the whole segmentation engine runs unchanged underneath.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { contentStreams } = require('../lib/reports/pdfCompare');
const { UNMEASURED, GREEN, STATUS_RED } = require('../lib/reports/chassis');
const {
  NOT_MEASURED_MARK,
  verdictColor,
  violationChipColor,
  verdictLabel,
  verdictRank,
  isViolation,
  isUnmeasurable,
  intentLabel,
  canCell,
  trafficCell,
  unmeasurableReason,
  truncationNote,
  headlineSentence,
  buildSegmentationPostureData,
  renderSegmentationPosturePdf,
  generateSegmentationPosturePdf,
} = require('../lib/reports/segmentationPosture');

// ── reading the PDF back ──────────────────────────────────────────────────

/**
 * pdfkit writes every glyph run as a HEX STRING inside a TJ array, so the words
 * are not visible as ASCII anywhere in the file. Decode each `<hex>` token in
 * document order and concatenate.
 *
 * ⛔ Concatenated with NO separator on purpose: kerning splits a single word
 * across several tokens, and a space inserted here would break every phrase
 * assertion below into unmatchable fragments.
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

function pageCount(buf) {
  return (buf.toString('latin1').match(/\/Type\s*\/Page[^s]/g) || []).length;
}

// ── the fixture ───────────────────────────────────────────────────────────
//
// Shaped after the live reference fleet, which is genuinely tri-state: Palo Alto
// over the API reports hit counters, every Fortinet-SSH device reports none at
// all, and one active firewall has never had a successful rule collection.

const DEV_PA = '11111111-1111-1111-1111-111111111111';
const DEV_FG = '22222222-2222-2222-2222-222222222222';
const DEV_NONE = '33333333-3333-3333-3333-333333333333';

const NOW = new Date('2026-09-15T00:00:00Z');

function rule(o) {
  return Object.assign({
    id: o.id,
    device_id: DEV_PA,
    device_name: 'IDC FW',
    vendor: 'paloalto',
    rule_name: o.id,
    rule_id_vendor: o.id,
    sequence_number: 1,
    enabled: true,
    action: 'allow',
    src_zones: [],
    dst_zones: [],
    hit_count: null,
    log_enabled: true,
  }, o);
}

function fixture(overrides = {}) {
  return Object.assign({
    intents: [
      // Permitted AND in use — the worst outcome.
      { id: 'i1', source_zone: 'untrust', dest_zone: 'private', expectation: 'deny', note: 'internet must not reach internal', created_by: 'amrin', created_at: NOW, updated_at: NOW },
      // Permitted, MEASURED at zero — the safest hole to close.
      { id: 'i2', source_zone: 'dmz', dest_zone: 'internal', expectation: 'deny', note: null, created_by: null, created_at: NOW, updated_at: NOW },
      // ⛔ THE ROW THIS WHOLE FILE EXISTS TO PROTECT. Permitted by a Fortinet-SSH
      // rule that reports no hit counter and whose logging is switched off, so
      // usage CANNOT be measured from any source.
      { id: 'i3', source_zone: 'wifi', dest_zone: 'server', expectation: 'deny', note: null, created_by: null, created_at: NOW, updated_at: NOW },
      // An allow-intent that works.
      { id: 'i4', source_zone: 'lan', dest_zone: 'wan', expectation: 'allow', note: null, created_by: null, created_at: NOW, updated_at: NOW },
    ],
    // ⛔ DEV_NONE is ACTIVE but contributes no rules — the state a newly added
    // firewall, or one whose collection is failing, drops the fleet into.
    activeDevices: [
      { id: DEV_PA, name: 'IDC FW' },
      { id: DEV_FG, name: 'TSR_EKM' },
      { id: DEV_NONE, name: 'Vietnam-YCC' },
    ],
    rules: [
      rule({ id: 'r1', src_zones: ['untrust'], dst_zones: ['private'], hit_count: '4231' }),
      // ⛔ The string '0' node-pg returns for a BIGINT. A `Number(v) || null`
      // anywhere in the chain turns real evidence into "not measured".
      rule({ id: 'r2', src_zones: ['dmz'], dst_zones: ['internal'], hit_count: '0' }),
      rule({
        id: 'r3', device_id: DEV_FG, device_name: 'TSR_EKM', vendor: 'fortinet',
        src_zones: ['wifi'], dst_zones: ['server'], hit_count: null, log_enabled: false,
      }),
      rule({ id: 'r4', src_zones: ['lan'], dst_zones: ['wan'], hit_count: '900' }),
      // A deny rule that matches nothing declared — present so the fixture is
      // not made entirely of allows.
      rule({ id: 'r5', src_zones: ['untrust'], dst_zones: ['dmz'], action: 'deny', hit_count: '12' }),
    ],
    // 720 of 720 hours: DEV_PA's silence is real evidence. DEV_FG sends nothing,
    // so its rules can never be certified as measured zeroes.
    coverage: [
      { device_id: DEV_PA, hours_with_events: 720, first_seen: new Date('2026-08-16T00:00:00Z'), last_seen: NOW, events: '1000000' },
    ],
    loggedHits: {},
    zones: ['dmz', 'internal', 'lan', 'private', 'server', 'untrust', 'wan', 'wifi'],
    zonesThrow: null,
    devices: [
      { id: DEV_PA, name: 'IDC FW', vendor: 'paloalto', mgmt_method: 'api', mgmt_ip: '10.0.0.1', site: 'IDC', active: true },
      { id: DEV_FG, name: 'TSR_EKM', vendor: 'fortinet', mgmt_method: 'ssh', mgmt_ip: '10.0.0.2', site: 'TSR', active: true },
      { id: DEV_NONE, name: 'Vietnam-YCC', vendor: 'fortinet', mgmt_method: 'ssh', mgmt_ip: '10.0.0.3', site: 'VN', active: true },
    ],
  }, overrides);
}

/**
 * The stub pool. Matches on the statement text and records everything it saw.
 *
 * ⛔ Branch order matters: FOUR of these statements read `firewall_rules` and
 * two of them also name `devices`.
 */
function makePool(f) {
  const seen = [];
  return {
    seen,
    async query(text, params) {
      seen.push({ text, params });
      if (/FROM segmentation_intents/.test(text)) return { rows: f.intents };
      if (/jsonb_array_elements_text/.test(text)) {
        if (f.zonesThrow) throw new Error(f.zonesThrow);
        return { rows: f.zones.map((z) => ({ zone: z })) };
      }
      if (/FROM syslog_rollup_hourly/.test(text)) return { rows: f.coverage };
      if (/FROM syslog_rule_hits_hourly/.test(text)) {
        return { rows: (f.loggedHits[params[0]] || []) };
      }
      // The per-device narrowing read, issued only when a deviceId was given.
      if (/FROM firewall_rules/.test(text) && /WHERE device_id = \$1/.test(text)) {
        return { rows: f.rules.filter((r) => r.device_id === params[0]) };
      }
      if (/FROM firewall_rules/.test(text)) return { rows: f.rules };
      if (/FROM devices/.test(text) && params && params[0]) {
        return { rows: f.devices.filter((d) => d.id === params[0]) };
      }
      if (/FROM devices/.test(text)) return { rows: f.activeDevices };
      throw new Error(`stub pool: unexpected statement\n${text}`);
    },
  };
}

/** A fleet with every device collected — the only shape that may read clean. */
function completeFixture(overrides = {}) {
  return fixture(Object.assign({
    activeDevices: [
      { id: DEV_PA, name: 'IDC FW' },
      { id: DEV_FG, name: 'TSR_EKM' },
    ],
    devices: [
      { id: DEV_PA, name: 'IDC FW', vendor: 'paloalto', mgmt_method: 'api', mgmt_ip: '10.0.0.1', site: 'IDC', active: true },
      { id: DEV_FG, name: 'TSR_EKM', vendor: 'fortinet', mgmt_method: 'ssh', mgmt_ip: '10.0.0.2', site: 'TSR', active: true },
    ],
  }, overrides));
}

// ── the two colours that must never be confused ───────────────────────────

describe('verdict colours', () => {
  it('⛔ violation_permitted and violation_unverified are DIFFERENT colours', () => {
    // These are opposite instructions. "Permitted, no traffic recorded" was
    // MEASURED at zero and is the safest thing on the estate to close;
    // "permitted, traffic not measurable" was never measured at all and must be
    // assumed live. Acting on the wrong one of the two is an outage, so they may
    // never be rendered alike.
    assert.notEqual(
      verdictColor('violation_permitted'),
      verdictColor('violation_unverified'),
      'the safe-to-close hole and the assume-it-is-live hole must not share a colour'
    );
  });

  it('⛔ ranks the unmeasurable violation ABOVE the measured-quiet one', () => {
    // The one you cannot rule out outranks the one you have already checked.
    assert.ok(verdictRank('violation_unverified') < verdictRank('violation_permitted'));
    assert.ok(verdictRank('violation_active') < verdictRank('violation_unverified'));
  });

  it('⛔ unmeasurable verdicts are HUELESS — never green, never red', () => {
    assert.equal(verdictColor('ok_unverified'), UNMEASURED);
    assert.equal(verdictColor('unknown'), UNMEASURED);
    assert.notEqual(verdictColor('unknown'), GREEN);
    assert.notEqual(verdictColor('ok_unverified'), GREEN);
  });

  // ⛔ THE COVER MUST NOT PAINT AN ALL-CLEAR OVER A VIOLATION IT DOES NOT SHOW.
  //
  // There are THREE violation verdicts and the cover has room for two chips
  // (`permitted AND in use`, `usage not measurable`). Each was green whenever
  // its own bucket was zero — so a fleet whose only breaches are
  // `violation_permitted` got a cover carrying two green zeros and no mention
  // of a violation anywhere on it, while page two led with one. That is exactly
  // what the live reference fleet produces: one `violation_permitted` breach.
  //
  // `violation_permitted` is the bucket an operator should go and CLOSE — the
  // measured-quiet standing hole — so hiding it behind green is the wrong
  // direction twice over.
  it('⛔ a violation chip is GREEN only when NO boundary is crossed at all', () => {
    // Nothing crossed anywhere: green is earned.
    assert.equal(violationChipColor(0, 0, STATUS_RED), GREEN);

    // This bucket is empty but ANOTHER violation verdict fired. Hueless, never
    // green — a zero in one bucket is not a clean estate.
    assert.equal(violationChipColor(0, 1, STATUS_RED), UNMEASURED);
    assert.notEqual(violationChipColor(0, 1, STATUS_RED), GREEN);
    assert.notEqual(violationChipColor(0, 3, UNMEASURED), GREEN);

    // This bucket fired: its own hot colour, whatever else is going on.
    assert.equal(violationChipColor(2, 2, STATUS_RED), STATUS_RED);
    assert.equal(violationChipColor(1, 5, STATUS_RED), STATUS_RED);
  });

  it('⛔ the cover states the violation total, not only the two chip buckets', async () => {
    // The live shape: one `violation_permitted`, zero in both chip buckets. The
    // cover must still say a declared boundary is permitted.
    const data = await buildSegmentationPostureData(makePool(fixture()), { now: NOW });
    assert.ok(data.totals.violations > 0, 'fixture must carry at least one violation');
    const text = pdfText(await renderSegmentationPosturePdf(data));
    assert.ok(
      says(text, 'Declared boundaries a rule permits'),
      'the cover must carry the total across all three violation verdicts'
    );
  });

  it('⛔ a verdict this file has never heard of is hueless, not green', () => {
    // A new engine verdict that fell through to a reassuring default would be a
    // failed read rendered as a clean result, in ink.
    assert.equal(verdictColor('some_future_verdict'), UNMEASURED);
    assert.notEqual(verdictColor('some_future_verdict'), GREEN);
  });

  it('borrows the engine\'s own labels rather than inventing a second vocabulary', () => {
    const { VERDICTS } = require('../lib/engines/segmentation');
    Object.keys(VERDICTS).forEach((v) => assert.equal(verdictLabel(v), VERDICTS[v].label));
  });

  it('classifies the three violation verdicts and the three unmeasurable ones', () => {
    assert.ok(isViolation('violation_active'));
    assert.ok(isViolation('violation_permitted'));
    assert.ok(isViolation('violation_unverified'));
    assert.ok(!isViolation('ok_blocked'));
    assert.ok(isUnmeasurable('violation_unverified'));
    assert.ok(isUnmeasurable('ok_unverified'));
    assert.ok(isUnmeasurable('unknown'));
    // ⛔ `ok_blocked` sets did=null because nothing permits the path, so there is
    // no permitting rule whose usage could be measured. That is the INTENDED
    // outcome, not a gap, and counting it as one made a clean fleet read as
    // unmeasurable.
    assert.ok(!isUnmeasurable('ok_blocked'));
  });

  it('spells the declared intent in the operator\'s words', () => {
    assert.equal(intentLabel('deny'), 'Must NOT connect');
    assert.equal(intentLabel('allow'), 'Must connect');
  });
});

// ── the tri-state cells ───────────────────────────────────────────────────

describe('the CAN and DID cells are tri-state', () => {
  it('⛔ an unmeasurable DID is a dash, never "None recorded"', () => {
    const cell = trafficCell({ can: true, did: null, unmeasuredRuleCount: 2 });
    assert.equal(cell.state, 'not_measured');
    assert.equal(cell.color, UNMEASURED);
    assert.ok(cell.text.startsWith(NOT_MEASURED_MARK));
    assert.match(cell.text, /Not measurable/);
    assert.ok(!/None recorded/.test(cell.text), 'not measured must never read as measured zero');
  });

  it('a MEASURED zero says so, and is not a dash', () => {
    const cell = trafficCell({ can: true, did: false, unmeasuredRuleCount: 0 });
    assert.equal(cell.state, 'measured_zero');
    assert.equal(cell.text, 'None recorded');
    assert.ok(!cell.text.includes(NOT_MEASURED_MARK));
  });

  it('⛔ "nothing permits it" is not a measurement gap', () => {
    // No permitting rule means no rule whose usage could be measured. Reporting
    // that as "not measurable" would manufacture a coverage gap out of the
    // desired outcome.
    const cell = trafficCell({ can: false, did: null });
    assert.equal(cell.state, 'n/a');
    assert.match(cell.text, /Not applicable/);
  });

  it('⛔ an unknown CAN is "cannot tell", never "no rule permits it"', () => {
    // A hole reported as closed is a false assurance, which is worse than an
    // admitted gap.
    const cell = canCell({ can: null, permittingRuleCount: 0 });
    assert.equal(cell.state, 'unknown');
    assert.equal(cell.color, UNMEASURED);
    assert.match(cell.text, /Cannot tell/);
    assert.ok(!/No rule permits/.test(cell.text));
  });

  it('a known CAN reports how many rules permit it', () => {
    assert.match(canCell({ can: true, permittingRuleCount: 3 }).text, /Yes - 3 rules/);
    assert.match(canCell({ can: true, permittingRuleCount: 1 }).text, /Yes - 1 rule\b/);
    assert.match(canCell({ can: false }).text, /No rule permits it/);
  });

  it('⛔ always gives a REASON for an unanswered pair', () => {
    // "Could not be determined" with no cause is indistinguishable from a bug.
    assert.match(
      unmeasurableReason({ evidenceReasons: ['no-rules-collected'] }),
      /No ruleset has been collected from any firewall/
    );
    assert.match(
      unmeasurableReason({ evidenceReasons: ['partial-rule-coverage'], uncollectedDeviceCount: 2 }),
      /2 firewalls have no ruleset collected/
    );
    assert.match(
      unmeasurableReason({ evidenceReasons: ['unrecognised-action'], unrecognisedActionRuleCount: 1 }),
      /cannot classify as allow or deny/
    );
    assert.match(
      unmeasurableReason({ evidenceReasons: [], can: true, did: null, unmeasuredRuleCount: 1 }),
      /Assume the path is live/
    );
    // Even with nothing to go on, a sentence is produced rather than a blank.
    assert.ok(unmeasurableReason({}).length > 0);
  });
});

// ── the headline ──────────────────────────────────────────────────────────

describe('the headline sentence', () => {
  const clean = {
    intents: 4, violations: 0, violationsActive: 0, expectedAllowMissing: 0,
    unmeasurable: 0, rulesCollected: true, ruleCount: 100, rulesWithoutHitData: 0,
    rulesWithUnrecognisedAction: 0, devicesWithoutRules: 0,
  };

  it('⛔ refuses an all-clear while any pair could not be measured', () => {
    const s = headlineSentence(Object.assign({}, clean, { unmeasurable: 2 }));
    assert.match(s, /NOT a complete picture/);
    assert.match(s, /could not be measured at all/);
  });

  it('⛔ a fleet with NO collected rules is never a clean bill of health', () => {
    const s = headlineSentence(Object.assign({}, clean, {
      rulesCollected: false, ruleCount: 0, unmeasurable: 4, devicesWithoutRules: 3,
    }));
    assert.match(s, /NOT a complete picture/);
    assert.match(s, /no ruleset has been collected from any firewall/);
    assert.ok(!/Every declared pair was evaluated/.test(s));
  });

  it('⛔ names rules that cannot report usage as a gap in their own right', () => {
    const s = headlineSentence(Object.assign({}, clean, { rulesWithoutHitData: 233 }));
    assert.match(s, /233 of 100 rules on the estate cannot report whether traffic ever used them/);
  });

  it('⛔ nothing declared is the WORST case, not the best one', () => {
    const s = headlineSentence(Object.assign({}, clean, { intents: 0 }));
    assert.match(s, /not a clean result/);
    assert.match(s, /nothing has been checked/);
  });

  it('leads with the violations that are permitted AND in use', () => {
    const s = headlineSentence(Object.assign({}, clean, { violations: 3, violationsActive: 1 }));
    assert.match(s, /permitted by a rule AND/);
  });

  it('calls a permitted-but-quiet violation a standing hole rather than a breach', () => {
    const s = headlineSentence(Object.assign({}, clean, { violations: 2, violationsActive: 0 }));
    assert.match(s, /standing holes rather than active breaches/);
  });

  it('only gives an unqualified clean sentence when every gap is genuinely zero', () => {
    const s = headlineSentence(clean);
    assert.match(s, /no rule permitting anything you said must not connect/);
    assert.match(s, /usage evidence was available for every rule that permits one/);
    assert.ok(!/NOT a complete picture/.test(s));
  });
});

// ── truncation ────────────────────────────────────────────────────────────

describe('no silent truncation', () => {
  it('discloses a shortened table and says nothing when nothing was dropped', () => {
    assert.equal(truncationNote(4, 4, 'declared pairs'), null);
    assert.match(truncationNote(1, 9, 'violations'), /^Showing 1 of 9 violations/);
  });

  it('⛔ a cap of 0 cannot silently empty a section', async () => {
    const data = await buildSegmentationPostureData(makePool(fixture()), {
      now: NOW, maxMatrixRows: 0, maxViolationRows: -3, maxUnmeasurableRows: 0,
    });
    assert.equal(data.caps.maxMatrixRows, 1);
    assert.equal(data.caps.maxViolationRows, 1);
    assert.equal(data.caps.maxUnmeasurableRows, 1);
  });
});

// ── the whole engine, through the stub pool ───────────────────────────────

describe('the evaluation reaches the document intact', () => {
  it('⛔ a pair whose permitting rule has NO hit data is UNKNOWN, never compliant', async () => {
    // wifi -> server is permitted by a Fortinet-SSH rule that reports no hit
    // counter and has logging switched off, so neither source can answer. It
    // must be a violation SecVault cannot verify — not a pass, and not a
    // measured zero.
    const data = await buildSegmentationPostureData(makePool(fixture()), { now: NOW });
    const wifi = data.intents.find((r) => r.sourceZone === 'wifi');

    assert.equal(wifi.verdict, 'violation_unverified');
    assert.equal(wifi.did, null, 'null, never false — one unmeasured rule makes the pair unknown');
    assert.ok(isUnmeasurable(wifi.verdict));
    assert.ok(data.unmeasurable.some((r) => r.sourceZone === 'wifi'));
    assert.ok(
      !data.intents.some((r) => r.sourceZone === 'wifi' && r.verdict.startsWith('ok_')),
      'an unmeasured pair must never be counted as a satisfied one'
    );
    assert.equal(data.totals.violationsUnverified, 1);

    const cell = trafficCell(wifi);
    assert.equal(cell.state, 'not_measured');
    assert.ok(cell.text.startsWith(NOT_MEASURED_MARK));
  });

  it('keeps the three "did" states apart end to end', async () => {
    const data = await buildSegmentationPostureData(makePool(fixture()), { now: NOW });
    const byPair = new Map(data.intents.map((r) => [`${r.sourceZone}->${r.destZone}`, r]));

    assert.equal(byPair.get('untrust->private').verdict, 'violation_active');
    assert.equal(byPair.get('untrust->private').did, true);
    // ⛔ The string '0' from node-pg stays a MEASURED zero. Turning it into
    // "not measured" would withdraw the only evidence that makes this the
    // safest hole on the estate to close.
    assert.equal(byPair.get('dmz->internal').verdict, 'violation_permitted');
    assert.equal(byPair.get('dmz->internal').did, false);
    assert.equal(byPair.get('wifi->server').did, null);
    assert.equal(byPair.get('lan->wan').verdict, 'ok_in_use');

    assert.equal(data.totals.violations, 3);
    assert.equal(data.totals.violationsActive, 1);
    assert.equal(data.totals.violationsPermitted, 1);
    assert.equal(data.totals.violationsUnverified, 1);
  });

  it('⛔ counts the firewall with no ruleset collected, and says how many rules cannot report usage', async () => {
    const data = await buildSegmentationPostureData(makePool(fixture()), { now: NOW });
    assert.equal(data.totals.activeDeviceCount, 3);
    assert.equal(data.totals.deviceCount, 2, 'only two firewalls contributed rules');
    assert.equal(data.totals.devicesWithoutRules, 1);
    // The Fortinet-SSH rule. Its NULL hit_count is a gap in what can be read,
    // not a statement that the rule is idle.
    assert.equal(data.totals.rulesWithoutHitData, 1);
    assert.equal(data.totals.ruleCount, 5);
  });

  it('reports the window the evidence ACTUALLY spans, not the number requested', async () => {
    // ⛔ `days=3` is measured as 7 by the engine's own floor. Printing the
    // request would mislabel every number under it.
    const data = await buildSegmentationPostureData(makePool(fixture()), { now: NOW, windowDays: 3 });
    assert.equal(data.windowDays, 7);
    assert.equal(data.requestedWindowDays, 3);
  });

  it('counts the zone pairs nobody has declared an intent for', async () => {
    const data = await buildSegmentationPostureData(makePool(fixture()), { now: NOW });
    assert.equal(data.totals.zoneCount, 8);
    assert.equal(data.totals.orderedPairs, 8 * 7);
    assert.equal(data.totals.undeclaredPairs, 56 - 4);
  });

  it('⛔ an unread zone census is UNKNOWN, never zero undeclared pairs', async () => {
    // Reporting zero here would silently claim the declared intents cover the
    // whole estate.
    const data = await buildSegmentationPostureData(
      makePool(fixture({ zonesThrow: 'connection refused' })),
      { now: NOW }
    );
    assert.equal(data.totals.zoneCount, null);
    assert.equal(data.totals.undeclaredPairs, null);
    assert.equal(data.sectionErrors.length, 1);
    assert.match(data.sectionErrors[0].message, /connection refused/);
    // ...and the matrix itself survives the loss.
    assert.equal(data.intents.length, 4);

    const text = pdfText(await renderSegmentationPosturePdf(data));
    assert.ok(says(text, 'Parts of this report could not be gathered'));
    assert.ok(says(text, 'unknown, not zero'));
  });
});

// ── the empty and the uncollected fleet ───────────────────────────────────

describe('an empty result is never a clean result', () => {
  it('⛔ a fleet with ZERO collected rules does not produce a clean bill of health', async () => {
    const f = fixture({ rules: [], coverage: [] });
    const data = await buildSegmentationPostureData(makePool(f), { now: NOW });

    assert.equal(data.totals.rulesCollected, false);
    assert.equal(data.totals.violations, 0, 'nothing can be proven a violation without rules');
    // ⛔ ...and that zero is NOT a pass. Every declared pair is unknown.
    assert.equal(data.totals.unmeasurable, 4);
    assert.equal(data.totals.unknown, 4);
    assert.equal(data.totals.ok, 0);
    data.intents.forEach((r) => assert.equal(r.verdict, 'unknown'));

    const text = pdfText(await renderSegmentationPosturePdf(data));
    assert.ok(says(text, 'NOT a complete picture'), 'the headline must refuse the all-clear');
    assert.ok(says(text, 'No ruleset has been collected at all'));
    assert.ok(says(text, 'NOTHING WAS CHECKED'));
    assert.ok(
      !says(text, 'No rule anywhere on the collected rulebase permits'),
      'a zero violation count over no rules must not be rendered as a clean estate'
    );
  });

  it('⛔ no declared intent renders as an EMPTY result, not a green one', async () => {
    const f = fixture({ intents: [] });
    const data = await buildSegmentationPostureData(makePool(f), { now: NOW });
    assert.equal(data.totals.intents, 0);

    const text = pdfText(await renderSegmentationPosturePdf(data));
    assert.ok(says(text, 'This is an empty result, not a clean one'));
    assert.ok(says(text, 'measures the absence of questions, not the state of the estate'));
  });

  it('does not throw on a completely empty fleet', async () => {
    const f = fixture({
      intents: [], rules: [], coverage: [], zones: [], activeDevices: [], devices: [],
    });
    const buf = await generateSegmentationPosturePdf(makePool(f), { now: NOW });
    assert.ok(Buffer.isBuffer(buf));
    assert.equal(buf.slice(0, 5).toString('latin1'), '%PDF-');
    const text = pdfText(buf);
    assert.ok(says(text, 'Nothing was checked, so nothing was found'));
  });

  it('gives an unqualified clean sentence only when every firewall was collected', async () => {
    // ⛔ The ONLY shape allowed to read as enforced: every active firewall
    // contributed rules, every rule reports a hit counter, and nothing permits
    // the declared boundary. Remove any ONE of those three and the sentence must
    // pick up a caveat — which the tests above check.
    const f = completeFixture({
      intents: [
        { id: 'i9', source_zone: 'untrust', dest_zone: 'private', expectation: 'deny', note: null, created_by: null, created_at: NOW, updated_at: NOW },
      ],
      rules: [
        rule({ id: 'r9', src_zones: ['lan'], dst_zones: ['wan'], hit_count: '5' }),
        rule({
          id: 'r10', device_id: DEV_FG, device_name: 'TSR_EKM', vendor: 'fortinet',
          src_zones: ['wifi'], dst_zones: ['server'], hit_count: '7',
        }),
      ],
    });
    const data = await buildSegmentationPostureData(makePool(f), { now: NOW });
    assert.equal(data.intents[0].verdict, 'ok_blocked');
    assert.equal(data.totals.unmeasurable, 0, 'ok_blocked is an answer, not a measurement gap');
    assert.match(data.headline, /no rule permitting anything you said must not connect/);
    assert.ok(!/NOT a complete picture/.test(data.headline));
  });
});

// ── the optional narrowing ────────────────────────────────────────────────

describe('deviceId is a narrowing, never a requirement', () => {
  it('fleet-wide by default', async () => {
    const data = await buildSegmentationPostureData(makePool(fixture()), { now: NOW });
    assert.equal(data.scope, 'fleet');
    assert.equal(data.device, null);
    assert.equal(data.intents.length, 4);
  });

  it('filters to the pairs one firewall participates in', async () => {
    const data = await buildSegmentationPostureData(makePool(fixture()), { now: NOW, deviceId: DEV_FG });
    assert.equal(data.scope, 'device');
    assert.equal(data.device.name, 'TSR_EKM');
    // Only wifi -> server is carried by a rule on this firewall.
    assert.equal(data.intents.length, 1);
    assert.equal(data.intents[0].sourceZone, 'wifi');
    // ⛔ The declared policy is still reported at its true size, so a narrowed
    // document can never be read as the whole of it.
    assert.equal(data.totals.intentsDeclaredFleetWide, 4);
  });

  it('⛔ says in print that a narrowed verdict is still an estate-wide judgement', async () => {
    const text = pdfText(await generateSegmentationPosturePdf(makePool(fixture()), { now: NOW, deviceId: DEV_FG }));
    assert.ok(says(text, 'Narrowed to TSR_EKM'));
    assert.ok(says(text, 'ESTATE-WIDE judgement'));
    assert.ok(says(text, 'filters which pairs are shown, never how any of them was decided'));
  });

  it('a deviceId that does not exist returns null, not an empty report', async () => {
    // ⛔ An empty report for a missing firewall would render as a perfectly
    // segmented one.
    const out = await generateSegmentationPosturePdf(makePool(fixture()), {
      now: NOW, deviceId: '99999999-9999-9999-9999-999999999999',
    });
    assert.equal(out, null);
  });
});

// ── the document itself ───────────────────────────────────────────────────

describe('the rendered artefact', () => {
  it('is a multi-page PDF carrying the cover, the matrix and the legend', async () => {
    const buf = await generateSegmentationPosturePdf(makePool(fixture()), { now: NOW });
    assert.ok(Buffer.isBuffer(buf));
    assert.equal(buf.slice(0, 5).toString('latin1'), '%PDF-');
    assert.ok(pageCount(buf) >= 2, 'a cover and at least one body page');

    const text = pdfText(buf);
    assert.ok(says(text, 'Segmentation Posture'));
    assert.ok(says(text, 'Declared intent, checked (4)'));
    assert.ok(says(text, 'What could not be verified, and why'));
    assert.ok(says(text, 'Legend - what each verdict means'));
    assert.ok(says(text, 'How this was produced'));
  });

  it('⛔ says "a rule permits this", never that a path is reachable', async () => {
    const text = pdfText(await generateSegmentationPosturePdf(makePool(fixture()), { now: NOW }));
    assert.ok(says(text, 'It does NOT mean a packet would actually get through'));
    assert.ok(says(text, 'never as "this is reachable"'));
    assert.ok(
      says(text, 'It does not claim a packet would or would not pass'),
      'the methodology must repeat the limit for a reader who skipped the front'
    );
  });

  it('⛔ the cover states the traffic window and the size of what could not be answered', async () => {
    const text = pdfText(await generateSegmentationPosturePdf(makePool(fixture()), { now: NOW }));
    // A "no traffic recorded" verdict means nothing without the span.
    assert.ok(says(text, 'Traffic evidence window'));
    assert.ok(says(text, '30 days'));
    assert.ok(says(text, 'Pairs that could not be answered'));
    assert.ok(says(text, 'Rules that cannot report usage'));
  });

  it('⛔ the legend explains why the two permitted-violation states differ', async () => {
    const text = pdfText(await generateSegmentationPosturePdf(makePool(fixture()), { now: NOW }));
    assert.ok(says(text, 'Why two of the violations are coloured differently'));
    assert.ok(says(text, 'ASSUME IT IS LIVE'));
    assert.ok(says(text, 'the safest kind to close'));
    assert.ok(says(text, 'deliberately never given the same colour'));
  });

  it('⛔ the unanswered pairs get their own counted section, not a footnote', async () => {
    const text = pdfText(await generateSegmentationPosturePdf(makePool(fixture()), { now: NOW }));
    assert.ok(says(text, 'THESE ARE NOT PASSES AND THEY ARE NOT FAILURES'));
    assert.ok(says(text, 'cannot report usage'));
    assert.ok(says(text, 'firewall with no ruleset collected'));
  });

  it('⛔ never leaks the internal developer documentation into the prose', async () => {
    // The same boundary tests/noInternalRefs.test.js guards for app/ and lib/:
    // a customer-facing document must not name the file this product is built
    // from. A report is the likeliest place for a sentence to be pasted out of
    // a comment.
    const text = pdfText(await generateSegmentationPosturePdf(makePool(fixture()), { now: NOW }));
    assert.ok(!/CLAUDE\.md/i.test(text));
  });

  it('a red headline figure stays red, and the hueless one stays hueless', () => {
    // Cheap guard on the chassis ramp being used rather than a local hex.
    assert.equal(verdictColor('violation_active'), STATUS_RED);
    assert.equal(verdictColor('unknown'), UNMEASURED);
  });
});
