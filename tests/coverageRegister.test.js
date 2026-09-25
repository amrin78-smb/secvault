'use strict';

// tests/coverageRegister.test.js — A2 blind-spot register, pure engine.
//
// ⛔ Every fixture below is a LIVE SHAPE measured on the reference fleet
// 2026-09-25, not an invented one. The three that drove the design:
//   PAKFood   0 syslog buckets while carrying 17 CVE assessments and 24 audit
//             findings — it renders as fully assessed everywhere else.
//   TSR_EKM   78 of 78 rules with no hit count, on the fleet's busiest logger.
//   TSR_EKC   rule analysis 49 days old, last_rules_collected_at NULL, 22
//             `unused` findings that PREDATE the hit_count tri-state fix.

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  assessDevice, rankRegister, summariseRegister, SOURCES, STATE, STALE_AFTER_DAYS,
} = require('../lib/engines/coverageRegister');

// A device with every evidence source present.
const healthy = () => ({
  deviceId: 'd-ok', deviceName: 'IDC FW', vendor: 'paloalto',
  rules: 721, rulesUnmeasured: 0, logBuckets: 2009, interfaces: 72,
  // ⛔ CHECKED, AND THE LOGS ANSWER NONE — not "we did not check". Every
  // fixture derived from this one therefore asserts the DEVICE-ONLY state; the
  // unreadable case is a null, and has its own tests below.
  rulesLogAnswered: 0, rulesLogAnsweredDeletionGrade: 0,
  objectRefs: 878, objectUnresolvable: 0, configAgeDays: 0,
  versionRows: 3, analysisAgeDays: 1, ruleFindings: 377,
  rulesCollectedAt: '2026-09-25T00:00:00Z',
});

const cellFor = (entry, key) => entry.cells.find((c) => c.key === key);

// ── the baseline ─────────────────────────────────────────────────────────

test('a device with every source measured has no gaps and withholds nothing', () => {
  const e = assessDevice(healthy());
  assert.equal(e.gapCount, 0);
  assert.equal(e.answersWithheld, 0);
  assert.equal(e.staleFindings, null);
  assert.equal(e.fullyCovered, true);
  assert.deepEqual(e.blockedEngines, []);
});

test('a measured cell names no blocked engines and carries no weight', () => {
  const e = assessDevice(healthy());
  for (const c of e.cells) {
    assert.equal(c.state, STATE.MEASURED, `${c.key} should be measured`);
    assert.deepEqual(c.gates, [], `${c.key} measured but names gates`);
    assert.equal(c.weight, 0, `${c.key} measured but carries weight`);
  }
});

// ── PAKFood: zero syslog, yet assessed everywhere else ───────────────────

test('zero syslog is ABSENT and names every answer it withholds (PAKFood)', () => {
  const e = assessDevice({ ...healthy(), deviceName: 'PAKFood', logBuckets: 0 });
  const c = cellFor(e, 'syslog');
  assert.equal(c.state, STATE.ABSENT);
  assert.equal(c.certain, true, 'a measured zero is certain — we DID check');
  assert.deepEqual(c.gates, SOURCES.syslog.gates);
  assert.ok(c.weight > 0);
  assert.equal(e.fullyCovered, false);
  // ⛔ The consequence must be stated, not left to the reader.
  assert.match(c.detail, /vulnerable service was reached/i);
  assert.ok(e.blockedEngines.some((g) => /log_hit/.test(g)));
});

// ── the Fortinets: hit counts, all-or-nothing vs partial ─────────────────

test('all rules unmeasured is ABSENT and says cleanup will refuse them (TSR_EKM)', () => {
  const e = assessDevice({
    ...healthy(), deviceName: 'TSR_EKM', vendor: 'fortinet',
    rules: 78, rulesUnmeasured: 78,
  });
  const c = cellFor(e, 'ruleUsage');
  assert.equal(c.state, STATE.ABSENT);
  assert.match(c.detail, /78 of 78/);
  assert.match(c.detail, /cleanup will refuse/i);
});

test('some rules unmeasured is PARTIAL, weighted below ABSENT', () => {
  const partial = assessDevice({ ...healthy(), rules: 100, rulesUnmeasured: 40 });
  const absent = assessDevice({ ...healthy(), rules: 100, rulesUnmeasured: 100 });
  assert.equal(cellFor(partial, 'ruleUsage').state, STATE.PARTIAL);
  assert.equal(cellFor(absent, 'ruleUsage').state, STATE.ABSENT);
  assert.ok(cellFor(partial, 'ruleUsage').weight < cellFor(absent, 'ruleUsage').weight,
    'a partial gap must not rank as heavily as a total one');
});

test('zero unmeasured rules is MEASURED, never a gap', () => {
  const e = assessDevice({ ...healthy(), rules: 47, rulesUnmeasured: 0 });
  assert.equal(cellFor(e, 'ruleUsage').state, STATE.MEASURED);
});

// ⛔ THE CASE THAT REGRESSES SILENTLY. A count we could not read is not a zero.
test('an UNREADABLE count is absent-but-UNCERTAIN, never a measured gap', () => {
  const e = assessDevice({ ...healthy(), logBuckets: null });
  const c = cellFor(e, 'syslog');
  assert.equal(c.state, STATE.ABSENT);
  assert.equal(c.certain, false, 'we could not check — that is not the same as a gap');
  assert.match(c.detail, /could not be read/i);
  assert.equal(e.uncertainCount, 1);
});

// ⛔ THE WHOLE COERCION FAMILY, not just null. `Number(null)`, `Number('')`,
// `Number([])` and `Number(false)` are ALL 0, and 0 is finite — so a bare
// `Number.isFinite(Number(v))` guard records every one of them as a measured
// zero. That was live in this engine until the test above caught it.
test('no falsy input is ever recorded as a measured zero', () => {
  for (const bad of [null, undefined, '', '   ', [], false, {}, NaN, 'n/a']) {
    const e = assessDevice({ ...healthy(), logBuckets: bad });
    const c = cellFor(e, 'syslog');
    assert.equal(c.certain, false, `${JSON.stringify(bad)} was read as a measurement`);
    assert.match(c.detail, /could not be read/i);
  }
  // …while a genuine zero, and pg's string form of one, both ARE measurements.
  for (const real of [0, '0']) {
    const c = cellFor(assessDevice({ ...healthy(), logBuckets: real }), 'syslog');
    assert.equal(c.certain, true, `${JSON.stringify(real)} is a real measured zero`);
    assert.match(c.detail, /sends no syslog/i);
  }
});

test('an unreadable count is reported separately from a real gap in the summary', () => {
  const real = assessDevice({ ...healthy(), deviceId: 'a', logBuckets: 0 });
  const unreadable = assessDevice({ ...healthy(), deviceId: 'b', logBuckets: null });
  const s = summariseRegister([real, unreadable]);
  assert.equal(s.devicesWithGaps, 2);
  assert.equal(s.devicesWithUnreadableChecks, 1, 'only one of the two was unreadable');
});

// ── objects ──────────────────────────────────────────────────────────────

test('wholly unresolvable object references are ABSENT; some are PARTIAL', () => {
  const all = assessDevice({ ...healthy(), objectRefs: 77, objectUnresolvable: 77 });
  const some = assessDevice({ ...healthy(), objectRefs: 878, objectUnresolvable: 36 });
  assert.equal(cellFor(all, 'objects').state, STATE.ABSENT);
  assert.equal(cellFor(some, 'objects').state, STATE.PARTIAL);
  assert.match(cellFor(all, 'objects').detail, /100%/);
});

// ── staleness ────────────────────────────────────────────────────────────

test('a stale CONFIG is STALE, not absent — the evidence exists, it is old', () => {
  const e = assessDevice({ ...healthy(), configAgeDays: STALE_AFTER_DAYS + 42 });
  const c = cellFor(e, 'config');
  assert.equal(c.state, STATE.STALE);
  assert.equal(c.ageDays, STALE_AFTER_DAYS + 42);
  assert.match(c.detail, /compliance and CVE applicability/i);
});

test('a config within the window is MEASURED', () => {
  const e = assessDevice({ ...healthy(), configAgeDays: STALE_AFTER_DAYS });
  assert.equal(cellFor(e, 'config').state, STATE.MEASURED);
});

// ⛔ The thesis case. Stale findings render as current answers.
test('stale rule analysis on a never-collected device is its own finding (TSR_EKC)', () => {
  const e = assessDevice({
    ...healthy(), deviceName: 'TSR_EKC', vendor: 'fortinet',
    rules: 30, rulesUnmeasured: 30, interfaces: 0, configAgeDays: 49,
    analysisAgeDays: 49, ruleFindings: 38, rulesCollectedAt: null,
  });
  assert.ok(e.staleFindings, 'a 49-day-old analysis must be reported');
  assert.equal(e.staleFindings.ageDays, 49);
  assert.equal(e.staleFindings.findingCount, 38);
  assert.equal(e.staleFindings.neverCollected, true);
  assert.match(e.staleFindings.detail, /never succeeded/i);
  // ⛔ The point of the state: nothing elsewhere marks these as old.
  assert.match(e.staleFindings.detail, /nothing marking them as that old/i);
});

test('stale findings alone make a device not fullyCovered', () => {
  const e = assessDevice({ ...healthy(), analysisAgeDays: 40, ruleFindings: 12 });
  assert.equal(e.gapCount, 0, 'no source gap in this fixture');
  assert.equal(e.fullyCovered, false, 'but stale findings are still a blind spot');
});

test('a device whose analysis age is unknown reports no stale finding', () => {
  const e = assessDevice({ ...healthy(), analysisAgeDays: null });
  assert.equal(e.staleFindings, null, 'unknown age must not be asserted as stale');
});

// ── ranking is by CONSEQUENCE, not gap count ─────────────────────────────

const entry = (name, over) => ({
  deviceName: name, gaps: [], gapCount: 0, answersWithheld: 0,
  blockedEngines: [], staleFindings: null, uncertainCount: 0,
  fullyCovered: true, ...over,
});

test('more answers withheld outranks more gaps', () => {
  const many = entry('many-small-gaps', {
    gapCount: 3, answersWithheld: 3, blockedEngines: ['a', 'b', 'c'],
  });
  const heavy = entry('one-heavy-gap', {
    gapCount: 1, answersWithheld: 8, blockedEngines: ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'],
  });
  assert.deepEqual(
    rankRegister([many, heavy]).map((e) => e.deviceName),
    ['one-heavy-gap', 'many-small-gaps'],
    'a register ranked by gap COUNT is a list of the fleet, not a to-do list',
  );
});

test('stale findings outrank a heavier pure gap', () => {
  const stale = entry('stale', { answersWithheld: 1, staleFindings: { ageDays: 49 } });
  const gappy = entry('gappy', { answersWithheld: 9 });
  assert.deepEqual(
    rankRegister([stale, gappy]).map((e) => e.deviceName), ['stale', 'gappy'],
    'a wrong answer shown as current is worse than a missing one',
  );
});

test('ranking is stable by name when consequence ties', () => {
  const a = entry('Bravo', { answersWithheld: 4 });
  const b = entry('Alpha', { answersWithheld: 4 });
  assert.deepEqual(rankRegister([a, b]).map((e) => e.deviceName), ['Alpha', 'Bravo']);
});

test('the real fleet ranks the three known blind spots above the healthy devices', () => {
  const fleet = [
    assessDevice(healthy()),
    assessDevice({ ...healthy(), deviceId: 'p', deviceName: 'PAKFood', logBuckets: 0, objectRefs: 77, objectUnresolvable: 77 }),
    assessDevice({ ...healthy(), deviceId: 'k', deviceName: 'TSR_EKC', rules: 30, rulesUnmeasured: 30, interfaces: 0, configAgeDays: 49, analysisAgeDays: 49, ruleFindings: 38, rulesCollectedAt: null }),
    assessDevice({ ...healthy(), deviceId: 'm', deviceName: 'TSR_EKM', rules: 78, rulesUnmeasured: 78 }),
  ];
  const order = rankRegister(fleet).map((e) => e.deviceName);
  assert.equal(order[0], 'TSR_EKC', 'stale-and-uncollected must lead');
  assert.equal(order[3], 'IDC FW', 'the fully covered device must be last');
});

// ── summary ──────────────────────────────────────────────────────────────

test('the summary counts devices, gaps by source and every blocked engine', () => {
  const s = summariseRegister([
    assessDevice(healthy()),
    assessDevice({ ...healthy(), deviceId: 'p', logBuckets: 0 }),
    assessDevice({ ...healthy(), deviceId: 'm', rules: 78, rulesUnmeasured: 78 }),
  ]);
  assert.equal(s.devices, 3);
  assert.equal(s.devicesFullyCovered, 1);
  assert.equal(s.devicesWithGaps, 2);
  assert.equal(s.gapsBySource.syslog, 1);
  assert.equal(s.gapsBySource.ruleUsage, 1);
  assert.ok(s.blockedEngines.length > 0);
  assert.deepEqual(s.blockedEngines, [...s.blockedEngines].sort(), 'stable order');
});

test('devicesWithStaleFindings is counted apart from devicesWithGaps', () => {
  const s = summariseRegister([
    assessDevice({ ...healthy(), analysisAgeDays: 49, ruleFindings: 22 }),
    assessDevice({ ...healthy(), deviceId: 'p', logBuckets: 0 }),
  ]);
  assert.equal(s.devicesWithStaleFindings, 1);
  assert.equal(s.devicesWithGaps, 2, 'the stale device has no source gap but is not covered');
});

// ── it must not throw on anything ────────────────────────────────────────

test('assessDevice tolerates junk without throwing', () => {
  for (const bad of [undefined, null, 'x', 42, [], {}]) {
    const e = assessDevice(bad);
    assert.ok(Array.isArray(e.cells));
    assert.equal(typeof e.answersWithheld, 'number');
    assert.ok(Number.isFinite(e.answersWithheld));
  }
});

test('rankRegister and summariseRegister tolerate a non-array', () => {
  for (const bad of [undefined, null, 'x', 42, {}]) {
    assert.deepEqual(rankRegister(bad), []);
    assert.equal(summariseRegister(bad).devices, 0);
  }
});

// ── the naming rule ──────────────────────────────────────────────────────

test('full coverage is named for VISIBILITY and never claims safety', () => {
  const src = require('node:fs').readFileSync(
    require('node:path').join(__dirname, '..', 'lib', 'engines', 'coverageRegister.js'), 'utf8',
  );
  // ⛔ Strip comments first — three separate source scans in this repo have
  // been satisfied by the comment explaining the thing they were hunting.
  const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
  assert.ok(/fullyCovered/.test(code));
  assert.ok(!/\b(secure|allClear|all_clear|healthy|clean)\s*[:=]/i.test(code),
    'no field here may read as a security verdict — coverage is visibility, not safety');
});

// ── A3: log-derived rule usage shrinks an OVERSTATED gap ─────────────────
//
// ⛔ `hit_count IS NULL` alone overstated the `ruleUsage` gap by 84 rules
// fleet-wide. A device that cannot report a hit count is not a device whose
// rule usage is unknown: its own logs may answer instead — live, 54 by the
// vendor's rule ID and 30 by NAME only. The register has to say so, and has to
// keep the two grades apart, because only an ID-grade answer may ever support
// removing a rule from a firewall.

// A firewall that reports no hit counts at all, with the log-evidence counts
// supplied literally.
const unmeasuredDevice = (answered, idGrade, over = {}) => assessDevice({
  ...healthy(),
  deviceName: 'TSR_EKM',
  vendor: 'fortinet',
  rules: 78,
  rulesUnmeasured: 78,
  rulesLogAnswered: answered,
  rulesLogAnsweredDeletionGrade: idGrade,
  ...over,
});

test('ALL unmeasured rules answered from logs is PARTIAL, not ABSENT', () => {
  const c = cellFor(unmeasuredDevice(78, 78), 'ruleUsage');
  assert.equal(c.state, STATE.PARTIAL, 'the gap is smaller than absent, so it must not read as absent');
  assert.equal(c.certain, true);
  assert.match(c.detail, /78 of 78 rules report no hit count/);
  assert.match(c.detail, /logs answer all 78/i);
  assert.doesNotMatch(c.detail, /refuse every rule on this firewall/i);
});

test('SOME answered is PARTIAL and the detail names BOTH numbers', () => {
  const c = cellFor(unmeasuredDevice(54, 54), 'ruleUsage');
  assert.equal(c.state, STATE.PARTIAL);
  assert.match(c.detail, /logs answer 54/i);
  assert.match(c.detail, /leaving 24 with no usage evidence at all/i);
  assert.match(c.detail, /refuse the other 24/i);
});

test('NONE answered leaves the cell exactly as it was', () => {
  const c = cellFor(unmeasuredDevice(0, 0), 'ruleUsage');
  assert.equal(c.state, STATE.ABSENT);
  assert.equal(c.certain, true, 'we DID check the logs — they answer none of them');
  assert.match(c.detail, /No hit counts at all \(78 of 78 rules\)/);
  assert.match(c.detail, /cleanup will refuse every rule on this firewall/i);
  assert.doesNotMatch(c.detail, /could not be read/i);
});

test('a PARTIAL device with no log answers keeps its original wording', () => {
  const c = cellFor(assessDevice({
    ...healthy(), rules: 100, rulesUnmeasured: 40, rulesLogAnswered: 0, rulesLogAnsweredDeletionGrade: 0,
  }), 'ruleUsage');
  assert.equal(c.state, STATE.PARTIAL);
  assert.equal(c.detail, '40 of 100 rules report no hit count.');
});

// ⛔ THE ONE THAT REGRESSES SILENTLY. A failed read must never improve the
// picture: "we could not check whether the logs answer these" is not "the logs
// answer these".
test('an UNREADABLE log-evidence count leaves the cell at its WORSE state, uncertain', () => {
  const e = unmeasuredDevice(null, null);
  const c = cellFor(e, 'ruleUsage');
  assert.equal(c.state, STATE.ABSENT, 'it must stay where the device evidence left it');
  assert.equal(c.certain, false);
  assert.match(c.detail, /78 of 78/);
  assert.match(c.detail, /could not be read/i);
  assert.match(c.detail, /overstate/i);
  assert.equal(e.uncertainCount, 1);
  // ⛔ And it must not claim a NUMBER of log answers. The sentence names the
  // logs to say they could not be read, which is the opposite of a claim.
  assert.doesNotMatch(c.detail, /logs answer (all )?\d/i);
});

test('an unreadable count on a PARTIAL device also stays partial and uncertain', () => {
  const c = cellFor(assessDevice({
    ...healthy(), rules: 100, rulesUnmeasured: 40,
    rulesLogAnswered: null, rulesLogAnsweredDeletionGrade: null,
  }), 'ruleUsage');
  assert.equal(c.state, STATE.PARTIAL);
  assert.equal(c.certain, false);
});

// ⛔ `Number(null)` is 0 and 0 is finite. The whole coercion family has to stay
// unreadable here, exactly as it does for every other count in this engine —
// this is the field where a coercion would IMPROVE the register, which is the
// direction that never gets noticed.
test('no falsy log-evidence input is ever read as "the logs answer none"', () => {
  for (const bad of [null, undefined, '', '   ', [], false, {}, NaN, 'n/a']) {
    const c = cellFor(unmeasuredDevice(bad, bad), 'ruleUsage');
    assert.equal(c.certain, false, `${JSON.stringify(bad)} was read as a measurement`);
    assert.equal(c.state, STATE.ABSENT, `${JSON.stringify(bad)} moved the cell`);
  }
  for (const real of [0, '0']) {
    const c = cellFor(unmeasuredDevice(real, real), 'ruleUsage');
    assert.equal(c.certain, true, `${JSON.stringify(real)} is a real measured zero`);
  }
});

// ⛔ KNOWING HOW MANY are answered without knowing how many are ID-GRADE cannot
// be rendered: the detail would imply a deletion authority it has not
// established. Either count unreadable holds the whole cell back.
test('a readable total with an unreadable grade split is still uncertain', () => {
  const c = cellFor(unmeasuredDevice(54, null), 'ruleUsage');
  assert.equal(c.certain, false);
  assert.equal(c.state, STATE.ABSENT);
  assert.doesNotMatch(c.detail, /54/);
});

test('an unreadable grade split with a zero total is also uncertain', () => {
  const c = cellFor(unmeasuredDevice(0, null), 'ruleUsage');
  assert.equal(c.certain, false);
});

// ── ID grade vs NAME grade ───────────────────────────────────────────────

test('NAME-grade evidence is never described as enough to remove a rule', () => {
  const c = cellFor(unmeasuredDevice(30, 0), 'ruleUsage');
  assert.match(c.detail, /NAME only/);
  assert.match(c.detail, /never authorise removing a rule/i);
  assert.match(c.detail, /renamed rule reads as unused/i);
  // ⛔ The consequence: cleanup still refuses every one of them.
  assert.match(c.detail, /cleanup will refuse all 78/i);
  assert.doesNotMatch(c.detail, /cleanup will accept/i);
});

test('ID-grade evidence is described as exact and as removable', () => {
  const c = cellFor(unmeasuredDevice(78, 78), 'ruleUsage');
  assert.match(c.detail, /rule ID, which is exact/i);
  assert.match(c.detail, /cleanup will accept them/i);
  assert.doesNotMatch(c.detail, /NAME only/);
});

test('a mix of the two grades reports them separately, never as one figure', () => {
  const c = cellFor(unmeasuredDevice(70, 54), 'ruleUsage');
  assert.match(c.detail, /54 are matched by the vendor's own rule ID/);
  assert.match(c.detail, /16 by rule NAME only/);
  assert.match(c.detail, /never authorise removing a rule/i);
  assert.match(c.detail, /refuse the other 24/i, '78 unmeasured minus 54 ID-grade');
});

test('the deletion figure counts ID grade only — name grade is refused alongside the unanswered', () => {
  // 40 answered on a 100-rule device with 40 unmeasured: 10 by ID, 30 by name.
  const c = cellFor(assessDevice({
    ...healthy(), rules: 100, rulesUnmeasured: 40,
    rulesLogAnswered: 40, rulesLogAnsweredDeletionGrade: 10,
  }), 'ruleUsage');
  assert.match(c.detail, /logs answer all 40/i);
  assert.match(c.detail, /10 are matched by the vendor's own rule ID/);
  assert.match(c.detail, /30 by rule NAME only/);
  assert.match(c.detail, /refuse the other 30/i, '40 unmeasured minus 10 ID-grade');
});

// ── the ceiling, and the arithmetic ──────────────────────────────────────

test('log evidence can NEVER promote the cell to MEASURED', () => {
  // ⛔ A bounded-window observation is not the device's own lifetime counter.
  for (const [a, i] of [[78, 78], [78, 0], [40, 20]]) {
    const c = cellFor(unmeasuredDevice(a, i), 'ruleUsage');
    assert.notEqual(c.state, STATE.MEASURED, `${a}/${i} promoted the cell`);
    assert.ok(c.weight > 0, `${a}/${i} stopped counting as a blind spot`);
    assert.deepEqual(c.gates, SOURCES.ruleUsage.gates);
  }
});

test('a log-answered firewall withholds fewer answers than an unanswered one', () => {
  const answered = unmeasuredDevice(78, 78);
  const not = unmeasuredDevice(0, 0);
  assert.ok(cellFor(answered, 'ruleUsage').weight < cellFor(not, 'ruleUsage').weight);
  assert.deepEqual(
    rankRegister([answered, not]).map((e) => cellFor(e, 'ruleUsage').state),
    [STATE.ABSENT, STATE.PARTIAL],
    'the firewall the logs cannot answer for must rank first',
  );
});

test('more answers than questions is CLAMPED, never reported as a surplus', () => {
  // Two reads disagreeing is not licence to claim more answers than there were
  // questions; the honest response is the smaller number.
  const c = cellFor(unmeasuredDevice(500, 500), 'ruleUsage');
  assert.match(c.detail, /logs answer all 78/i);
  assert.doesNotMatch(c.detail, /500/);
  assert.match(c.detail, /cleanup will accept them/i);
});

test('an ID-grade count larger than the answered count is clamped too', () => {
  const c = cellFor(unmeasuredDevice(30, 99), 'ruleUsage');
  assert.match(c.detail, /All 30 are matched by the vendor's own rule ID/);
  assert.doesNotMatch(c.detail, /99/);
});

test('a negative log-evidence count is not a measurement', () => {
  // Not reachable from the plumbing, but a negative is a broken read, not a
  // smaller gap, and it must not silently behave like zero.
  const c = cellFor(unmeasuredDevice(-3, 0), 'ruleUsage');
  assert.equal(c.state, STATE.ABSENT);
  assert.equal(c.certain, false, 'a negative must not render as "we checked; none"');
  assert.match(c.detail, /could not be read/i);
  assert.equal(cellFor(unmeasuredDevice(30, -1), 'ruleUsage').certain, false);
});
