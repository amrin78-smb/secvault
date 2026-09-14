'use strict';
// Pins lib/engines/workQueue.js and buildWorkQueueAnswer — the single ranked
// feed across every engine (Phase 3).
//
// ⛔ THIS FEATURE HAS EXACTLY TWO WAYS TO FAIL, and both produce a page that
// looks better than the truth:
//
//   1. EVERYTHING BECOMES URGENT. CLAUDE.md already records this outcome from
//      the rejected `log_hit` definition, which would have moved ~all 155
//      assessments to patch_now: "a queue where everything is urgent has no
//      prioritisation left". The guard is that `act_now` is a claim about
//      EVIDENCE — an item SecVault could not measure may never enter it,
//      however loudly its source declares itself urgent.
//
//   2. A FAILED SOURCE MAKES THE QUEUE LOOK CLEAN. If the compliance query
//      throws and the queue simply renders five fewer items, it is shortest and
//      most reassuring at precisely the moment it is least trustworthy. This is
//      the codebase's oldest bug — a failed read recorded as an affirmative
//      value — applied to the to-do list itself.
//
// The third rule worth pinning is that `verify` is a REAL band, not a bin. The
// items in it (a licence expiry that would not parse, a firewall that cannot be
// collected from) are the ones every competing product silently drops, and a
// firewall SecVault cannot read otherwise looks like the healthiest device on
// the fleet because it contributes no findings to anything.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { bandFor, rankItems, summarise, WORK_BANDS } = require('../lib/engines/workQueue');
const { buildWorkQueueAnswer } = require('../lib/answers');

const item = (over) => ({
  type: 'cve',
  key: 'k',
  title: 't',
  severity: 'high',
  urgency: 'soon',
  evidence: 'reported',
  count: 1,
  deviceIds: ['d1'],
  ...over,
});

describe('banding', () => {
  it('measured + urgent is act_now', () => {
    assert.equal(bandFor(item({ evidence: 'measured', urgency: 'now' })), 'act_now');
  });

  it('reported + urgent is still act_now', () => {
    // A KEV-listed CVE on an affected version is the vendor's word plus our
    // version match. That is enough to act on; it is not a measurement.
    assert.equal(bandFor(item({ evidence: 'reported', urgency: 'now' })), 'act_now');
  });

  it('non-urgent is scheduled', () => {
    assert.equal(bandFor(item({ evidence: 'measured', urgency: 'soon' })), 'scheduled');
  });

  it('⛔ UNMEASURED CAN NEVER BE act_now, however urgent the source says it is', () => {
    // The load-bearing line. A source cannot promote a guess by declaring it
    // urgent — `act_now` is a claim about evidence we do not have.
    assert.equal(bandFor(item({ evidence: 'unmeasured', urgency: 'now' })), 'verify');
    assert.equal(bandFor(item({ evidence: 'unmeasured', urgency: 'soon' })), 'verify');
  });

  it('⛔ an unknown or missing evidence value fails CLOSED to verify', () => {
    // Never fall through to act_now on a typo.
    assert.equal(bandFor(item({ evidence: undefined })), 'verify');
    assert.equal(bandFor(item({ evidence: 'probably' })), 'verify');
    assert.equal(bandFor({}), 'verify');
    assert.equal(bandFor(null), 'verify');
  });
});

describe('ranking', () => {
  it('orders by band first', () => {
    const ranked = rankItems([
      item({ key: 'c', evidence: 'unmeasured' }),
      item({ key: 'b', evidence: 'measured', urgency: 'soon' }),
      item({ key: 'a', evidence: 'measured', urgency: 'now' }),
    ]);
    assert.deepEqual(ranked.map((r) => r.band), ['act_now', 'scheduled', 'verify']);
  });

  it('orders by severity inside a band', () => {
    const ranked = rankItems([
      item({ key: 'low', severity: 'low', urgency: 'now', evidence: 'measured' }),
      item({ key: 'crit', severity: 'critical', urgency: 'now', evidence: 'measured' }),
    ]);
    assert.equal(ranked[0].key, 'crit');
  });

  it('a bigger backlog outranks a smaller one of the same kind', () => {
    const ranked = rankItems([
      item({ key: 'small', count: 3, urgency: 'soon', evidence: 'measured' }),
      item({ key: 'big', count: 90, urgency: 'soon', evidence: 'measured' }),
    ]);
    assert.equal(ranked[0].key, 'big');
  });

  it('⛔ is STABLE across identical inputs', () => {
    // A queue that reorders itself between refreshes destroys the one thing a
    // queue is for. Two items alike in every rank key fall back to the title.
    const mk = () => [
      item({ key: 'z', title: 'Zebra', urgency: 'soon', evidence: 'measured' }),
      item({ key: 'a', title: 'Apple', urgency: 'soon', evidence: 'measured' }),
    ];
    assert.deepEqual(rankItems(mk()).map((r) => r.title), rankItems(mk()).map((r) => r.title));
    assert.equal(rankItems(mk())[0].title, 'Apple');
  });

  it('does not mutate its input', () => {
    const input = [item({ key: 'x' })];
    rankItems(input);
    assert.equal(input[0].band, undefined);
  });

  it('survives junk', () => {
    assert.deepEqual(rankItems(null), []);
    assert.deepEqual(rankItems([null, undefined]), []);
  });
});

describe('⛔ a failed source is never silently zero', () => {
  it('counts and names failed sources', () => {
    const s = summarise([], [
      { key: 'cve', ok: true },
      { key: 'compliance', ok: false, error: 'relation does not exist' },
    ]);
    assert.equal(s.sourcesFailed, 1);
    assert.equal(s.sourcesTotal, 2);
    assert.deepEqual(s.failedSources, [{ key: 'compliance', error: 'relation does not exist' }]);
  });

  it('⛔ REFUSES an all-clear when a source failed, even with an empty queue', () => {
    // The most dangerous sentence this page can print. An operator who reads
    // "nothing outstanding" closes the tab.
    const a = buildWorkQueueAnswer(summarise([], [
      { key: 'cve', ok: true },
      { key: 'compliance', ok: false, error: 'boom' },
    ]));
    assert.notEqual(a.tone, 'ok');
    assert.match(a.lead + ' ' + a.sentence, /could not be built|not a complete picture/);
    assert.match(a.coverage, /could not be read/);
  });

  it('allows the all-clear only when every source ran and nothing is unverifiable', () => {
    const a = buildWorkQueueAnswer(summarise([], [{ key: 'cve', ok: true }]));
    assert.equal(a.tone, 'ok');
    assert.equal(a.coverage, null);
    assert.match(a.lead, /Nothing is outstanding/);
  });

  it('⛔ REFUSES an all-clear while anything sits in verify', () => {
    const items = rankItems([item({ evidence: 'unmeasured' })]);
    const a = buildWorkQueueAnswer(summarise(items, [{ key: 'licence', ok: true }]));
    assert.notEqual(a.tone, 'ok');
    assert.match(a.coverage, /cannot verify/);
  });
});

describe('the summary', () => {
  it('counts each band and de-duplicates devices across items', () => {
    const items = rankItems([
      item({ key: 'a', urgency: 'now', evidence: 'measured', deviceIds: ['d1'] }),
      item({ key: 'b', urgency: 'soon', evidence: 'measured', deviceIds: ['d1', 'd2'] }),
      item({ key: 'c', evidence: 'unmeasured', deviceIds: ['d2'] }),
    ]);
    const s = summarise(items, []);
    assert.equal(s.total, 3);
    assert.equal(s.act_now, 1);
    assert.equal(s.scheduled, 1);
    assert.equal(s.verify, 1);
    assert.equal(s.deviceCount, 2);
  });

  it('leads with the act_now count when there is one', () => {
    const items = rankItems([
      item({ key: 'a', urgency: 'now', evidence: 'measured' }),
      item({ key: 'b', urgency: 'soon', evidence: 'measured' }),
    ]);
    const a = buildWorkQueueAnswer(summarise(items, [{ key: 'x', ok: true }]));
    assert.equal(a.tone, 'critical');
    assert.match(a.lead, /1 item needs attention now/);
    assert.match(a.sentence, /1 more scheduled/);
  });

  it('never throws on junk', () => {
    for (const bad of [null, undefined, {}, { act_now: 'x' }]) {
      const a = buildWorkQueueAnswer(bad);
      assert.equal(typeof a.sentence, 'string');
    }
    assert.equal(summarise(null, null).total, 0);
  });

  it('the three bands are the documented three', () => {
    assert.deepEqual(WORK_BANDS, ['act_now', 'scheduled', 'verify']);
  });
});

describe('⛔ a cap that bit is disclosed', () => {
  it('carries the shown/total through the summary', () => {
    // Live on the first run: 74 critical/high compliance failures existed, the
    // cap returned 50, and the page reported nothing. A truncated list looks
    // complete, which makes this the more insidious of the two ways the queue
    // can be shorter than the truth.
    const s = summarise([], [{ key: 'compliance', ok: true, count: 50, truncatedFrom: 74 }]);
    assert.equal(s.sourcesTruncated, 1);
    assert.deepEqual(s.truncatedSources, [{ key: 'compliance', shown: 50, of: 74 }]);
  });

  it('says so in the coverage line, with the real numbers', () => {
    const a = buildWorkQueueAnswer(
      summarise([], [{ key: 'compliance', ok: true, count: 50, truncatedFrom: 74 }])
    );
    assert.match(a.coverage, /only 50 of 74 compliance items are listed/);
  });

  it('⛔ still discloses the cap when even the count failed', () => {
    const a = buildWorkQueueAnswer(
      summarise([], [{ key: 'cve', ok: true, count: 50, truncatedFrom: 'unknown' }])
    );
    assert.match(a.coverage, /more work than is listed here/);
  });

  it('an uncapped source reports no truncation', () => {
    const s = summarise([], [{ key: 'cve', ok: true, count: 3, truncatedFrom: null }]);
    assert.equal(s.sourcesTruncated, 0);
  });
});

describe('⛔ grouping — an item is a decision, not a fact', () => {
  // These assert the SHAPE the gathers must produce, because the rule is easy
  // to state and was missed on the first pass: one compliance check failing on
  // five firewalls shipped as five items repeating an identical remediation,
  // which is precisely the wall of duplicated prose a queue exists to replace.
  it('a grouped item keeps every affected device in deviceIds', () => {
    const grouped = item({
      key: 'compliance:any-any',
      count: 5,
      deviceIds: ['d1', 'd2', 'd3', 'd4', 'd5'],
      urgency: 'now',
      evidence: 'measured',
      severity: 'critical',
    });
    const s = summarise(rankItems([grouped]), []);
    assert.equal(s.total, 1, 'one decision, not five');
    assert.equal(s.deviceCount, 5, 'but the scope is not lost');
  });

  it('a grouped item outranks a smaller one of the same severity', () => {
    // The count is what makes breadth visible after aggregation, so it has to
    // participate in the ordering.
    const ranked = rankItems([
      item({ key: 'one', count: 1, urgency: 'now', evidence: 'measured', severity: 'critical' }),
      item({ key: 'five', count: 5, urgency: 'now', evidence: 'measured', severity: 'critical' }),
    ]);
    assert.equal(ranked[0].key, 'five');
  });
});
