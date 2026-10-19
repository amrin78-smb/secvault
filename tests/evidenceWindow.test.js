'use strict';
// tests/evidenceWindow.test.js
//
// ⛔ THE BUG THIS MODULE EXISTS TO PREVENT PRODUCES *FEWER* FINDINGS WHILE
// LOOKING LIKE MORE EVIDENCE. ruleHitCorrelation.js gates coverage on
// `sufficientHistory = historyHours >= windowHours`, so a window longer than
// the history that exists makes `covered` false for every device, and
// `ruleAnalysis.js` emits `unused` only for a MEASURED zero. Raising the old
// hardcoded 30 to 90 on a fleet holding 41 days of rollups therefore deletes
// all 185 live `unused` findings, empties the rule-cleanup loop, and throws
// nothing. Every case below is really asking "can this resolver ever hand a
// consumer a window wider than the evidence behind it".

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  resetEvidenceWindowCache,
  MIN_EVIDENCE_WINDOW_DAYS,
  MAX_EVIDENCE_WINDOW_DAYS,
  SAFETY_MARGIN_DAYS,
  resolveEvidenceWindow,
  loadFleetLogHistoryDays,
  resolveEvidenceWindowDays,
} = require('../lib/engines/evidenceWindow');

describe('⛔ the window is never wider than the history behind it', () => {
  it('the live fleet case: 40.31 days available resolves to 39, not 90', () => {
    // Measured on the reference deployment 2026-10-19. The old literal was 30,
    // so this is a real gain; 90 would have been a silent regression.
    const r = resolveEvidenceWindow(40.31);
    assert.equal(r.days, 39);
    assert.equal(r.reason, 'adaptive');
    assert.ok(r.days < 40.31, 'the window must stay strictly inside the history');
  });

  it('⛔ the resolved window is ALWAYS strictly less than availableDays', () => {
    // The property, swept rather than sampled — this is the whole safety claim.
    for (let d = MIN_EVIDENCE_WINDOW_DAYS + 2; d <= 400; d += 0.37) {
      const r = resolveEvidenceWindow(d);
      assert.ok(r.days < d, `window ${r.days} must be < available ${d}`);
    }
  });

  it('caps at MAX so an "unused" claim never rests on year-old traffic', () => {
    const r = resolveEvidenceWindow(500);
    assert.equal(r.days, MAX_EVIDENCE_WINDOW_DAYS);
    assert.equal(r.reason, 'capped');
  });

  it('the margin is applied, not just the floor()', () => {
    // 42 days available: floor(42) - 1 = 41, not 42.
    assert.equal(resolveEvidenceWindow(42).days, 42 - SAFETY_MARGIN_DAYS);
  });
});

describe('⛔ the floor is the no-regression guarantee', () => {
  it('less history than MIN still yields MIN — today’s behaviour, not a narrower window', () => {
    // Narrowing below MIN would change what `unused` MEANS on a young install.
    // Staying at MIN leaves sufficientHistory correctly false, which is exactly
    // what the old fixed literal already did.
    for (const d of [0, 1, 5, 29, 30, 31]) {
      const r = resolveEvidenceWindow(d);
      assert.equal(r.days, MIN_EVIDENCE_WINDOW_DAYS, `available ${d} must floor to MIN`);
      assert.equal(r.reason, 'floored');
    }
  });

  it('a brand-new install (zero history) is floored, never zero or negative', () => {
    const r = resolveEvidenceWindow(0);
    assert.equal(r.days, MIN_EVIDENCE_WINDOW_DAYS);
    assert.ok(r.days > 0);
  });
});

describe('⛔ an unmeasurable history falls back to the FLOOR, never the cap', () => {
  // The signature bug of this codebase is a failed read recorded as a
  // confident value. Here the dangerous fallback is the CAP: it would collapse
  // `covered` fleet-wide on precisely the runs whose read failed.
  for (const [label, input] of [
    ['null', null],
    ['undefined', undefined],
    ['NaN', NaN],
    ['a string', 'forty'],
    ['Infinity', Infinity],
    ['negative (clock disagreement)', -3],
  ]) {
    it(`${label} resolves to MIN with a stated reason`, () => {
      const r = resolveEvidenceWindow(input);
      assert.equal(r.days, MIN_EVIDENCE_WINDOW_DAYS);
      assert.notEqual(r.days, MAX_EVIDENCE_WINDOW_DAYS);
      assert.match(r.reason, /unknown_history|unreadable_history/);
    });
  }

  it('the two unmeasurable cases are NOT collapsed into one reason', () => {
    // "nothing has ever been measured" and "the value we got back is junk" send
    // an operator to different places.
    assert.equal(resolveEvidenceWindow(null).reason, 'unknown_history');
    assert.equal(resolveEvidenceWindow(NaN).reason, 'unreadable_history');
  });
});

describe('⛔ the read never throws and never guesses', () => {
  const stub = (impl) => ({ query: impl });

  it('a throwing pool yields null, which the policy floors', async () => {
    const days = await loadFleetLogHistoryDays(stub(async () => { throw new Error('db down'); }));
    assert.equal(days, null);
    const r = await resolveEvidenceWindowDays(stub(async () => { throw new Error('db down'); }));
    assert.equal(r.days, MIN_EVIDENCE_WINDOW_DAYS);
    assert.equal(r.reason, 'unknown_history');
  });

  it('no rollup rows at all yields null, not zero days', async () => {
    const r = await resolveEvidenceWindowDays(stub(async () => ({ rows: [{ youngest: null }] })));
    assert.equal(r.days, MIN_EVIDENCE_WINDOW_DAYS);
    assert.equal(r.availableDays, null, 'absent history is unknown, never 0');
  });

  it('⛔ it asks for the YOUNGEST source, not the oldest', async () => {
    // Keyed on the youngest source so the per-device ratio budget (0.9) stays
    // available for collector restarts and network blips rather than being
    // spent on a device’s late onboarding. Measured live: the fleet reaches
    // back 41.1 days, OKF(F2) only 40.3, and the gate covers 15/15 devices at
    // 39 days but 0/15 at 90.
    let sql = '';
    await loadFleetLogHistoryDays(stub(async (q) => { sql = q; return { rows: [] }; }));
    assert.match(sql, /max\(first_bucket\)/, 'must take the LATEST per-device first bucket');
    assert.match(sql, /min\(bucket_hour\)/);
    assert.match(sql, /GROUP BY device_id/);
    // An unmanaged sender must not be able to peg the fleet at the floor.
    assert.match(sql, /device_id IS NOT NULL/);
  });

  it('a first bucket in the FUTURE is unmeasurable, not negative history', async () => {
    const future = new Date(Date.now() + 86400000 * 5);
    const r = await resolveEvidenceWindowDays(stub(async () => ({ rows: [{ youngest: future }] })));
    assert.equal(r.days, MIN_EVIDENCE_WINDOW_DAYS);
    assert.equal(r.availableDays, null);
  });

  it('resolves the real shape end to end', async () => {
    const first = new Date(Date.now() - 86400000 * 40.31);
    const r = await resolveEvidenceWindowDays(stub(async () => ({ rows: [{ youngest: first }] })));
    assert.equal(r.days, 39);
    assert.equal(r.reason, 'adaptive');
  });
});

describe('⛔ the bounds themselves are pinned', () => {
  it('MIN is exactly the literal every consumer used before this module', () => {
    // Four separate hardcoded 30s. If MIN ever moves, the no-regression claim
    // in this module’s header stops being true.
    assert.equal(MIN_EVIDENCE_WINDOW_DAYS, 30);
  });
  it('MIN < MAX and the margin is smaller than the span', () => {
    assert.ok(MIN_EVIDENCE_WINDOW_DAYS < MAX_EVIDENCE_WINDOW_DAYS);
    assert.ok(SAFETY_MARGIN_DAYS >= 1);
    assert.ok(SAFETY_MARGIN_DAYS < MAX_EVIDENCE_WINDOW_DAYS - MIN_EVIDENCE_WINDOW_DAYS);
  });
});

// ── the de-duplication itself, asserted against the source ──────────────────

describe('⛔ the window has ONE definition and the consumers may not redefine it', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const { stripComments } = require('./stripComments');

  // Every module that feeds getDeviceLogCoverage / getLoggedRuleHits. Before
  // this module existed, four of these carried their own `= 30` and
  // coverageRegisterData.js's header relied on all four being edited together
  // — which is a hope, not an invariant. The register grading usage over a
  // different window from the page it links to is the failure it warns about.
  const CONSUMERS = [
    'lib/engines/ruleAnalysis.js',
    'lib/engines/ruleHitCorrelation.js',
    'lib/engines/ruleChangeRequestReport.js',
    'lib/engines/coverageRegisterData.js',
    'lib/engines/segmentationData.js',
    'lib/engines/applicationViewData.js',
    'lib/reports/ruleHygiene.js',
  ];

  const read = (rel) => fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');

  for (const rel of CONSUMERS) {
    it(`${rel} takes the window from evidenceWindow.js`, () => {
      const src = read(rel);
      assert.match(
        src,
        /require\((['"])(\.\.?\/)+(engines\/)?evidenceWindow\1\)/,
        `${rel} must import the shared window, not define its own`
      );
    });

    it(`${rel} carries no hardcoded log-evidence window literal`, () => {
      const src = read(rel);
      // ⛔ THE SHARED STRIPPER, AND NOT A HAND-ROLLED PAIR OF replace() CALLS.
      // These files DISCUSS the old literal at length, so a raw-source scan
      // would read the explanation as the defect — the mistake the device-scope
      // coverage check made when it read notificationChannels.js's prose as
      // evidence of device data. And the ORDER of the two strippers matters:
      // block-before-line lets a `/*` inside a `//` comment open a phantom
      // block that eats real code, which tests/stripOrder.test.js exists to
      // fail the build over. It caught this test on its first run.
      const code = stripComments(src);
      const offenders = code
        .split('\n')
        .filter((l) => /(EVIDENCE_WINDOW_DAYS|logEvidenceDays|DEFAULT_WINDOW_DAYS)\s*[:=]\s*\d+/.test(l));
      assert.deepEqual(
        offenders.map((l) => l.trim()), [],
        `${rel} must not hardcode the window; use MIN_EVIDENCE_WINDOW_DAYS`
      );
    });
  }

  it('⛔ the resolver is the only place the two bounds are written as numbers', () => {
    const src = read('lib/engines/evidenceWindow.js');
    assert.match(src, /const MIN_EVIDENCE_WINDOW_DAYS = 30;/);
    assert.match(src, /const MAX_EVIDENCE_WINDOW_DAYS = 90;/);
  });
});

// ── one resolution per pass ─────────────────────────────────────────────────

describe('⛔ the window is resolved ONCE per pass, not once per device', () => {
  const countingPool = (firstBucket) => {
    const calls = [];
    return {
      calls,
      async query(sql, params) {
        calls.push({ sql, params });
        return { rows: [{ youngest: firstBucket }] };
      },
    };
  };
  const FIRST = () => new Date(Date.now() - 86400000 * 40.34);

  it('repeated calls on the SAME pool issue one query', async () => {
    // loadOptionsFromSettings sits inside runAnalysisForDevice, which both
    // runAnalysisForAllDevices and collectAndStore call PER DEVICE — so this
    // was 16 aggregates per nightly pass on the reference fleet.
    const pool = countingPool(FIRST());
    const a = await resolveEvidenceWindowDays(pool);
    const b = await resolveEvidenceWindowDays(pool);
    const c = await resolveEvidenceWindowDays(pool);
    assert.equal(pool.calls.length, 1, 'one aggregate for the whole pass');
    assert.equal(a.days, 39);
    // ⛔ AND THE SAME ANSWER EVERY TIME. Each device resolving independently
    // meant two firewalls in one pass could get different windows if
    // floor(availableDays) ticked mid-run — and that number is written into the
    // stored finding text, persisting "39 days" beside "40 days" for one run.
    assert.equal(b.days, a.days);
    assert.equal(c.days, a.days);
  });

  it('⛔ a DIFFERENT pool always issues its own query', async () => {
    // What makes the cache safe in tests: production holds one singleton pool,
    // every test builds a fresh stub. A time-keyed cache would have made
    // query-count assertions depend on how fast the suite runs.
    const p1 = countingPool(FIRST());
    const p2 = countingPool(FIRST());
    await resolveEvidenceWindowDays(p1);
    await resolveEvidenceWindowDays(p2);
    assert.equal(p1.calls.length, 1);
    assert.equal(p2.calls.length, 1);
  });

  it('resetEvidenceWindowCache forces a fresh read', async () => {
    const pool = countingPool(FIRST());
    await resolveEvidenceWindowDays(pool);
    resetEvidenceWindowCache(pool);
    await resolveEvidenceWindowDays(pool);
    assert.equal(pool.calls.length, 2);
  });

  it('⛔ an explicit `now` BYPASSES the cache and is threaded into the read', async () => {
    // The resolver read the real wall clock and ignored the caller's pinned
    // clock, while the caller handed that pinned clock to getDeviceLogCoverage.
    // With only one day of margin, a caller pinning `now` even a few days back
    // resolved a window WIDER than its own clock could justify, making
    // sufficientHistory false for the entire fleet.
    const first = new Date('2026-09-01T00:00:00Z');
    const pool = countingPool(first);

    // Real clock: ~48 days of history by 2026-10-19 -> a wide window.
    const live = await resolveEvidenceWindowDays(pool);
    // Pinned 10 days after that first bucket -> only 10 days of history, so the
    // window must collapse to the floor, NOT stay at the live value.
    const pinned = await resolveEvidenceWindowDays(pool, new Date('2026-09-11T00:00:00Z'));

    assert.equal(pinned.days, MIN_EVIDENCE_WINDOW_DAYS,
      'a pinned clock seeing 10 days of history must floor, not inherit the live window');
    assert.ok(live.days > pinned.days, 'the live clock sees more history than the pinned one');
    assert.equal(pool.calls.length, 2, 'an explicit now must not be served from cache');
  });
});
