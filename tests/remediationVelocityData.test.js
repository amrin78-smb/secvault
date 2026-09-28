'use strict';

// tests/remediationVelocityData.test.js
//
// Pins lib/engines/remediationVelocityData.js — A8's plumbing.
//
// ⛔ THE CENTRAL THING THIS FILE GUARDS. `device_cve_assessments` is
// DELETE+reinserted every match run, so a remediated exposure leaves NO ROW. An
// implementation fed only from that table sees open exposures forever and
// reports 0% remediated — a figure that would be an artefact of the schema and
// indistinguishable from the true 0% this fleet actually has. The reconstruction
// from `device_versions` is what makes the real 0% falsifiable, so these tests
// exercise it with transitions the live fleet does not contain.
//
// NO DATABASE. The pool is a stub routed on the marker comments each query
// carries (`rv:open`, `rv:versions`, `rv:advisories`).

const { describe, it, test } = require('node:test');
const assert = require('node:assert/strict');

const {
  getRemediationVelocity,
  findRemediationEvents,
  advisoryCovers,
  OPEN_EXPOSURES_SQL,
} = require('../lib/engines/remediationVelocityData');

const NOW = new Date('2026-09-28T00:00:00Z');

// A FortiGate advisory covering everything below 7.4.10.
const ADV = {
  id: 'a1',
  cve_id: 'CVE-2026-24858',
  vendor: 'fortinet',
  kev_listed: true,
  cvss_score: '9.4',
  published_at: new Date('2026-01-28T00:00:00Z'),
  created_at: new Date('2026-07-16T00:00:00Z'),
  affected_version_ranges: [{ min: '7.4.0', max: '7.4.10', exclude_fixed: true }],
};

function ver(over) {
  return Object.assign({
    device_id: 'dev-1',
    device_name: 'TSR-TL',
    vendor: 'fortinet',
    version_string: 'v7.4.9,build2573',
    first_seen_at: new Date('2026-07-16T00:00:00Z'),
    last_seen_at: new Date('2026-08-20T00:00:00Z'),
  }, over || {});
}

function stubPool(o) {
  const opts = o || {};
  const calls = [];
  return {
    calls,
    async query(sql) {
      calls.push(sql);
      const which = (sql.match(/rv:(\w+)/) || [])[1];
      if (opts.throwOn === which) throw new Error('boom: ' + which);
      if (which === 'open') return { rows: opts.open || [] };
      if (which === 'versions') return { rows: opts.versions || [] };
      if (which === 'advisories') return { rows: opts.advisories || [ADV] };
      return { rows: [] };
    },
  };
}

// ── the version test ───────────────────────────────────────────────────────

describe('advisoryCovers reuses isInRange and refuses to guess', () => {
  it('an affected version is covered', () => {
    assert.equal(advisoryCovers('fortinet', 'v7.4.9,build2573', ADV.affected_version_ranges), true);
  });

  it('the fixed version is not', () => {
    assert.equal(advisoryCovers('fortinet', 'v7.4.10,build2600', ADV.affected_version_ranges), false);
  });

  it('⛔ an UNREADABLE version is null, never false', () => {
    // parseVersion returns fabricated zeros for junk, so a naive call would
    // test 0.0.0 against the range. Reading that as "not affected" would
    // manufacture a REMEDIATION — the flattering direction, on the one page
    // whose whole job is to be unflattering.
    for (const bad of ['', 'unknown', null, undefined, 'n/a']) {
      assert.equal(advisoryCovers('fortinet', bad, ADV.affected_version_ranges), null,
        `${JSON.stringify(bad)} must be unknown, not "not affected"`);
    }
  });

  it('⛔ no usable ranges is null, never false', () => {
    for (const bad of [null, undefined, [], 'nope', {}]) {
      assert.equal(advisoryCovers('fortinet', 'v7.4.9', bad), null);
    }
  });
});

// ── the reconstruction ─────────────────────────────────────────────────────

describe('⛔ remediation events are reconstructed from version history', () => {
  it('an affected -> fixed transition produces one event', () => {
    const events = findRemediationEvents([
      ver({ version_string: 'v7.4.9,build2573' }),
      ver({
        version_string: 'v7.4.11,build2700',
        first_seen_at: new Date('2026-08-25T00:00:00Z'),
        last_seen_at: NOW,
      }),
    ], [ADV]);
    assert.equal(events.length, 1);
    assert.equal(events[0].cve_id, 'CVE-2026-24858');
    assert.deepEqual(events[0].remediated_at, new Date('2026-08-25T00:00:00Z'),
      'dated at the FIRST observation of the fixed version');
    assert.equal(events[0].remediation_dated_from, 'first_observation_of_fixed_version');
  });

  it('a device that never moved produces none — the live fleet shape', () => {
    assert.deepEqual(findRemediationEvents([ver()], [ADV]), []);
  });

  it('⛔ a move between two AFFECTED versions is not a remediation', () => {
    const events = findRemediationEvents([
      ver({ version_string: 'v7.4.8,build2500' }),
      ver({
        version_string: 'v7.4.9,build2573',
        first_seen_at: new Date('2026-08-25T00:00:00Z'),
      }),
    ], [ADV]);
    assert.deepEqual(events, [], 'upgrading and staying vulnerable is not a fix');
  });

  it('⛔ a move FROM an unreadable version produces no event', () => {
    const events = findRemediationEvents([
      ver({ version_string: 'unknown' }),
      ver({
        version_string: 'v7.4.11,build2700',
        first_seen_at: new Date('2026-08-25T00:00:00Z'),
      }),
    ], [ADV]);
    assert.deepEqual(events, [],
      'we cannot claim it was affected before, so we cannot claim it was fixed');
  });

  it('a different vendor\'s advisory is not applied', () => {
    const pan = Object.assign({}, ADV, { vendor: 'paloalto' });
    const events = findRemediationEvents([
      ver({ version_string: 'v7.4.9,build2573' }),
      ver({ version_string: 'v7.4.11,build2700', first_seen_at: new Date('2026-08-25T00:00:00Z') }),
    ], [pan]);
    assert.deepEqual(events, []);
  });

  it('tolerates junk rather than throwing', () => {
    for (const bad of [null, undefined, 'nope', 42, {}]) {
      assert.ok(Array.isArray(findRemediationEvents(bad, [ADV])));
      assert.ok(Array.isArray(findRemediationEvents([ver(), ver()], bad)));
    }
  });
});

// ── the whole call ─────────────────────────────────────────────────────────

describe('getRemediationVelocity on the live fleet shape', () => {
  const openRow = {
    device_id: 'dev-1',
    device_name: 'TSR-TL',
    cve_id: 'CVE-2026-24858',
    kev_listed: true,
    priority_band: 'patch_now',
    cvss_score: '9.4',
    advisory_published_at: ADV.published_at,
    advisory_known_at: ADV.created_at,
    device_first_seen_at: new Date('2026-07-16T00:00:00Z'),
  };

  it('reports 0% remediated, and says WHY it is 0%', () => {
    return getRemediationVelocity(stubPool({ open: [openRow], versions: [ver()] }), { now: NOW })
      .then((r) => {
        assert.equal(r.ok, true);
        assert.equal(r.summary.exposures, 1);
        assert.equal(r.summary.remediatedPct, 0);
        assert.equal(r.summary.allCensored, true);
        assert.equal(r.headline.tone, 'bad');
        // ⛔ THE CAVEAT THAT SEPARATES "nothing was patched" FROM "nothing was
        // looked for". Without it a 0% is unfalsifiable.
        const keys = r.caveats.map((c) => c.key);
        assert.ok(keys.includes('no_transitions_observed'));
        assert.ok(keys.includes('remediations_are_reconstructed'));
        assert.ok(keys.includes('ages_are_lower_bounds'));
        assert.equal(r.coverage.devicesWithAVersionChange, 0);
        assert.equal(r.coverage.devicesWithVersionHistory, 1);
      });
  });

  it('a reconstructed event lands in the same list as the open ones', async () => {
    const r = await getRemediationVelocity(stubPool({
      open: [openRow],
      versions: [
        ver({ device_id: 'dev-2', device_name: 'SMT', version_string: 'v7.4.9,build2573' }),
        ver({
          device_id: 'dev-2',
          device_name: 'SMT',
          version_string: 'v7.4.11,build2700',
          first_seen_at: new Date('2026-08-25T00:00:00Z'),
        }),
      ],
    }), { now: NOW });
    assert.equal(r.summary.exposures, 2);
    assert.equal(r.summary.remediated, 1);
    assert.equal(r.summary.open, 1);
    assert.ok(!r.caveats.map((c) => c.key).includes('no_transitions_observed'));
    assert.equal(r.coverage.reconstructedEvents, 1);
  });

  it('⛔ A FAILED READ IS NOT AN EMPTY FLEET', () => {
    // A shorter exposure list on this page reads as a better-performing fleet,
    // so a failure must refuse to produce a summary at all.
    // Mapped explicitly rather than string-munged: the marker and the failure
    // label are two different vocabularies, and a substring test between them
    // silently passed for two of the three.
    const LABEL = { open: 'open_exposures', versions: 'version_history', advisories: 'advisory_ranges' };
    return Promise.all(Object.entries(LABEL).map(async ([which, label]) => {
      const r = await getRemediationVelocity(stubPool({ throwOn: which }), { now: NOW });
      assert.equal(r.ok, false, `${which} failing must not be ok`);
      assert.equal(r.summary, null, 'no velocity figure may be rendered');
      assert.equal(r.headline, null);
      assert.ok(r.failures.some((f) => f.source === label),
        `the failure must be named "${label}", got ${JSON.stringify(r.failures)}`);
    }));
  });

  it('the query is restricted to genuinely affected, active devices', () => {
    // An advisory that never applied was never an exposure; counting it would
    // dilute the denominator with work that did not exist.
    assert.match(OPEN_EXPOSURES_SQL, /version_affected = true/);
    assert.match(OPEN_EXPOSURES_SQL, /d\.active = true/);
  });

  test('⛔ it never reads assessed_at', () => {
    // All 246 live rows share one assessed_at, today's — it is rewritten every
    // run and is not an exposure clock.
    assert.ok(!/assessed_at/.test(OPEN_EXPOSURES_SQL));
  });

  it('takes its clock, so a fixed fixture stays testable', async () => {
    const a = await getRemediationVelocity(
      stubPool({ open: [openRow], versions: [ver()] }), { now: NOW });
    const b = await getRemediationVelocity(
      stubPool({ open: [openRow], versions: [ver()] }),
      { now: new Date('2026-12-28T00:00:00Z') });
    assert.ok(b.summary.longestOpenDays > a.summary.longestOpenDays + 80);
  });
});
