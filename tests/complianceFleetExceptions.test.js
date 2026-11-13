'use strict';

// ⛔ WHAT THIS FILE IS FOR.
//
// The fleet exceptions page answers "what risk has been formally accepted, and
// what has quietly stopped being covered?" Every way of getting that wrong is
// the same shape: a register that looks TIDIER than the estate. An empty table
// reading as a clean fleet, a lapsed acceptance counted as cover, a
// deactivated firewall's acceptances inflating the live count, or a failing
// count that could not be read reported as zero — each one makes the page
// calmer than the facts.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  listFleetExceptions,
  countFleetFailingChecks,
  describeExceptions,
  summariseExceptions,
} = require('../lib/engines/complianceExceptions');
const { buildExceptionsAnswer } = require('../lib/answers');

/** A stub pool that records the SQL it was handed. */
function stubPool(result, onQuery) {
  const seen = [];
  return {
    seen,
    query: async (sql, params) => {
      seen.push({ sql, params });
      if (onQuery) return onQuery(sql);
      return result;
    },
  };
}

describe('the fleet read cannot quietly widen or narrow its own scope', () => {
  it('counts only ACTIVE firewalls, via an inner join', async () => {
    const pool = stubPool({ rows: [] });
    await listFleetExceptions(pool);
    const { sql } = pool.seen[0];
    // ⛔ A deactivated firewall's acceptances would otherwise report risk
    // accepted on machines nobody manages any more.
    assert.match(sql, /JOIN devices d ON d\.id = ce\.device_id AND d\.active = true/);
  });

  it('reuses the shared EXCEPTION_SELECT rather than restating it', async () => {
    const pool = stubPool({ rows: [] });
    await listFleetExceptions(pool);
    const { sql } = pool.seen[0];
    // ⛔ Both joins must stay LEFT. A check that left the seed library, and a
    // device that has never been audited, must still show the operator's
    // recorded decision — an inner join here would drop it from the fleet page
    // while it still showed on the device page.
    assert.match(sql, /LEFT JOIN audit_checks ac/);
    assert.match(sql, /LEFT JOIN audit_findings af/);
    assert.match(sql, /ce\.compensating_control/);
  });

  it('the failing-check count is a PAIR count, matching what `covers` counts', async () => {
    const pool = stubPool({ rows: [{ failing: 6 }] });
    assert.equal(await countFleetFailingChecks(pool), 6);
    // ⛔ Not DISTINCT ac.check_id: summariseExceptions subtracts a count of
    // exceptions (one per (device, check) pair) from this, and mixing the
    // units could produce a negative that clamps to 0 and prints as "every
    // failure is accepted".
    assert.doesNotMatch(pool.seen[0].sql, /DISTINCT/i);
    assert.match(pool.seen[0].sql, /d\.active = true/);
  });
});

describe('an unreadable count is null, never zero', () => {
  it('a throwing read returns null', async () => {
    const pool = stubPool(null, () => { throw new Error('connection reset'); });
    assert.equal(await countFleetFailingChecks(pool), null);
  });

  it('no rows, a null, an empty string and a non-number all return null', async () => {
    assert.equal(await countFleetFailingChecks(stubPool({ rows: [] })), null);
    assert.equal(await countFleetFailingChecks(stubPool({ rows: [{ failing: null }] })), null);
    assert.equal(await countFleetFailingChecks(stubPool({ rows: [{ failing: '' }] })), null);
    assert.equal(await countFleetFailingChecks(stubPool({ rows: [{ failing: 'lots' }] })), null);
    // ⛔ Number(null) is 0 and 0 is finite, so a bare Number.isFinite guard
    // would turn "we could not read it" into "nothing is failing" — the exact
    // trap CLAUDE.md records against the licence device count.
    assert.equal(await countFleetFailingChecks(stubPool({ rows: [{ failing: 0 }] })), 0);
  });

  it('and a null count suppresses `unaccepted` rather than claiming full cover', () => {
    const s = summariseExceptions([], null);
    assert.equal(s.failingChecks, null);
    assert.equal(s.unaccepted, null);
  });
});

describe('the sentence never lets the register look tidier than the estate', () => {
  const base = {
    total: 0, accepted: 0, expiring: 0, expired: 0, revoked: 0, covering: 0,
    failingChecks: 0, unaccepted: 0, unreadableExpiry: 0,
    overCheckNotEvaluated: 0, overCheckNoLongerFailing: 0,
  };

  it('an unreadable register is unknown, never "nothing accepted"', () => {
    const a = buildExceptionsAnswer(null);
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /could not be read/i);
  });

  it('an EMPTY register over a failing fleet names the paperwork gap and is not ok', () => {
    const a = buildExceptionsAnswer({ ...base, failingChecks: 6, unaccepted: 6 });
    assert.equal(a.tone, 'unknown');
    assert.match(a.sentence, /6 checks are failing/);
    assert.match(a.sentence, /paperwork, not a result about the firewalls/);
  });

  it('a lapse leads the sentence and is critical', () => {
    const a = buildExceptionsAnswer({ ...base, total: 3, expired: 1, accepted: 2, covering: 2, failingChecks: 6, unaccepted: 4 });
    assert.equal(a.tone, 'critical');
    assert.match(a.lead, /1 exception lapsed/);
    // ⛔ Not "so that failing check…", which reads as one conjunction and
    // makes the reader back up.
    assert.doesNotMatch(a.sentence, /so that failing/);
  });

  it('⛔ `ok` is unreachable — a live exception is accepted risk, not resolved risk', () => {
    const shapes = [
      { ...base, total: 3, accepted: 3, covering: 3, failingChecks: 3, unaccepted: 0 },
      { ...base, total: 1, accepted: 1, covering: 1, failingChecks: 1, unaccepted: 0 },
      { ...base, total: 2, accepted: 1, expiring: 1, covering: 2, failingChecks: 2, unaccepted: 0 },
    ];
    for (const s of shapes) {
      assert.notEqual(buildExceptionsAnswer(s).tone, 'ok', JSON.stringify(s));
    }
  });

  it('stale cover is stated in the coverage line, not swallowed', () => {
    const a = buildExceptionsAnswer({ ...base, total: 2, accepted: 2, covering: 1, overCheckNoLongerFailing: 1, failingChecks: 1, unaccepted: 0 });
    assert.ok(a.coverage, 'a stale acceptance must be qualified beside the claim');
    assert.match(a.coverage, /no longer failing|no longer being evaluated/);
  });
});

describe('a lapsed acceptance stops counting the moment it lapses', () => {
  const row = (over) => ({
    id: 'x', device_id: 'd1', check_slug: 'c1', reason: 'r', accepted_by: 'k',
    accepted_at: '2026-01-01T00:00:00Z', current_status: 'fail', ...over,
  });

  it('read-time expiry: the same row is cover one day and not the next', () => {
    const rows = [row({ expires_at: '2026-11-14T00:00:00Z' })];
    const before = summariseExceptions(describeExceptions(rows, new Date('2026-11-13T00:00:00Z')), 1);
    const after = summariseExceptions(describeExceptions(rows, new Date('2026-11-15T00:00:00Z')), 1);
    assert.equal(before.covering, 1);
    assert.equal(before.unaccepted, 0);
    assert.equal(after.covering, 0);
    // ⛔ The failing check becomes UNACCEPTED with no job having run.
    assert.equal(after.unaccepted, 1);
    assert.equal(after.expired, 1);
  });

  it('an exception over a check that is no longer failing covers nothing', () => {
    const rows = [row({ expires_at: '2027-01-01T00:00:00Z', current_status: 'pass' })];
    const s = summariseExceptions(describeExceptions(rows, new Date('2026-11-13T00:00:00Z')), 0);
    assert.equal(s.accepted, 1);
    assert.equal(s.covering, 0);
    assert.equal(s.overCheckNoLongerFailing, 1);
  });
});
