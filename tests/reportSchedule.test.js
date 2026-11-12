'use strict';
//
// Pins lib/engines/reportSchedule.js (pure) and lib/engines/reportScheduleData.js
// (the plumbing, exercised with a stub pool).
//
// ⛔ WHAT THIS FILE IS ACTUALLY DEFENDING. A scheduler has exactly two ways to
// be wrong, and both are silent:
//   1. it sends the same document twice — an auditor holding two identical,
//      equally official compliance PDFs with no way to tell which is the real
//      one; and
//   2. it stops sending and nothing says so — the report simply never arrives,
//      every signal still green, and somebody finds out when they are asked for
//      it.
// Both come from the same root as every other bug in this codebase: a FAILED
// READ RECORDED AS A FACT. Here the read is "when did this last deliver", and
// the fact invented from it is "never" (-> resend for ever) or "already"
// (-> silence for ever). So the central test below is not the happy path, it is
// `lastSuccessPeriod === undefined`.
//
// No database. runReportScheduleJob/resolveDueSchedules take a pool, so they
// get a stub that returns canned rows and records the SQL it was handed — the
// same convention tests/configRetention.test.js uses, and it gives two
// independent things to pin: the statements built, and the interpretation of
// what comes back.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  FREQUENCIES,
  DAY_NAMES,
  DUE_REASONS,
  MAX_DAY_OF_MONTH,
  periodKeyFor,
  dueState,
  describeSchedule,
  validateSchedule,
} = require('../lib/engines/reportSchedule');

const {
  evaluateSchedules,
  resolveDueSchedules,
  runReportScheduleJob,
  recipientCount,
  formatScheduleSummary,
} = require('../lib/engines/reportScheduleData');

const { reportById } = require('../lib/reports/catalogue');

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

/** A local Date, built from components so the test never depends on the host's
 *  zone — the engine reads LOCAL getters throughout, deliberately. */
const at = (y, m, d, h = 0, min = 0) => new Date(y, m - 1, d, h, min, 0, 0);

/** A report_schedules row as listSchedules returns it. */
function row(over = {}) {
  return {
    id: '11111111-1111-4111-8111-111111111111',
    report_id: 'compliance-fleet',
    params: {},
    device_id: null,
    frequency: 'monthly',
    hour: 6,
    day_of_week: null,
    day_of_month: 1,
    channel_id: '22222222-2222-4222-8222-222222222222',
    enabled: true,
    channel_name: 'Audit mailbox',
    channel_type: 'email',
    channel_enabled: true,
    device_name: null,
    last_success_period: null,
    last_success_at: null,
    last_attempt_status: null,
    last_attempt_error: null,
    last_attempt_at: null,
    created_at: at(2026, 1, 1),
    updated_at: at(2026, 1, 1),
    created_by: 'amrin',
    ...over,
  };
}

const isScheduleSelect = (sql) => /FROM\s+report_schedules\s+s/i.test(sql);
const isDeliveryInsert = (sql) => /INSERT\s+INTO\s+report_delivery_log/i.test(sql);

/** Records every {sql, params}. `handler` may return a result object, or an
 *  Error instance meaning "reject with this". */
function stubPool(handler) {
  const calls = [];
  return {
    calls,
    query(sql, params) {
      calls.push({ sql: String(sql), params });
      const result = handler ? handler(String(sql), params, calls.length) : undefined;
      if (result instanceof Error) return Promise.reject(result);
      return Promise.resolve(result || { rows: [], rowCount: 0 });
    },
  };
}

/** A pool that answers the schedule select with `rows` and swallows inserts. */
function poolWith(rows, extra) {
  return stubPool((sql, params, n) => {
    if (isScheduleSelect(sql)) return { rows, rowCount: rows.length };
    if (extra) {
      const r = extra(sql, params, n);
      if (r !== undefined) return r;
    }
    return { rows: [], rowCount: 1 };
  });
}

// --------------------------------------------------------------------------
describe('periodKeyFor — the firing slot, which IS the double-send guarantee', () => {
  it('daily is the local calendar day', () => {
    assert.equal(periodKeyFor('daily', at(2026, 11, 12, 23, 59)), '2026-11-12');
    assert.equal(periodKeyFor('daily', at(2026, 1, 5, 0, 0)), '2026-01-05');
  });

  it('monthly is the local calendar month', () => {
    assert.equal(periodKeyFor('monthly', at(2026, 2, 28, 18)), '2026-02');
  });

  it('weekly is the ISO week', () => {
    assert.equal(periodKeyFor('weekly', at(2026, 11, 12, 12)), '2026-W46');
  });

  it('⛔ the ISO YEAR is used, not the calendar year', () => {
    // Both of these fall in an ISO week belonging to the OTHER year. Keying on
    // getFullYear() would emit '2027-W53' and '2025-W01' — slots belonging to
    // neither year, and the log dedupes on this string, so a wrong key means a
    // double send or a lost week once a year, on a date nobody checks by hand.
    assert.equal(periodKeyFor('weekly', at(2027, 1, 1, 12)), '2026-W53');
    assert.equal(periodKeyFor('weekly', at(2025, 12, 29, 12)), '2026-W01');
  });

  it('a Sunday belongs to the ISO week that STARTED on the previous Monday', () => {
    // 2026-11-15 is a Sunday; Monday 2026-11-09 is W46.
    assert.equal(periodKeyFor('weekly', at(2026, 11, 15, 12)), '2026-W46');
    assert.equal(periodKeyFor('weekly', at(2026, 11, 16, 12)), '2026-W47');
  });

  it('returns null — never a plausible key — for junk', () => {
    assert.equal(periodKeyFor('hourly', at(2026, 1, 1)), null);
    assert.equal(periodKeyFor('daily', 'not a date'), null);
    assert.equal(periodKeyFor('daily', null), null);
  });
});

// --------------------------------------------------------------------------
describe('dueState', () => {
  it('a daily schedule is due once its hour has arrived and not before', () => {
    const s = row({ frequency: 'daily', hour: 6, day_of_month: null });
    assert.equal(dueState(s, at(2026, 11, 12, 5, 59), null).due, false);
    assert.equal(dueState(s, at(2026, 11, 12, 5, 59), null).reason, DUE_REASONS.NOT_REACHED);
    const due = dueState(s, at(2026, 11, 12, 6, 5), null);
    assert.equal(due.due, true);
    assert.equal(due.period, '2026-11-12');
    assert.equal(due.reason, DUE_REASONS.DUE);
  });

  it('a slot already delivered is not due again', () => {
    const s = row({ frequency: 'daily', hour: 6, day_of_month: null });
    const v = dueState(s, at(2026, 11, 12, 9), '2026-11-12');
    assert.equal(v.due, false);
    assert.equal(v.reason, DUE_REASONS.ALREADY);
    // and LAST week's delivery does not satisfy today's slot
    assert.equal(dueState(s, at(2026, 11, 12, 9), '2026-11-11').due, true);
  });

  it('⛔ an UNREADABLE delivery history SKIPS — it is not "never delivered"', () => {
    // THE test in this file. `undefined` means the log could not be read.
    // Folding it into `null` would re-send on every tick for as long as the read
    // kept failing; folding it into "already delivered" would silence the
    // schedule for ever. Both are wrong, and the skip is chosen because a late
    // report is recoverable and a duplicated audit PDF is not.
    const s = row({ frequency: 'daily', hour: 6, day_of_month: null });
    const unknown = dueState(s, at(2026, 11, 12, 9), undefined);
    assert.equal(unknown.due, false);
    assert.equal(unknown.reason, DUE_REASONS.UNKNOWN_HISTORY);
    // The period is still reported, so the caller can name the slot it skipped.
    assert.equal(unknown.period, '2026-11-12');

    // ... and a MEASURED "nothing delivered" (null) is a different answer.
    const measured = dueState(s, at(2026, 11, 12, 9), null);
    assert.equal(measured.due, true);
    assert.notEqual(measured.reason, unknown.reason);
  });

  it('a paused schedule is not blocked-on-a-read, it is simply disabled', () => {
    // The order matters: `disabled` is decided BEFORE the history is judged, so
    // a paused schedule is never reported as stuck behind a failed read.
    const s = row({ enabled: false });
    assert.equal(dueState(s, at(2026, 11, 12, 9), undefined).reason, DUE_REASONS.DISABLED);
  });

  it('weekly fires on its own day and is still due later in the same week', () => {
    const s = row({ frequency: 'weekly', hour: 7, day_of_week: 1, day_of_month: null });
    // 2026-11-09 is a Monday.
    assert.equal(dueState(s, at(2026, 11, 9, 6), null).reason, DUE_REASONS.NOT_REACHED);
    assert.equal(dueState(s, at(2026, 11, 9, 7), null).due, true);
    // Thursday of the same week: the slot passed and was never delivered.
    assert.equal(dueState(s, at(2026, 11, 12, 1), null).due, true);
    // ⛔ THE SUNDAY BELONGS TO THE WEEK THAT STARTED ON THE PREVIOUS MONDAY.
    // Sunday 2026-11-08 sits at the END of ISO week 2026-W45 (Mon 11-02 .. Sun
    // 11-08), so the slot it is asking about is Monday 11-02 — already passed.
    // Treating Sunday as the START of the next week would make this W46 and
    // report the slot as not yet reached, i.e. skip a whole week's delivery.
    assert.equal(dueState(s, at(2026, 11, 8, 23), null).period, '2026-W45');
    assert.equal(dueState(s, at(2026, 11, 8, 23), '2026-W45').reason, DUE_REASONS.ALREADY);
  });

  it('a Sunday schedule is not treated as already-passed on the Monday', () => {
    // day_of_week 0 = Sunday, which is ISO position 7, not 0. Reading it as 0
    // would make every Monday look like "the slot has passed" and deliver six
    // days early, every week.
    const s = row({ frequency: 'weekly', hour: 8, day_of_week: 0, day_of_month: null });
    assert.equal(dueState(s, at(2026, 11, 9, 23), null).reason, DUE_REASONS.NOT_REACHED);
    assert.equal(dueState(s, at(2026, 11, 15, 8), null).due, true);
  });

  it('monthly fires on its day and remains due for the rest of the month', () => {
    const s = row({ frequency: 'monthly', hour: 6, day_of_month: 3 });
    assert.equal(dueState(s, at(2026, 11, 2, 23), null).reason, DUE_REASONS.NOT_REACHED);
    assert.equal(dueState(s, at(2026, 11, 3, 5), null).reason, DUE_REASONS.NOT_REACHED);
    assert.equal(dueState(s, at(2026, 11, 3, 6), null).due, true);
    assert.equal(dueState(s, at(2026, 11, 27, 1), null).due, true);
  });

  it('⛔ only the CURRENT period is ever delivered — a missed month is not back-filled', () => {
    // A report is a point-in-time measurement. Building last month's document
    // from today's data and filing it under last month's slot is a mislabelled
    // artefact, which on an audit PDF is worse than an absent one.
    const s = row({ frequency: 'monthly', hour: 6, day_of_month: 1 });
    const v = dueState(s, at(2026, 11, 20, 12), '2026-09');
    assert.equal(v.period, '2026-11', 'the period is always the slot NOW falls in');
    assert.equal(v.due, true);
  });

  it('a malformed row is invalid, never due, and never throws', () => {
    assert.equal(dueState(null, at(2026, 1, 1), null).reason, DUE_REASONS.INVALID);
    assert.equal(dueState(row({ frequency: 'hourly' }), at(2026, 1, 1), null).due, false);
    assert.equal(dueState(row({ hour: 99 }), at(2026, 1, 1), null).reason, DUE_REASONS.INVALID);
    assert.equal(
      dueState(row({ frequency: 'weekly', day_of_week: null, day_of_month: null }),
        at(2026, 1, 1), null).reason,
      DUE_REASONS.INVALID
    );
    assert.equal(dueState(row(), 'not a date', null).reason, DUE_REASONS.INVALID);
  });

  it('tolerates the numeric-string shapes a form and a driver produce', () => {
    const s = row({ frequency: 'weekly', hour: '7', day_of_week: '1', day_of_month: null });
    assert.equal(dueState(s, at(2026, 11, 9, 7), null).due, true);
  });
});

// --------------------------------------------------------------------------
describe('describeSchedule — ONE sentence, shared by the panel, the API and the log', () => {
  it('names the day and the hour for each frequency', () => {
    assert.equal(describeSchedule({ frequency: 'daily', hour: 6 }), 'Every day at 06:00');
    assert.equal(
      describeSchedule({ frequency: 'weekly', hour: 7, day_of_week: 1 }),
      'Every Monday at 07:00'
    );
    assert.equal(
      describeSchedule({ frequency: 'monthly', hour: 18, day_of_month: 28 }),
      'Day 28 of each month at 18:00'
    );
  });

  it('⛔ an unusable row says so rather than printing half a sentence', () => {
    // "Every  at :00" reads as a rendering fault; a reader cannot tell it from
    // a schedule that is simply mis-stored.
    assert.equal(describeSchedule({ frequency: 'weekly', hour: 7 }), 'Not a usable schedule');
    assert.equal(describeSchedule(null), 'Not a usable schedule');
    assert.equal(describeSchedule({ frequency: 'daily', hour: 24 }), 'Not a usable schedule');
  });

  it('DAY_NAMES is indexed by day_of_week, 0 = Sunday', () => {
    assert.equal(DAY_NAMES[0], 'Sunday');
    assert.equal(DAY_NAMES[6], 'Saturday');
    assert.equal(DAY_NAMES.length, 7);
  });
});

// --------------------------------------------------------------------------
describe('validateSchedule — the catalogue is the allow-list', () => {
  const compliance = reportById('compliance-fleet');
  const traffic = reportById('traffic-activity');
  const changeRequest = reportById('rule-change-request');
  const executive = reportById('executive-summary');
  const CHANNEL = '22222222-2222-4222-8222-222222222222';
  const DEVICE = '33333333-3333-4333-8333-333333333333';

  it('accepts a well-formed monthly schedule and normalises it', () => {
    const r = validateSchedule({
      report_id: 'compliance-fleet',
      frequency: 'monthly',
      day_of_month: '1',
      hour: '6',
      channel_id: CHANNEL,
      params: { standard: 'PCI_DSS' },
    }, compliance);
    assert.equal(r.ok, true, r.errors.join(' '));
    assert.deepEqual(r.value, {
      report_id: 'compliance-fleet',
      params: { standard: 'PCI_DSS' },
      device_id: null,
      frequency: 'monthly',
      hour: 6,
      day_of_week: null,
      day_of_month: 1,
      channel_id: CHANNEL,
      enabled: true,
    });
  });

  it('⛔ a parameter value outside the entry\'s own choices is REFUSED, not dropped', () => {
    // Dropping it would quietly deliver the whole-fleet document under a
    // filename saying PCI — a mislabelled audit artefact arriving every month
    // with nobody checking.
    const r = validateSchedule({
      report_id: 'compliance-fleet',
      frequency: 'monthly',
      day_of_month: 1,
      channel_id: CHANNEL,
      params: { standard: 'HIPAA' },
    }, compliance);
    assert.equal(r.ok, false);
    assert.equal(r.value, null);
    assert.match(r.errors.join(' '), /HIPAA/);
  });

  it('⛔ an UNDECLARED parameter key is refused', () => {
    const r = validateSchedule({
      report_id: 'executive-summary',
      frequency: 'daily',
      channel_id: CHANNEL,
      params: { standard: 'PCI_DSS' },
    }, executive);
    assert.equal(r.ok, false);
    assert.match(r.errors.join(' '), /no parameter called standard/);
  });

  it('⛔ a fixed date RANGE cannot be scheduled', () => {
    // Two absolute timestamps stored on a schedule never move, so a weekly
    // delivery would mail the same fixed week for ever under a cover page
    // claiming "the last 7 days".
    const r = validateSchedule({
      report_id: 'traffic-activity',
      frequency: 'weekly',
      day_of_week: 1,
      channel_id: CHANNEL,
      params: { from: '2026-01-01T00:00:00Z', to: '2026-01-08T00:00:00Z' },
    }, traffic);
    assert.equal(r.ok, false);
    assert.match(r.errors.join(' '), /same window every time/);

    // ... and with no range supplied it is schedulable, so the refusal is
    // narrow rather than banning the report.
    const ok = validateSchedule({
      report_id: 'traffic-activity',
      frequency: 'weekly',
      day_of_week: 1,
      channel_id: CHANNEL,
    }, traffic);
    assert.equal(ok.ok, true, ok.errors.join(' '));
    assert.deepEqual(ok.value.params, {});
  });

  it('⛔ an entity-scoped report cannot be scheduled, with the reason named', () => {
    const r = validateSchedule({
      report_id: 'rule-change-request',
      frequency: 'daily',
      channel_id: CHANNEL,
    }, changeRequest);
    assert.equal(r.ok, false);
    assert.match(r.errors.join(' '), /single record/);
  });

  it('a report the catalogue does not carry is refused by name', () => {
    const r = validateSchedule({
      report_id: 'nope', frequency: 'daily', channel_id: CHANNEL,
    }, null);
    assert.equal(r.ok, false);
    assert.match(r.errors.join(' '), /No such report: nope/);
  });

  it('the grain field the frequency needs is required, and the other is refused', () => {
    const weeklyNoDay = validateSchedule({
      report_id: 'executive-summary', frequency: 'weekly', channel_id: CHANNEL,
    }, executive);
    assert.equal(weeklyNoDay.ok, false);
    assert.match(weeklyNoDay.errors.join(' '), /day_of_week/);

    const dailyWithDay = validateSchedule({
      report_id: 'executive-summary', frequency: 'daily', day_of_week: 2, channel_id: CHANNEL,
    }, executive);
    assert.equal(dailyWithDay.ok, false);
    assert.match(dailyWithDay.errors.join(' '), /meaningless for a daily schedule/);

    const monthlyWithDow = validateSchedule({
      report_id: 'executive-summary',
      frequency: 'monthly',
      day_of_month: 4,
      day_of_week: 2,
      channel_id: CHANNEL,
    }, executive);
    assert.equal(monthlyWithDow.ok, false);
  });

  it(`⛔ day_of_month stops at ${MAX_DAY_OF_MONTH}, and the message says why`, () => {
    const r = validateSchedule({
      report_id: 'executive-summary', frequency: 'monthly', day_of_month: 30, channel_id: CHANNEL,
    }, executive);
    assert.equal(r.ok, false);
    assert.match(r.errors.join(' '), /February/);
    assert.equal(
      validateSchedule({
        report_id: 'executive-summary',
        frequency: 'monthly',
        day_of_month: MAX_DAY_OF_MONTH,
        channel_id: CHANNEL,
      }, executive).ok,
      true
    );
  });

  it('⛔ an unparseable hour is an ERROR, never a silent fallback to the default', () => {
    // The same call SESSION_IDLE_MINUTES makes: a typo must not quietly move a
    // delivery (or, there, switch a security control off).
    const bad = validateSchedule({
      report_id: 'executive-summary', frequency: 'daily', hour: 'noon', channel_id: CHANNEL,
    }, executive);
    assert.equal(bad.ok, false);
    assert.match(bad.errors.join(' '), /hour must be/);

    const negative = validateSchedule({
      report_id: 'executive-summary', frequency: 'daily', hour: -1, channel_id: CHANNEL,
    }, executive);
    assert.equal(negative.ok, false);

    // Absent IS allowed, and takes the column default.
    const absent = validateSchedule({
      report_id: 'executive-summary', frequency: 'daily', channel_id: CHANNEL,
    }, executive);
    assert.equal(absent.ok, true, absent.errors.join(' '));
    assert.equal(absent.value.hour, 6);
    // ... and an explicit 0 is midnight, not "absent".
    assert.equal(
      validateSchedule({
        report_id: 'executive-summary', frequency: 'daily', hour: 0, channel_id: CHANNEL,
      }, executive).value.hour,
      0
    );
  });

  it('a channel id is required and must look like one', () => {
    const r = validateSchedule({
      report_id: 'executive-summary', frequency: 'daily', channel_id: 'the audit mailbox',
    }, executive);
    assert.equal(r.ok, false);
    assert.match(r.errors.join(' '), /channel_id/);
  });

  it('⛔ a report that cannot narrow REFUSES a device rather than ignoring it', () => {
    // Ignoring it answers "the posture of THIS firewall" with the whole-fleet
    // document — the same mislabelled artefact the download route refuses.
    const notNarrowable = reportById('rule-change-request');
    const r = validateSchedule({
      report_id: 'rule-change-request',
      frequency: 'daily',
      channel_id: CHANNEL,
      device_id: DEVICE,
    }, notNarrowable);
    assert.equal(r.ok, false);
    assert.match(r.errors.join(' '), /cannot be narrowed|single record/);

    // A fleet report declaring optionalDevice accepts one.
    const ok = validateSchedule({
      report_id: 'compliance-fleet',
      frequency: 'monthly',
      day_of_month: 1,
      channel_id: CHANNEL,
      device_id: DEVICE,
    }, compliance);
    assert.equal(ok.ok, true, ok.errors.join(' '));
    assert.equal(ok.value.device_id, DEVICE);
  });

  it('a malformed device id is a bad request, not an empty report', () => {
    const r = validateSchedule({
      report_id: 'compliance-fleet',
      frequency: 'monthly',
      day_of_month: 1,
      channel_id: CHANNEL,
      device_id: 'TSR_EKC',
    }, compliance);
    assert.equal(r.ok, false);
    assert.match(r.errors.join(' '), /not a valid identifier/);
  });

  it('never throws, whatever it is handed', () => {
    for (const junk of [null, undefined, 'a string', 42, [], { params: 'nope' }]) {
      const r = validateSchedule(junk, compliance);
      assert.equal(r.ok, false);
      assert.ok(Array.isArray(r.errors) && r.errors.length > 0);
    }
  });

  it('only an explicit false disables', () => {
    const base = {
      report_id: 'executive-summary', frequency: 'daily', channel_id: CHANNEL,
    };
    assert.equal(validateSchedule(base, executive).value.enabled, true);
    assert.equal(validateSchedule({ ...base, enabled: false }, executive).value.enabled, false);
    assert.equal(validateSchedule({ ...base, enabled: 'true' }, executive).value.enabled, true);
  });

  it('FREQUENCIES is frozen and is the three the CHECK constraint permits', () => {
    assert.deepEqual([...FREQUENCIES], ['daily', 'weekly', 'monthly']);
    assert.equal(Object.isFrozen(FREQUENCIES), true);
  });
});

// --------------------------------------------------------------------------
describe('resolveDueSchedules / evaluateSchedules', () => {
  it('reads only ENABLED schedules, and parameterises its SQL', () => {
    const pool = poolWith([]);
    return resolveDueSchedules(pool, at(2026, 11, 12, 9)).then(() => {
      const select = pool.calls.find((c) => isScheduleSelect(c.sql));
      assert.ok(select, 'no schedule select was issued');
      assert.match(select.sql, /s\.enabled = TRUE/);
      // the last SUCCESSFUL delivery is what due-ness is derived from
      assert.match(select.sql, /status = 'success'/);
      // ⛔ and there is no stored next-run anywhere in the statement
      assert.doesNotMatch(select.sql, /next_run_at/);
    });
  });

  it('returns only the due ones, each with its slot', async () => {
    const due = row({ id: 'due-1', frequency: 'daily', hour: 6, day_of_month: null });
    const notYet = row({ id: 'later', frequency: 'daily', hour: 23, day_of_month: null });
    const done = row({
      id: 'done', frequency: 'daily', hour: 6, day_of_month: null,
      last_success_period: '2026-11-12',
    });
    const out = await resolveDueSchedules(poolWith([due, notYet, done]), at(2026, 11, 12, 9));
    assert.deepEqual(out.map((o) => o.schedule.id), ['due-1']);
    assert.equal(out[0].period, '2026-11-12');
  });

  it('⛔ a row with NO last_success_period KEY is unmeasured, not "never delivered"', async () => {
    // The LATERAL join always returns the column, so `null` is a real
    // measurement ("read, and there is no success"). A row with no such key at
    // all is `undefined`, which is "not measured".
    //
    // ⛔ WHAT THIS ACTUALLY PINS, and the first version of it pinned nothing.
    // The engine once wrapped this read in a hasOwnProperty test with a comment
    // calling it the guard; an absent property is `undefined` either way, so
    // deleting that test changed no outcome and this assertion stayed green —
    // a guard that cannot fire, verified by a test that could not see it. The
    // real regression is NORMALISING: `row.last_success_period ?? null` reads as
    // tidying and turns an unread history into a confident "never delivered",
    // re-sending every report on every tick. Mutation-verified against exactly
    // that change.
    const bare = row({ frequency: 'daily', hour: 6, day_of_month: null });
    delete bare.last_success_period;
    const evaluated = await evaluateSchedules(poolWith([bare]), at(2026, 11, 12, 9));
    assert.equal(evaluated.length, 1);
    assert.equal(evaluated[0].due, false);
    assert.equal(evaluated[0].reason, DUE_REASONS.UNKNOWN_HISTORY);

    // the same row WITH the key present and null is due — so the guard is
    // keyed on the key's presence, not on its falsiness
    const measured = await evaluateSchedules(
      poolWith([row({ frequency: 'daily', hour: 6, day_of_month: null })]),
      at(2026, 11, 12, 9)
    );
    assert.equal(measured[0].due, true);
  });
});

// --------------------------------------------------------------------------
describe('runReportScheduleJob', () => {
  it('⛔ NEVER THROWS when the schedules cannot be read, and delivers nothing', async () => {
    // We do not know what has been sent, so we send nothing. Guessing "nothing
    // yet" would re-mail every schedule for as long as the read kept failing.
    const pool = stubPool((sql) => (isScheduleSelect(sql)
      ? new Error('relation "report_schedules" does not exist')
      : { rows: [], rowCount: 0 }));
    const summary = await runReportScheduleJob(pool, { now: at(2026, 11, 12, 9) });
    assert.equal(summary.delivered, 0);
    assert.equal(summary.considered, 0);
    assert.equal(summary.errors.length, 1);
    assert.match(summary.errors[0], /nothing was delivered/);
    assert.equal(pool.calls.filter((c) => isDeliveryInsert(c.sql)).length, 0);
  });

  it('⛔ reports a skip caused by an unreadable delivery history — it does not hide it', async () => {
    const bare = row({ frequency: 'daily', hour: 6, day_of_month: null });
    delete bare.last_success_period;
    const summary = await runReportScheduleJob(poolWith([bare]), { now: at(2026, 11, 12, 9) });
    assert.equal(summary.considered, 1);
    assert.equal(summary.delivered, 0);
    assert.equal(summary.skipped, 1);
    assert.equal(summary.skipReasons[DUE_REASONS.UNKNOWN_HISTORY], 1);
    // A guard nobody can see is a guard that cannot fire, so this reaches the
    // engine log as a problem rather than only a tally.
    assert.equal(summary.errors.length, 1);
    assert.match(summary.errors[0], /could not be read/);
    assert.match(summary.errors[0], /duplicate/);
  });

  it('⛔ a schedule naming a withdrawn report is a NAMED FAILURE in the log', async () => {
    // A schedule that quietly stops producing anything is indistinguishable
    // from one that was never due, and the operator finds out when an auditor
    // asks where the document went.
    const gone = row({
      report_id: 'retired-report', frequency: 'daily', hour: 6, day_of_month: null,
    });
    const pool = poolWith([gone]);
    const summary = await runReportScheduleJob(pool, { now: at(2026, 11, 12, 9) });
    assert.equal(summary.failed, 1);
    assert.equal(summary.delivered, 0);
    assert.equal(summary.skipped, 0);

    const insert = pool.calls.find((c) => isDeliveryInsert(c.sql));
    assert.ok(insert, 'no report_delivery_log row was written — the failure would be invisible');
    assert.equal(insert.params[1], '2026-11-12', 'the slot must be recorded');
    assert.equal(insert.params[2], 'error');
    assert.match(String(insert.params[5]), /retired-report/);
    assert.match(summary.errors.join(' '), /retired-report/);
  });

  it('⛔ one bad schedule does not stop the others', async () => {
    const a = row({ id: 'a', report_id: 'gone-a', frequency: 'daily', hour: 6, day_of_month: null });
    const b = row({ id: 'b', report_id: 'gone-b', frequency: 'daily', hour: 6, day_of_month: null });
    const summary = await runReportScheduleJob(poolWith([a, b]), { now: at(2026, 11, 12, 9) });
    assert.equal(summary.considered, 2);
    assert.equal(summary.failed, 2);
    assert.equal(summary.errors.length, 2);
  });

  it('a stored row that no longer validates is a named failure, not a guess', async () => {
    // A parameter's `choices` can change in a release. Passing a value that no
    // longer means anything to a builder is how a document gets a title it does
    // not match.
    const stale = row({
      report_id: 'compliance-fleet',
      frequency: 'daily',
      hour: 6,
      day_of_month: null,
      params: { standard: 'HIPAA' },
    });
    const pool = poolWith([stale]);
    const summary = await runReportScheduleJob(pool, { now: at(2026, 11, 12, 9) });
    assert.equal(summary.failed, 1);
    const insert = pool.calls.find((c) => isDeliveryInsert(c.sql));
    assert.equal(insert.params[2], 'error');
    assert.match(String(insert.params[5]), /no longer valid/);
  });

  it('⛔ a DISABLED channel is a skip with its own reason, not an hourly error row', async () => {
    // Disabling a channel is a deliberate operator act. An error row every hour
    // for it would bury the real failures in the same log; the panel renders
    // channel_enabled, so the state is visible where it belongs.
    const s = row({
      frequency: 'daily', hour: 6, day_of_month: null, channel_enabled: false,
    });
    const warned = [];
    const pool = poolWith([s]);
    const summary = await runReportScheduleJob(pool, {
      now: at(2026, 11, 12, 9),
      logger: { info() {}, warn: (m) => warned.push(m), error() {} },
    });
    assert.equal(summary.skipped, 1);
    assert.equal(summary.skipReasons.channel_disabled, 1);
    assert.equal(summary.failed, 0);
    assert.equal(summary.errors.length, 0);
    assert.equal(pool.calls.filter((c) => isDeliveryInsert(c.sql)).length, 0);
    assert.match(warned.join(' '), /disabled/);
  });

  it('a slot already delivered is skipped without an attempt', async () => {
    const done = row({
      frequency: 'daily', hour: 6, day_of_month: null, last_success_period: '2026-11-12',
    });
    const pool = poolWith([done]);
    const summary = await runReportScheduleJob(pool, { now: at(2026, 11, 12, 9) });
    assert.equal(summary.skipped, 1);
    assert.equal(summary.skipReasons[DUE_REASONS.ALREADY], 1);
    assert.equal(pool.calls.filter((c) => isDeliveryInsert(c.sql)).length, 0);
  });

  it('a missing pool is reported, not thrown', async () => {
    const summary = await runReportScheduleJob(null, { now: at(2026, 11, 12, 9) });
    assert.equal(summary.delivered, 0);
    assert.match(summary.errors.join(' '), /requires pool/);
  });

  it('the success insert is guarded by ON CONFLICT, so a slot cannot succeed twice', async () => {
    // The partial unique index on (schedule_id, period) WHERE status='success'
    // is the double-send guarantee; this pins that the engine does not defeat
    // it by inserting unconditionally.
    const gone = row({ report_id: 'gone', frequency: 'daily', hour: 6, day_of_month: null });
    const pool = poolWith([gone]);
    await runReportScheduleJob(pool, { now: at(2026, 11, 12, 9) });
    const insert = pool.calls.find((c) => isDeliveryInsert(c.sql));
    assert.match(insert.sql, /ON CONFLICT DO NOTHING/);
    assert.match(insert.sql, /\$7::timestamptz/, 'a timestamp parameter must be cast explicitly');
  });
});

// --------------------------------------------------------------------------
describe('updateSchedule', () => {
  const { updateSchedule } = require('../lib/engines/reportScheduleData');

  it('⛔ PAUSING works even on a schedule whose report has been withdrawn', async () => {
    // report_id is a catalogue id and the catalogue is CODE, so a report can be
    // removed under a live schedule. Re-validating the whole row on every patch
    // made the panel's Pause button answer 400 for exactly the schedule an
    // operator most wants to stop, leaving DELETE — which discards its
    // recipients and its history — as the only way out.
    const stale = row({ report_id: 'retired-xyz' });
    const pool = poolWith([stale], (sql) => {
      if (/UPDATE\s+report_schedules/i.test(sql)) return { rows: [], rowCount: 1 };
      return undefined;
    });
    const r = await updateSchedule(pool, stale.id, { enabled: false });
    assert.equal(r.ok, true, r.errors.join(' '));
    const upd = pool.calls.find((c) => /UPDATE\s+report_schedules/i.test(c.sql));
    assert.ok(upd, 'nothing was written');
    // ⛔ ONE COLUMN. A patch that also rewrote report_id/params here would be
    // writing a row it had refused to validate.
    assert.match(upd.sql, /SET enabled = \$1, updated_at = now\(\)/);
    assert.deepEqual(upd.params, [false, stale.id]);
  });

  it('a FULL edit of that same schedule is still refused, by name', async () => {
    const stale = row({ report_id: 'retired-xyz' });
    const r = await updateSchedule(poolWith([stale]), stale.id, { hour: 9 });
    assert.equal(r.ok, false);
    assert.match(r.errors.join(' '), /No such report: retired-xyz/);
  });

  it('a schedule that no longer exists is reported, not thrown', async () => {
    const r = await updateSchedule(poolWith([]), '11111111-1111-4111-8111-111111111111', { hour: 9 });
    assert.equal(r.ok, false);
    assert.match(r.errors.join(' '), /no longer exists/);
  });
});

// --------------------------------------------------------------------------
describe('summary reporting', () => {
  it('recipientCount counts the addresses an email channel actually names', () => {
    assert.equal(recipientCount({ to: 'a@x.com, b@x.com;c@x.com' }), 3);
    assert.equal(recipientCount({ to: '  ' }), 0);
    assert.equal(recipientCount({}), 0);
    assert.equal(recipientCount(null), 0);
  });

  it('the log line names what was SKIPPED and why, not only what was sent', async () => {
    // A quiet night and a stuck scheduler print the same "0 delivered" without
    // the reasons beside it.
    const bare = row({ frequency: 'daily', hour: 6, day_of_month: null });
    delete bare.last_success_period;
    const summary = await runReportScheduleJob(poolWith([bare]), { now: at(2026, 11, 12, 9) });
    const line = formatScheduleSummary(summary);
    assert.match(line, /1 enabled schedule/);
    assert.match(line, /0 delivered/);
    assert.match(line, new RegExp(DUE_REASONS.UNKNOWN_HISTORY));
  });

  it('formatScheduleSummary tolerates a summary it was not given', () => {
    assert.match(formatScheduleSummary(null), /0 delivered/);
    assert.match(formatScheduleSummary({}), /0 delivered/);
  });
});
