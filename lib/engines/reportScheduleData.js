'use strict';
// lib/engines/reportScheduleData.js — scheduled report delivery, the PLUMBING.
//
// Every function takes `pool` as its FIRST argument, per CLAUDE.md's pool rule.
// The judgement lives next door in the pure lib/engines/reportSchedule.js; this
// file reads rows, builds a document through lib/reports/catalogue.js, hands it
// to the EXISTING outbound mail path, and records what happened. Same split as
// segmentation.js/segmentationData.js.
//
// ⛔ NO SECOND SMTP PATH, AND NO SECOND REPORT BUILDER. Delivery goes through
// lib/notificationChannels.js (storage + decryption + last_error bookkeeping)
// and lib/notify.js's dispatchNotification (the one place nodemailer is
// configured, and the only one that knows a PDF attachment is email-only).
// The document comes from the catalogue entry's own lazy `builder`, which is the
// same function app/api/reports/[id]/pdf/route.js calls. A copy of either would
// drift, and the drifting copy would be the one mailing an auditor.
//
// ⛔ THE MONTHLY COMPLIANCE JOB IS DELIBERATELY UNTOUCHED. It has its own log
// table, its own partial unique index and its own `compliance_report` alert
// type, all live on deployed servers. Rewriting it to route through here would
// risk a double send or a silent stop on the ONE report customers already
// receive, for no new capability. This generalises the pattern beside it.

const { reportById } = require('../reports/catalogue');
const {
  dueState,
  describeSchedule,
  validateSchedule,
  periodKeyFor,
  DUE_REASONS,
} = require('./reportSchedule');
const {
  getChannelPlaintext,
  recordChannelSuccess,
  recordChannelError,
} = require('../notificationChannels');
const { dispatchNotification } = require('../notify');

// ⛔ ONE PASS AT A TIME. services/engine-worker.js's runTrackedJob does NOT
// serialise by job name, and this job runs on an hourly tick AND once at
// startup — a deploy landing on the tick could overlap the two. The partial
// unique index on report_delivery_log stops a second SUCCESS ROW, but it cannot
// un-send an email, so the overlap has to be refused BEFORE the send rather
// than detected after it. A module-level flag is enough because there is
// exactly one engine process; if that ever stops being true this needs a real
// database claim, and the ON CONFLICT check at the end of deliverOne() is what
// would make the breach visible rather than silent.
let passInFlight = false;

/**
 * Every schedule with the channel it targets, the firewall it narrows to, and
 * its delivery history.
 *
 * ⛔ `last_success_period` IS THE DUE-NESS INPUT and is read here, not stored.
 * NULL means the log was read and holds no success for this schedule — a real
 * measurement. See evaluateSchedules for what happens when the column is not
 * returned at all.
 */
async function listSchedules(pool, opts = {}) {
  if (!pool) throw new Error('listSchedules requires pool parameter');
  const where = [];
  const params = [];
  if (opts.enabledOnly) where.push('s.enabled = TRUE');
  if (opts.id) {
    params.push(opts.id);
    where.push(`s.id = $${params.length}`);
  }
  const { rows } = await pool.query(
    `SELECT s.id, s.report_id, s.params, s.device_id, s.frequency, s.hour,
            s.day_of_week, s.day_of_month, s.channel_id, s.enabled,
            s.created_by, s.created_at, s.updated_at,
            c.name AS channel_name,
            c.channel_type AS channel_type,
            c.enabled AS channel_enabled,
            d.name AS device_name,
            ok.period AS last_success_period,
            ok.finished_at AS last_success_at,
            last.status AS last_attempt_status,
            last.error AS last_attempt_error,
            last.started_at AS last_attempt_at
       FROM report_schedules s
       JOIN notification_channels c ON c.id = s.channel_id
       LEFT JOIN devices d ON d.id = s.device_id
       LEFT JOIN LATERAL (
         SELECT period, finished_at
           FROM report_delivery_log
          WHERE schedule_id = s.id AND status = 'success'
          ORDER BY started_at DESC
          LIMIT 1
       ) ok ON TRUE
       LEFT JOIN LATERAL (
         SELECT status, error, started_at
           FROM report_delivery_log
          WHERE schedule_id = s.id
          ORDER BY started_at DESC
          LIMIT 1
       ) last ON TRUE
      ${where.length > 0 ? `WHERE ${where.join(' AND ')}` : ''}
      ORDER BY s.created_at ASC`,
    params
  );
  return rows;
}

/** One schedule, or null. Never a partially-populated stub. */
async function getSchedule(pool, id) {
  if (!pool) throw new Error('getSchedule requires pool parameter');
  const rows = await listSchedules(pool, { id });
  return rows[0] || null;
}

/** The last N delivery attempts for one schedule, newest first — the evidence
 *  behind whatever the panel says about it. */
async function listDeliveries(pool, scheduleId, limit = 10) {
  if (!pool) throw new Error('listDeliveries requires pool parameter');
  const n = Number.isInteger(limit) && limit > 0 && limit <= 100 ? limit : 10;
  const { rows } = await pool.query(
    `SELECT id, period, status, recipient_count, byte_count, error,
            started_at, finished_at
       FROM report_delivery_log
      WHERE schedule_id = $1
      ORDER BY started_at DESC
      LIMIT ${n}`,
    [scheduleId]
  );
  return rows;
}

/**
 * Checks the channel a schedule names: it must exist, and it must be an EMAIL
 * channel.
 *
 * ⛔ EMAIL ONLY, AND REFUSED AT WRITE TIME RATHER THAN AT DELIVERY TIME. A
 * Slack/Teams/generic webhook payload has no attachment concept at all —
 * lib/notify.js's webhook senders never read `message.attachments` — so a
 * schedule pointed at one would queue a delivery that can never succeed and
 * write an error row every hour for ever. That is the same trap
 * components/settings/NotificationsPanel.js already closes for the
 * `compliance_report` alert type, and it is closed in the same direction here.
 *
 * @returns {{ok: boolean, error?: string, channel?: object}}
 */
async function checkChannel(pool, channelId) {
  const { rows } = await pool.query(
    'SELECT id, name, channel_type, enabled FROM notification_channels WHERE id = $1',
    [channelId]
  );
  const channel = rows[0];
  if (!channel) return { ok: false, error: 'That notification channel no longer exists.' };
  if (channel.channel_type !== 'email') {
    return {
      ok: false,
      error: `${channel.name} is a ${channel.channel_type} channel. A report is delivered as a `
        + 'PDF attachment, which only an email channel can carry.',
    };
  }
  return { ok: true, channel };
}

/**
 * Create a schedule.
 *
 * ⛔ IT VALIDATES AGAIN, even though the route already did. Two independent
 * gates, the same shape as the compliance report's `standard` (allow-listed in
 * the route, refused a second time by resolveStandard) — because a mislabelled
 * audit document is the one output this product must never produce, and this
 * function is callable from anywhere.
 *
 * @returns {{ok: boolean, errors: string[], schedule: object|null}} — never
 *   throws for a bad input, so the route maps it straight to a 400. A genuine
 *   database failure still throws, because that is a 500.
 */
async function createSchedule(pool, input, createdBy) {
  if (!pool) throw new Error('createSchedule requires pool parameter');
  const entry = reportById(input && input.report_id);
  const checked = validateSchedule(input, entry);
  if (!checked.ok) return { ok: false, errors: checked.errors, schedule: null };
  const v = checked.value;

  const channel = await checkChannel(pool, v.channel_id);
  if (!channel.ok) return { ok: false, errors: [channel.error], schedule: null };

  if (v.device_id) {
    const { rows } = await pool.query('SELECT id FROM devices WHERE id = $1', [v.device_id]);
    if (rows.length === 0) {
      return { ok: false, errors: ['That firewall no longer exists.'], schedule: null };
    }
  }

  const { rows } = await pool.query(
    `INSERT INTO report_schedules
       (report_id, params, device_id, frequency, hour, day_of_week, day_of_month,
        channel_id, enabled, created_by)
     VALUES ($1, $2::jsonb, $3, $4, $5, $6, $7, $8, $9, $10)
     RETURNING id`,
    [
      v.report_id, JSON.stringify(v.params || {}), v.device_id, v.frequency, v.hour,
      v.day_of_week, v.day_of_month, v.channel_id, v.enabled,
      typeof createdBy === 'string' && createdBy.trim() !== '' ? createdBy.trim() : null,
    ]
  );
  const schedule = await getSchedule(pool, rows[0].id);
  return { ok: true, errors: [], schedule };
}

/**
 * Patch a schedule. Absent keys are left alone; the result is re-validated as a
 * WHOLE row, not field by field.
 *
 * ⛔ THE WHOLE ROW, because the grain fields are not independent: switching a
 * weekly schedule to monthly without clearing day_of_week violates
 * report_schedules_grain_chk, and validating only the changed field would send
 * the operator a raw constraint-violation message instead of a sentence. The
 * merge also NULLS the grain field the new frequency does not use, so changing
 * frequency alone is a legal edit rather than a two-step dance.
 */
async function updateSchedule(pool, id, patch) {
  if (!pool) throw new Error('updateSchedule requires pool parameter');
  const existing = await getSchedule(pool, id);
  if (!existing) return { ok: false, errors: ['That schedule no longer exists.'], schedule: null };

  const p = patch && typeof patch === 'object' ? patch : {};

  // ⛔ PAUSING MUST ALWAYS WORK, INCLUDING ON A SCHEDULE THAT IS NO LONGER
  // VALID — and the first draft of this function made it the one edit that
  // could not be made. report_id is a catalogue id and the catalogue is CODE,
  // so a report can be withdrawn under a live schedule; re-validating the whole
  // row on every patch meant the panel's Pause button would answer 400 for
  // exactly the schedule an operator most wants to stop, leaving DELETE (which
  // discards its recipients and its history) as the only way out. An
  // `enabled`-only patch therefore writes that one boolean and nothing else.
  // It gives up no gate: the column has no CHECK, the row's validity is
  // re-checked at DELIVERY time by deliverOne(), and resuming an invalid
  // schedule produces a NAMED failure in report_delivery_log rather than
  // silence.
  const keys = Object.keys(p);
  if (keys.length === 1 && keys[0] === 'enabled') {
    const enabled = p.enabled === true || p.enabled === 'true';
    await pool.query(
      'UPDATE report_schedules SET enabled = $1, updated_at = now() WHERE id = $2',
      [enabled, id]
    );
    return { ok: true, errors: [], schedule: await getSchedule(pool, id) };
  }

  const merged = {
    report_id: p.report_id !== undefined ? p.report_id : existing.report_id,
    params: p.params !== undefined ? p.params : existing.params,
    device_id: p.device_id !== undefined ? p.device_id : existing.device_id,
    frequency: p.frequency !== undefined ? p.frequency : existing.frequency,
    hour: p.hour !== undefined ? p.hour : existing.hour,
    day_of_week: p.day_of_week !== undefined ? p.day_of_week : existing.day_of_week,
    day_of_month: p.day_of_month !== undefined ? p.day_of_month : existing.day_of_month,
    channel_id: p.channel_id !== undefined ? p.channel_id : existing.channel_id,
    enabled: p.enabled !== undefined ? p.enabled : existing.enabled,
  };
  // A frequency change clears the grain field the new frequency has no use for,
  // unless the caller supplied one explicitly in the same patch.
  if (p.frequency !== undefined && p.frequency !== existing.frequency) {
    if (merged.frequency !== 'weekly' && p.day_of_week === undefined) merged.day_of_week = null;
    if (merged.frequency !== 'monthly' && p.day_of_month === undefined) merged.day_of_month = null;
  }

  const entry = reportById(merged.report_id);
  const checked = validateSchedule(merged, entry);
  if (!checked.ok) return { ok: false, errors: checked.errors, schedule: null };
  const v = checked.value;

  const channel = await checkChannel(pool, v.channel_id);
  if (!channel.ok) return { ok: false, errors: [channel.error], schedule: null };

  await pool.query(
    `UPDATE report_schedules
        SET report_id = $1, params = $2::jsonb, device_id = $3, frequency = $4,
            hour = $5, day_of_week = $6, day_of_month = $7, channel_id = $8,
            enabled = $9, updated_at = now()
      WHERE id = $10`,
    [
      v.report_id, JSON.stringify(v.params || {}), v.device_id, v.frequency, v.hour,
      v.day_of_week, v.day_of_month, v.channel_id, v.enabled, id,
    ]
  );
  const schedule = await getSchedule(pool, id);
  return { ok: true, errors: [], schedule };
}

/**
 * Delete a schedule. Its delivery log goes with it (ON DELETE CASCADE).
 *
 * ⛔ DELETING A SCHEDULE WIDENS NOTHING AND CHANGES NO OTHER ROW'S MEANING —
 * this is NOT the user_device_scopes trap, where an emptied table flips from
 * "restricted" to "the whole fleet". Zero schedule rows means "nothing is
 * scheduled" both before and after, so no guard is needed here.
 *
 * @returns {boolean} whether a row was actually removed.
 */
async function deleteSchedule(pool, id) {
  if (!pool) throw new Error('deleteSchedule requires pool parameter');
  const res = await pool.query('DELETE FROM report_schedules WHERE id = $1', [id]);
  return (res.rowCount || 0) > 0;
}

/**
 * Every ENABLED schedule, each with the verdict the pure engine gives it.
 *
 * Shared by resolveDueSchedules (which filters to the due ones, per its own
 * contract) and runReportScheduleJob (which needs every verdict so it can
 * REPORT the skips rather than silently dropping them).
 *
 * ⛔ `null` AND `undefined` ARRIVE HERE DISTINGUISHABLE, AND NOTHING MAY FOLD
 * THEM. The LATERAL join always returns the column, and `pg` gives `null` for a
 * SQL NULL — a real measurement, "the log was read and holds no success". A row
 * that does NOT carry the key at all (a future edit dropping it from the select
 * list, a view or driver that stops returning it) reads as `undefined`, which
 * is "we did not measure this", and dueState skips rather than re-sending (see
 * its comment for the asymmetric-cost argument).
 *
 * ⛔ SO THE ONE THING THIS LINE MUST NOT DO IS NORMALISE. `row.last_success_period
 * ?? null`, `|| null`, or a destructure with a `= null` default each look like
 * tidying and each turn an unread history into a confident "never delivered" —
 * every report re-sent on every tick, for as long as the read keeps failing.
 * The first draft of this file wrapped the read in a `hasOwnProperty` test and
 * a comment claiming it was the guard; it was not. An absent property is
 * `undefined` either way, so that test could never change the outcome — a
 * guard that cannot fire, dressed as the one that matters. The read is plain
 * now and the invariant is stated where it actually lives: in dueState, and in
 * the test that mutation-checks a `?? null` here.
 *
 * THROWS if the schedules cannot be read at all — the caller reports that and
 * delivers nothing, which is the same choice in the same direction: we do not
 * know what has been sent, so we send nothing.
 */
async function evaluateSchedules(pool, now) {
  const when = now instanceof Date ? now : new Date(now || Date.now());
  const rows = await listSchedules(pool, { enabledOnly: true });
  return rows.map((row) => {
    // Read verbatim. See the ⛔ note above: no ??, no ||, no default.
    const verdict = dueState(row, when, row.last_success_period);
    return { schedule: row, period: verdict.period, due: verdict.due, reason: verdict.reason };
  });
}

/**
 * The schedules that should be delivered right now.
 * @returns {Promise<Array<{schedule: object, period: string}>>}
 */
async function resolveDueSchedules(pool, now) {
  if (!pool) throw new Error('resolveDueSchedules requires pool parameter');
  const evaluated = await evaluateSchedules(pool, now);
  return evaluated
    .filter((e) => e.due)
    .map((e) => ({ schedule: e.schedule, period: e.period }));
}

/** How many addresses an email channel's `to` actually names. Reported in the
 *  log so "delivered" is not mistaken for "delivered to someone". */
function recipientCount(config) {
  const to = config && typeof config.to === 'string' ? config.to : '';
  return to.split(/[,;]/).map((s) => s.trim()).filter(Boolean).length;
}

async function logAttempt(pool, scheduleId, period, fields) {
  // ⛔ ON CONFLICT DO NOTHING guards the SUCCESS row only, which is what the
  // partial unique index covers. Unlimited error rows may accumulate on purpose:
  // a transient SMTP failure must be retried on the next tick rather than
  // permanently consuming that slot.
  const res = await pool.query(
    `INSERT INTO report_delivery_log
       (schedule_id, period, status, recipient_count, byte_count, error, started_at, finished_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, now())
     ON CONFLICT DO NOTHING
     RETURNING id`,
    [
      scheduleId, period, fields.status, fields.recipientCount || 0,
      fields.byteCount === undefined ? null : fields.byteCount,
      fields.error || null, fields.startedAt,
    ]
  );
  return (res.rowCount || 0) > 0;
}

/**
 * Build and deliver ONE due schedule. Returns a verdict; never throws.
 *
 * @returns {Promise<{status: 'delivered'|'failed'|'skipped', reason?: string,
 *   error?: string, bytes?: number, recipients?: number}>}
 */
async function deliverOne(pool, schedule, period) {
  const startedAt = new Date();
  const label = `${schedule.report_id}${schedule.device_name ? ` (${schedule.device_name})` : ''}`;

  // ⛔ A SCHEDULE NAMING A REPORT THAT NO LONGER EXISTS IS A NAMED FAILURE,
  // never a silent skip. report_schedules.report_id is a catalogue id and the
  // catalogue is CODE, so a report can be renamed or withdrawn under a live
  // schedule. A schedule that quietly stops producing anything is
  // indistinguishable from one that was never due — and the operator finds out
  // when an auditor asks where the monthly document went. The error row is what
  // the panel renders.
  const entry = reportById(schedule.report_id);
  if (!entry) {
    const error = `No report called "${schedule.report_id}" exists any more, so nothing could `
      + 'be delivered. Point this schedule at a report that still exists, or remove it.';
    await logAttempt(pool, schedule.id, period, { status: 'error', error, startedAt });
    return { status: 'failed', error };
  }

  // ⛔ THE STORED ROW IS RE-VALIDATED AGAINST THE CATALOGUE AS IT STANDS NOW.
  // A parameter's `choices` can change in a release, which would leave a stored
  // value that no longer means anything. Passing it to a builder anyway is how a
  // document gets a title it does not match; refusing it with the reason named
  // is recoverable.
  const checked = validateSchedule(schedule, entry);
  if (!checked.ok) {
    const error = `This schedule is no longer valid for ${entry.name}: ${checked.errors.join(' ')}`;
    await logAttempt(pool, schedule.id, period, { status: 'error', error, startedAt });
    return { status: 'failed', error };
  }

  // The secret is decrypted through the one function that does it, and only at
  // the moment of sending.
  let channel;
  try {
    channel = await getChannelPlaintext(schedule.channel_id, pool);
  } catch (err) {
    const error = `The notification channel could not be read: ${err.message}`;
    await logAttempt(pool, schedule.id, period, { status: 'error', error, startedAt });
    return { status: 'failed', error };
  }
  if (!channel) {
    const error = 'The notification channel this schedule targets no longer exists.';
    await logAttempt(pool, schedule.id, period, { status: 'error', error, startedAt });
    return { status: 'failed', error };
  }
  if (channel.channelType !== 'email') {
    const error = `${channel.name} is a ${channel.channelType} channel and cannot carry a PDF.`;
    await logAttempt(pool, schedule.id, period, { status: 'error', error, startedAt });
    return { status: 'failed', error };
  }

  let buffer;
  try {
    const build = entry.builder();
    buffer = await build(pool, {
      deviceId: schedule.device_id || null,
      ...(checked.value.params || {}),
    });
  } catch (err) {
    const error = `${entry.name} could not be built: ${err.message}`;
    await logAttempt(pool, schedule.id, period, { status: 'error', error, startedAt });
    return { status: 'failed', error };
  }
  // ⛔ A ZERO-BYTE PDF IS NOT A DELIVERY. An empty attachment is a confident
  // artefact that says nothing, and somebody would file it.
  if (!buffer || !buffer.length) {
    const error = `${entry.name} produced an empty document; nothing was sent.`;
    await logAttempt(pool, schedule.id, period, { status: 'error', error, startedAt });
    return { status: 'failed', error };
  }

  const recipients = recipientCount(channel.config);
  const suffixParts = Object.values(checked.value.params || {})
    .map((v) => String(v).toLowerCase().replace(/[^a-z0-9]+/g, '-'))
    .filter(Boolean);
  const filename = `secvault-${entry.id}`
    + `${suffixParts.length > 0 ? `-${suffixParts.join('-')}` : ''}-${period}.pdf`;

  const scopeWords = schedule.device_name
    ? `for ${schedule.device_name}`
    : 'for the whole fleet';
  try {
    await dispatchNotification(channel, {
      // ⛔ A SCHEDULED REPORT IS NOT AN ALERT, and this string is not in
      // lib/notificationChannels.js's ALERT_TYPES on purpose. The channel is
      // addressed BY ID from the schedule, never by alert-type subscription, so
      // adding a fourth vocabulary entry would offer operators a checkbox that
      // routes nothing. `alertType` is carried only because dispatchNotification's
      // generic-webhook payload reads it, and this path is email-only anyway.
      alertType: 'report_schedule',
      title: `SecVault ${entry.name} — ${period}`,
      summary: `The ${entry.name} ${scopeWords} is attached. `
        + `${describeSchedule(schedule)}. Generated ${startedAt.toISOString()}.`,
      attachments: [{ filename, content: buffer, contentType: 'application/pdf' }],
    });
  } catch (err) {
    const error = `Sending to ${channel.name} failed: ${err.message}`;
    await recordChannelError(schedule.channel_id, err.message, pool).catch(() => {});
    await logAttempt(pool, schedule.id, period, {
      status: 'error', error, recipientCount: recipients, startedAt,
    });
    return { status: 'failed', error };
  }

  await recordChannelSuccess(schedule.channel_id, pool).catch(() => {});
  const claimed = await logAttempt(pool, schedule.id, period, {
    status: 'success',
    recipientCount: recipients,
    byteCount: buffer.length,
    startedAt,
  });
  if (!claimed) {
    // ⛔ VISIBLE, NOT SWALLOWED. The unique index refused the success row, so a
    // success for this slot already existed when we had just finished sending —
    // i.e. the mail probably went twice. Nothing here can un-send it; what it
    // CAN do is say so, rather than letting the overlap look like a clean run.
    return {
      status: 'failed',
      error: `${label} was delivered, but a successful delivery for ${period} was already `
        + 'recorded — this slot may have been sent twice. Check for overlapping engine runs.',
    };
  }
  return { status: 'delivered', bytes: buffer.length, recipients };
}

/**
 * The engine job. ⛔ NEVER THROWS — per-schedule failures come back in the
 * summary, exactly as runConfigRetention() does, because one bad schedule must
 * not stop the others from being delivered.
 *
 * @param {import('pg').Pool} pool
 * @param {{now?: Date, logger?: {info: Function, warn: Function, error: Function}}} [opts]
 * @returns {Promise<{considered: number, delivered: number, failed: number,
 *   skipped: number, errors: string[], skipReasons: object}>}
 */
async function runReportScheduleJob(pool, opts = {}) {
  const summary = {
    considered: 0, delivered: 0, failed: 0, skipped: 0, errors: [], skipReasons: {},
  };
  const log = opts.logger || null;
  const note = (reason) => {
    summary.skipped += 1;
    summary.skipReasons[reason] = (summary.skipReasons[reason] || 0) + 1;
  };

  if (!pool) {
    summary.errors.push('runReportScheduleJob requires pool parameter');
    return summary;
  }
  if (passInFlight) {
    // The startup pass and an hourly tick overlapping. Refused before any send.
    summary.errors.push('A report-schedule pass was already running; this tick did nothing.');
    return summary;
  }
  passInFlight = true;

  try {
    const now = opts.now instanceof Date ? opts.now : new Date();
    let evaluated;
    try {
      evaluated = await evaluateSchedules(pool, now);
    } catch (err) {
      // ⛔ WE DO NOT KNOW WHAT HAS BEEN SENT, SO WE SEND NOTHING. Guessing
      // "nothing yet" would re-mail every schedule for as long as the read keeps
      // failing.
      summary.errors.push(
        `Report schedules could not be read, so nothing was delivered: ${err.message}`
      );
      return summary;
    }

    summary.considered = evaluated.length;

    for (const item of evaluated) {
      if (!item.due) {
        note(item.reason);
        if (item.reason === DUE_REASONS.UNKNOWN_HISTORY) {
          // ⛔ SURFACED, because a guard nobody can see is a guard that cannot
          // fire. The skip itself is the safe choice (see dueState); reporting
          // it is what stops a permanently-stuck schedule reading as a quiet
          // one.
          summary.errors.push(
            `Schedule ${item.schedule.id} (${item.schedule.report_id}): the last delivery `
            + 'could not be read, so it was skipped rather than risking a duplicate.'
          );
        }
        continue;
      }

      // ⛔ A DISABLED CHANNEL IS A SKIP, NOT AN ERROR ROW EVERY HOUR. Disabling
      // a channel is a deliberate operator act with its own meaning ("stop
      // sending through this"), and writing an hourly error row for it would
      // bury the real failures in the same log. It is not invisible either: the
      // panel renders channel_enabled, so a schedule pointed at a paused channel
      // says so on screen.
      if (item.schedule.channel_enabled === false) {
        note('channel_disabled');
        if (log) {
          log.warn(
            `Job [report-schedule] ${item.schedule.report_id}: channel `
            + `"${item.schedule.channel_name}" is disabled — nothing sent for ${item.period}.`
          );
        }
        continue;
      }

      let verdict;
      try {
        verdict = await deliverOne(pool, item.schedule, item.period);
      } catch (err) {
        // deliverOne is written not to throw; this is the belt-and-braces layer
        // that keeps one schedule from ending the pass.
        verdict = { status: 'failed', error: err.message };
      }
      if (verdict.status === 'delivered') {
        summary.delivered += 1;
        if (log) {
          log.info(
            `Job [report-schedule] delivered ${item.schedule.report_id} for ${item.period} `
            + `to ${item.schedule.channel_name} (${verdict.recipients} recipient(s), `
            + `${verdict.bytes} bytes).`
          );
        }
      } else if (verdict.status === 'failed') {
        summary.failed += 1;
        summary.errors.push(`${item.schedule.report_id} (${item.period}): ${verdict.error}`);
      } else {
        note(verdict.reason || 'skipped');
      }
    }
    return summary;
  } catch (err) {
    // Last resort: the job reports, it does not throw.
    summary.errors.push(`Report schedule pass failed: ${err.message}`);
    return summary;
  } finally {
    passInFlight = false;
  }
}

/** One line for engine.log. Reports what was SKIPPED and why alongside what was
 *  delivered, the same way runConfigRetention's summary names the protection
 *  that kept a row — so an operator can tell a quiet night from a stuck one. */
function formatScheduleSummary(summary) {
  const s = summary || {};
  const reasons = Object.entries(s.skipReasons || {})
    .map(([k, v]) => `${k}=${v}`)
    .join(', ');
  return `${s.considered || 0} enabled schedule(s): ${s.delivered || 0} delivered, `
    + `${s.failed || 0} failed, ${s.skipped || 0} not due${reasons ? ` (${reasons})` : ''}`
    + `${(s.errors || []).length > 0 ? `; ${s.errors.length} problem(s)` : ''}`;
}

module.exports = {
  listSchedules,
  getSchedule,
  listDeliveries,
  createSchedule,
  updateSchedule,
  deleteSchedule,
  evaluateSchedules,
  resolveDueSchedules,
  runReportScheduleJob,
  formatScheduleSummary,
  recipientCount,
  periodKeyFor,
};
