'use strict';
// lib/engines/reportSchedule.js — scheduled report delivery, the PURE half.
//
// Data in, data out. No pool, no I/O, no clock it was not handed, no logger,
// and it never throws — every refusal comes back as a value. The plumbing
// lives in lib/engines/reportScheduleData.js, which is the only file here that
// touches the database, exactly the split segmentation.js/segmentationData.js
// and applicationView.js/applicationViewData.js already use. The judgement is
// the valuable part, so the judgement has to be testable without a database.
//
// ⛔ ZERO REQUIRES, DELIBERATELY. components/reports/ReportSchedulesPanel.js is
// a client component and imports describeSchedule from here so the form can
// show the operator the sentence their choices produce. That only works while
// this file drags nothing in behind it — the same contract lib/licenceBanner.js
// keeps, and for the same reason (lib/productLicense.js cannot cross that
// boundary because it reaches child_process). Do not add a require here.
//
// ⛔ THERE IS NO next_run_at, ANYWHERE, AND THAT IS THE CENTRAL DECISION.
// lib/schema.sql's report_schedules comment states it: a stored next-run is a
// verdict about the future, and a verdict goes stale the moment the schedule is
// edited, the clock shifts, or a deploy restarts SecVault-Engine mid-tick. A
// scheduler that trusts a stale one either double-sends or silently stops.
// Due-ness is DERIVED here, at every tick, from two facts: the schedule
// definition, and the period of the last SUCCESSFUL delivery. Same rule as
// segmentation's "no stored verdict column".
//
// ⛔ SERVER-LOCAL TIME THROUGHOUT. Every Date field read below is a LOCAL
// getter (getHours/getDate/getDay/getFullYear), never a getUTC*. The fixed-HH:MM
// cron jobs in services/engine-worker.js run in the server's own zone, and
// lib/engines/complianceReport.js records what happened the last time a period
// was computed from getUTC* while the tick that asked for it fired on local
// time: a double send in the first month, then a permanently skipped tick from
// month two. A schedule stored as "06:00" that fires at 13:00 is a schedule
// nobody can reason about, and nothing would look broken.

/** The three frequencies report_schedules.frequency_chk permits. */
const FREQUENCIES = Object.freeze(['daily', 'weekly', 'monthly']);

/** 0 = Sunday, matching report_schedules.day_of_week and Date#getDay(). */
const DAY_NAMES = Object.freeze([
  'Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday',
]);

/**
 * ⛔ monthly day_of_month IS CAPPED AT 28, matching the CHECK constraint. A
 * schedule set to the 30th would silently never fire in February — a schedule
 * that looks configured and is not, which is the shape of defect this codebase
 * names most often.
 */
const MAX_DAY_OF_MONTH = 28;

/** The reason strings dueState can return. Kept as a named set so the data
 *  layer and the tests cannot drift from a string literal typed twice. */
const DUE_REASONS = Object.freeze({
  DUE: 'due',
  INVALID: 'invalid_schedule',
  DISABLED: 'disabled',
  ALREADY: 'already_delivered',
  NOT_REACHED: 'slot_not_reached',
  /** ⛔ The "we could not measure this" state — see dueState's own comment. */
  UNKNOWN_HISTORY: 'last_delivery_unknown',
});

function isInt(v) {
  return typeof v === 'number' && Number.isInteger(v);
}

/** Accepts a number or a numeric string (a form posts strings; so does a DB
 *  driver for some column types). Returns null for anything else — never 0,
 *  which would silently become midnight. */
function toInt(v) {
  if (isInt(v)) return v;
  if (typeof v === 'string' && /^-?\d+$/.test(v.trim())) return parseInt(v.trim(), 10);
  return null;
}

function pad2(n) {
  return String(n).padStart(2, '0');
}

function asDate(value) {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value === 'string' || typeof value === 'number') {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  return null;
}

/**
 * ISO-8601 week of a LOCAL date: { isoYear, week }.
 *
 * ⛔ THE ISO YEAR IS NOT THE CALENDAR YEAR, and that is why this is not a
 * three-line function. 2027-01-01 falls in ISO week 2026-W53; computing the key
 * as `getFullYear() + '-W' + week` would emit '2027-W53', a slot that belongs to
 * neither year. Since the key is what the partial unique index dedupes on, a
 * wrong key at a year boundary means either a double send or a lost week — the
 * two failures this whole file exists to prevent, arriving once a year on a
 * date nobody tests by hand.
 */
function isoWeekOf(date) {
  // Midnight local, so a DST shift inside the day cannot move the week.
  const d = new Date(date.getFullYear(), date.getMonth(), date.getDate());
  // Monday = 0 … Sunday = 6. ISO weeks start on Monday.
  const dayIndex = (d.getDay() + 6) % 7;
  // The Thursday of this ISO week determines the ISO year, by definition.
  d.setDate(d.getDate() - dayIndex + 3);
  const isoYear = d.getFullYear();
  const jan4 = new Date(isoYear, 0, 4);
  const jan4Index = (jan4.getDay() + 6) % 7;
  jan4.setDate(jan4.getDate() - jan4Index + 3);
  const week = 1 + Math.round((d.getTime() - jan4.getTime()) / (7 * 24 * 3600 * 1000));
  return { isoYear, week };
}

/**
 * The firing SLOT a moment belongs to, as a string.
 *
 *   daily   -> 'YYYY-MM-DD'
 *   weekly  -> 'YYYY-Www'   (ISO week)
 *   monthly -> 'YYYY-MM'
 *
 * ⛔ A SLOT, NOT A TIMESTAMP. report_delivery_log's partial unique index is on
 * (schedule_id, period) WHERE status = 'success', so the period is the entire
 * double-send guarantee. A timestamp would make every retry a brand-new slot
 * and the index would guarantee nothing at all.
 *
 * @returns {string|null} null for an unusable frequency or date — never a
 *   plausible-looking key, which would be written into the log and then dedupe
 *   against the wrong thing for ever.
 */
function periodKeyFor(frequency, date) {
  const d = asDate(date);
  if (!d) return null;
  if (frequency === 'daily') {
    return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
  }
  if (frequency === 'weekly') {
    const { isoYear, week } = isoWeekOf(d);
    return `${isoYear}-W${pad2(week)}`;
  }
  if (frequency === 'monthly') {
    return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}`;
  }
  return null;
}

/**
 * Position of a day within an ISO week: Monday = 1 … Sunday = 7.
 * day_of_week is stored 0 = Sunday (Date#getDay()'s own convention), so Sunday
 * has to move to the END of the week rather than the start, or a Sunday
 * schedule would read as already-passed on every Monday.
 */
function isoDayPosition(dayOfWeek) {
  return dayOfWeek === 0 ? 7 : dayOfWeek;
}

/** Has this period's firing moment already arrived at `now`? */
function slotReached(schedule, now) {
  const hour = toInt(schedule.hour);
  if (schedule.frequency === 'daily') {
    return now.getHours() >= hour;
  }
  if (schedule.frequency === 'weekly') {
    const want = isoDayPosition(toInt(schedule.day_of_week));
    const have = isoDayPosition(now.getDay());
    if (have > want) return true;
    if (have < want) return false;
    return now.getHours() >= hour;
  }
  if (schedule.frequency === 'monthly') {
    const want = toInt(schedule.day_of_month);
    const have = now.getDate();
    if (have > want) return true;
    if (have < want) return false;
    return now.getHours() >= hour;
  }
  return false;
}

/** True when the row carries the four fields slotReached/periodKeyFor need. */
function schedulePlausible(schedule) {
  if (!schedule || typeof schedule !== 'object') return false;
  if (!FREQUENCIES.includes(schedule.frequency)) return false;
  const hour = toInt(schedule.hour);
  if (hour === null || hour < 0 || hour > 23) return false;
  if (schedule.frequency === 'weekly') {
    const dow = toInt(schedule.day_of_week);
    if (dow === null || dow < 0 || dow > 6) return false;
  }
  if (schedule.frequency === 'monthly') {
    const dom = toInt(schedule.day_of_month);
    if (dom === null || dom < 1 || dom > MAX_DAY_OF_MONTH) return false;
  }
  return true;
}

/**
 * Is this schedule due right now?
 *
 * @param {object} schedule a report_schedules row (or an equivalent object)
 * @param {Date|string|number} now the caller's clock — never read from here
 * @param {string|null|undefined} lastSuccessPeriod the `period` of the most
 *   recent SUCCESSFUL delivery. THREE distinct inputs, and the third is the one
 *   that regresses silently:
 *     a string  — delivered, and this is the slot it covered
 *     null      — MEASURED: the delivery log was read and holds no success
 *     undefined — UNMEASURED: the log could not be read at all
 * @returns {{due: boolean, period: string|null, reason: string}}
 *
 * ⛔ AN UNREADABLE DELIVERY HISTORY SKIPS, AND THE ARGUMENT IS ASYMMETRIC COST.
 * `undefined` is NOT folded into `null`. Treating it as "never delivered" would
 * re-send on every tick for as long as the read keeps failing — an auditor
 * receiving the same compliance PDF hourly, each copy looking exactly as
 * official as the first, and no way for them to tell which is the real one.
 * Treating it as "already delivered" would silently stop a security report that
 * somebody is relying on, with every signal still green. Neither is harmless, so
 * the choice is made on which is RECOVERABLE: a late report is fixed by the next
 * healthy tick and the operator is told in the job summary; a duplicated audit
 * document cannot be unsent, and the trust it costs is not recovered by the next
 * tick. So: SKIP, with its own reason, surfaced by runReportScheduleJob rather
 * than swallowed. This is the failed-read-as-a-fact rule applied to a scheduler
 * — the same call lib/engines/evidenceWindow.js makes when it falls back to the
 * floor rather than the cap.
 *
 * ⛔ ONLY THE CURRENT PERIOD IS EVER DELIVERED. A slot missed entirely — the
 * engine was down for a week — is NOT back-filled, because a report is a
 * point-in-time measurement: building last week's document from today's data
 * and filing it under last week's slot would be a mislabelled artefact, which
 * on an audit PDF is worse than an absent one. `period` is always the slot `now`
 * falls in, and that is the only slot the log can be satisfied by.
 */
function dueState(schedule, now, lastSuccessPeriod) {
  try {
    const when = asDate(now);
    if (!when) return { due: false, period: null, reason: DUE_REASONS.INVALID };
    if (!schedulePlausible(schedule)) {
      return { due: false, period: null, reason: DUE_REASONS.INVALID };
    }
    const period = periodKeyFor(schedule.frequency, when);
    if (!period) return { due: false, period: null, reason: DUE_REASONS.INVALID };

    // Checked BEFORE the history read is judged: a paused schedule is not
    // waiting on anything and must not be reported as blocked by a failed read.
    if (schedule.enabled === false) {
      return { due: false, period, reason: DUE_REASONS.DISABLED };
    }

    if (lastSuccessPeriod === undefined) {
      return { due: false, period, reason: DUE_REASONS.UNKNOWN_HISTORY };
    }
    if (typeof lastSuccessPeriod === 'string' && lastSuccessPeriod === period) {
      return { due: false, period, reason: DUE_REASONS.ALREADY };
    }
    if (!slotReached(schedule, when)) {
      return { due: false, period, reason: DUE_REASONS.NOT_REACHED };
    }
    return { due: true, period, reason: DUE_REASONS.DUE };
  } catch (_err) {
    // Never throws: a scheduler that dies on one malformed row stops delivering
    // every other schedule too.
    return { due: false, period: null, reason: DUE_REASONS.INVALID };
  }
}

/**
 * The schedule in the operator's own words — rendered in the panel, in the API
 * response and in the engine log, from ONE definition. Three copies of this
 * sentence would eventually disagree, and the disagreeing one would be the one
 * on screen next to a delivery that did not match it.
 *
 * @returns {string} never empty, and never a half-sentence: an unusable row
 *   says so rather than printing "Every  at :00".
 */
function describeSchedule(schedule) {
  if (!schedulePlausible(schedule)) return 'Not a usable schedule';
  const hour = `${pad2(toInt(schedule.hour))}:00`;
  if (schedule.frequency === 'daily') return `Every day at ${hour}`;
  if (schedule.frequency === 'weekly') {
    return `Every ${DAY_NAMES[toInt(schedule.day_of_week)]} at ${hour}`;
  }
  return `Day ${toInt(schedule.day_of_month)} of each month at ${hour}`;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Validate a schedule as submitted, against the catalogue entry it names.
 *
 * @param {object} input the request body / row to check
 * @param {object|null} catalogueEntry lib/reports/catalogue.js's entry for
 *   input.report_id — resolved by the CALLER, because this file may not require
 *   the catalogue (see the zero-requires rule at the top) and because a null
 *   entry is itself a finding this function has to report.
 * @returns {{ok: boolean, errors: string[], value: object|null}}
 *
 * ⛔ THE CATALOGUE IS THE ALLOW-LIST, exactly as app/api/reports/[id]/pdf/route.js
 * treats it. A declared `choice` parameter is accepted only if the value appears
 * in that entry's own `choices`, and an UNDECLARED key is refused rather than
 * dropped. Dropping it would silently widen the document — a schedule the
 * operator believes delivers the PCI report quietly mailing the whole-fleet one
 * under a PCI filename, once a month, for ever. A mislabelled audit artefact is
 * strictly worse than an error.
 */
function validateSchedule(input, catalogueEntry) {
  const errors = [];
  try {
    const src = input && typeof input === 'object' ? input : {};

    // ---- the report -------------------------------------------------------
    const reportId = typeof src.report_id === 'string' ? src.report_id.trim() : '';
    if (!reportId) errors.push('report_id is required.');
    if (reportId && !catalogueEntry) {
      errors.push(`No such report: ${reportId}.`);
    }
    if (catalogueEntry && catalogueEntry.id !== reportId) {
      errors.push('The catalogue entry does not match report_id.');
    }

    // ⛔ AN ENTITY-SCOPED REPORT IS NOT SCHEDULABLE, and this is a refusal
    // rather than an omission. The Rule Change Request report is produced FROM A
    // RECORD, and report_schedules has no column for that record's id — by
    // design, because the thing a recurring schedule would have to do is pick
    // one, and "whichever request happens to be newest" is a document whose
    // subject changes without anyone asking. Adding a column later is a schema
    // decision with its own argument; silently scheduling the wrong record is
    // not. The catalogue stays the single registry: this refuses one SCOPE, not
    // one id.
    if (catalogueEntry && catalogueEntry.scope === 'entity') {
      errors.push(
        `${catalogueEntry.name} is produced from a single record and cannot be scheduled; `
        + 'export it from the record itself.'
      );
    }

    // ---- frequency + grain ------------------------------------------------
    const frequency = typeof src.frequency === 'string' ? src.frequency.trim() : '';
    if (!FREQUENCIES.includes(frequency)) {
      errors.push(`frequency must be one of: ${FREQUENCIES.join(', ')}.`);
    }

    // ⛔ hour DEFAULTS TO 6, matching the column default, but ONLY when it is
    // absent. An unparseable hour is an ERROR, never a fallback to 6 — a typo
    // must not silently move a delivery, the same call SESSION_IDLE_MINUTES
    // makes when it refuses to treat a negative as "off".
    let hour = 6;
    if (src.hour !== undefined && src.hour !== null && src.hour !== '') {
      const h = toInt(src.hour);
      if (h === null || h < 0 || h > 23) {
        errors.push('hour must be a whole number from 0 to 23 (server-local).');
      } else {
        hour = h;
      }
    }

    let dayOfWeek = null;
    let dayOfMonth = null;
    if (frequency === 'weekly') {
      const dow = toInt(src.day_of_week);
      if (dow === null || dow < 0 || dow > 6) {
        errors.push('A weekly schedule needs day_of_week, 0 (Sunday) to 6 (Saturday).');
      } else {
        dayOfWeek = dow;
      }
      if (src.day_of_month !== undefined && src.day_of_month !== null && src.day_of_month !== '') {
        errors.push('day_of_month is meaningless for a weekly schedule.');
      }
    } else if (frequency === 'monthly') {
      const dom = toInt(src.day_of_month);
      if (dom === null || dom < 1 || dom > MAX_DAY_OF_MONTH) {
        // ⛔ The cap is NAMED in the message. "1 to 28" with no reason reads as
        // an arbitrary limit and the operator tries 30 again next month.
        errors.push(
          `A monthly schedule needs day_of_month, 1 to ${MAX_DAY_OF_MONTH} — a later day `
          + 'would never fire in February.'
        );
      } else {
        dayOfMonth = dom;
      }
      if (src.day_of_week !== undefined && src.day_of_week !== null && src.day_of_week !== '') {
        errors.push('day_of_week is meaningless for a monthly schedule.');
      }
    } else if (frequency === 'daily') {
      if (src.day_of_week !== undefined && src.day_of_week !== null && src.day_of_week !== '') {
        errors.push('day_of_week is meaningless for a daily schedule.');
      }
      if (src.day_of_month !== undefined && src.day_of_month !== null && src.day_of_month !== '') {
        errors.push('day_of_month is meaningless for a daily schedule.');
      }
    }

    // ---- the channel ------------------------------------------------------
    // Shape only. Whether the row exists, is an EMAIL channel and is enabled is
    // a database question, answered in reportScheduleData.js / the route — this
    // file takes no pool.
    const channelId = typeof src.channel_id === 'string' ? src.channel_id.trim() : '';
    if (!channelId || !UUID_RE.test(channelId)) {
      errors.push('channel_id must be the id of an email notification channel.');
    }

    // ---- scope ------------------------------------------------------------
    const rawDevice = src.device_id === undefined || src.device_id === null || src.device_id === ''
      ? null
      : String(src.device_id).trim();
    if (rawDevice && !UUID_RE.test(rawDevice)) {
      errors.push('device_id is not a valid identifier.');
    }
    if (catalogueEntry) {
      const takesDevice = catalogueEntry.scope === 'device' || catalogueEntry.optionalDevice === true;
      // ⛔ A device-scoped report with no device must NOT quietly deliver the
      // whole fleet under a title saying otherwise, and a fleet-only report
      // must not silently ignore a device somebody chose. Both are the same
      // mislabelled-document failure the download route refuses, arriving
      // through a schedule instead of a query string.
      if (catalogueEntry.scope === 'device' && !rawDevice) {
        errors.push(`${catalogueEntry.name} is scoped to one firewall and needs a device.`);
      }
      if (rawDevice && !takesDevice) {
        errors.push(`${catalogueEntry.name} cannot be narrowed to a single firewall.`);
      }
    }

    // ---- declared parameters ---------------------------------------------
    const params = {};
    const given = src.params && typeof src.params === 'object' && !Array.isArray(src.params)
      ? src.params
      : {};
    if (src.params !== undefined && src.params !== null
      && (typeof src.params !== 'object' || Array.isArray(src.params))) {
      errors.push('params must be an object.');
    }
    const declared = catalogueEntry && Array.isArray(catalogueEntry.params)
      ? catalogueEntry.params
      : [];
    const declaredKeys = new Set(declared.map((p) => p.key));
    if (catalogueEntry) {
      for (const key of Object.keys(given)) {
        // An absolute from/to pair belongs to a `range` parameter, refused just
        // below — name it precisely rather than as an unknown key.
        if (declaredKeys.has(key) || key === 'from' || key === 'to') continue;
        errors.push(`${catalogueEntry.name} has no parameter called ${key}.`);
      }
    }
    for (const p of declared) {
      // ⛔ A RANGE PARAMETER CANNOT BE SCHEDULED, and this is the one refusal
      // most likely to be "fixed" by a later session. A range is two ABSOLUTE
      // timestamps (Traffic Activity's from/to). Stored on a schedule they do
      // not move, so a weekly report would mail the same fixed window for ever
      // — a document whose cover page says "last 7 days" and whose contents are
      // a week last March, with nothing in the product disagreeing. The builder's
      // own default window is RELATIVE to generation time and is therefore the
      // only correct behaviour for a recurring delivery, so the schedule stores
      // nothing and lets it apply. If a relative window is ever wanted, it needs
      // its own declared parameter (a `hours`/`days` choice), not a stored
      // instant.
      if (p.kind === 'range') {
        const supplied = ['from', 'to', p.key].filter((k) => given[k] !== undefined
          && given[k] !== null && given[k] !== '');
        if (supplied.length > 0) {
          errors.push(
            `${p.label || p.key} is a fixed date range and cannot be scheduled — a stored `
            + 'range would deliver the same window every time. Leave it unset and each '
            + 'delivery covers the window up to when it ran.'
          );
        }
        continue;
      }
      const raw = given[p.key];
      // Absent or empty is "unscoped", which is every report's own default and
      // is a real choice (the picker's "All standards"), not a blank.
      if (raw === undefined || raw === null || raw === '') continue;
      const value = String(raw);
      const allowed = Array.isArray(p.choices) ? p.choices : [];
      if (!allowed.some((c) => c.value === value)) {
        errors.push(`${value} is not a valid ${p.label || p.key} for ${catalogueEntry.name}.`);
      } else {
        params[p.key] = value;
      }
    }

    // `enabled` is tri-state on the wire: absent means "use the column default"
    // (TRUE). Only an explicit false disables.
    const enabled = src.enabled === undefined || src.enabled === null
      ? true
      : src.enabled === true || src.enabled === 'true';

    if (errors.length > 0) return { ok: false, errors, value: null };
    return {
      ok: true,
      errors: [],
      value: {
        report_id: reportId,
        params,
        device_id: rawDevice,
        frequency,
        hour,
        day_of_week: dayOfWeek,
        day_of_month: dayOfMonth,
        channel_id: channelId,
        enabled,
      },
    };
  } catch (err) {
    // Never throws — a malformed body is a 400, not a 500.
    return {
      ok: false,
      errors: errors.length > 0 ? errors : [`Could not read the schedule: ${err.message}`],
      value: null,
    };
  }
}

module.exports = {
  FREQUENCIES,
  DAY_NAMES,
  DUE_REASONS,
  MAX_DAY_OF_MONTH,
  periodKeyFor,
  dueState,
  describeSchedule,
  validateSchedule,
};
