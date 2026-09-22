// lib/engines/complianceExceptions.js
//
// The compliance EXCEPTION workflow: an operator's recorded decision that a
// FAILING check is accepted on this device, with a compensating control, an
// owner and — mandatorily — an expiry.
//
// ⛔ AN EXCEPTION NEVER CHANGES A FINDING'S STATUS, AND THE HEADLINE SCORE IS
// COMPUTED WITHOUT IT. A failing check with an accepted exception is still
// `fail`: the firewall is still configured that way. Letting a label somebody
// typed move a measurement is how a compliance score stops being a fact people
// act on and becomes a number people manage. Structurally, that guarantee is
// kept by this module TOUCHING NOTHING the score reads — it never writes
// `audit_findings`, and no scoring code (`lib/engines/configAuditor.js`,
// `lib/engines/dashboardSnapshot.js`, `lib/reports/*`, the per-device page's
// own `scorePctFromCounts`) references `compliance_exceptions` at all.
// tests/complianceExceptions.test.js asserts both halves of that, by reading
// the repo — a comment promising it would not survive the first refactor.
//
// ⛔ THE CALLER MAY REPORT COUNTS BESIDE THE SCORE, NEVER A SECOND SCORE.
// `summariseExceptions()` therefore returns COUNTS and deliberately no
// percentage: two compliance percentages on one page, differing by a set of
// hand-typed labels, is the exact artefact this feature must not produce.
//
// ⛔ EXPIRY IS EVALUATED AT READ TIME against an injected `now`. There is no
// cron job and no stored state column — a lapsed exception stops counting as
// accepted the moment it lapses, the same way lib/engines/deviceHealth.js
// derives staleness. A stored `state` would go stale and then be read as fact.
//
// ⛔ THE SLUG/UUID TRAP — the single most likely bug in this feature.
// `audit_findings.check_id` is a UUID FK to `audit_checks.id`, while
// `compliance_exceptions.check_slug` holds `audit_checks.check_id`, the STABLE
// TEXT slug. Two columns called `check_id`, on two tables, with different types
// and different meanings. Every join here therefore routes THROUGH
// `audit_checks`: `JOIN audit_checks ac ON ac.id = af.check_id` and then
// `ac.check_id = $slug`. Comparing `af.check_id` to a slug is a type error that
// Postgres reports as invalid UUID syntax; comparing `ac.id` to a slug is the
// same mistake wearing a different hat. Never write either.
//
// Pool-taking storage + PURE status helpers, kept separable so the helpers can
// be pinned with no database and no clock. CommonJS, like every other engine.

'use strict';

// ── the four states ─────────────────────────────────────────────────────────
//
// ⛔ THREE LIVE STATES, NEVER TWO, plus revoked history. `accepted` and
// `expired` must not look alike (one covers a failing check, the other does
// not), and neither may look like "no exception was ever recorded" — an
// absence. `expiring` exists so that nobody is surprised by a lapse.
const ACCEPTED = 'accepted';
const EXPIRING = 'expiring';
const EXPIRED = 'expired';
const REVOKED = 'revoked';

const EXCEPTION_STATES = [ACCEPTED, EXPIRING, EXPIRED, REVOKED];

/**
 * How long before expiry an exception is reported as `expiring`.
 *
 * ⛔ 30 DAYS, AND IT IS A CONSTANT RATHER THAN AN ENV VAR. The reasoning is the
 * product's own review cadence, not taste: the scheduled compliance report runs
 * MONTHLY (`0 6 1 * *` in services/engine-worker.js), and a per-device
 * compliance page is something an operator opens at about that rhythm. A window
 * shorter than a month can therefore open and close ENTIRELY between two
 * reviews — the exception reads "accepted" at one sitting and "lapsed" at the
 * next, with the warning state never once on screen, which is precisely the
 * surprise this state exists to prevent. 30 days is also long enough to either
 * renew the acceptance or schedule the firewall change that removes the need
 * for it.
 *
 * It is a visibility SAFETY FLOOR, not a tuning knob — the same call
 * lib/engines/configRetention.js makes about MIN_KEEP_CONFIGS. Making it
 * configurable would let an installation set it to 0 and reintroduce the
 * surprise.
 */
const EXPIRING_WINDOW_DAYS = 30;
const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * The furthest into the future an expiry may be set.
 *
 * ⛔ A LOWER BOUND ALONE DOES NOT DELIVER THE FORCED REVIEW. `validateExpiry`
 * refused a missing, unreadable or past date and accepted anything else — so
 * `2999-12-31` was accepted, and the whole guarantee this feature rests on (an
 * acceptance comes back for review) was defeated by typing a longer number in
 * the same box. That is precisely the "permanent silent pass" the mandatory
 * expiry exists to prevent, wearing a date. The 30-day `expiring` window can
 * only warn about a lapse that is going to happen.
 *
 * ⛔ 365 DAYS, AND IT IS A CONSTANT RATHER THAN AN ENV VAR, for the same reason
 * EXPIRING_WINDOW_DAYS is: it is a safety floor, not a tuning knob, and an
 * installation that could set it to 36,500 would be back where it started. A
 * year is the review cadence a risk acceptance is actually signed off at, and
 * it is what the rest of this product already treats as "a long time" for
 * operator-declared state (CONFIG_BACKUP_RETENTION_DAYS, VPN_SESSION_RETENTION_DAYS).
 * Renewing is one form submission; the point is that somebody has to look again.
 */
const MAX_EXPIRY_DAYS = 365;

// ── pure helpers ────────────────────────────────────────────────────────────

/** A Date, or null when the value is absent or unparseable. Never throws. */
function parseTimestamp(value) {
  if (value === null || value === undefined || value === '') return null;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

const isoOrNull = (d) => (d ? d.toISOString() : null);

/**
 * Validate a requested expiry. PURE — takes `now` rather than reading a clock.
 *
 * ⛔ `expires_at` IS MANDATORY. An exception with no expiry is a permanent
 * silent pass, which is the entire failure mode this feature exists to avoid.
 * So three separate refusals, each with its own message, because the operator's
 * next action differs: supply one / supply a readable one / supply a future one.
 *
 * @returns {{ok: true, expiresAt: Date}|{ok: false, error: string}}
 */
function validateExpiry(value, now = new Date()) {
  if (value === null || value === undefined || String(value).trim() === '') {
    return {
      ok: false,
      error:
        'An expiry date is required. An exception with no expiry is a permanent '
        + 'silent pass on a check that is still failing.',
    };
  }
  const expiresAt = parseTimestamp(value);
  if (!expiresAt) {
    return {
      ok: false,
      error: `Could not read "${String(value)}" as a date. Use a date such as 2026-12-31.`,
    };
  }
  const reference = parseTimestamp(now) || new Date();
  if (expiresAt.getTime() <= reference.getTime()) {
    return {
      ok: false,
      error:
        `That expiry (${expiresAt.toISOString().slice(0, 10)}) is not in the future, so the `
        + 'exception would lapse the moment it was recorded.',
    };
  }
  // ⛔ THE UPPER BOUND, and it is the same refusal as the missing one. See
  // MAX_EXPIRY_DAYS: without it a far-future date is a permanent silent pass
  // with a date attached, which is the exact failure the mandatory expiry
  // exists to prevent — the guard was only half present.
  const latest = reference.getTime() + MAX_EXPIRY_DAYS * MS_PER_DAY;
  if (expiresAt.getTime() > latest) {
    return {
      ok: false,
      error:
        `That expiry (${expiresAt.toISOString().slice(0, 10)}) is more than ${MAX_EXPIRY_DAYS} `
        + 'days away. An acceptance that runs that long is a permanent pass on a check that is '
        + `still failing — record it for up to ${MAX_EXPIRY_DAYS} days (no later than `
        + `${new Date(latest).toISOString().slice(0, 10)}) and renew it if the risk is still `
        + 'accepted then.',
    };
  }
  return { ok: true, expiresAt };
}

/**
 * The state of one stored exception, at read time.
 *
 * ⛔ REVOKED IS CHECKED FIRST. A revoked row's expiry is irrelevant history;
 * reporting it as `expired` would imply it lapsed on its own when in fact
 * somebody withdrew it, and reporting it as `accepted` would be worse.
 *
 * ⛔ AN UNREADABLE EXPIRY FAILS CLOSED TO `expired`. The column is NOT NULL, so
 * this is defensive — but "default it to fine" is exactly where this codebase's
 * signature bug survives review, and an exception whose expiry cannot be read
 * must never be counted as covering a failing check. The caller learns WHY from
 * `describeException`'s `expiryUnreadable` flag; it is not silently swallowed.
 */
function exceptionState(row, now = new Date()) {
  if (!row || typeof row !== 'object') return EXPIRED;
  if (parseTimestamp(row.revoked_at)) return REVOKED;
  const expiresAt = parseTimestamp(row.expires_at);
  if (!expiresAt) return EXPIRED;
  const reference = parseTimestamp(now) || new Date();
  const msLeft = expiresAt.getTime() - reference.getTime();
  if (msLeft <= 0) return EXPIRED;
  if (msLeft <= EXPIRING_WINDOW_DAYS * MS_PER_DAY) return EXPIRING;
  return ACCEPTED;
}

const STATE_LABELS = {
  [ACCEPTED]: 'Accepted',
  [EXPIRING]: 'Expiring',
  [EXPIRED]: 'Lapsed',
  [REVOKED]: 'Revoked',
};

// ⛔ TONES, NOT COLOURS — the component maps these onto design tokens. Four
// distinct values, because the four states must be distinguishable at a glance:
// `danger` for a lapse (a failing check with nothing covering it any more is a
// real, actionable fact), `warning` for an approaching one, `success` for a
// live acceptance, and `muted` for withdrawn history. ⛔ `unmeasured` is the
// FIFTH tone and carries NO HUE — it is used only when the expiry itself could
// not be read, which is neither good news nor bad news.
const STATE_TONES = {
  [ACCEPTED]: 'success',
  [EXPIRING]: 'warning',
  [EXPIRED]: 'danger',
  [REVOKED]: 'muted',
};

/**
 * A serialisable descriptor for one exception row. PURE.
 *
 * Every date leaves as an ISO string and every derived number is computed here
 * rather than in the component, so the server can render the state it evaluated
 * and the client cannot silently re-derive a different one from its own clock.
 */
function describeException(row, now = new Date()) {
  const reference = parseTimestamp(now) || new Date();
  const expiresAt = parseTimestamp(row && row.expires_at);
  const revokedAt = parseTimestamp(row && row.revoked_at);
  const state = exceptionState(row, reference);

  // ⛔ NULL, NEVER 0, when the expiry could not be read. A 0 here would render
  // as "expires today", which is a claim; we do not know when it expires.
  const daysRemaining = expiresAt
    ? Math.ceil((expiresAt.getTime() - reference.getTime()) / MS_PER_DAY)
    : null;

  // The CURRENT finding status for this check on this device, as of the last
  // compliance run. ⛔ TRI-STATE AND THE NULL MATTERS: `null` means there is no
  // finding row for this check on this device at all — the check is not being
  // evaluated here (never audited, or it left the seed library). An exception
  // over a check nobody is asking is not evidence of anything, and must not be
  // presented as cover.
  const currentStatus = row && typeof row.current_status === 'string' ? row.current_status : null;

  return {
    id: (row && row.id) || null,
    deviceId: (row && row.device_id) || null,
    checkSlug: (row && row.check_slug) || null,
    checkName: (row && row.check_name) || null,
    checkSeverity: (row && row.check_severity) || null,
    checkStandards: Array.isArray(row && row.check_standards) ? row.check_standards : [],
    reason: (row && row.reason) || null,
    compensatingControl: (row && row.compensating_control) || null,
    acceptedBy: (row && row.accepted_by) || null,
    acceptedAt: isoOrNull(parseTimestamp(row && row.accepted_at)),
    expiresAt: isoOrNull(expiresAt),
    expiresAtRaw: row && row.expires_at ? String(row.expires_at) : null,
    revokedAt: isoOrNull(revokedAt),
    revokedBy: (row && row.revoked_by) || null,
    state,
    label: STATE_LABELS[state] || STATE_LABELS[EXPIRED],
    tone: STATE_TONES[state] || STATE_TONES[EXPIRED],
    daysRemaining,
    // ⛔ Surfaced rather than swallowed: the state fell closed to `expired`
    // because the date could not be read, which is a different story from an
    // exception that genuinely ran out and needs saying differently on screen.
    expiryUnreadable: !expiresAt && !revokedAt,
    // Does this exception still sit over a FAILING check?
    currentStatus,
    checkNotEvaluated: currentStatus === null,
    checkNoLongerFailing: currentStatus !== null && currentStatus !== 'fail',
    // ⛔ A live exception is one in `accepted` or `expiring`. `expired` is NOT
    // live — that is the whole point of evaluating expiry at read time.
    covers: (state === ACCEPTED || state === EXPIRING) && currentStatus === 'fail',
  };
}

/** Map describeException over a row set. PURE. */
function describeExceptions(rows, now = new Date()) {
  return (Array.isArray(rows) ? rows : []).map((r) => describeException(r, now));
}

/**
 * Counts, by state. PURE.
 *
 * ⛔ COUNTS ONLY — there is deliberately no `scorePct` here and there must never
 * be one. See this file's header: the headline compliance score is computed as
 * if no exception existed, and a second percentage beside it, differing by a
 * set of typed labels, is the artefact this feature must not create. Counts
 * answer the audit question ("3 of the 12 failures are formally accepted")
 * without inventing a rival number.
 */
function summariseExceptions(described, failingCheckCount = null) {
  const list = Array.isArray(described) ? described : [];
  const byState = { [ACCEPTED]: 0, [EXPIRING]: 0, [EXPIRED]: 0, [REVOKED]: 0 };
  let covering = 0;
  let unreadableExpiry = 0;
  let overCheckNotEvaluated = 0;
  let overCheckNoLongerFailing = 0;
  for (const d of list) {
    if (d.state in byState) byState[d.state] += 1;
    if (d.covers) covering += 1;
    if (d.expiryUnreadable) unreadableExpiry += 1;
    if (d.state !== REVOKED && d.checkNotEvaluated) overCheckNotEvaluated += 1;
    if (d.state !== REVOKED && d.checkNoLongerFailing) overCheckNoLongerFailing += 1;
  }
  const failing = Number.isFinite(failingCheckCount) ? failingCheckCount : null;
  return {
    total: list.length,
    accepted: byState[ACCEPTED],
    expiring: byState[EXPIRING],
    expired: byState[EXPIRED],
    revoked: byState[REVOKED],
    // Failing checks with a live exception over them.
    covering,
    // ⛔ null, not 0, when the failing-check count was not supplied — "0 failing
    // checks are unaccepted" and "we were not told how many are failing" are
    // opposite statements.
    failingChecks: failing,
    unaccepted: failing === null ? null : Math.max(0, failing - covering),
    unreadableExpiry,
    overCheckNotEvaluated,
    overCheckNoLongerFailing,
  };
}

// ── storage ─────────────────────────────────────────────────────────────────

// ⛔ Every one of these joins routes slug -> UUID through audit_checks. See the
// header. `ac.check_id` is the TEXT slug; `af.check_id` is the UUID.
const EXCEPTION_SELECT = `
  SELECT ce.id,
         ce.device_id,
         ce.check_slug,
         ce.reason,
         ce.compensating_control,
         ce.accepted_by,
         ce.accepted_at,
         ce.expires_at,
         ce.revoked_at,
         ce.revoked_by,
         ac.name        AS check_name,
         ac.severity    AS check_severity,
         ac.standards   AS check_standards,
         af.status      AS current_status
    FROM compliance_exceptions ce
    -- ⛔ LEFT JOIN, not JOIN. A check removed from the seed library leaves a
    -- harmless orphan (the schema comment says so, and declines a FK for this
    -- reason); an inner join would make an operator's recorded decision vanish
    -- from the page rather than showing it with an unresolved name.
    LEFT JOIN audit_checks ac   ON ac.check_id = ce.check_slug
    -- ⛔ LEFT JOIN for the same reason, plus one of its own: audit_findings is
    -- DELETE+reinserted on every compliance run, so a device that has never
    -- been audited has no row here. current_status then comes back NULL, which
    -- describeException reports as "this check is not being evaluated" rather
    -- than inventing a status.
    LEFT JOIN audit_findings af ON af.check_id = ac.id AND af.device_id = ce.device_id
`;

/** Every exception ever recorded for one device, live and revoked. */
async function listExceptions(pool, deviceId) {
  const { rows } = await pool.query(
    `${EXCEPTION_SELECT}
     WHERE ce.device_id = $1
     ORDER BY (ce.revoked_at IS NULL) DESC, ce.expires_at ASC, ce.accepted_at DESC`,
    [deviceId]
  );
  return rows;
}

/**
 * The checks currently FAILING on this device — the only checks an exception
 * may be recorded against, and the option list the form offers.
 */
async function listFailingChecks(pool, deviceId) {
  const { rows } = await pool.query(
    `SELECT ac.check_id  AS check_slug,
            ac.name      AS check_name,
            ac.severity  AS check_severity,
            ac.standards AS check_standards,
            af.detail,
            af.detected_at
       FROM audit_findings af
       JOIN audit_checks ac ON ac.id = af.check_id
      WHERE af.device_id = $1
        AND af.status = 'fail'
      ORDER BY ac.name ASC`,
    [deviceId]
  );
  return rows.map((r) => ({
    checkSlug: r.check_slug,
    checkName: r.check_name,
    checkSeverity: r.check_severity || null,
    checkStandards: Array.isArray(r.check_standards) ? r.check_standards : [],
    detail: r.detail || null,
    detectedAt: r.detected_at ? new Date(r.detected_at).toISOString() : null,
  }));
}

/**
 * Errors this module throws for an operator mistake rather than a fault. The
 * routes map these to a 400/409 with the message intact; anything else is a
 * 500, because an unexpected failure must not be dressed up as bad input.
 */
class ExceptionRequestError extends Error {
  constructor(message, { status = 400 } = {}) {
    super(message);
    this.name = 'ExceptionRequestError';
    this.status = status;
  }
}

/**
 * Record an exception.
 *
 * ⛔ `acceptedBy` IS A PARAMETER THE ROUTE FILLS FROM THE SESSION, and this
 * function refuses an empty one. It never appears in a request body — the same
 * rule saved views follow for `user_id`. A caller able to attribute a risk
 * acceptance to a colleague turns the audit trail into a liability, and
 * `accepted_by` is the one column an auditor actually reads.
 *
 * ⛔ AN EXCEPTION IS ONLY RECORDED AGAINST A CHECK THAT IS ACTUALLY FAILING.
 * Accepting a passing or `na` check is meaningless, and it would let somebody
 * pre-accept a failure that has not happened yet — an exception banked in
 * advance, which is the one shape of this feature that could actually hide a
 * real regression. The check is re-made HERE, server-side, against
 * `audit_findings`; the form's option list is a convenience, this is the
 * guarantee. The same call `ruleChangeRequests.createRequest` makes.
 */
async function createException(pool, opts = {}, now = new Date()) {
  const { deviceId, checkSlug, reason, compensatingControl, acceptedBy, expiresAt } = opts;

  if (!deviceId) throw new ExceptionRequestError('deviceId is required');
  const slug = typeof checkSlug === 'string' ? checkSlug.trim() : '';
  if (!slug) throw new ExceptionRequestError('Select the check this exception applies to.');

  const why = typeof reason === 'string' ? reason.trim() : '';
  if (!why) {
    throw new ExceptionRequestError(
      'A reason is required. An exception with no stated reason is indistinguishable '
      + 'from an unexamined failure.'
    );
  }

  const owner = typeof acceptedBy === 'string' ? acceptedBy.trim() : '';
  if (!owner) {
    // ⛔ REFUSED, not recorded as 'unknown'. An un-attributable risk acceptance
    // is worth nothing in an audit, and a fabricated owner string is this
    // codebase's failed-read-as-a-fact bug pointed at its own audit trail.
    throw new ExceptionRequestError(
      'SecVault could not determine who is accepting this risk, so the exception '
      + 'was not recorded. An exception must name the person who accepted it.'
    );
  }

  const expiry = validateExpiry(expiresAt, now);
  if (!expiry.ok) throw new ExceptionRequestError(expiry.error);

  // Rule 6, enforced before anything is written.
  const { rows: findingRows } = await pool.query(
    `SELECT af.status, ac.name AS check_name
       FROM audit_findings af
       JOIN audit_checks ac ON ac.id = af.check_id
      WHERE af.device_id = $1
        AND ac.check_id = $2
      LIMIT 1`,
    [deviceId, slug]
  );
  if (findingRows.length === 0) {
    // ⛔ A DISTINCT MESSAGE FROM "not failing". No row means this check is not
    // being evaluated on this device at all — it has never been audited, or the
    // check left the seed library. That is a fact about SecVault's coverage,
    // and telling the operator "it is not failing" would be a different and
    // false claim.
    throw new ExceptionRequestError(
      `No compliance result exists for "${slug}" on this device, so there is nothing `
      + 'to accept. Run the compliance audit first.'
    );
  }
  const current = findingRows[0].status;
  if (current !== 'fail') {
    throw new ExceptionRequestError(
      `"${findingRows[0].check_name || slug}" is currently "${current}", not failing. `
      + 'An exception can only be recorded against a check that is actually failing — '
      + 'accepting a passing or non-assessable check would bank an acceptance against '
      + 'a future failure.'
    );
  }

  try {
    const { rows } = await pool.query(
      `INSERT INTO compliance_exceptions
         (device_id, check_slug, reason, compensating_control, accepted_by, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6::timestamptz)
       RETURNING *`,
      // ⛔ Explicit ::timestamptz — without it PostgreSQL reports "could not
      // determine data type of parameter $6".
      [deviceId, slug, why, (compensatingControl || '').trim() || null, owner, expiry.expiresAt.toISOString()]
    );
    return rows[0];
  } catch (err) {
    // uq_compliance_exceptions_live: ONE live exception per (device, check).
    // ⛔ Reported as a conflict with an instruction, not as a 500 — the
    // operator's next action is to revoke the existing one, and a stack trace
    // does not say so.
    if (err && err.code === '23505') {
      throw new ExceptionRequestError(
        'This check already has a live exception on this device. Revoke it first, '
        + 'then record the replacement — revoking keeps the old decision in the history.',
        { status: 409 }
      );
    }
    throw err;
  }
}

/**
 * Revoke (never delete) an exception.
 *
 * ⛔ A SOFT REVOKE, because the partial unique index is deliberately partial:
 * the audit trail of who accepted what, and who later withdrew it, is the
 * durable value here. A DELETE would let an exception be recorded, relied on,
 * and erased.
 *
 * Scoped by device_id as well as id, so a mis-addressed id cannot revoke
 * another device's decision, and `revoked_at IS NULL` makes it idempotent-safe:
 * a second call finds no row rather than re-stamping a new revocation time over
 * the real one.
 *
 * @returns the revoked row, or null when there was no live exception with that id.
 */
async function revokeException(pool, { exceptionId, deviceId, revokedBy }) {
  if (!exceptionId) throw new ExceptionRequestError('exceptionId is required');
  if (!deviceId) throw new ExceptionRequestError('deviceId is required');
  const actor = typeof revokedBy === 'string' ? revokedBy.trim() : '';
  if (!actor) {
    throw new ExceptionRequestError(
      'SecVault could not determine who is revoking this exception, so it was left '
      + 'in place. A revocation must name the person who made it.'
    );
  }
  const { rows } = await pool.query(
    `UPDATE compliance_exceptions
        SET revoked_at = now(), revoked_by = $3
      WHERE id = $1
        AND device_id = $2
        AND revoked_at IS NULL
      RETURNING *`,
    [exceptionId, deviceId, actor]
  );
  return rows[0] || null;
}

/**
 * Everything the panel needs for one device, in one place: the exceptions with
 * their read-time states, the failing checks still available to accept, and the
 * counts.
 */
async function getExceptionView(pool, deviceId, now = new Date()) {
  const [rows, failingChecks] = await Promise.all([
    listExceptions(pool, deviceId),
    listFailingChecks(pool, deviceId),
  ]);
  const exceptions = describeExceptions(rows, now);
  const liveSlugs = new Set(
    exceptions.filter((e) => e.state !== REVOKED).map((e) => e.checkSlug)
  );
  return {
    exceptions,
    failingChecks,
    // ⛔ An `expired` exception still occupies the live unique index, so its
    // check is NOT offered for a new acceptance — the operator must revoke the
    // lapsed one first. Offering it would produce a 409 from a control that
    // looked available.
    availableChecks: failingChecks.filter((c) => !liveSlugs.has(c.checkSlug)),
    summary: summariseExceptions(exceptions, failingChecks.length),
    evaluatedAt: (parseTimestamp(now) || new Date()).toISOString(),
    expiringWindowDays: EXPIRING_WINDOW_DAYS,
  };
}

module.exports = {
  // states
  ACCEPTED,
  EXPIRING,
  EXPIRED,
  REVOKED,
  EXCEPTION_STATES,
  STATE_LABELS,
  STATE_TONES,
  EXPIRING_WINDOW_DAYS,
  MAX_EXPIRY_DAYS,
  // pure
  validateExpiry,
  exceptionState,
  describeException,
  describeExceptions,
  summariseExceptions,
  // storage
  ExceptionRequestError,
  listExceptions,
  listFailingChecks,
  createException,
  revokeException,
  getExceptionView,
};
