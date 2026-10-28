'use strict';
//
// lib/entraSettings.js — validating and sequencing a change to WHICH DIRECTORY
// IS TRUSTED TO ISSUE IDENTITIES for this platform.
//
// ⛔ WHY THIS IS PURE AND SEPARATELY TESTED, and why that is not idiom. It is
// the same argument lib/consoleUrl.js makes about NEXTAUTH_URL — "the
// validation is the safety mechanism, not decoration around a write" — applied
// to a strictly more dangerous field. Getting the console address wrong locks
// the operator out; getting ENTRA_TENANT_ID wrong points the sign-in flow at a
// directory somebody else controls, and `manage_users` gates this route for
// exactly that reason.
//
// It was NOT separate at first: every function here lived in
// app/api/system/entra/route.js, which imports next-auth, next/server and the
// auth options, none of which resolve under plain node. So the test loaded it
// by stripping `import` lines and evaluating the remainder — a technique that
// works, is used elsewhere in this repo, and is load-bearing brittleness in a
// test guarding an authorisation boundary: it breaks on an unrelated import
// change, and a test that breaks for the wrong reason gets waived.
//
// ⛔ THREE DEFECTS SHIPPED HERE BECAUSE NOTHING COULD TEST IT. Each is written
// out beside the function that now prevents it: a refused write reported as
// HTTP 200, a disable path the form could not reach, and a restart banner that
// compared configured-NESS instead of values so a credential ROTATION never
// showed it. All three are shapes a behavioural test catches and a source scan
// does not.
//
// ⛔ THE CLIENT SECRET IS WRITE-ONLY. Nothing here returns it, and nothing here
// returns lib/envFile.js's `previous` — which, for ENTRA_CLIENT_SECRET, IS the
// old secret. The console-address route forwards `previous` to its client;
// copying that pattern here would put a live credential in an HTTP response.

// ⛔ ONE PARSER FOR THE ENV GRAMMAR, NOT TWO. lib/envFile.js's LINE_RE carries a
// trailing-\r fix whose absence once corrupted the very file this feature
// writes to; a second regex for the same grammar is a second parser that would
// eventually disagree with the authoritative one.
const { LINE_RE } = require('./envFile');

/** The three keys, in no particular order — the ORDER that matters is below. */
const ENTRA_KEYS = ['ENTRA_TENANT_ID', 'ENTRA_CLIENT_ID', 'ENTRA_CLIENT_SECRET'];

/** How far back "Recent refused sign-ins" looks. */
const REFUSAL_WINDOW_DAYS = 7;

/**
 * The human label for each key, used in the restart banner and in a partial
 * write report. ⛔ LABELS TRAVEL, VALUES DO NOT — this map is the whole reason
 * the secret can be compared at all.
 */
const ENTRA_FIELD_LABELS = {
  ENTRA_TENANT_ID: 'Directory (tenant) ID',
  ENTRA_CLIENT_ID: 'Application (client) ID',
  ENTRA_CLIENT_SECRET: 'Client secret',
};

/** A GUID, which is what both the tenant and client ids are. */
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Normalise the three values out of a request body.
 *
 * ⛔ THE SECRET IS TRIMMED NOW, AND IT USED TO BE DELIBERATELY NOT. The old
 * reasoning was that a secret may legitimately contain unusual characters, so
 * nothing should touch it — but `parseEnv` in lib/envFile.js TRIMS ON READ, so
 * surrounding whitespace could never have survived the round trip anyway.
 * Keeping it only meant storing bytes that would never be read back. Worse, a
 * LEADING OR TRAILING NEWLINE — which is what a paste from a text editor or a
 * `cat`-ed file produces — hit setEnvValue's line-break refusal, and while that
 * refusal was being discarded (see applyEntraWrites) the operator was told the
 * secret had saved. So the trim is what makes the common paste work; it mangles
 * nothing, because the untrimmed form was unreadable.
 *
 * ⛔ A WHOLLY-WHITESPACE SECRET IS NOT A CLEAR. It trims to '', which is the
 * explicit "remove the stored secret" instruction, and inferring that from what
 * is far more likely a bad paste would delete a working credential. It is
 * reported as `blankedByTrim` and refused by planEntraWrite.
 */
function normaliseEntraInput(body) {
  const b = body && typeof body === 'object' ? body : {};
  const tenantId = typeof b.tenantId === 'string' ? b.tenantId.trim() : '';
  const clientId = typeof b.clientId === 'string' ? b.clientId.trim() : '';
  // ⛔ THREE-WAY, AND THE THIRD STATE IS LOAD-BEARING. `undefined` means LEAVE
  // THE STORED SECRET ALONE, '' means CLEAR IT, anything else means replace it.
  // Collapsing the first two would make every edit of the tenant id wipe the
  // secret, because the form cannot pre-fill a value it is never given.
  const raw = typeof b.clientSecret === 'string' ? b.clientSecret : undefined;
  const clientSecret = raw === undefined ? undefined : raw.trim();
  return {
    tenantId,
    clientId,
    clientSecret,
    blankedByTrim: raw !== undefined && raw !== '' && clientSecret === '',
  };
}

/**
 * Which keys appear MORE THAN ONCE in the file. Pre-flight, because a duplicate
 * is the one setEnvValue refusal that is a property of the FILE rather than of
 * the value — so it is knowable before any write, and knowing it before the
 * first write is what keeps a refusal from landing halfway through the
 * sequence below.
 *
 * ⛔ THIS IS THE REPRODUCED CASE, NOT A HYPOTHETICAL. `.env.local.example`
 * ships all three ENTRA_* keys blank and docs/ENTRA-SSO-SETUP.md describes
 * adding them by hand as a fallback — doing both duplicates all three, and
 * every save then answered 200 while changing nothing.
 */
function duplicateEntraKeys(text, keys = ENTRA_KEYS) {
  const counts = new Map();
  for (const line of String(text == null ? '' : text).split(/\r?\n/)) {
    const m = LINE_RE.exec(line);
    if (m && keys.includes(m[1])) counts.set(m[1], (counts.get(m[1]) || 0) + 1);
  }
  return keys.filter((k) => (counts.get(k) || 0) > 1);
}

/**
 * Turn a normalised body into a validated, ordered list of writes.
 *
 * ⛔ THE ORDER IS OFF → CHANGE → ON, AND THAT IS THE WHOLE SAFETY PROPERTY.
 * This route used to write the secret first and claim in a comment that "a
 * partial failure leaves a tenant WITHOUT a usable secret, which is refused at
 * sign-in, rather than a secret sitting beside a tenant id that no longer
 * matches it." The claim was the exact inverse of what the code produced: a
 * refused tenant write left the NEW SECRET beside the OLD TENANT ID, and
 * because isEntraConfigured() (lib/entraRoles.js) requires all three to be
 * non-empty — and all three already are on any machine where Entra is live —
 * no partial sequence could ever turn the feature off.
 *
 * So the sequence now MAKES that state unreachable rather than asserting it is:
 *
 *   1. ENTRA_TENANT_ID = ''      the feature is now definitively OFF
 *   2. ENTRA_CLIENT_SECRET       (only when the body supplied one)
 *   3. ENTRA_CLIENT_ID
 *   4. ENTRA_TENANT_ID = <new>   the feature is ON again, last
 *
 * Any failure after step 1 leaves the tenant blank, so no sign-in button
 * renders, local accounts keep working, and the operator is told which keys
 * landed. A failure AT step 1 has changed nothing at all. ⛔ That costs two
 * extra writes when the tenant id is unchanged (a rotation of the secret alone)
 * and it is worth it: lib/entraRoles.js's own note says a half-configured
 * tenant "would register a button that cannot complete a sign-in, which is
 * worse than no button". Turning it off loudly is the documented preference.
 * Step 1 is free on a first-ever configure — setEnvValue reports `unchanged`
 * and writes nothing when the value already matches.
 *
 * ⛔ DISABLING WRITES THE TENANT FIRST TOO, for the same reason: the first
 * write of the three is already the one that takes the feature out of service.
 */
function planEntraWrite(input, context) {
  const ctx = context || {};
  const { tenantId, clientId, clientSecret, blankedByTrim } = input;
  const disabling = tenantId === '' && clientId === '' && clientSecret === '';

  if (disabling) {
    return {
      ok: true,
      disabling,
      configured: false,
      writes: [
        { key: 'ENTRA_TENANT_ID', value: '' },
        { key: 'ENTRA_CLIENT_ID', value: '' },
        { key: 'ENTRA_CLIENT_SECRET', value: '' },
      ],
    };
  }

  // ⛔ THE REFUSAL AN ADMINISTRATOR DECOMMISSIONING A TENANT USED TO GET WAS
  // "The Directory (tenant) ID must be a GUID" — an instruction to put back the
  // value they had just deliberately removed, with no path to off except RDP
  // into the server. The form could never produce the one body that satisfied
  // `disabling`, so the disable branch, its audit action and the panel's own
  // cleared-status string were all dead code. Blank ids with no explicit
  // instruction about the secret is now answered by naming the control that
  // does the job.
  if (tenantId === '' && clientId === '' && clientSecret === undefined) {
    return {
      ok: false,
      status: 400,
      error: 'Both IDs are blank. To switch Entra ID single sign-on off, use "Turn off single '
        + 'sign-on" — it clears the tenant, the application id and the stored secret together. '
        + 'Clearing the boxes alone cannot do it, because a blank secret box means "keep the '
        + 'secret you already have".',
    };
  }

  if (blankedByTrim) {
    return {
      ok: false,
      status: 400,
      error: 'The client secret was only whitespace. It has NOT been changed — if you meant to '
        + 'remove the stored secret, tick "Remove the stored secret" instead, and if you meant to '
        + 'replace it, paste the secret value again.',
    };
  }

  if (!GUID.test(tenantId)) {
    return {
      ok: false,
      status: 400,
      error: 'The Directory (tenant) ID must be a GUID, e.g. 8f4a1c2e-9b7d-4e6a-bc13-5d2f70a9e4c1.',
    };
  }
  if (!GUID.test(clientId)) {
    return {
      ok: false,
      status: 400,
      error: 'The Application (client) ID must be a GUID. Copy it from the app registration '
        + 'Overview page — not the Object ID, and not the secret ID.',
    };
  }
  // ⛔ AN INTERIOR LINE BREAK IS STILL REFUSED, AND REFUSED HERE RATHER THAN BY
  // setEnvValue. Trimming removes a trailing newline; it cannot remove one in
  // the middle, and lib/envFile.js answers that with {ok:false} — which the
  // route is only now able to see. Refusing before the first write means the
  // off-change-on sequence never starts, so the feature is not taken down by a
  // value that was never going to be writable.
  if (clientSecret !== undefined && /[\r\n]/.test(clientSecret)) {
    return {
      ok: false,
      status: 400,
      error: 'The client secret contains a line break, so it cannot be stored in the environment '
        + 'file. Paste the secret value on one line.',
    };
  }

  const writes = [{ key: 'ENTRA_TENANT_ID', value: '' }];
  if (clientSecret !== undefined) {
    writes.push({ key: 'ENTRA_CLIENT_SECRET', value: clientSecret });
  }
  writes.push({ key: 'ENTRA_CLIENT_ID', value: clientId });
  writes.push({ key: 'ENTRA_TENANT_ID', value: tenantId });

  // Will the trio be complete once these land? ⛔ An explicitly CLEARED secret
  // leaves a tenant with no credential, which is a legitimate thing to ask for
  // and leaves SSO off — so it is reported rather than refused or hidden.
  const secretAfter = clientSecret === undefined
    ? Boolean(ctx.storedSecret)
    : clientSecret !== '';

  return {
    ok: true,
    disabling: false,
    configured: Boolean(tenantId && clientId && secretAfter),
    secretCleared: clientSecret === '',
    secretReplaced: clientSecret !== undefined && clientSecret !== '',
    writes,
  };
}

/**
 * Run the planned writes, STOPPING AT THE FIRST REFUSAL.
 *
 * ⛔ setEnvValue RETURNS {ok:false, error}; IT DOES NOT THROW for any of its
 * real failure modes — a duplicated key, the 1 MB size tripwire, an unreadable
 * file, a line break in the value, a failed backup, a failed write, a failed
 * self-check. The route wrapped three bare calls in a try/catch and inspected
 * nothing, so the catch could only fire on an exception the function is written
 * not to produce: EVERY refused write answered HTTP 200 `ok:true`, and
 * `written` was pushed unconditionally, asserting that a key had landed when it
 * had not. Reproduced with a duplicated ENTRA_TENANT_ID line: 200, three keys
 * reported written, the tenant unchanged on disk and the NEW SECRET sitting
 * beside the OLD TENANT. The sibling console-url and session-policy routes both
 * get this right and the second says so in a comment.
 *
 * ⛔ THE try/catch STAYS AS WELL, around the return-value check rather than
 * instead of it. setEnvValue is not documented to throw, but it does real I/O,
 * and a defensive branch that turns an unexpected throw into the same stop-and-
 * report path costs nothing.
 *
 * ⛔ `write` IS INJECTED RATHER THAN REACHED FOR, which is what keeps this
 * module pure and lets a test drive every {ok:false} shape — including the ones
 * a real filesystem will not reproduce on demand — without a server. The route
 * passes `(key, value) => setEnvValue(file, key, value)`.
 */
function applyEntraWrites(writes, write) {
  const landed = [];
  const changed = [];
  for (const w of writes) {
    let result;
    try {
      result = write(w.key, w.value);
    } catch (err) {
      result = { ok: false, error: `${w.key} could not be written: ${(err && err.message) || String(err)}` };
    }
    if (!result || !result.ok) {
      return {
        ok: false,
        failedKey: w.key,
        error: (result && result.error) || `${w.key} could not be written.`,
        backupPath: (result && result.backupPath) || null,
        landed,
        changed,
      };
    }
    landed.push(w.key);
    if (!result.unchanged) changed.push(w.key);
  }
  return { ok: true, landed, changed };
}

/**
 * What to tell the administrator when a write in the middle of the sequence
 * failed — including WHICH keys landed, because they are the person who has to
 * recover from it and the panel renders only `error`.
 *
 * ⛔ THE PARTIAL STATE IS THE POINT. The old 500 carried `written` in the body
 * and the panel showed `body.error` alone, so even a genuine failure did not
 * say which keys had changed.
 *
 * ⛔ IT CARRIES NO VALUE, ONLY LABELS — see this file's header on `previous`.
 */
function entraWriteFailureAnswer(outcome) {
  const landed = outcome.landed || [];
  // ⛔ THE TENANT BLANK IS ALWAYS THE FIRST WRITE, so "nothing landed" and
  // "single sign-on is now off" are the only two states a stopped sequence can
  // be in. That is a property of planEntraWrite's order, not a guess about it.
  const nothingChanged = landed.length === 0;
  const parts = [`Entra ID single sign-on could not be saved: ${outcome.error}`];
  if (nothingChanged) {
    parts.push('Nothing was changed — the previous configuration is intact.');
  } else {
    parts.push(
      'Single sign-on is now OFF: the tenant id was cleared first on purpose, so a part-finished '
      + 'change can never leave a credential beside an id it does not belong to. Local accounts are '
      + 'unaffected. Fix the problem above and save again to switch it back on.'
    );
    parts.push(`Already written: ${landed.map((k) => ENTRA_FIELD_LABELS[k] || k).join(', ')}.`);
  }
  if (outcome.backupPath) parts.push(`The previous file is at ${outcome.backupPath}.`);
  return {
    error: parts.join(' '),
    failedField: ENTRA_FIELD_LABELS[outcome.failedKey] || outcome.failedKey || null,
    written: landed,
    writtenFields: landed.map((k) => ENTRA_FIELD_LABELS[k] || k),
    nothingChanged,
    ssoDisabled: !nothingChanged,
    backupPath: outcome.backupPath || null,
  };
}

/**
 * Which fields differ between what is SAVED on disk and what the process is
 * actually RUNNING with.
 *
 * ⛔ IT COMPARES VALUES, AND IT USED TO COMPARE CONFIGURED-NESS. The panel
 * computed `savedConfigured !== data.runningConfigured` — boolean against
 * boolean — and both are `true` whenever Entra is already live, so ANY EDIT to
 * an already-configured tenant produced `pendingRestart === false`. The routine
 * case it broke is a client-secret rotation: the administrator pastes the new
 * secret, saves, refreshes, sees no banner, and believes the new credential is
 * in force while the running process still presents the REVOKED one to
 * Microsoft and every Entra sign-in fails with nothing on screen saying why. It
 * worked only for the first-ever configure, which is why it passed manual
 * testing. lib/consoleUrl.js's route compares values (`current !==
 * process.env.NEXTAUTH_URL`); the comment here claimed the same distinction
 * while the code did not draw it.
 *
 * ⛔ THE SECRETS ARE COMPARED HERE, ON THE SERVER, AND NEITHER LEAVES IT. Only
 * the field LABEL of a difference is returned. A digest would also work and
 * would be no safer: the comparison is between two values the process already
 * holds, and the disclosure to guard against is the response body.
 */
function entraRestartPending(saved, running) {
  const norm = (v) => String(v == null ? '' : v).trim();
  const fields = [];
  for (const key of ENTRA_KEYS) {
    if (norm(saved && saved[key]) !== norm(running && running[key])) {
      fields.push(ENTRA_FIELD_LABELS[key]);
    }
  }
  return { pending: fields.length > 0, fields };
}

/**
 * The SQL for the refused-sign-in list, as text and parameters.
 *
 * ⛔ IT IS BUILT HERE SO THE TIME BOUND IS TESTABLE. Without a database the
 * bound cannot be observed by running the query — and it used to be absent
 * altogether, which was the defect. Returning it from a pure function makes it
 * the module's CONTRACT rather than a line of source: a test asserts the
 * returned `values` and that `text` bounds `occurred_at`, and no comment in the
 * route can satisfy that.
 *
 * ⛔ PARAMETERISED, never interpolated — the rule every query in this codebase
 * follows, and `$1::int` is cast explicitly because an untyped parameter inside
 * an interval expression is the shape PostgreSQL refuses with "could not
 * determine data type of parameter $N".
 */
function refusalQuery(windowDays = REFUSAL_WINDOW_DAYS, limit = 5) {
  return {
    text: `SELECT actor, detail, occurred_at
             FROM activity_log
            WHERE action = 'entra_signin_refused'
              AND occurred_at > now() - ($1::int * INTERVAL '1 day')
            ORDER BY occurred_at DESC
            LIMIT ${Number(limit) || 5}`,
    values: [windowDays],
  };
}

/**
 * The refused-sign-ins panel, as three states rather than one list.
 *
 * ⛔ "NO REFUSALS" AND "WE COULD NOT READ THE LOG" MUST NOT BOTH BE `[]`. The
 * read is best-effort — a logging problem must not become a configuration
 * outage — but degrading to an empty array made a failed read indistinguishable
 * from a clean one, which is this codebase's most-repeated defect. `unknown` is
 * its own state and the panel draws it hueless.
 *
 * ⛔ AND THE LIST IS TIME-BOUNDED (see refusalQuery), because nothing clears it.
 * An administrator mistypes a group object id, three users are refused, the
 * administrator fixes it and SSO works perfectly — and the amber panel then sat
 * there for ever, because once sign-in works no newer refusals arrive to push
 * those rows out. A permanent amber chip for a system working correctly teaches
 * an operator to ignore the chip that matters.
 */
function entraRefusalAnswer(rows, readFailed) {
  if (readFailed) {
    return {
      refusals: [],
      refusalState: 'unknown',
      refusalWindowDays: REFUSAL_WINDOW_DAYS,
      refusalNote: 'The activity log could not be read, so recent refused sign-ins are unknown — '
        + 'this is not a statement that there were none.',
    };
  }
  const list = Array.isArray(rows) ? rows : [];
  return {
    refusals: list,
    refusalState: list.length > 0 ? 'some' : 'none',
    refusalWindowDays: REFUSAL_WINDOW_DAYS,
    refusalNote: list.length > 0
      ? null
      : `No Entra sign-in has been refused in the last ${REFUSAL_WINDOW_DAYS} days.`,
  };
}

module.exports = {
  ENTRA_KEYS,
  REFUSAL_WINDOW_DAYS,
  ENTRA_FIELD_LABELS,
  GUID,
  normaliseEntraInput,
  duplicateEntraKeys,
  planEntraWrite,
  applyEntraWrites,
  entraWriteFailureAnswer,
  entraRestartPending,
  refusalQuery,
  entraRefusalAnswer,
};
