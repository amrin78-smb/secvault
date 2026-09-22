'use strict';
// Pins lib/engines/complianceExceptions.js — the compliance EXCEPTION workflow.
//
// WHY THIS FILE EXISTS. An exception is a label a human types, sitting next to a
// measurement. Every way this feature can go wrong is the same way: the label
// starts being treated as the measurement. So six contract rules are pinned
// here, each with the "we could not measure this" case alongside the pass and
// fail cases — because that is the one that regresses silently, the wrong
// answer being a plausible sentence rather than a crash:
//
//   1. an exception NEVER changes a finding's status, and the headline score is
//      computed without it
//   2. expires_at is MANDATORY
//   3. expiry is evaluated at READ TIME, with no cron job
//   4. THREE live states + revoked history, none of them look alike
//   5. accepted_by comes from the SESSION, never the request body
//   6. an exception is only recorded against a check that is ACTUALLY FAILING
//
// ⛔ NO DATABASE. Every storage function only calls `pool.query(sql, params)`,
// so each test hands it a stub that records the statements it was given and
// returns canned rows. That gives two independent things to pin: the SQL the
// engine constructs, and its interpretation of what comes back. The readonly
// role on the live server cannot write anyway.
//
// SQL assertions match a meaningful FRAGMENT, never a whole string, and each
// comment says which rule the fragment stands for.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  ACCEPTED,
  EXPIRING,
  EXPIRED,
  REVOKED,
  EXCEPTION_STATES,
  STATE_LABELS,
  STATE_TONES,
  EXPIRING_WINDOW_DAYS,
  validateExpiry,
  exceptionState,
  describeException,
  describeExceptions,
  summariseExceptions,
  ExceptionRequestError,
  listExceptions,
  listFailingChecks,
  createException,
  revokeException,
  getExceptionView,
} = require('../lib/engines/complianceExceptions');

const REPO = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(REPO, rel), 'utf8');

// ⛔ NEGATIVE source assertions run over CODE ONLY. Every file in this feature
// carries a comment saying what it must NOT do ("⛔ NOT body.acceptedBy",
// "there is deliberately no scorePct here"), and a naive grep matches the
// warning as if it were the violation — a test that fails precisely because the
// rule was documented. Comments are stripped first; the positive assertions
// still read the whole file, because a comment is where the reasoning lives.
function codeOf(rel) {
  const noBlock = read(rel).replace(/\/\*[\s\S]*?\*\//g, ' ');
  return noBlock
    .split('\n')
    .map((line) => {
      // Strip a `//` comment, but not one inside a `https://` URL — crude on
      // purpose. These four files contain no regex literals and no `//` inside
      // a string, and a lint that over-strips only ever gives up coverage,
      // which is the safe direction.
      const i = line.indexOf('//');
      if (i < 0) return line;
      if (i > 0 && line[i - 1] === ':') return line;
      return line.slice(0, i);
    })
    .join('\n');
}

const ENGINE_PATH = 'lib/engines/complianceExceptions.js';
const POST_ROUTE = 'app/api/compliance/[deviceId]/exceptions/route.js';
const DELETE_ROUTE = 'app/api/compliance/[deviceId]/exceptions/[exceptionId]/route.js';
const PANEL = 'components/compliance/ExceptionsPanel.js';

// ── stub pool ───────────────────────────────────────────────────────────────

// Records every {sql, params}. `handler(sql, params, n)` may return a result
// object, or an Error meaning "reject with this".
function stubPool(handler) {
  const calls = [];
  return {
    calls,
    query(sql, params) {
      calls.push({ sql: String(sql), params });
      const out = handler ? handler(String(sql), params, calls.length) : undefined;
      if (out instanceof Error) return Promise.reject(out);
      return Promise.resolve(out === undefined ? { rows: [], rowCount: 0 } : out);
    },
  };
}

const isInsert = (sql) => /\bINSERT\s+INTO\b/i.test(sql);
const isUpdate = (sql) => /\bUPDATE\b/i.test(sql);
const isDelete = (sql) => /\bDELETE\s+FROM\b/i.test(sql);

// A stub that answers the rule-6 validation SELECT with `status`, and accepts
// the INSERT. The (device, check) pair is a REAL one off the live fleet: HRIS,
// `rule-no-any-any-allow` — 151 failing findings exist across 16 devices there.
const DEVICE_ID = '710506de-d602-459e-8fa1-40b7a318dcd4';
const SLUG = 'rule-no-any-any-allow';
const EXC_ID = '11111111-2222-3333-4444-555555555555';

function poolForCreate(findingRows, insertResult) {
  return stubPool((sql) => {
    if (isInsert(sql)) {
      return insertResult instanceof Error
        ? insertResult
        : insertResult || { rows: [{ id: EXC_ID, check_slug: SLUG, expires_at: '2027-01-01T00:00:00Z' }] };
    }
    return { rows: findingRows, rowCount: findingRows.length };
  });
}

const NOW = new Date('2026-09-22T00:00:00Z');
const day = (n) => new Date(NOW.getTime() + n * 24 * 60 * 60 * 1000).toISOString();

function row(over = {}) {
  return {
    id: EXC_ID,
    device_id: DEVICE_ID,
    check_slug: SLUG,
    reason: 'Segment is air-gapped; accepted by the security committee.',
    compensating_control: 'Compensated by upstream ACL on the core switch.',
    accepted_by: 'amrin',
    accepted_at: day(-10),
    expires_at: day(90),
    revoked_at: null,
    revoked_by: null,
    check_name: 'No unrestricted (any-source/any-destination) allow rules',
    check_severity: 'high',
    check_standards: ['PCI_DSS', 'CIS_V8'],
    current_status: 'fail',
    ...over,
  };
}

// ══════════════════════════════════════════════════════════════════════════
// RULE 1 — an exception never changes a finding's status, and the headline
//          score is computed without it
// ══════════════════════════════════════════════════════════════════════════

describe('rule 1: an exception never moves a finding or the score', () => {
  it('the engine never writes audit_findings, on any code path', () => {
    const src = read(ENGINE_PATH);
    // The engine may READ audit_findings (rule 6 needs to), but every write
    // verb against it would be a status change.
    for (const verb of ['UPDATE audit_findings', 'INSERT INTO audit_findings', 'DELETE FROM audit_findings']) {
      assert.ok(
        !new RegExp(verb, 'i').test(src),
        `${ENGINE_PATH} must never "${verb}" — an exception does not change a finding's status`
      );
    }
  });

  it('no storage function issues a write against audit_findings at runtime', async () => {
    const pool = poolForCreate([{ status: 'fail', check_name: 'x' }]);
    await createException(pool, {
      deviceId: DEVICE_ID, checkSlug: SLUG, reason: 'r', acceptedBy: 'amrin', expiresAt: day(60),
    }, NOW);
    await revokeException(pool, { exceptionId: EXC_ID, deviceId: DEVICE_ID, revokedBy: 'amrin' });
    await getExceptionView(pool, DEVICE_ID, NOW);
    for (const c of pool.calls) {
      const touchesFindings = /audit_findings/i.test(c.sql);
      const writes = isInsert(c.sql) || isUpdate(c.sql) || isDelete(c.sql);
      assert.ok(
        !(touchesFindings && writes),
        `a write reached audit_findings:\n${c.sql}`
      );
    }
  });

  it('NO SCORE-COMPUTING CODE references compliance_exceptions', () => {
    // ⛔ THE REAL PIN FOR RULE 1, and it is a repo scan rather than a comment
    // because a comment promising this would not survive the first refactor.
    // If a scoring path ever learns about exceptions, the headline compliance
    // score stops being a measurement and this test fails.
    //
    // ⛔ THE LIST IS THE ARITHMETIC, NOT EVERY SURFACE THAT PRINTS IT. The
    // contract explicitly permits a PRESENTATION surface to show the accepted
    // count BESIDE the score — lib/schema.sql's own comment says the UI and the
    // PDF should — so the fleet/standards pages and the report renderer are
    // deliberately NOT here: a mention there may be entirely correct. What must
    // never happen is an exception reaching the pass/fail/warning counts, and
    // that arithmetic lives in these five files only.
    const scorers = [
      'lib/engines/configAuditor.js',
      'lib/engines/dashboardSnapshot.js',
      'lib/engines/securityScore.js',
      'app/api/compliance/[deviceId]/route.js',
      'app/api/compliance/fleet/route.js',
    ];
    for (const rel of scorers) {
      const full = path.join(REPO, rel);
      if (!fs.existsSync(full)) continue;
      const src = fs.readFileSync(full, 'utf8');
      assert.ok(
        !/compliance_exceptions|complianceExceptions/.test(src),
        `${rel} must not know about compliance exceptions — the headline score is computed as if none existed`
      );
    }
  });

  it('the per-device page computes its score BEFORE and WITHOUT the exception data', () => {
    const src = read('app/(dashboard)/compliance/[deviceId]/page.js');
    // aggregateStandards is the score path; it must be fed `findings` only.
    assert.match(src, /aggregateStandards\(findings\)/);
    assert.ok(
      !/aggregateStandards\([^)]*exception/i.test(src),
      'the score aggregation must not be handed exception data'
    );
    // scorePctFromCounts's inputs are pass/fail/warning — no exception term.
    const fn = src.slice(src.indexOf('function scorePctFromCounts'), src.indexOf('async function getDevice'));
    assert.ok(!/exception/i.test(fn), 'scorePctFromCounts must contain no exception term');
  });

  it('summariseExceptions reports COUNTS and never a percentage', () => {
    const s = summariseExceptions(describeExceptions([row()], NOW), 12);
    assert.equal(s.failingChecks, 12);
    assert.equal(s.covering, 1);
    assert.equal(s.unaccepted, 11);
    // ⛔ A second compliance percentage beside the first, differing by a set of
    // typed labels, is the artefact this feature must not create.
    for (const k of Object.keys(s)) {
      assert.ok(!/pct|percent|score/i.test(k), `summary must not expose a score-shaped field: ${k}`);
    }
    assert.ok(!/scorePct/.test(codeOf(ENGINE_PATH)), 'the engine must not compute a scorePct');
  });

  it('the panel states on screen that the score ignores exceptions', () => {
    const src = read(PANEL);
    // ⛔ Without this sentence a reader can reasonably assume the accepted count
    // has already been netted off the score above.
    assert.match(src, /does not change the compliance score/i);
  });

  it('an unsupplied failing-check count is null, not 0', () => {
    // "0 failing checks are unaccepted" and "we were not told how many are
    // failing" are opposite statements.
    const s = summariseExceptions([], null);
    assert.equal(s.failingChecks, null);
    assert.equal(s.unaccepted, null);
    assert.notEqual(s.unaccepted, 0);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// RULE 2 — expires_at is MANDATORY
// ══════════════════════════════════════════════════════════════════════════

describe('rule 2: expires_at is mandatory', () => {
  for (const bad of [undefined, null, '', '   ']) {
    it(`refuses a missing expiry (${JSON.stringify(bad)}) and says an expiry is required`, () => {
      const v = validateExpiry(bad, NOW);
      assert.equal(v.ok, false);
      assert.match(v.error, /expiry date is required/i);
      // The reason is stated, not just the refusal.
      assert.match(v.error, /permanent|silent pass/i);
    });
  }

  it('refuses an unparseable expiry with a DIFFERENT message than a missing one', () => {
    const v = validateExpiry('next tuesday-ish', NOW);
    assert.equal(v.ok, false);
    assert.match(v.error, /could not read/i);
    assert.notEqual(v.error, validateExpiry('', NOW).error);
  });

  it('refuses an expiry in the past', () => {
    const v = validateExpiry(day(-1), NOW);
    assert.equal(v.ok, false);
    assert.match(v.error, /not in the future/i);
  });

  it('refuses an expiry exactly equal to now — it would lapse on arrival', () => {
    assert.equal(validateExpiry(NOW.toISOString(), NOW).ok, false);
  });

  it('accepts a future expiry', () => {
    const v = validateExpiry(day(30), NOW);
    assert.equal(v.ok, true);
    assert.ok(v.expiresAt instanceof Date);
  });

  it('createException THROWS BEFORE ANY WRITE when the expiry is missing', async () => {
    const pool = poolForCreate([{ status: 'fail', check_name: 'x' }]);
    await assert.rejects(
      () => createException(pool, { deviceId: DEVICE_ID, checkSlug: SLUG, reason: 'r', acceptedBy: 'amrin' }, NOW),
      (err) => err instanceof ExceptionRequestError && /expiry date is required/i.test(err.message)
    );
    // ⛔ Nothing at all was written — not even the validation SELECT should
    // have led to a partial row.
    assert.equal(pool.calls.filter((c) => isInsert(c.sql)).length, 0);
  });

  it('the INSERT casts the expiry ::timestamptz explicitly', async () => {
    const pool = poolForCreate([{ status: 'fail', check_name: 'x' }]);
    await createException(pool, {
      deviceId: DEVICE_ID, checkSlug: SLUG, reason: 'r', acceptedBy: 'amrin', expiresAt: day(60),
    }, NOW);
    const ins = pool.calls.find((c) => isInsert(c.sql));
    assert.ok(ins, 'expected an INSERT');
    // Without the cast PostgreSQL reports "could not determine data type of parameter".
    assert.match(ins.sql, /::timestamptz/);
    assert.match(ins.sql, /expires_at/);
  });

  it('the form marks the expiry required and offers no way to omit it', () => {
    const src = read(PANEL);
    assert.match(src, /id="ce-expiry"/);
    assert.match(src, /An expiry is mandatory/i);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// RULE 3 — expiry is evaluated at READ TIME, with no cron job
// ══════════════════════════════════════════════════════════════════════════

describe('rule 3: expiry is a read-time computation', () => {
  it('the SAME stored row is accepted at one read and expired at a later one', () => {
    const r = row({ expires_at: day(10) });
    assert.equal(exceptionState(r, NOW), EXPIRING);
    assert.equal(exceptionState(r, new Date(NOW.getTime() + 11 * 86400000)), EXPIRED);
    // Nothing about the row changed. Only `now` did.
    assert.equal(r.expires_at, day(10));
  });

  it('there is no stored state column and nothing writes one', () => {
    const schema = read('lib/schema.sql');
    const block = schema.slice(
      schema.indexOf('CREATE TABLE IF NOT EXISTS compliance_exceptions'),
      schema.indexOf('uq_compliance_exceptions_live')
    );
    assert.ok(block.length > 0, 'compliance_exceptions must exist in schema.sql');
    // Only the two timestamp facts; no derived status.
    assert.ok(!/\bstate\b|\bstatus\b/i.test(block), 'compliance_exceptions must store no derived state');
  });

  it('NO CRON JOB — the engine worker does not know this feature exists', () => {
    const src = read('services/engine-worker.js');
    assert.ok(
      !/compliance_exceptions|complianceExceptions/.test(src),
      'expiry must not be enforced by a scheduled job'
    );
  });

  it('`expiring` is its own visible state, so a lapse is never a surprise', () => {
    assert.ok(EXCEPTION_STATES.includes(EXPIRING));
    assert.equal(exceptionState(row({ expires_at: day(EXPIRING_WINDOW_DAYS - 1) }), NOW), EXPIRING);
    assert.equal(exceptionState(row({ expires_at: day(EXPIRING_WINDOW_DAYS + 1) }), NOW), ACCEPTED);
    // The boundary itself is inside the warning window, not outside it.
    assert.equal(exceptionState(row({ expires_at: day(EXPIRING_WINDOW_DAYS) }), NOW), EXPIRING);
  });

  it('the expiring window is a constant, not an env var', () => {
    const src = read(ENGINE_PATH);
    assert.equal(typeof EXPIRING_WINDOW_DAYS, 'number');
    assert.ok(EXPIRING_WINDOW_DAYS > 0);
    // ⛔ A visibility SAFETY FLOOR, not a tuning knob — configurable would let
    // an install set it to 0 and reintroduce the surprise.
    assert.ok(
      !/process\.env/.test(src),
      'the engine must read no environment variables'
    );
  });

  it('a lapsed exception stops counting as covering immediately', () => {
    const live = describeException(row({ expires_at: day(5) }), NOW);
    const lapsed = describeException(row({ expires_at: day(-5) }), NOW);
    assert.equal(live.covers, true);
    assert.equal(lapsed.covers, false);
    assert.equal(summariseExceptions([lapsed], 3).covering, 0);
    assert.equal(summariseExceptions([lapsed], 3).unaccepted, 3);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// RULE 4 — three live states + revoked, none of them look alike
// ══════════════════════════════════════════════════════════════════════════

describe('rule 4: three states, never two, plus revoked history', () => {
  it('produces all four states from real row shapes', () => {
    assert.equal(exceptionState(row({ expires_at: day(120) }), NOW), ACCEPTED);
    assert.equal(exceptionState(row({ expires_at: day(3) }), NOW), EXPIRING);
    assert.equal(exceptionState(row({ expires_at: day(-3) }), NOW), EXPIRED);
    assert.equal(exceptionState(row({ revoked_at: day(-1) }), NOW), REVOKED);
    assert.deepEqual([...EXCEPTION_STATES].sort(), [ACCEPTED, EXPIRED, EXPIRING, REVOKED].sort());
  });

  it('REVOKED wins over expiry — a withdrawn exception did not lapse on its own', () => {
    // Revoked AND past its expiry: it must read as revoked, because somebody
    // withdrew it; "lapsed" would tell the wrong story about how it ended.
    assert.equal(exceptionState(row({ revoked_at: day(-2), expires_at: day(-1) }), NOW), REVOKED);
    // And revoked while still in date must certainly not read as accepted.
    assert.equal(exceptionState(row({ revoked_at: day(-2), expires_at: day(90) }), NOW), REVOKED);
  });

  it('every state has a DISTINCT label and a DISTINCT tone', () => {
    const labels = EXCEPTION_STATES.map((s) => STATE_LABELS[s]);
    const tones = EXCEPTION_STATES.map((s) => STATE_TONES[s]);
    assert.equal(new Set(labels).size, EXCEPTION_STATES.length, `labels collide: ${labels}`);
    assert.equal(new Set(tones).size, EXCEPTION_STATES.length, `tones collide: ${tones}`);
    // ⛔ The two that must never be confused.
    assert.notEqual(STATE_TONES[EXPIRED], STATE_TONES[ACCEPTED]);
    assert.notEqual(STATE_LABELS[EXPIRED], STATE_LABELS[ACCEPTED]);
  });

  it('an expired exception is NOT rendered as an absence either', () => {
    // It has a tone, a label and a timing sentence — it is a positive, visible,
    // actionable fact ("this check is failing with nothing covering it"), not a
    // blank where an exception used to be.
    const d = describeException(row({ expires_at: day(-4) }), NOW);
    assert.equal(d.state, EXPIRED);
    assert.equal(d.label, 'Lapsed');
    assert.ok(d.tone);
    assert.equal(d.expiryUnreadable, false);
    assert.equal(typeof d.daysRemaining, 'number');
    assert.ok(d.daysRemaining < 0, 'a lapsed exception reports how long ago it lapsed');
  });

  it('the panel separates revoked history from live exceptions', () => {
    const src = read(PANEL);
    assert.match(src, /state !== 'revoked'/);
    assert.match(src, /Revoked history/);
  });

  it('the panel maps all four tones to tokens, never hex', () => {
    const src = read(PANEL);
    assert.ok(!/#[0-9a-fA-F]{3,8}\b/.test(src), 'the panel must use design tokens, not hex');
    for (const tone of new Set(Object.values(STATE_TONES))) {
      assert.match(src, new RegExp(`\\b${tone}\\b`), `panel has no treatment for tone "${tone}"`);
    }
  });
});

// ══════════════════════════════════════════════════════════════════════════
// RULE 5 — accepted_by comes from the SESSION, never the request body
// ══════════════════════════════════════════════════════════════════════════

describe('rule 5: accepted_by comes from the session', () => {
  it('the POST route reads the actor from the session and never from the body', () => {
    const src = read(POST_ROUTE);
    // Positive: the actor is resolved off the session object.
    assert.match(src, /session\.user\.name/);
    assert.match(src, /acceptedBy,?\s*$|acceptedBy,/m);
    // ⛔ Negative, and this is the assertion that matters: no body-supplied
    // owner, in any spelling. A caller must not be able to attribute a risk
    // acceptance to a colleague.
    const code = codeOf(POST_ROUTE);
    for (const re of [/body\.acceptedBy/, /body\.accepted_by/, /body\[['"]accepted/, /body\.owner/]) {
      assert.ok(!re.test(code), `POST route must not read the acceptor from the body (${re})`);
    }
  });

  it('the DELETE route resolves the revoker from the session too', () => {
    const src = read(DELETE_ROUTE);
    assert.match(src, /session\.user\.name/);
    assert.ok(!/body\.revokedBy|body\.revoked_by/.test(src));
    // A DELETE has no body to read in the first place; pin that it stays that way.
    assert.ok(!/request\.json\(\)/.test(src), 'the revoke route must not parse a body');
  });

  it('the panel never offers an acceptor field and never sends one', () => {
    const src = read(PANEL);
    assert.ok(!/acceptedBy:/.test(src), 'the panel must not send an acceptedBy field');
    assert.match(src, /JSON\.stringify\(\{\s*checkSlug, reason, compensatingControl: control, expiresAt\s*\}\)/);
  });

  it('createException REFUSES an empty actor rather than writing "unknown"', async () => {
    // ⛔ An un-attributable risk acceptance is worth nothing in an audit, and a
    // fabricated owner string is the failed-read-as-a-fact bug aimed at this
    // feature's own audit trail.
    for (const actor of [undefined, null, '', '  ']) {
      const pool = poolForCreate([{ status: 'fail', check_name: 'x' }]);
      await assert.rejects(
        () => createException(pool, {
          deviceId: DEVICE_ID, checkSlug: SLUG, reason: 'r', acceptedBy: actor, expiresAt: day(60),
        }, NOW),
        (err) => err instanceof ExceptionRequestError && /could not determine who/i.test(err.message)
      );
      assert.equal(pool.calls.filter((c) => isInsert(c.sql)).length, 0);
    }
    const src = read(ENGINE_PATH);
    assert.ok(!/accepted_by.*'unknown'|'unknown'.*accepted_by/.test(src));
  });

  it('revokeException refuses an empty revoker too', async () => {
    const pool = stubPool(() => ({ rows: [row()], rowCount: 1 }));
    await assert.rejects(
      () => revokeException(pool, { exceptionId: EXC_ID, deviceId: DEVICE_ID, revokedBy: '' }),
      (err) => err instanceof ExceptionRequestError && /could not determine who/i.test(err.message)
    );
    assert.equal(pool.calls.length, 0, 'nothing may be written without a named revoker');
  });

  it('the actor reaches the INSERT verbatim, trimmed', async () => {
    const pool = poolForCreate([{ status: 'fail', check_name: 'x' }]);
    await createException(pool, {
      deviceId: DEVICE_ID, checkSlug: SLUG, reason: '  r  ', acceptedBy: '  amrin  ', expiresAt: day(60),
    }, NOW);
    const ins = pool.calls.find((c) => isInsert(c.sql));
    assert.ok(ins.params.includes('amrin'));
    assert.ok(ins.params.includes('r'));
  });

  it('both mutating routes are gated on OPERATE, and the UI gate is not stricter', () => {
    for (const rel of [POST_ROUTE, DELETE_ROUTE]) {
      const src = read(rel);
      assert.match(src, /can\(session, OPERATE\)/, `${rel} must gate on OPERATE`);
      assert.match(src, /forbiddenResponse\(OPERATE\)/, `${rel} must use forbiddenResponse`);
      assert.match(src, /getServerSession\(authOptions\)/, `${rel} must resolve its own session`);
      assert.match(src, /export const dynamic = 'force-dynamic'/, `${rel} must be force-dynamic`);
    }
    // ⛔ A UI gate must never be STRICTER than the API it fronts: the page
    // passes the SAME capability the routes check.
    const page = read('app/(dashboard)/compliance/[deviceId]/page.js');
    assert.match(page, /can\(session, OPERATE\)/);
    assert.match(page, /canWrite=\{canWrite\}/);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// RULE 6 — only against a check that is ACTUALLY FAILING
// ══════════════════════════════════════════════════════════════════════════

describe('rule 6: an exception is only recorded against a failing check', () => {
  for (const status of ['pass', 'warning', 'na']) {
    it(`refuses a check whose current status is "${status}"`, async () => {
      const pool = poolForCreate([{ status, check_name: 'NTP configured' }]);
      await assert.rejects(
        () => createException(pool, {
          deviceId: DEVICE_ID, checkSlug: SLUG, reason: 'r', acceptedBy: 'amrin', expiresAt: day(60),
        }, NOW),
        (err) => err instanceof ExceptionRequestError
          && new RegExp(`"${status}", not failing`).test(err.message)
      );
      assert.equal(pool.calls.filter((c) => isInsert(c.sql)).length, 0);
    });
  }

  it('⛔ refuses a check with NO finding at all, with its OWN message', async () => {
    // "we could not measure this" — the check is not evaluated on this device
    // (never audited, or it left the seed library). Telling the operator "it is
    // not failing" would be a different and FALSE claim: we do not know what it
    // is. So the two refusals must not share a message.
    const pool = poolForCreate([]);
    await assert.rejects(
      () => createException(pool, {
        deviceId: DEVICE_ID, checkSlug: SLUG, reason: 'r', acceptedBy: 'amrin', expiresAt: day(60),
      }, NOW),
      (err) => err instanceof ExceptionRequestError
        && /No compliance result exists/i.test(err.message)
        && !/not failing/i.test(err.message)
    );
    assert.equal(pool.calls.filter((c) => isInsert(c.sql)).length, 0);
  });

  it('allows a check that IS failing', async () => {
    const pool = poolForCreate([{ status: 'fail', check_name: 'x' }]);
    const created = await createException(pool, {
      deviceId: DEVICE_ID, checkSlug: SLUG, reason: 'r', acceptedBy: 'amrin', expiresAt: day(60),
    }, NOW);
    assert.equal(created.id, EXC_ID);
  });

  it('the validation query runs BEFORE the insert, not after', async () => {
    const pool = poolForCreate([{ status: 'fail', check_name: 'x' }]);
    await createException(pool, {
      deviceId: DEVICE_ID, checkSlug: SLUG, reason: 'r', acceptedBy: 'amrin', expiresAt: day(60),
    }, NOW);
    const validateIdx = pool.calls.findIndex((c) => /audit_findings/i.test(c.sql));
    const insertIdx = pool.calls.findIndex((c) => isInsert(c.sql));
    assert.ok(validateIdx >= 0 && insertIdx > validateIdx);
  });

  it('refuses an empty reason before touching the database', async () => {
    const pool = poolForCreate([{ status: 'fail', check_name: 'x' }]);
    await assert.rejects(
      () => createException(pool, {
        deviceId: DEVICE_ID, checkSlug: SLUG, reason: '   ', acceptedBy: 'amrin', expiresAt: day(60),
      }, NOW),
      (err) => err instanceof ExceptionRequestError && /reason is required/i.test(err.message)
    );
    assert.equal(pool.calls.length, 0);
  });

  it('a duplicate live exception is a 409 with an instruction, not a 500', async () => {
    const dup = Object.assign(new Error('duplicate key value violates unique constraint'), { code: '23505' });
    const pool = poolForCreate([{ status: 'fail', check_name: 'x' }], dup);
    await assert.rejects(
      () => createException(pool, {
        deviceId: DEVICE_ID, checkSlug: SLUG, reason: 'r', acceptedBy: 'amrin', expiresAt: day(60),
      }, NOW),
      (err) => err instanceof ExceptionRequestError && err.status === 409 && /Revoke it first/i.test(err.message)
    );
  });

  it('an unexpected database error is NOT dressed up as bad input', async () => {
    const boom = Object.assign(new Error('connection terminated'), { code: '08006' });
    const pool = poolForCreate([{ status: 'fail', check_name: 'x' }], boom);
    await assert.rejects(
      () => createException(pool, {
        deviceId: DEVICE_ID, checkSlug: SLUG, reason: 'r', acceptedBy: 'amrin', expiresAt: day(60),
      }, NOW),
      (err) => !(err instanceof ExceptionRequestError) && /connection terminated/.test(err.message)
    );
  });
});

// ══════════════════════════════════════════════════════════════════════════
// THE SLUG <-> UUID JOIN — the single most likely bug in this feature
// ══════════════════════════════════════════════════════════════════════════

describe('the slug/UUID join routes through audit_checks', () => {
  // `audit_findings.check_id` is a UUID FK to `audit_checks.id`;
  // `compliance_exceptions.check_slug` holds `audit_checks.check_id`, the TEXT
  // slug. Two columns called check_id, two tables, two types.
  const allSql = () => {
    const src = read(ENGINE_PATH);
    return src;
  };

  it('every findings join is ON ac.id = af.check_id', () => {
    const src = allSql();
    const joins = [...src.matchAll(/JOIN\s+audit_findings\s+af\s+ON\s+([^\n]+)/gi)].map((m) => m[1]);
    assert.ok(joins.length > 0, 'expected at least one audit_findings join');
    for (const j of joins) {
      assert.match(j, /af\.check_id\s*=\s*ac\.id|ac\.id\s*=\s*af\.check_id/);
    }
    const inner = [...src.matchAll(/FROM\s+audit_findings\s+af\s+JOIN\s+audit_checks\s+ac\s+ON\s+([^\n]+)/gi)].map((m) => m[1]);
    for (const j of inner) {
      assert.match(j, /ac\.id\s*=\s*af\.check_id/);
    }
  });

  it('the slug is compared against ac.check_id, NEVER af.check_id or ac.id', () => {
    const src = allSql();
    // Positive: the text slug is matched on audit_checks.
    assert.match(src, /ac\.check_id\s*=\s*\$\d/);
    assert.match(src, /ac\.check_id\s*=\s*ce\.check_slug/);
    // ⛔ Negative: either of these is the bug. `af.check_id = $slug` is a type
    // error Postgres reports as invalid UUID syntax; `ac.id = $slug` is the
    // same mistake wearing a different hat.
    assert.ok(!/af\.check_id\s*=\s*\$\d/.test(src), 'a slug must never be compared to af.check_id');
    assert.ok(!/ac\.id\s*=\s*ce\.check_slug/.test(src), 'a slug must never be compared to ac.id');
    assert.ok(!/ac\.id\s*=\s*\$\d/.test(src), 'a slug must never be compared to ac.id');
  });

  it('listFailingChecks selects the SLUG, not the finding UUID', async () => {
    const pool = stubPool(() => ({
      rows: [{ check_slug: SLUG, check_name: 'n', check_severity: 'high', check_standards: ['PCI_DSS'], detail: null, detected_at: null }],
      rowCount: 1,
    }));
    const out = await listFailingChecks(pool, DEVICE_ID);
    assert.equal(out[0].checkSlug, SLUG);
    const sql = pool.calls[0].sql;
    assert.match(sql, /ac\.check_id\s+AS\s+check_slug/i);
    // And only failing checks are offered.
    assert.match(sql, /af\.status\s*=\s*'fail'/i);
    assert.deepEqual(pool.calls[0].params, [DEVICE_ID]);
  });

  it('listExceptions LEFT JOINs both, so an orphan slug still renders', async () => {
    const pool = stubPool(() => ({ rows: [row({ check_name: null, current_status: null })], rowCount: 1 }));
    const rows = await listExceptions(pool, DEVICE_ID);
    assert.equal(rows.length, 1);
    const sql = pool.calls[0].sql;
    // ⛔ An inner join would make an operator's recorded decision VANISH from
    // the page when a check leaves the seed library, or when the device has
    // never been audited.
    assert.match(sql, /LEFT JOIN audit_checks/i);
    assert.match(sql, /LEFT JOIN audit_findings/i);
  });

  it('every query is parameterised — no interpolation into a SQL string', () => {
    // ⛔ Only template literals that CONTAIN SQL are examined. An error message
    // legitimately interpolates the operator's own bad input; a SQL string must
    // never interpolate anything but the shared SELECT fragment constant, which
    // carries no user input of any kind.
    const src = allSql();
    const literals = [...src.matchAll(/`([^`]*)`/g)].map((m) => m[1]);
    const sqlLiterals = literals.filter((l) => /\b(SELECT|INSERT INTO|UPDATE|DELETE FROM)\b/i.test(l));
    assert.ok(sqlLiterals.length >= 4, `expected the engine's SQL literals, found ${sqlLiterals.length}`);
    for (const lit of sqlLiterals) {
      for (const m of lit.matchAll(/\$\{([^}]+)\}/g)) {
        assert.equal(m[1].trim(), 'EXCEPTION_SELECT', `unexpected SQL interpolation: \${${m[1]}}`);
      }
    }
    // And every query passes its values as $n placeholders.
    assert.match(src, /\$1/);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// "WE COULD NOT MEASURE THIS" — the cases that regress silently
// ══════════════════════════════════════════════════════════════════════════

describe('the unmeasured cases', () => {
  it('an UNREADABLE stored expiry fails CLOSED to expired, and says so', () => {
    const d = describeException(row({ expires_at: 'not-a-date' }), NOW);
    // ⛔ Never accepted. "Default it to fine" is exactly where this codebase's
    // signature bug survives review.
    assert.notEqual(d.state, ACCEPTED);
    assert.notEqual(d.state, EXPIRING);
    assert.equal(d.state, EXPIRED);
    assert.equal(d.covers, false);
    // ⛔ And it is not silently swallowed — the caller can tell this apart from
    // an exception that genuinely ran out.
    assert.equal(d.expiryUnreadable, true);
    assert.equal(describeException(row({ expires_at: day(-1) }), NOW).expiryUnreadable, false);
  });

  it('daysRemaining is NULL, never 0, when the expiry cannot be read', () => {
    // A 0 would render as "expires today", which is a claim. We do not know.
    const d = describeException(row({ expires_at: null }), NOW);
    assert.equal(d.daysRemaining, null);
    assert.notEqual(d.daysRemaining, 0);
  });

  it('the panel draws an unreadable expiry HUELESS, not red and not green', () => {
    const src = read(PANEL);
    assert.match(src, /expiryUnreadable/);
    // The hueless chip is the --unmeasured token, per the design system's
    // "NOT MEASURED has no hue" rule.
    assert.match(src, /var\(--unmeasured\)/);
    const chip = src.slice(src.indexOf('function UnmeasuredChip'), src.indexOf('function StateChip'));
    for (const banned of ['--sev-', '--tint-danger', '--tint-success', '--tint-warn', '--red', '--green']) {
      assert.ok(!chip.includes(banned), `the unmeasured chip must carry no hue (${banned})`);
    }
  });

  it('an exception over a check that is NOT BEING EVALUATED is flagged, not counted as cover', () => {
    // current_status NULL = no finding row at all on this device. An exception
    // over a check nobody is asking is not evidence of anything.
    const d = describeException(row({ current_status: null, expires_at: day(90) }), NOW);
    assert.equal(d.state, ACCEPTED);          // its own timing is fine
    assert.equal(d.checkNotEvaluated, true);
    assert.equal(d.covers, false);            // but it covers nothing
    const s = summariseExceptions([d], 0);
    assert.equal(s.overCheckNotEvaluated, 1);
    assert.equal(s.covering, 0);
  });

  it('an exception over a check that now PASSES is flagged as no longer needed', () => {
    const d = describeException(row({ current_status: 'pass' }), NOW);
    assert.equal(d.checkNoLongerFailing, true);
    assert.equal(d.checkNotEvaluated, false);
    assert.equal(d.covers, false);
    assert.equal(summariseExceptions([d], 0).overCheckNoLongerFailing, 1);
  });

  it('checkNotEvaluated and checkNoLongerFailing are never both true', () => {
    for (const st of [null, 'pass', 'fail', 'warning', 'na']) {
      const d = describeException(row({ current_status: st }), NOW);
      assert.ok(!(d.checkNotEvaluated && d.checkNoLongerFailing), `both set for status ${st}`);
    }
  });

  it('the page reports an exception LOAD FAILURE rather than omitting the panel', () => {
    // ⛔ Silently dropping the panel would render a device with three accepted
    // exceptions identically to one with none.
    const src = read('app/(dashboard)/compliance/[deviceId]/page.js');
    assert.match(src, /Accepted risk could not be loaded/i);
    assert.match(src, /exceptions\.error \?/);
  });

  it('describeException never throws on a junk row', () => {
    for (const junk of [{}, { expires_at: {} }, { revoked_at: 'x', expires_at: 'y' }]) {
      const d = describeException(junk, NOW);
      assert.ok(EXCEPTION_STATES.includes(d.state));
      assert.equal(d.covers, false);
    }
    assert.equal(exceptionState(null, NOW), EXPIRED);
    assert.equal(exceptionState(undefined, NOW), EXPIRED);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// revoke + view assembly
// ══════════════════════════════════════════════════════════════════════════

describe('revoke and the assembled view', () => {
  it('revoke is a soft UPDATE scoped by device and idempotent-safe — never a DELETE', async () => {
    const pool = stubPool(() => ({ rows: [row({ revoked_at: day(0), revoked_by: 'amrin' })], rowCount: 1 }));
    const out = await revokeException(pool, { exceptionId: EXC_ID, deviceId: DEVICE_ID, revokedBy: 'amrin' });
    assert.ok(out);
    const { sql, params } = pool.calls[0];
    // ⛔ A DELETE would let an exception be recorded, relied on, and erased.
    assert.ok(!isDelete(sql), 'revoke must never DELETE the row');
    assert.match(sql, /SET revoked_at = now\(\), revoked_by = \$3/);
    // Scoped by device inside the SQL, so a mis-addressed id cannot revoke
    // another device's decision.
    assert.match(sql, /AND\s+device_id\s*=\s*\$2/);
    // And re-revoking finds no row rather than re-stamping over the real time.
    assert.match(sql, /AND\s+revoked_at\s+IS\s+NULL/);
    assert.deepEqual(params, [EXC_ID, DEVICE_ID, 'amrin']);
  });

  it('revoking a non-existent or already-revoked exception returns null', async () => {
    const pool = stubPool(() => ({ rows: [], rowCount: 0 }));
    assert.equal(await revokeException(pool, { exceptionId: EXC_ID, deviceId: DEVICE_ID, revokedBy: 'a' }), null);
  });

  it('getExceptionView withholds a check that already has a LAPSED exception', async () => {
    // ⛔ An expired row still occupies the live partial unique index, so
    // offering its check for a new acceptance would produce a 409 from a
    // control that looked available. Revoke first.
    const pool = stubPool((sql) => {
      if (/compliance_exceptions/i.test(sql)) {
        return { rows: [row({ expires_at: day(-5) })], rowCount: 1 };
      }
      return {
        rows: [
          { check_slug: SLUG, check_name: 'a', check_severity: 'high', check_standards: [], detail: null, detected_at: null },
          { check_slug: 'paloalto-ntp-configured', check_name: 'b', check_severity: 'low', check_standards: [], detail: null, detected_at: null },
        ],
        rowCount: 2,
      };
    });
    const view = await getExceptionView(pool, DEVICE_ID, NOW);
    assert.equal(view.failingChecks.length, 2);
    assert.deepEqual(view.availableChecks.map((c) => c.checkSlug), ['paloalto-ntp-configured']);
    assert.equal(view.summary.expired, 1);
    assert.equal(view.summary.covering, 0);
    assert.equal(view.summary.unaccepted, 2);
    assert.equal(view.expiringWindowDays, EXPIRING_WINDOW_DAYS);
    assert.ok(view.evaluatedAt);
  });

  it('a REVOKED exception frees its check for a new acceptance', async () => {
    const pool = stubPool((sql) => {
      if (/compliance_exceptions/i.test(sql)) return { rows: [row({ revoked_at: day(-1) })], rowCount: 1 };
      return {
        rows: [{ check_slug: SLUG, check_name: 'a', check_severity: 'high', check_standards: [], detail: null, detected_at: null }],
        rowCount: 1,
      };
    });
    const view = await getExceptionView(pool, DEVICE_ID, NOW);
    assert.deepEqual(view.availableChecks.map((c) => c.checkSlug), [SLUG]);
    assert.equal(view.summary.revoked, 1);
  });

  it('every descriptor field is JSON-serialisable for the server -> client boundary', () => {
    // ⛔ v2.120.0 shipped a blank /reports because a FUNCTION crossed this
    // boundary. Dates leave as ISO strings and nothing else crosses.
    const d = describeException(row(), NOW);
    const round = JSON.parse(JSON.stringify(d));
    assert.deepEqual(round, d);
    assert.equal(typeof d.expiresAt, 'string');
    assert.equal(typeof d.acceptedAt, 'string');
  });
});
