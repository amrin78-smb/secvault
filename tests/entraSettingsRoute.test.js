'use strict';
// tests/entraSettingsRoute.test.js
//
// Pins app/api/system/entra/route.js and components/settings/EntraSsoPanel.js.
// There was NO test anywhere on either of them, and the defects that cost the
// most were all shapes a behavioural test catches and a source scan does not:
//
//   1. ⛔ EVERY WRITE FAILURE REPORTED HTTP 200 `ok:true`. lib/envFile.js
//      RETURNS {ok:false, error} and does not throw for any of its refusals —
//      duplicate key, the 1 MB size tripwire, an unreadable file, a line break
//      in the value, a failed backup, a failed write, a failed self-check. The
//      route wrapped three bare setEnvValue calls in a try/catch and inspected
//      nothing, so the catch could only fire on an exception the function is
//      written not to produce. Reproduced with a duplicated ENTRA_TENANT_ID
//      line: 200, three keys reported written, and the NEW SECRET on disk
//      beside the OLD TENANT. Reachable through documented setup, because
//      .env.local.example ships the three keys and docs/ENTRA-SSO-SETUP.md
//      tells the operator to add them by hand.
//   2. ⛔ THE WRITE ORDER CLAIMED A PROPERTY IT DELIVERED THE INVERSE OF: "a
//      partial failure leaves a tenant WITHOUT a usable secret ... rather than
//      a secret sitting beside a tenant id that no longer matches it". The
//      order produced exactly the second state, and could never produce the
//      first, because isEntraConfigured() needs all three non-empty and all
//      three already are on a live install.
//   3. ⛔ THE DISABLE PATH WAS UNREACHABLE and the panel told the operator to
//      use it. The form omitted `clientSecret` whenever blank, and '' was the
//      only value satisfying `disabling`, so an administrator decommissioning
//      a tenant got "The Directory (tenant) ID must be a GUID". The repo's own
//      v2.193.0 pattern: mechanism correct, reachability nil, 24 tests green.
//   4. ⛔ THE RESTART BANNER COMPARED CONFIGURED-NESS, boolean against boolean,
//      so a client-secret ROTATION never showed it — the panel asserted new
//      credentials were in force while the process still presented the revoked
//      secret to Microsoft.
//   5. ⛔ "Recent refused sign-ins" had no time bound, so a fixed problem left
//      a permanent amber panel, and `[]` meant both "none" and "the log could
//      not be read".
//   6. ⛔ The secret was deliberately not trimmed, so a pasted trailing newline
//      hit the line-break refusal — which, with defect 1, was discarded.
//
// ⛔ EVERY TEST HERE ASSERTS AN OUTCOME. Several run lib/envFile.js against
// REAL TEMPORARY FILES and then read the bytes back, because "the route handled
// the refusal" is only interesting if the file on disk ends up in the state
// claimed. Three shipped-broken features in one day came from checks that
// asserted a mechanism.
//
// LOADING. The decision layer is `require`d PLAINLY from lib/entraSettings.js.
// ⛔ IT DID NOT START THAT WAY, AND THE MOVE IS PART OF THE FIX. Every function
// below lived in the route, which imports next-auth, next/server and the auth
// options — none of which resolve under plain node — so this file first loaded
// them by stripping `import` lines and evaluating the remainder. That technique
// works and is used elsewhere in this repo, and it is load-bearing brittleness
// in a test guarding an authorisation boundary: it breaks on an unrelated
// import change, and a test that breaks for the wrong reason gets waived. The
// precedent is lib/consoleUrl.js, which CLAUDE.md calls "pure and separately
// tested" and whose refusals are trustworthy for that reason.
//
// The PANEL is still loaded by stripping, because it is a React component and
// cannot be anything else — but only two module-level constants are taken from
// it, both plain values with no imported identifier in them.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { parseEnv, readEnvFile, setEnvValue } = require('../lib/envFile');
const R = require('../lib/entraSettings');

const REPO = path.join(__dirname, '..');
const ROUTE_PATH = path.join(REPO, 'app', 'api', 'system', 'entra', 'route.js');
const PANEL_PATH = path.join(REPO, 'components', 'settings', 'EntraSsoPanel.js');

/** Strip `import` lines and the `export` keyword, then evaluate up to `stop`. */
function loadPure(file, stop, names) {
  const declarations = fs.readFileSync(file, 'utf8')
    .split('\n')
    .filter((line) => !/^\s*import\s/.test(line))
    .join('\n')
    .replace(/^export[ \t]+default[ \t]+/gm, '')
    .replace(/^export[ \t]+/gm, '');
  const cut = declarations.indexOf(stop);
  assert.notEqual(cut, -1, `expected ${JSON.stringify(stop)} to mark the end of the pure half of ${path.basename(file)}`);
  // eslint-disable-next-line no-new-func
  return new Function(`${declarations.slice(0, cut)}\nreturn { ${names.join(', ')} };`)();
}

const P = loadPure(PANEL_PATH, 'function EntraSsoPanel(', [
  'ENTRA_DISABLE_PAYLOAD',
  'entraSavePayload',
]);

const TENANT_A = '8f4a1c2e-9b7d-4e6a-bc13-5d2f70a9e4c1';
const TENANT_B = '11112222-3333-4444-5555-666677778888';
const CLIENT_A = '1b2c3d4e-5f60-4718-9a2b-3c4d5e6f7081';

/** A throwaway .env.local with the shape a real one has. */
function tmpEnv(body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secvault-entra-'));
  const file = path.join(dir, '.env.local');
  fs.writeFileSync(file, body, 'utf8');
  return { dir, file };
}

const LIVE_ENV = [
  '# Auth (standalone)',
  'NEXTAUTH_SECRET=keep-me',
  'CREDENTIAL_KEY=0123456789abcdef',
  `ENTRA_TENANT_ID=${TENANT_A}`,
  `ENTRA_CLIENT_ID=${CLIENT_A}`,
  'ENTRA_CLIENT_SECRET=old-secret-value',
  '',
].join('\n');

/** The product's own definition of "SSO is on": all three non-empty. */
const configuredOnDisk = (file) => {
  const v = readEnvFile(file).values;
  return Boolean(v.ENTRA_TENANT_ID && v.ENTRA_CLIENT_ID && v.ENTRA_CLIENT_SECRET);
};

/** Run a plan against a real file, optionally refusing one key. */
function runPlan(file, writes, failOn) {
  return R.applyEntraWrites(writes, (key, value) => {
    if (failOn && key === failOn.key && value === failOn.value) {
      return { ok: false, error: `refused ${key} on purpose` };
    }
    return setEnvValue(file, key, value);
  });
}

// ── defect 1: a refused write is a failure ──────────────────────────────────

describe('⛔ setEnvValue returns {ok:false} and does not throw — it must be CHECKED', () => {
  it('stops at the first refusal and never reports it as written', () => {
    const calls = [];
    const out = R.applyEntraWrites(
      [
        { key: 'ENTRA_TENANT_ID', value: '' },
        { key: 'ENTRA_CLIENT_SECRET', value: 'new' },
        { key: 'ENTRA_CLIENT_ID', value: CLIENT_A },
      ],
      (key, value) => {
        calls.push(key);
        if (key === 'ENTRA_CLIENT_SECRET') return { ok: false, error: 'duplicated key' };
        return { ok: true, previous: value, unchanged: false };
      }
    );
    assert.equal(out.ok, false);
    assert.equal(out.failedKey, 'ENTRA_CLIENT_SECRET');
    assert.match(out.error, /duplicated key/);
    // ⛔ The refused key is NOT in `landed`, and nothing after it was attempted.
    assert.deepEqual(out.landed, ['ENTRA_TENANT_ID']);
    assert.deepEqual(calls, ['ENTRA_TENANT_ID', 'ENTRA_CLIENT_SECRET']);
  });

  it('a falsy or undefined verdict is a failure, not a success', () => {
    assert.equal(R.applyEntraWrites([{ key: 'ENTRA_CLIENT_ID', value: 'x' }], () => undefined).ok, false);
    assert.equal(R.applyEntraWrites([{ key: 'ENTRA_CLIENT_ID', value: 'x' }], () => null).ok, false);
    assert.equal(R.applyEntraWrites([{ key: 'ENTRA_CLIENT_ID', value: 'x' }], () => ({})).ok, false);
  });

  it('an unexpected THROW is also a stop, not an uncaught 500', () => {
    const out = R.applyEntraWrites(
      [{ key: 'ENTRA_TENANT_ID', value: '' }],
      () => { throw new Error('EBUSY'); }
    );
    assert.equal(out.ok, false);
    assert.match(out.error, /EBUSY/);
    assert.deepEqual(out.landed, []);
  });

  it('only a CHANGED key counts as changed; an unchanged write still landed', () => {
    const out = R.applyEntraWrites(
      [{ key: 'ENTRA_TENANT_ID', value: '' }, { key: 'ENTRA_CLIENT_ID', value: CLIENT_A }],
      (key) => ({ ok: true, unchanged: key === 'ENTRA_TENANT_ID' })
    );
    assert.deepEqual(out.landed, ['ENTRA_TENANT_ID', 'ENTRA_CLIENT_ID']);
    assert.deepEqual(out.changed, ['ENTRA_CLIENT_ID']);
  });

  it('THE REPRODUCED CASE: a duplicated key on a REAL file is refused, and the file is unchanged', () => {
    // Exactly what following .env.local.example AND docs/ENTRA-SSO-SETUP.md
    // produces: the shipped blank key plus the hand-added one.
    const { file } = tmpEnv([
      'ENTRA_TENANT_ID=',
      'CREDENTIAL_KEY=0123456789abcdef',
      `ENTRA_TENANT_ID=${TENANT_A}`,
      '',
    ].join('\n'));
    const before = fs.readFileSync(file, 'utf8');

    // ⛔ The real refusal, from the real module. This is the {ok:false} the
    // route used to discard.
    const refusal = setEnvValue(file, 'ENTRA_TENANT_ID', TENANT_B);
    assert.equal(refusal.ok, false);
    assert.match(refusal.error, /appears 2 times/);
    assert.equal(fs.readFileSync(file, 'utf8'), before);

    // And the route's pre-flight sees it BEFORE any write is attempted, so the
    // off-change-on sequence never starts.
    const dupes = R.duplicateEntraKeys(before, R.ENTRA_KEYS);
    assert.deepEqual(dupes, ['ENTRA_TENANT_ID']);
  });

  it('the pre-flight does not cry duplicate over a single occurrence or a comment', () => {
    const text = [
      '# ENTRA_TENANT_ID=commented-out-example',
      `ENTRA_TENANT_ID=${TENANT_A}`,
      `ENTRA_CLIENT_ID=${CLIENT_A}`,
      '',
    ].join('\n');
    assert.deepEqual(
      R.duplicateEntraKeys(text, R.ENTRA_KEYS),
      []
    );
  });

  it('the pre-flight survives CRLF, which is the shipped shape of this file', () => {
    const text = `ENTRA_TENANT_ID=\r\nCREDENTIAL_KEY=x\r\nENTRA_TENANT_ID=${TENANT_A}\r\n`;
    assert.deepEqual(R.duplicateEntraKeys(text, ['ENTRA_TENANT_ID']), ['ENTRA_TENANT_ID']);
  });
});

// ── defect 2: the write order ───────────────────────────────────────────────

describe('⛔ the write order is OFF -> change -> ON, and the end state proves it', () => {
  const plan = () => R.planEntraWrite(
    R.normaliseEntraInput({ tenantId: TENANT_B, clientId: CLIENT_A, clientSecret: 'new-secret' }),
    { storedSecret: true }
  );

  it('blanks the tenant FIRST and writes the real tenant LAST', () => {
    const { writes } = plan();
    assert.deepEqual(writes[0], { key: 'ENTRA_TENANT_ID', value: '' });
    assert.deepEqual(writes[writes.length - 1], { key: 'ENTRA_TENANT_ID', value: TENANT_B });
    // the secret and the client id sit between the two tenant writes
    assert.deepEqual(
      writes.slice(1, -1).map((w) => w.key),
      ['ENTRA_CLIENT_SECRET', 'ENTRA_CLIENT_ID']
    );
  });

  it('A FAILURE PART-WAY LEAVES SSO DEFINITIVELY OFF ON DISK — not a new secret beside an old id', () => {
    const { file } = tmpEnv(LIVE_ENV);
    assert.equal(configuredOnDisk(file), true, 'the fixture starts live');

    const out = runPlan(file, plan().writes, { key: 'ENTRA_CLIENT_ID', value: CLIENT_A });
    assert.equal(out.ok, false);

    const after = readEnvFile(file).values;
    // ⛔ THE OUTCOME, not the order: the feature is off.
    assert.equal(configuredOnDisk(file), false);
    assert.equal(after.ENTRA_TENANT_ID, '');
    // ⛔ And the state the old comment claimed to prevent — a new secret beside
    // a tenant id that no longer matches it — is not on disk either, because
    // there is no tenant id at all.
    assert.equal(after.ENTRA_CLIENT_SECRET, 'new-secret');
    assert.notEqual(after.ENTRA_TENANT_ID, TENANT_A);
    // every unrelated secret in the file survived
    assert.equal(after.NEXTAUTH_SECRET, 'keep-me');
    assert.equal(after.CREDENTIAL_KEY, '0123456789abcdef');

    const answer = R.entraWriteFailureAnswer(out);
    assert.equal(answer.ssoDisabled, true);
    assert.equal(answer.nothingChanged, false);
    assert.match(answer.error, /Single sign-on is now OFF/);
    // ⛔ The partial state is NAMED, because the reader has to recover from it.
    assert.deepEqual(answer.writtenFields, ['Directory (tenant) ID', 'Client secret']);
    assert.match(answer.error, /Already written: Directory \(tenant\) ID, Client secret/);
    assert.equal(answer.failedField, 'Application (client) ID');
  });

  it('a failure on the FIRST write changes nothing, and says so', () => {
    const { file } = tmpEnv(LIVE_ENV);
    const before = fs.readFileSync(file, 'utf8');
    const out = runPlan(file, plan().writes, { key: 'ENTRA_TENANT_ID', value: '' });
    assert.equal(out.ok, false);
    assert.equal(fs.readFileSync(file, 'utf8'), before);
    assert.equal(configuredOnDisk(file), true, 'the previous configuration is intact');

    const answer = R.entraWriteFailureAnswer(out);
    assert.equal(answer.nothingChanged, true);
    assert.equal(answer.ssoDisabled, false);
    assert.match(answer.error, /previous configuration is intact/);
  });

  it('a clean run leaves all three new values on disk and SSO on', () => {
    const { file } = tmpEnv(LIVE_ENV);
    const out = runPlan(file, plan().writes, null);
    assert.equal(out.ok, true);
    const after = readEnvFile(file).values;
    assert.equal(after.ENTRA_TENANT_ID, TENANT_B);
    assert.equal(after.ENTRA_CLIENT_ID, CLIENT_A);
    assert.equal(after.ENTRA_CLIENT_SECRET, 'new-secret');
    assert.equal(configuredOnDisk(file), true);
    assert.equal(after.NEXTAUTH_SECRET, 'keep-me');
  });

  it('a FIRST-EVER configure costs no extra write — the blanking step is already satisfied', () => {
    const { file } = tmpEnv('CREDENTIAL_KEY=0123456789abcdef\nENTRA_TENANT_ID=\nENTRA_CLIENT_ID=\nENTRA_CLIENT_SECRET=\n');
    const out = runPlan(file, plan().writes, null);
    assert.equal(out.ok, true);
    // ENTRA_TENANT_ID is written twice; the first is a no-op because it was
    // already blank, so setEnvValue reports `unchanged` and writes nothing.
    assert.deepEqual(out.changed, ['ENTRA_CLIENT_SECRET', 'ENTRA_CLIENT_ID', 'ENTRA_TENANT_ID']);
    assert.equal(configuredOnDisk(file), true);
  });
});

// ── defect 3: disabling is reachable, from the panel's own payload ──────────

describe('⛔ the disable path is reachable FROM THE FORM, which is the whole defect', () => {
  it("the panel's Turn-off payload reaches the route's disable branch", () => {
    // ⛔ END TO END THROUGH BOTH FILES. The panel constant is fed to the
    // route's own planner — the two halves that used to disagree.
    const plan = R.planEntraWrite(R.normaliseEntraInput(P.ENTRA_DISABLE_PAYLOAD), { storedSecret: true });
    assert.equal(plan.ok, true);
    assert.equal(plan.disabling, true);
    assert.equal(plan.configured, false);
    assert.deepEqual(plan.writes.map((w) => w.key), [
      'ENTRA_TENANT_ID', 'ENTRA_CLIENT_ID', 'ENTRA_CLIENT_SECRET',
    ]);
    assert.ok(plan.writes.every((w) => w.value === ''));
  });

  it('and it really clears the file', () => {
    const { file } = tmpEnv(LIVE_ENV);
    const plan = R.planEntraWrite(R.normaliseEntraInput(P.ENTRA_DISABLE_PAYLOAD), { storedSecret: true });
    assert.equal(runPlan(file, plan.writes, null).ok, true);
    const after = readEnvFile(file).values;
    assert.equal(after.ENTRA_TENANT_ID, '');
    assert.equal(after.ENTRA_CLIENT_ID, '');
    assert.equal(after.ENTRA_CLIENT_SECRET, '');
    assert.equal(configuredOnDisk(file), false);
    assert.equal(after.CREDENTIAL_KEY, '0123456789abcdef');
  });

  it('an EMPTIED FORM is not a disable, and is answered by naming the control that is', () => {
    // This is the body the old panel sent when the administrator cleared every
    // box: `clientSecret` omitted, because blank means keep.
    const emptied = P.entraSavePayload({ tenantId: '', clientId: '', clientSecret: '', clearSecret: false });
    assert.equal(Object.prototype.hasOwnProperty.call(emptied, 'clientSecret'), false);

    const plan = R.planEntraWrite(R.normaliseEntraInput(emptied), { storedSecret: true });
    assert.equal(plan.ok, false);
    assert.equal(plan.status, 400);
    // ⛔ NOT the old "must be a GUID", which told the operator to put back the
    // value they had just deliberately removed.
    assert.doesNotMatch(plan.error, /must be a GUID/);
    assert.match(plan.error, /Turn off single sign-on/);
  });

  it('blank secret box + unchanged ids KEEPS the stored secret — no secret write is planned', () => {
    const payload = P.entraSavePayload({ tenantId: TENANT_B, clientId: CLIENT_A, clientSecret: '', clearSecret: false });
    assert.equal(Object.prototype.hasOwnProperty.call(payload, 'clientSecret'), false);
    const plan = R.planEntraWrite(R.normaliseEntraInput(payload), { storedSecret: true });
    assert.equal(plan.ok, true);
    assert.equal(plan.writes.some((w) => w.key === 'ENTRA_CLIENT_SECRET'), false);
    // ⛔ The trio stays complete because the stored secret is untouched.
    assert.equal(plan.configured, true);

    const { file } = tmpEnv(LIVE_ENV);
    assert.equal(runPlan(file, plan.writes, null).ok, true);
    assert.equal(readEnvFile(file).values.ENTRA_CLIENT_SECRET, 'old-secret-value');
  });

  it('THE SECRET CAN BE CLEARED ALONE, which was impossible before', () => {
    const payload = P.entraSavePayload({ tenantId: TENANT_B, clientId: CLIENT_A, clientSecret: '', clearSecret: true });
    assert.equal(payload.clientSecret, '');
    const plan = R.planEntraWrite(R.normaliseEntraInput(payload), { storedSecret: true });
    assert.equal(plan.ok, true);
    assert.equal(plan.disabling, false);
    assert.equal(plan.secretCleared, true);
    // ⛔ The ids survive and SSO is OFF, because the trio is incomplete — said
    // rather than reported as a successful configure.
    assert.equal(plan.configured, false);

    const { file } = tmpEnv(LIVE_ENV);
    assert.equal(runPlan(file, plan.writes, null).ok, true);
    const after = readEnvFile(file).values;
    assert.equal(after.ENTRA_CLIENT_SECRET, '');
    assert.equal(after.ENTRA_TENANT_ID, TENANT_B);
    assert.equal(configuredOnDisk(file), false);
  });

  it('a typed secret is carried through', () => {
    const payload = P.entraSavePayload({ tenantId: TENANT_B, clientId: CLIENT_A, clientSecret: 'typed', clearSecret: false });
    assert.equal(payload.clientSecret, 'typed');
    const plan = R.planEntraWrite(R.normaliseEntraInput(payload), { storedSecret: false });
    assert.equal(plan.secretReplaced, true);
    assert.equal(plan.configured, true);
  });

  it('the ids are still validated as GUIDs when not disabling', () => {
    const bad = R.planEntraWrite(R.normaliseEntraInput({ tenantId: 'nope', clientId: CLIENT_A }), {});
    assert.equal(bad.ok, false);
    assert.match(bad.error, /Directory \(tenant\) ID must be a GUID/);
    const bad2 = R.planEntraWrite(R.normaliseEntraInput({ tenantId: TENANT_A, clientId: 'nope' }), {});
    assert.equal(bad2.ok, false);
    assert.match(bad2.error, /Application \(client\) ID must be a GUID/);
  });
});

// ── defect 4: pendingRestart compares VALUES ────────────────────────────────

describe('⛔ a credential CHANGE shows the restart banner, not only a first configure', () => {
  const live = {
    ENTRA_TENANT_ID: TENANT_A,
    ENTRA_CLIENT_ID: CLIENT_A,
    ENTRA_CLIENT_SECRET: 'running-secret',
  };

  it('THE SECRET ROTATION: same ids, new secret -> pending, naming the secret', () => {
    const r = R.entraRestartPending({ ...live, ENTRA_CLIENT_SECRET: 'brand-new-secret' }, live);
    // The old comparison was savedConfigured !== runningConfigured — true vs
    // true — so this was the case that silently reported "in force" while the
    // process still presented the REVOKED secret to Microsoft.
    assert.equal(r.pending, true);
    assert.deepEqual(r.fields, ['Client secret']);
  });

  it('NEITHER SECRET APPEARS IN WHAT IS RETURNED', () => {
    const r = R.entraRestartPending({ ...live, ENTRA_CLIENT_SECRET: 'brand-new-secret' }, live);
    const serialised = JSON.stringify(r);
    assert.doesNotMatch(serialised, /brand-new-secret/);
    assert.doesNotMatch(serialised, /running-secret/);
  });

  it('identical saved and running -> not pending', () => {
    assert.equal(R.entraRestartPending({ ...live }, live).pending, false);
  });

  it('a tenant change, a client change, and all three, each name themselves', () => {
    assert.deepEqual(
      R.entraRestartPending({ ...live, ENTRA_TENANT_ID: TENANT_B }, live).fields,
      ['Directory (tenant) ID']
    );
    assert.deepEqual(
      R.entraRestartPending({ ...live, ENTRA_CLIENT_ID: TENANT_B }, live).fields,
      ['Application (client) ID']
    );
    assert.deepEqual(
      R.entraRestartPending(live, {}).fields,
      ['Directory (tenant) ID', 'Application (client) ID', 'Client secret']
    );
  });

  it('the first-ever configure still works — the case that used to be the only one', () => {
    assert.equal(R.entraRestartPending(live, { ENTRA_TENANT_ID: '', ENTRA_CLIENT_ID: '', ENTRA_CLIENT_SECRET: '' }).pending, true);
  });

  it('whitespace and absence are the same value, so neither invents a pending restart', () => {
    assert.equal(R.entraRestartPending({ ENTRA_TENANT_ID: '  ' }, { ENTRA_TENANT_ID: undefined }).pending, false);
    assert.equal(R.entraRestartPending({ ENTRA_TENANT_ID: ` ${TENANT_A} ` }, { ENTRA_TENANT_ID: TENANT_A }).pending, false);
  });
});

// ── defect 5: the refused-sign-in panel ─────────────────────────────────────

describe('⛔ "no refusals" and "we could not read the log" are different facts', () => {
  it('a FAILED READ is `unknown` and says it is not a statement that there were none', () => {
    const a = R.entraRefusalAnswer(null, true);
    assert.equal(a.refusalState, 'unknown');
    assert.deepEqual(a.refusals, []);
    assert.match(a.refusalNote, /not a statement that there were none/i);
  });

  it('a genuinely empty log is `none`', () => {
    const a = R.entraRefusalAnswer([], false);
    assert.equal(a.refusalState, 'none');
    assert.match(a.refusalNote, new RegExp(String(R.REFUSAL_WINDOW_DAYS)));
  });

  it('rows are `some`, and carry the window they were read over', () => {
    const a = R.entraRefusalAnswer([{ actor: 'x@y', detail: 'no mapped group', at: '2026-10-20T00:00:00Z' }], false);
    assert.equal(a.refusalState, 'some');
    assert.equal(a.refusals.length, 1);
    assert.equal(a.refusalWindowDays, R.REFUSAL_WINDOW_DAYS);
  });

  it('⛔ THE WINDOW IS BOUNDED AND FINITE — an unbounded list never clears', () => {
    assert.ok(Number.isInteger(R.REFUSAL_WINDOW_DAYS));
    assert.ok(R.REFUSAL_WINDOW_DAYS >= 1 && R.REFUSAL_WINDOW_DAYS <= 90);
  });

  it('⛔ and the QUERY applies it, asserted as a RETURN VALUE rather than as source', () => {
    // ⛔ THIS WAS A SOURCE SCAN UNTIL refusalQuery() EXISTED. There is still no
    // database here, so the bound cannot be observed by RUNNING the query — but
    // building it in a pure function makes the bound the module's CONTRACT
    // instead of a line of text, and no comment in the route can satisfy an
    // assertion on a returned object.
    const q = R.refusalQuery();
    assert.deepEqual(q.values, [R.REFUSAL_WINDOW_DAYS], 'the window travels as a parameter');
    assert.match(q.text, /occurred_at\s*>/, 'the refusal query must bound occurred_at');
    assert.match(q.text, /\$1/, 'the bound must be parameterised, never interpolated');
    // ⛔ CAST EXPLICITLY. An untyped parameter inside an interval expression is
    // the shape PostgreSQL refuses with "could not determine data type".
    assert.match(q.text, /\$1::int/);
    assert.match(q.text, /ORDER BY occurred_at DESC/);
    assert.match(q.text, /LIMIT 5/, 'bounded by count as well as by time');
  });

  it('a caller-supplied window travels too, so the bound can never be a literal', () => {
    assert.deepEqual(R.refusalQuery(14).values, [14]);
    // A junk limit falls back rather than reaching the SQL unbounded.
    assert.match(R.refusalQuery(7, 'drop table').text, /LIMIT 5/);
  });

  it('⛔ the ROUTE uses that query rather than carrying its own copy', () => {
    // The one remaining at-rest assertion in this file, and it is about the
    // route CALLING the contract — a second hand-written copy of this SQL in
    // the route is how the bound gets lost again without the tests above ever
    // going red. Comments stripped first: this file's subject explains the
    // missing bound in prose.
    const src = fs.readFileSync(ROUTE_PATH, 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/(^|[\s{(;,])\/\/[^\n]*/g, '$1 ');
    assert.match(src, /refusalQuery\(/, 'the route must build the refusal query through the module');
    assert.doesNotMatch(src, /FROM activity_log/, 'the route must not carry its own copy of that SQL');
  });
});

// ── defect 6: the secret and whitespace ─────────────────────────────────────

describe('⛔ a pasted trailing newline must not be a silent failure', () => {
  it('lib/envFile.js really does refuse a line break — this is why it mattered', () => {
    const { file } = tmpEnv(LIVE_ENV);
    const r = setEnvValue(file, 'ENTRA_CLIENT_SECRET', 'abc\n');
    assert.equal(r.ok, false);
    assert.match(r.error, /line break/);
    // and with defect 1 that verdict was discarded, so the operator was told
    // the secret had saved while it had not
    assert.equal(readEnvFile(file).values.ENTRA_CLIENT_SECRET, 'old-secret-value');
  });

  it('a trailing newline is trimmed, and the secret SAVES', () => {
    const input = R.normaliseEntraInput({ tenantId: TENANT_B, clientId: CLIENT_A, clientSecret: 'abc\n' });
    assert.equal(input.clientSecret, 'abc');
    assert.equal(input.blankedByTrim, false);
    const plan = R.planEntraWrite(input, { storedSecret: true });
    assert.equal(plan.ok, true);

    const { file } = tmpEnv(LIVE_ENV);
    assert.equal(runPlan(file, plan.writes, null).ok, true);
    assert.equal(readEnvFile(file).values.ENTRA_CLIENT_SECRET, 'abc');
  });

  it('trimming mangles nothing, because parseEnv trims on READ anyway', () => {
    // The old reasoning for not trimming was that a secret may contain unusual
    // characters. Surrounding whitespace could never have survived the round
    // trip, so keeping it only stored bytes nothing would read back.
    assert.equal(parseEnv('ENTRA_CLIENT_SECRET=  abc  \n').ENTRA_CLIENT_SECRET, 'abc');
  });

  it('interior punctuation and unusual characters are left alone', () => {
    const odd = 'aB3~._-Q9ZxP8::;,=+/|&%$#@!';
    const input = R.normaliseEntraInput({ tenantId: TENANT_B, clientId: CLIENT_A, clientSecret: odd });
    assert.equal(input.clientSecret, odd);
    const { file } = tmpEnv(LIVE_ENV);
    const plan = R.planEntraWrite(input, { storedSecret: true });
    assert.equal(runPlan(file, plan.writes, null).ok, true);
    assert.equal(readEnvFile(file).values.ENTRA_CLIENT_SECRET, odd);
  });

  it('⛔ A WHOLLY-WHITESPACE SECRET IS REFUSED, NEVER READ AS "remove it"', () => {
    const input = R.normaliseEntraInput({ tenantId: TENANT_B, clientId: CLIENT_A, clientSecret: '   \n ' });
    assert.equal(input.blankedByTrim, true);
    const plan = R.planEntraWrite(input, { storedSecret: true });
    assert.equal(plan.ok, false);
    assert.equal(plan.status, 400);
    assert.match(plan.error, /has NOT been changed/);
    // ⛔ And it is NOT mistaken for the disable instruction.
    assert.notEqual(plan.disabling, true);
  });

  it('an INTERIOR line break is refused before any write starts', () => {
    const input = R.normaliseEntraInput({ tenantId: TENANT_B, clientId: CLIENT_A, clientSecret: 'ab\ncd' });
    const plan = R.planEntraWrite(input, { storedSecret: true });
    assert.equal(plan.ok, false);
    assert.match(plan.error, /line break/);
    // The sequence never starts, so a value that was never writable cannot
    // take the feature down on its way to being refused.
    assert.equal(plan.writes, undefined);
  });

  it('an explicit empty string stays an empty string — trimming must not create one', () => {
    const input = R.normaliseEntraInput({ tenantId: '', clientId: '', clientSecret: '' });
    assert.equal(input.clientSecret, '');
    assert.equal(input.blankedByTrim, false, 'an already-empty value was not blanked BY the trim');
  });

  it('a non-string secret is `undefined` (keep), never coerced', () => {
    for (const v of [null, 0, false, {}, []]) {
      assert.equal(R.normaliseEntraInput({ clientSecret: v }).clientSecret, undefined);
    }
  });
});

// ── "we could not measure this" ─────────────────────────────────────────────

describe('⛔ a failed read must never be recorded as an affirmative value', () => {
  it('an UNREADABLE env file throws out of readEnvFile — the contract the route refuses on', () => {
    const missing = path.join(os.tmpdir(), 'secvault-entra-does-not-exist', '.env.local');
    assert.throws(() => readEnvFile(missing));
    // ⛔ And setEnvValue turns that into {ok:false}, not an exception and not a
    // success — so a write against a file of unknown contents cannot happen.
    const r = setEnvValue(missing, 'ENTRA_TENANT_ID', TENANT_A);
    assert.equal(r.ok, false);
    assert.match(r.error, /Could not read/);
  });

  it('an UNWRITABLE env file fails the first write and leaves the configuration intact', () => {
    const { file } = tmpEnv(LIVE_ENV);
    const before = fs.readFileSync(file, 'utf8');
    fs.chmodSync(file, 0o444);
    const plan = R.planEntraWrite(
      R.normaliseEntraInput({ tenantId: TENANT_B, clientId: CLIENT_A, clientSecret: 'new' }),
      { storedSecret: true }
    );
    const out = runPlan(file, plan.writes, null);
    fs.chmodSync(file, 0o600);
    if (out.ok) {
      // Running as root (or on a filesystem ignoring the mode) the write
      // succeeds, and asserting a refusal would then be asserting a property
      // of the test machine. Say so rather than passing quietly.
      assert.ok(
        process.getuid && process.getuid() === 0,
        'a read-only .env.local was written by a non-root user — the mode was not honoured'
      );
      return;
    }
    assert.equal(out.ok, false);
    assert.deepEqual(out.landed, []);
    assert.equal(fs.readFileSync(file, 'utf8'), before);
    const answer = R.entraWriteFailureAnswer(out);
    assert.equal(answer.nothingChanged, true);
    assert.equal(answer.ssoDisabled, false);
  });

  it('an unreadable activity log is `unknown`, which is NOT an all-clear', () => {
    const a = R.entraRefusalAnswer(undefined, true);
    assert.equal(a.refusalState, 'unknown');
    assert.notEqual(a.refusalState, 'none');
  });

  it('a non-array row set is empty, never undefined-shaped', () => {
    assert.deepEqual(R.entraRefusalAnswer(null, false).refusals, []);
    assert.equal(R.entraRefusalAnswer(null, false).refusalState, 'none');
  });

  it('every key the failure report names has a human label', () => {
    for (const key of ['ENTRA_TENANT_ID', 'ENTRA_CLIENT_ID', 'ENTRA_CLIENT_SECRET']) {
      assert.equal(typeof R.ENTRA_FIELD_LABELS[key], 'string');
      assert.ok(R.ENTRA_FIELD_LABELS[key].length > 0);
    }
  });
});

// ── the sweep's expectation for this route ──────────────────────────────────

describe('⛔ /api/system/entra is manage_users, so an `admin` session must be DENIED it', () => {
  // scripts/apiSweep.js assumed its account was a super_admin, so a 403 was
  // always a failure. Its credentials then became a dedicated `secvault-smoke`
  // account with role `admin`, and this route — plus /api/users,
  // /api/ldap-mappings and /api/credential-profiles — started answering 403
  // CORRECTLY and being counted as broken. Four false failures is worse than a
  // gap: the output stops being read.
  const { authedVerdict, capabilitiesForRole, heldCapabilities } = require('../scripts/apiSweep');
  const { MANAGE_USERS, MANAGE_SETTINGS } = require('../lib/rbac');

  const check = { path: '/api/system/entra', capability: MANAGE_USERS };
  const admin = { role: 'admin', capabilities: capabilitiesForRole('admin') };
  const json = (status, body) => ({
    status, contentType: 'application/json', location: null,
    bytes: Buffer.byteLength(body), head: body.slice(0, 8), body,
  });
  const denial = JSON.stringify({ error: 'Forbidden', required: MANAGE_USERS });

  it('an `admin` really does lack manage_users, which is what makes this coverage', () => {
    assert.equal(admin.capabilities.includes(MANAGE_USERS), false);
    assert.equal(admin.capabilities.includes(MANAGE_SETTINGS), true);
  });

  it('a correct 403 for an `admin` is a PASS, and the assertion is counted', () => {
    const v = authedVerdict(check, json(403, denial), admin);
    assert.equal(v.ok, true, v.reason);
    assert.ok(v.checks.includes('capability-gate-fires'));
  });

  it('⛔ A 200 THERE IS A LOUD FAILURE — the denial direction, finally testable', () => {
    const v = authedVerdict(check, json(200, '{"tenantId":""}'), admin);
    assert.equal(v.ok, false);
    assert.match(v.reason, /does NOT hold "manage_users"/);
    assert.match(v.reason, /gate did not fire/);
  });

  it('a capability the session DOES hold must not be denied', () => {
    const settings = { path: '/api/settings', capability: MANAGE_SETTINGS };
    assert.equal(authedVerdict(settings, json(200, '{}'), admin).ok, true);
    const denied = authedVerdict(settings, json(403, JSON.stringify({ error: 'Forbidden', required: MANAGE_SETTINGS })), admin);
    assert.equal(denied.ok, false, 'a route denying a capability the session holds is a mistyped constant');
    assert.match(denied.reason, /holds that capability/);
  });

  it('⛔ AN UNKNOWN ROLE ASSUMES EVERYTHING, NEVER NOTHING', () => {
    // Reading a failed session lookup as an account with no capabilities would
    // make every gated route expect a 403 and report the whole product broken.
    assert.equal(capabilitiesForRole('no-such-role'), null);
    assert.equal(capabilitiesForRole('constructor'), null, 'prototype keys must not resolve');
    assert.equal(heldCapabilities({ role: 'no-such-role', capabilities: null }), null);
    assert.equal(heldCapabilities(null), null);
    // With an unknown role the old behaviour is restored exactly: a 403 fails.
    assert.equal(authedVerdict(check, json(403, denial), null).ok, false);
    assert.equal(authedVerdict(check, json(200, '{}'), null).ok, true);
  });
});

// ── the write-only contract ─────────────────────────────────────────────────

describe('⛔ the client secret is WRITE-ONLY and must never travel to the browser', () => {
  it('no response-shaping function here returns a secret value', () => {
    const secret = 'a-secret-nobody-should-see';
    const plan = R.planEntraWrite(
      R.normaliseEntraInput({ tenantId: TENANT_B, clientId: CLIENT_A, clientSecret: secret }),
      { storedSecret: true }
    );
    // The plan carries it, because the plan is what performs the write — but
    // nothing derived from it for a RESPONSE may.
    const out = R.applyEntraWrites(plan.writes, () => ({ ok: true, previous: secret, unchanged: false }));
    assert.doesNotMatch(JSON.stringify(out), new RegExp(secret));

    const failure = R.entraWriteFailureAnswer({
      failedKey: 'ENTRA_CLIENT_ID',
      error: 'refused',
      landed: ['ENTRA_TENANT_ID', 'ENTRA_CLIENT_SECRET'],
      backupPath: null,
    });
    assert.doesNotMatch(JSON.stringify(failure), new RegExp(secret));
  });

  it('⛔ setEnvValue\'s `previous` IS the old secret, which is why it is not echoed', () => {
    // The console-address route returns `previous` to the client. Copying that
    // here would put the OLD SECRET in an HTTP response body. Pinned so the
    // reason is not lost: this is the value that must not be forwarded.
    const { file } = tmpEnv(LIVE_ENV);
    const r = setEnvValue(file, 'ENTRA_CLIENT_SECRET', 'replacement');
    assert.equal(r.ok, true);
    assert.equal(r.previous, 'old-secret-value');

    const src = fs.readFileSync(ROUTE_PATH, 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/(^|[\s{(;,])\/\/[^\n]*/g, '$1 ');
    // ⛔ THE PROPERTY, NOT THE WORD. This route's prose legitimately says "the
    // previous configuration is intact"; what must never appear is a READ of
    // the field, which is the old secret.
    assert.doesNotMatch(src, /\.previous\b/, 'the Entra route must not read setEnvValue\'s `previous`');
    assert.doesNotMatch(src, /\bprevious\s*:/, 'the Entra route must not return a `previous` field');
  });
});
