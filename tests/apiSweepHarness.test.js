'use strict';
// tests/apiSweepHarness.test.js
//
// ⛔ THE SWEEP ITSELF NEEDS A TEST, BECAUSE A LIVE RUN ONLY EVER EXERCISES THE
// GREEN PATH. `npm run apisweep` reported 375/375 against production the second
// time it was pointed at it — which tells you nothing about whether it can go
// red. The failing path is the entire point of the harness and it is the one a
// healthy fleet never reaches. Same reasoning as tests/smokeHarness.test.js,
// whose header says so first.
//
// So the verdict logic is pure and gets fed synthetic responses here: an empty
// 500 (the exact shape a real defect produced on the first live run), a 200 that
// should have been a 401, a 403 that names no capability, and a 200
// application/pdf of eleven bytes.
//
// This file does NOT talk to a server. scripts/apiSweep.js only sweeps when it
// is run directly (`require.main === module`).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const {
  API_ROUTES,
  READ_CHECKS,
  REPORT_PARAM_CASES,
  MATCHER_PROBES,
  NON_MUTATING_POSTS,
  UNKNOWN_UUID,
  anonVerdict,
  authedVerdict,
  capture,
  capabilityNamedIn,
  assertSafeChecks,
  assertRouteTableComplete,
  listRouteFiles,
  reportChecks,
  resolvePath,
  routeFor,
} = require('../scripts/apiSweep');
const { ALL_CAPABILITIES, OPERATE, MANAGE_USERS } = require('../lib/rbac');
const { REPORTS } = require('../lib/reports/catalogue');

const REPO_ROOT = path.join(__dirname, '..');

/** A response as capture() builds it, with sane defaults per field. */
function res(over = {}) {
  const body = over.body === undefined ? '{"ok":true}' : over.body;
  return {
    status: 200,
    contentType: 'application/json',
    location: null,
    bytes: Buffer.byteLength(String(body || '')),
    head: String(body || '').slice(0, 8),
    ...over,
    body,
  };
}

const pdf = (bytes) => res({
  contentType: 'application/pdf',
  body: '',
  bytes,
  head: '%PDF-1.3',
});

// ─────────────────────────────────────────────────────────────────────────────

describe('⛔ a 500 is always a failure, and its body always reaches the report', () => {
  it('a JSON 500 fails and the reason carries the message', () => {
    const v = authedVerdict({ path: '/api/x' }, res({ status: 500, body: '{"error":"the compliance query failed"}' }));
    assert.equal(v.ok, false);
    assert.match(v.reason, /HTTP 500/);
    assert.match(v.reason, /the compliance query failed/, 'the body is the only diagnostic a production build gives');
  });

  it('⛔ AN EMPTY 500 IS NAMED AS NEXT\'S UNCAUGHT-THROW SHAPE — the live defect', () => {
    // This is verbatim what GET /api/system/console-url returned on the first
    // live run: status 500, no content-type, zero bytes. A reason of "HTTP 500"
    // alone would have sent someone looking for a message that does not exist.
    const v = authedVerdict({ path: '/api/system/console-url' }, res({ status: 500, contentType: '', body: '' }));
    assert.equal(v.ok, false);
    assert.match(v.reason, /EMPTY 500/);
    assert.match(v.reason, /app-error\.log/, 'the reason must say where the stack actually is');
  });

  it('a 503 fails too — it is not only 500 that is a server error', () => {
    assert.equal(authedVerdict({ path: '/api/x' }, res({ status: 503, body: '{}' })).ok, false);
  });

  it('and no check may DECLARE a 500 acceptable', () => {
    assert.throws(() => assertSafeChecks([{ path: '/api/x', expect: [200, 500] }], []), /never an acceptable answer/);
  });

  it('⛔ but a 504 is NOT a server error — a timed-out log search is an honest answer', () => {
    // logSearch.js returns timedOut:true with a reason rather than rows:[], and
    // the route wraps that in a 504. Treating it as a crash would make the
    // product's most careful refusal look like a bug.
    const v = authedVerdict({ path: '/api/logs/search', expect: [200, 504] }, res({ status: 504, body: '{"timedOut":true,"reason":"x"}' }));
    assert.equal(v.ok, true);
  });
});

describe('⛔ capture() keeps the whole body — the one defect this sweep has had', () => {
  // ⛔ THIS SUITE EXISTS BECAUSE A MUTATION ESCAPED. Re-introducing the 4 KB
  // slice capture() shipped with changed nothing in this file, because every
  // other test builds its own `observed` object. The sweep was confidently
  // wrong about eight healthy routes and the harness could not see it. So this
  // drives capture() through a real Response and asserts by BEHAVIOUR.

  it('a 60 KB JSON response arrives whole and passes the verdict', async () => {
    const big = JSON.stringify({ applications: Array.from({ length: 3000 }, (_, i) => ({ id: String(i) })) });
    assert.ok(big.length > 40000, 'the fixture has to be past any plausible slice point');
    const obs = await capture(new Response(big, { status: 200, headers: { 'content-type': 'application/json' } }));
    assert.equal(obs.body.length, big.length, 'the body must not be truncated before it is judged');
    assert.equal(obs.bytes, Buffer.byteLength(big));
    assert.equal(authedVerdict({ path: '/api/applications' }, obs).ok, true);
  });

  it('a binary body keeps its length and first bytes but not its content', async () => {
    const buf = Buffer.concat([Buffer.from('%PDF-1.7\n'), Buffer.alloc(40000, 0x41)]);
    const obs = await capture(new Response(buf, { status: 200, headers: { 'content-type': 'application/pdf' } }));
    assert.equal(obs.body, '', 'a PDF must not be decoded as text');
    assert.equal(obs.bytes, buf.length);
    assert.equal(obs.head, '%PDF-1.7');
    assert.equal(authedVerdict({ path: '/api/reports/x/pdf', type: 'pdf' }, obs).ok, true);
  });

  it('status, content-type and location all survive', async () => {
    const obs = await capture(new Response('', { status: 307, headers: { location: '/login' } }));
    assert.equal(obs.status, 307);
    assert.equal(obs.location, '/login');
    assert.equal(obs.bytes, 0);
    assert.equal(anonVerdict({ path: '/api/settings' }, obs).ok, false);
  });

  it('an empty 500 with no content-type captures as the live defect did', async () => {
    const obs = await capture(new Response(null, { status: 500 }));
    assert.equal(obs.status, 500);
    assert.equal(obs.body, '');
    const v = authedVerdict({ path: '/api/system/console-url' }, obs);
    assert.equal(v.ok, false);
    assert.match(v.reason, /EMPTY 500/);
  });
});

describe('⛔ a 200 must be the body the caller can actually use', () => {
  it('unparseable JSON fails, and the reason quotes what came back', () => {
    const v = authedVerdict({ path: '/api/x' }, res({ body: '<html>Internal Server Error</html>' }));
    assert.equal(v.ok, false);
    assert.match(v.reason, /not parseable JSON/);
    assert.match(v.reason, /Internal Server Error/);
  });

  it('an empty 200 body fails rather than counting as success', () => {
    const v = authedVerdict({ path: '/api/x' }, res({ body: '' }));
    assert.equal(v.ok, false);
    assert.match(v.reason, /\(empty\)/);
  });

  it('a JSON scalar fails — a route must answer an object or an array', () => {
    assert.equal(authedVerdict({ path: '/api/x' }, res({ body: '42' })).ok, false);
    assert.equal(authedVerdict({ path: '/api/x' }, res({ body: 'null' })).ok, false);
  });

  it('a bare array passes — GET /api/devices really answers one', () => {
    assert.equal(authedVerdict({ path: '/api/devices' }, res({ body: '[{"id":"a"}]' })).ok, true);
  });

  it('⛔ A BODY LARGER THAN 4 KB PASSES. The first draft of capture() sliced to '
    + '4,000 chars before the verdict saw it, so eight healthy routes were '
    + 'reported broken — the harness truncating its own evidence and then '
    + 'judging it. /api/applications answers 1.1 MB live.', () => {
    const big = `{"applications":[${Array.from({ length: 4000 }, (_, i) => `{"id":"${i}"}`).join(',')}]}`;
    assert.ok(big.length > 40000, 'the fixture has to be past any plausible slice point');
    assert.equal(authedVerdict({ path: '/api/applications' }, res({ body: big })).ok, true);
  });

  it('⛔ a 400 or 404 is asserted to be JSON too', () => {
    // Every refusal in this product carries a sentence saying what to do next.
    // A bare status with an HTML body is a refusal the UI cannot render.
    const v = authedVerdict({ path: '/api/x', expect: [404] }, res({ status: 404, contentType: 'text/html', body: '<html>404</html>' }));
    assert.equal(v.ok, false);
    assert.match(v.reason, /not parseable JSON/);
    assert.equal(authedVerdict({ path: '/api/x', expect: [404] }, res({ status: 404, body: '{"error":"Job not found"}' })).ok, true);
  });

  it('an unexpected status fails and the reason states what was expected', () => {
    const v = authedVerdict({ path: '/api/x', expect: [404] }, res({ status: 200 }));
    assert.equal(v.ok, false);
    assert.match(v.reason, /HTTP 200, expected 404/);
  });
});

describe('⛔ a PDF route must return a document, not a content-type', () => {
  it('a good PDF passes', () => {
    assert.equal(authedVerdict({ path: '/api/reports/x/pdf', type: 'pdf' }, pdf(30000)).ok, true);
  });

  it('⛔ a 200 application/pdf of 11 bytes FAILS — someone would file it', () => {
    const v = authedVerdict({ path: '/api/reports/x/pdf', type: 'pdf' }, pdf(11));
    assert.equal(v.ok, false);
    assert.match(v.reason, /only 11 bytes/);
  });

  it('a JSON body served as application/pdf fails on the magic bytes', () => {
    const v = authedVerdict(
      { path: '/api/reports/x/pdf', type: 'pdf' },
      res({ status: 200, contentType: 'application/pdf', body: '', bytes: 50000, head: '{"error"' })
    );
    assert.equal(v.ok, false);
    assert.match(v.reason, /not "%PDF"/);
  });

  it('a PDF route answering text/html fails on the content type', () => {
    const v = authedVerdict(
      { path: '/api/reports/x/pdf', type: 'pdf' },
      res({ status: 200, contentType: 'text/html', body: 'x'.repeat(5000) })
    );
    assert.equal(v.ok, false);
    assert.match(v.reason, /not application\/pdf/);
  });
});

describe('⛔ the 403 shape — what CAN be asserted without a second account', () => {
  it('a 403 naming no capability at all FAILS', () => {
    const v = authedVerdict({ path: '/api/users' }, res({ status: 403, body: '{"error":"Forbidden"}' }));
    assert.equal(v.ok, false);
    assert.match(v.reason, /does not name a capability/);
  });

  it('a 403 naming an INVENTED capability counts as naming none', () => {
    // `required: "adminish"` would satisfy a "is the field present" check while
    // naming an authority lib/rbac.js does not recognise — which is exactly
    // what a mistyped constant produces, since can() denies any string it does
    // not know.
    const v = authedVerdict({ path: '/api/users' }, res({ status: 403, body: '{"error":"Forbidden","required":"adminish"}' }));
    assert.equal(v.ok, false);
    assert.match(v.reason, /does not name a capability/);
  });

  it('a well-formed 403 on a route that should have allowed it fails with the RIGHT reason', () => {
    // The sweep signs in as super_admin, which holds every capability, so a 403
    // can only mean the route is gating on something can() will not grant.
    const v = authedVerdict({ path: '/api/users' }, res({
      status: 403,
      body: JSON.stringify({ error: `Forbidden — this action requires the "${MANAGE_USERS}" permission`, required: MANAGE_USERS }),
    }));
    assert.equal(v.ok, false);
    assert.match(v.reason, /holds every capability/);
    assert.match(v.reason, new RegExp(MANAGE_USERS));
  });

  it('and a 403 that WAS expected passes, provided it named the capability', () => {
    const ok = authedVerdict({ path: '/api/users', expect: [403] }, res({
      status: 403, body: JSON.stringify({ error: 'x', required: MANAGE_USERS }),
    }));
    assert.equal(ok.ok, true);
    const bad = authedVerdict({ path: '/api/users', expect: [403] }, res({ status: 403, body: '{"error":"nope"}' }));
    assert.equal(bad.ok, false, 'expecting a 403 must not excuse an unnamed one');
  });

  it('capabilityNamedIn reads `required`, falls back to the prose, and refuses anything else', () => {
    assert.equal(capabilityNamedIn(JSON.stringify({ required: OPERATE })), OPERATE);
    assert.equal(capabilityNamedIn(JSON.stringify({ error: `requires the "${OPERATE}" permission` })), OPERATE);
    assert.equal(capabilityNamedIn('{"required":""}'), null);
    assert.equal(capabilityNamedIn('{"required":"operator"}'), null, 'a ROLE is not a capability');
    assert.equal(capabilityNamedIn('not json'), null);
    assert.equal(capabilityNamedIn('[]'), null);
    assert.equal(capabilityNamedIn(''), null);
  });

  it('every capability lib/rbac.js exports is recognisable in a 403 body', () => {
    for (const cap of ALL_CAPABILITIES) {
      assert.equal(capabilityNamedIn(JSON.stringify({ required: cap })), cap);
    }
  });
});

describe('⛔ the unauthenticated contract: 401, and never a redirect', () => {
  const route = { path: '/api/settings' };

  it('401 passes', () => {
    assert.equal(anonVerdict(route, res({ status: 401, body: '{"error":"Unauthorized"}' })).ok, true);
  });

  it('⛔ 200 WITH NO COOKIE is reported as reachable unauthenticated', () => {
    const v = anonVerdict(route, res({ status: 200 }));
    assert.equal(v.ok, false);
    assert.match(v.reason, /reachable unauthenticated/);
  });

  it('⛔ a 307 to /login is its own failure, not just a wrong number', () => {
    // fetch() follows it and the caller then parses an HTML login page as
    // JSON, so the symptom surfaces nowhere near the cause.
    const v = anonVerdict(route, res({ status: 307, location: 'https://host/login', body: '' }));
    assert.equal(v.ok, false);
    assert.match(v.reason, /redirected to https:\/\/host\/login/);
    assert.match(v.reason, /not redirect/);
    for (const s of [301, 302, 308]) {
      assert.equal(anonVerdict(route, res({ status: s, location: '/login', body: '' })).ok, false);
    }
  });

  it('any other status fails and says what was wanted', () => {
    const v = anonVerdict(route, res({ status: 403, body: '{}' }));
    assert.equal(v.ok, false);
    assert.match(v.reason, /expected 401/);
  });

  it('the one public prefix is asserted the other way round', () => {
    // /api/auth/csrf must stay public or nobody can sign in at all — so a 401
    // there is the failure, and a 200 is the pass.
    const pub = { path: '/api/auth/{...nextauth}', public: true, anonPath: '/api/auth/csrf', anonExpect: [200] };
    assert.equal(anonVerdict(pub, res({ status: 200, body: '{"csrfToken":"x"}' })).ok, true);
    assert.equal(anonVerdict(pub, res({ status: 401, body: '{}' })).ok, false);
  });
});

describe('⛔ the tables cannot be made dangerous by an edit', () => {
  it('the shipping tables pass their own guard', () => {
    assert.ok(assertSafeChecks([...READ_CHECKS, ...reportChecks(REPORTS), ...REPORT_PARAM_CASES], API_ROUTES));
  });

  it('a PUT, DELETE or PATCH is refused outright', () => {
    for (const method of ['PUT', 'DELETE', 'PATCH']) {
      assert.throws(
        () => assertSafeChecks([{ path: '/api/devices/{device}', method }], []),
        /non-mutating allow-list/,
        `${method} must be refused`
      );
    }
  });

  it('⛔ even an allow-listed compute route may only be POSTed', () => {
    assert.throws(
      () => assertSafeChecks([{ path: '/api/topology/path-query', method: 'DELETE' }], []),
      /may only be POSTed/
    );
  });

  it('a POST to anything NOT on the allow-list is refused', () => {
    assert.throws(
      () => assertSafeChecks([{ path: '/api/devices/{device}/collect', method: 'POST' }], []),
      /may only call routes that persist nothing/
    );
    assert.throws(
      () => assertSafeChecks([{ path: '/api/feeds/sync', method: 'POST' }], []),
      /may only call routes that persist nothing/
    );
  });

  it('and the two that ARE allow-listed are accepted', () => {
    assert.ok(assertSafeChecks([
      { path: '/api/devices/{device}/access-path', method: 'POST' },
      { path: '/api/topology/path-query', method: 'POST' },
    ], []));
    assert.equal(NON_MUTATING_POSTS.size, 2, 'widening this set is a decision, not a tweak');
  });

  it('the allow-list is matched on the path, so a query string cannot smuggle one past', () => {
    assert.throws(
      () => assertSafeChecks([{ path: '/api/devices/{device}/collect?x=/api/topology/path-query', method: 'POST' }], []),
      /non-mutating allow-list/
    );
  });

  it('an empty or missing expect list is refused', () => {
    assert.throws(() => assertSafeChecks([{ path: '/api/x', expect: [] }], []), /non-empty list/);
  });

  it('a non-/api path is refused — pages belong to scripts/smoke.js', () => {
    assert.throws(() => assertSafeChecks([{ path: '/devices' }], []), /covers \/api only/);
  });

  it('⛔ a route entry expecting anything but 401 unauthenticated is refused unless public', () => {
    assert.throws(
      () => assertSafeChecks([], [{ path: '/api/health', capability: null, anonExpect: [200] }]),
      /must answer 401/
    );
    assert.ok(assertSafeChecks([], [{ path: '/api/auth/{...nextauth}', capability: null, public: true, anonExpect: [200] }]));
  });

  it('a capability lib/rbac.js does not know is refused in the route table', () => {
    assert.throws(
      () => assertSafeChecks([], [{ path: '/api/x', capability: 'adminish' }]),
      /not a capability/
    );
  });
});

describe('⛔ the route table cannot drift from app/api', () => {
  it('it matches the filesystem RIGHT NOW', () => {
    // This is the assertion that makes the sweep's auth coverage a fact rather
    // than a claim: a route added without an entry gets no 401 assertion at
    // all, and the sweep would then print a clean pass over an ungated route.
    assert.ok(assertRouteTableComplete(listRouteFiles(REPO_ROOT), API_ROUTES));
  });

  it('and it would catch a route file with no entry', () => {
    assert.throws(
      () => assertRouteTableComplete(['/api/health', '/api/brand-new'], [{ path: '/api/health', capability: null }]),
      /not in API_ROUTES: \/api\/brand-new/
    );
  });

  it('and an entry whose route file is gone', () => {
    assert.throws(
      () => assertRouteTableComplete(['/api/health'], [
        { path: '/api/health', capability: null },
        { path: '/api/deleted', capability: null },
      ]),
      /no route file: \/api\/deleted/
    );
  });

  it('listRouteFiles converts [param] to {param} so the comparison is mechanical', () => {
    const files = listRouteFiles(REPO_ROOT);
    assert.ok(files.includes('/api/devices/{id}/rules'), 'bracket params must normalise');
    assert.ok(files.includes('/api/auth/{...nextauth}'), 'the catch-all must normalise too');
    assert.ok(files.length >= 80, `only ${files.length} route files found`);
  });

  it('every route entry declares its verbs, and every declared verb is real', () => {
    for (const r of API_ROUTES) {
      assert.ok(Array.isArray(r.methods) && r.methods.length > 0, `${r.path} declares no methods`);
      for (const m of r.methods) {
        assert.ok(['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].includes(m), `${r.path}: ${m}`);
      }
    }
  });
});

describe('⛔ every check points at a route that exists', () => {
  it('routeFor resolves each shipping check', () => {
    // A mistyped path in a check that expects a 404 would otherwise PASS, for
    // the wrong reason, for ever.
    const all = [...READ_CHECKS, ...reportChecks(REPORTS), ...REPORT_PARAM_CASES];
    const orphans = all.map((c) => c.path).filter((p) => !routeFor(p, API_ROUTES));
    assert.deepEqual(orphans, []);
  });

  it('⛔ but a MATCHER probe is allowed to point at nothing — that is its job', () => {
    // /api/HEALTH deliberately matches no route: it is the evidence that
    // middleware answers before routing resolves, which is what the header's
    // "this cannot tell gated from not-deployed" caveat rests on. The probes
    // that must stay PUBLIC, though, have to be real endpoints.
    const unrouted = MATCHER_PROBES.filter((p) => !routeFor(p.path, API_ROUTES));
    assert.ok(unrouted.length >= 1, 'at least one probe must target no route at all');
    for (const p of unrouted) assert.deepEqual(p.expect, [401], `${p.path} must still be gated`);
    for (const p of MATCHER_PROBES.filter((x) => x.expect.includes(200))) {
      assert.ok(routeFor(p.path, API_ROUTES), `${p.path} must be a real endpoint`);
    }
  });

  it('and it would catch one that does not', () => {
    assert.equal(routeFor('/api/jobsss/abc', API_ROUTES), null);
    assert.equal(routeFor('/api/devices/{id}/nope', API_ROUTES), null);
  });

  it('a token matches one segment, and the catch-all matches the rest', () => {
    assert.equal(routeFor('/api/devices/abc/rules?limit=5', API_ROUTES).path, '/api/devices/{id}/rules');
    assert.equal(routeFor('/api/auth/csrf', API_ROUTES).path, '/api/auth/{...nextauth}');
    assert.equal(routeFor('/api/auth/callback/local', API_ROUTES).path, '/api/auth/{...nextauth}');
  });
});

describe('⛔ report checks are DERIVED from the catalogue, so a new report cannot be unswept', () => {
  const derived = reportChecks(REPORTS);

  it('every catalogue entry produces at least one check', () => {
    for (const entry of REPORTS) {
      assert.ok(derived.some((c) => c.key.startsWith(`report:${entry.id}`)), `${entry.id} has no check`);
    }
  });

  it('an entity-scoped report is covered by its two refusals and no happy path', () => {
    // No entity is created, because creating one is a mutation. What is
    // asserted is the whole contract the route has before its builder runs.
    const entity = REPORTS.find((r) => r.scope === 'entity');
    assert.ok(entity, 'the catalogue still has an entity-scoped report');
    const mine = derived.filter((c) => c.key.startsWith(`report:${entity.id}`));
    assert.deepEqual(mine.map((c) => c.expect[0]).sort(), [400, 404]);
    assert.ok(mine.every((c) => c.type !== 'pdf'));
  });

  it('⛔ every optionalDevice report is ALSO checked against a Fortinet', () => {
    // The defect this whole file exists for answered 500 for Fortinet devices
    // only, because the per-device branch got a shape the fleet branch never
    // produced.
    for (const entry of REPORTS.filter((r) => r.optionalDevice)) {
      const fort = derived.find((c) => c.key === `report:${entry.id}:fortinet`);
      assert.ok(fort, `${entry.id} has no Fortinet-scoped check`);
      assert.match(fort.path, /deviceId=\{fortinet\}/);
      assert.equal(fort.type, 'pdf');
    }
  });

  it('a declared choice param is exercised with a real allowed value', () => {
    const withChoices = REPORTS.find((r) => (r.params || []).some((p) => Array.isArray(p.choices) && p.choices.length));
    const p = withChoices.params.find((x) => Array.isArray(x.choices) && x.choices.length);
    const check = derived.find((c) => c.key === `report:${withChoices.id}`);
    assert.match(check.path, new RegExp(`${p.key}=${p.choices[0].value}`));
  });

  it('a range param is exercised with both ends', () => {
    const withRange = REPORTS.find((r) => (r.params || []).some((p) => p.kind === 'range'));
    const check = derived.find((c) => c.key === `report:${withRange.id}`);
    assert.match(check.path, /from=\{windowFrom\}/);
    assert.match(check.path, /to=\{windowTo\}/);
  });

  it('the derived checks carry the catalogue\'s own capability, not a guess', () => {
    const identity = REPORTS.find((r) => r.capability === 'view_identity');
    assert.ok(identity, 'the VPN access review still declares view_identity');
    assert.equal(derived.find((c) => c.key === `report:${identity.id}`).capability, 'view_identity');
  });
});

describe('⛔ an unresolvable fixture is reported, never substituted', () => {
  it('a missing token is named rather than sent as a literal', () => {
    // Sending `/api/devices/{fortinet}/vpn` would 404 and be reported as a
    // broken route, when the truth is "this fleet has no Fortinet".
    const r = resolvePath('/api/devices/{fortinet}/vpn', {});
    assert.deepEqual(r.missing, ['fortinet']);
    assert.match(r.path, /\{fortinet\}/, 'left unsent, not guessed');
  });

  it('every missing token is listed, not just the first', () => {
    assert.deepEqual(
      resolvePath('/api/devices/{a}/backups/{b}', {}).missing,
      ['a', 'b']
    );
  });

  it('an empty string is missing, not a value', () => {
    assert.deepEqual(resolvePath('/api/devices/{device}', { device: '' }).missing, ['device']);
  });

  it('a resolved token is url-encoded', () => {
    const r = resolvePath('/api/advisories/{cveId}/conditions', { cveId: 'CVE-2026-1 x' });
    assert.deepEqual(r.missing, []);
    assert.equal(r.path, '/api/advisories/CVE-2026-1%20x/conditions');
  });

  it('the unknown-id fixture is a well-formed uuid that cannot exist', () => {
    assert.match(UNKNOWN_UUID, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });
});

describe('⛔ coverage of the table itself', () => {
  it('every /api route file has an auth assertion', () => {
    assert.equal(API_ROUTES.length, listRouteFiles(REPO_ROOT).length);
    assert.ok(API_ROUTES.length >= 80, `only ${API_ROUTES.length} routes listed`);
  });

  it('the documented parameter refusals are all present', () => {
    const paths = REPORT_PARAM_CASES.map((c) => c.path).join(' ');
    assert.match(paths, /no-such-report/, 'a bad report id');
    assert.match(paths, /deviceId=not-a-uuid/, 'a malformed deviceId');
    assert.match(paths, /compliance-fleet\/pdf\?deviceId=/, 'a deviceId on a report that cannot narrow');
    assert.match(paths, /standard=BOGUS/, 'an out-of-allow-list param value');
    assert.match(paths, /from=notadate/, 'a bad date');
    assert.ok(REPORT_PARAM_CASES.every((c) => c.expect[0] === 400 || c.expect[0] === 404));
    assert.ok(REPORT_PARAM_CASES.every((c) => typeof c.why === 'string' && c.why.length > 10),
      'a refusal check must say which contract it pins');
  });

  it('the unknown-id reads all expect 404 — never a 500, never an empty 200', () => {
    const unknowns = READ_CHECKS.filter((c) => c.path.includes('{unknownUuid}'));
    assert.ok(unknowns.length >= 5, `only ${unknowns.length} unknown-id checks`);
    for (const c of unknowns) assert.deepEqual(c.expect, [404], c.path);
  });

  it('a Fortinet is exercised on the per-device read paths', () => {
    assert.ok(READ_CHECKS.filter((c) => c.path.includes('{fortinet}')).length >= 4);
  });

  it('the matcher probes cover both directions the matcher can be wrong in', () => {
    assert.ok(MATCHER_PROBES.some((p) => p.expect.includes(200)), 'a prefix that must stay public');
    assert.ok(MATCHER_PROBES.some((p) => p.expect.includes(401)), 'a prefix that must stay gated');
  });
});
