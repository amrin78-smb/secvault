'use strict';
// tests/deviceScopeEnforcement.test.js
//
// ⛔ MIDDLEWARE WAS NEVER THE BOUNDARY IT CLAIMED TO BE.
//
// middleware.js decides device-scope refusals from `token.deviceScoped`, and a
// comment beside it certified that the flag "is re-read from the database on
// every token use". The jwt() callback does re-read it — but middleware does
// not call jwt(). `getToken()` from next-auth/jwt only DECRYPTS the cookie
// (verified: zero references to `callbacks` in that package), so what
// middleware sees is whatever was written the last time NextAuth RE-ISSUED the
// cookie. With SESSION_IDLE_MINUTES=0 that window is NextAuth's own 30 days.
//
// The staleness is asymmetric and only one direction matters:
//
//   scope REVOKED, claim still true   -> refused a surface it may now use.
//   scope GRANTED, claim still false  -> SERVED THE WHOLE FLEET.
//
// So pages are decided AGAIN in app/(dashboard)/layout.js against a live read.
// The verdict itself is pure (`pageRefusal`) precisely so this file can test it
// by behaviour — a test that read the layout looking for the right words would
// pass over an if-block someone had commented out, which is the failure mode
// this repo has already shipped once.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  SCOPE_STATES,
  scopeAssignmentRefusal,
  scopesEmptiedByDeviceDeletion,
  loadScopeForSession,
} = require('../lib/deviceScope');
const {
  pageRefusal,
  surfaceToPattern,
  UNMAPPABLE_BLOCKED,
  PATHNAME_HEADER,
  blockedSurfaceFor,
} = require('../lib/deviceScopePaths');

const REPO = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(REPO, p), 'utf8');

// Strip comments before any wiring assertion. ⛔ A positive assertion that
// reads raw source is satisfied by a COMMENT containing the same words, which
// is how three deleted authorization gates once passed a green suite.
function code(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

// A blocked page and an aware one, taken from the live register rather than
// hardcoded, so this file cannot drift from the classification it tests.
const BLOCKED_PAGE = '/compliance';
const AWARE_PAGE = '/devices';

describe('pageRefusal — the authoritative page verdict', () => {
  it('the fixtures are what this file assumes they are', () => {
    assert.ok(blockedSurfaceFor(BLOCKED_PAGE), `${BLOCKED_PAGE} must be a blocked surface`);
    assert.equal(blockedSurfaceFor(AWARE_PAGE), null, `${AWARE_PAGE} must NOT be blocked`);
  });

  it('a SCOPED account is refused a blocked surface', () => {
    const v = pageRefusal(BLOCKED_PAGE, { state: SCOPE_STATES.SCOPED, deviceIds: ['x'] });
    assert.equal(v.refused, true);
    assert.equal(v.reason, 'scoped');
    assert.ok(v.surface, 'the refusing surface is named, so a redirect can explain itself');
  });

  it('an UNSCOPED account is refused nothing — every account today is unscoped', () => {
    assert.equal(pageRefusal(BLOCKED_PAGE, { state: SCOPE_STATES.UNSCOPED }).refused, false);
    assert.equal(pageRefusal(AWARE_PAGE, { state: SCOPE_STATES.UNSCOPED }).refused, false);
  });

  it('a scoped account still reaches the surfaces that ARE scope-aware', () => {
    assert.equal(pageRefusal(AWARE_PAGE, { state: SCOPE_STATES.SCOPED }).refused, false);
  });

  describe('⛔ everything that is not a clean allow denies', () => {
    // The whole design is default-deny; a state nobody recognised becoming a
    // third flavour of allow is how that erodes.
    for (const [label, scope] of [
      ['unknown (the scope read FAILED)', { state: SCOPE_STATES.UNKNOWN }],
      ['a null scope', null],
      ['an undefined scope', undefined],
      ['an empty object', {}],
      ['a state nobody recognises', { state: 'probably-fine' }],
      ['a state that is not a string', { state: 1 }],
    ]) {
      it(label, () => {
        const v = pageRefusal(BLOCKED_PAGE, scope);
        assert.equal(v.refused, true, `${label} must not be served a blocked surface`);
        assert.equal(v.reason, 'unknown');
      });
    }
  });

  describe('⛔ an unresolvable pathname refuses NOTHING, and that is not a fail-open', () => {
    // It means middleware did not run, so the matcher is broken. Refusing every
    // page would lock a scoped account out of /devices too — the only place it
    // can work — which is a self-inflicted outage in place of a boundary.
    for (const bad of [null, undefined, '', 'compliance', 42, {}]) {
      it(`${JSON.stringify(bad)} resolves nothing`, () => {
        const v = pageRefusal(bad, { state: SCOPE_STATES.SCOPED });
        assert.equal(v.refused, false);
        assert.equal(v.reason, 'no-pathname');
      });
    }
  });
});

describe('⛔ the layout is wired to the verdict, and middleware feeds it the path', () => {
  // Wiring only — the VERDICT is tested above, by behaviour. These two
  // assertions exist because the pure function is worth nothing uncalled, and
  // there is no render harness in this repo that could catch that.
  it('the dashboard layout calls pageRefusal with a live scope read', () => {
    const src = code(read('app/(dashboard)/layout.js'));
    assert.match(src, /pageRefusal\(/, 'the layout must call the verdict');
    assert.match(src, /loadScopeForSession\(/, 'and must read the scope from the database');
    assert.match(src, /redirect\(/, 'and must act on a refusal');
    assert.match(src, /headers\(\)\.get\(PATHNAME_HEADER\)/,
      'and must read the forwarded pathname — by the shared constant, so the layout and '
      + 'middleware cannot drift onto two different header names');
  });

  it('middleware forwards the pathname on the REQUEST headers', () => {
    const src = code(read('middleware.js'));
    assert.match(src, /PATHNAME_HEADER/, 'middleware must set the forwarding header');
    assert.match(src, /NextResponse\.next\(\{\s*request:/,
      'it must be set on the forwarded REQUEST — a response header would not reach a server '
      + 'component, and would be visible to the browser');
  });

  it('⛔ the header is OVERWRITTEN, never read from the client', () => {
    const src = code(read('middleware.js'));
    // `forwarded.set(...)` replaces any inbound copy. `.append` would let a
    // client prepend a harmless path and keep its real one.
    assert.match(src, /\.set\(PATHNAME_HEADER/, 'set(), not append()');
    assert.doesNotMatch(src, /\.append\(PATHNAME_HEADER/);
  });

  it('⛔ middleware no longer claims the token is re-read from the database', () => {
    // The comment that said so was false and sent a reader looking for a
    // freshness guarantee that did not exist.
    const src = read('middleware.js');
    assert.doesNotMatch(src, /re-read from the database on every\s*\n?\/\/\s*token use/,
      'the false freshness claim must not come back');
  });
});

describe('⛔ scopeAssignmentRefusal — an account that can manage users may not be scoped', () => {
  it('refuses a super_admin', () => {
    assert.ok(scopeAssignmentRefusal('super_admin', ['a-device']),
      'scoping the only account that can reach the un-scoping endpoint is unrecoverable');
  });

  it('⛔ allows an admin — decided on the CAPABILITY, not the word "admin"', () => {
    // `admin` does not hold manage_users. Matching the substring "admin" would
    // refuse the common case and make the feature useless.
    assert.equal(scopeAssignmentRefusal('admin', ['a-device']), null);
  });

  it('allows an operator', () => {
    assert.equal(scopeAssignmentRefusal('operator', ['a-device']), null);
  });

  it('⛔ CLEARING a scope is always allowed, for every role', () => {
    // Zero rows means unscoped, so clearing can only widen access — it can
    // never lock anyone out, including a super_admin.
    for (const role of ['super_admin', 'admin', 'operator', null, undefined]) {
      assert.equal(scopeAssignmentRefusal(role, []), null, String(role));
      assert.equal(scopeAssignmentRefusal(role, null), null, String(role));
    }
  });

  it('an unknown or missing role holds no capabilities, so it is scopable', () => {
    assert.equal(scopeAssignmentRefusal('viewer', ['a']), null);
    assert.equal(scopeAssignmentRefusal(null, ['a']), null);
  });
});

describe('⛔ scopesEmptiedByDeviceDeletion — deleting a firewall can WIDEN access', () => {
  // user_device_scopes.device_id is ON DELETE CASCADE and zero rows means
  // UNSCOPED, so removing the last firewall in an account's scope promotes that
  // account from "one firewall" to "every firewall".
  const stub = (rows) => ({ query: async () => ({ rows }) });

  it('names the accounts that would be emptied', async () => {
    const got = await scopesEmptiedByDeviceDeletion(stub([{ username: 'bob' }]), 'dev-1');
    assert.deepEqual(got, ['bob']);
  });

  it('is empty when nobody is affected — the ordinary case', async () => {
    assert.deepEqual(await scopesEmptiedByDeviceDeletion(stub([]), 'dev-1'), []);
  });

  it('⛔ THROWS on a failed read rather than returning []', async () => {
    // `[]` here means "nobody is affected, go ahead and delete". A database
    // error must never be able to say that — the same rule the adapter
    // contract applies to getRules(). Both callers refuse the delete on a
    // throw, because a delete cannot be undone.
    const failing = { query: async () => { throw new Error('connection terminated'); } };
    await assert.rejects(() => scopesEmptiedByDeviceDeletion(failing, 'dev-1'));
  });

  it('refuses to run without a device id', async () => {
    await assert.rejects(() => scopesEmptiedByDeviceDeletion(stub([]), ''));
    await assert.rejects(() => scopesEmptiedByDeviceDeletion(stub([]), null));
  });

  it('⛔ the query excludes users who hold another device', async () => {
    // Shrinking a scope from three firewalls to two is correct and must not be
    // refused; only the EMPTYING case is. Asserted on the SQL because the
    // distinction lives there.
    let sql = '';
    const recording = { query: async (q) => { sql = q; return { rows: [] }; } };
    await scopesEmptiedByDeviceDeletion(recording, 'dev-1');
    assert.match(sql, /NOT EXISTS/i);
    assert.match(sql, /other\.device_id <> \$1/);
  });

  it('⛔ both delete paths call it — a third one would silently reopen this', () => {
    for (const f of ['app/api/devices/[id]/route.js', 'app/(dashboard)/devices/page.js']) {
      assert.match(code(read(f)), /scopesEmptiedByDeviceDeletion\(/,
        `${f} deletes a device and must check first`);
    }
  });
});

describe('⛔ loadScopeForSession — three cases, not two', () => {
  const pool = { query: async () => ({ rows: [] }) };

  it('a session with NO id is UNKNOWN, not unscoped', async () => {
    // This fell open: an id-less session took the same branch as an LDAP one
    // and was reported UNSCOPED, i.e. handed the whole fleet. "This provider
    // cannot be scoped" and "we do not know who this is" are different facts.
    for (const s of [{ user: {} }, { user: { id: '' } }, { user: { id: null } }, { user: { id: 7 } }]) {
      const got = await loadScopeForSession(s, pool);
      assert.equal(got.state, SCOPE_STATES.UNKNOWN, JSON.stringify(s));
    }
  });

  it('no session at all is UNKNOWN', async () => {
    assert.equal((await loadScopeForSession(null, pool)).state, SCOPE_STATES.UNKNOWN);
    assert.equal((await loadScopeForSession({}, pool)).state, SCOPE_STATES.UNKNOWN);
  });

  it('an LDAP username is UNSCOPED — a real identity with no users row', async () => {
    const got = await loadScopeForSession({ user: { id: 'FIRMANS0' } }, pool);
    assert.equal(got.state, SCOPE_STATES.UNSCOPED);
  });

  it('a local UUID with no rows is UNSCOPED', async () => {
    const got = await loadScopeForSession(
      { user: { id: '11111111-2222-3333-4444-555555555555' } }, pool
    );
    assert.equal(got.state, SCOPE_STATES.UNSCOPED);
  });

  it('⛔ a THROWN read is UNKNOWN, never unscoped', async () => {
    const failing = { query: async () => { throw new Error('down'); } };
    const got = await loadScopeForSession(
      { user: { id: '11111111-2222-3333-4444-555555555555' } }, failing
    );
    assert.equal(got.state, SCOPE_STATES.UNKNOWN, 'a database blip must not widen access');
  });
});

describe('⛔ every blocked surface compiles to a pattern that can actually fire', () => {
  it('no blocked surface is unenforceable', () => {
    assert.deepEqual(UNMAPPABLE_BLOCKED, [],
      'a surface classified `blocked` that compiles to no URL pattern is a refusal that can '
      + 'never happen — and the coverage test would not see it, because that one checks every '
      + 'surface is CLASSIFIED, not that every classification is ENFORCEABLE');
  });

  it('⛔ route groups are stripped generically, not by name', () => {
    // The original form tested for `app/api/` and `app/(dashboard)/` and
    // returned null for anything else, so a surface in a NEW group would be
    // silently dropped from the pattern list.
    assert.ok(surfaceToPattern('app/(reports)/quarterly/page.js').test('/quarterly'));
    assert.ok(surfaceToPattern('app/(a)/(b)/deep/page.js').test('/deep'));
    assert.ok(surfaceToPattern('app/(dashboard)/compliance/page.js').test('/compliance'));
    assert.ok(surfaceToPattern('app/api/devices/route.js').test('/api/devices'));
  });

  it('a dynamic segment matches one element and never a slash', () => {
    const re = surfaceToPattern('app/api/devices/[id]/route.js');
    assert.ok(re.test('/api/devices/abc'));
    assert.equal(re.test('/api/devices/abc/analysis'), false,
      '/devices/[id] must not swallow /devices/[id]/analysis, a separate classification');
  });

  it('a catch-all does match across slashes', () => {
    const re = surfaceToPattern('app/api/thing/[...rest]/route.js');
    assert.ok(re.test('/api/thing/a/b/c'));
  });

  it('a file outside app/ maps to nothing', () => {
    assert.equal(surfaceToPattern('lib/engines/ruleAnalysis.js'), null);
  });
});
