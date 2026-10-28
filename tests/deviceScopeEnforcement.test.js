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
  return src.replace(/(^|[^:])\/\/.*$/gm, '$1').replace(/\/\*[\s\S]*?\*\//g, '');
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

// ⛔ THE LAYOUT IS TESTED BY RUNNING IT, BECAUSE THE SOURCE-SHAPED VERSION
// COULD NOT FAIL.
//
// What stood here was four greps: `pageRefusal(`, `loadScopeForSession(`,
// `redirect(` and `headers().get(PATHNAME_HEADER)`. Mutation-verified: change
// the layout's `if (refusedPath)` to `if (false && refusedPath)` and all four
// still match, so the whole suite stayed green over a page-level device-scope
// boundary that could never fire. This file's own header warned that a
// source-shaped test "would pass over an if-block someone had commented out" —
// the comment-stripper handles that ONE form, and nothing else: a disabled
// condition, an ignored return value, or an early `return null` from
// `refusedSurfaceFor` are all invisible to a grep.
//
// So this builds the smallest harness that answers the only question that
// matters — GIVEN a blocked path and a scope, does the layout REDIRECT? The
// file is compiled with the JSX-aware parser tests/jsxSyntax.test.js already
// uses (`next/dist/build/swc`; `next` is a runtime dependency, so this adds no
// devDependency, which package.json deliberately has none of). Its imports are
// then resolved by hand: the REAL lib/deviceScope and lib/deviceScopePaths, so
// the verdict under test is the shipped one; a stub pool and session; and inert
// placeholders for the components, which are only ever turned into React
// elements here and never rendered.
//
// ⛔ The pathname is served under the REAL PATHNAME_HEADER constant, so a
// layout reading some other header name gets null and refuses nothing — which
// is what the fourth grep used to be for, now decided by behaviour.
function loadDashboardLayout({ session, pathname, scopeRows, scopeThrows }) {
  let transformSync;
  try {
    ({ transformSync } = require('next/dist/build/swc'));
  } catch (err) {
    // ⛔ FAIL, NEVER SKIP. A green tick over an unrun check is the
    // guard-that-cannot-fire pattern this whole file is about.
    assert.fail('Could not load next/dist/build/swc, so the layout was not exercised: '
      + err.message);
  }
  const { code: compiled } = transformSync(read('app/(dashboard)/layout.js'), {
    filename: 'layout.js',
    jsc: {
      parser: { syntax: 'ecmascript', jsx: true },
      target: 'es2022',
      transform: { react: { runtime: 'automatic' } },
    },
    module: { type: 'commonjs' },
    isModule: true,
  });

  const redirects = [];
  const queries = [];
  const inert = { __esModule: true, default: function Inert() { return null; } };
  const stubs = {
    'next/headers': {
      headers: () => ({ get: (name) => (name === PATHNAME_HEADER ? pathname : null) }),
    },
    'next/navigation': {
      // Next's own redirect() throws, and the layout relies on that to stop
      // rendering. A stub that returned would let a broken guard still look
      // like a refusal.
      redirect: (url) => { redirects.push(url); throw new Error('NEXT_REDIRECT ' + url); },
    },
    'next-auth': { getServerSession: async () => session },
    '../api/auth/[...nextauth]/route': { authOptions: {} },
    '../../lib/db': {
      pool: {
        query: async (...args) => {
          queries.push(args);
          if (scopeThrows) throw new Error('connection terminated');
          return { rows: scopeRows || [] };
        },
      },
    },
    '../../components/ui/Evidence': { EvidenceProvider: function EvidenceProvider() { return null; } },
  };
  const fakeRequire = (id) => {
    if (Object.prototype.hasOwnProperty.call(stubs, id)) return stubs[id];
    if (id.startsWith('../../components/')) return inert;
    if (id === 'react' || id === 'react/jsx-runtime') return require(id);
    if (id.startsWith('../../lib/')) return require('../lib/' + id.slice('../../lib/'.length));
    if (id === '../../package.json') return require('../package.json');
    throw new Error('the layout grew an import this harness does not model: ' + id);
  };
  const mod = { exports: {} };
  // eslint-disable-next-line no-new-func
  new Function('require', 'module', 'exports', compiled)(fakeRequire, mod, mod.exports);
  return { Layout: mod.exports.default, redirects, queries };
}

async function renderLayout(opts) {
  const h = loadDashboardLayout(opts);
  let rendered = null;
  try {
    rendered = await h.Layout({ children: null });
  } catch (err) {
    if (!/NEXT_REDIRECT/.test(err.message)) throw err;
  }
  return { redirects: h.redirects, queries: h.queries, rendered };
}

describe('⛔ the layout REFUSES, not merely mentions the verdict', () => {
  const LOCAL_ID = '11111111-2222-3333-4444-555555555555';
  const localSession = { user: { id: LOCAL_ID, provider: 'local' } };

  it('a SCOPED account is redirected away from a blocked page', async () => {
    const r = await renderLayout({
      session: localSession, pathname: BLOCKED_PAGE, scopeRows: [{ device_id: 'dev-1' }],
    });
    assert.deepEqual(r.redirects, [`/devices?scopeBlocked=${encodeURIComponent(BLOCKED_PAGE)}`],
      'the refusal must happen and must name the surface it refused');
    assert.equal(r.rendered, null, 'and the page must not render anyway');
  });

  it('⛔ A FAILED SCOPE READ IS REFUSED TOO — the case that regresses silently', async () => {
    // "We could not measure this account's access" must not be served as
    // "unrestricted". A database blip must never widen anyone's fleet.
    const r = await renderLayout({
      session: localSession, pathname: BLOCKED_PAGE, scopeThrows: true,
    });
    assert.equal(r.redirects.length, 1, 'an unknown scope must refuse a blocked page');
  });

  it('an UNSCOPED account is refused nothing — every account today is unscoped', async () => {
    const r = await renderLayout({
      session: localSession, pathname: BLOCKED_PAGE, scopeRows: [],
    });
    assert.deepEqual(r.redirects, []);
    assert.ok(r.rendered, 'the shell must still render');
  });

  it('a scoped account still reaches a scope-AWARE page, with no scope read at all', async () => {
    // ⛔ The second half is the cost claim in the layout's own comment: the
    // scope is read ONLY for a surface that could be refused.
    const r = await renderLayout({
      session: localSession, pathname: AWARE_PAGE, scopeRows: [{ device_id: 'dev-1' }],
    });
    assert.deepEqual(r.redirects, []);
    assert.equal(r.queries.length, 0, 'an unrefusable page must not cost a database round-trip');
  });

  it('⛔ no forwarded pathname refuses NOTHING, and that is not a fail-open', async () => {
    // It means middleware did not run, so the matcher is broken. Refusing
    // every page would lock a scoped account out of /devices too — an outage
    // in place of a boundary.
    for (const bad of [null, undefined, 'compliance']) {
      const r = await renderLayout({
        session: localSession, pathname: bad, scopeRows: [{ device_id: 'dev-1' }],
      });
      assert.deepEqual(r.redirects, [], JSON.stringify(bad));
    }
  });
});

describe('⛔ middleware feeds the layout the path', () => {
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
    //
    // ⛔ THE GUARD WAS PINNED TO ONE LINE-WRAPPING AND SO COULD BARELY FIRE.
    // It matched `every\s*\n?//\s*token use` — i.e. the claim had to be broken
    // across a line at exactly that word. Written on one line, or wrapped
    // anywhere else, the same false sentence sailed through. The prose is
    // therefore normalised first: comment markers stripped, all whitespace
    // collapsed, so wrapping cannot hide anything.
    //
    // ⛔ A QUOTED COPY IS ALLOWED, AND MUST BE. middleware.js names the old
    // claim in quotes in order to explain why it was wrong — exactly the
    // comment that stops someone reinstating it. A banned-construct assertion
    // that matches the comment explaining the ban is a mistake this repo has
    // already made twice; the fix is never to delete the explanation.
    const CLAIM = /re-read from the database on every token use/i;
    const asserted = (src) => src
      .replace(/\r/g, '')
      .replace(/^[ \t]*\/\/[ \t]?/gm, ' ')
      .replace(/\s+/g, ' ')
      .replace(/"[^"]*"/g, ' ')
      .replace(/“[^”]*”/g, ' ');

    // ⛔ PROVEN NON-VACUOUS AGAINST A SYNTHETIC REINSTATEMENT, not against
    // middleware.js's current wording — which another author may legitimately
    // rephrase, and a guard that quietly depends on one sentence staying put is
    // how this one stopped working in the first place.
    for (const wrapping of [
      '// the flag is re-read from the database on every token use',
      '// the flag is re-read from the\n// database on every token use',
      '// the flag is\n// re-read from the database on\n// every token use',
      '  //re-read from the database on every token use, says the comment',
    ]) {
      assert.match(asserted(wrapping), CLAIM,
        `the guard must see the claim however it is wrapped: ${JSON.stringify(wrapping)}`);
    }
    assert.doesNotMatch(asserted('// It said the flag is "re-read from the\n'
      + '// database on every token use". It does not.'), CLAIM,
      'and must still tolerate the quotation that explains the ban');

    assert.doesNotMatch(asserted(read('middleware.js')), CLAIM,
      'the false freshness claim must not come back — middleware reads the cookie claim, '
      + 'and getToken() never runs the jwt() callback that would refresh it');
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

describe('⛔ loadScopeForSession — the PROVIDER decides, never the id shape', () => {
  const pool = { query: async () => ({ rows: [] }) };
  const LOCAL = '11111111-2222-3333-4444-555555555555';

  it('a local session with NO usable id is UNKNOWN, not unscoped', async () => {
    // This fell open twice over. First an id-less session took the same branch
    // as an LDAP one and was handed the whole fleet. Then the shape test that
    // fixed it became the NEXT fail-open — see the Entra case below.
    for (const u of [{ provider: 'local' }, { id: '', provider: 'local' },
                     { id: null, provider: 'local' }, { id: 7, provider: 'local' }]) {
      const got = await loadScopeForSession({ user: u }, pool);
      assert.equal(got.state, SCOPE_STATES.UNKNOWN, JSON.stringify(u));
    }
  });

  it('⛔ an UNSCOPABLE provider with no usable id is UNKNOWN TOO, not the whole fleet', async () => {
    // ⛔ THE INVARIANT ABOVE HELD FOR `local` ONLY, AND IT WAS UN-PINNED IN THE
    // SAME COMMIT THAT BROKE IT. This case used to be covered here; v2.205.0
    // renamed the test "a local session with NO usable id" and added
    // `provider: 'local'` to all four fixtures, after moving the provider
    // branches AHEAD of the id check. From then on `{ id: null, provider:
    // 'entra' }` — an Entra id_token carrying neither `oid` nor `sub` — took
    // the UNSCOPABLE branch and resolved to `unscoped`: the ENTIRE FLEET, with
    // nothing logged, while the byte-identical `local` fixture one test up was
    // correctly denied.
    //
    // "This provider cannot own a scope" is a claim about a real directory
    // person. Without an id there is no person, only a failed read of the
    // session — and a failed read is never an affirmative answer.
    for (const u of [{ provider: 'entra' }, { id: null, provider: 'entra' },
                     { id: '', provider: 'ldap' }, { id: 7, provider: 'ldap' },
                     { id: {}, provider: 'ldap' }]) {
      const got = await loadScopeForSession({ user: u }, pool);
      assert.equal(got.state, SCOPE_STATES.UNKNOWN, JSON.stringify(u));
    }
  });

  it('⛔ …and the other direction: a REAL unscopable identity is still UNSCOPED', async () => {
    // The fix must not become "every directory account is denied". An LDAP or
    // Entra user with a usable id is a real person with no `users` row, which
    // is genuinely unscoped and has been for this product's whole life.
    for (const u of [{ id: 'FIRMANS0', provider: 'ldap' },
                     { id: '8f4a1c2e-9b7d-4e6a-bc13-5d2f70a9e4c1', provider: 'entra' }]) {
      const got = await loadScopeForSession({ user: u }, pool);
      assert.equal(got.state, SCOPE_STATES.UNSCOPED, JSON.stringify(u));
    }
  });

  it('no session at all is UNKNOWN', async () => {
    assert.equal((await loadScopeForSession(null, pool)).state, SCOPE_STATES.UNKNOWN);
    assert.equal((await loadScopeForSession({}, pool)).state, SCOPE_STATES.UNKNOWN);
  });

  it('an LDAP account is UNSCOPED — a real identity with no users row', async () => {
    const got = await loadScopeForSession({ user: { id: 'FIRMANS0', provider: 'ldap' } }, pool);
    assert.equal(got.state, SCOPE_STATES.UNSCOPED);
  });

  it('a local account with no rows is UNSCOPED', async () => {
    const got = await loadScopeForSession({ user: { id: LOCAL, provider: 'local' } }, pool);
    assert.equal(got.state, SCOPE_STATES.UNSCOPED);
  });

  it('⛔ an Entra account is UNSCOPED by CLASSIFICATION, never by id shape', async () => {
    // ⛔ Phase 0 of .ai-codex/entra-sso-proposal.md. An Entra `oid` is a GUID
    // and passes a local-UUID shape test, so the old check read it as LOCAL,
    // found zero scope rows (there is no `users` row for it to have any), and
    // zero rows means UNSCOPED: the whole fleet, silently. A shape test cannot
    // be made safe by adding shapes — provenance is the fact that matters.
    // ⛔ Assert the query NEVER RAN. A throwing pool reaches UNKNOWN through
    // the catch as well, so a state-only assertion is green under the bug.
    let queried = false;
    const got = await loadScopeForSession(
      { user: { id: '8f4a1c2e-9b7d-4e6a-bc13-5d2f70a9e4c1', provider: 'entra' } },
      { query: async () => { queried = true; return { rows: [] }; } }
    );
    assert.equal(queried, false, 'the Entra oid must not be used as a users.id');
    // ⛔ UNSCOPED because 'entra' is listed in UNSCOPABLE_PROVIDERS (v2.212.0),
    // the same treatment LDAP has. An UNRECOGNISED provider still denies — see
    // the next case, which is the protection v2.205.0 actually added.
    assert.equal(got.state, SCOPE_STATES.UNSCOPED);
  });

  it('⛔ an unrecognised or absent provider DENIES rather than defaulting', async () => {
    for (const u of [{ id: LOCAL }, { id: LOCAL, provider: '' },
                     { id: LOCAL, provider: 'saml' }, { id: LOCAL, provider: 7 }]) {
      const got = await loadScopeForSession({ user: u }, pool);
      assert.equal(got.state, SCOPE_STATES.UNKNOWN, JSON.stringify(u));
    }
  });

  it('⛔ a THROWN read is UNKNOWN, never unscoped', async () => {
    const failing = { query: async () => { throw new Error('down'); } };
    const got = await loadScopeForSession({ user: { id: LOCAL, provider: 'local' } }, failing);
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
