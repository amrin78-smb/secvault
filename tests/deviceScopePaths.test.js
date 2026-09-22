'use strict';
// tests/deviceScopePaths.test.js
//
// ⛔ THIS IS THE TEST FOR THE GUARD THAT DID NOT FIRE.
// When per-user scoping shipped (v2.168.0) `lib/deviceScopeCoverage.js`
// classified every surface, a test failed the build on an unclassified one,
// and NOTHING CALLED ANY OF IT AT RUNTIME. The default-deny property the whole
// design rests on was documented, completeness-tested, and unenforced: a
// scoped account would still have been served the entire fleet on /compliance.
// A guard that cannot fire is worse than no guard, because the code reads as
// handled — the same defect as the jsonb JSON.stringify comparison that could
// never be true.
//
// So these assert BEHAVIOUR at the URL level, which is what middleware
// actually sees.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  surfaceToPattern, resolveSurface, blockedSurfaceFor, BLOCKED_PATTERNS,
} = require('../lib/deviceScopePaths');
const { COVERAGE } = require('../lib/deviceScopeCoverage');

describe('surface files map to URL patterns', () => {
  const m = (file, path) => surfaceToPattern(file).test(path);

  it('routes and pages lose their filename', () => {
    assert.ok(m('app/api/devices/route.js', '/api/devices'));
    assert.ok(m('app/(dashboard)/devices/page.js', '/devices'));
    assert.ok(m('app/(dashboard)/page.js', '/'));
  });

  it('a dynamic segment matches one element and never a slash', () => {
    // Otherwise /devices/[id] swallows /devices/[id]/analysis, which is a
    // SEPARATE surface with its own classification.
    assert.ok(m('app/(dashboard)/devices/[id]/page.js', '/devices/abc'));
    assert.equal(m('app/(dashboard)/devices/[id]/page.js', '/devices/abc/analysis'), false);
    assert.equal(m('app/(dashboard)/devices/[id]/page.js', '/devices'), false);
  });

  it('a catch-all matches the rest of the path', () => {
    assert.ok(m('app/api/auth/[...nextauth]/route.js', '/api/auth/session'));
    assert.ok(m('app/api/auth/[...nextauth]/route.js', '/api/auth/callback/local'));
  });

  it('a trailing slash does not change the answer', () => {
    assert.equal(blockedSurfaceFor('/compliance'), blockedSurfaceFor('/compliance/'));
  });
});

describe('⛔ the scope-aware surfaces are reachable', () => {
  it('the four aware surfaces are NOT blocked', () => {
    // If any of these were blocked, a scoped account could reach nothing at
    // all and the feature would present as broken rather than restricted.
    for (const p of ['/devices', '/devices/abc-123', '/api/devices', '/api/devices/abc-123']) {
      assert.equal(blockedSurfaceFor(p), null, `${p} must stay reachable`);
    }
  });

  it('⛔ a literal sibling is not shadowed by a dynamic one', () => {
    // /api/compliance/fleet matches app/api/compliance/[deviceId]/route.js as
    // well as its own file. The most specific match has to win, or an `aware`
    // literal route would be refused because a dynamic neighbour is blocked.
    assert.equal(
      blockedSurfaceFor('/api/compliance/fleet'),
      'app/api/compliance/fleet/route.js'
    );
    assert.equal(
      blockedSurfaceFor('/api/compliance/abc-123'),
      'app/api/compliance/[deviceId]/route.js'
    );
  });
});

describe('⛔ the first match decides, whatever its classification', () => {
  // ⛔ TESTED AGAINST A SYNTHETIC REGISTER BECAUSE THE REAL ONE CANNOT
  // EXERCISE IT. Today no `blocked` pattern shadows an `aware` one, so a
  // version that kept scanning past an aware match behaves identically against
  // production data -- it survived mutation testing for exactly that reason.
  // The rule still has to hold the day a literal route is promoted to `aware`
  // under a blocked dynamic neighbour, so it is pinned here on the shape
  // rather than on the current contents.
  const synthetic = [
    { file: 'aware/literal', cls: 'aware', re: /^\/api\/thing\/fleet$/, dynamic: 0 },
    { file: 'blocked/dynamic', cls: 'blocked', re: /^\/api\/thing\/[^/]+$/, dynamic: 1 },
  ];

  it('an AWARE literal is not refused by a BLOCKED dynamic neighbour', () => {
    assert.equal(resolveSurface(synthetic, '/api/thing/fleet'), null,
      'scanning past the aware match would refuse a surface that scopes correctly');
  });

  it('while the dynamic sibling is still refused', () => {
    assert.equal(resolveSurface(synthetic, '/api/thing/abc'), 'blocked/dynamic');
  });

  it('and order is what decides — reverse it and the aware surface breaks', () => {
    // States the dependency outright: the ordering in ALL_PATTERNS is load-
    // bearing, not cosmetic.
    assert.equal(resolveSurface([...synthetic].reverse(), '/api/thing/fleet'), 'blocked/dynamic');
  });
});

describe('⛔ blocked surfaces are refused', () => {
  it('pages and routes that read device data without scoping it', () => {
    for (const p of ['/', '/compliance', '/vulnerability', '/analysis', '/api/compliance/fleet']) {
      assert.ok(blockedSurfaceFor(p), `${p} reads device data and must be refused when scoped`);
    }
  });

  it('⛔ sign-in and session paths are NEVER blocked', () => {
    // Blocking these would lock a scoped account out of the product entirely,
    // and the account could not even be told why.
    for (const p of ['/login', '/api/auth/session', '/api/auth/csrf', '/api/auth/callback/local']) {
      assert.equal(blockedSurfaceFor(p), null, `${p} must always be reachable`);
    }
  });

  it('a path matching no surface is allowed, not guessed at', () => {
    // A static asset or a 404 is not something the router has resolved, and
    // refusing it here would be inventing a decision.
    for (const p of ['/_next/static/chunk.js', '/favicon.ico', '/nothing/here']) {
      assert.equal(blockedSurfaceFor(p), null, p);
    }
  });

  it('junk input is allowed rather than throwing', () => {
    for (const p of [null, undefined, '', 42, {}]) {
      assert.equal(blockedSurfaceFor(p), null, JSON.stringify(p));
    }
  });
});

describe('⛔ the matcher covers the register', () => {
  it('every blocked surface produced a usable pattern', () => {
    const blocked = Object.entries(COVERAGE).filter(([, c]) => c === 'blocked');
    assert.equal(BLOCKED_PATTERNS.length, blocked.length,
      'a blocked surface whose pattern could not be built would be silently reachable');
  });

  it('and every one of them is actually refused at its own URL', () => {
    // The register and the matcher agreeing in aggregate is not the same as
    // each surface being refused — a pattern that compiled but matched nothing
    // would pass the count check above and enforce nothing.
    const unreachable = [];
    for (const { file, re } of BLOCKED_PATTERNS) {
      // Build a concrete URL for this surface by filling each dynamic segment.
      const url = file
        .replace(/^app\/api/, '/api')
        .replace(/^app\/\(dashboard\)/, '')
        .replace(/\/(route|page)\.js$/, '')
        .replace(/\[\.\.\.[^\]]+\]/g, 'x/y')
        .replace(/\[[^\]]+\]/g, 'x') || '/';
      if (!re.test(url) || blockedSurfaceFor(url) === null) unreachable.push(`${file} -> ${url}`);
    }
    assert.deepEqual(unreachable, [],
      `these are classified 'blocked' but are not refused at their own URL:\n  `
      + unreachable.join('\n  '));
  });
});
