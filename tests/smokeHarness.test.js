'use strict';
// tests/smokeHarness.test.js
//
// ⛔ THE SWEEP ITSELF NEEDS A TEST, BECAUSE A LIVE RUN ONLY EVER EXERCISES THE
// GREEN PATH. `npm run smoke` reported 28/28 the first time it was pointed at
// production — which tells you nothing about whether it can go red. The failing
// path is the entire point of the harness and it is the one a healthy fleet
// never reaches.
//
// So the verdict logic is pure and gets fed synthetic responses here, including
// the exact v2.120.0 shape: HTTP 200, a full page of sidebar and header, and no
// page content at all.
//
// This file does NOT talk to a server. `scripts/smoke.js` only sweeps when it is
// run directly (`require.main === module`).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { assertUsableMarkers, pageVerdict, STATIC_ROUTES, NAV_LABELS, ERROR_SHAPES } = require('../scripts/smoke');

const route = { path: '/reports', markers: ['Point-in-time PDFs you can hand to an auditor'] };

// What a dashboard page looks like when the layout renders and the page does
// not: the sidebar nav, the header, and nothing else.
const SHELL = `<!DOCTYPE html><html><body><nav>${NAV_LABELS.join('</a><a>')}</nav>`
  + '<header>SecVault</header><main></main></body></html>';

describe('⛔ the blank-page shape is caught', () => {
  it('200 + a full shell + no page content FAILS', () => {
    const v = pageVerdict(route, { status: 200, body: SHELL });
    assert.equal(v.ok, false);
    assert.match(v.reason, /none of its content markers rendered/);
    assert.match(v.reason, /blank-page shape/);
  });

  it('the shell is big enough that a byte-length check would have passed it', () => {
    // Guards the reasoning, not just the outcome: "is the body suspiciously
    // short" is the obvious cheap test, and it would have shipped v2.120.0.
    assert.ok(SHELL.length > 200, 'the shell is substantial, which is the trap');
    const v = pageVerdict(route, { status: 200, body: SHELL });
    assert.equal(v.ok, false, 'length must not be what decides this');
  });

  it('the same page WITH its marker passes', () => {
    const v = pageVerdict(route, { status: 200, body: SHELL + route.markers[0] });
    assert.equal(v.ok, true);
    assert.equal(v.marker, route.markers[0]);
  });
});

describe("⛔ Next's error shell is caught even when it is served as 200", () => {
  for (const body of [
    '<html><body>Application error: a server-side exception has occurred while loading the page.</body></html>',
    '<html><body>digest: "3663440509"</body></html>',
    '<html><body>Internal Server Error</body></html>',
  ]) {
    it(`rejects: ${body.slice(30, 75)}`, () => {
      const v = pageVerdict(route, { status: 200, body });
      assert.equal(v.ok, false);
      assert.match(v.reason, /server-error shell/);
      assert.match(v.reason, /app-error\.log/, 'the reason must say where the digest resolves');
    });
  }

  it('and a 500 is reported as a plain HTTP failure', () => {
    const v = pageVerdict(route, { status: 500, body: '' });
    assert.equal(v.ok, false);
    assert.match(v.reason, /HTTP 500/);
  });

  it('ERROR_SHAPES is not empty — an empty list would accept every error page', () => {
    assert.ok(ERROR_SHAPES.length >= 3);
  });
});

describe('⛔ a lost session is one failure with the right reason', () => {
  it('a 307 to /login is reported as the session not being accepted', () => {
    const v = pageVerdict(route, { status: 307, location: 'https://host/login', body: '' });
    assert.equal(v.ok, false);
    assert.match(v.reason, /session was not accepted/);
    assert.match(v.reason, /\/login/);
  });

  it('but /login itself is allowed to be reached anonymously', () => {
    const anon = { path: '/login', anon: true, markers: ['x'] };
    const v = pageVerdict(anon, { status: 200, body: 'x' });
    assert.equal(v.ok, true);
  });
});

describe('⛔ no marker may be a navigation label', () => {
  // The sidebar renders every one of these into EVERY dashboard page from the
  // shared layout, so such a marker is satisfied by a working shell around a
  // dead page — the precise failure this harness exists to catch. The first
  // draft of smoke.js declared NAV_LABELS, wrote that warning, and never
  // checked it.
  it('the route table has none', () => {
    const offenders = [];
    for (const r of STATIC_ROUTES) {
      for (const m of r.markers) {
        if (NAV_LABELS.some((label) => label.toLowerCase() === m.trim().toLowerCase())) {
          offenders.push(`${r.path} -> ${JSON.stringify(m)}`);
        }
      }
    }
    assert.deepEqual(offenders, [], 'a nav label cannot distinguish a page from a shell');
  });

  it('and the check would catch one if it were added', () => {
    // Without this, the assertion above passes just as happily on an empty
    // NAV_LABELS list or a typo'd comparison.
    const bad = [{ path: '/compliance', markers: ['Compliance'] }];
    const offenders = bad.flatMap((r) => r.markers.filter(
      (m) => NAV_LABELS.some((l) => l.toLowerCase() === m.trim().toLowerCase())
    ));
    assert.deepEqual(offenders, ['Compliance']);
  });

  it('every route carries at least one marker', () => {
    for (const r of STATIC_ROUTES) {
      assert.ok(Array.isArray(r.markers) && r.markers.length > 0, `${r.path} has no marker`);
      assert.ok(r.markers.every((m) => typeof m === 'string' && m.length >= 4), `${r.path} has a too-short marker`);
    }
  });

  it('covers the pages that exist', () => {
    // A route table that silently lost half its entries would sweep green.
    assert.ok(STATIC_ROUTES.length >= 20, `only ${STATIC_ROUTES.length} routes listed`);
    for (const must of ['/', '/reports', '/devices', '/work', '/settings', '/login']) {
      assert.ok(STATIC_ROUTES.some((r) => r.path === must), `${must} must be swept`);
    }
  });
});

describe('⛔ the nav-label guard covers DISCOVERED routes, not just the static table', () => {
  it('refuses a marker that the shared layout renders into every page', () => {
    // It used to be asserted only over STATIC_ROUTES, so `/compliance/<id>`
    // shipped with markers: ['Compliance', <device>] — and since markers are
    // OR'd, a blank body wrapped in a working sidebar passed the sweep. The
    // file's own comment had predicted that exact line.
    assert.throws(
      () => assertUsableMarkers([{ path: '/compliance/abc', markers: ['Compliance', 'FW1'] }]),
      /navigation label/
    );
  });

  it('accepts a marker only the page body produces', () => {
    const routes = [{ path: '/compliance/abc', markers: ['Compliance — FW1', 'FW1'] }];
    assert.equal(assertUsableMarkers(routes), routes);
  });

  it('and it throws rather than warning, because the update logs a pass either way', () => {
    // A sweep that can be made green by a blank page is worse than no sweep.
    assert.throws(() => assertUsableMarkers([{ path: '/x', markers: ['Settings'] }]));
  });
});
