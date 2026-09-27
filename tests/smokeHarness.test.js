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

// ─────────────────────────────────────────────────────────────────────────
// ⛔ A DATA-DEPENDENT MARKER FAILS THE DEPLOY GATE ON A HEALTHY FLEET
// (found 2026-09-27)
//
// `/coverage` and `/conformance` shipped with markers that only some DATA
// produces:
//
//   'Gaps by evidence source'  — a heading inside `rows.length > 0` in
//                                CoverageRegister.js
//   'In the smaller group'     — a <th> ConformanceBoard renders only when a
//                                `measured` cohort holds at least one VALUE
//                                deviation (and its RANKING_HEADING's lowercase
//                                "…in the smaller group" does not satisfy a
//                                case-sensitive includes() either)
//
// A customer with two FortiGates and two Palo Altos has every cohort below
// MIN_COHORT and may have no recorded gaps: nothing renders, both pages are
// CORRECT, and Update-SecVault.ps1 then sets `hadFailure` so the closing banner
// refuses to say the deploy completed. The second marker on each route is the
// scope-refusal branch, which only fires on a FAILED scope read.
//
// So a marker has to be something the page prints whatever the data says. The
// model is the /vulnerability?tab=upgrade marker: an unconditional StatCard label.

const fs = require('node:fs');
const path = require('node:path');
const { stripComments } = require('./stripComments');

const REPO = path.join(__dirname, '..');
const readSrc = (...p) => fs.readFileSync(path.join(REPO, ...p), 'utf8');
const markersFor = (p) => (STATIC_ROUTES.find((r) => r.path === p) || {}).markers;

describe('⛔ no marker may depend on the fleet having interesting data', () => {
  // Named, with the file and the guard each sat behind, so a future edit that
  // reintroduces one is refused with the reason rather than just the string.
  const DATA_DEPENDENT = [
    ['Gaps by evidence source', 'CoverageRegister.js renders it inside `rows.length > 0`'],
    ['In the smaller group', 'ConformanceBoard.js renders it only for a cohort with a value deviation'],
  ];

  it('the route table uses none of them', () => {
    const offenders = [];
    for (const r of STATIC_ROUTES) {
      for (const m of r.markers) {
        const hit = DATA_DEPENDENT.find(([s]) => s === m);
        if (hit) offenders.push(`${r.path} -> ${JSON.stringify(m)} (${hit[1]})`);
      }
    }
    assert.deepEqual(offenders, [],
      'a marker only some data produces turns a correct page into a failed deploy gate');
  });

  it('/coverage leads with an unconditional StatCard label', () => {
    const m = markersFor('/coverage');
    assert.deepEqual(m, ['Firewalls with a blind spot', 'Coverage could not be shown']);
    // ⛔ ASSERTED AGAINST THE SOURCE, so a rename breaks the build and not the
    // deploy. Comments stripped LINE-first via the shared helper: the prose in
    // both files quotes the strings it renders.
    const reg = stripComments(readSrc('components', 'devices', 'CoverageRegister.js'));
    assert.ok(reg.includes('Firewalls with a blind spot'),
      'the marker must still be a string CoverageRegister.js renders');
    assert.ok(!/rows\.length > 0[\s\S]{0,400}Firewalls with a blind spot/.test(reg),
      'and it must not have moved behind the row guard');
    const page = stripComments(readSrc('app', '(dashboard)', 'coverage', 'page.js'));
    assert.ok(page.includes('Coverage could not be shown'),
      'the refusal branch keeps its own marker');
  });

  it('/conformance leads with the unconditional board purpose', () => {
    const m = markersFor('/conformance');
    assert.deepEqual(m, [
      'A cohort is one vendor collected one way', 'Conformance could not be shown',
    ]);
    const board = stripComments(readSrc('components', 'analysis', 'ConformanceBoard.js'));
    assert.ok(board.includes('A cohort is one vendor collected one way'),
      'BOARD_PURPOSE must still open with this');
    assert.ok(board.includes('{BOARD_PURPOSE}'),
      'and it must still be rendered unconditionally above the tiles');
    const page = stripComments(readSrc('app', '(dashboard)', 'conformance', 'page.js'));
    assert.ok(page.includes('Conformance could not be shown'));
  });

  it('every marker on every route is present in some source file', () => {
    // The cheapest guard against the whole class: a marker nothing renders can
    // never pass, and would be discovered by a failed deploy rather than here.
    // Pages and components only — a marker must come from a page body.
    const roots = [
      path.join(REPO, 'app'), path.join(REPO, 'components'), path.join(REPO, 'lib'),
    ];
    const files = [];
    const walk = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) walk(full);
        else if (e.name.endsWith('.js')) files.push(full);
      }
    };
    roots.forEach(walk);
    const haystack = files.map((f) => fs.readFileSync(f, 'utf8')).join('\n');
    const missing = [];
    for (const r of STATIC_ROUTES) {
      for (const m of r.markers) {
        // Markers may be HTML-escaped forms of a source string; those carry an
        // `&#x` and are checked by their sibling marker instead.
        if (m.includes('&#x')) continue;
        if (!haystack.includes(m)) missing.push(`${r.path} -> ${JSON.stringify(m)}`);
      }
    }
    assert.deepEqual(missing, [], 'no source file renders these, so they can never pass');
  });
});

describe('⛔ alsoMarkers is an AND, which is the point of it', () => {
  // ⛔ WHY THIS EXISTS AT ALL. `markers` is an OR, so a page that grows a SECOND
  // independent section cannot be covered by adding to it — the original marker
  // satisfies the OR while the new section renders nothing. That is the blank
  // body this whole sweep was written for, one section down. The live case is
  // the A7 change-outcome board on /devices/[id]/changes, which sits below the
  // change list and is a server component handing a whole computed object to a
  // client one: the exact shape that shipped a blank /reports in v2.120.0.

  const twoSection = {
    path: '/devices/x/changes',
    markers: ['Configuration Changes'],
    alsoMarkers: ['compared with how much that firewall normally varies'],
  };

  it('the FIRST section alone is NOT a pass', () => {
    const v = pageVerdict(twoSection, { status: 200, body: SHELL + 'Configuration Changes' });
    assert.equal(v.ok, false, 'this is the case an OR marker would have passed');
    assert.match(v.reason, /REQUIRED second section did not/);
    assert.match(v.reason, /one section of this page is blank/);
  });

  it('it names the section that did not render, not just that something failed', () => {
    const v = pageVerdict(twoSection, { status: 200, body: SHELL + 'Configuration Changes' });
    // An operator reading the deploy log has to know WHICH half is dead.
    assert.match(v.reason, /normally varies/);
  });

  it('both sections present is a pass', () => {
    const body = SHELL + 'Configuration Changes'
      + ' ... compared with how much that firewall normally varies from one day to the next.';
    const v = pageVerdict(twoSection, { status: 200, body });
    assert.equal(v.ok, true);
    assert.equal(v.marker, 'Configuration Changes');
  });

  it('⛔ the SECOND section alone is still a failure', () => {
    // Order independence: alsoMarkers must not be able to stand in for markers.
    const v = pageVerdict(twoSection, {
      status: 200,
      body: SHELL + 'compared with how much that firewall normally varies',
    });
    assert.equal(v.ok, false);
    assert.match(v.reason, /none of its content markers rendered/);
  });

  it('a route with no alsoMarkers is completely unaffected', () => {
    // The field is optional, and every existing route omits it. A `for` over
    // undefined would throw and fail all 28 pages at once.
    for (const also of [undefined, null, []]) {
      const r = { path: '/reports', markers: route.markers, alsoMarkers: also };
      const v = pageVerdict(r, { status: 200, body: SHELL + route.markers[0] });
      assert.equal(v.ok, true, `alsoMarkers=${JSON.stringify(also)} must not change the verdict`);
    }
  });

  it('every alsoMarkers string in the real table is also checked for usability', () => {
    // ⛔ THE SAME RULE AS `markers`: a nav label here would be satisfied by the
    // shared layout. assertUsableMarkers owns that rule; this asserts the new
    // field is not exempt from it.
    const all = STATIC_ROUTES.flatMap((r) => r.alsoMarkers || []);
    for (const m of all) {
      assert.ok(!NAV_LABELS.includes(m), `${m} is a nav label and would pass on a blank page`);
      assert.ok(m.length > 12, `${m} is too short to be distinctive`);
    }
  });
});
