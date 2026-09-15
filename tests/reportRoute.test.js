'use strict';
// Pins the report delivery surface: lib/reports/catalogue.js's contract with
// app/api/reports/[id]/pdf/route.js and app/(dashboard)/reports/page.js.
//
// ⛔ WHY A SOURCE-SCANNING TEST AND NOT A ROUTE TEST. There is no HTTP harness
// in this repo and none is being added for this. What actually needs pinning is
// not the response shape — it is that THREE PLACES AGREE: the page lists a
// report, the route serves it, and the registry declares the capability both
// consult. Those three drifting apart is the same class of bug Phase A merged
// two copies of a PDF helper to prevent, and it surfaces to an operator as "the
// button does nothing", which is the least diagnosable failure available.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { REPORTS, reportById, visibleReports, SCOPES } = require('../lib/reports/catalogue');

const ROOT = path.join(__dirname, '..');
const routeSrc = fs.readFileSync(
  path.join(ROOT, 'app', 'api', 'reports', '[id]', 'pdf', 'route.js'), 'utf8'
);
const pageSrc = fs.readFileSync(
  path.join(ROOT, 'app', '(dashboard)', 'reports', 'page.js'), 'utf8'
);
const sidebarSrc = fs.readFileSync(
  path.join(ROOT, 'components', 'layout', 'Sidebar.js'), 'utf8'
);

// Comments quote the rules they enforce, so a naive scan matches the
// explanation rather than the code. Strip them first — a source-scanning test
// has to read what RUNS.
const code = (src) => src
  .split('\n')
  .filter((l) => !l.trim().startsWith('//') && !l.trim().startsWith('*'))
  .join('\n');

const ROUTE = code(routeSrc);
const PAGE = code(pageSrc);

describe('⛔ the route enforces the capability the registry declares', () => {
  it('resolves the report through the registry, not a hardcoded map', () => {
    // A second list of reports inside the route is the drift this registry
    // exists to prevent.
    assert.match(ROUTE, /reportById\(/);
    assert.match(ROUTE, /require.*reports\/catalogue|from '.*reports\/catalogue'/);
  });

  it('calls can() with the ENTRY\'s capability, not a literal', () => {
    assert.match(ROUTE, /can\(session, entry\.capability\)/);
    assert.equal(
      /can\(session, (OPERATE|MANAGE_[A-Z_]+|VIEW_[A-Z_]+)\)/.test(ROUTE), false,
      'a hardcoded capability would ignore what the entry declares — and Phase D '
      + 'adds an identity report whose capability differs from every other'
    );
  });

  it('returns 403 through forbiddenResponse, which names the capability', () => {
    // "admin role required" became actively misleading with three roles.
    assert.match(ROUTE, /forbiddenResponse\(entry\.capability\)/);
  });

  it('⛔ an unknown id is 404, never an empty PDF', () => {
    // A zero-byte "report" is a confident-looking artefact someone would file.
    assert.match(ROUTE, /status: 404/);
    assert.match(ROUTE, /No such report/);
  });

  it('⛔ refuses a device-scoped report with no device rather than widening to the fleet', () => {
    // Silently rendering the whole fleet under a title that says one firewall
    // is a MISLABELLED document — worse on an audit artefact than an error.
    assert.match(ROUTE, /scope === 'device'/);
    assert.match(ROUTE, /isValidUuid\(deviceId\)/);
    assert.match(ROUTE, /status: 400/);
  });

  it('validates an entity id the same way', () => {
    assert.match(ROUTE, /scope === 'entity'/);
    assert.match(ROUTE, /isValidUuid\(entityId\)/);
  });

  it('⛔ forbids caching — a report asserts a generation time on its cover', () => {
    // A cached copy served days later carries a cover page claiming a moment it
    // does not have. That is the stale-evidence problem this product exists to
    // avoid, delivered by an HTTP header.
    assert.match(ROUTE, /Cache-Control/);
    assert.match(ROUTE, /no-store/);
  });

  it('⛔ surfaces a build failure instead of returning a broken file', () => {
    assert.match(ROUTE, /status: 500/);
    assert.match(ROUTE, /catch \(err\)/);
  });

  it('exports dynamic = force-dynamic, or the build prerenders it against the DB', () => {
    assert.match(ROUTE, /export const dynamic = 'force-dynamic'/);
  });
});

describe('the page and the registry cannot drift', () => {
  it('the page lists from visibleReports, not its own array', () => {
    assert.match(PAGE, /visibleReports\(/);
    assert.equal(
      /const REPORTS\s*=\s*\[/.test(PAGE), false,
      'a second catalogue in the page is exactly the drift the registry prevents'
    );
  });

  it('gates listing on the session\'s real capabilities', () => {
    assert.match(PAGE, /capabilitiesOf\(session\)/);
  });

  it('⛔ filtering in the page is DISCOVERY — the route still checks', () => {
    // If the page were the only gate, typing the URL would bypass it.
    assert.match(ROUTE, /can\(session, entry\.capability\)/);
  });

  it('every registered scope is handled by the page', () => {
    const handled = new Set();
    if (/SCOPES\.FLEET/.test(PAGE)) handled.add(SCOPES.FLEET);
    if (/SCOPES\.DEVICE/.test(PAGE)) handled.add(SCOPES.DEVICE);
    if (/SCOPES\.ENTITY/.test(PAGE)) handled.add(SCOPES.ENTITY);
    for (const r of REPORTS) {
      assert.ok(
        handled.has(r.scope),
        `${r.id} is scope '${r.scope}' and the page renders no branch for it — `
        + 'it would be registered and invisible'
      );
    }
  });

  it('is reachable from the sidebar with its own glyph', () => {
    // Every nav entry must keep a DISTINCT glyph; that, not colour, is the
    // per-item wayfinding cue.
    assert.match(sidebarSrc, /href: '\/reports'/);
    assert.match(sidebarSrc, /Icon: IconReport/);
    const glyphs = [...sidebarSrc.matchAll(/Icon: (Icon\w+)/g)].map((m) => m[1]);
    assert.equal(new Set(glyphs).size, glyphs.length, 'two nav entries share a glyph');
  });
});

describe('the registry stays honest about what exists', () => {
  it('every entry resolves to a real builder function', () => {
    // Catches an engine rename that would otherwise only surface when an
    // operator clicked Download.
    for (const r of REPORTS) {
      assert.equal(typeof r.builder(), 'function', `${r.id}'s builder does not resolve`);
    }
  });

  it('ids are unique and URL-safe, since they are path segments', () => {
    const ids = REPORTS.map((r) => r.id);
    assert.equal(new Set(ids).size, ids.length);
    for (const id of ids) assert.match(id, /^[a-z0-9-]+$/, `${id} is not URL-safe`);
  });

  it('reportById refuses anything not registered', () => {
    assert.equal(reportById('../../etc/passwd'), null);
    assert.equal(reportById('compliance-fleet '), null, 'no trimming — an id is exact');
    assert.ok(reportById('compliance-fleet'));
  });

  it('⛔ a null capability set grants nothing', () => {
    assert.equal(visibleReports(null).length, 0);
    assert.equal(visibleReports(undefined).length, 0);
    assert.equal(visibleReports({}).length, 0);
  });
});
