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

describe('⛔ nothing non-serialisable crosses into a client component', () => {
  // THE BUG THIS EXISTS FOR, because nothing in this suite could see it.
  //
  // The page passed whole catalogue entries to <ReportCard>, which is a client
  // component. An entry carries `builder` — a lazy `() => require(...)` so the
  // registry can be read without pulling pdfkit and the entire engine graph in
  // behind it. React refuses to send a function across that boundary, and in a
  // PRODUCTION build the failure is a bare digest on an empty page with the
  // message deliberately withheld "to avoid leaking sensitive details".
  //
  // Every test passed. The build was clean. The page was blank. There is no
  // render harness in this repo, so the only thing that can catch this class is
  // a check on the shape of what gets handed over.

  it('clientSafe strips the builder', () => {
    const { clientSafe, REPORTS } = require('../lib/reports/catalogue');
    for (const entry of REPORTS) {
      const safe = clientSafe(entry);
      assert.equal(safe.builder, undefined, `${entry.id} still carries its builder`);
      assert.equal(safe.capability, undefined, 'the capability is a server concern');
    }
  });

  it('⛔ every clientSafe entry survives JSON, which is what React requires', () => {
    const { clientSafe, REPORTS } = require('../lib/reports/catalogue');
    for (const entry of REPORTS) {
      const safe = clientSafe(entry);
      for (const [k, v] of Object.entries(safe)) {
        assert.notEqual(typeof v, 'function', `${entry.id}.${k} is a function`);
      }
      assert.deepEqual(JSON.parse(JSON.stringify(safe)), safe, `${entry.id} does not round-trip`);
    }
  });

  it('⛔ it is an ALLOW-LIST, so a new function field cannot leak through', () => {
    // Written as "pick these fields" rather than "delete builder", because the
    // next field added might also be a function — a formatter, a predicate —
    // and a deny-list silently starts passing it.
    const { clientSafe } = require('../lib/reports/catalogue');
    const safe = clientSafe({
      id: 'x', name: 'X', summary: 's', scope: 'fleet', formats: ['pdf'],
      builder: () => {},
      validate: () => {},          // a plausible future addition
      capability: 'operate',
      pool: { query: () => {} },   // something genuinely dangerous
    });
    assert.equal(safe.validate, undefined);
    assert.equal(safe.pool, undefined);
    assert.equal(safe.builder, undefined);
    assert.deepEqual(Object.keys(safe).sort(),
      ['formats', 'id', 'name', 'optionalDevice', 'scope', 'summary']);
  });

  it('the page serialises before rendering the client component', () => {
    assert.match(PAGE, /clientSafe/, 'the page must serialise catalogue entries');
    assert.match(
      PAGE, /visibleReports\([^)]*\)\s*\.map\(clientSafe\)/,
      'serialise ONCE where the list is built, not at each call site'
    );
  });

  it('clientSafe tolerates a null entry rather than throwing', () => {
    const { clientSafe } = require('../lib/reports/catalogue');
    assert.equal(clientSafe(null), null);
    assert.equal(clientSafe(undefined), null);
  });
});
