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

  it('every registered scope is reachable, none is silently invisible', () => {
    // ⛔ THE CLAIM IS UNCHANGED; ONLY WHERE IT IS ENFORCED MOVED. This used to
    // check the PAGE for a branch per scope, because the page rendered one
    // section per scope and a report whose scope had no section was registered
    // and invisible. The page is now a rail plus a panel and does no scope
    // filtering at all — it hands every visible report to the workspace — so
    // the place a scope can now go unhandled is the workspace's own labels and
    // its entity branch. Checking the old location would have kept passing
    // while testing nothing, which is worse than deleting it.
    const ws = fs.readFileSync(
      path.join(ROOT, 'components', 'reports', 'ReportWorkspace.js'), 'utf8');

    assert.equal(
      /SCOPES\.FLEET/.test(PAGE), false,
      'the page must not filter by scope — the workspace shows the whole catalogue'
    );

    const block = ws.match(/const SCOPE_LABEL = \{([\s\S]*?)\};/);
    assert.ok(block, 'SCOPE_LABEL not found in ReportWorkspace.js');
    for (const r of REPORTS) {
      assert.match(
        block[1], new RegExp('\\b' + r.scope + '\\s*:'),
        `${r.id} is scope '${r.scope}' and the workspace has no label for it — `
        + 'the rail would print the raw enum value'
      );
    }

    // Entity-scoped reports cannot be run from this page and the panel must say
    // so. Without this branch the download button would 404 with no explanation.
    if (REPORTS.some((r) => r.scope === SCOPES.ENTITY)) {
      assert.match(ws, /isEntity/,
        'an entity-scoped report is registered but the panel has no branch for it');
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
      ['contents', 'formats', 'icon', 'id', 'name', 'optionalDevice', 'params', 'scope', 'summary']);
  });

  it('the page serialises before rendering the client component', () => {
    assert.match(PAGE, /clientSafe/, 'the page must serialise catalogue entries');
    assert.match(
      PAGE, /visibleReports\([^)]*\)\s*\.map\(clientSafe\)/,
      'serialise ONCE where the list is built, not at each call site'
    );
  });

  it('⛔ a function nested inside params cannot cross either', () => {
    // The flat "no function values" check above walks only the top level, and
    // `params` is the first NESTED structure this boundary carries. A
    // formatter or predicate added to a choice would sit one level down, where
    // that check cannot see it — and the failure is the blank page with a bare
    // digest, all over again.
    const { clientSafe } = require('../lib/reports/catalogue');
    const safe = clientSafe({
      id: 'x', name: 'X', summary: 's', scope: 'fleet', formats: ['pdf'],
      params: [{
        key: 'k', label: 'K', allLabel: 'All',
        choices: [{ value: 'v', label: 'V', render: () => 'nope' }],
        validate: () => true,
      }],
    });
    assert.deepEqual(JSON.parse(JSON.stringify(safe)), safe);
    assert.equal(safe.params[0].validate, undefined);
    assert.equal(safe.params[0].choices[0].render, undefined);
    assert.deepEqual(Object.keys(safe.params[0].choices[0]).sort(), ['label', 'value']);
  });

  it('a report with no params gets an empty array, not undefined', () => {
    // The panel maps over this unconditionally; undefined would throw at render
    // rather than at build, which on this page means a blank screen.
    const { clientSafe, REPORTS } = require('../lib/reports/catalogue');
    for (const entry of REPORTS) {
      assert.ok(Array.isArray(clientSafe(entry).params), `${entry.id}.params is not an array`);
    }
  });

  it('clientSafe tolerates a null entry rather than throwing', () => {
    const { clientSafe } = require('../lib/reports/catalogue');
    assert.equal(clientSafe(null), null);
    assert.equal(clientSafe(undefined), null);
  });

  // ── The rail and panel need two more fields per entry ──────────────────
  // Both are OPTIONAL in clientSafe (they default to null / []) so a new
  // report cannot crash the page by omitting them — but a report that reaches
  // the catalogue without them renders as a generic glyph and an empty
  // "what is in the document" block, which looks like a bug in the page rather
  // than a gap in the entry. So the catalogue itself is held to having them.

  it('every report declares a glyph and what the document contains', () => {
    const { REPORTS } = require('../lib/reports/catalogue');
    for (const r of REPORTS) {
      assert.ok(r.icon, `${r.id} has no icon`);
      assert.ok(Array.isArray(r.contents) && r.contents.length >= 3,
        `${r.id} should list at least three things the document contains`);
    }
  });

  it('⛔ the glyphs are DISTINCT — that, not colour, is the rail wayfinding cue', () => {
    const { REPORTS } = require('../lib/reports/catalogue');
    const icons = REPORTS.map((r) => r.icon);
    assert.equal(new Set(icons).size, icons.length, `duplicate glyph: ${icons.join(', ')}`);
  });

  it('⛔ every declared glyph is one the workspace can actually resolve', () => {
    // The catalogue names its glyph as a STRING (it is required from a server
    // component, where a React element cannot cross the boundary). So the name
    // and the lookup live in different files and can drift silently — the
    // fallback would quietly give two reports the same icon, defeating the
    // distinctness above without failing anything.
    const ws = fs.readFileSync(
      path.join(__dirname, '..', 'components', 'reports', 'ReportWorkspace.js'), 'utf8');
    const block = ws.match(/const GLYPHS = \{([\s\S]*?)\}/);
    assert.ok(block, 'GLYPHS map not found in ReportWorkspace.js');
    const known = new Set(block[1].split(',').map((x) => x.trim()).filter(Boolean));
    const { REPORTS } = require('../lib/reports/catalogue');
    for (const r of REPORTS) {
      assert.ok(known.has(r.icon), `${r.id} names ${r.icon}, which GLYPHS does not carry`);
    }
  });

  it('the page hands the client component its tiles', () => {
    assert.match(PAGE, /tilesFor\(/, 'the page must attach per-report tiles');
    assert.match(PAGE, /ReportWorkspace/, 'the page must render the workspace');
  });
});

describe('report stats — the figures shown before you download', () => {
  const { getReportStats, tilesFor } = require('../lib/reports/reportStats');

  // ⛔ THE POINT OF THESE TESTS. Every tile is a number an operator may act on,
  // and the failure that matters is not a wrong count — it is a count rendered
  // confidently when nothing was read. That is this codebase's most-repeated
  // bug, and a Reports page showing a tidy row of zeros would be it in its most
  // reassuring form: "nothing to report" is what a clean fleet looks like.

  it('⛔ returns null when the query fails — NEVER a zero-filled object', async () => {
    const pool = { query: async () => { throw new Error('connection refused'); } };
    assert.equal(await getReportStats(pool), null);
  });

  it('⛔ a null stats object yields NO tiles, not tiles reading zero', () => {
    for (const id of ['executive-summary', 'rule-hygiene', 'vulnerability-posture',
                      'compliance-fleet']) {
      assert.equal(tilesFor(id, null), null, `${id} fabricated tiles from nothing`);
    }
  });

  it('an unknown report id has no tiles rather than guessing a set', () => {
    assert.equal(tilesFor('not-a-report', { devices: 3 }), null);
  });

  it('one round trip — a page must not cost one query per report', async () => {
    let calls = 0;
    const pool = { query: async () => { calls++; return { rows: [{ devices: 16 }] }; } };
    await getReportStats(pool);
    assert.equal(calls, 1);
  });

  it('⛔ the unmeasured tiles carry the hueless tone, not a colour', () => {
    const stats = {
      devices: 16, cve_patch_now: 1, cve_patch_now_devices: 3, cve_scheduled: 32,
      rule_findings: 1132, rules_unmeasured: 233, rules_total: 1757,
      compliance_fails: 74, compliance_devices: 16,
    };
    const hygiene = tilesFor('rule-hygiene', stats);
    const unmeasured = hygiene.filter((t) => /usage data|Of the ruleset/.test(t.label));
    assert.equal(unmeasured.length, 2);
    for (const t of unmeasured) {
      assert.equal(t.tone, 'unmeasured',
        `"${t.label}" is a coverage gap and must not be drawn as good or bad news`);
    }
  });

  it('a zero count still renders as 0 — measured-zero is a real answer', () => {
    // The counterpart to the rule above: the hueless treatment is for what was
    // NOT measured. A genuine zero is evidence and is shown as a number.
    const stats = {
      devices: 16, cve_patch_now: 0, cve_patch_now_devices: 0, cve_scheduled: 0,
      rule_findings: 0, rules_unmeasured: 0, rules_total: 0,
      compliance_fails: 0, compliance_devices: 16,
    };
    const vuln = tilesFor('vulnerability-posture', stats);
    const patchNow = vuln.find((t) => t.label === 'Patch now');
    assert.equal(patchNow.value, '0');
    assert.equal(patchNow.tone, 'ok');
  });

  it('a percentage over a zero denominator is an em-dash, not NaN% or 0%', () => {
    const stats = {
      devices: 0, cve_patch_now: 0, cve_patch_now_devices: 0, cve_scheduled: 0,
      rule_findings: 0, rules_unmeasured: 0, rules_total: 0,
      compliance_fails: 0, compliance_devices: 0,
    };
    const hygiene = tilesFor('rule-hygiene', stats);
    assert.equal(hygiene.find((t) => t.label === 'Of the ruleset').value, '—');
  });
});
