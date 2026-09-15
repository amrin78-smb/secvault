'use strict';
// Pins the one-click "declare this cloud service as an application" action:
// app/api/applications/from-cloud/derive.js (the derivation) and
// .../route.js (the boundary).
//
// ⛔ WHAT THESE TESTS ARE FOR. This action writes a DECLARATION with the
// operator's name on it, and everything else on /applications is later measured
// against that declaration — "this application is broken", "this rule is
// unclaimed", and eventually a rule-cleanup request. So the failure that
// matters here is not a crash. It is a plausible, confident, FABRICATED flow:
// a port nobody published, a destination nobody stated, or a truncated list
// that reads as complete. Every case below is one of those.
//
// ⛔ AND THE ZERO-FLOW CASE IS TESTED AS A SUCCESS, not as an error. Measured
// live, Microsoft publishes urls on 62 of 63 endpoint sets and IP ranges on 10,
// so "nothing could be derived" is the ORDINARY outcome for most services. A
// suite that only asserted the happy path would let that outcome regress into
// an error, or worse into a guess.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const derive = require('../app/api/applications/from-cloud/derive');

const {
  MAX_FLOWS, SRC_PLACEHOLDER_NOTE, CASES,
  parsePortList, findServiceRows, deriveFlows, planFor, buildPlans, labelFor,
} = derive;

const ROOT = path.join(__dirname, '..');
const ROUTE_FILE = path.join(ROOT, 'app', 'api', 'applications', 'from-cloud', 'route.js');
const ROUTE_SRC = fs.readFileSync(ROUTE_FILE, 'utf8');

// A catalogue IP row in the shape lib/feeds/cloudApps.loadCatalogue returns.
const ipRow = (value, extra = {}) => ({
  provider: 'microsoft_365',
  service: 'Exchange',
  service_display: 'Exchange Online',
  kind: 'ip',
  value,
  range_start: 1,
  range_end: 2,
  tcp_ports: null,
  udp_ports: null,
  source_version: '2026081400',
  ...extra,
});

const hostRow = (value, extra = {}) => ({
  provider: 'microsoft_365',
  service: 'Common',
  service_display: 'Microsoft 365 Common and Office Online',
  kind: 'host',
  value,
  source_version: '2026081400',
  ...extra,
});

// ── The published port string ──────────────────────────────────────────────

describe('parsePortList — the REAL published shapes', () => {
  it("reads '80,443' (Microsoft's live value)", () => {
    const r = parsePortList('80,443');
    assert.equal(r.published, true);
    assert.deepEqual(r.ranges, [{ start: 80, end: 80 }, { start: 443, end: 443 }]);
    assert.deepEqual(r.unreadable, []);
  });

  it("reads '143, 587, 993, 995' — SPACES AND ALL", () => {
    // ⛔ The spaces are the point. This is a verbatim live value, and a parser
    // written against the documentation's tidier '143,587,993,995' would file
    // every one of these as unreadable and silently produce no flows for
    // Exchange's mail submission/retrieval ports.
    const r = parsePortList('143, 587, 993, 995');
    assert.equal(r.published, true);
    assert.deepEqual(r.ranges.map((x) => x.start), [143, 587, 993, 995]);
    assert.deepEqual(r.unreadable, []);
  });

  it('a single port is a one-port range, not a bare number', () => {
    assert.deepEqual(parsePortList('443').ranges, [{ start: 443, end: 443 }]);
  });

  it('reads a hyphenated range', () => {
    assert.deepEqual(parsePortList('50000-59999').ranges, [{ start: 50000, end: 59999 }]);
  });

  it('⛔ NO PORTS PUBLISHED is not the same fact as NO PORTS READABLE', () => {
    // The first may become an every-port flow; the second may not become
    // anything at all. Collapsing them is how an unreadable value turns into a
    // confident wide-open declaration.
    for (const empty of [null, undefined, '', '   ']) {
      const r = parsePortList(empty);
      assert.equal(r.published, false, `${JSON.stringify(empty)} should not read as published`);
      assert.deepEqual(r.ranges, []);
    }
    const junk = parsePortList('https');
    assert.equal(junk.published, true, 'the publisher DID state something');
    assert.deepEqual(junk.ranges, []);
  });

  it('⛔ an unreadable token produces NO flow and is COUNTED, never guessed', () => {
    const r = parsePortList('80, https, 443');
    assert.deepEqual(r.ranges, [{ start: 80, end: 80 }, { start: 443, end: 443 }]);
    assert.deepEqual(r.unreadable, ['https']);
    // and nothing invented in its place
    assert.equal(r.ranges.length, 2);
  });

  it('refuses out-of-range and reversed values rather than clamping them', () => {
    assert.deepEqual(parsePortList('0').unreadable, ['0']);
    assert.deepEqual(parsePortList('70000').unreadable, ['70000']);
    assert.deepEqual(parsePortList('900-100').unreadable, ['900-100']);
    for (const v of ['0', '70000', '900-100']) {
      assert.deepEqual(parsePortList(v).ranges, [], `${v} produced a range`);
    }
  });

  it('a trailing comma carries no claim and is not counted as unreadable', () => {
    const r = parsePortList('80,443,');
    assert.equal(r.ranges.length, 2);
    assert.deepEqual(r.unreadable, []);
  });

  it('a repeated port is stored once', () => {
    assert.equal(parsePortList('443,443').ranges.length, 1);
  });
});

// ── Case 1: ranges AND ports ───────────────────────────────────────────────

describe('deriveFlows — the publisher states ranges AND ports', () => {
  const rows = [
    ipRow('52.96.0.0/14', { tcp_ports: '80,443', range_start: 10 }),
    ipRow('40.92.0.0/15', { tcp_ports: '143, 587, 993, 995', range_start: 20 }),
  ];

  it('creates one flow per (prefix x port range)', () => {
    const { flows, derivation } = deriveFlows(rows);
    assert.equal(derivation.case, CASES.PORTS);
    assert.equal(flows.length, 6); // 2 + 4
    assert.equal(derivation.prefixesWithPublishedPorts, 2);
  });

  it('every flow is tcp, allow, from any, on a PUBLISHED port', () => {
    const { flows } = deriveFlows(rows);
    for (const f of flows) {
      assert.equal(f.protocol, 'tcp');
      assert.equal(f.expectation, 'allow');
      assert.equal(f.src, 'any');
      assert.ok([80, 443, 143, 587, 993, 995].includes(f.port_start));
      assert.equal(f.port_start, f.port_end);
    }
    assert.deepEqual(
      [...new Set(flows.map((f) => f.dst))].sort(),
      ['40.92.0.0/15', '52.96.0.0/14']
    );
  });

  it('udp_ports produce udp flows beside the tcp ones', () => {
    const { flows } = deriveFlows([ipRow('13.107.64.0/18', { tcp_ports: '443', udp_ports: '3478,3479' })]);
    assert.deepEqual(
      flows.map((f) => `${f.protocol}/${f.port_start}`).sort(),
      ['tcp/443', 'udp/3478', 'udp/3479']
    );
  });

  it('⛔ every created flow carries the src-placeholder caveat VERBATIM', () => {
    // `src: 'any'` unlabelled reads as a decision somebody made. Only the
    // operator knows which of their networks reaches the service.
    const { flows, derivation } = deriveFlows(rows);
    for (const f of flows) assert.equal(f.note, SRC_PLACEHOLDER_NOTE);
    assert.equal(derivation.srcCaveat, SRC_PLACEHOLDER_NOTE);
    assert.match(SRC_PLACEHOLDER_NOTE, /placeholder/i);
  });

  it('the order is deterministic, so two clicks plan the same declaration', () => {
    const a = deriveFlows(rows).flows.map((f) => `${f.dst}/${f.protocol}/${f.port_start}`);
    const b = deriveFlows([...rows].reverse()).flows.map((f) => `${f.dst}/${f.protocol}/${f.port_start}`);
    assert.deepEqual(a, b);
  });
});

// ── Case 2: ranges, NO ports ───────────────────────────────────────────────

describe('⛔ deriveFlows — ranges but NO published ports yields NULL ports, NOT 443', () => {
  // AWS, Google and Cloudflare publish no ports at all. NULL/NULL is what
  // schema.sql defines as "every port of this protocol" — wider than the truth
  // but STATED. 443 would be narrower and invented, and an operator reviewing
  // the row would have no way to tell which of the two it was.
  const rows = [
    ipRow('3.5.140.0/22', { provider: 'aws', service: 'S3', service_display: 'S3', tcp_ports: null, udp_ports: null }),
  ];

  it('the ports are NULL', () => {
    const { flows, derivation } = deriveFlows(rows);
    assert.equal(derivation.case, CASES.RANGES_ONLY);
    assert.equal(flows.length, 1);
    assert.equal(flows[0].port_start, null);
    assert.equal(flows[0].port_end, null);
  });

  it('443 appears NOWHERE in the derived flow', () => {
    const { flows } = deriveFlows(rows);
    assert.equal(JSON.stringify(flows[0]).includes('443'), false);
  });

  it('nor is a protocol invented — the publisher stated none', () => {
    // Writing 'tcp' here would be the same invention one field to the left.
    const { flows } = deriveFlows(rows);
    assert.equal(flows[0].protocol, 'any');
  });

  it('the destination is still the published prefix', () => {
    assert.equal(deriveFlows(rows).flows[0].dst, '3.5.140.0/22');
  });

  it('a mixed set counts both kinds of prefix separately', () => {
    const { derivation } = deriveFlows([
      ipRow('52.96.0.0/14', { tcp_ports: '443' }),
      ipRow('3.5.140.0/22'),
    ]);
    assert.equal(derivation.case, CASES.PORTS);
    assert.equal(derivation.prefixesWithPublishedPorts, 1);
    assert.equal(derivation.prefixesWithoutPublishedPorts, 1);
  });
});

// ── Case 3: ports published but unreadable ─────────────────────────────────

describe('⛔ deriveFlows — an unreadable port string produces NO flow, counted', () => {
  const rows = [ipRow('52.96.0.0/14', { tcp_ports: 'https and smtp' })];

  it('no flow at all — not an every-port one, and not a guessed 443', () => {
    const { flows, derivation } = deriveFlows(rows);
    assert.deepEqual(flows, []);
    assert.equal(derivation.case, CASES.PORTS_UNREADABLE);
  });

  it('⛔ it does NOT fall back to the no-ports branch', () => {
    // That is the dangerous simplification: "we could not read the ports" would
    // silently become "the publisher stated none", and a declaration opening
    // every port would be created from a value nobody understood.
    const { derivation } = deriveFlows(rows);
    assert.equal(derivation.prefixesWithoutPublishedPorts, 0);
    assert.equal(derivation.prefixesWithUnreadablePorts, 1);
  });

  it('the unreadable value is counted AND reported with what was published', () => {
    const { derivation } = deriveFlows(rows);
    assert.equal(derivation.unreadablePortCount, 1);
    assert.equal(derivation.unreadablePorts[0].prefix, '52.96.0.0/14');
    assert.equal(derivation.unreadablePorts[0].published, 'https and smtp');
    assert.equal(derivation.unreadablePorts[0].protocol, 'tcp');
  });

  it('the reason says the flow was refused rather than guessed', () => {
    const plan = planFor(
      { ips: rows, hosts: [] },
      'microsoft_365',
      'Exchange Online'
    );
    assert.match(plan.derivation.reason, /none of its published port values could be read/i);
    assert.match(plan.derivation.reason, /rather than a guessed one/i);
  });

  it('a partly-unreadable string still yields the readable ports', () => {
    const { flows, derivation } = deriveFlows([ipRow('52.96.0.0/14', { tcp_ports: '80, https, 443' })]);
    assert.deepEqual(flows.map((f) => f.port_start), [80, 443]);
    assert.equal(derivation.unreadablePortCount, 1);
  });
});

// ── Case 4: no ranges at all ───────────────────────────────────────────────

describe('⛔ a service with NO published IP ranges — zero flows is a CORRECT outcome', () => {
  const catalogue = {
    hosts: [hostRow('*.office.com'), hostRow('outlook.office365.com')],
    ips: [],
    summary: { count: 2, lastSeenAt: new Date().toISOString() },
  };

  it('the plan exists, and it plans zero flows', () => {
    const plan = planFor(catalogue, 'microsoft_365', 'Microsoft 365 Common and Office Online');
    assert.ok(plan, 'the pair is in the catalogue and must be declarable');
    assert.deepEqual(plan.flows, []);
    assert.equal(plan.derivation.case, CASES.NO_RANGES);
    assert.equal(plan.derivation.prefixCount, 0);
  });

  it('⛔ it is NOT an error, and nothing in the plan says failure', () => {
    const plan = planFor(catalogue, 'microsoft_365', 'Microsoft 365 Common and Office Online');
    // There is no error field, no throw, and the pair still resolves — and the
    // sentence says in words that this is the correct outcome, so a reader
    // cannot mistake the empty declaration for a broken one.
    assert.equal(plan.derivation.error, undefined);
    assert.match(plan.derivation.reason, /correct outcome, not a failure/i);
  });

  it('the reason STATES that the publisher lists hostnames only', () => {
    // "0 flows" alone reads as a broken feature; with the reason attached it
    // reads as the ordinary outcome it is.
    const plan = planFor(catalogue, 'microsoft_365', 'Microsoft 365 Common and Office Online');
    assert.match(plan.derivation.reason, /hostname/i);
    assert.match(plan.derivation.reason, /no IP ranges/i);
  });

  it('the button says so BEFORE it is clicked', () => {
    const plan = planFor(catalogue, 'microsoft_365', 'Microsoft 365 Common and Office Online');
    assert.match(plan.derivation.buttonLabel, /no flows can be derived/i);
  });
});

// ── The cap ────────────────────────────────────────────────────────────────

describe('⛔ the flow cap is enforced AND disclosed', () => {
  // Live: AWS's 'AMAZON' service area alone carries 5,969 IPv4 prefixes. A
  // declaration nobody can review is not a declaration — but a truncated list
  // that looks complete is worse, because the operator works to the bottom and
  // believes they are finished.
  const many = [];
  for (let i = 0; i < 120; i += 1) {
    many.push(ipRow(`10.${i}.0.0/16`, { tcp_ports: '80,443', range_start: i * 65536 }));
  }

  it('stops at the cap', () => {
    const { flows, derivation } = deriveFlows(many);
    assert.equal(flows.length, MAX_FLOWS);
    assert.equal(derivation.plannedFlowCount, MAX_FLOWS);
    assert.equal(derivation.cap, MAX_FLOWS);
  });

  it('discloses the total it could have made, and how many it did not', () => {
    const { derivation } = deriveFlows(many);
    assert.equal(derivation.candidateFlowCount, 240);
    assert.equal(derivation.capped, true);
    assert.equal(derivation.omittedByCap, 240 - MAX_FLOWS);
  });

  it('⛔ the truncation is stated in the sentence a person reads', () => {
    const plan = planFor({ hosts: [], ips: many }, 'microsoft_365', 'Exchange Online');
    assert.match(plan.derivation.reason, new RegExp(`${240 - MAX_FLOWS} further flows`));
    assert.match(plan.derivation.reason, new RegExp(`stops at ${MAX_FLOWS}`));
  });

  it('an uncapped result never claims it was capped', () => {
    const { derivation } = deriveFlows([ipRow('52.96.0.0/14', { tcp_ports: '443' })]);
    assert.equal(derivation.capped, false);
    assert.equal(derivation.omittedByCap, 0);
    assert.equal(/further flow/.test(derivation.reason || ''), false);
  });

  it('the cap is a fixed safety limit, not a tuning knob on the request', () => {
    // The route passes no cap; only an in-process caller can lower it, and it
    // can never be raised out of a request body into an unreviewable pile.
    assert.equal(/cap\s*:/.test(ROUTE_SRC), false, 'the route sets its own cap');
    assert.equal(typeof MAX_FLOWS, 'number');
    assert.ok(MAX_FLOWS > 0 && MAX_FLOWS <= 100);
  });
});

// ── Catalogue validation ───────────────────────────────────────────────────

describe('⛔ the (provider, service) pair is validated against the catalogue', () => {
  const catalogue = {
    hosts: [hostRow('*.office.com')],
    ips: [ipRow('52.96.0.0/14', { tcp_ports: '80,443' })],
    summary: { count: 2 },
  };

  it('an unknown provider has no plan at all', () => {
    assert.equal(planFor(catalogue, 'oracle_cloud', 'Anything'), null);
    assert.equal(findServiceRows(catalogue, 'oracle_cloud', 'Anything'), null);
  });

  it('an unknown service under a known provider has no plan either', () => {
    assert.equal(planFor(catalogue, 'microsoft_365', 'Dynamics 365'), null);
  });

  it('a blank provider is refused rather than matching everything', () => {
    assert.equal(planFor(catalogue, '', ''), null);
  });

  it('the display name and the raw key both resolve to the same rows', () => {
    const byDisplay = findServiceRows(catalogue, 'microsoft_365', 'Exchange Online');
    const byKey = findServiceRows(catalogue, 'microsoft_365', 'Exchange');
    assert.equal(byDisplay.ipRows.length, 1);
    assert.deepEqual(byKey.ipRows.map((r) => r.value), byDisplay.ipRows.map((r) => r.value));
  });

  it('an absent service matches only rows that genuinely have none', () => {
    // Cloudflare publishes no service breakdown at all; its rows carry a NULL
    // service BY DESIGN, and coercing that to a string would make the provider
    // undeclarable.
    const cf = {
      hosts: [],
      ips: [{ provider: 'cloudflare', service: null, service_display: null, kind: 'ip', value: '1.1.1.0/24', range_start: 1, range_end: 2 }],
      summary: { count: 1 },
    };
    const plan = planFor(cf, 'cloudflare', '');
    assert.ok(plan);
    assert.equal(plan.service, null);
    assert.equal(plan.label, 'Cloudflare');
    // and the Microsoft rows are NOT swept in by an empty service
    assert.equal(findServiceRows(catalogue, 'microsoft_365', ''), null);
  });

  it('the application name is the catalogue label, character for character', () => {
    // applications.name is UNIQUE, so a label that drifts by one character
    // creates a duplicate declaration instead of the 409 the operator needs.
    const { providerLabel } = require('../lib/engines/cloudApps');
    const expected = `${providerLabel('microsoft_365')} — Exchange Online`;
    assert.equal(labelFor('microsoft_365', 'Exchange Online'), expected);
    assert.equal(planFor(catalogue, 'microsoft_365', 'Exchange').label, expected);
  });

  it('buildPlans covers every pair in the catalogue exactly once', () => {
    const plans = buildPlans(catalogue);
    assert.equal(plans.length, 2); // Common (hosts) + Exchange Online (ips)
    assert.deepEqual(
      plans.map((p) => p.service).sort(),
      ['Exchange Online', 'Microsoft 365 Common and Office Online']
    );
  });
});

// ── The route boundary ─────────────────────────────────────────────────────
//
// Source-scanned, the same way tests/applicationRoutes.test.js does it: there
// is no HTTP harness in this repo and package.json deliberately carries no
// devDependencies. What needs pinning is the access boundary and the honesty of
// the response, and both are visible in the source.

describe('⛔ POST /api/applications/from-cloud', () => {
  it('gates on OPERATE, through can() and forbiddenResponse()', () => {
    assert.match(ROUTE_SRC, /can\(session,\s*OPERATE\)/);
    assert.match(ROUTE_SRC, /forbiddenResponse\(OPERATE\)/);
    assert.match(ROUTE_SRC, /getServerSession\(authOptions\)/);
  });

  it('gates BEFORE it reads the catalogue or writes anything', () => {
    const gate = ROUTE_SRC.search(/can\(session,\s*OPERATE\)/);
    const work = ROUTE_SRC.search(/loadDeclarationCatalogue\(|createApplication\(|addFlow\(/);
    assert.ok(gate > -1 && work > -1 && gate < work,
      'the capability check runs after the work — by then it is done');
  });

  it('⛔ validates the pair against the catalogue and 400s an unknown one', () => {
    // Trusting the body would create an application named after a service no
    // publisher lists, which can never match anything — and the operator would
    // read that as "my rules are missing".
    assert.match(ROUTE_SRC, /planFor\(catalogue, provider, service\)/);
    assert.match(ROUTE_SRC, /if \(!plan\)/);
    assert.match(ROUTE_SRC, /status: 400/);
    const validate = ROUTE_SRC.search(/planFor\(/);
    const create = ROUTE_SRC.search(/createApplication\(/);
    assert.ok(validate < create, 'the application is created before the pair is validated');
  });

  it('a duplicate name is a 409, not a 500', () => {
    assert.match(ROUTE_SRC, /23505/);
    assert.match(ROUTE_SRC, /status: 409/);
  });

  it('⛔ REUSES the engine rather than writing its own INSERT', () => {
    // addFlow validates each flow with the same parser that will later evaluate
    // it, which is what stops an unusable row being stored at all.
    assert.match(ROUTE_SRC, /from '\.\.\/\.\.\/\.\.\/\.\.\/lib\/engines\/applicationViewData'/);
    assert.match(ROUTE_SRC, /createApplication,\s*addFlow/);
    assert.equal(/INSERT\s+INTO/i.test(ROUTE_SRC), false, 'the route writes its own SQL');
    assert.equal(/pool\.query/.test(ROUTE_SRC), false, 'the route queries directly');
    const engine = require('../lib/engines/applicationViewData');
    assert.equal(typeof engine.createApplication, 'function');
    assert.equal(typeof engine.addFlow, 'function');
  });

  it('⛔ a partial flow failure is REPORTED, not pretended away', () => {
    // The application genuinely exists by then; claiming otherwise leaves the
    // operator with a row they cannot see and cannot delete.
    assert.match(ROUTE_SRC, /failed\.push/);
    assert.match(ROUTE_SRC, /failedFlowCount/);
    assert.match(ROUTE_SRC, /partial:/);
  });

  it('the whole derivation travels with the result', () => {
    for (const field of ['derivation', 'createdFlowCount', 'srcCaveat']) {
      assert.ok(
        ROUTE_SRC.includes(field) || JSON.stringify(deriveFlows([]).derivation).includes(field),
        `${field} is not carried back to the caller`
      );
    }
  });

  it('exports force-dynamic and nothing but its handler', () => {
    assert.match(ROUTE_SRC, /export const dynamic = 'force-dynamic'/);
    const exported = [...ROUTE_SRC.matchAll(/export\s+(?:async\s+)?(?:function|const)\s+(\w+)/g)]
      .map((m) => m[1]);
    assert.deepEqual(exported.sort(), ['POST', 'dynamic']);
    assert.equal(/export\s+default/.test(ROUTE_SRC), false);
  });

  it('records the action in the activity log, without letting it break the write', () => {
    assert.match(ROUTE_SRC, /logActivity\(/);
    assert.match(ROUTE_SRC, /try\s*\{[\s\S]{0,500}logActivity\([\s\S]{0,500}\}\s*catch/);
  });

  it('surfaces a thrown failure rather than an empty 200', () => {
    assert.match(ROUTE_SRC, /catch\s*\(\s*err\s*\)/);
    assert.match(ROUTE_SRC, /status: 500/);
    assert.match(ROUTE_SRC, /error:\s*err\.message/);
  });
});

// ── The UI promise ─────────────────────────────────────────────────────────

describe('⛔ the control states its effect before it is clicked', () => {
  const DECLARE = fs.readFileSync(
    path.join(ROOT, 'components', 'applications', 'DeclareCloudApp.js'), 'utf8'
  );
  const SECTION = fs.readFileSync(
    path.join(ROOT, 'components', 'applications', 'CloudServices.js'), 'utf8'
  );

  it('the button label comes from the server-built plan, not from the click', () => {
    assert.match(DECLARE, /plan\.buttonLabel/);
    assert.match(DECLARE, /plan\.reason/);
  });

  it('⛔ the src-placeholder caveat is shown after success', () => {
    assert.match(DECLARE, /srcCaveat/);
  });

  it('the client island is the ONLY client part — the section stays server-rendered', () => {
    assert.match(DECLARE, /^'use client';/);
    assert.equal(/'use client'/.test(SECTION), false,
      'CloudServices became a client component');
    assert.match(SECTION, /import DeclareCloudApp/);
  });

  it('the plan is derived by the SAME module the route writes from', () => {
    // Two derivations would drift, and the one that drifted would be the
    // preview — promising flows the write does not create.
    assert.match(SECTION, /from-cloud\/derive/);
    assert.match(ROUTE_SRC, /from '\.\/derive'/);
  });

  it('no hardcoded hex anywhere in either file', () => {
    for (const [name, src] of [['DeclareCloudApp.js', DECLARE], ['CloudServices.js', SECTION]]) {
      assert.equal(/#[0-9a-fA-F]{3,8}\b/.test(src), false, `${name} hardcodes a colour`);
    }
  });

  it('no React component is defined inside another', () => {
    // The rule that costs input focus on every keystroke when it is broken.
    const inner = /function\s+\w+\([\s\S]{0,200}?\)\s*\{[\s\S]*?\n\s+function\s+[A-Z]\w*\s*\(/;
    assert.equal(inner.test(DECLARE), false);
  });
});
