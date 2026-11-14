// tests/calmFromUnreadData.test.js
//
// Two surfaces that asserted calm or completeness from a read they did not
// consult:
//
//   (a) components/dashboard/SecurityLogWidgets.js — TopThreatsWidget awaited
//       getThreatCoverage() into `coverage` and NEVER REFERENCED IT, printing a
//       flat "No named threats in the last 24 hours." where its three siblings
//       render <ThreatEmpty coverage={...}/>. lib/syslog/threatStats.js names
//       that exact shape as what the coverage read exists to prevent: "a
//       security dashboard asserting calm because its own aggregation has not
//       run … it was the live state for the first minutes after the rollup
//       shipped". DeviceThreatTable never fetched coverage at all, although
//       getDeviceThreatSummary()'s own comment delegates the no-coverage case
//       to "the widget, not … a NULL here", and closed with the fleet-wide
//       all-clear "No device reported any threat events in this window."
//
//   (b) components/devices/OverviewComplianceCard.js — six compliance donuts
//       with no gradeable-check denominator, calling neither
//       buildDeviceCoverage() nor deviceCoverageEvidence(), the machinery
//       v2.225.0 added for exactly this and that /compliance/[deviceId] has
//       carried since. So the first tab opened for a firewall showed a bare
//       percentage and the page one click away showed the same assessment WITH
//       its basis — two screens disagreeing about what the number is worth.
//
// ⛔ WHY THESE RENDER THE COMPONENTS RATHER THAN SCANNING THEIR SOURCE. Both
// wrong answers are CONFIDENT, PLAUSIBLE SENTENCES on screen, not a missing
// guard visible in a line of source — and CLAUDE.md records three features
// that shipped broken past tests asserting the MECHANISM instead of the
// OUTCOME (the MFA field marked `hidden` and fully visible, the
// `useState(false)` default, the attribute check that passed while the box was
// on screen). A test asserting "getThreatCoverage is called" would have passed
// against the defect being fixed here, because it WAS called. So these read
// the words that render.
//
// ⛔ EVERY CASE INCLUDES THE "WE COULD NOT MEASURE THIS" ARM. That is the one
// that regresses silently, because its wrong answer is a reassuring sentence
// rather than a crash.
//
// The JSX is compiled with the parser tests/jsxSyntax.test.js already uses
// (`next/dist/build/swc`, a runtime dependency), exactly as
// tests/topFailingControls.test.js and tests/deltaBadge.test.js do —
// package.json deliberately has no devDependencies.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

const REPO = path.resolve(__dirname, '..');

/** Compile-on-require for the app's own ESM+JSX. */
function installRenderHooks() {
  const swc = require('next/dist/build/swc');
  const origExt = Module._extensions['.js'];
  Module._extensions['.js'] = function (mod, filename) {
    if (filename.split(path.sep).join('/').includes('/node_modules/')) {
      return origExt(mod, filename);
    }
    const out = swc.transformSync(fs.readFileSync(filename, 'utf8'), {
      filename,
      jsc: {
        parser: { syntax: 'ecmascript', jsx: true },
        target: 'es2020',
        transform: { react: { runtime: 'automatic' } },
      },
      module: { type: 'commonjs' },
    });
    return mod._compile(out.code, filename);
  };
}

// ⛔ THE POOL IS STUBBED, NOT CONNECTED. `lib/db` is pre-seeded into
// require.cache so the singleton Pool is never constructed and nothing in this
// suite can reach a database. `handler` is swapped per case, which is what lets
// one loaded module answer a swept rollup, an unswept one and a throwing read.
let handler = () => {
  throw new Error('no query handler installed for this case');
};
const stubPool = { query: (sql, params) => handler(sql, params) };

function seedDbStub() {
  const dbPath = require.resolve(path.join(REPO, 'lib', 'db.js'));
  const m = new Module(dbPath, null);
  m.filename = dbPath;
  m.loaded = true;
  m.exports = { pool: stubPool };
  require.cache[dbPath] = m;
}

// `*_COMPONENT` lets the mutation run point this suite at a scratchpad copy.
const WIDGETS = process.env.CALM_WIDGETS || path.join(REPO, 'components', 'dashboard', 'SecurityLogWidgets.js');
const CARD = process.env.CALM_CARD || path.join(REPO, 'components', 'devices', 'OverviewComplianceCard.js');

let React = null;
let renderToStaticMarkup = null;
let widgets = null;
let OverviewComplianceCard = null;
let coverageEngine = null;
let loadError = null;
try {
  installRenderHooks();
  seedDbStub();
  React = require('react');
  ({ renderToStaticMarkup } = require('react-dom/server'));
  coverageEngine = require(path.join(REPO, 'lib', 'engines', 'complianceCoverage.js'));
  widgets = require(WIDGETS);
  OverviewComplianceCard = require(CARD).default;
} catch (err) {
  // Reported as a failure rather than skipped: a suite that quietly stops
  // checking is the same shape of problem as the bugs it covers.
  loadError = err;
}

/** Every word a reader sees, tags stripped and entities decoded. */
function words(markup) {
  return String(markup)
    .replace(/<[^>]+>/g, ' ')
    .replace(/&#x27;|&apos;/g, "'")
    .replace(/&#x2019;|&rsquo;/g, '’')
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, '&')
    .replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Renders an async server component to the words it puts on screen. */
async function renderAsync(Component, props) {
  assert.ok(Component, 'could not load the component under test: '
    + (loadError ? loadError.stack : 'unknown'));
  const tree = await Component(props || {});
  return words(renderToStaticMarkup(tree));
}

// ── (a) the threat widgets ─────────────────────────────────────────────────

/** The sentence the defect printed. Calm, and true only over a swept rollup. */
const CALM_THREATS = 'No named threats in the last 24 hours';
/** The fleet-wide all-clear DeviceThreatTable printed. */
const CALM_FLEET = 'No device reported any threat events in this window';
/** The hueless gap every coverage-aware empty state renders instead. */
const GAP = 'Not measured';

/**
 * A pool that answers getThreatCoverage() with the given hours and every other
 * query with no rows.
 *
 * ⛔ The coverage object is built by the REAL getThreatCoverage() against this
 * stub, never hand-written — a hand-written shape cannot fail when the engine's
 * output changes, so it would keep passing while the widget was handed
 * something else entirely.
 *
 * @param {number|null} sweptHours   hours the rollup sweep covered; null means
 *   the coverage query returned NO ROW AT ALL, i.e. the read did not land.
 * @param {number} aggregatedHours   hours with threat buckets
 */
function threatPool({ sweptHours, aggregatedHours = 0, rows = [] }) {
  return (sql) => {
    // `swept_hours` appears only in getThreatCoverage()'s own statement.
    if (/swept_hours/.test(sql)) {
      if (sweptHours === null) return { rows: [] };
      return { rows: [{ swept_hours: sweptHours, aggregated_hours: aggregatedHours }] };
    }
    return { rows };
  };
}

/** One active device with no threat events — the all-zero fleet. */
const QUIET_DEVICE_ROWS = [
  { device_id: 'dev-1', name: 'FW-1', vendor: 'fortinet', threat_events: '0', attackers: '0', distinct_threats: '0', last_threat: null },
];

describe('(a) threat widgets: an unswept rollup may not read as calm', () => {
  it('TopThreatsWidget renders the gap, not the calm sentence, when nothing was aggregated', async () => {
    handler = threatPool({ sweptHours: 0, aggregatedHours: 0 });
    const text = await renderAsync(widgets.TopThreatsWidget);
    assert.ok(text.includes(GAP), `expected the unmeasured state, got: ${text}`);
    assert.ok(
      /not a report of zero threats/i.test(text),
      `the gap must say outright that it is not a zero: ${text}`
    );
    assert.ok(
      !text.includes(CALM_THREATS),
      `an unswept rollup rendered the calm sentence: ${text}`
    );
  });

  it('TopThreatsWidget renders the calm sentence when the window WAS fully aggregated', async () => {
    handler = threatPool({ sweptHours: 24, aggregatedHours: 24 });
    const text = await renderAsync(widgets.TopThreatsWidget);
    assert.ok(text.includes(CALM_THREATS), `a measured zero must still be reported: ${text}`);
    assert.ok(!text.includes(GAP), `a measured zero must not be hedged: ${text}`);
    // The explanation of where signature names come from survived the swap.
    assert.ok(/IPS, antivirus and URL-filtering/.test(text), text);
  });

  it('TopThreatsWidget states partial coverage beside the calm sentence', async () => {
    handler = threatPool({ sweptHours: 24, aggregatedHours: 6 });
    const text = await renderAsync(widgets.TopThreatsWidget);
    assert.ok(text.includes(CALM_THREATS), text);
    assert.ok(
      /covers 6 of the last 24 hours/.test(text),
      `partial coverage must be stated, not swallowed: ${text}`
    );
  });

  it('TopThreatsWidget now answers an unswept rollup the SAME WAY as its siblings', async () => {
    handler = threatPool({ sweptHours: 0, aggregatedHours: 0 });
    const threats = await renderAsync(widgets.TopThreatsWidget);
    const attackers = await renderAsync(widgets.TopAttackersWidget);
    const targets = await renderAsync(widgets.TopTargetsWidget);
    const severity = await renderAsync(widgets.ThreatSeverityWidget);
    for (const [name, text] of [['attackers', attackers], ['targets', targets], ['severity', severity]]) {
      assert.ok(text.includes(GAP), `sibling ${name} should already render the gap: ${text}`);
    }
    // The shared sentence, not merely a shared verdict: the four widgets print
    // one explanation of the gap, so an operator cannot read one as softer.
    const shared = 'It fills in once the collector’s next rollup sweep completes';
    for (const [name, text] of [['threats', threats], ['attackers', attackers], ['targets', targets], ['severity', severity]]) {
      assert.ok(text.includes(shared), `${name} is missing the shared gap sentence: ${text}`);
    }
  });

  it('a coverage read that returned NO ROW is unknown, and unknown renders the gap', async () => {
    // ⛔ The "we could not measure this" arm. rows[0] is absent, so
    // getThreatCoverage() reports evaluable:false — never a swept window.
    handler = threatPool({ sweptHours: null });
    const text = await renderAsync(widgets.TopThreatsWidget);
    assert.ok(text.includes(GAP), text);
    assert.ok(!text.includes(CALM_THREATS), `an unreadable coverage read rendered calm: ${text}`);
  });

  it('a coverage read that THROWS cannot produce the calm sentence either', async () => {
    // Loud beats plausible: the widget rejects rather than rendering a zero.
    handler = (sql) => {
      if (/swept_hours/.test(sql)) throw new Error('relation "syslog_rollup_hourly" does not exist');
      return { rows: [] };
    };
    await assert.rejects(
      () => renderAsync(widgets.TopThreatsWidget),
      /syslog_rollup_hourly/,
      'a failed coverage read must not be swallowed into a calm render'
    );
  });

  it('DeviceThreatTable withholds the fleet all-clear when nothing was aggregated', async () => {
    handler = threatPool({ sweptHours: 0, aggregatedHours: 0, rows: QUIET_DEVICE_ROWS });
    const text = await renderAsync(widgets.DeviceThreatTable);
    assert.ok(
      !text.includes(CALM_FLEET),
      `an unswept rollup produced a fleet-wide all-clear: ${text}`
    );
    assert.ok(text.includes(GAP), text);
    assert.ok(
      /every dash above is an absent measurement/i.test(text),
      `the dashes must be named as absent measurements: ${text}`
    );
  });

  it('DeviceThreatTable gives the fleet all-clear only over a swept window', async () => {
    handler = threatPool({ sweptHours: 24, aggregatedHours: 24, rows: QUIET_DEVICE_ROWS });
    const text = await renderAsync(widgets.DeviceThreatTable);
    assert.ok(text.includes(CALM_FLEET), `a measured quiet fleet must still be reported: ${text}`);
    assert.ok(!text.includes(GAP), text);
  });

  it('DeviceThreatTable states partial coverage beside the all-clear', async () => {
    handler = threatPool({ sweptHours: 24, aggregatedHours: 9, rows: QUIET_DEVICE_ROWS });
    const text = await renderAsync(widgets.DeviceThreatTable);
    assert.ok(text.includes(CALM_FLEET), text);
    assert.ok(/9 of 24 hours/.test(text), `partial coverage must be stated: ${text}`);
  });

  // ⛔ THE DEFENSIVE ARM, RENDERED DIRECTLY. No widget can be made to hand
  // these components an absent coverage object, so this is the only place the
  // "a caller forgot the read" default can be held to. A mutation that flips it
  // to "absent reads as swept" survives every test above.
  describe('an absent or malformed coverage object defaults to the gap, never to calm', () => {
    const el = (Component, props) => words(renderToStaticMarkup(React.createElement(Component, props)));

    for (const [label, coverage] of [
      ['null', null],
      ['undefined', undefined],
      ['an empty object', {}],
      ['evaluable missing', { aggregatedHours: 24, windowHours: 24 }],
      ['evaluable not a boolean', { evaluable: 'yes', aggregatedHours: 24, windowHours: 24 }],
    ]) {
      it(`ThreatEmpty renders the gap when coverage is ${label}`, () => {
        assert.ok(widgets.ThreatEmpty, 'ThreatEmpty must be exported for this to be testable');
        const text = el(widgets.ThreatEmpty, { coverage, measured: CALM_THREATS });
        assert.ok(text.includes(GAP), `coverage ${label} rendered something other than the gap: ${text}`);
        assert.ok(!text.includes(CALM_THREATS), `coverage ${label} rendered calm: ${text}`);
      });

      it(`FleetThreatEmptyNote renders the gap when coverage is ${label}`, () => {
        assert.ok(widgets.FleetThreatEmptyNote, 'FleetThreatEmptyNote must be exported');
        const text = el(widgets.FleetThreatEmptyNote, { coverage });
        assert.ok(text.includes(GAP), `coverage ${label} rendered something other than the gap: ${text}`);
        assert.ok(!text.includes(CALM_FLEET), `coverage ${label} rendered the fleet all-clear: ${text}`);
      });
    }

    it('a truthy evaluable still reports the measured answer', () => {
      const text = el(widgets.FleetThreatEmptyNote, {
        coverage: { evaluable: true, aggregatedHours: 24, windowHours: 24 },
      });
      assert.ok(text.includes(CALM_FLEET), text);
    });
  });

  it('DeviceThreatTable says nothing about coverage when a device DID report threats', async () => {
    handler = threatPool({
      sweptHours: 24,
      aggregatedHours: 24,
      rows: [{ ...QUIET_DEVICE_ROWS[0], threat_events: '412', attackers: '7', distinct_threats: '3' }],
    });
    const text = await renderAsync(widgets.DeviceThreatTable);
    assert.ok(!text.includes(CALM_FLEET), text);
    assert.ok(!text.includes(GAP), text);
    assert.ok(/412/.test(text), text);
  });
});

// ── (b) the overview compliance card ───────────────────────────────────────

/**
 * A pool for OverviewComplianceCard: the device row, the findings, and the
 * applicable/library check counts.
 *
 * @param {object} o
 * @param {{name:string,vendor:string}|null|'throw'} o.device
 * @param {{check_slug:string,standards:string[],status:string}[]} o.findings
 * @param {{applicable:number,library_total:number}|'throw'} o.library
 */
function cardPool({ device, findings = [], library }) {
  return (sql) => {
    if (/FROM devices WHERE id/.test(sql)) {
      if (device === 'throw') throw new Error('devices read failed');
      return { rows: device ? [device] : [] };
    }
    if (/FROM audit_checks WHERE vendor IS NULL/.test(sql)) {
      if (library === 'throw') throw new Error('audit_checks read failed');
      return { rows: library ? [library] : [] };
    }
    if (/FROM audit_findings/.test(sql)) {
      return { rows: findings };
    }
    throw new Error(`unexpected query: ${sql.slice(0, 80)}`);
  };
}

/**
 * n checks mapped to one or more standards with a fixed pass/fail split.
 * Slugs are unique across calls so the DISTINCT-check counts are real.
 *
 * ⛔ `standards` IS AN ARRAY BECAUSE audit_checks.standards IS ONE. A fixture
 * that only ever maps a check to a single standard makes a finding ROW and a
 * CHECK coincide, and that is precisely what hides the two-units confusion the
 * card has to avoid — so one case below deliberately maps every check to three.
 */
let slugSeq = 0;
function checks(standards, pass, fail) {
  const list = Array.isArray(standards) ? standards : [standards];
  const out = [];
  for (let i = 0; i < pass; i += 1) {
    out.push({ check_slug: `chk-${(slugSeq += 1)}`, standards: list, status: 'pass' });
  }
  for (let i = 0; i < fail; i += 1) {
    out.push({ check_slug: `chk-${(slugSeq += 1)}`, standards: list, status: 'fail' });
  }
  return out;
}

// ⛔ FIXTURE SHAPES MEASURED, NOT INVENTED. secvault_mock, 2026-11-15, a
// 74-check library: MOCK-SANGFOR-Branch-06 scores on 9 gradeable checks of 19
// applicable and is the fleet's HIGHEST score, while a fortinet admits 28.
const LIBRARY_TOTAL = 74;
const SANGFOR_APPLICABLE = 19;
const FORTINET_APPLICABLE = 28;
const ASA_APPLICABLE = 13;

// Per-standard 50% and 75% -> blended 63%. The DEVICE-WIDE score over the same
// findings is 4/6 = 67%, which appears nowhere on the card — which is the whole
// reason the strip is handed the blend and not the device-wide figure.
const THIN_FINDINGS = () => [...checks('PCI_DSS', 1, 1), ...checks('ISO_27001', 3, 1)];
// The SAME per-standard percentages (50% and 75%, blend 63%) over four times
// as many checks: every donut on the card is identical, the basis is not.
const BROAD_FINDINGS = () => [...checks('PCI_DSS', 5, 5), ...checks('ISO_27001', 12, 4)];

describe('(b) overview compliance card: a score renders with its denominator', () => {
  it('states how many checks the figure rests on, and which vendor decides that', async () => {
    handler = cardPool({
      device: { name: 'MOCK-SANGFOR-Branch-06', vendor: 'sangfor' },
      findings: THIN_FINDINGS(),
      library: { applicable: SANGFOR_APPLICABLE, library_total: LIBRARY_TOTAL },
    });
    const text = await renderAsync(OverviewComplianceCard, { deviceId: 'dev-1' });
    assert.ok(
      text.includes(`${SANGFOR_APPLICABLE} of ${LIBRARY_TOTAL} SecVault checks`),
      `the denominator must be on the card: ${text}`
    );
    assert.ok(/rests on 6 checks/.test(text), `the gradeable count must be stated: ${text}`);
    assert.ok(/Sangfor/.test(text), `the vendor that decides the denominator must be named: ${text}`);
    assert.ok(
      text.includes(coverageEngine.GRADE_LABEL.thin),
      `six gradeable checks is thin evidence: ${text}`
    );
  });

  it('⛔ qualifies the percentage that is ON the card, never a second one', async () => {
    handler = cardPool({
      device: { name: 'MOCK-SANGFOR-Branch-06', vendor: 'sangfor' },
      findings: THIN_FINDINGS(),
      library: { applicable: SANGFOR_APPLICABLE, library_total: LIBRARY_TOTAL },
    });
    const text = await renderAsync(OverviewComplianceCard, { deviceId: 'dev-1' });
    // The blended average, which is the headline donut.
    assert.ok(/the 63% rests on 6 checks/.test(text), `the strip must restate the card's own figure: ${text}`);
    // ⛔ The DEVICE-WIDE score over the same findings (4 pass of 6 gradeable =
    // 67%). CLAUDE.md forbids a second compliance percentage on the same screen
    // as the headline score, so this number may not appear anywhere.
    assert.ok(!/67%/.test(text), `a rival compliance percentage appeared: ${text}`);
  });

  it('⛔ two firewalls with IDENTICAL donuts no longer render identically', async () => {
    handler = cardPool({
      device: { name: 'FW-THIN', vendor: 'sangfor' },
      findings: THIN_FINDINGS(),
      library: { applicable: SANGFOR_APPLICABLE, library_total: LIBRARY_TOTAL },
    });
    const thin = await renderAsync(OverviewComplianceCard, { deviceId: 'dev-thin' });

    handler = cardPool({
      device: { name: 'FW-BROAD', vendor: 'fortinet' },
      findings: BROAD_FINDINGS(),
      library: { applicable: FORTINET_APPLICABLE, library_total: LIBRARY_TOTAL },
    });
    const broad = await renderAsync(OverviewComplianceCard, { deviceId: 'dev-broad' });

    // Same blended score, same per-standard scores: every donut is the same.
    assert.ok(/the 63% rests on 6 checks/.test(thin), thin);
    assert.ok(/the 63% rests on 26 checks/.test(broad), broad);
    // ...and the evidence grades differ, which is the regression: before the
    // fix these two cards were indistinguishable.
    assert.ok(thin.includes(coverageEngine.GRADE_LABEL.thin), thin);
    assert.ok(broad.includes(coverageEngine.GRADE_LABEL.broad), broad);
    assert.notEqual(
      thin.includes(coverageEngine.GRADE_LABEL.thin),
      broad.includes(coverageEngine.GRADE_LABEL.thin),
      'the two firewalls must not share an evidence grade'
    );
  });

  it('⛔ counts DISTINCT CHECKS, not finding rows summed across standards', async () => {
    // 6 checks, each mapped to THREE standards, so audit_findings yields 6 rows
    // but aggregateStandards() counts 18. Handing the coverage engine 18 would
    // print "rests on 18 checks" — plausible, under the 19 the vendor admits,
    // and wrong. CLAUDE.md: "two units, kept apart".
    const multi = [...checks(['PCI_DSS', 'ISO_27001', 'CIS_V8'], 4, 2)];
    assert.equal(multi.length, 6, 'fixture sanity: six checks');
    assert.equal(
      multi.reduce((n, f) => n + f.standards.length, 0),
      18,
      'fixture sanity: eighteen per-standard rows'
    );
    handler = cardPool({
      device: { name: 'FW-MULTI', vendor: 'sangfor' },
      findings: multi,
      library: { applicable: SANGFOR_APPLICABLE, library_total: LIBRARY_TOTAL },
    });
    const text = await renderAsync(OverviewComplianceCard, { deviceId: 'dev-multi' });
    assert.ok(/rests on 6 checks/.test(text), `the distinct-check count must be stated: ${text}`);
    assert.ok(!/rests on 18 checks/.test(text), `the per-standard row count was printed: ${text}`);
    assert.ok(!/18 checks/.test(text), text);
  });

  it('⛔ an `na` check is EVALUATED but not ANSWERED, and only the answered count grades', async () => {
    // ⛔ Without an `na` in the fixture, evaluatedChecks and answeredChecks are
    // the same number and swapping one for the other is invisible — which is
    // the whole distinction CLAUDE.md's `warning` vs `na` rule turns on: `na`
    // is a fact about SECVAULT and is dropped from the denominator.
    const na = [];
    for (let i = 0; i < 4; i += 1) {
      na.push({ check_slug: `na-${(slugSeq += 1)}`, standards: ['PCI_DSS'], status: 'na' });
    }
    handler = cardPool({
      device: { name: 'FW-NA', vendor: 'sangfor' },
      findings: [...THIN_FINDINGS(), ...na],
      library: { applicable: SANGFOR_APPLICABLE, library_total: LIBRARY_TOTAL },
    });
    const text = await renderAsync(OverviewComplianceCard, { deviceId: 'dev-na' });
    assert.ok(/10 ran/.test(text), `all ten checks ran: ${text}`);
    assert.ok(
      /4 could not be assessed at all and are excluded from the score/.test(text),
      `the excluded checks must be named: ${text}`
    );
    assert.ok(/rests on 6 checks/.test(text), `only the gradeable six may grade it: ${text}`);
    assert.ok(!/rests on 10 checks/.test(text), `an na check was counted as gradeable: ${text}`);
  });

  it('⛔ a duplicated (device, check) finding row counts once', async () => {
    // audit_findings carries no UNIQUE(device_id, check_id), so a row can
    // repeat — and a count of ROWS rather than DISTINCT CHECKS then overstates
    // the basis, which is the more dangerous direction (a thin assessment
    // reading as a thorough one).
    const base = THIN_FINDINGS();
    const dupes = [base[0], base[0], base[1], base[1]];
    handler = cardPool({
      device: { name: 'FW-DUP', vendor: 'sangfor' },
      findings: [...base, ...dupes],
      library: { applicable: SANGFOR_APPLICABLE, library_total: LIBRARY_TOTAL },
    });
    const text = await renderAsync(OverviewComplianceCard, { deviceId: 'dev-dup' });
    assert.ok(/rests on 6 checks/.test(text), `duplicates must collapse: ${text}`);
    assert.ok(!/rests on 10 checks/.test(text), `rows were counted instead of checks: ${text}`);
    assert.ok(text.includes(coverageEngine.GRADE_LABEL.thin), text);
  });

  it('⛔ the grade is an ABSOLUTE count, so the thinner firewall is not flattered', async () => {
    // 6 of 19 is a worse RATIO than 26 of 28, and also a worse absolute count —
    // but the point is the reverse case: a near-complete thin assessment.
    handler = cardPool({
      device: { name: 'FW-ASA', vendor: 'cisco_asa' },
      // 9 of a possible 13 — a 69% RATIO, better than the broad firewall's
      // would be if the library were smaller, and still thin evidence.
      findings: [...checks('PCI_DSS', 4, 1), ...checks('ISO_27001', 3, 1)],
      library: { applicable: ASA_APPLICABLE, library_total: LIBRARY_TOTAL },
    });
    const text = await renderAsync(OverviewComplianceCard, { deviceId: 'dev-asa' });
    assert.ok(text.includes(coverageEngine.GRADE_LABEL.thin), `a near-complete ASA is still thin: ${text}`);
    assert.ok(!text.includes(coverageEngine.GRADE_LABEL.broad), text);
  });

  it('⛔ a never-audited firewall gets its denominator too, and no fabricated zero', async () => {
    handler = cardPool({
      device: { name: 'MOCK-ASA-Edge-05', vendor: 'cisco_asa' },
      findings: [],
      library: { applicable: ASA_APPLICABLE, library_total: LIBRARY_TOTAL },
    });
    const text = await renderAsync(OverviewComplianceCard, { deviceId: 'dev-asa' });
    assert.ok(text.includes(`${ASA_APPLICABLE} of ${LIBRARY_TOTAL} SecVault checks`), text);
    assert.ok(
      /no percentage to read/.test(text),
      `nothing gradeable must say so outright rather than imply a zero: ${text}`
    );
    assert.ok(!/0%/.test(text), `a never-audited firewall must not render a 0%: ${text}`);
    assert.ok(text.includes(coverageEngine.GRADE_LABEL.none), text);
  });

  // ── the "we could not measure this" arms ─────────────────────────────────

  it('⛔ an unreadable check-library count reports the basis as unread, never as zero', async () => {
    handler = cardPool({
      device: { name: 'FW-1', vendor: 'sangfor' },
      findings: THIN_FINDINGS(),
      library: 'throw',
    });
    const text = await renderAsync(OverviewComplianceCard, { deviceId: 'dev-1' });
    assert.ok(
      /could not be read/.test(text),
      `a failed library read must say so: ${text}`
    );
    assert.ok(
      !new RegExp(`of ${LIBRARY_TOTAL} SecVault checks`).test(text),
      `a denominator was printed from a read that failed: ${text}`
    );
    assert.ok(!/0 of 0/.test(text), `"0 of 0" is a claim, and a false one: ${text}`);
  });

  it('⛔ an unreadable DEVICE row does not fall back to a vendor', async () => {
    handler = cardPool({ device: 'throw', findings: THIN_FINDINGS(), library: { applicable: 19, library_total: 74 } });
    const text = await renderAsync(OverviewComplianceCard, { deviceId: 'dev-1' });
    assert.ok(/could not be read/.test(text), text);
    // The vendor decides the denominator, so without it no vendor may be named.
    assert.ok(!/Sangfor|Fortinet|Palo Alto|Check Point/.test(text), `a vendor was guessed: ${text}`);
  });

  it('⛔ an absent device row is the same unknown, not an empty success', async () => {
    handler = cardPool({ device: null, findings: THIN_FINDINGS(), library: { applicable: 19, library_total: 74 } });
    const text = await renderAsync(OverviewComplianceCard, { deviceId: 'dev-1' });
    assert.ok(/could not be read/.test(text), text);
  });

  it('⛔ more answered checks than can be asked degrades to unknown, not to a grade', async () => {
    // The two-units confusion: per-standard rows summed. 20 distinct checks
    // against an ASA that admits 13 cannot be right, and the engine says so
    // rather than printing a count that cannot be true.
    const many = [];
    for (let i = 0; i < 20; i += 1) many.push(...checks('PCI_DSS', 1, 0));
    handler = cardPool({
      device: { name: 'FW-ASA', vendor: 'cisco_asa' },
      findings: many,
      library: { applicable: ASA_APPLICABLE, library_total: LIBRARY_TOTAL },
    });
    const text = await renderAsync(OverviewComplianceCard, { deviceId: 'dev-asa' });
    assert.ok(
      /could not be established/.test(text),
      `an impossible basis must be reported as unknown: ${text}`
    );
    assert.ok(text.includes(coverageEngine.GRADE_LABEL.unknown), text);
    assert.ok(!/rests on 20 checks/.test(text), `the impossible count was printed: ${text}`);
  });

  // ⛔ ONE MUTATION IS EQUIVALENT ON SCREEN AND IS RECORDED RATHER THAN
  // PRESENTED AS A COVERED GUARD. Replacing `libraryTotal: library ?
  // library.libraryTotal : null` with a literal `74` changes NOTHING a reader
  // sees: `applicable` comes from the same query, so it is null too,
  // `available` stays false and the headline still says the count could not be
  // read. The fabricated total reaches only the evidence DRAWER's "checks in
  // SecVault's library" row — and `EvidenceMark` returns null without an
  // `EvidenceContext` provider, so no drawer exists in a renderToStaticMarkup
  // pass and no assertion on rendered output can reach it. Measured, not
  // assumed. Same treatment CLAUDE.md gives isInRange's min-side check.

  it('⛔ the coverage statement carries no severity hue', async () => {
    handler = cardPool({
      device: { name: 'FW-1', vendor: 'sangfor' },
      findings: THIN_FINDINGS(),
      library: { applicable: SANGFOR_APPLICABLE, library_total: LIBRARY_TOTAL },
    });
    const tree = await OverviewComplianceCard({ deviceId: 'dev-1' });
    const markup = renderToStaticMarkup(tree);
    // A gap in SecVault's reach is not a severity of the customer's, and the
    // raw ramp tokens also fail WCAG 1.4.3 as text in the light theme.
    const strip = markup.slice(markup.indexOf('Thin evidence') - 2000, markup.indexOf('Thin evidence') + 2000);
    for (const banned of ['--sev-crit', '--sev-high', '--sev-med', '--yellow', '--orange', '--red']) {
      assert.ok(
        !strip.includes(`var(${banned})`),
        `the coverage statement used the severity ramp token ${banned}`
      );
    }
    assert.ok(markup.includes('var(--unmeasured)'), 'the grade must be drawn in the hueless token');
  });
});
