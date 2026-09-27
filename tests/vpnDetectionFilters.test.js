'use strict';
// tests/vpnDetectionFilters.test.js
//
// Pins lib/vpnDetectionFilters.js — the narrowing behind /vpn?vtab=detections.
//
// ⛔ WHY A FILTER NEEDS TESTS AT ALL. Every wrong answer here is a SHORTER LIST
// THAT LOOKS COMPLETE, which is this repo's most-repeated failure wearing a
// filter's clothes. Nothing throws, nothing renders oddly; an operator filters
// by country, sees three rows instead of eleven, and concludes the other eight
// attacks did not happen.
//
// The specific hazard is that the six detections carry country in THREE
// different shapes — `country`, `countries[]`, and a from/to PAIR — so a filter
// written against the first shape silently drops half the detections out of
// every country query.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  matchesFilters,
  filtersActive,
  countriesIn,
  countriesOf,
  panelView,
} = require('../lib/vpnDetectionFilters');

// One finding of each country SHAPE the engine actually emits.
const SPRAY = { severity: 'critical', srcIp: '93.152.210.31', country: 'Bulgaria', devices: [{ deviceName: 'IDC FW' }] };
const BRUTE = { severity: 'high', username: 'admin', srcIp: '2.27.98.43', country: 'Germany' };
const TARGETED = { severity: 'medium', username: 'romain.deguitre', countries: ['Poland', 'Canada'] };
const CHANGE = { severity: 'low', username: 'jdoe', fromCountry: 'Thailand', toCountry: 'Switzerland', fromSrcIp: '1.1.1.1', toSrcIp: '2.2.2.2' };
const OFF_HOURS = { severity: 'low', username: 'sistema', hourUtc: 3, countries: ['Thailand'] };
// ⛔ The live case with no geography at all: the firewall reported no country.
const NO_COUNTRY = { severity: 'high', username: 'test', srcIp: '10.0.0.5' };

describe('countriesOf — all three shapes, or three detections vanish', () => {
  it('reads a plain country', () => assert.deepEqual(countriesOf(SPRAY), ['Bulgaria']));
  it('reads a countries[] array', () => assert.deepEqual(countriesOf(TARGETED), ['Poland', 'Canada']));
  it('reads a from/to pair', () => assert.deepEqual(countriesOf(CHANGE), ['Thailand', 'Switzerland']));
  it('returns nothing for a finding with no geography', () => assert.deepEqual(countriesOf(NO_COUNTRY), []));
  it('never throws on junk', () => {
    for (const bad of [null, undefined, 0, '', [], 'nope', { countries: 'not-an-array' }]) {
      assert.doesNotThrow(() => countriesOf(bad));
      assert.deepEqual(countriesOf(bad), []);
    }
  });
  it('ignores empty and whitespace-only country strings', () => {
    assert.deepEqual(countriesOf({ country: '   ', countries: ['', 'Spain'] }), ['Spain']);
  });
});

describe('matchesFilters — severity', () => {
  it('keeps an exact match and drops the rest', () => {
    assert.equal(matchesFilters(SPRAY, { severity: 'critical' }), true);
    assert.equal(matchesFilters(BRUTE, { severity: 'critical' }), false);
  });
  it('an unset severity filter keeps everything', () => {
    for (const f of [SPRAY, BRUTE, TARGETED, CHANGE, NO_COUNTRY]) {
      assert.equal(matchesFilters(f, { severity: '' }), true);
    }
  });
});

describe('matchesFilters — country, across every shape', () => {
  it('matches a plain country', () => {
    assert.equal(matchesFilters(SPRAY, { country: 'Bulgaria' }), true);
    assert.equal(matchesFilters(SPRAY, { country: 'Germany' }), false);
  });

  it('⛔ matches inside countries[] — the account-targeted and off-hours shape', () => {
    // Written against `country` alone, this returns false and account_targeted
    // disappears from every country filter.
    assert.equal(matchesFilters(TARGETED, { country: 'Canada' }), true);
    assert.equal(matchesFilters(OFF_HOURS, { country: 'Thailand' }), true);
  });

  it('⛔ matches EITHER END of a country change', () => {
    // A country-change finding is about a pair. Matching only `fromCountry`
    // would hide "somebody authenticated into Switzerland" from a Switzerland
    // filter — which is the direction a reader actually cares about.
    assert.equal(matchesFilters(CHANGE, { country: 'Thailand' }), true);
    assert.equal(matchesFilters(CHANGE, { country: 'Switzerland' }), true);
    assert.equal(matchesFilters(CHANGE, { country: 'Poland' }), false);
  });

  it('⛔ a finding naming NO country is EXCLUDED, not passed through', () => {
    // "We do not know where this came from" is not a match for "Switzerland".
    // Letting it through would file an unlocatable finding under a heading that
    // claims a location for it. The cost — that narrowing hides findings whose
    // country the firewall never reported — is why the caller prints
    // "showing N of M" rather than N alone.
    assert.equal(matchesFilters(NO_COUNTRY, { country: 'Switzerland' }), false);
    // ...and it survives when no country filter is set.
    assert.equal(matchesFilters(NO_COUNTRY, { country: '' }), true);
  });

  it('is exact, not substring — "Chad" must not match "Chile"', () => {
    assert.equal(matchesFilters({ country: 'Chile' }, { country: 'Ch' }), false);
  });
});

describe('matchesFilters — free-text search', () => {
  it('finds a username, an address and a country', () => {
    assert.equal(matchesFilters(BRUTE, { q: 'admin' }), true);
    assert.equal(matchesFilters(BRUTE, { q: '2.27.98' }), true);
    assert.equal(matchesFilters(BRUTE, { q: 'germany' }), true);
  });

  it('searches BOTH addresses of a country change', () => {
    assert.equal(matchesFilters(CHANGE, { q: '2.2.2.2' }), true);
  });

  it('reaches a device name inside the devices[] objects', () => {
    // devices[] holds {deviceId, deviceName, vendor}, not strings. Joining the
    // objects directly yields "[object Object]" and the search silently never
    // matches a firewall name.
    assert.equal(matchesFilters(SPRAY, { q: 'idc' }), true);
  });

  it('is case-insensitive and trims', () => {
    assert.equal(matchesFilters(BRUTE, { q: '  ADMIN  ' }), true);
  });

  it('drops a finding that matches nothing', () => {
    assert.equal(matchesFilters(BRUTE, { q: 'nonesuch' }), false);
  });
});

describe('matchesFilters — the filters combine with AND', () => {
  it('all set filters must hold', () => {
    assert.equal(matchesFilters(BRUTE, { q: 'admin', severity: 'high', country: 'Germany' }), true);
    assert.equal(matchesFilters(BRUTE, { q: 'admin', severity: 'low', country: 'Germany' }), false);
    assert.equal(matchesFilters(BRUTE, { q: 'admin', severity: 'high', country: 'Poland' }), false);
  });

  it('no filters at all keeps everything, and never throws', () => {
    for (const none of [null, undefined, {}, { q: '', country: '', severity: '' }]) {
      assert.equal(matchesFilters(BRUTE, none), true);
    }
  });
});

describe('filtersActive', () => {
  it('is false for nothing set', () => {
    for (const none of [null, undefined, {}, { q: '   ', country: '', severity: '' }]) {
      assert.equal(filtersActive(none), false);
    }
  });
  it('is true for any single filter', () => {
    assert.equal(filtersActive({ q: 'x' }), true);
    assert.equal(filtersActive({ country: 'Chad' }), true);
    assert.equal(filtersActive({ severity: 'low' }), true);
  });
});

describe('countriesIn — the dropdown is derived, never typed', () => {
  const DETECTIONS = [
    { findings: [SPRAY, BRUTE], unverifiable: [] },
    { findings: [TARGETED], unverifiable: [CHANGE] },
    { findings: [NO_COUNTRY], unverifiable: [] },
  ];

  it('collects every country from every shape, sorted and deduped', () => {
    assert.deepEqual(
      countriesIn(DETECTIONS),
      ['Bulgaria', 'Canada', 'Germany', 'Poland', 'Switzerland', 'Thailand']
    );
  });

  it('⛔ reads `unverifiable` too, not just `findings`', () => {
    // Those items are shown on the page. A dropdown built from findings alone
    // offers no option for a country that appears only among the observations
    // we could not judge — so filtering for it silently returns nothing.
    assert.ok(countriesIn(DETECTIONS).includes('Switzerland'));
    const findingsOnly = [{ findings: [SPRAY], unverifiable: [CHANGE] }];
    assert.ok(countriesIn(findingsOnly).includes('Thailand'));
  });

  it('never throws on a malformed detection list', () => {
    for (const bad of [null, undefined, 'nope', [null], [{}], [{ findings: 'x' }]]) {
      assert.doesNotThrow(() => countriesIn(bad));
      assert.ok(Array.isArray(countriesIn(bad)));
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────
// panelView — WHICH OF THE FOUR THINGS A PANEL SAYS
// ─────────────────────────────────────────────────────────────────────────
//
// ⛔ THE BUG THIS EXISTS TO STOP. components/vpn/VpnDetections.js rendered
//
//     {measured && findings.length === 0 ? <div>Nothing matched this detection
//                                          in the last {windowLabel}.</div> : null}
//
// where `findings` was the FILTERED array. So a filter could manufacture the
// page's one earned all-clear: live, `?vtab=detections&dCountry=CH` left
// credential_spray with 0 of 130 surviving and the card then asserted "Nothing
// matched this detection in the last 24 hours" — a claim about the WINDOW —
// directly beneath "showing 0 of 130". A bogus `?dSeverity=xyz` did it to all six
// panels at once, turning a typo into a fleet-wide all-clear.
//
// The judgement is pure and lives here so it can be tested by BEHAVIOUR. The
// component's own rendering of it is pinned further down, with react-dom/server.
describe('⛔ panelView — a filter may never earn an all-clear', () => {
  const measured = (findings, unverifiable = []) => ({
    id: 'credential_spray',
    status: 'measured',
    findings,
    unverifiable,
    unverifiableTotal: unverifiable.length,
  });

  it('an EARNED all-clear needs the UNFILTERED set to be empty', () => {
    const v = panelView(measured([]), null);
    assert.equal(v.earnedAllClear, true);
    assert.equal(v.narrowedToNothing, false);
  });

  it('⛔ narrowing to nothing is NOT an all-clear, and states what it is hiding', () => {
    const v = panelView(measured([SPRAY, BRUTE, TARGETED]), { country: 'Switzerland' });
    assert.equal(v.findings.length, 0);
    assert.equal(v.earnedAllClear, false, 'a filter manufactured the earned all-clear');
    assert.equal(v.narrowedToNothing, true);
    assert.equal(v.findingsTotal, 3);
    assert.equal(v.hiddenByFilters, 3);
  });

  it('⛔ a severity nobody offers zeroes every panel, and must not silence one', () => {
    // `?dSeverity=xyz` is one keystroke away and matches nothing.
    const v = panelView(measured([SPRAY, BRUTE]), { severity: 'xyz' });
    assert.equal(v.earnedAllClear, false);
    assert.equal(v.narrowedToNothing, true);
    assert.equal(v.hiddenByFilters, 2);
  });

  it('a partial narrowing reports both numbers', () => {
    const v = panelView(measured([SPRAY, BRUTE, TARGETED]), { country: 'Germany' });
    assert.deepEqual(v.findings, [BRUTE]);
    assert.equal(v.findingsTotal, 3);
    assert.equal(v.hiddenByFilters, 2);
  });

  it('⛔ an unmeasured detection can never produce either sentence', () => {
    for (const status of ['insufficient_baseline', 'no_data', undefined, 'nonsense']) {
      const v = panelView({ status, findings: [], unverifiable: [], unverifiableTotal: 0 }, null);
      assert.equal(v.measured, false);
      assert.equal(v.earnedAllClear, false,
        'an all-clear from a detection that could not look is the worst output available');
      assert.equal(v.narrowedToNothing, false);
    }
  });

  // ⛔ FINDING 7. The unverifiable list ignored every filter, so one card could
  // print "Nothing matched…", "showing 0 of 130" and 25 unverifiable rows from
  // three other countries, all at once.
  it('⛔ the unverifiable SAMPLE is narrowed by the same filters', () => {
    const v = panelView(measured([SPRAY], [BRUTE, TARGETED]), { country: 'Germany' });
    assert.deepEqual(v.unverifiable, [BRUTE]);
    assert.equal(v.unverifiableHiddenByFilters, 1);
  });

  it('⛔ but the unverifiable TOTAL is the engine\'s claim and no filter shrinks it', () => {
    // The engine caps the listed sample at 25 and carries the true count; that
    // count is the claim and the list is illustration.
    const d = { status: 'measured', findings: [], unverifiable: [BRUTE], unverifiableTotal: 393 };
    const v = panelView(d, { country: 'Switzerland' });
    assert.equal(v.unverifiable.length, 0);
    assert.equal(v.unverifiableTotal, 393, 'a filter reduced a count of what could not be judged');
  });

  it('falls back to the sample length only when the engine declared no total', () => {
    const v = panelView({ status: 'measured', findings: [], unverifiable: [SPRAY, BRUTE] }, null);
    assert.equal(v.unverifiableTotal, 2);
  });

  it('never throws on a malformed detection', () => {
    for (const bad of [null, undefined, 'nope', 0, { findings: 'x', unverifiable: 5 }]) {
      assert.doesNotThrow(() => panelView(bad, { country: 'Germany' }));
      const v = panelView(bad, { country: 'Germany' });
      assert.ok(Array.isArray(v.findings));
      assert.equal(v.earnedAllClear, false);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────
// THE RENDERED PANEL
// ─────────────────────────────────────────────────────────────────────────
//
// ⛔ WHY THESE ARE RENDERED AND NOT SOURCE-SCANNED. The wrong answer here is a
// CONFIDENT ENGLISH SENTENCE — "Nothing matched this detection in the last 24
// hours" — printed under a heading that already says "showing 0 of 130". No
// missing guard is visible in one line of source; only the words on the screen
// show it. Same reasoning, and the same swc-on-require harness, as
// tests/deltaBadge.test.js.
//
// `next/navigation` is stubbed because the filter bar is a client component that
// calls useRouter/useSearchParams, and there is no app router in a test process.
// Stubbing it is what lets the REAL component tree be rendered rather than a
// re-implementation of its decisions.

const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

let React = null;
let renderToStaticMarkup = null;
let VpnDetections = null;
let loadError = null;
try {
  const swc = require('next/dist/build/swc');
  const origExt = Module._extensions['.js'];
  Module._extensions['.js'] = function (mod, filename) {
    if (filename.split(path.sep).join('/').includes('/node_modules/')) return origExt(mod, filename);
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
  const origLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    if (request === 'next/navigation') {
      return {
        useRouter: () => ({ push() {}, replace() {} }),
        usePathname: () => '/vpn',
        useSearchParams: () => new URLSearchParams('vtab=detections'),
      };
    }
    return origLoad(request, parent, isMain);
  };
  React = require('react');
  ({ renderToStaticMarkup } = require('react-dom/server'));
  VpnDetections = require('../components/vpn/VpnDetections').default;
} catch (err) {
  // Reported as a failure rather than skipped: a suite that quietly stops
  // checking is the same shape of problem as the bugs it covers.
  loadError = err;
}

const BASE_DATA = {
  windowHours: 24,
  windowStart: new Date('2026-09-26T16:00:00Z'),
  generatedAt: new Date('2026-09-27T16:00:00Z'),
  baseline: { hasHistory: true, spanDays: 18.2, firstBucketAt: new Date('2026-09-09T01:00:00Z') },
  headline: { figures: [] },
  coverage: {
    devices: [], reportingGapDevices: [], unattributedCoverage: [],
    totalFailures: 46090, totalSuccesses: 120, sourcesSeen: 2074,
  },
  detections: [],
};

function panel(over = {}) {
  return {
    id: 'credential_spray',
    title: 'Credential spray',
    question: 'Is one address trying many different usernames?',
    method: 'One source address, 5 or more distinct usernames failing.',
    status: 'measured',
    baseline: null,
    findings: [],
    unverifiable: [],
    unverifiableTotal: 0,
    caveats: [],
    ...over,
  };
}

const sprayFinding = (over = {}) => ({
  kind: 'credential_spray',
  srcIp: '93.152.210.31',
  country: 'Bulgaria',
  usernames: 861,
  usernamesIsFloor: false,
  failures: 1737,
  hours: 22,
  devices: ['IDC FW'],
  lastSeenAt: '2026-09-27T02:00:00Z',
  severity: 'critical',
  successClaimVerified: true,
  blindDevices: [],
  ...over,
});

function render(props) {
  assert.ok(VpnDetections, 'could not load VpnDetections for rendering: '
    + (loadError ? loadError.stack : 'unknown'));
  return renderToStaticMarkup(React.createElement(VpnDetections, {
    canSearchLogs: false, hours: 24, ...props,
  }));
}

/** The visible words, tags stripped and whitespace collapsed. */
function visible(props) {
  return render(props).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}

describe('⛔ the rendered panel — a filter must not print an all-clear', () => {
  const data = (detections, over = {}) => ({ ...BASE_DATA, detections, ...over });

  it('an EARNED all-clear still reads exactly as it did', () => {
    const txt = visible({ data: data([panel({ findings: [] })]), filters: null });
    assert.match(txt, /Nothing matched this detection in the last 24 h/);
  });

  it('⛔ a country filter that hides every finding does NOT claim the window was clean', () => {
    // Live: ?vtab=detections&dCountry=CH left credential_spray with 130 findings
    // and 0 survivors, and the card asserted "Nothing matched this detection in
    // the last 24 hours" directly under "showing 0 of 130".
    const txt = visible({
      data: data([panel({ findings: [sprayFinding(), sprayFinding({ srcIp: '5.5.5.5' })] })]),
      filters: { q: '', country: 'Switzerland', severity: '' },
    });
    assert.doesNotMatch(txt, /Nothing matched this detection/,
      'a filter manufactured the page’s one earned all-clear');
    // It says what actually happened instead, with the number it is hiding.
    assert.match(txt, /No finding here matches the current filters/);
    assert.match(txt, /found 2 in the last 24 h/);
    assert.match(txt, /showing 0 of 2/);
  });

  it('⛔ a severity nobody offers silences every panel — and must not', () => {
    const txt = visible({
      data: data([
        panel({ findings: [sprayFinding()] }),
        panel({ id: 'brute_force', title: 'Brute force', findings: [sprayFinding()] }),
      ]),
      filters: { q: '', country: '', severity: 'xyz' },
    });
    assert.doesNotMatch(txt, /Nothing matched this detection/);
    assert.equal((txt.match(/No finding here matches the current filters/g) || []).length, 2);
  });

  it('a partial narrowing lists the survivors and prints both counts', () => {
    const txt = visible({
      data: data([panel({ findings: [sprayFinding(), sprayFinding({ srcIp: '5.5.5.5', country: 'Germany' })] })]),
      filters: { q: '', country: 'Germany', severity: '' },
    });
    assert.match(txt, /showing 1 of 2/);
    assert.match(txt, /5\.5\.5\.5/);
    assert.doesNotMatch(txt, /Nothing matched this detection/);
    assert.doesNotMatch(txt, /No finding here matches/);
  });

  it('⛔ an insufficient baseline never reads as either sentence', () => {
    const txt = visible({
      data: data([panel({
        id: 'new_country_for_user',
        title: 'New country for a user',
        status: 'insufficient_baseline',
        baseline: { required: 7, have: 1.2, unit: 'days of VPN authentication history', firstBucketAt: null },
        unverifiable: [], unverifiableTotal: 24,
      })]),
      filters: null,
    });
    assert.doesNotMatch(txt, /Nothing matched this detection/);
    assert.doesNotMatch(txt, /No finding here matches/);
    assert.match(txt, /Not measured/);
    assert.match(txt, /24 observation\(s\) could not be judged/);
  });

  // ⛔ FINDING 7. One card could print "Nothing matched…", "showing 0 of 130" and
  // 25 unverifiable rows from other countries simultaneously.
  it('⛔ the unverifiable rows obey the filter, while the TOTAL does not', () => {
    const txt = visible({
      data: data([panel({
        findings: [sprayFinding()],
        unverifiable: [sprayFinding({ srcIp: '7.7.7.7', reason: 'no-success-baseline' })],
        unverifiableTotal: 83,
      })]),
      filters: { q: '', country: 'Switzerland', severity: '' },
    });
    // The count is the claim and survives untouched...
    assert.match(txt, /83 could not be verified/);
    // ...the sample does not, and the panel says so rather than showing a
    // Bulgarian row under a Switzerland filter.
    assert.doesNotMatch(txt, /7\.7\.7\.7/);
    assert.match(txt, /narrowed by the current filters/);
  });

  it('the unverifiable rows are listed in full when no filter is set', () => {
    const txt = visible({
      data: data([panel({
        findings: [],
        unverifiable: [sprayFinding({ srcIp: '7.7.7.7', reason: 'no-success-baseline' })],
        unverifiableTotal: 83,
      })]),
      filters: null,
    });
    assert.match(txt, /7\.7\.7\.7/);
    assert.doesNotMatch(txt, /narrowed by the current filters/);
  });
});

// ⛔ FINDING 6. The window <select> offered 24/72/168/192 while the page clamps
// dHours to 1..192, so ?dHours=48 ran a 48-hour window under a control reading
// "Last 24 hours" — a filter reporting a value that is not the one the figures
// beside it were computed from.
describe('⛔ the window control shows the window in force', () => {
  it('a listed window is selected, with no extra option invented', () => {
    const out = render({ data: { ...BASE_DATA, windowHours: 72 }, filters: null });
    assert.match(out, /<option value="72"[^>]*>Last 3 days<\/option>/);
    assert.doesNotMatch(out, /value="48"/);
  });

  it('⛔ an UNLISTED window still appears, labelled honestly', () => {
    const out = render({ data: { ...BASE_DATA, windowHours: 48 }, filters: null });
    assert.match(out, /<option value="48"[^>]*>Last 2 days<\/option>/);
    // Sorted into place rather than appended, so the list still reads as a scale.
    assert.ok(out.indexOf('value="48"') < out.indexOf('value="72"'));
  });

  it('an odd hour count is named in hours, not rounded to a day', () => {
    const out = render({ data: { ...BASE_DATA, windowHours: 5 }, filters: null });
    assert.match(out, /<option value="5"[^>]*>Last 5 hours<\/option>/);
  });
});
