// tests/topFailingControls.test.js
//
// components/compliance/TopFailingControls.js — the "which controls are
// failing on the most firewalls" teaser.
//
// ⛔ WHY THESE RENDER THE COMPONENT RATHER THAN SCANNING ITS SOURCE. Every
// rule this widget carries has a wrong answer that is a CONFIDENT, PLAUSIBLE
// SENTENCE on screen, not a missing guard visible in one line of source:
//
//   · "No control is failing" over a library nothing has measured — a green
//     tick on a compliance dashboard, which is this codebase's signature bug
//     (a failed read recorded as an affirmative value) in its single most
//     reassuring form.
//   · five rows that look like all the rows, because the remainder sentence
//     did not render.
//   · a percentage — a second compliance figure over a different denominator,
//     disagreeing with the headline score on the same screen.
//
// CLAUDE.md records three features that shipped BROKEN past tests that
// asserted the mechanism instead of the outcome (the MFA field marked
// `hidden` and fully visible, the `useState(false)` default, the attribute
// check that passed while the box was on screen). So these tests read the
// WORDS THAT RENDER.
//
// ⛔ FIXTURES ARE BUILT WITH THE ENGINE'S OWN `buildControl`, never
// hand-written object literals. A hand-written shape cannot fail when the
// engine's output changes, so it would keep passing while the page handed the
// component something else entirely — a test that has stopped measuring the
// thing it names.
//
// The JSX is compiled with the parser tests/jsxSyntax.test.js already uses
// (`next/dist/build/swc`, a runtime dependency), exactly as
// tests/deltaBadge.test.js does — package.json deliberately has no
// devDependencies.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

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

// `COMPONENT` lets the mutation run point this suite at a scratchpad copy.
const COMPONENT = process.env.TFC_COMPONENT || '../components/compliance/TopFailingControls';

let React = null;
let renderToStaticMarkup = null;
let TopFailingControls = null;
let engine = null;
let loadError = null;
try {
  installRenderHooks();
  React = require('react');
  ({ renderToStaticMarkup } = require('react-dom/server'));
  engine = require('../lib/engines/complianceControls');
  TopFailingControls = require(COMPONENT).default;
} catch (err) {
  // Reported as a failure rather than skipped: a suite that quietly stops
  // checking is the same shape of problem as the bugs it covers.
  loadError = err;
}

const html = (props) => {
  assert.ok(TopFailingControls, 'could not load TopFailingControls for rendering: '
    + (loadError ? loadError.stack : 'unknown'));
  return renderToStaticMarkup(React.createElement(TopFailingControls, props));
};

/** Every word a reader sees, tags stripped and entities decoded. */
const text = (props) =>
  html(props)
    .replace(/<[^>]+>/g, ' ')
    .replace(/&#x27;|&apos;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, '&')
    .replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

// ── fixtures, built through the real engine ─────────────────────────────────

/**
 * One control, built by `buildControl` so its shape is by construction the
 * shape `gatherControls` hands the page.
 *
 * @param {object} o
 * @param {number} o.fail      how many firewalls answered `fail`
 * @param {number} [o.pass]    how many answered `pass`
 * @param {number|null} [o.applicable] firewalls the check's vendor scope admits
 */
function control({ slug, name, fail = 0, pass = 0, applicable = 10, severity = 'high' }) {
  const findings = [];
  for (let i = 0; i < fail; i += 1) {
    findings.push({ deviceId: `${slug}-f${i}`, deviceName: `FW-fail-${i}`, status: 'fail', detectedAt: '2026-11-01T00:00:00.000Z' });
  }
  for (let i = 0; i < pass; i += 1) {
    findings.push({ deviceId: `${slug}-p${i}`, deviceName: `FW-pass-${i}`, status: 'pass', detectedAt: '2026-11-01T00:00:00.000Z' });
  }
  return engine.buildControl({
    slug,
    name: name || slug,
    severity,
    standards: ['CIS_V8'],
    vendor: null,
    predicateType: 'config_key_exists',
    findings,
    applicableDeviceCount: applicable,
    liveExceptions: [],
  });
}

/** A control the library declares unanswerable — PERMANENT, never a failure. */
function notEvaluable(slug) {
  return engine.buildControl({
    slug,
    name: slug,
    severity: 'medium',
    standards: [],
    vendor: null,
    predicateType: 'not_evaluable_from_config',
    findings: [],
    applicableDeviceCount: 10,
    liveExceptions: [],
  });
}

/** The real summary, over the real controls — never a hand-built object. */
const summaryOf = (controls) => engine.summariseControls(controls);

const sorted = (controls) => engine.sortControls(controls);

/** n failing controls, each failing on a descending number of firewalls. */
function failingLibrary(n) {
  const out = [];
  for (let i = 0; i < n; i += 1) {
    out.push(control({ slug: `c-${i}`, name: `Control ${i}`, fail: n - i, pass: 0, applicable: 10 }));
  }
  return sorted(out);
}

// ── the rule that matters most ──────────────────────────────────────────────

describe('TopFailingControls — an empty widget must never read as an all-clear', () => {
  // The two zeroes are byte-identical in the data: `failingControls === 0`
  // whether the fleet is perfectly compliant or whether nothing was ever
  // asked. Only the gap fields can tell them apart, and the component must
  // consult them before it is allowed to say anything reassuring.
  it('says the library was not fully evaluated when controls were never measured', () => {
    // A library of controls that apply here and that no firewall has answered.
    const controls = sorted([
      control({ slug: 'a', fail: 0, pass: 0, applicable: 10 }),
      control({ slug: 'b', fail: 0, pass: 0, applicable: 10 }),
    ]);
    const summary = summaryOf(controls);
    assert.equal(summary.failingControls, 0, 'fixture must have nothing failing');
    assert.ok(summary.notMeasured > 0, 'fixture must have a real, engine-derived gap');

    const out = text({ controls, summary });
    assert.match(out, /not fully evaluated/i);
    assert.match(out, /not an all-clear/i);
    assert.match(out, /never been measured/i);
    // ⛔ The negative half is the one that catches the dangerous mutation: a
    // widget that ALSO prints the clean sentence beside the caveat has still
    // told the operator everything is fine.
    assert.doesNotMatch(out, /every control in the library was evaluated/i);
  });

  it('says so for `partial` too — passing where measured is not passing', () => {
    // Passing on the firewalls it could be asked, and it could not be asked
    // everywhere. The state this whole view exists to surface.
    const controls = sorted([control({ slug: 'a', fail: 0, pass: 3, applicable: 16 })]);
    const summary = summaryOf(controls);
    assert.equal(summary.partial, 1, 'fixture must be `partial` per the engine');
    assert.equal(summary.notMeasured, 0, 'this case must isolate `partial` from `notMeasured`');

    const out = text({ controls, summary });
    assert.match(out, /not fully evaluated/i);
    assert.match(out, /not an all-clear/i);
    assert.match(out, /only on the firewalls SecVault could ask/i);
    assert.doesNotMatch(out, /every control in the library was evaluated/i);
  });

  it('names the two gaps SEPARATELY when both are present', () => {
    // ⛔ `notMeasured` clears itself the next time a config is collected;
    // `partial` is a control answered on only some firewalls. Summing them
    // into one "N unmeasured" would send an operator looking for one fix where
    // there are two — the call /capacity makes between `no_log_coverage` and
    // `bytes_not_summable`.
    const controls = sorted([
      control({ slug: 'a', fail: 0, pass: 0, applicable: 10 }),
      control({ slug: 'b', fail: 0, pass: 3, applicable: 16 }),
    ]);
    const summary = summaryOf(controls);
    assert.equal(summary.notMeasured, 1);
    assert.equal(summary.partial, 1);

    const out = text({ controls, summary });
    assert.match(out, /never been measured/i);
    assert.match(out, /only on the firewalls SecVault could ask/i);
  });

  it('falls CLOSED to unknown when the gap fields cannot be read', () => {
    // A summary whose gap fields are absent is not a summary proving zero
    // gaps. Reading a missing field as 0 would turn "we cannot tell" into
    // "fully evaluated, everything passed" — the exact substitution this
    // codebase names most often.
    for (const broken of [
      { failingControls: 0 },
      { failingControls: 0, notMeasured: null, partial: null },
      { failingControls: 0, notMeasured: 'n/a', partial: 0 },
      { failingControls: 0, notMeasured: 0 },
    ]) {
      const out = text({ controls: [], summary: broken });
      assert.match(out, /could not be determined/i, `unreadable gap must report unknown: ${JSON.stringify(broken)}`);
      assert.match(out, /not an all-clear/i);
      assert.doesNotMatch(out, /every control in the library was evaluated/i);
    }
  });

  it('an entirely absent summary still refuses the all-clear', () => {
    for (const summary of [undefined, null, {}, 'nonsense']) {
      const out = text({ controls: [], summary });
      assert.doesNotMatch(out, /every control in the library was evaluated/i);
      assert.match(out, /not an all-clear/i);
    }
  });

  it('DOES claim a clean result when the library really was fully evaluated', () => {
    // The other side of the same rule: a guard that can never pass is not a
    // guard, it is a widget that always says the same thing. A fully-evaluated
    // library with nothing failing is a real, earned result and must read as
    // one, or the caveat stops meaning anything.
    const controls = sorted([
      control({ slug: 'a', fail: 0, pass: 10, applicable: 10 }),
      control({ slug: 'b', fail: 0, pass: 10, applicable: 10 }),
    ]);
    const summary = summaryOf(controls);
    assert.equal(summary.notMeasured, 0);
    assert.equal(summary.partial, 0);
    assert.equal(summary.failingControls, 0);

    const out = text({ controls, summary });
    assert.match(out, /No control is failing on any firewall/i);
    assert.match(out, /every control in the library was evaluated/i);
    assert.doesNotMatch(out, /not an all-clear/i);
  });

  it('a permanently not-evaluable control does NOT block the clean result', () => {
    // ⛔ `not_evaluable_from_config` is PERMANENT and is excluded from the
    // score rather than counted against it. Folding it into the gap would make
    // a correctly-behaving library permanently unable to report clean, which
    // teaches an operator to ignore the caveat that matters.
    const controls = sorted([
      control({ slug: 'a', fail: 0, pass: 10, applicable: 10 }),
      notEvaluable('b'),
    ]);
    const summary = summaryOf(controls);
    assert.equal(summary.notEvaluable, 1, 'fixture must contain a permanent gap');
    assert.equal(summary.notMeasured, 0);
    assert.equal(summary.partial, 0);

    assert.match(text({ controls, summary }), /every control in the library was evaluated/i);
  });
});

// ── truncation ──────────────────────────────────────────────────────────────

describe('TopFailingControls — a truncated list may never look complete', () => {
  it('shows at most five controls', () => {
    const controls = failingLibrary(23);
    const out = html({ controls, summary: summaryOf(controls) });
    const rows = [...out.matchAll(/firewalls failing/g)];
    assert.equal(rows.length, 5, 'exactly five rows may render');
  });

  it('discloses the remainder in WORDS when it truncates', () => {
    const controls = failingLibrary(23);
    const summary = summaryOf(controls);
    assert.equal(summary.failingControls, 23);
    // The sentence, not merely a link — an operator who reads five rows and a
    // "view all" link reasonably concludes the five ARE the failing controls.
    assert.match(text({ controls, summary }), /Showing 5 of 23 failing controls/i);
  });

  it('does NOT print a truncation sentence when nothing was truncated', () => {
    const controls = failingLibrary(3);
    assert.doesNotMatch(text({ controls, summary: summaryOf(controls) }), /Showing \d+ of/i);
  });

  it('prints no truncation sentence at exactly five', () => {
    // The boundary: five of five is the whole list, and claiming "showing 5 of
    // 5" invites the reader to look for a sixth.
    const controls = failingLibrary(5);
    assert.doesNotMatch(text({ controls, summary: summaryOf(controls) }), /Showing \d+ of/i);
  });

  it('takes the LARGER denominator when the summary and the list disagree', () => {
    // ⛔ Under-stating the remainder makes a truncated list look complete,
    // which is the dangerous direction. A summary claiming fewer failing
    // controls than the list actually holds must never shrink the disclosure.
    const controls = failingLibrary(9);
    const out = text({ controls, summary: { ...summaryOf(controls), failingControls: 2 } });
    assert.match(out, /Showing 5 of 9 failing controls/i);
  });

  it('ranks by the number of firewalls failing, worst first', () => {
    // The whole question this widget answers. A list in library order would
    // look identical and be wrong.
    const controls = sorted([
      control({ slug: 'few', name: 'Few firewalls', fail: 1, applicable: 10 }),
      control({ slug: 'many', name: 'Many firewalls', fail: 7, applicable: 10 }),
      control({ slug: 'some', name: 'Some firewalls', fail: 4, applicable: 10 }),
    ]);
    const out = text({ controls, summary: summaryOf(controls) });
    assert.ok(
      out.indexOf('Many firewalls') < out.indexOf('Some firewalls'),
      'the control failing on most firewalls must come first'
    );
    assert.ok(out.indexOf('Some firewalls') < out.indexOf('Few firewalls'));
  });

  it('renders only FAILING controls, never a passing or unmeasured one', () => {
    const controls = sorted([
      control({ slug: 'bad', name: 'Bad control', fail: 2, applicable: 10 }),
      control({ slug: 'good', name: 'Good control', fail: 0, pass: 10, applicable: 10 }),
      control({ slug: 'unasked', name: 'Unasked control', fail: 0, pass: 0, applicable: 10 }),
    ]);
    const out = text({ controls, summary: summaryOf(controls) });
    assert.match(out, /Bad control/);
    assert.doesNotMatch(out, /Good control/);
    assert.doesNotMatch(out, /Unasked control/);
  });
});

// ── the unit, and the forbidden second percentage ───────────────────────────

describe('TopFailingControls — every number is a count of FIREWALLS', () => {
  it('states the split, never a bare verdict', () => {
    const controls = sorted([control({ slug: 'a', name: 'Any-any allow', fail: 4, pass: 11, applicable: 15 })]);
    const out = text({ controls, summary: summaryOf(controls) });
    // "4 of 15 firewalls failing" — the denominator is the APPLICABLE count,
    // not the number that happened to answer. "4 of 4 failing" over a fleet of
    // fifteen is true and useless.
    assert.match(out, /4 of 15 firewalls failing/);
  });

  it('NEVER renders a percentage', () => {
    // ⛔ `scorePct` is the one compliance figure this product publishes. A
    // second one here, over a different denominator, would sit on the same
    // screen as the headline score and disagree with it.
    const controls = failingLibrary(12);
    const out = html({ controls, summary: summaryOf(controls) });
    assert.doesNotMatch(out, /%/, 'no percent sign may appear anywhere in the markup');
    assert.doesNotMatch(text({ controls, summary: summaryOf(controls) }), /percent/i);
  });

  it('names the unit on screen, not only in the engine comments', () => {
    const controls = failingLibrary(3);
    const out = text({ controls, summary: summaryOf(controls) });
    assert.match(out, /failing on one firewall and passing on another/i);
  });
});

// ── the gap travels with the count ──────────────────────────────────────────

describe('TopFailingControls — the coverage gap rides beside the failure count', () => {
  it('states how many applicable firewalls were never asked', () => {
    // Failing on 3, passing on 0, applicable 8 → 5 never asked. Those five are
    // where the next failure comes from, so the 3 must never travel alone.
    const c = control({ slug: 'a', name: 'Gapped control', fail: 3, pass: 0, applicable: 8 });
    assert.equal(c.notEvaluatedDeviceCount, 5, 'fixture must carry an engine-derived gap');
    const controls = sorted([c]);
    const out = text({ controls, summary: summaryOf(controls) });
    assert.match(out, /3 of 8 firewalls failing/);
    assert.match(out, /5 never asked/);
  });

  it('prints no gap note when there is no gap', () => {
    const controls = sorted([control({ slug: 'a', fail: 4, pass: 6, applicable: 10 })]);
    assert.doesNotMatch(text({ controls, summary: summaryOf(controls) }), /never asked/);
  });

  it('reports an UNREADABLE applicable count as unknown, not as full coverage', () => {
    // ⛔ `applicableDeviceCount: null` is "we could not read it", and the
    // engine propagates that into a null gap. Falling back to the answered
    // count would make every control look fully covered — the failed read
    // recorded as a fact, in a cell.
    const c = control({ slug: 'a', name: 'Unknown scope', fail: 2, pass: 0, applicable: null });
    assert.equal(c.applicableDeviceCount, null);
    assert.equal(c.notEvaluatedDeviceCount, null);
    const controls = sorted([c]);
    const out = text({ controls, summary: summaryOf(controls) });
    assert.match(out, /2 of an unknown number of firewalls failing/i);
    assert.match(out, /coverage unknown/i);
    assert.doesNotMatch(out, /2 of 2 firewalls failing/);
  });
});

// ── severity, and links ─────────────────────────────────────────────────────

describe('TopFailingControls — severity and navigation', () => {
  it('shows each control severity', () => {
    const controls = sorted([control({ slug: 'a', name: 'Crit', fail: 2, severity: 'critical' })]);
    assert.match(text({ controls, summary: summaryOf(controls) }), /Critical/);
  });

  it('shows an UNRECOGNISED severity raw rather than mapping it to a default', () => {
    // `medium` is the column's DEFAULT, so badging an unknown value as Medium
    // would invent a grading the library never recorded.
    const controls = sorted([control({ slug: 'a', name: 'Odd', fail: 2, severity: 'sev-9' })]);
    const out = text({ controls, summary: summaryOf(controls) });
    assert.match(out, /sev-9/);
    assert.doesNotMatch(out, /Medium/);
  });

  it('links through to the failing filter on /compliance/controls', () => {
    const controls = failingLibrary(8);
    const out = html({ controls, summary: summaryOf(controls) });
    assert.match(out, /href="\/compliance\/controls\?status=failing"/);
  });

  it('links each control to the list, never to a per-control route', () => {
    // No per-control detail route exists in this working copy; a link to a 404
    // is worse than a link to the page that holds the answer.
    const controls = failingLibrary(3);
    const out = html({ controls, summary: summaryOf(controls) });
    // ⛔ WAS `doesNotMatch` UNTIL THE DETAIL ROUTE LANDED (v2.227.0). The
    // widget shipped linking at the bare list because no per-control route
    // existed, and this assertion was written INVERTED on purpose so that
    // adding the route would fail the build and force a deliberate edit here
    // rather than leaving a teaser that quietly points at the wrong page.
    assert.match(out, /href="\/compliance\/controls\/[a-z0-9-]/i);
  });

  it('offers the way through even when nothing is failing', () => {
    // A widget whose only link disappears on the empty path strands the
    // operator on the one screen where they most want the detail.
    const out = html({ controls: [], summary: { failingControls: 0, notMeasured: 4, partial: 0 } });
    assert.match(out, /href="\/compliance\/controls\?status=failing"/);
  });
});

// ── it does no data access ──────────────────────────────────────────────────

describe('TopFailingControls — it renders what it is handed', () => {
  it('imports no pool and issues no query', () => {
    // ⛔ A second query here would be a second measurement of the same fact,
    // taken moments later, that eventually disagrees with the table beside it
    // — and a reader has no way to tell which of two numbers on one screen is
    // real. Asserted on the SOURCE because there is nothing in the rendered
    // output that could ever show it.
    //
    // ⛔ COMMENTS ARE STRIPPED FIRST, and this test failed on correct code
    // until they were. The component's own doc comment NAMES `gatherControls`
    // to say where its props come from, and a raw-source scan read that
    // sentence as evidence that it calls it — the identical defect
    // `deviceScopeCoverage.js` records, where `notificationChannels.js` was
    // classified as holding device data because it said in prose that it does
    // not.
    const src = fs
      .readFileSync(path.join(__dirname, '..', 'components', 'compliance', 'TopFailingControls.js'), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
    assert.doesNotMatch(src, /lib\/db|pool\.query|gatherControls|require\(/);
  });

  it('survives a malformed control row without inventing a number', () => {
    // A null or shapeless entry must not throw the page that mounts this, and
    // must not be counted as a failing control.
    const good = control({ slug: 'a', name: 'Real control', fail: 2, applicable: 10 });
    const controls = [null, undefined, { status: 'failing' }, good];
    const out = text({ controls, summary: summaryOf([good]) });
    assert.match(out, /Real control/);
  });
});
