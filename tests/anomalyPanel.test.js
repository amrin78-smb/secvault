// tests/anomalyPanel.test.js
//
// components/alerts/AnomalyPanel.js — the A6 detectors' on-screen surface, and
// since v2.236.4 a COLLAPSED one.
//
// ⛔ WHY THESE RENDER RATHER THAN SCAN THE SOURCE. Collapsing a section whose
// whole purpose is "show the operator what they would otherwise never see" is
// one edit away from hiding it. Every way that goes wrong is a plausible
// sentence or a missing element on screen, not a missing guard visible in one
// line: an error panel behind a closed chevron, a bar labelled with a bare
// count nobody opens, "42 firewalls" printed over three, or a list quietly
// shortened to the first few rows. None of those is findable by grepping the
// file, and this repo has twice watched a source-shape assertion pass over an
// inverted guard. So the component is mounted and the markup is read.
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

let React = null;
let renderToStaticMarkup = null;
let AnomalyPanel = null;
let describeAnomalies = null;
let loadError = null;
try {
  installRenderHooks();
  React = require('react');
  ({ renderToStaticMarkup } = require('react-dom/server'));
  const mod = require('../components/alerts/AnomalyPanel');
  AnomalyPanel = mod.default;
  describeAnomalies = mod.describeAnomalies;
} catch (err) {
  // Reported as a failure rather than skipped: a suite that quietly stops
  // checking is the same shape of problem as the bugs it covers.
  loadError = err;
}

const LOOKBACK = 28;

const html = (props) => {
  assert.ok(AnomalyPanel, 'could not load AnomalyPanel for rendering: '
    + (loadError ? loadError.message : 'unknown'));
  return renderToStaticMarkup(
    React.createElement(AnomalyPanel, { lookbackDays: LOOKBACK, ...props })
  );
};

const strip = (s) => s.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
const text = (props) => strip(html(props));

/** Just the closed bar — what a reader who never opens the section is given. */
const barText = (props) => {
  const m = /<summary[^>]*>([\s\S]*?)<\/summary>/.exec(html(props));
  assert.ok(m, 'expected a <summary> bar');
  return strip(m[1]);
};

/** N silence findings spread over `devices` firewalls. */
function silences(count, devices = 1) {
  return Array.from({ length: count }, (_, i) => ({
    detector: 'device_silent',
    naturalKey: `device_silent:dev${i % devices}:${i}`,
    deviceId: `dev${i % devices}`,
    title: `FW-${i % devices} stopped sending syslog`,
    // ⛔ UNIQUE PER OBSERVATION, and that is the whole value of the fixture.
    // The first draft reused one summary per DEVICE, so a slice(0, 5) kept one
    // of each and the "collapsed is not truncated" assertion passed over a
    // truncated list — a guard that could not fire, caught by mutating it.
    summary: `FW-${i % devices} stopped sending syslog for 2 consecutive hours. [obs-${i}]`,
    startAt: '2026-11-09T00:00:00.000Z',
    path: `/devices/dev${i % devices}`,
  }));
}

function spikes(count, devices = 1) {
  return Array.from({ length: count }, (_, i) => ({
    detector: 'denied_spike',
    naturalKey: `denied_spike:sdev${i % devices}:${i}`,
    deviceId: `sdev${i % devices}`,
    title: `FW-S${i % devices} denied traffic above normal`,
    summary: '4,812 against a ceiling of 1,230 over 27 observations.',
    startAt: '2026-11-20T00:00:00.000Z',
    path: `/devices/sdev${i % devices}`,
  }));
}

const CLEAN_STATES = {
  device_silent: { measured: 16, insufficient_baseline: 0, no_data: 0 },
  denied_spike: { measured: 16, insufficient_baseline: 0, no_data: 0 },
};

// ─────────────────────────────────────────────────────────────────────────────

describe('AnomalyPanel — a failed read is never put behind a chevron', () => {
  // ⛔ The one state that may not collapse. "These checks could not run" inside
  // a closed disclosure is the failed-read-as-a-fact rule with an affordance on
  // it: the section looks like every other quiet one on the page.
  it('renders the error with no <details> at all', () => {
    const markup = html({ error: 'relation "syslog_rollup_hourly" does not exist', result: null });
    assert.ok(!/<details/.test(markup), 'the error panel must not be collapsible');
    assert.match(strip(markup), /could not run/);
    assert.match(strip(markup), /not.{0,20}an all-clear/i);
  });
});

describe('AnomalyPanel — findings collapse, and nothing is dropped', () => {
  const result = { findings: silences(42, 3), states: CLEAN_STATES };

  it('is a <details> that is CLOSED on arrival', () => {
    const markup = html({ result });
    assert.match(markup, /<details/, 'expected a collapsible section');
    // renderToStaticMarkup emits `open=""` for an open <details>. Its absence
    // is the whole feature: the page must not open on three screens of prose.
    const tag = /<details[^>]*>/.exec(markup)[0];
    assert.ok(!/\sopen/.test(tag), `expected the section closed, got: ${tag}`);
  });

  it('COLLAPSED IS NOT TRUNCATED — every observation is still in the markup', () => {
    const markup = html({ result });
    // ⛔ naturalKey is React's `key` and never reaches the markup, so asserting
    // on it would be asserting on nothing. The per-observation token is what is
    // actually printed.
    for (let i = 0; i < result.findings.length; i += 1) {
      assert.ok(markup.includes(`[obs-${i}]`), `observation ${i} is missing from the page`);
    }
    // And every one still links to its firewall, so the collapse costs no route.
    assert.equal((markup.match(/href="\/devices\/dev/g) || []).length, 42);
  });

  it('the closed bar states WHAT is inside, not just how many', () => {
    // ⛔ The load-bearing assertion. A disclosure labelled "42 observations" is
    // a number nobody opens; one that says a firewall stopped sending syslog is
    // read. Disclosure.js's own test, applied to a whole section.
    const bar = barText({ result });
    assert.match(bar, /3 firewalls stopped sending syslog/);
    assert.match(bar, /42 observations/);
    assert.match(bar, /last 28 days/);
  });

  it('TWO UNITS, KEPT APART — 42 observations is never 42 firewalls', () => {
    const bar = barText({ result });
    assert.ok(!/42 firewalls/.test(bar), `the bar conflated observations with firewalls: ${bar}`);
    assert.match(bar, /on 3 firewalls/);
  });

  it('one firewall that went quiet six times reads as ONE firewall', () => {
    // The production shape: the same name repeated down the list because the
    // detector emits one finding per RUN.
    const bar = barText({ result: { findings: silences(6, 1), states: CLEAN_STATES } });
    assert.match(bar, /1 firewall stopped sending syslog/);
    assert.match(bar, /6 observations/);
    assert.ok(!/6 firewalls/.test(bar), bar);
  });
});

describe('AnomalyPanel — the mark is toned by what is actually inside', () => {
  // ⛔ Only the silence detector tints, matching the row badges. A denied-traffic
  // exceedance is an observation whose margin is often a few percent; putting it
  // on the severity ramp promises more than the measurement supports.
  it('a silence finding tints the bar pill warn', () => {
    const markup = html({ result: { findings: silences(3, 3), states: CLEAN_STATES } });
    const bar = /<summary[^>]*>([\s\S]*?)<\/summary>/.exec(markup)[1];
    assert.match(bar, /--tint-warn/);
  });

  it('denied-traffic exceedances alone do NOT reach the severity ramp', () => {
    const markup = html({ result: { findings: spikes(4, 2), states: CLEAN_STATES } });
    const bar = /<summary[^>]*>([\s\S]*?)<\/summary>/.exec(markup)[1];
    assert.ok(!/--tint-warn/.test(bar), 'a denied-traffic exceedance must not be tinted warn');
    assert.ok(!/--red|--sev-/.test(bar), 'nothing here belongs on the severity ramp');
    assert.match(strip(bar), /2 firewalls above normal denied traffic/);
  });

  it('a tinted GROUND is never used — tone belongs on a mark', () => {
    const markup = html({ result: { findings: silences(9, 2), states: CLEAN_STATES } });
    const tag = /<summary[^>]*>/.exec(markup)[0];
    assert.ok(!/tint|--red|--sev-/.test(tag),
      `the bar itself must stay --bg-card; tone goes on the pill: ${tag}`);
  });
});

describe('AnomalyPanel — coverage qualifies an empty list as hard as a full one', () => {
  const states = {
    device_silent: { measured: 14, insufficient_baseline: 1, no_data: 1 },
    denied_spike: { measured: 13, insufficient_baseline: 3, no_data: 0 },
  };

  it('no findings but an unjudged firewall still collapses, and SAYS so', () => {
    const bar = barText({ result: { findings: [], states } });
    assert.match(bar, /not measured on every firewall/);
    // ⛔ And it must not read as an all-clear while coverage is incomplete.
    assert.ok(!/No firewall stopped reporting/.test(bar), bar);
  });

  it('the coverage mark is HUELESS', () => {
    const markup = html({ result: { findings: [], states } });
    const bar = /<summary[^>]*>([\s\S]*?)<\/summary>/.exec(markup)[1];
    assert.ok(!/--tint-warn|--red|--sev-|--green/.test(bar),
      'a gap in OUR reach is not a severity of the customer’s');
    assert.match(bar, /--unmeasured|--hatch/);
  });

  it('the real per-detector numbers survive inside', () => {
    const body = text({ result: { findings: [], states } });
    assert.match(body, /1 with too little history to judge and 1 with no syslog at all/);
    assert.match(body, /3 with too little history to judge/);
  });

  it('NO FIREWALL COUNT on the bar — states are per (device, detector)', () => {
    // Summing across detectors tallies PAIRS, so a firewall unjudged by both
    // would be counted twice. The bar says "every firewall"; the numbers live
    // inside, per detector, where their denominator is stated.
    const bar = barText({ result: { findings: [], states } });
    assert.ok(!/5 firewalls|not measured on \d/.test(bar), bar);
  });
});

describe('AnomalyPanel — an earned all-clear has nothing to disclose', () => {
  it('renders no <details> when there are no findings and no gaps', () => {
    const markup = html({ result: { findings: [], states: CLEAN_STATES } });
    assert.ok(!/<details/.test(markup),
      'a chevron over an empty box is an affordance that lies');
    assert.match(strip(markup), /No firewall stopped reporting and none exceeded/);
  });
});

describe('describeAnomalies — the sentence the collapse rests on', () => {
  it('refuses a firewall count when a finding carries no device id', () => {
    // ⛔ Unreachable today — every detector sets deviceId — which is why the
    // branch is written rather than assumed away. Keying on the natural key
    // instead would count one firewall per observation.
    const findings = [...silences(3, 1), { detector: 'device_silent', naturalKey: 'x', title: 't', summary: 's' }];
    const d = describeAnomalies(findings, CLEAN_STATES, LOOKBACK);
    assert.equal(d.devices, null);
    assert.ok(!/firewalls? stopped/.test(d.sentence), d.sentence);
    assert.match(d.sentence, /4 silences observed/);
    assert.match(d.sentence, /4 observations/);
  });

  it('names an unregistered detector rather than dropping it from the bar', () => {
    const d = describeAnomalies(
      [{ detector: 'brand_new', naturalKey: 'k', deviceId: 'd1', title: 't', summary: 's' }],
      CLEAN_STATES, LOOKBACK
    );
    // It has no label and no phrase, but its rows WOULD render inside, so the
    // bar may not report an empty section over them.
    assert.equal(d.observations, 1);
    assert.equal(d.collapsible, true);
  });

  it('a non-array result is treated as nothing found, never as a throw', () => {
    const d = describeAnomalies(undefined, undefined, LOOKBACK);
    assert.equal(d.observations, 0);
    assert.equal(d.collapsible, false);
    assert.equal(d.tone, 'none');
  });
});
