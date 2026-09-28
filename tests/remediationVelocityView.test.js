'use strict';

// tests/remediationVelocityView.test.js
//
// Pins components/vulnerability/RemediationVelocity.js — A8's rendering.
//
// ⛔ THE DEFECT THIS FILE EXISTS TO PREVENT. Kaplan-Meier "survival" is the
// probability a subject has NOT had the event. Here the event is being patched,
// so S(t) = 100% means EVERY EXPOSURE IS STILL OPEN — the worst possible
// result, wearing the number a dashboard tints green. On the live fleet S(t) is
// flat at 1.0 for all 74 observed days, so this is not a hypothetical.
//
// The view is therefore tested on BEHAVIOUR (what the rendered tree contains)
// rather than on source shape, plus one source assertion for the negative rule
// that has no rendered form: `survivingPct` must never be read here at all.

const { describe, it, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { stripComments } = require('./stripComments');
const {
  summariseVelocity,
  velocityHeadline,
  buildExposure,
} = require('../lib/engines/remediationVelocity');

const SRC = path.join(__dirname, '..', 'components', 'vulnerability', 'RemediationVelocity.js');
const NOW = new Date('2026-09-28T00:00:00Z');

function openRow(over) {
  return Object.assign({
    device_id: 'dev-1',
    device_name: 'TSR-TL',
    cve_id: 'CVE-2026-24858',
    kev_listed: true,
    priority_band: 'patch_now',
    cvss_score: '9.4',
    advisory_published_at: new Date('2026-01-28T00:00:00Z'),
    advisory_known_at: new Date('2026-07-16T00:00:00Z'),
    device_first_seen_at: new Date('2026-07-16T00:00:00Z'),
    remediated_at: null,
  }, over || {});
}

describe('⛔ the view never renders the survival number', () => {
  test('`survivingPct` is not referenced outside comments', () => {
    // ⛔ THE INVERSION HAPPENS ONCE, IN THE ENGINE. A component that inverted
    // it itself would be a second definition of the polarity, and the wrong one
    // looks entirely plausible — the call securityScore.js makes about
    // riskScore, for the same reason.
    const src = stripComments(fs.readFileSync(SRC, 'utf8'));
    assert.ok(!/survivingPct/.test(src),
      'the component must read remediatedPct, which the engine supplies inverted');
  });

  test('there is no tint mapping that makes a zero rate look acceptable', () => {
    const src = stripComments(fs.readFileSync(SRC, 'utf8'));
    // The tone table must not map `bad` to anything but the danger tint.
    assert.match(src, /bad:\s*\{\s*bg:\s*'var\(--tint-danger\)'/,
      'a bad verdict must carry the danger tint');
    // And the fallback must not be `ok`.
    assert.match(src, /TONE_TINT\[tone\]\s*\|\|\s*TONE_TINT\.unknown/,
      'an unrecognised tone falls to unknown, never to ok');
  });
});

describe('the headline the view is handed, on the live fleet shape', () => {
  const allOpen = Array.from({ length: 246 }, (_, i) =>
    buildExposure(openRow({ device_id: `d${i % 16}`, kev_listed: i < 3 }), NOW));
  const summary = summariseVelocity(allOpen, NOW);

  it('is tinted bad, never ok, at a 0% remediation rate', () => {
    assert.equal(summary.remediatedPct, 0);
    assert.equal(velocityHeadline(summary).tone, 'bad');
  });

  it('⛔ the median is absent, and the view must caption it NOT REACHED', () => {
    // The wrong renders are "0 days" and a blank cell. The engine hands null;
    // the component's caption branch is what turns that into a sentence.
    assert.equal(summary.medianDaysToRemediate, null);
    const src = stripComments(fs.readFileSync(SRC, 'utf8'));
    assert.match(src, /not reached in/,
      'a null median must render as "not reached", never as 0 or as blank');
  });

  it('the KEV count is carried separately and is not folded into the total', () => {
    assert.equal(summary.kevOpen, 3);
    assert.ok(summary.kevLongestOpenDays > 0);
  });
});

describe('⛔ a failed read renders a refusal, not an empty fleet', () => {
  it('the engine gives the view nothing numeric to render', () => {
    // A shorter exposure list on this page reads as a fleet that patches
    // better than it does, so the refusal has to be total.
    const src = stripComments(fs.readFileSync(SRC, 'utf8'));
    assert.match(src, /if \(!ok \|\| !summary\)/,
      'the view must refuse on either flag, not only on ok');
    assert.match(src, /could not be measured/);
  });

  it('the refusal names which source failed', () => {
    const src = stripComments(fs.readFileSync(SRC, 'utf8'));
    assert.match(src, /failures\.map\(\(f\) => f\.source\)/,
      'an operator has to know which half is dead');
  });
});

describe('⛔ the second clock is kept out of the operator-accountable figures', () => {
  it('the unaware window is its own panel, not a column beside the ages', () => {
    // Mixing "time before SecVault held the advisory" into the response-time
    // figures reads as operator delay for a window nobody here could act in.
    const src = stripComments(fs.readFileSync(SRC, 'utf8'));
    assert.match(src, /Before SecVault could have told you/);
    assert.match(src, /not time anyone here could have acted in/);
  });

  it('the engine supplies both clocks on every exposure', () => {
    const e = buildExposure(openRow(), NOW);
    assert.ok(e.daysSinceKnown > 0);
    assert.ok(e.daysSincePublished > e.daysSinceKnown);
  });
});

describe('the smoke markers cover BOTH render paths', () => {
  // ⛔ NOT `require`d. This component is JSX/ESM and node:test cannot load it —
  // the first draft of this block did require it, and the suite then failed at
  // CONSTRUCTION while the summary line still read `# fail 0`. Only the exit
  // code showed it. Source is read as text instead.
  const raw = fs.readFileSync(SRC, 'utf8');
  const stripped = stripComments(raw);

  it('the happy-path marker is rendered', () => {
    assert.match(raw, /export const VELOCITY_PURPOSE/);
    assert.ok(stripped.includes('{VELOCITY_PURPOSE}'), 'the constant must actually be rendered');
  });

  it('⛔ the REFUSAL path has its own marker, because the purpose line is not on it', () => {
    // The purpose line sits after the `!ok || !summary` early return, so a
    // failed read renders the EmptyState and NOT the purpose line. A sweep
    // carrying only the happy-path marker would report the tab as broken
    // whenever a source was merely unavailable — and, worse, an author who
    // "fixed" that by loosening the marker would lose the blank-page check.
    // Both strings are markers; `markers` is an OR, which is exactly right here
    // because both are successful renders.
    const purposeAt = stripped.indexOf('{VELOCITY_PURPOSE}');
    const refusalAt = stripped.indexOf('could not be measured');
    assert.ok(refusalAt > -1, 'the refusal must carry its own distinctive string');
    assert.ok(refusalAt < purposeAt,
      'the refusal returns first — which is why it needs a marker of its own');
  });

  it('neither marker is a nav label or too short to be distinctive', () => {
    const NAV = ['Overview', 'Vulnerabilities', 'Compliance', 'Settings', 'Reports'];
    for (const m of ['Remediation velocity could not be measured',
      'How long a vulnerability SecVault knows about stays open']) {
      assert.ok(!NAV.includes(m));
      assert.ok(m.length > 12);
    }
  });
});
