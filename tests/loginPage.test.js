'use strict';
// tests/loginPage.test.js
//
// ⛔ THE SIGN-IN PAGE CARRIES FIVE DOCUMENTED SECURITY PROPERTIES AND HAD NO
// GUARD ON ANY OF THEM. Every one is recorded in CLAUDE.md or in a comment on
// the page itself, and every one is a single careless edit from disappearing —
// with no test failing, because each of them is an ABSENCE. Nothing breaks when
// a version number reappears in the footer; the page renders perfectly.
//
// ⛔ AND THE PRESSURE TO BREAK THEM IS REAL AND NAMED. The page was restyled on
// 2026-09-25 by explicit benchmark against `netvault/app/(auth)/login/page.tsx`,
// which does FOUR of these things differently: it prints its version and build
// number, paints a hardcoded "Platform Status: Operational" badge that measures
// nothing, reveals the MFA field only for accounts that have MFA, and uses the
// suite red. A later session diffing the two files will read those differences
// as drift. They are decisions. This file is where they are written down in a
// form that fails the build.
//
// Source-shape assertions, following tests/segmentation.test.js's precedent of
// reading a component's source: there is no DOM harness in this repo (see
// tests/README.md), and these properties are about what the file does NOT
// contain, which a render test is poorly placed to prove anyway.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const PAGE = path.join(ROOT, 'app', '(auth)', 'login', 'page.js');
const BACKDROP = path.join(ROOT, 'components', 'auth', 'LoginBackdrop.js');

const page = fs.readFileSync(PAGE, 'utf8');
const backdrop = fs.readFileSync(BACKDROP, 'utf8');

// Comments are where the REASONS live, so they must be stripped before asking
// what the code does — otherwise every rule below is "satisfied" by the comment
// explaining it. The same trap deviceScopeCoverage's transitive check hit, where
// prose saying a module held no device data was read as evidence that it did.
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/^\s*\/\/.*$/gm, ' ');
}
const code = stripComments(page);
const backdropCode = stripComments(backdrop);

describe('⛔ the sign-in page is PRE-AUTH — what it must never disclose', () => {
  it('never prints a version or build number', () => {
    // Measured live before this was removed: the login HTML read
    // "SecVault v2.61.2", which maps an unauthenticated visitor straight onto
    // the exact advisory set for that build. The sibling prints
    // "NocVault v1.2.0 • Build 2026.06.11" in the footer position.
    assert.doesNotMatch(code, /\bv?\d+\.\d+\.\d+\b/, 'a version-shaped string reached the login page');
    assert.doesNotMatch(code, /PRODUCT_VERSION|package\.json|APP_VERSION|\bBuild\b/i);
  });

  it('shows the product NAME, which is fine, and gets it from branding', () => {
    // The refusal above is about the version, not the identity — a login page
    // that will not say what product it is would be its own defect.
    assert.match(code, /PRODUCT_NAME/);
  });

  it('paints no health or status indicator', () => {
    // ⛔ THE ONE MOST WORTH KEEPING. NetVault renders a green dot plus the word
    // "Operational" as static markup — it measures nothing at all. On a product
    // whose thesis is that it does not assert what it has not measured, a
    // decorative health light on the first screen anyone sees breaks the rule
    // before sign-in. If one is ever added it must read a real probe, and an
    // unreadable probe must render as unknown rather than green.
    assert.doesNotMatch(code, /Operational|Platform Status|All systems|healthy/i);
  });
});

describe('⛔ the sign-in form is not an ORACLE', () => {
  it('renders the authenticator field unconditionally', () => {
    assert.match(code, /id="totp"/, 'the authenticator input is gone');
    // The input must not sit behind a conditional. Revealing it per-account
    // discloses which accounts are protected and therefore which are worth
    // attacking.
    const totpAt = code.indexOf('id="totp"');
    const fieldStart = code.lastIndexOf('login-field', totpAt);
    const before = code.slice(fieldStart, totpAt);
    assert.doesNotMatch(before, /&&|\?\s|mfaStage|mfaRequired|showTotp/,
      'the authenticator field became conditional — that turns the form into an oracle');
  });

  it('does not precheck whether an account has MFA', () => {
    // NetVault POSTs the credentials to /api/auth/mfa/precheck to decide whether
    // to show the field. That is the oracle above, plus a second credential
    // round-trip. CLAUDE.md's single-form rule is the other half of the same
    // decision: NextAuth v4's authorize() is ONE call.
    assert.doesNotMatch(code, /precheck|mfaRequired|mfaStage/i);
  });

  it('gives ONE failure message, which never names the code as the cause', () => {
    const messages = [...code.matchAll(/setError\(\s*'([^']+)'/g)].map((m) => m[1]);
    assert.ok(messages.length > 0, 'no failure message found at all');
    for (const m of messages) {
      assert.doesNotMatch(m, /code (was|is) (wrong|invalid|incorrect)|invalid code|wrong password|bad password/i,
        `a failure message distinguishes the factor that failed: "${m}"`);
    }
  });
});

describe('⛔ the return path and the timeout notice', () => {
  it('routes callbackUrl through safeReturnPath, never raw', () => {
    assert.match(code, /safeReturnPath\(\s*q\.get\('callbackUrl'\)\s*\)/,
      'callbackUrl must not reach the router without safeReturnPath — // and /\\ both resolve to another host');
  });

  it('reads the query string from window.location, not useSearchParams', () => {
    // useSearchParams() in a client component opts the whole subtree out of
    // static prerendering unless it is wrapped in Suspense.
    assert.doesNotMatch(code, /useSearchParams/);
    assert.match(code, /window\.location\.search/);
  });

  it('tints the timeout as INFORMATION and the failure as DANGER — never the same', () => {
    // Shown in red, a timeout reads as a rejected sign-in and the next thing
    // the user doubts is their password.
    assert.match(code, /login-note-info/, 'the timeout notice lost its info tint');
    assert.match(code, /login-note-error/, 'the failure notice lost its danger tint');
    const infoAt = code.indexOf('login-note-info');
    const errAt = code.indexOf('login-note-error');
    assert.notEqual(infoAt, errAt);
    // The timeout branch must be the one carrying the info class.
    const timeoutBlock = code.slice(code.indexOf('timedOut &&'), errAt);
    assert.match(timeoutBlock, /login-note-info/);
  });
});

describe('⛔ the page keeps SecVault’s palette, not the suite’s', () => {
  it('uses no suite red anywhere', () => {
    // v2.87.0 moved --primary off the shared #C8102E precisely so red could
    // mean danger and nothing else. The brand panel this replaced still glowed
    // rgba(200,16,46,0.14) — a decorative red wash on the first screen anyone
    // sees, which is the dilution that change existed to remove.
    for (const src of [code, backdropCode]) {
      assert.doesNotMatch(src, /#C8102E|200\s*,\s*16\s*,\s*46/i, 'suite red reached the login page');
    }
  });

  it('the page still carries the /login smoke marker verbatim', () => {
    // scripts/smoke.js asserts this exact sentence. If it is edited here and
    // not there, the ONE gate that actually loads this page goes green over a
    // page that did not render.
    const marker = 'Firewall security posture, in one place.';
    assert.match(page, new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    const smoke = fs.readFileSync(path.join(ROOT, 'scripts', 'smoke.js'), 'utf8');
    assert.match(smoke, new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
      'the login marker drifted out of scripts/smoke.js');
  });
});

describe('⛔ the animated backdrop is decoration and must behave like it', () => {
  it('honours prefers-reduced-motion', () => {
    assert.match(backdropCode, /prefers-reduced-motion/);
    // And still paints one frame, so a reduced-motion user gets the
    // composition rather than an empty ground.
    assert.match(backdropCode, /reduceMotion/);
  });

  it('cancels its animation frame and its listeners on unmount', () => {
    assert.match(backdropCode, /cancelAnimationFrame/);
    assert.match(backdropCode, /removeEventListener\('resize'/);
    assert.match(backdropCode, /removeEventListener\('visibilitychange'/);
  });

  it('pauses when the tab is hidden', () => {
    // A sign-in page is routinely left open in a background tab all day.
    assert.match(backdropCode, /visibilitychange/);
    assert.match(backdropCode, /document\.hidden/);
  });

  it('scales for device pixel ratio', () => {
    assert.match(backdropCode, /devicePixelRatio/);
  });

  it('is hidden from assistive technology', () => {
    assert.match(backdrop, /aria-hidden/);
  });
});
