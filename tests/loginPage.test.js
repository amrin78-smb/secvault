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
    .replace(/^\s*\/\/.*$/gm, ' ')
    .replace(/\/\*[\s\S]*?\*\//g, ' ');
}
const code = stripComments(page);
const backdropCode = stripComments(backdrop);

/**
 * The initial value of ONE named useState declaration, as written.
 *
 * ⛔ THIS EXISTS BECAUSE A BARE REGEX OVER THE WHOLE FILE CANNOT PIN A DEFAULT.
 * The showCode guard below used to be `assert.match(code, /useState\(false\)/)`
 * — and the page declares SIX states that way. Mutating the showCode line to
 * `useState(true)`, which is the exact regression the test names in its own
 * failure message, left it green: any of the other five satisfied it. That is
 * the shape CLAUDE.md records for v2.193.0 itself, where 24 tests pinned the
 * MECHANISM and none pinned the DEFAULT, and the feature shipped doing nothing.
 *
 * Returns null when the declaration is absent, so a RENAMED state fails its
 * assertion loudly instead of quietly matching something else.
 */
function initialStateOf(name) {
  const re = new RegExp(
    `const\\s*\\[\\s*${name}\\s*,\\s*set[A-Za-z0-9_]+\\s*\\]\\s*=\\s*useState\\(([^)]*)\\)`
  );
  const m = re.exec(code);
  return m ? m[1].trim() : null;
}

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
  // ⛔ THIS BLOCK CHANGED IN v2.193.0, AND WHAT IT GUARDS CHANGED WITH IT.
  //
  // It used to require the authenticator field to render UNCONDITIONALLY, on
  // the grounds that revealing it per-account discloses which accounts are
  // protected. The field is now revealed only when the account needs it — but
  // the disclosure that worried this test never happens, because
  // /api/auth/mfa/precheck VERIFIES THE PASSWORD BEFORE ANSWERING. Without
  // valid credentials every caller gets the same `{ ok: false }` and the field
  // is shown regardless.
  //
  // So the oracle property is still pinned; it has simply moved. What must hold
  // now is that the FORM cannot reveal anything on its own — it asks a server
  // that is itself password-gated (tests/mfaPrecheck.test.js pins that end) and
  // treats every unclear answer as "show it".

  it('still renders the authenticator field, hidden until something reveals it', () => {
    assert.match(code, /id="totp"/, 'the authenticator input is gone');
    // ⛔ HIDDEN BY DEFAULT IS THE WHOLE POINT, and the first implementation got
    // it backwards: it started VISIBLE and hid the field on an explicit "no".
    // Since the answer only arrives after a submit, and a user without MFA is
    // signed in BY that submit, the box showed on every page load and was never
    // hidden in practice — the feature shipped doing nothing.
    //
    // ⛔ AND THE GUARD ON THAT WAS ITSELF A GUARD THAT COULD NOT FIRE, for five
    // versions. See initialStateOf() at the top of this file for what it missed
    // and why a whole-file regex can never pin a default.
    assert.notEqual(initialStateOf('showCode'), null,
      'the showCode state is gone or renamed — if that is deliberate, rewrite this test rather than deleting it');
    assert.equal(initialStateOf('showCode'), 'false',
      'showCode must start hidden — starting visible makes the reveal logic inert, which is how v2.193.0 shipped');
    // ⛔ CONDITIONALLY RENDERED, not merely marked `hidden`: `.login-field`
    // sets display:flex, which beats the UA `[hidden]` rule, so the attribute
    // was inert and the box stayed on screen.
    assert.match(code, /\{showCode && \(/);
    assert.doesNotMatch(code, /className="login-field" hidden=/);
  });

  it('⛔ THREE independent paths reveal it, so it can never be missing when needed', () => {
    // precheck says yes; precheck could not tell; a sign-in failed.
    assert.match(code, /revealCode\(\);/, 'the affirmative answer must reveal it');
    const nullBranch = code.slice(code.indexOf('if (needed === null)'));
    assert.match(nullBranch.slice(0, 600), /setShowCode\(true\)/,
      'an unclear answer must reveal it');
    const failBranch = code.slice(code.indexOf('Sign-in failed.'));
    assert.match(failBranch.slice(0, 600), /setShowCode\(true\)/,
      'a failed sign-in must reveal it, whatever the precheck claimed');
  });

  it('⛔ an unclear answer still SUBMITS rather than blocking the sign-in', () => {
    const at = code.indexOf('if (needed === null)');
    assert.ok(at > -1);
    // Bounded to the block's OWN closing brace, located with indexOf so there
    // is no newline escape in the expression. A fixed-width window ran past
    // the block into the try below and matched THAT code's return.
    const end = code.indexOf('      }', at);
    const block = code.slice(at, end > at ? end : at + 400);
    assert.ok(block.length > 0 && block.length < 700, 'the block bound looks wrong');
    assert.doesNotMatch(block, /return;/,
      'refusing to submit here would block every sign-in while the precheck is down');
    assert.match(block, /setShowCode\(true\)/);
  });

  it('⛔ the form never decides on the username alone', () => {
    // The precheck is sent BOTH credentials. A request carrying only the
    // username would be answerable without a password, which is the oracle
    // this block has always existed to prevent.
    const at = code.indexOf('/api/auth/mfa/precheck');
    assert.ok(at > -1, 'the precheck call is gone — if that is deliberate, rewrite this test');
    const call = code.slice(at, at + 400);
    assert.match(call, /JSON\.stringify\(\{ username, password \}\)/,
      'the precheck must be sent the password, or it cannot gate its answer on one');
  });

  it('⛔ every unclear answer shows the field', () => {
    const fn = code.slice(code.indexOf('async function askWhetherCodeNeeded'));
    // Split on the closing brace at indent 2 rather than searching for a
    // newline escape sequence: there is then nothing for a code generator to
    // mangle. Writing that escape through one turned it into a REAL newline
    // and broke this file, twice in one session.
    const body = fn.split(/^  \}/m)[0];
    assert.match(body, /if \(!res\.ok\) return null;/);
    assert.match(body, /data\.ok !== true/);
    assert.match(body, /catch \{\s*return null;/);
  });

  it('gives ONE failure message, which never names the code as the cause', () => {
    // ⛔ UNCHANGED, and it still matters. The precheck confirms a password to
    // whoever already HAS it; the failure message must still confirm nothing
    // to whoever does not.
    const messages = [...code.matchAll(/setError\(\s*'([^']+)'/g)].map((m) => m[1]);
    assert.ok(messages.length > 0, 'no failure message found at all');
    for (const m of messages) {
      assert.doesNotMatch(m, /code (was|is) (wrong|invalid|incorrect)|invalid code|wrong password|bad password/i,
        `a failure message distinguishes the factor that failed: "${m}"`);
    }
  });
});

describe('⛔ controls that must start HIDDEN, for the same reason showCode does', () => {
  it('the Microsoft button is off until the SERVER says the provider exists', () => {
    // A "Sign in with Microsoft" button on an installation with no tenant is a
    // button that cannot complete — it reads as a broken product on the first
    // screen anybody sees. Starting it true and hiding it on a negative answer
    // repeats v2.193.0 exactly: the answer arrives after paint, so the wrong
    // default is what every visitor sees.
    assert.notEqual(initialStateOf('entraAvailable'), null,
      'the entraAvailable state is gone or renamed — if deliberate, rewrite this test');
    assert.equal(initialStateOf('entraAvailable'), 'false',
      'the SSO button must start hidden and be revealed by getProviders(), never the reverse');
  });
});

describe('⛔ the two sign-in cues explain themselves, and echo nothing', () => {
  // TWO agreed literals, and they are NOT interchangeable:
  //
  //   /login?sso=refused — TERMINAL. The front door turned the account away;
  //                        an administrator must map a group before anything
  //                        changes. Telling this user to sign in again wastes
  //                        their afternoon.
  //   /login?sso=norole  — frequently TRANSIENT. An already-issued session's
  //                        role went null, so signing in again genuinely does
  //                        fix it. Its causes include a deleted LOCAL account
  //                        and a database outage, so its copy may not name a
  //                        provider at all.
  //
  // ⛔ BEHAVIOUR, NOT SHAPE. Each case below pulls the page's OWN matching
  // expression and RUNS it against real query strings. A regex asserting the
  // line still looks similar would be satisfied by a startsWith, a case fold
  // or a lookup in a map object — three plausible "improvements", each of
  // which renders a panel for values nobody agreed to. CLAUDE.md records the
  // same move on cveHub's freshnessErrors(): a test that asserted the line
  // EXISTED passed while the line never ran.
  const CUES = [
    { state: 'ssoRefused', setter: 'setSsoRefused', value: 'refused' },
    { state: 'ssoNoRole', setter: 'setSsoNoRole', value: 'norole' },
  ];

  const matcherFor = (cue) => {
    const assign = new RegExp(`${cue.setter}\\(([^;]+)\\);`).exec(code);
    assert.ok(assign,
      `nothing assigns ${cue.state}: a user sent to /login?sso=${cue.value} lands on a silent page`);
    return (search) => {
      const q = new URLSearchParams(search);
      // eslint-disable-next-line no-new-func
      return Function('q', `return (${assign[1]});`)(q);
    };
  };

  const blockFor = (cue) => {
    const at = code.indexOf(`${cue.state} &&`);
    assert.ok(at > -1, `${cue.state} is set and nothing renders it — the state is dead`);
    const end = code.indexOf('</p>', at);
    assert.ok(end > at, 'the notice block could not be bounded');
    return code.slice(at, end);
  };

  /**
   * The words a user actually reads, with the condition and the tag stripped.
   *
   * ⛔ THE COPY, NOT THE BLOCK, AND THE DIFFERENCE WAS MEASURED. The
   * "do not share one piece of copy" case below first compared blockFor()
   * output — which BEGINS with `ssoRefused &&` or `ssoNoRole &&`, so the two
   * can never be equal and the assertion could never fail. Mutating the page
   * to render byte-identical sentences for both cues left it GREEN. That is
   * the same guard-that-cannot-fire shape this file already records twice (the
   * whole-file useState regex, and v2.193.2 asserting an attribute instead of
   * what rendered); it is easy to write and invisible once written.
   */
  const copyFor = (cue) => {
    const m = /<p className="[^"]*">([\s\S]*)$/.exec(blockFor(cue));
    assert.ok(m, `the ${cue.state} notice is not a <p> with a class — rewrite this helper`);
    return m[1].replace(/\s+/g, ' ').trim();
  };

  for (const cue of CUES) {
    it(`?sso=${cue.value} renders for that value, and NOTHING for anything else`, () => {
      const matches = matcherFor(cue);
      assert.equal(matches(`?sso=${cue.value}`), true, 'the agreed value must show its notice');

      // ⛔ THE "WE CANNOT TELL" CASES, which are the ones that rot silently. An
      // unrecognised value must render NOTHING — not an empty panel, and above
      // all not a guess at what happened. Absence of a recognised cue is not
      // evidence of a cue.
      assert.equal(matches(''), false, 'no sso parameter at all must render nothing');
      assert.equal(matches('?sso='), false, 'an empty value must render nothing');
      assert.equal(matches(`?sso=${cue.value.toUpperCase()}`), false,
        'case must not be folded — these are agreed literals between two files, not user input');
      assert.equal(matches(`?sso=${cue.value}-by-policy`), false,
        'a prefix match would accept outcomes nobody defined');
      assert.equal(matches('?sso=denied'), false, 'an unrecognised outcome must render nothing');

      // ⛔ THE PROTOTYPE CASES, and they matter MORE now there are two values:
      // a second literal is exactly when `NOTICES[q.get('sso')]` starts to
      // look like the tidy refactor. That lookup answers TRUTHY for all three
      // of these and would push something nobody wrote onto an unauthenticated
      // page. Two equality tests cannot; a third cue is a third line.
      for (const inherited of ['toString', 'constructor', 'valueOf']) {
        assert.equal(matches(`?sso=${inherited}`), false,
          `the match must be an equality test, never a property lookup (?sso=${inherited} matched)`);
      }
    });
  }

  it('⛔ the two cues never fire for each other', () => {
    // They carry OPPOSITE advice — one says sign in again, the other says do
    // not bother until someone acts. A widened match that crossed them over
    // would be worse than either notice missing.
    for (const cue of CUES) {
      const matches = matcherFor(cue);
      for (const other of CUES) {
        if (other === cue) continue;
        assert.equal(matches(`?sso=${other.value}`), false,
          `?sso=${other.value} also triggers the ${cue.state} notice — the advice would contradict itself`);
      }
    }
  });

  it('⛔ never renders text taken from the URL', () => {
    // This page is UNAUTHENTICATED. Printing caller-supplied text under the
    // product's own brand, on the real hostname, behind the real certificate,
    // is how a login page becomes a phishing surface — "your password has
    // expired, call this number" served by the genuine console. The copy is a
    // literal in the page; the query string only ever SELECTS it.
    assert.doesNotMatch(code, /\{\s*q\.get\(/, 'query-string text is being rendered into the page');
    assert.doesNotMatch(code, /set(Sso|SSO)(Reason|Message|Detail|Error)\b/,
      'a reason string from the URL is being held in state — match a known value and render your own copy');
  });

  for (const cue of CUES) {
    it(`?sso=${cue.value} is tinted as INFORMATION, like the timeout and unlike a failure`, () => {
      // ⛔ THE SHARPEST VERSION OF THE TIMEOUT ARGUMENT. Nothing the user typed
      // was wrong — in the refusal case their credentials were accepted before
      // SecVault turned them away, and in the role case they were accepted at
      // sign-in. In the danger tint either one reads as a rejected password,
      // and the next thing the user does is doubt one that is fine, or retry
      // it until something locks.
      const block = blockFor(cue);
      assert.match(block, /login-note-info/, 'the notice lost its information tint');
      assert.doesNotMatch(block, /login-note-error/,
        'tinted as danger, this accuses the one thing that was NOT wrong');
    });
  }

  it('⛔ refused: does not disclose WHICH refusal occurred, and points at a human', () => {
    // Missing group claim, no matching group, and a claims overage need three
    // different administrator fixes, and naming them here publishes the
    // tenant's group-mapping state to anyone who can load the login page. The
    // named reason already goes where it can be acted on: Settings -> Single
    // sign-on. What this page owes the user is "stop retrying, ask someone".
    const block = blockFor(CUES[0]);
    assert.doesNotMatch(block, /overage|claim|no matching|unmapped group|tenant|object id/i,
      'the notice names the specific refusal — that belongs in Settings, not on an unauthenticated page');
    assert.match(block, /administrator/i,
      'the notice must say who can fix this, or it is a dead end wearing an explanation');
  });

  it('⛔ norole: is PROVIDER-NEUTRAL, because the cause is often not SSO at all', () => {
    // ⛔ THIS VALUE ALSO FIRES FOR A DELETED LOCAL ACCOUNT AND FOR A DATABASE
    // OUTAGE. Telling a local administrator whose database blipped that their
    // single sign-on failed sends them, and whoever they ask, to debug a
    // system they may not even run — a confident wrong mechanism, which this
    // codebase rates worse than no explanation at all. The three causes are
    // genuinely indistinguishable from the login page, so the copy names none
    // of them.
    const block = blockFor(CUES[1]);
    assert.doesNotMatch(block, /microsoft|entra|directory|single sign|\bSSO\b|tenant|azure|LDAP/i,
      'the role notice names a provider — it also fires for a local account and for a database outage');
    assert.match(block, /administrator/i, 'the notice must say who can look into it');
  });

  it('⛔ the two cues do not share one piece of copy', () => {
    // If they ever collapse into the same sentence, one of the two situations
    // is being described wrongly — the whole reason there are two values is
    // that "sign in again" is correct advice for exactly one of them.
    const [refused, norole] = CUES.map(copyFor);
    assert.ok(refused.length > 0 && norole.length > 0, 'a cue renders an empty notice');
    assert.notEqual(refused, norole, 'both cues render the same notice — then one of them is lying');
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

  it('⛔ derives its boundary from the CARD, and draws no standalone plane', () => {
    // v2.184.0 drew a vertical inspection plane at a fixed 46% of the width.
    // On a real screen it read as a PANEL DIVIDER — a hard full-height seam
    // between the pitch and the form, which is exactly the navy/white split
    // the redesign existed to remove — and it had no visible relationship to
    // the packets, so it looked accidental rather than designed.
    //
    // The boundary is now the sign-in card's own left edge, measured from the
    // DOM. That removes the line and makes the motion explain the card's
    // position instead of competing with it.
    assert.match(backdropCode, /querySelector\('\.login-card'\)/,
      'the boundary must be measured from the card, not assumed');
    assert.match(backdropCode, /getBoundingClientRect/);
    assert.doesNotMatch(backdropCode, /PLANE_X|PLANE_LINE|planePx/,
      'a standalone drawn inspection plane came back — it reads as a panel divider');
  });

  it('⛔ most traffic PASSES — the firewall does not drop everything', () => {
    // v2.184.1 absorbed every packet at the card's leading edge. Wrong twice
    // over: a firewall that dropped everything would be a broken one, so the
    // picture told a false story about the product — and with nothing emerging
    // on the far side, the whole region right of the card (a quarter of a wide
    // viewport) was dead space. Only the flaring minority is stopped now.
    assert.match(backdropCode, /cardRight/,
      'the card’s FAR edge is gone — traffic can no longer emerge, so nothing passes');
    assert.match(backdropCode, /PASSED_GAIN/,
      'allowed traffic must read brighter on the far side than on the way in');
    // And the stopped minority must stay a minority.
    const rate = Number((/FLARE_RATE\s*=\s*([\d.]+)/.exec(backdropCode) || [])[1]);
    assert.ok(Number.isFinite(rate), 'FLARE_RATE is gone');
    assert.ok(rate > 0 && rate < 0.35,
      `${rate} of traffic stopped — above about a third this reads as a broken firewall, not a working one`);
  });

  it('⛔ keeps the density low enough to read as motion rather than static', () => {
    // 20 lanes x 6 packets at near-identical length and alpha resolved as
    // STATIC, and put noise behind a 30px headline. Fewer and more varied is
    // what reads as flow; this is a legibility setting, not a taste one.
    const lanes = Number((/LANE_COUNT\s*=\s*(\d+)/.exec(backdropCode) || [])[1]);
    const perLane = Number((/PER_LANE\s*=\s*(\d+)/.exec(backdropCode) || [])[1]);
    assert.ok(Number.isFinite(lanes) && Number.isFinite(perLane), 'density constants are gone');
    assert.ok(lanes * perLane <= 60,
      `${lanes * perLane} packets — past about 60 this reads as static, not traffic`);
  });
});

describe('⛔ the headline is not asked to compete with the backdrop', () => {
  it('a scrim sits under the centred content', () => {
    // Moving marks under 30px type cost legibility, and the first screen of a
    // security console is the wrong place to trade that for atmosphere.
    const css = fs.readFileSync(path.join(ROOT, 'app', 'globals.css'), 'utf8');
    assert.match(css, /\.login-center::before/, 'the content scrim is gone');
  });
});
