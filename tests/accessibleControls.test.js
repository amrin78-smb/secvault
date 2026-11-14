'use strict';
// tests/accessibleControls.test.js
//
// ⛔ EVERY DEFECT PINNED HERE WAS ON A CONTROL THAT WAS THE ONLY WAY TO DO
// SOMETHING, which is what separates these from cosmetic accessibility debt. A
// keyboard-only user could not open an alert from the notification bell, could
// not reach "Stay signed in" before their session ended, could not learn why a
// segmentation cell was flagged, and heard no name at all on the control that
// grants `manage_users`.
//
// ⛔ AND THE GUARDS FOUND FOUR MORE INSTANCES THAN THE ROADMAP ROW LISTED —
// components/ui/Evidence.js plus three fields in
// components/config/ConditionsManager.js. The row was compiled by reading; a
// scan reads every file. That is the whole argument for writing the guard
// before the fix rather than after it.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { stripComments } = require('./stripComments');

const REPO = path.join(__dirname, '..');
const SKIP = new Set(['node_modules', '.next', '.git', 'tests', 'installer', 'public', 'docs', '.playwright-mcp']);

// ⛔ THE TRAP IS LOADED AND RUN, NOT ONLY READ — AND A FAILED LOAD IS A VISIBLE
// SKIP, NEVER A PASS. `components/ui/useFocusTrap.js` is an ES module in a
// package with no `"type"`, so loading it from this CommonJS test relies on
// Node's module-syntax detection (default since 22.7) plus `require(esm)`
// (default since 22.12). The dev box runs Node 22 and that is where the suite
// runs; the production server runs Node 20 and does not run tests. Rather than
// assert a Node-20 behaviour nobody here could measure, the load is attempted
// and the REASON is printed when it fails — the `tests/psScripts.js` contract:
// "could not measure here" is visible, where a silent green tick over an unrun
// check is the guard-that-cannot-fire pattern.
let TRAP = null;
let TRAP_SKIP = null;
try {
  // eslint-disable-next-line global-require, import/no-dynamic-require
  TRAP = require(path.join(REPO, 'components/ui/useFocusTrap.js'));
} catch (err) {
  TRAP_SKIP = `could not load components/ui/useFocusTrap.js here (${err.code || err.name}: `
    + `${String(err.message).split('\n')[0]}) — needs Node >= 22.12 for require() of an ES `
    + `module; this process is ${process.version}. NOT a pass: the behavioural trap tests did `
    + 'not run.';
}

function sourceFiles() {
  const out = [];
  (function walk(dir) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (SKIP.has(e.name)) continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.js')) out.push(p);
    }
  })(REPO);
  return out;
}

// keepLines so a reported line number matches the real file.
const readStripped = (f) => stripComments(fs.readFileSync(f, 'utf8'), { keepLines: true });
const rel = (f) => path.relative(REPO, f);
const lineOf = (code, index) => code.slice(0, index).split('\n').length;

describe('aria-modal is a promise, and it needs a focus trap to be true', () => {
  // ⛔ `aria-modal="true"` TELLS ASSISTIVE TECHNOLOGY EVERYTHING OUTSIDE THE
  // DIALOG IS INERT. Declaring it without managing focus is worse than not
  // declaring it: the user's focus point is still out in a page the screen
  // reader has been told to ignore. components/layout/IdleTimeout.js declared
  // it with `grep -c focus` === 0 — so "Stay signed in", the only control that
  // saves the session, was unreachable while the countdown ran.
  //
  // ⛔ NAMED EXEMPTIONS WITH A REASON EACH, never a silent skip.
  //
  // ⛔ components/ui/Evidence.js WAS EXEMPT HERE AND NO LONGER IS (roadmap row
  // 58, fixed). It had 3 of the 4 mechanisms, all of them in the
  // EvidenceProvider rather than the panel, and was missing only Tab
  // confinement — so Tab walked out of the product's most-used dialog while
  // `aria-modal` claimed the page behind it was inert. It now calls the shared
  // hook in `confineOnly` mode, which adds the one missing mechanism without
  // introducing a second focus restore to race the provider's.
  const EXEMPT = Object.freeze({
    'components/ui/useFocusTrap.js':
      'it IS the trap; it names aria-modal in its own contract',
  });

  it('⛔ every dialog declaring aria-modal uses the ONE shared focus trap', () => {
    const offenders = [];
    for (const f of sourceFiles()) {
      const r = rel(f);
      if (EXEMPT[r]) continue;
      const code = readStripped(f);
      if (!/aria-modal/.test(code)) continue;
      // ⛔ AN IMPORT AND A CALL, NOT A MENTION. The first draft tested
      // `!/useFocusTrap/` and a mutation that DELETED IdleTimeout's import line
      // stayed green, because the identifier still appeared in the call below it
      // and in a comment. A guard satisfied by prose about the thing is the
      // defect this repo names most often — and it escaped inside the suite
      // written to catch guards that cannot fire.
      const imported = /import\s+useFocusTrap\s+from\s+'[^']*useFocusTrap'/.test(code);
      const called = /useFocusTrap\s*\(\s*\{/.test(code);
      if (!imported || !called) offenders.push(`${r}${imported ? '' : ' (no import)'}${called ? '' : ' (never called)'}`);
    }
    assert.deepEqual(
      offenders, [],
      'these declare aria-modal without components/ui/useFocusTrap, so focus is '
      + 'not moved in, Tab is not confined and focus is not restored — the dialog '
      + 'claims the page behind it is inert while it is still reachable:\n  '
      + offenders.join('\n  ')
    );
  });

  it('the hook arms NOTHING while the dialog is unreachable', () => {
    // ⛔ THE SHARPEST HAZARD IN THE Evidence.js FIX, and the one thing here that
    // only the React layer can answer — so it is pinned on the source, and
    // stated as a source pin. The evidence drawer is NEVER UNMOUNTED: it is
    // pushed off-screen with a transform and marked aria-hidden/inert. A trap
    // armed on that closed panel would swallow Tab for the whole page on all 30
    // dashboard pages — strictly worse than the missing confinement it fixes.
    // `Modal` and `IdleTimeout` return null when shut and so cannot reach this,
    // which is exactly why nothing caught it before the drawer became a caller.
    const src = readStripped(path.join(REPO, 'components/ui/useFocusTrap.js'));
    assert.match(
      src, /if\s*\(\s*!active\s*\)\s*return/,
      'useFocusTrap must bail out of its effect when the dialog is not active, '
      + 'or a mounted-but-hidden panel traps Tab for the entire page'
    );
  });

  it('⛔ the full four mechanisms stay the DEFAULT for every other dialog', () => {
    // A call-site pin, because `confineOnly` is a claim that the other three
    // mechanisms live somewhere else — true of the evidence drawer, false of
    // these two, and `aria-modal` is a lie without them. Behavioural proof that
    // the default really does all four is in the harness below; this is what
    // stops a caller opting out of it.
    for (const f of ['components/ui/Modal.js', 'components/layout/IdleTimeout.js']) {
      const src = readStripped(path.join(REPO, f));
      assert.ok(
        !/confineOnly/.test(src),
        `${f} must take the DEFAULT focus trap: it implements none of the other `
        + 'three mechanisms itself, so confinement alone would leave aria-modal '
        + 'promising an inert page with focus still outside the dialog'
      );
    }
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// ⛔ THE TRAP IS EXERCISED, NOT READ. What stood here was five regexes over the
// hook's own source (`/document\.activeElement/`, `/'Tab'/`, …) — the shape of
// guard that has already been satisfied by a MENTION twice in this file's own
// history, once with the import deleted. The hook's four mechanisms are plain
// DOM work; React only decides WHEN they are armed. So the imperative half is
// `installFocusTrap(getPanel, {win, doc})` and these tests drive it against a
// stand-in document: real code, real key events, asserted OUTCOMES.
//
// ⛔ What the stand-in deliberately does NOT model: `querySelectorAll` returns
// the children it was given and ignores the selector, because the selector is
// not what is under test here — it is exported data and asserted as data below.
// Everything else (which node ends up focused, how many times, whether the
// event was swallowed, whether a listener survives release) is real.
function makeDom() {
  const doc = { activeElement: null };
  const keydown = [];
  const win = {
    addEventListener(type, fn) { if (type === 'keydown') keydown.push(fn); },
    removeEventListener(type, fn) {
      const i = keydown.indexOf(fn);
      if (type === 'keydown' && i >= 0) keydown.splice(i, 1);
    },
  };
  const node = (name) => {
    const n = {
      name,
      focusCount: 0,
      focus() { n.focusCount += 1; doc.activeElement = n; },
    };
    return n;
  };
  const panel = (children) => {
    const p = {
      name: 'panel',
      focusCount: 0,
      focus() { p.focusCount += 1; doc.activeElement = p; },
      querySelectorAll: () => children.slice(),
    };
    return p;
  };
  const press = (key, { shiftKey = false } = {}) => {
    const e = {
      key,
      shiftKey,
      prevented: false,
      preventDefault() { e.prevented = true; },
    };
    for (const fn of keydown.slice()) fn(e);
    return e;
  };
  return { doc, win, node, panel, press, listeners: () => keydown.length };
}

describe('the shared focus trap, run against a stand-in document', () => {
  const skip = TRAP_SKIP ? { skip: TRAP_SKIP } : {};

  // A dialog with three focusables and an opener outside it, which is the shape
  // every caller has: Modal's forms, IdleTimeout's two buttons, the evidence
  // drawer's close button.
  function arm(opts) {
    const dom = makeDom();
    const opener = dom.node('opener');
    const first = dom.node('first');
    const middle = dom.node('middle');
    const last = dom.node('last');
    const panel = dom.panel([first, middle, last]);
    dom.doc.activeElement = opener;
    opener.focusCount = 0;
    const release = TRAP.installFocusTrap(() => panel, { win: dom.win, doc: dom.doc, ...opts });
    return { dom, opener, first, middle, last, panel, release };
  }

  describe('the default — all four mechanisms, which is what aria-modal promises', () => {
    it('moves focus INTO the panel, and remembers what had it', skip, () => {
      const t = arm({});
      assert.equal(t.dom.doc.activeElement, t.first, 'focus must land on the first focusable');
      assert.equal(t.first.focusCount, 1);
      t.release();
      assert.equal(t.dom.doc.activeElement, t.opener, 'and must be handed back on release');
      assert.equal(t.opener.focusCount, 1);
    });

    it('cycles Tab from the last focusable back to the first', skip, () => {
      const t = arm({});
      t.last.focus();
      const e = t.dom.press('Tab');
      assert.equal(e.prevented, true, 'Tab at the end must be swallowed, not passed to the page');
      assert.equal(t.dom.doc.activeElement, t.first);
    });

    it('cycles Shift+Tab from the first focusable back to the last', skip, () => {
      const t = arm({});
      t.first.focus();
      const e = t.dom.press('Tab', { shiftKey: true });
      assert.equal(e.prevented, true);
      assert.equal(t.dom.doc.activeElement, t.last);
    });

    it('leaves Tab alone in the middle of the panel', skip, () => {
      const t = arm({});
      t.middle.focus();
      const e = t.dom.press('Tab');
      assert.equal(e.prevented, false, 'the browser must still move focus normally inside');
      assert.equal(t.dom.doc.activeElement, t.middle);
    });

    it('Escape is opt-in: it fires a handler when given one', skip, () => {
      let closed = 0;
      const t = arm({ onEscape: () => { closed += 1; } });
      t.dom.press('Escape');
      assert.equal(closed, 1);
    });

    it('…and does nothing at all when no handler was passed', skip, () => {
      // ⛔ IdleTimeout passes none on purpose — there is nothing to close, and a
      // dismissable deadline warning would hide a session that still ends.
      const t = arm({});
      assert.doesNotThrow(() => t.dom.press('Escape'));
      assert.equal(t.dom.doc.activeElement, t.first, 'Escape must not move focus by itself');
    });

    it('releases its listener, so a closed dialog cannot still swallow Tab', skip, () => {
      const t = arm({});
      assert.equal(t.dom.listeners(), 1);
      t.release();
      assert.equal(t.dom.listeners(), 0);
    });
  });

  describe('⛔ confineOnly — mechanism 3 ALONE, for a caller that owns the other three', () => {
    it('still cycles Tab in both directions', skip, () => {
      const fwd = arm({ confineOnly: true });
      fwd.last.focus();
      const a = fwd.dom.press('Tab');
      assert.equal(a.prevented, true, 'confinement is the whole point of this mode');
      assert.equal(fwd.dom.doc.activeElement, fwd.first);

      const back = arm({ confineOnly: true });
      back.first.focus();
      const b = back.dom.press('Tab', { shiftKey: true });
      assert.equal(b.prevented, true);
      assert.equal(back.dom.doc.activeElement, back.last);
    });

    it('does NOT move focus into the panel', skip, () => {
      // The evidence drawer focuses its close button from the provider's own
      // effect. A second focus-in here would fight it for no benefit.
      const t = arm({ confineOnly: true });
      assert.equal(t.dom.doc.activeElement, t.opener, 'focus must be left exactly where it was');
      assert.equal(t.first.focusCount, 0, 'the first focusable must not be touched');
      assert.equal(t.panel.focusCount, 0, 'and neither must the panel');
    });

    it('does NOT restore focus on release — the caller owns that', skip, () => {
      // ⛔ THIS IS THE RACE THE MODE EXISTS TO REMOVE. EvidenceProvider.close()
      // focuses the mark that opened the drawer, synchronously, before React
      // re-renders. If the trap ALSO restored, two restores would run on every
      // close and the winner would depend on effect-cleanup order — unjudgeable
      // without a browser, and silently wrong the day that order changes.
      const t = arm({ confineOnly: true });
      t.middle.focus();
      t.release();
      assert.equal(
        t.dom.doc.activeElement, t.middle,
        'release must not yank focus anywhere; the caller has already placed it'
      );
      assert.equal(t.opener.focusCount, 0, 'the opener must not be focused by the trap');
    });

    it('releases its listener like the default does', skip, () => {
      const t = arm({ confineOnly: true });
      assert.equal(t.dom.listeners(), 1);
      t.release();
      assert.equal(t.dom.listeners(), 0);
    });
  });

  describe('⛔ and when it cannot measure a focusable at all', () => {
    it('swallows Tab in a panel with nothing focusable, rather than letting it escape', skip, () => {
      // The "we could not measure this" case for a focus trap: the panel is
      // there, the dialog is open, and the trap can find nothing to cycle
      // through. Letting Tab through would walk the user out into a page
      // `aria-modal` has declared inert — so Tab is swallowed and focus is left
      // on the panel itself. Both modes, because both make the same promise.
      for (const opts of [{}, { confineOnly: true }]) {
        const dom = makeDom();
        const opener = dom.node('opener');
        const outside = dom.node('outside');
        const panel = dom.panel([]);
        dom.doc.activeElement = opener;
        const release = TRAP.installFocusTrap(() => panel, { win: dom.win, doc: dom.doc, ...opts });
        const e = dom.press('Tab');
        assert.equal(e.prevented, true, `Tab must be swallowed (confineOnly=${!!opts.confineOnly})`);
        assert.equal(outside.focusCount, 0, 'nothing outside the dialog may be focused');
        release();
      }
    });

    it('a panel that has gone away does not throw and does not leak Tab', skip, () => {
      const dom = makeDom();
      const release = TRAP.installFocusTrap(() => null, { win: dom.win, doc: dom.doc });
      assert.doesNotThrow(() => dom.press('Tab'));
      assert.doesNotThrow(() => dom.press('Escape'));
      release();
      assert.equal(dom.listeners(), 0);
    });

    it('with no DOM at all it arms nothing and returns a release that is safe to call', skip, () => {
      // A server render. A focus trap must never be able to break the render of
      // the dialog it is protecting.
      const release = TRAP.installFocusTrap(() => null);
      assert.equal(typeof release, 'function');
      assert.doesNotThrow(release);
    });
  });

  it('the focusable set still excludes what the browser will not focus', skip, () => {
    // Exported data, asserted as data — the one part the stand-in document
    // cannot exercise.
    assert.match(TRAP.FOCUSABLE_SELECTOR, /button:not\(\[disabled\]\)/);
    assert.match(TRAP.FOCUSABLE_SELECTOR, /\[tabindex\]:not\(\[tabindex="-1"\]\)/);
  });
});

describe('the evidence drawer is confined, and only while it is reachable', () => {
  // ⛔ A SOURCE PIN, STATED AS ONE. There is no component render harness in this
  // repo and no devDependencies to add one, so how Evidence.js WIRES the hook
  // can only be read. What the hook then DOES is covered behaviourally above.
  const src = () => readStripped(path.join(REPO, 'components/ui/Evidence.js'));

  it('⛔ the trap is anchored on the .ev-drawer panel, not the scrim', () => {
    const code = src();
    const aside = code.match(/<aside\b[^>]*>/);
    assert.ok(aside, 'the drawer panel must still be an <aside>');
    assert.match(aside[0], /ref=\{panelRef\}/, 'the trap must be anchored on the panel');
    assert.match(aside[0], /className="ev-drawer"/, 'and that panel is the drawer itself');
    const scrim = code.match(/className="ev-scrim"[\s\S]{0,200}?\/>/);
    assert.ok(scrim, 'the scrim must still be there');
    assert.ok(
      !/ref=\{panelRef\}/.test(scrim[0]),
      'a trap on the backdrop would count the backdrop as part of the dialog'
    );
  });

  it('⛔ it is armed by the SAME flag that hides the panel from the page', () => {
    // The drawer is never unmounted. If `active` and `inert`/`aria-hidden` could
    // disagree, a closed drawer would hold Tab hostage on every page in the
    // product — a worse defect than the missing confinement this fixed.
    const code = src();
    assert.match(
      code, /const open = !!payload;/,
      'one flag decides whether the drawer is reachable'
    );
    // ⛔ Deliberately indifferent to what follows `open`, so this test fails for
    // its OWN reason and not because some other option beside it moved.
    assert.match(
      code, /useFocusTrap\(\s*\{\s*active:\s*open\b/,
      'the trap must be armed on `open`, never unconditionally'
    );
    assert.match(code, /aria-hidden=\{open \? undefined : 'true'\}/, 'same flag');
    assert.match(code, /inert=\{open \? undefined : ''\}/, 'same flag');
  });

  it('⛔ the scrolling body is focusable, or confinement pins you in front of it', () => {
    // ⛔ A CONSEQUENCE OF THE TRAP, NOT A SEPARATE TIDY-UP. `.ev-body` is the
    // drawer's scroll container and the close button is outside it in
    // `.ev-head`, so with focus where the provider puts it there is no
    // scrollable ancestor for the browser to act on. Measured in Chromium
    // against app/globals.css's real `.ev-*` rules — 2,268px of content in a
    // 398px viewport — PageDown and ArrowDown both left scrollTop at 0, and
    // "What could not be measured" was below the fold. Before the trap a
    // keyboard user could at least Tab out; closing the loop without this would
    // have shipped "pinned in front of content you cannot read". With the
    // tabindex: scrollTop 0 -> 348 on one PageDown, and the body joins the
    // confinement cycle so Tab moves Close <-> detail.
    const code = src();
    const body = code.match(/<div\s+className="ev-body"[\s\S]{0,160}?>/);
    assert.ok(body, 'the drawer must still have its .ev-body scroll container');
    assert.match(body[0], /tabIndex=\{0\}/, 'the scroll container must be keyboard-reachable');
    assert.match(body[0], /role="region"/, 'and announced as a region…');
    assert.match(body[0], /aria-label="[^"]+"/, '…which requires a name');
  });

  it('⛔ it takes confinement ONLY, and the other three stay in the provider', () => {
    const code = src();
    assert.match(
      code, /useFocusTrap\(\s*\{[^}]*confineOnly:\s*true/,
      'the panel must not install a second focus restore to race the provider'
    );
    // The three the provider owns. If one of these is ever moved or deleted,
    // confineOnly becomes a dialog with no focus management at all and
    // aria-modal goes back to being a lie — so they are named here.
    assert.match(code, /openerRef\.current = opener \|\| null;/, 'provider remembers the opener');
    assert.match(code, /if \(el && typeof el\.focus === 'function'\) el\.focus\(\);/,
      'provider restores focus to the opener on close');
    assert.match(code, /if \(e\.key === 'Escape'\) close\(\);/, 'provider closes on Escape');
    assert.match(code, /if \(payload && closeRef\.current\) closeRef\.current\.focus\(\);/,
      'provider moves focus into the panel on open');
  });
});

describe('a navigation is a link, not a div you can only click', () => {
  // ⛔ components/layout/NotificationBell.js rendered every notification row as
  // a bare `<div onClick>` with no role, no tabIndex and no key handler, so the
  // per-alert deep links were MOUSE-ONLY (WCAG 2.1.1, Level A) — and the bell is
  // in the shared header, i.e. on all 30 dashboard pages.
  //
  // ⛔ The rule is deliberately about NAVIGATION rather than about every
  // `<div onClick>`: a backdrop that closes a dialog on click is legitimate so
  // long as Escape works, and banning it would flag Modal's own overlay and
  // teach everyone to waive this. A div that CHANGES THE PAGE has no such
  // defence — it needs an anchor, which brings keyboard activation, a focus
  // ring, the announced role and open-in-new-tab with nothing to maintain.
  it('⛔ no div-with-onClick performs a navigation', () => {
    const offenders = [];
    for (const f of sourceFiles()) {
      const code = readStripped(f);
      for (const m of code.matchAll(/<div\b[^>]*onClick=\{[\s\S]{0,400}?\}/g)) {
        if (/router\.push\(|window\.location\s*=|location\.href\s*=/.test(m[0])) {
          offenders.push(`${rel(f)}:${lineOf(code, m.index)}`);
        }
      }
    }
    assert.deepEqual(
      offenders, [],
      'these navigate from a <div onClick>, which is unreachable by keyboard. '
      + 'Use next/link — see components/layout/NotificationBell.js and '
      + 'components/layout/JobCentre.js:\n  ' + offenders.join('\n  ')
    );
  });
});

describe('a visible label is bound to its control', () => {
  // ⛔ A <label> that neither carries htmlFor nor WRAPS its control names
  // nothing: the text is merely adjacent, and the field announces as "edit
  // text, blank". Measured when this was written: three fields in
  // components/settings/LdapRolesPanel.js — including the group-DN box that
  // decides which directory group becomes an Administrator — the per-row role
  // <select> in components/settings/UsersPanel.js, and three more in
  // components/config/ConditionsManager.js that the roadmap row never named.
  //
  // ⛔ WRAPPING COUNTS, because it is equally valid and widely used here; the
  // rule is "bound", not "htmlFor". An aria-label on the control is the third
  // accepted form and is what UsersPanel's per-row select uses, since a visible
  // "Role" would announce identically on every row of the table.
  it('⛔ no <label> is left unbound to anything', () => {
    const offenders = [];
    for (const f of sourceFiles()) {
      const code = readStripped(f);
      for (const m of code.matchAll(/<label\b([^>]*)>([\s\S]*?)<\/label>/g)) {
        if (/htmlFor=/.test(m[1])) continue;
        if (/<(input|select|textarea)\b/.test(m[2])) continue;
        offenders.push(`${rel(f)}:${lineOf(code, m.index)}`);
      }
    }
    assert.deepEqual(
      offenders, [],
      'these <label>s are neither bound with htmlFor nor wrapped around their '
      + 'control, so the field they describe has no accessible name:\n  '
      + offenders.join('\n  ')
    );
  });

  it('the controls on the privilege surfaces are named', () => {
    // Named explicitly as well as counted, for the reason
    // tests/deviceScopeCoverage.test.js names its six aware surfaces: a count
    // alone cannot say WHICH, and other labels being bound would satisfy it.
    const ldap = readStripped(path.join(REPO, 'components/settings/LdapRolesPanel.js'));
    for (const id of ['ldap_group_dn', 'ldap_role', 'ldap_description']) {
      assert.match(ldap, new RegExp(`htmlFor="${id}"`), `${id} label must be bound`);
      assert.match(ldap, new RegExp(`id="${id}"`), `${id} control must carry the id`);
    }
    const users = readStripped(path.join(REPO, 'components/settings/UsersPanel.js'));
    assert.match(
      users, /aria-label=\{`Role for \$\{u\.username\}`\}/,
      'the per-row role select must name the USER, not just "Role" — the same '
      + 'two words on every row tell a screen-reader user nothing about whose '
      + 'privileges they are changing, and there is no undo'
    );
  });
});

describe('a flagged segmentation cell does not rely on colour', () => {
  // ⛔ components/analysis/ReachabilityTab.js signalled its risk tier with the
  // cell OUTLINE COLOUR and nothing else (WCAG 1.4.1), with the reason in a
  // `title` on a non-focusable <td> — hover-only, so keyboard and touch never
  // reached it. The Badge inside reads "Allow" on a flagged cell and on an
  // ordinary one alike, so with the hue gone the two are identical, and the
  // flagged one is an External zone reaching Internal directly.
  it('⛔ the risk tier is in the cell CONTENT, in words', () => {
    const src = readStripped(path.join(REPO, 'components/analysis/ReachabilityTab.js'));
    assert.match(src, /const RISK_MARK = \{/, 'the tier needs a text label, not only an outline');
    for (const tier of ['high', 'medium']) {
      assert.ok(
        new RegExp(`${tier}:\\s*'`).test(src),
        `riskTier's '${tier}' must have a word for it in RISK_MARK`
      );
    }
    // ⛔ THE CONDITIONAL, not just the identifier. The first draft asserted
    // /RISK_MARK\[tier\]/ and a mutation replacing `{RISK_MARK[tier] ?` with
    // `{false ?` stayed GREEN, because `{RISK_MARK[tier]}` also appears as the
    // marker's own text content and satisfied the match. Source-shape pin, and
    // stated as one: this repo has no component render harness, so there is no
    // way to assert the rendered output here. Either guard form is accepted so
    // a future `&&` rewrite does not fail on correct code.
    assert.match(
      src, /RISK_MARK\[tier\]\s*(\?|&&)/,
      'the marker must be CONDITIONALLY RENDERED on the tier, not merely declared'
    );
    assert.match(src, /\{RISK_MARK\[tier\]\}/, 'and its text must be the tier word itself');
    // ⛔ The GLYPH is decorative and the WORDS carry the meaning. A bare ⚠
    // announced as "warning" says no more than the colour it replaced.
    assert.match(src, /aria-hidden="true">&#9888;/, 'the warning glyph must be aria-hidden');
  });
});
