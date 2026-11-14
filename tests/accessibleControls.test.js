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
  const EXEMPT = Object.freeze({
    'components/ui/useFocusTrap.js':
      'it IS the trap; it names aria-modal in its own contract',
    'components/ui/Evidence.js':
      'PARTIAL AND RECORDED, not waived — roadmap row 58. It has 3 of the 4 '
      + 'mechanisms (Escape, focus-in to the close button, restore to the opener) '
      + 'and is missing only Tab CONFINEMENT. The other three live in the '
      + 'EvidenceProvider rather than the panel, deliberately, because the '
      + 'provider owns open/close state and the opener identity across pages — so '
      + 'dropping the panel-level hook in would leave two focus restores racing '
      + 'each other, which cannot be judged without rendering the drawer. Fixing '
      + 'it is its own piece of work, with the drawer open in a browser.',
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

  it('the shared trap still implements all four mechanisms', () => {
    // ⛔ A BEHAVIOURAL FLOOR ON THE HOOK ITSELF. Every dialog in the product now
    // delegates to it, so if the trap quietly lost its Tab branch the guard
    // above would stay green over a fleet of dialogs that no longer trap.
    const src = readStripped(path.join(REPO, 'components/ui/useFocusTrap.js'));
    assert.match(src, /document\.activeElement/, 'must remember what had focus');
    assert.match(src, /\.focus\(\)/, 'must move focus into the panel');
    assert.match(src, /'Tab'/, 'must confine Tab');
    assert.match(src, /previouslyFocusedRef\.current\?\.focus/, 'must restore focus on close');
    assert.match(src, /onEscape\?\.\(\)/, 'Escape must be opt-in, not assumed');
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
