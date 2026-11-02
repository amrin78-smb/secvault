'use strict';

// lib/logSearchFields.js — the log search form's fields, and the completeness
// guard the form's own comment had been asking for in prose.
//
// ⛔ THE BUG THIS EXISTS FOR, verbatim from the component it replaced:
//   "A PARAM WITH NO FIELD IS DROPPED BY THE FIRST RE-SUBMIT. This form is
//    the whole query — it carries no hidden inputs — so anything the page
//    accepts but the form cannot render disappears the moment an operator
//    presses Search, silently WIDENING their search while looking like the
//    same one."
// It had happened twice (srcCountry, then authOutcome). A warning in a
// comment cannot fail a build; this can.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { stripComments } = require('./stripComments');

const {
  LOG_SEARCH_FIELDS, ESSENTIAL_LOG_FIELDS, ADVANCED_LOG_FIELDS, HIDDEN_LOG_FIELDS,
  ALL_FIELD_NAMES, advancedIsApplied, logFilterChips, withoutLogFilter,
} = require('../lib/logSearchFields');

const REPO = path.join(__dirname, '..');
const PAGE = fs.readFileSync(path.join(REPO, 'app', '(dashboard)', 'logs', 'page.js'), 'utf8');
// ⛔ COMMENTS STRIPPED. The raw file was scanned first and the `useState`
// guard below fired on the component's OWN HEADER — "No client JS, no
// useState" — which is prose describing the very property being asserted.
// That is the FIFTH guard in this repo to match its own explanation; the
// shared helper exists because of the other four.
const FORM = stripComments(
  fs.readFileSync(path.join(REPO, 'components', 'logs', 'LogSearchForm.js'), 'utf8')
);

// The parameter list the page actually accepts.
function acceptedParams() {
  const m = stripComments(PAGE).match(/for \(const k of \[([\s\S]*?)\]\)/);
  assert.ok(m, 'could not find the accepted-parameter list in logs/page.js');
  return [...m[1].matchAll(/'([a-zA-Z]+)'/g)].map((x) => x[1]);
}

describe('⛔ every parameter the page accepts can survive a re-submit', () => {
  it('no accepted param is missing from the registry', () => {
    const reg = new Set(ALL_FIELD_NAMES);
    const orphans = acceptedParams().filter((p) => !reg.has(p));
    assert.deepEqual(orphans, [],
      'these are accepted by /logs and have no control and no hidden input, so pressing '
      + 'Search deletes them and silently widens the search: ' + orphans.join(', '));
  });

  // ⛔ THE ENGINE IS THE UPSTREAM AUTHORITY, AND COMPARING THE TWO DOWNSTREAM
  // COPIES TO EACH OTHER COULD NOT SEE THE REAL GAP. `ruleId` was registered in
  // lib/syslog/logSearch.js and accepted by BOTH /api/logs routes while the page
  // whitelist and the registry each omitted it — so the two assertions around
  // this one AGREED WITH EACH OTHER and passed, for the third instance of the
  // silent-widening bug this file exists to end. A guard whose two sides are
  // both downstream of the thing it is really checking is the
  // mechanism-not-outcome pattern wearing a completeness test's clothes.
  it('⛔ every filter the SEARCH ENGINE accepts has a field here', () => {
    const engine = stripComments(
      fs.readFileSync(path.join(REPO, 'lib', 'syslog', 'logSearch.js'), 'utf8')
    );
    const block = engine.match(/const FILTERS = \{([\s\S]*?)\n\};/);
    assert.ok(block, 'could not find FILTERS in lib/syslog/logSearch.js');
    const keys = [...block[1].matchAll(/^\s{2}([a-zA-Z]+):\s*\{/gm)].map((x) => x[1]);
    // A walk that found nothing would make this vacuously true.
    assert.ok(keys.length > 15, `expected the engine's filter list, found ${keys.length}`);
    const reg = new Set(ALL_FIELD_NAMES);
    const orphans = keys.filter((k) => !reg.has(k));
    assert.deepEqual(orphans, [],
      'the search engine accepts these and the form cannot render them, so a link from '
      + 'elsewhere in the product sets one and the first re-submit DELETES it, widening '
      + 'the result set with nothing on screen to say so: ' + orphans.join(', '));
  });

  it('no registry field is unknown to the page', () => {
    const accepted = new Set(acceptedParams());
    const unread = ALL_FIELD_NAMES.filter((n) => !accepted.has(n));
    assert.deepEqual(unread, [],
      'these render a control whose value the page ignores: ' + unread.join(', '));
  });

  it('⛔ EVERY FIELD IS REACHABLE — rendered, or carried as a hidden input', () => {
    const tiers = new Set(['essential', 'advanced', 'hidden', null]);
    for (const f of LOG_SEARCH_FIELDS) {
      assert.ok(tiers.has(f.tier), `${f.name}: unknown tier ${f.tier}`);
    }
    const rendered = new Set([
      ...ESSENTIAL_LOG_FIELDS, ...ADVANCED_LOG_FIELDS, ...HIDDEN_LOG_FIELDS,
    ].map((f) => f.name));
    // The two non-filters are rendered by the action row and the pager.
    for (const f of LOG_SEARCH_FIELDS) {
      if (f.tier === null) continue;
      assert.ok(rendered.has(f.name), `${f.name} is in no tier and nothing renders it`);
    }
  });

  it('field names and labels are unique', () => {
    const names = LOG_SEARCH_FIELDS.map((f) => f.name);
    assert.equal(new Set(names).size, names.length);
    const labels = LOG_SEARCH_FIELDS.map((f) => f.label);
    assert.equal(new Set(labels).size, labels.length);
  });

  it('⛔ the form carries a hidden input for every hidden-tier field', () => {
    assert.match(FORM, /HIDDEN_LOG_FIELDS\.map/);
    assert.match(FORM, /type="hidden" name=\{def\.name\}/);
  });
});

describe('progressive disclosure', () => {
  it('the essential tier is short enough to be a starting point', () => {
    assert.ok(ESSENTIAL_LOG_FIELDS.length <= 8,
      `${ESSENTIAL_LOG_FIELDS.length} "essential" filters is the nineteen-field wall again`);
    assert.ok(ADVANCED_LOG_FIELDS.length >= 6, 'nothing was actually moved behind the disclosure');
  });

  it('⛔ the window and the two addresses are essential — an investigation starts there', () => {
    const names = ESSENTIAL_LOG_FIELDS.map((f) => f.name);
    for (const n of ['from', 'to', 'deviceId', 'srcIp', 'dstIp']) {
      assert.ok(names.includes(n), `${n} must not be behind a disclosure`);
    }
  });

  it('⛔ THE PANEL OPENS ITSELF WHEN AN ADVANCED FILTER IS APPLIED', () => {
    assert.equal(advancedIsApplied({}), false);
    assert.equal(advancedIsApplied({ srcIp: '10.0.0.1' }), false, 'essential does not open it');
    assert.equal(advancedIsApplied({ threatName: 'x' }), true);
  });

  it('⛔ AND WHEN A FIELD WITH NO CONTROL AT ALL IS APPLIED', () => {
    // These matter MORE, not less: without a control there is nothing on
    // screen between the operator and a filter narrowing their results.
    assert.equal(advancedIsApplied({ vendor: 'fortinet' }), true);
    assert.equal(advancedIsApplied({ urlCategory: 'malware' }), true);
  });

  it('an empty string is not an applied filter', () => {
    assert.equal(advancedIsApplied({ threatName: '' }), false);
    assert.equal(advancedIsApplied({ threatName: null }), false);
  });

  it('⛔ the form renders <details> with a server-side `open`, not client state', () => {
    assert.match(FORM, /<details className="log-advanced" open=\{openAdvanced \|\| undefined\}>/);
    assert.equal(/useState/.test(FORM), false,
      'a disclosure in React state is shut on first paint over an applied filter — '
      + 'exactly what the requirement forbids');
    assert.equal(/'use client'/.test(FORM), false);
  });

  it('⛔ a collapsed panel still declares a count', () => {
    assert.match(FORM, /log-advanced-count/);
  });
});

describe('the chips', () => {
  it('list every applied filter with a readable label', () => {
    const chips = logFilterChips({ srcIp: '10.0.0.1', threatName: 'Mirai' });
    assert.deepEqual(chips.map((c) => `${c.label}: ${c.value}`),
      ['Source IP: 10.0.0.1', 'Threat: Mirai']);
  });

  it('⛔ a select renders its OPTION LABEL, not the raw value', () => {
    const [chip] = logFilterChips({ authOutcome: 'failure' });
    assert.equal(chip.value, 'Failed');
  });

  it('⛔ a filter with no control still produces a chip', () => {
    const [chip] = logFilterChips({ urlCategory: 'malware' });
    assert.equal(chip.label, 'URL category');
    assert.equal(chip.known, true);
  });

  it('⛔ AND SO DOES ONE THE REGISTRY HAS NEVER HEARD OF, marked unknown', () => {
    const [chip] = logFilterChips({ somethingNew: 'x' });
    assert.equal(chip.known, false,
      'skipping it would hide an active filter from the one row whose job is to list them');
    assert.equal(chip.label, 'somethingNew');
  });

  it('⛔ `limit` and `page` are NOT filters and never become chips', () => {
    assert.deepEqual(logFilterChips({ limit: '200', page: '3' }), []);
  });

  it('empty values are not chips', () => {
    assert.deepEqual(logFilterChips({ srcIp: '', threatName: null }), []);
  });

  it('removing a chip removes exactly that filter and keeps the rest', () => {
    const href = withoutLogFilter({ srcIp: '10.0.0.1', threatName: 'Mirai', limit: '200' }, 'threatName');
    assert.ok(href.includes('srcIp=10.0.0.1'));
    assert.ok(href.includes('limit=200'), 'rows-per-page is not a filter and must survive');
    assert.equal(/threatName/.test(href), false);
  });

  it('⛔ removing a chip RESETS the page, because page 3 of a smaller result set is empty', () => {
    const href = withoutLogFilter({ srcIp: '10.0.0.1', page: '3' }, 'srcIp');
    assert.equal(/page=/.test(href), false);
  });

  it('removing the only filter lands on the bare page', () => {
    assert.equal(withoutLogFilter({ srcIp: '10.0.0.1' }, 'srcIp'), '/logs');
  });

  it('⛔ the form renders the chips with a remove affordance that is not colour alone', () => {
    assert.match(FORM, /filter-chip/);
    assert.match(FORM, /className="sr-only"> \(remove\)</);
    assert.match(FORM, /filter-clear/);
  });
});
