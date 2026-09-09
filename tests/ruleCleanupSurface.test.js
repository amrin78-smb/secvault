'use strict';
// The rule-cleanup SURFACE: the two things this screen can silently stop doing.
//
// ⛔ WHY THIS FILE EXISTS. lib/engines/ruleChangeRequests.js is already pure and
// already refuses to offer a rule it could not measure. That refusal is only
// worth anything if the UI SHOWS it. Both of the failures guarded here render
// perfectly, build clean, and look finished:
//
//   1. The screen draws `eligible` and drops `withheld`. 21 candidates appear,
//      9 rules are gone, nothing says so. That is CLAUDE.md's most-repeated bug
//      class — a failed read presented as a fact — with a delete button
//      attached, and it is invisible precisely because the shorter list looks
//      complete.
//   2. Someone adds a "mark as done" control. The request list then shows
//      verified requests exactly as it does today, except the claim is a
//      person's assertion rather than a re-collected ruleset. The feature is
//      gone; the screenshot is identical. ManageEngine Firewall Analyzer can
//      already list unused rules — the measured completion is the entire
//      differentiator.
//
// ⛔ WHAT THIS PROVES AND DOES NOT. The engine half runs for real against a
// stub pool. The UI half is a SOURCE-LEVEL pin: CleanupTab.js,
// RuleChangeRequests.js and both route files are ESM + JSX and open lib/db's
// pool at import time, so a CommonJS test cannot require, render or call them.
// Source pins or no pins at all, and these two behaviours are worth a pin.
// tests/jsxSyntax.test.js separately proves they parse; tests/sqlColumns.test.js
// proves the columns exist.
//
// ⛔ CONSERVATIVE, like every other repo-wide lint here: assertions run over
// whitespace-COLLAPSED, comment-STRIPPED source, so reformatting cannot fail
// this test and a comment describing the right thing can never stand in for
// code doing it. If one fires on a legal rewrite, widen the pattern — do not
// lower the assertion.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  getCleanupCandidates,
  createRequest,
} = require('../lib/engines/ruleChangeRequests');

const REPO = path.join(__dirname, '..');

function read(...parts) {
  return fs.readFileSync(path.join(REPO, ...parts), 'utf8');
}
function codeOf(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/^\s*\/\/[^\n]*$/gm, ' ')
    .replace(/\s+/g, ' ');
}

// A pool that answers every query with one canned row set and records the SQL.
function stubPool(rows) {
  const seen = [];
  return {
    seen,
    async query(sql, params) {
      seen.push({ sql, params });
      return { rows };
    },
  };
}

const ROW = {
  rule_id_vendor: 'R1',
  finding_type: 'unused',
  severity: 'medium',
  detail: 'No hits in 90 days',
  rule_name: 'Old lab access',
  hit_count: '0',
  enabled: true,
  ack_status: 'new',
};

// --------------------------------------------------------------------------
// The engine's two refusals — the contract the UI is required to render
// --------------------------------------------------------------------------

describe('getCleanupCandidates separates what it measured from what it could not', () => {
  it('offers a MEASURED zero — that is the evidence, not a gap', async () => {
    const { eligible, withheld } = await getCleanupCandidates(stubPool([ROW]), 'dev-1');
    assert.equal(withheld.length, 0);
    assert.equal(eligible.length, 1);
    assert.equal(eligible[0].hitCount, 0, 'a genuine 0 is the whole point of the feature');
  });

  it('WITHHOLDS a rule whose hit count was never measured, with a reason', async () => {
    // ⛔ The case that regresses silently. NULL means the vendor/transport
    // cannot report hit counts at all (Fortinet SSH, Sangfor, Palo Alto SSH) —
    // 164 of 1,716 rules on the live fleet. "We cannot tell whether this rule
    // is used" is not a reason to delete it.
    const { eligible, withheld } = await getCleanupCandidates(
      stubPool([{ ...ROW, hit_count: null }]),
      'dev-1'
    );
    assert.equal(eligible.length, 0, 'an unmeasured rule must never be offered');
    assert.equal(withheld.length, 1);
    assert.match(withheld[0].reason, /never measured/i, 'the reason must be renderable');
    assert.equal(withheld[0].ruleIdVendor, 'R1');
  });

  it('WITHHOLDS a rule with no vendor identifier, because removal could never be confirmed', async () => {
    const { eligible, withheld } = await getCleanupCandidates(
      stubPool([{ ...ROW, rule_id_vendor: null }]),
      'dev-1'
    );
    assert.equal(eligible.length, 0);
    assert.equal(withheld.length, 1);
    assert.match(withheld[0].reason, /no vendor identifier/i);
  });

  it('refuses an unmeasured rule posted straight to createRequest, not just in the UI', async () => {
    // The checkbox filter is a convenience; this is the guarantee.
    const pool = stubPool([{ ...ROW, hit_count: null }]);
    await assert.rejects(
      () => createRequest(pool, { deviceId: 'dev-1', ruleIds: ['R1'] }),
      /cannot be included/i
    );
  });
});

// --------------------------------------------------------------------------
// The surface — source-level pins
// --------------------------------------------------------------------------

const TAB = codeOf(read('components', 'analysis', 'CleanupTab.js'));
const LIST = codeOf(read('components', 'analysis', 'RuleChangeRequests.js'));
const DEVICE_ROUTE = codeOf(
  read('app', 'api', 'devices', '[id]', 'rule-change-requests', 'route.js')
);
const ITEM_ROUTE = codeOf(read('app', 'api', 'rule-change-requests', '[id]', 'route.js'));

describe('the withheld half of the engine answer reaches the screen', () => {
  it('CleanupTab destructures withheld and hands it to the panel', () => {
    assert.match(TAB, /withheld/, 'CleanupTab must read the withheld list');
    assert.match(
      TAB,
      /withheld=\{withheld\}/,
      'withheld must be passed to the panel, not computed and dropped'
    );
  });

  it('CleanupTab explains, per finding row, why a rule was held back', () => {
    assert.match(TAB, /withheldReasons/, 'the reason, not just the fact, must reach the row');
    assert.match(TAB, /NotMeasured/, 'a held-back rule renders as unmeasured, never as a zero');
  });

  it('the withheld notice states a COUNT and the reasons, and is not itself collapsed', () => {
    assert.match(LIST, /export function WithheldNotice/);
    assert.match(LIST, /rows\.length\}\s*more rule/, 'the count must be in the visible text');
    // The per-rule list may sit behind a <details>; the count and the grouped
    // reasons must not. If this ever fails because the whole notice was wrapped
    // in a disclosure, that is the regression, not the test.
    assert.ok(
      LIST.indexOf('byReason.entries()') < LIST.indexOf('<details'),
      'the grouped reasons must render above/outside the disclosure'
    );
  });

  it('the panel renders the notice BEFORE the candidate list', () => {
    assert.ok(
      LIST.indexOf('<WithheldNotice') < LIST.indexOf('{children}'),
      'a footnote under the table is exactly the failure being guarded against'
    );
  });

  it('the device route returns withheld alongside eligible', () => {
    assert.match(DEVICE_ROUTE, /getCleanupCandidates\(pool, id\)/);
    assert.match(DEVICE_ROUTE, /candidates/, 'the whole engine answer travels, not just eligible');
    assert.ok(
      !/const\s*\{\s*eligible\s*\}\s*=\s*await getCleanupCandidates/.test(DEVICE_ROUTE),
      'destructuring only eligible drops the refusals on the floor'
    );
  });
});

describe('a request is never completed by hand', () => {
  const SOURCES = { TAB, LIST, DEVICE_ROUTE, ITEM_ROUTE };

  it('no owned file writes a completion status or a removed outcome', () => {
    for (const [name, src] of Object.entries(SOURCES)) {
      assert.ok(
        !/status\s*=\s*'(verified|partial)'/.test(src),
        `${name} must not assert completion — verifyRequestsForDevice measures it`
      );
      assert.ok(
        !/outcome\s*=\s*'(removed|still_present)'/.test(src),
        `${name} must not assert an item outcome`
      );
    }
  });

  it('no owned file offers a mark-as-done control', () => {
    for (const [name, src] of Object.entries(SOURCES)) {
      assert.ok(
        !/mark\s+(as\s+)?(done|complete)/i.test(src),
        `${name} must not offer manual completion`
      );
    }
  });

  it('the PATCH route accepts submit and abandon and nothing else', () => {
    assert.match(ITEM_ROUTE, /action !== 'submit' && action !== 'abandon'/);
    assert.match(ITEM_ROUTE, /submitRequest/);
    assert.match(ITEM_ROUTE, /abandonRequest/);
    assert.ok(
      !/verifyRequestsForDevice/.test(ITEM_ROUTE) && !/verifyRequestsForDevice/.test(DEVICE_ROUTE),
      'verification belongs to the collection run, not to an HTTP request'
    );
  });

  it('both mutating routes are admin-gated', () => {
    // These write shared state another operator acts on at the firewall —
    // unlike the ungated non-mutating POSTs (access-path, path-query).
    assert.match(DEVICE_ROUTE, /if \(!isAdmin\(session\)\) \{ return forbiddenResponse\(\); \}/);
    assert.match(ITEM_ROUTE, /if \(!isAdmin\(session\)\) \{ return forbiddenResponse\(\); \}/);
  });
});

describe('unverifiable is rendered as an absence of measurement, not as a failure', () => {
  it('has no colour in the outcome colour map', () => {
    const map = LIST.match(/const OUTCOME_META = \{[^}]*\}[^;]*;/);
    assert.ok(map, 'OUTCOME_META must exist');
    assert.ok(
      !/unverifiable/.test(map[0]),
      'giving unverifiable a hue reports our collection gap as the operator\'s inaction'
    );
  });

  it('routes through NotMeasured with a reason', () => {
    assert.match(
      LIST,
      /outcome === 'unverifiable'\s*\)\s*\{\s*return <NotMeasured reason=\{UNVERIFIABLE_REASON\}/,
      'unverifiable must render as NotMeasured, carrying the reason'
    );
    assert.match(
      LIST,
      /UNVERIFIABLE_REASON\s*=\s*[\s\S]{0,40}No rules collection has succeeded/,
      'the reason must name the collection gap, not blame the change'
    );
  });

  it('a submitted request with nothing measurable says so in words', () => {
    assert.match(LIST, /nothingMeasurable/);
    assert.match(LIST, /Nothing can be concluded yet/);
  });

  it('pending is also unmeasured, not a zero', () => {
    assert.match(LIST, /outcome === 'pending'[\s\S]{0,80}NotMeasured reason=\{PENDING_REASON\}/);
  });
});
