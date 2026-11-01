'use strict';

// tests/workQueueFilter.test.js
//
// Filtering the work queue, and the one thing that must not follow the filter.
//
// ⛔ THE DANGEROUS PART OF ADDING FILTERS TO THIS PAGE. `summarise()` carries
// the band counts, the failed-source list and the truncation disclosure, and
// `buildWorkQueueAnswer` is forbidden from claiming an empty queue while any
// of those is non-zero. If the summary were computed from the FILTERED list,
// `?severity=critical` with no matches would render this page's own headline
// as "nothing outstanding" over a queue with forty items in it — a filter
// silently becoming an all-clear, on the one screen whose entire job is to say
// what is outstanding. That is this codebase's signature bug (a failed read
// recorded as an affirmative fact) wearing a query parameter.
//
// So the separation is asserted from both sides: the page summarises the full
// list, and the board's all-clear is gated on the UNFILTERED total.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { stripComments } = require('./stripComments');
const {
  WORK_BANDS,
  EVIDENCE,
  bandFor,
  rankItems,
  summarise,
  filterWorkItems,
  workFilterOptions,
} = require('../lib/engines/workQueue');

const ROOT = path.join(__dirname, '..');
const read = (p) => stripComments(fs.readFileSync(path.join(ROOT, p), 'utf8'));

const mk = (over) => ({
  key: over.key,
  type: over.type || 'cve',
  severity: over.severity || 'high',
  evidence: over.evidence || 'measured',
  urgency: over.urgency || 'now',
  title: over.title || 'An item',
  count: 1,
  affects: over.affects || ['FW1'],
  ...over,
});

const ITEMS = rankItems([
  mk({ key: 'a', type: 'cve', severity: 'critical', evidence: 'measured', urgency: 'now', title: 'CVE-2026-1 on FW1', affects: ['FW1'] }),
  mk({ key: 'b', type: 'compliance', severity: 'high', evidence: 'measured', urgency: 'soon', title: 'Logging disabled', affects: ['FW2'] }),
  mk({ key: 'c', type: 'licence', severity: 'medium', evidence: 'unmeasured', urgency: 'now', title: 'Licence expiry unreadable', affects: ['FW2', 'FW3'] }),
  mk({ key: 'd', type: 'rule_cleanup', severity: 'low', evidence: 'measured', urgency: 'soon', title: 'Unused rules', affects: ['FW1'] }),
]);

describe('filterWorkItems narrows what is drawn', () => {
  test('no filters returns everything, unchanged and in order', () => {
    assert.deepEqual(filterWorkItems(ITEMS, {}).map((i) => i.key), ITEMS.map((i) => i.key));
    assert.deepEqual(filterWorkItems(ITEMS, undefined).map((i) => i.key), ITEMS.map((i) => i.key));
  });

  test('each field narrows on its own', () => {
    assert.deepEqual(filterWorkItems(ITEMS, { severity: 'critical' }).map((i) => i.key), ['a']);
    assert.deepEqual(filterWorkItems(ITEMS, { type: 'compliance' }).map((i) => i.key), ['b']);
    assert.deepEqual(filterWorkItems(ITEMS, { evidence: 'unmeasured' }).map((i) => i.key), ['c']);
    assert.deepEqual(filterWorkItems(ITEMS, { band: 'verify' }).map((i) => i.key), ['c']);
  });

  test('fields combine as AND', () => {
    assert.deepEqual(filterWorkItems(ITEMS, { type: 'cve', severity: 'critical' }).map((i) => i.key), ['a']);
    assert.deepEqual(filterWorkItems(ITEMS, { type: 'cve', severity: 'low' }).map((i) => i.key), []);
  });

  test('⛔ an UNRECOGNISED value matches NOTHING, never everything', () => {
    // Returning the whole queue would look like the filter had been applied
    // and matched everything — the operator reads a full list as "all of these
    // are critical". An empty result with the chip beside it is the honest
    // answer, and the chip is what explains it.
    assert.deepEqual(filterWorkItems(ITEMS, { severity: 'criticl' }), []);
    assert.deepEqual(filterWorkItems(ITEMS, { band: 'nonsense' }), []);
    assert.deepEqual(filterWorkItems(ITEMS, { type: 'nope' }), []);
  });

  test('an empty string is NOT a filter', () => {
    assert.equal(filterWorkItems(ITEMS, { severity: '', type: '', q: '' }).length, ITEMS.length);
  });

  test('⛔ the firewall filter matches the names the item DISPLAYS', () => {
    // An item spanning several firewalls deliberately names no device_id (the
    // one-device-or-none rule), so an id filter would drop exactly the broad
    // items an operator most wants when they filter by a firewall.
    assert.deepEqual(filterWorkItems(ITEMS, { device: 'FW3' }).map((i) => i.key), ['c']);
    assert.deepEqual(filterWorkItems(ITEMS, { device: 'FW2' }).map((i) => i.key).sort(), ['b', 'c']);
  });

  test('search covers the title, the type and the affected firewalls', () => {
    assert.deepEqual(filterWorkItems(ITEMS, { q: 'cve-2026' }).map((i) => i.key), ['a']);
    assert.deepEqual(filterWorkItems(ITEMS, { q: 'LOGGING' }).map((i) => i.key), ['b'], 'search is case-insensitive');
    assert.deepEqual(filterWorkItems(ITEMS, { q: 'fw3' }).map((i) => i.key), ['c']);
  });

  test('a non-array input yields an empty list rather than throwing', () => {
    assert.deepEqual(filterWorkItems(null, { severity: 'high' }), []);
    assert.deepEqual(filterWorkItems(undefined, {}), []);
  });
});

describe('⛔ THE SUMMARY MUST NOT FOLLOW THE FILTER', () => {
  const sources = [{ key: 'cve', ok: true }, { key: 'compliance', ok: true }];

  test('summarising the FULL list keeps every band count', () => {
    // ⛔ summarise() SPREADS the band counts at the top level (`...counts`),
    // it does not nest them under `.counts`. Worth pinning: a test written
    // against the wrong shape reads `undefined` and compares it to another
    // `undefined`, which passes.
    const s = summarise(ITEMS, sources);
    assert.equal(s.act_now + s.scheduled + s.verify, ITEMS.length);
    assert.ok(s.verify > 0, 'the fixture must exercise the verify band');
    assert.equal(s.total, ITEMS.length);
  });

  test('…and summarising a FILTERED list would under-report it — which is why nothing does', () => {
    // This asserts the HAZARD exists, so the guard below is not protecting
    // against an imaginary problem.
    const narrowed = filterWorkItems(ITEMS, { severity: 'critical' });
    const wrong = summarise(narrowed, sources);
    assert.equal(wrong.verify, 0);
    assert.notEqual(wrong.verify, summarise(ITEMS, sources).verify);
    assert.notEqual(wrong.total, summarise(ITEMS, sources).total);
  });

  test('⛔ the PAGE summarises before it filters', () => {
    const src = read('app/(dashboard)/work/page.js');
    // `summarise(items, ...)` where `items` is the ranked full list, and the
    // filtered list is a SEPARATE binding handed to the board.
    assert.match(src, /const summary = summarise\(items, sources\);/);
    assert.match(src, /const shown = filterWorkItems\(items, filters\);/);
    assert.ok(!/summarise\(shown/.test(src),
      'the summary is being computed from the filtered list — a filter would become an all-clear');
    assert.match(src, /items: shown/, 'the board must receive the FILTERED list to draw');
    assert.match(src, /totalItems=\{items\.length\}/, 'the board must receive the UNFILTERED total');
  });

  test('⛔ the BOARD gates its all-clear on the unfiltered total', () => {
    const src = read('components/work/WorkQueueBoard.js');
    assert.match(src, /\{total === 0 && summary\.sourcesFailed === 0 \?/,
      'the all-clear must test the unfiltered total, not items.length');
    assert.ok(!/\{items\.length === 0 && summary\.sourcesFailed === 0 \?/.test(src),
      'the all-clear is back on the filtered list');
  });

  test('⛔ "filtered to nothing" has its OWN sentence, worded apart', () => {
    const src = read('components/work/WorkQueueBoard.js');
    assert.match(src, /items\.length === 0 && total > 0/);
    assert.match(src, /No items match these filters/);
    // The all-clear's wording must not be reachable from the filtered branch.
    assert.match(src, /an all-clear that SecVault is prepared to stand behind/);
  });

  test('⛔ the incompleteness banners read the summary, so a filter cannot silence them', () => {
    const src = read('components/work/WorkQueueBoard.js');
    assert.match(src, /summary\.sourcesFailed > 0 \?/);
    assert.match(src, /summary\.sourcesTruncated > 0 \?/);
  });
});

describe('⛔ NOTHING EXPANDS BY DEFAULT', () => {
  test('the board no longer opens the first item of each band', () => {
    // With three bands that expanded THREE items on arrival, pushing the part
    // being triaged below the fold on every load and every AutoRefresh.
    const src = read('components/work/WorkQueueBoard.js');
    assert.ok(!/defaultOpen/.test(src), 'an item still opens by default');
    assert.ok(!/<details[\s\S]{0,200}?\bopen\b/.test(src), 'a <details> is still rendered open');
  });
});

describe('workFilterOptions is derived from the items, never hardcoded', () => {
  test('it offers only values that are actually present', () => {
    const o = workFilterOptions(ITEMS);
    assert.deepEqual(o.types.sort(), ['compliance', 'cve', 'licence', 'rule_cleanup']);
    assert.deepEqual(o.severities.sort(), ['critical', 'high', 'low', 'medium']);
    assert.deepEqual(o.devices, ['FW1', 'FW2', 'FW3']);
  });

  test('bands and evidence keep their CANONICAL order, not alphabetical', () => {
    // act_now/scheduled/verify is a severity ordering; sorting it would put
    // "Needs a human" in the middle of the control.
    const o = workFilterOptions(ITEMS);
    assert.deepEqual(o.bands, WORK_BANDS.filter((b) => o.bands.includes(b)));
    assert.deepEqual(o.evidences, EVIDENCE.filter((e) => o.evidences.includes(e)));
  });

  test('an option that could only return nothing is never offered', () => {
    const only = workFilterOptions([mk({ key: 'x', type: 'cve', severity: 'low', evidence: 'measured' })]);
    assert.deepEqual(only.types, ['cve']);
    assert.ok(!only.severities.includes('critical'));
  });

  test('empty input yields empty option lists rather than throwing', () => {
    const o = workFilterOptions([]);
    assert.deepEqual(o.types, []);
    assert.deepEqual(o.bands, []);
  });

  test('⛔ options come from the FULL list, so narrowing never empties the controls', () => {
    const src = read('app/(dashboard)/work/page.js');
    assert.match(src, /workFilterOptions\(items\)/);
    assert.ok(!/workFilterOptions\(shown\)/.test(src),
      'a filter set that collapses as you use it is one you cannot back out of');
  });
});

describe('⛔ no fabricated workflow controls', () => {
  test('the filter bar offers no owner, status, due date or comment', () => {
    // None of these is persisted anywhere in this product. Rendering them
    // backed by local component state would give an operator a control that
    // forgets what they typed the moment they navigate, on the screen they use
    // to decide what to do next.
    const src = read('components/work/WorkQueueFilters.js');
    for (const word of ['owner', 'assignee', 'dueDate', 'due_date', 'comment']) {
      assert.ok(!new RegExp(word, 'i').test(src), `${word} has no backing store and must not be a control`);
    }
  });

  test('every control it does offer maps to a real item field', () => {
    const src = read('components/work/WorkQueueFilters.js');
    const params = [...src.matchAll(/param="(\w+)"/g)].map((m) => m[1]);
    assert.deepEqual(params.sort(), ['band', 'device', 'evidence', 'q', 'severity', 'type']);
  });
});
