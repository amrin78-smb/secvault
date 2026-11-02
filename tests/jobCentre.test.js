'use strict';

// The job centre (§9) and the collection-health indicator (§9's "data health
// indicator").
//
// ⛔ §9 PERMITS A JOB CENTRE "ONLY IF REAL ASYNC JOB STATE EXISTS", so the
// first test here is that it does. If `background_jobs` ever becomes a stub,
// this panel becomes the fabricated-state surface the brief forbids.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { stripComments } = require('./stripComments');

const { describeCollectionHealth } = require('../lib/dataHealth');

const ROOT = path.join(__dirname, '..');
const read = (p) => stripComments(fs.readFileSync(path.join(ROOT, p), 'utf8'));
const SCHEMA = fs.readFileSync(path.join(ROOT, 'lib/schema.sql'), 'utf8');
const JOBS_LIB = read('lib/engines/backgroundJobs.js');
const ROUTE = read('app/api/jobs/route.js');
const PANEL = read('components/layout/JobCentre.js');
const HEADER = read('components/layout/Header.js');

describe('⛔ the job state this panel shows is real', () => {
  it('background_jobs has status, progress and an error column', () => {
    const t = SCHEMA.slice(SCHEMA.indexOf('CREATE TABLE IF NOT EXISTS background_jobs'));
    const body = t.slice(0, t.indexOf(');'));
    for (const col of ['job_type', 'status', 'progress_current', 'progress_total', 'error', 'finished_at']) {
      assert.match(body, new RegExp(`\\b${col}\\b`), `background_jobs has no ${col}`);
    }
  });

  it('two real job types are produced and consumed', () => {
    assert.match(JOBS_LIB, /JOB_TYPES = new Set\(\['device_delete', 'device_collect'\]\)/);
    const worker = read('services/engine-worker.js');
    assert.match(worker, /job\.job_type === 'device_collect'/);
    assert.match(worker, /job\.job_type === 'device_delete'/);
  });

  it('⛔ an abandoned job is reaped to FAILED, never assumed to have worked', () => {
    assert.match(JOBS_LIB, /reapStaleJobs/);
    assert.match(JOBS_LIB, /STALE_RUNNING_MINUTES/);
  });
});

describe('listing', () => {
  it('⛔ ONE QUERY, live first — two queries can lose a job between them', () => {
    const fn = JOBS_LIB.slice(JOBS_LIB.indexOf('async function listRecentJobs'));
    const body = fn.slice(0, fn.indexOf('\n}'));
    assert.equal((body.match(/pool\.query\(/g) || []).length, 1);
    assert.match(body, /ORDER BY \(j\.status IN \('queued', 'running'\)\) DESC/);
  });

  it('⛔ the device name is LEFT-joined — a finished delete has no device', () => {
    const fn = JOBS_LIB.slice(JOBS_LIB.indexOf('async function listRecentJobs'));
    assert.match(fn.slice(0, fn.indexOf('\n}')), /LEFT JOIN devices d/);
  });

  // ⛔ THE BOUND IS ASSERTED BY BEHAVIOUR, NOT BY THE ARITHMETIC'S SPELLING.
  // This used to require the literal `Math.min(Math.max(` in the source, which
  // is "testing the mechanism, not the outcome" — it failed on CORRECT code the
  // moment the clamp was rewritten to stop a negative limit resolving to ONE
  // row, and it would have passed just as happily over a clamp that was
  // reshuffled into something wrong. The real bound is exercised in
  // "listRecentJobs clamps the limit rather than trusting it" below; what is
  // worth pinning HERE is that the value is parameterised rather than
  // interpolated into the SQL.
  it('the limit is parameterised, never interpolated', () => {
    const fn = JOBS_LIB.slice(JOBS_LIB.indexOf('async function listRecentJobs'));
    const body = fn.slice(0, fn.indexOf('\n}'));
    assert.match(body, /LIMIT \$1/);
    assert.doesNotMatch(body, /LIMIT \$\{/, 'the limit must never be interpolated into the SQL');
  });
});

describe('the route', () => {
  it('refuses an unauthenticated caller', () => {
    assert.match(ROUTE, /if \(!session\)/);
    assert.match(ROUTE, /status: 401/);
  });

  it('⛔ A FAILED READ IS 503, NEVER `{jobs: []}`', () => {
    // An empty array is indistinguishable from "nothing is running", and the
    // panel would paint an all-clear over a database it could not read.
    assert.match(ROUTE, /status: 503/);
    const c = ROUTE.slice(ROUTE.indexOf('catch'));
    assert.equal(/jobs: \[\]/.test(c), false);
  });

  it('⛔ the live count is computed SERVER-side from the rows it returns', () => {
    assert.match(ROUTE, /live: jobs\.filter/);
  });

  it('⛔ it is classified in the device-scope register', () => {
    const reg = read('lib/deviceScopeCoverage.js');
    assert.match(reg, /'app\/api\/jobs\/route\.js': 'blocked'/);
  });

  it('⛔ and in the API sweep table', () => {
    const sweep = read('scripts/apiSweep.js');
    assert.match(sweep, /\{ path: '\/api\/jobs', methods: \['GET'\], capability: null \}/);
  });

  it('exports force-dynamic — it queries on every request', () => {
    assert.match(ROUTE, /export const dynamic = 'force-dynamic'/);
  });
});

describe('the panel', () => {
  it('⛔ STARTS AT `null`, NOT AN EMPTY LIST', () => {
    assert.match(PANEL, /useState\(null\)/);
    assert.equal(/useState\(\[\]\)/.test(PANEL), false,
      'an empty array renders as "nothing is running" before the first read returns');
  });

  it('⛔ a failed refresh SAYS SO and keeps the last good list', () => {
    assert.match(PANEL, /setFailed\(true\)/);
    assert.match(PANEL, /could not refresh/);
    const c = PANEL.slice(PANEL.indexOf('} catch {'));
    assert.equal(/setData\(null\)/.test(c.slice(0, 300)), false,
      'blanking on a transient error is the same false all-clear');
  });

  it('⛔ an UNKNOWN progress total is not rendered as 0', () => {
    const fn = PANEL.slice(PANEL.indexOf('function progressText'), PANEL.indexOf('export default'));
    assert.match(fn, /total === null \|\| total === undefined/);
    assert.ok(fn.includes('return `${cur}`'), 'an unknown total must print the count alone');
  });

  it('⛔ a FAILED job carries its error in full, not behind a hover', () => {
    assert.match(PANEL, /\{j\.error && <p className="jobc-error">\{j\.error\}<\/p>\}/);
    const css = read('app/globals.css');
    const block = css.slice(css.indexOf('.jobc-error {'), css.indexOf('}', css.indexOf('.jobc-error {')));
    assert.match(block, /word-break: break-word/);
    assert.equal(/text-overflow:\s*ellipsis/.test(block), false);
  });

  it('⛔ polls fast only while something is live', () => {
    assert.match(PANEL, /LIVE_POLL_MS = \d+/);
    assert.match(PANEL, /IDLE_POLL_MS = \d+/);
    const live = Number(PANEL.match(/LIVE_POLL_MS = (\d+)/)[1]);
    const idle = Number(PANEL.match(/IDLE_POLL_MS = (\d+)/)[1]);
    assert.ok(idle > live * 4, `idle ${idle}ms is not meaningfully slower than live ${live}ms`);
  });

  it('⛔ the running count is in the ACCESSIBLE NAME, not only a coloured badge', () => {
    assert.match(PANEL, /aria-label=\{live > 0 \? `Background jobs — \$\{live\} running`/);
  });

  it('is keyboard-dismissable and restores focus', () => {
    assert.match(PANEL, /e\.key === 'Escape'/);
    assert.match(PANEL, /btnRef\.current\?\.focus\(\)/);
  });

  it('is mounted in the header', () => {
    assert.match(HEADER, /<JobCentre \/>/);
  });
});

describe('the collection-health indicator', () => {
  const counts = (o) => ({ deviceCount: 8, devicesCollectedFresh: 8, devicesNeverCollected: 0, collectionStaleAfterDays: 7, ...o });

  // ⛔ A FAILED FIRST READ MUST NOT LOOK LIKE A READ IN FLIGHT. `jobs` is null
  // in both cases — before the first poll, and after one that failed, because
  // the catch keeps the last good list rather than blanking it. The panel
  // therefore has to branch on BOTH, or a 503 on the first poll renders
  // "Loading…" indefinitely over the one state it exists to surface.
  it('⛔ a failed FIRST read says so, rather than claiming to be loading', () => {
    const panel = read('components/layout/JobCentre.js');
    assert.match(panel, /jobs === null && failed \?/,
      'the failed-and-empty case must be branched BEFORE the plain null case, '
      + 'or a 503 on the first poll shows "Loading…" for ever');
    assert.match(panel, /could not read the job list/i);
    // The ordering is the whole fix: a plain `jobs === null` test first would
    // shadow it.
    assert.ok(
      panel.indexOf('jobs === null && failed') < panel.indexOf('>Loading'),
      'the failed branch must come first'
    );
  });

  // ⛔ THE ENGINE IS EXERCISED, NOT REGEXED. Every property of listRecentJobs
  // that matters was asserted by slicing the source and matching characters —
  // the single query, the LEFT JOIN, the live-first ORDER BY — while
  // tests/backgroundJobs.test.js never called the function at all. A rewrite
  // that kept the right words and changed the behaviour passed 6442 tests, and
  // the suite's stub-pool pattern was already sitting there to prevent exactly
  // that.
  it('⛔ listRecentJobs: ONE query, live first, device name LEFT-joined', async () => {
    const { listRecentJobs } = require('../lib/engines/backgroundJobs');
    const seen = [];
    const stub = {
      query: async (sql, params) => {
        seen.push({ sql, params });
        return { rows: [{ id: 'j1', status: 'running', device_name: null }] };
      },
    };

    const rows = await listRecentJobs(stub, { limit: 5 });
    assert.deepEqual(rows, [{ id: 'j1', status: 'running', device_name: null }],
      'the rows are returned as the database gave them');

    // ⛔ ONE query. Two can disagree: a job finishing between them appears in
    // NEITHER list, and "in neither" is a job that vanishes from the panel
    // whose purpose is not losing track of it.
    assert.equal(seen.length, 1, `issued ${seen.length} queries, must be exactly 1`);

    const { sql, params } = seen[0];
    // ⛔ LEFT JOIN, not JOIN — a finished DELETE is exactly the case where the
    // device row is gone, and an inner join would drop the job that mattered.
    assert.match(sql, /LEFT JOIN devices/i);
    assert.doesNotMatch(sql, /\n\s*(INNER )?JOIN devices/i);
    // Live work first, then newest.
    assert.match(sql, /ORDER BY[\s\S]*queued[\s\S]*running[\s\S]*DESC/i);
    assert.deepEqual(params, [5], 'the limit must be parameterised, never interpolated');
  });

  it('⛔ listRecentJobs clamps the limit rather than trusting it', async () => {
    const { listRecentJobs } = require('../lib/engines/backgroundJobs');
    const asked = [];
    const stub = { query: async (_s, p) => { asked.push(p[0]); return { rows: [] }; } };
    for (const given of [0, -5, 1000, 'abc', 7, 7.9]) {
      await listRecentJobs(stub, { limit: given });
    }
    // ⛔ A NEGATIVE FALLS BACK TO THE DEFAULT, NOT TO 1. It used to clamp to 1
    // (`Number(-5) || 20` is -5, then Math.max(-5, 1)), which presents a
    // one-row list as "recent background jobs" — a truncated list that looks
    // complete.
    assert.deepEqual(asked, [20, 20, 100, 20, 7, 7],
      'an unbounded, negative or nonsense limit must not reach the database');
  });

  // ⛔ A FAILED READ MUST NOT RESOLVE. listRecentJobs has no try/catch by
  // design, so the throw reaches the route, which answers 503 — the whole
  // reason the route is not allowed to return `{jobs: []}`.
  it('⛔ a failed query THROWS rather than resolving to an empty list', async () => {
    const { listRecentJobs } = require('../lib/engines/backgroundJobs');
    const stub = { query: async () => { throw new Error('connection terminated'); } };
    await assert.rejects(() => listRecentJobs(stub), /connection terminated/,
      'resolving to [] here would render "Nothing has run recently" over a failed read');
  });

  it('⛔ A HEALTHY FLEET RENDERS NOTHING', () => {
    const h = describeCollectionHealth(counts());
    assert.equal(h.state, 'ok');
    assert.equal(h.label, null,
      'a permanent chip for the system working correctly teaches an operator to ignore the chip that matters');
  });

  it('⛔ IT READS BOTH KEY SHAPES — the raw row and the decorated headline', () => {
    // getDeviceCounts() returns total / collected_fresh / never_collected;
    // getFleetHeadline() decorates them. The first draft read only the
    // decorated names off the RAW function, got undefined for all three, and
    // rendered COLLECTION UNKNOWN on a fleet it could count — the indicator
    // whose job is saying when a figure cannot be trusted, lying about itself.
    const raw = describeCollectionHealth({ total: 8, collected_fresh: 0, never_collected: 1 });
    const dec = describeCollectionHealth(counts({ devicesCollectedFresh: 0, devicesNeverCollected: 1 }));
    assert.equal(raw.label, '0/8 CURRENT');
    assert.equal(raw.label, dec.label);
    assert.equal(raw.state, dec.state);
  });

  it('⛔ the header calls the CHEAP count, not the whole headline builder', () => {
    const lib = read('lib/dataHealth.js');
    assert.match(lib, /getDeviceCounts/);
    assert.equal(/getFleetHeadline/.test(lib), false,
      'the indicator renders on every page and must not pay for the security '
      + 'score and compliance roll-up to learn four counts');
  });

  // ⛔ AN EMPTY FLEET IS A SUCCESSFUL READ, AND IT WAS REPORTED AS A FAILED ONE.
  // `total <= 0` used to sit inside the unreadable guard, so a fresh install —
  // or any install whose devices are all `active = false`, since
  // getDeviceCounts filters on that — got byte-identical output to a count that
  // threw: a COLLECTION UNKNOWN chip on every page of the console, hovering
  // "SecVault could not count how recently it collected from the fleet". It
  // counted perfectly; there was simply nothing in the inventory. That is
  // `none` collapsed into `unknown`, which this product keeps apart everywhere
  // else, on the SECOND indicator in this file to lie about itself.
  it('⛔ AN EMPTY FLEET IS `empty` AND SILENT — not `unknown`, and not a chip', () => {
    const e = describeCollectionHealth({ total: 0, collected_fresh: 0, never_collected: 0 });
    assert.equal(e.state, 'empty', 'a successful count of zero is not a failed count');
    assert.equal(e.label, null, 'no fleet means no figures whose currency could be in doubt');
    assert.equal(e.title, null);
    // And it must stay distinguishable from the failed read.
    assert.notEqual(e.state, describeCollectionHealth(null).state);
  });

  // ⛔ `Number(null)` IS 0, AND 0 IS FINITE. An explicit null count used to
  // become a confident measured zero: `{total: 8, collected_fresh: null}` gave
  // `0/8 CURRENT` and "8 last collected over 7 days ago" — a failed read
  // printed as a precise fact. CLAUDE.md names this exact trap in the licensing
  // section. No current caller can produce it; this function is exported and
  // its own comment invites new ones.
  it('⛔ a NULL count is unknown, never a measured zero', () => {
    for (const bad of [
      { total: 8, collected_fresh: null, never_collected: null },
      counts({ devicesCollectedFresh: null }),
      counts({ deviceCount: null }),
    ]) {
      const h = describeCollectionHealth(bad);
      assert.equal(h.state, 'unknown', JSON.stringify(bad));
      assert.equal(h.label, 'COLLECTION UNKNOWN');
    }
  });

  it('⛔ AN UNREADABLE COUNT IS `unknown`, NEVER `ok`', () => {
    for (const bad of [null, {}, counts({ deviceCount: NaN }), counts({ devicesCollectedFresh: undefined })]) {
      assert.equal(describeCollectionHealth(bad).state, 'unknown');
    }
    assert.match(describeCollectionHealth(null).title, /could not count/i);
  });

  it('⛔ "never collected" and "collected long ago" stay SEPARATE in the sentence', () => {
    const h = describeCollectionHealth(counts({ devicesCollectedFresh: 0, devicesNeverCollected: 1 }));
    assert.equal(h.never, 1);
    assert.equal(h.stale, 7);
    assert.match(h.title, /1 never collected from/);
    assert.match(h.title, /7 last collected over 7 days ago/);
  });

  it('⛔ the stale count is clamped — it is derived by subtraction', () => {
    const h = describeCollectionHealth(counts({ devicesCollectedFresh: 9, devicesNeverCollected: 5 }));
    assert.equal(h.stale, 0);
  });

  it('⛔ it is a LINK, not a title-only div like the pill beside it', () => {
    assert.match(HEADER, /<Link\s+href="\/coverage"\s+className="dh-pill"/);
    assert.match(HEADER, /className="sr-only"> — \{collection\.title\}<\/span>/);
  });

  it('⛔ it is NOT merged into the feed pill — they are different questions', () => {
    assert.match(HEADER, /const collection = await getCollectionHealth\(pool\)/);
    assert.match(HEADER, /\{collection\.label && \(/, 'it must be conditional on there being something to say');
    // The feed pill keeps its own verdict.
    assert.match(HEADER, /\{syncStatus\.label\}/);
  });

  it('⛔ the unknown state is HUELESS — our failed read is not their severity', () => {
    const css = read('app/globals.css');
    const i = css.indexOf('.dh-pill[data-state="unknown"]');
    const block = css.slice(i, css.indexOf('}', i));
    assert.match(block, /var\(--shell-fg\)/);
    assert.equal(/f0c86b|--tint-warn/.test(block), false);
  });
});
