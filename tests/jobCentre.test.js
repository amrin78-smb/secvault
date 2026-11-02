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

  it('the limit is bounded and parameterised', () => {
    const fn = JOBS_LIB.slice(JOBS_LIB.indexOf('async function listRecentJobs'));
    const body = fn.slice(0, fn.indexOf('\n}'));
    assert.match(body, /Math\.min\(Math\.max\(/);
    assert.match(body, /LIMIT \$1/);
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

  it('⛔ A HEALTHY FLEET RENDERS NOTHING', () => {
    const h = describeCollectionHealth(counts());
    assert.equal(h.state, 'ok');
    assert.equal(h.label, null,
      'a permanent chip for the system working correctly teaches an operator to ignore the chip that matters');
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
