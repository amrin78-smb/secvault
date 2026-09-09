'use strict';
// Pins lib/engines/backgroundJobs.js and the three call sites that carry a job
// result out to the operator.
//
// WHY THIS FILE EXISTS. On 2026-09-09 an operator clicked Collect Now on a
// FortiGate. collectAndStore ran 111 seconds inside POST
// /api/devices/[id]/collect and the app was unusable for the whole of it. The
// fix moved that work onto a background_jobs queue run by
// services/engine-worker.js, with the UI polling GET /api/jobs/[id]. Moving
// work off the request path is easy; moving it WITHOUT losing the honesty of
// the result is the part that regresses silently, because every way of losing
// it produces a plausible sentence rather than a crash:
//
//   * a queued job reported as a succeeded one,
//   * an unknown progress total rendered as 0/0, which reads as finished,
//   * a job whose worker died left 'running' (the UI spins forever) or, far
//     worse, assumed 'succeeded',
//   * a failed rule pull (rulesCount NULL) shown as "Collected — 0 rules."
//
// That last one is CLAUDE.md's own most-repeated bug — a failed read recorded
// as an affirmative value — and it now travels through three files, so it is
// asserted in all three.
//
// ⛔ NO DATABASE. Every engine call gets a stub pool that records the SQL and
// params it was handed and returns canned rows.
//
// ⛔ Some tests here are SOURCE-PROPERTY tests, in the style of the repo's
// existing lint-shaped tests (moduleLoad/importIntegrity/jsxSyntax/sqlColumns).
// The route handler and the React component are ESM+JSX and cannot be
// `require`d by node:test at all, so the only way to pin their behaviour
// cheaply is to assert a property of their source. They are deliberately
// CONSERVATIVE: each matches a meaningful fragment and says which rule it
// stands for, so a reformat is a one-line update while a REMOVED protection
// still fails loudly.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  JOB_TYPES,
  TERMINAL,
  STALE_RUNNING_MINUTES,
  enqueueJob,
  claimNextJob,
  reportProgress,
  finishJob,
  reapStaleJobs,
} = require('../lib/engines/backgroundJobs');

const REPO = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(REPO, rel), 'utf8');

// ⛔ Every 'must NOT contain' assertion below runs against source with COMMENTS
// REMOVED. These files document the very anti-patterns they must not perform
// ('NOT `rulesCount ?? 0`'), so a naive scan of the raw text fails on the
// warning rather than on the bug. Stripping is deliberately crude and only ever
// feeds doesNotMatch, where over-removal can only lose coverage, never invent a
// failure.
const BLOCK_COMMENT = new RegExp('/\\*[\\s\\S]*?\\*/', 'g');
const LINE_COMMENT = new RegExp('(^|[\\s{(;,])//[^\\n]*', 'g');
const stripComments = (src) =>
  String(src).replace(BLOCK_COMMENT, ' ').replace(LINE_COMMENT, '$1 ');

const WORKER = 'services/engine-worker.js';
const JOB_ROUTE = 'app/api/jobs/[id]/route.js';
const COLLECT_ROUTE = 'app/api/devices/[id]/collect/route.js';
const ACTIONS = 'components/devices/DeviceActions.js';

// --------------------------------------------------------------------------
// Stub pool
// --------------------------------------------------------------------------

function stubPool(responder) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql: String(sql), params: params || [] });
      const canned = typeof responder === 'function' ? responder(String(sql), params || [], calls) : null;
      return canned || { rows: [], rowCount: 0 };
    },
  };
}

const JOB_ROW = {
  id: 'job-1',
  job_type: 'device_collect',
  device_id: 'dev-1',
  status: 'queued',
  progress_current: null,
  progress_total: null,
  detail: null,
  error: null,
};

// --------------------------------------------------------------------------
// Enqueue
// --------------------------------------------------------------------------

describe('enqueueJob', () => {
  it('rejects a job type the worker has no handler for', async () => {
    const pool = stubPool();
    await assert.rejects(
      () => enqueueJob(pool, { jobType: 'reformat_the_firewall', deviceId: 'dev-1' }),
      /Unknown job type/
    );
    assert.equal(pool.calls.length, 0, 'must not reach the database at all');
  });

  it('queues a device_collect as status queued — NOT as a result', async () => {
    const pool = stubPool(() => ({ rows: [{ ...JOB_ROW }], rowCount: 1 }));
    const { job, created } = await enqueueJob(pool, {
      jobType: 'device_collect',
      deviceId: 'dev-1',
      requestedBy: 'amrin',
    });
    assert.equal(created, true);
    assert.equal(job.status, 'queued');
    // ⛔ A queued job is not a succeeded job. Nothing about a fresh enqueue may
    // be readable as an outcome — there is no measurement yet.
    assert.equal(TERMINAL.has(job.status), false);
    assert.match(pool.calls[0].sql, /INSERT INTO background_jobs/i);
    assert.match(pool.calls[0].sql, /'queued'/, 'inserted status must be queued');
  });

  it('hands back the incumbent live job when the dedupe index rejects a second one', async () => {
    // The double-click case: the partial unique index makes the INSERT a
    // no-op, and the caller must be able to FOLLOW the running job rather
    // than be told the click failed (or start a second SSH session).
    const running = { ...JOB_ROW, status: 'running' };
    const pool = stubPool((sql) =>
      /INSERT INTO/i.test(sql) ? { rows: [], rowCount: 0 } : { rows: [running], rowCount: 1 }
    );
    const { job, created } = await enqueueJob(pool, { jobType: 'device_collect', deviceId: 'dev-1' });
    assert.equal(created, false);
    assert.equal(job.status, 'running');
    assert.equal(TERMINAL.has(job.status), false, 'running is still not a result');
  });

  it('reports no job at all rather than inventing one when nothing comes back', async () => {
    const pool = stubPool(() => ({ rows: [], rowCount: 0 }));
    const { job, created } = await enqueueJob(pool, { jobType: 'device_delete', deviceId: 'dev-1' });
    assert.equal(created, false);
    assert.equal(job, null);
  });

  it('knows exactly the two job types the worker implements', () => {
    assert.deepEqual([...JOB_TYPES].sort(), ['device_collect', 'device_delete']);
  });
});

// --------------------------------------------------------------------------
// Claiming
// --------------------------------------------------------------------------

describe('claimNextJob', () => {
  it('claims atomically — two workers must never run the same delete', async () => {
    const pool = stubPool(() => ({ rows: [{ ...JOB_ROW, status: 'running' }], rowCount: 1 }));
    const job = await claimNextJob(pool, ['device_collect', 'device_delete']);
    assert.equal(job.status, 'running');
    const { sql, params } = pool.calls[0];
    assert.match(sql, /FOR UPDATE SKIP LOCKED/i, 'the claim is what stops a double-run');
    assert.match(sql, /SET status = 'running'/i);
    assert.deepEqual(params[0], ['device_collect', 'device_delete']);
  });

  it('returns null, not a fabricated job, when the queue is empty', async () => {
    const pool = stubPool(() => ({ rows: [], rowCount: 0 }));
    assert.equal(await claimNextJob(pool), null);
  });
});

// --------------------------------------------------------------------------
// Progress — the "we could not measure this" case
// --------------------------------------------------------------------------

describe('reportProgress keeps an unknown size unknown', () => {
  it('sends NULL for a total that is not known, never 0', async () => {
    // ⛔ THE UNMEASURED CASE. A collect has no step count: collectAndStore
    // reports none and the worker must not invent one. A progress bar
    // rendering an unknown total as 0/0 reads as FINISHED.
    const pool = stubPool();
    await reportProgress(pool, 'job-1', { current: null, total: null, detail: 'Contacting the device…' });
    const { params } = pool.calls[0];
    assert.equal(params[1], null, 'progress_current stays NULL');
    assert.equal(params[2], null, 'progress_total stays NULL — unknown, not zero');
    assert.notEqual(params[2], 0);
    assert.notEqual(params[2], '0');
  });

  it('sends NULL for a total that was simply omitted', async () => {
    const pool = stubPool();
    await reportProgress(pool, 'job-1', { detail: 'still going' });
    assert.equal(pool.calls[0].params[1], null);
    assert.equal(pool.calls[0].params[2], null);
  });

  it('does distinguish a genuine zero from an unknown', async () => {
    // 0 is a real measurement — "there are zero rows to rewrite" — and must
    // reach the database as 0, not be swallowed as absent.
    const pool = stubPool();
    await reportProgress(pool, 'job-1', { current: 0, total: 0 });
    assert.equal(pool.calls[0].params[1], '0');
    assert.equal(pool.calls[0].params[2], '0');
  });

  it('never resurrects a job that already finished', async () => {
    const pool = stubPool();
    await reportProgress(pool, 'job-1', { detail: 'late progress line' });
    assert.match(pool.calls[0].sql, /status = 'running'/i);
  });
});

// --------------------------------------------------------------------------
// Finishing
// --------------------------------------------------------------------------

describe('finishJob', () => {
  it('refuses a status that is not terminal', async () => {
    const pool = stubPool();
    for (const bogus of ['running', 'queued', 'done', 'ok', '']) {
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(() => finishJob(pool, 'job-1', bogus), /Not a terminal status/);
    }
    assert.equal(pool.calls.length, 0);
  });

  it('accepts exactly the three terminal statuses', () => {
    assert.deepEqual([...TERMINAL].sort(), ['cancelled', 'failed', 'succeeded']);
  });

  it('carries a structured result through detail without flattening it', async () => {
    // ⛔ background_jobs has no JSON column, so the collect result rides in
    // `detail` as JSON. That is what keeps rulesCount's NULL a NULL all the way
    // to the browser — see the DeviceActions/route assertions below.
    const encoded = JSON.stringify({
      message: 'Collected, but the device reported no rule count — the ruleset was NOT updated.',
      rulesCount: null,
      errors: ['rules: connect ETIMEDOUT'],
    });
    const pool = stubPool(() => ({ rows: [{ ...JOB_ROW, status: 'failed', detail: encoded }], rowCount: 1 }));
    const row = await finishJob(pool, 'job-1', 'failed', { error: 'rules: connect ETIMEDOUT', detail: encoded });
    const decoded = JSON.parse(row.detail);
    assert.equal(decoded.rulesCount, null, 'a failed rule pull must still read as NULL, not 0');
    assert.notEqual(decoded.rulesCount, 0);
    assert.equal(typeof decoded.rulesCount, 'object'); // typeof null
  });

  it('keeps a genuine zero distinguishable from a failed pull', async () => {
    const encoded = JSON.stringify({ message: 'Collected — 0 rules.', rulesCount: 0, errors: [] });
    const pool = stubPool(() => ({ rows: [{ ...JOB_ROW, status: 'succeeded', detail: encoded }], rowCount: 1 }));
    const row = await finishJob(pool, 'job-1', 'succeeded', { detail: encoded });
    const decoded = JSON.parse(row.detail);
    assert.equal(decoded.rulesCount, 0);
    assert.equal(typeof decoded.rulesCount, 'number', 'a real 0 must survive as a number');
  });
});

// --------------------------------------------------------------------------
// Reaping — the other "we could not measure this" case
// --------------------------------------------------------------------------

describe('reapStaleJobs', () => {
  it('fails a job whose worker vanished, and never marks it succeeded', async () => {
    const pool = stubPool(() => ({
      rows: [{ id: 'job-1', job_type: 'device_delete', device_id: 'dev-1' }],
      rowCount: 1,
    }));
    const reaped = await reapStaleJobs(pool);
    assert.equal(reaped.length, 1);
    const { sql, params } = pool.calls[0];
    assert.match(sql, /SET status = 'failed'/i, "a vanished worker is failed, never 'succeeded'");
    assert.doesNotMatch(sql, /'succeeded'/i);
    // ⛔ The reason is load-bearing: the work MAY have completed. The row must
    // not claim it did, and must not claim it did not.
    assert.match(sql, /unknown/i, 'the reason must say the outcome is unknown');
    assert.match(sql, /WHERE status = 'running'/i, 'only ever reaps rows stuck in running');
    assert.equal(params[0], STALE_RUNNING_MINUTES);
  });

  it('falls back to the documented threshold when handed junk', async () => {
    const pool = stubPool(() => ({ rows: [], rowCount: 0 }));
    await reapStaleJobs(pool, 'soon');
    assert.equal(pool.calls[0].params[0], STALE_RUNNING_MINUTES);
    await reapStaleJobs(pool, 45);
    assert.equal(pool.calls[1].params[0], 45);
  });
});

// --------------------------------------------------------------------------
// The worker's collect handler (source-property — engine-worker.js starts
// timers at module scope and is never require()d by the suite; see
// moduleLoad.test.js's PARSE_ONLY set)
// --------------------------------------------------------------------------

describe('services/engine-worker.js job runner', () => {
  const src = read(WORKER);
  const bare = stripComments(src);

  it('handles both job types', () => {
    assert.match(src, /job\.job_type === 'device_collect'/);
    assert.match(src, /job\.job_type === 'device_delete'/);
  });

  it('requires deviceDeletion LAZILY so a missing module cannot kill the service', () => {
    // The top-level require block must not mention it; the handler must.
    const topBlock = src.slice(0, src.indexOf('// Logging (winston)'));
    assert.doesNotMatch(topBlock, /deviceDeletion/, 'must NOT be a module-scope require');
    assert.match(src, /require\('\.\.\/lib\/engines\/deviceDeletion'\)/);
    assert.match(src, /was NOT deleted/, 'a missing module must fail that one job, plainly');
  });

  it('never invents a progress total for a collect', () => {
    // ⛔ collectAndStore reports no step count. The worker must not manufacture
    // one — NULL means "the size is not known", which is the truth.
    const handler = src.slice(
      src.indexOf('async function runDeviceCollectJob'),
      src.indexOf('async function runDeviceDeleteJobHandler')
    );
    assert.ok(handler.length > 100, 'located the collect handler');
    assert.doesNotMatch(stripComments(handler), /total:\s*0\b/, 'an unknown total must never be written as 0');
  });

  it('preserves the rulesCount tri-state instead of defaulting it', () => {
    const handler = src.slice(
      src.indexOf('async function runDeviceCollectJob'),
      src.indexOf('async function runDeviceDeleteJobHandler')
    );
    // ⛔ THE CANONICAL BUG. `?? 0` / `|| 0` here turns a FAILED rule pull into
    // the sentence "Collected — 0 rules.".
    assert.doesNotMatch(stripComments(handler), /rulesCount\s*(\?\?|\|\|)\s*0/);
    assert.match(
      handler,
      /result\.rulesCount === null \|\| result\.rulesCount === undefined \? null :/,
      'null must stay null'
    );
    assert.match(handler, /the ruleset was NOT updated/, 'and must be SAID, not silently dropped');
  });

  it('always closes a job row out, so nothing is left running forever', () => {
    assert.match(src, /finishJob\(pool, job\.id, outcome\.status/);
    // Self-catching: one failed job must never crash the service.
    assert.match(src, /Job \[job-queue\] .*threw/);
  });

  it('reaps at startup and periodically, and starts the queue before the long startup passes', () => {
    const main = src.slice(src.indexOf('async function main()'));
    const reapAt = main.indexOf("'job-reaper'");
    const startAt = main.indexOf('startJobQueue()');
    const feedAt = main.indexOf("'feed-sync-and-match'");
    assert.ok(reapAt > -1 && startAt > -1 && feedAt > -1);
    assert.ok(reapAt < startAt, 'reap stale rows before claiming new work');
    assert.ok(startAt < feedAt, 'the queue must not wait behind the multi-minute startup passes');
    assert.match(src, /JOB_REAP_INTERVAL_MS/, 'and reaps periodically, not only at startup');
  });
});

// --------------------------------------------------------------------------
// The two routes and the component (source-property — ESM/JSX, not requireable)
// --------------------------------------------------------------------------

describe('POST /api/devices/[id]/collect only enqueues', () => {
  const src = read(COLLECT_ROUTE);
  const bare = stripComments(src);

  it('does not run the collection on the request path any more', () => {
    assert.doesNotMatch(bare, /collectAndStore/, 'the 111-second foreground request is the bug');
    assert.match(src, /enqueueJob\(/);
  });

  it('is admin-gated and force-dynamic', () => {
    assert.match(src, /isAdmin\(session\)/);
    assert.match(src, /forbiddenResponse\(\)/);
    assert.match(src, /export const dynamic = 'force-dynamic'/);
  });

  it('reports a queued job as queued, never as a result', () => {
    // ⛔ No ok / rulesCount / errors in the enqueue response: nothing has been
    // measured yet, and a caller reading a 202 as "collected" would be
    // inventing an outcome.
    assert.doesNotMatch(bare, /rulesCount/);
    assert.match(src, /jobId: job\.id/);
    assert.match(src, /status: job\.status/);
    assert.match(src, /status: 202/);
  });
});

describe('GET /api/jobs/[id]', () => {
  const src = read(JOB_ROUTE);
  const bare = stripComments(src);

  it('is authenticated but not admin-gated — it is a read', () => {
    assert.match(src, /if \(!session\)/);
    assert.match(src, /status: 401/);
    assert.doesNotMatch(bare, /isAdmin/);
    assert.match(src, /export const dynamic = 'force-dynamic'/);
  });

  it('maps an absent progress count to null, never to 0', () => {
    // ⛔ pg returns BIGINT as a string, so the tempting `Number(v) || 0` is
    // right there — and it turns "not known" into "0 of 0", which reads as
    // finished.
    assert.match(src, /function numOrNull/);
    assert.match(src, /if \(value === null \|\| value === undefined\) return null;/);
    assert.doesNotMatch(bare, /progress_total\s*(\?\?|\|\|)\s*0/);
    assert.doesNotMatch(bare, /Number\([^)]*\)\s*\|\|\s*0/);
  });

  it('does not treat queued or running as terminal', () => {
    assert.match(src, /terminal: TERMINAL\.has\(job\.status\)/);
  });

  it('passes a non-JSON detail through as text rather than discarding it', () => {
    assert.match(src, /function normalizeDetail/);
    assert.match(src, /return \{ message: detail, result: null \};/);
  });
});

describe('DeviceActions.js polls instead of blocking', () => {
  const src = read(ACTIONS);
  const bare = stripComments(src);

  it('follows a job id instead of awaiting the collection', () => {
    assert.match(src, /\/api\/jobs\//);
    assert.match(src, /data\.jobId/);
    assert.match(src, /terminal/);
  });

  it('keeps the rulesCount tri-state all the way to the sentence shown', () => {
    // ⛔ The regression this whole file exists to prevent. `?? 0` here renders
    // a FAILED rule pull as "Collected — 0 rules." in the one place the
    // operator is actively watching for the result.
    assert.doesNotMatch(bare, /rulesCount\s*(\?\?|\|\|)\s*0/);
    assert.match(src, /Number\.isFinite\(rulesCount\)/, 'a real number, including 0, is the only measured case');
    assert.match(src, /the device reported no rule count — the ruleset was NOT updated/);
    assert.match(src, /Collected — \$\{rulesCount\} rules\./);
  });

  it('renders an unknown progress total as unknown, not as 0 of 0', () => {
    assert.match(src, /typeof total === 'number' && total > 0/);
    assert.match(src, /total not known/);
  });

  it('reports a failed POLL as an unknown STATUS, not as a failed job', () => {
    // ⛔ Absence of an observation is not evidence of absence. A poll that
    // cannot reach the server says nothing about the collect.
    assert.match(src, /statusUnknown/);
    assert.match(src, /Status unknown/);
    assert.match(src, /may still be running/);
  });

  it('paints the unmeasured state with no hue', () => {
    // Colour means RISK (CLAUDE.md Design System). An unknown outcome is
    // neither green nor red.
    assert.match(src, /unknown: 'var\(--unmeasured\)'/);
  });

  it('never claims success on enqueue', () => {
    const beforePoll = bare.slice(0, bare.indexOf('await pollJob('));
    assert.doesNotMatch(beforePoll, /state: 'ok'[\s\S]{0,80}Collected/);
    assert.match(src, /A QUEUED JOB IS NOT A SUCCESSFUL COLLECT/);
  });

  it('defines no component inside a component', () => {
    // CLAUDE.md Critical Rule: a nested component remounts on every keystroke.
    // Slice PAST the component's own declaration, or this matches itself.
    const decl = 'export default function DeviceActions';
    const body = bare.slice(bare.indexOf(decl) + decl.length);
    assert.doesNotMatch(body, /function [A-Z][A-Za-z0-9]*\s*\(/);
  });
});
