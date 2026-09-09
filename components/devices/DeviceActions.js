'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';

// Collect Now / Test Connectivity.
//
// ⛔ COLLECT IS NO LONGER A FOREGROUND REQUEST. It used to be: click ->
// fetch('/api/devices/[id]/collect') -> await the whole collectAndStore.
// collectAndStore runs getVersion + getRules + getConfig in sequence, each to
// its own adapter timeout (PAN-OS budgets 120s for getConfig alone). On
// 2026-09-09 a live Collect Now against a FortiGate ran for 111 seconds and the
// operator reported the app unusable for the whole of it. Measured at the time:
// the server answered other requests in 20-90ms and Postgres had zero locks and
// zero blocked queries, so neither was saturated — the exact client-side
// blocking mechanism was never proven. It did not need to be. A 111-second
// foreground request is wrong regardless, so the request now only ENQUEUES a
// background_jobs row (services/engine-worker.js runs it) and this component
// polls GET /api/jobs/[id] for the result.
//
// Test Connectivity is unchanged and still synchronous — it is a single probe,
// not a three-capability collection.

const POLL_INTERVAL_MS = 2000;

// A collect that has not reported a terminal status in 20 minutes is not
// declared failed here — it is declared UNKNOWN, and the engine's own reaper
// (30 minutes, lib/engines/backgroundJobs.js) is what actually decides.
const POLL_CEILING_MS = 20 * 60 * 1000;

// ⛔ Three states, not two. `unknown` is a first-class visual state with NO HUE
// (CLAUDE.md's Design System rule): it means we could not measure the outcome,
// which is neither a success nor a failure and must not be painted as either.
const RESULT_COLOR = {
  ok: 'var(--green)',
  bad: 'var(--red)',
  unknown: 'var(--unmeasured)',
};

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ⛔ THE TRI-STATE, carried the whole way from collectAndStore -> the job row's
// JSON `detail` -> GET /api/jobs/[id]'s `result` -> here.
// collectAndStore sets rulesCount to NULL when the rule pull FAILED and to a
// number (INCLUDING a genuine 0) when it succeeded — the same tri-state as
// hit_count. There must be no `?? 0` anywhere on this path: it would turn a
// failed pull into the sentence "Collected — 0 rules.", reporting a failed read
// as a measured zero in the one place the operator is actively watching for the
// result. An ABSENT rulesCount (an older job row, a shape change upstream) is
// treated the same as null — the safe direction. Say what actually happened.
function collectResultText(job) {
  const result = job && job.result && typeof job.result === 'object' ? job.result : null;
  const rulesCount = result ? result.rulesCount : undefined;
  const ruleCountKnown = typeof rulesCount === 'number' && Number.isFinite(rulesCount);

  if (job.status === 'succeeded') {
    return ruleCountKnown
      ? `Collected — ${rulesCount} rules.`
      : 'Collected, but the device reported no rule count — the ruleset was NOT updated.';
  }

  if (job.status === 'cancelled') {
    return 'The collect was cancelled before it finished.';
  }

  const reason = job.error || 'The collect failed.';
  return ruleCountKnown ? reason : `${reason} The ruleset was NOT updated.`;
}

// Progress line shown while a collect is in flight.
function progressLabel(job) {
  if (!job) return 'Queued — waiting for the collector to pick it up.';

  // ⛔ A failed POLL is not a failed JOB. Say the STATUS is unknown.
  if (job.statusUnknown) {
    return 'Status unknown — SecVault could not read the job. The collect may still be running.';
  }

  const base =
    job.status === 'queued'
      ? 'Queued — waiting for the collector to pick it up.'
      : job.message || 'Collecting…';

  const total = job.progressTotal;
  const current = job.progressCurrent;

  // ⛔ progressTotal NULL means the size is NOT KNOWN, never zero. Rendering
  // unknown as "0 of 0" reads as finished, which is the failed-read-as-a-fact
  // bug applied to a progress indicator. Only a real positive total earns an
  // "x of y"; a count with no total is shown as a count and labelled as such.
  if (typeof total === 'number' && total > 0 && typeof current === 'number') {
    return `${base} (${current} of ${total})`;
  }
  if (typeof current === 'number' && (total === null || total === undefined)) {
    return `${base} (${current} so far — total not known)`;
  }
  return base;
}

export default function DeviceActions({ deviceId }) {
  const router = useRouter();
  const [running, setRunning] = useState(null); // 'collect' | 'test' | null
  const [result, setResult] = useState(null); // { state: 'ok'|'bad'|'unknown', text }
  const [job, setJob] = useState(null); // last polled job snapshot

  // Set on unmount so a poll loop that outlives the component stops touching
  // state (and stops issuing requests) instead of warning on every tick.
  const cancelledRef = useRef(false);
  useEffect(() => {
    cancelledRef.current = false;
    return () => {
      cancelledRef.current = true;
    };
  }, []);

  const pollJob = useCallback(async (jobId) => {
    const startedAt = Date.now();
    let consecutiveFailures = 0;

    for (;;) {
      await sleep(POLL_INTERVAL_MS);
      if (cancelledRef.current) return;

      let data = null;
      try {
        const res = await fetch(`/api/jobs/${jobId}`, { cache: 'no-store' });
        if (!res.ok) throw new Error(`status ${res.status}`);
        data = await res.json();
        if (!data || typeof data.status !== 'string') throw new Error('unrecognised job response');
      } catch (err) {
        // ⛔ The POLL failed, not the job. One blip is not worth reporting; a
        // run of them is, and it is reported as UNKNOWN, never as a failure.
        consecutiveFailures += 1;
        if (cancelledRef.current) return;
        if (consecutiveFailures >= 2) {
          setJob((prev) => ({ ...(prev || { status: 'running' }), statusUnknown: true }));
        }
        if (Date.now() - startedAt > POLL_CEILING_MS) {
          setResult({
            state: 'unknown',
            text:
              'Status unknown — SecVault stopped being able to read this job. ' +
              'The collect may still be running; reload to see the device’s latest data.',
          });
          return;
        }
        continue;
      }

      consecutiveFailures = 0;
      if (cancelledRef.current) return;
      setJob({ ...data, statusUnknown: false });

      if (data.terminal) {
        setResult({
          state: data.status === 'succeeded' ? 'ok' : 'bad',
          text: collectResultText(data),
        });
        return;
      }

      if (Date.now() - startedAt > POLL_CEILING_MS) {
        setResult({
          state: 'unknown',
          text:
            'Status unknown — this collect has been running longer than SecVault waits for. ' +
            'It has NOT been declared failed; the engine will record its real outcome.',
        });
        return;
      }
    }
  }, []);

  async function runAction(kind, path) {
    if (running) return;
    setRunning(kind);
    setResult(null);
    setJob(null);
    try {
      const res = await fetch(path, { method: 'POST' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok && !data.jobId) {
        throw new Error(data.error || `${kind === 'collect' ? 'Collect' : 'Test'} failed`);
      }
      if (data.error) {
        throw new Error(data.error);
      }

      if (kind === 'test') {
        setResult({
          state: data.ok === true ? 'ok' : 'bad',
          text: data.message || (data.ok ? 'Connected' : 'Connection failed'),
        });
        router.refresh();
        return;
      }

      // ⛔ A QUEUED JOB IS NOT A SUCCESSFUL COLLECT. Nothing here reports
      // success — the only thing that may is a terminal status from the poll.
      if (!data.jobId) {
        throw new Error(
          'The collect was not queued (no job id returned), so nothing is running and nothing was collected.'
        );
      }
      setJob({
        status: data.status || 'queued',
        message:
          data.created === false
            ? 'A collect was already running for this device — following that one.'
            : 'Queued — waiting for the collector to pick it up.',
        progressCurrent: null,
        progressTotal: null,
        statusUnknown: false,
      });
      await pollJob(data.jobId);
      router.refresh();
    } catch (err) {
      setResult({
        state: 'bad',
        text: err.message || `${kind === 'collect' ? 'Collect' : 'Test'} failed`,
      });
    } finally {
      if (!cancelledRef.current) {
        setRunning(null);
        setJob(null);
      }
    }
  }

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--s2)' }}>
      <Button
        type="button"
        variant="secondary"
        onClick={() => runAction('collect', `/api/devices/${deviceId}/collect`)}
        disabled={Boolean(running)}
      >
        {running === 'collect' && <LoadingSpinner size={14} />}
        {running === 'collect' ? 'Collecting…' : 'Collect Now'}
      </Button>
      <Button
        type="button"
        variant="secondary"
        onClick={() => runAction('test', `/api/devices/${deviceId}/test`)}
        disabled={Boolean(running)}
      >
        {running === 'test' && <LoadingSpinner size={14} />}
        {running === 'test' ? 'Testing…' : 'Test Connectivity'}
      </Button>
      {result && (
        <span style={{ fontSize: 'var(--text-base)', color: RESULT_COLOR[result.state] || 'var(--unmeasured)' }}>
          {result.text}
        </span>
      )}
      {running === 'collect' && (
        <span
          style={{
            fontSize: 'var(--text-xs)',
            // No hue while the outcome is unmeasured.
            color: job && job.statusUnknown ? 'var(--unmeasured)' : 'var(--text-muted)',
          }}
        >
          {progressLabel(job)}
        </span>
      )}
      {running === 'collect' && (
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          Runs on the engine — you can leave this page.
        </span>
      )}
      {running === 'test' && (
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          This can take up to a couple of minutes on an unreachable device.
        </span>
      )}
    </div>
  );
}
