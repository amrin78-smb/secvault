'use client';

import { useEffect, useRef, useState } from 'react';
import { KNOWN_FEEDS } from '../../lib/feedStatus';
import { FEED_LABELS } from '../../lib/formatDisplay';
import { useRouter } from 'next/navigation';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';

// Same pattern as components/devices/DeviceActions.js / RunAnalysisButton.js, but now
// fire-and-forget + poll rather than one long blocking request — same shape as
// components/settings/UpdatePanel.js's POST /api/system/update + poll-a-status-endpoint
// pattern (simpler here: no service-restart liveness concern, just "has the async work
// finished").
//
// This USED to `await` the POST all the way to completion. That was already risky when
// runFullSync() only did NVD (rate-limited to 1 req/6s across 6 vendor CPE strings) + KEV.
// It got worse once Palo Alto PSIRT and Fortinet PSIRT (RSS discovery + up to ~50 advisories
// at 1s/advisory-pair) were added as two more sequential steps in runFullSync — a full run can
// legitimately take several minutes now, and holding one HTTP request open that whole time has
// no resilience against a dev-server hot-reload, a proxy's idle-connection timeout, or the
// browser tab losing focus. A stuck `feed_sync_log` row (status='partial', finished_at=NULL) is
// exactly what that kind of mid-flight interruption looks like.
//
// POST /api/feeds/sync now schedules runFullSync() and responds almost instantly with
// { started: true } — it does not wait for the sync to finish. Progress/completion is observed
// by polling GET /api/feeds/status (already existed) and checking that every one of the 4
// feed_sync_log sources has a finished_at that is both non-null AND >= the timestamp captured
// right before the POST — that "at-or-after this click" check is what distinguishes "this run
// actually completed" from "showing a stale result from a previous run".
const POLL_INTERVAL_MS = 3000;
const POLL_TIMEOUT_MS = 600000; // 10 minutes — same precedent as UpdatePanel.js's HEALTH_TIMEOUT_MS
// ⛔ DERIVED, NOT DUPLICATED — this was the FIFTH hand-maintained copy of the feed
// list and it silently went stale when CVE.org and EPSS were added. Three wrong
// outputs followed, all confirmed against a live run:
//   1. `allDone` was satisfied the moment CISA KEV finished, so the button said
//      "Sync complete." ~18s before the run was over — then called router.refresh(),
//      re-rendering the banner with the two feeds it had just declared done showing
//      as not-yet-finished.
//   2. `failed` only inspected the old four, so an errored CVE.org or EPSS still
//      produced a green "Sync complete."
//   3. The copy said "all 4 feed sources" when there are six.
// A registry that must be edited in five places WILL drift, and nothing errors when
// it does — the UI just quietly describes a system that no longer exists.
const FEED_SOURCES = KNOWN_FEEDS.map((key) => ({ key, label: FEED_LABELS[key] || key }));

function summarizeBySource(bySource) {
  return FEED_SOURCES.map(({ key, label }) => {
    const entry = bySource && bySource[key];
    return `${label}: ${entry ? entry.status : 'no result'}`;
  }).join(' · ');
}

export default function SyncNowButton() {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null); // { ok, text }
  const pollIntervalRef = useRef(null);

  // Memory-leak guard — same convention as every other polling component in this app
  // (e.g. UpdatePanel.js's tick()/pollId cleanup): clear any in-flight poll on unmount.
  useEffect(() => {
    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    };
  }, []);

  function stopPolling() {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
  }

  function pollStatus(triggeredAt) {
    const pollingStartedAt = Date.now();
    pollIntervalRef.current = setInterval(async () => {
      if (Date.now() - pollingStartedAt > POLL_TIMEOUT_MS) {
        stopPolling();
        setRunning(false);
        setResult({ ok: false, text: 'Sync is taking longer than expected — check status below.' });
        return;
      }

      try {
        const res = await fetch('/api/feeds/status', { cache: 'no-store' });
        const data = await res.json().catch(() => ({}));
        const bySource = data && data.bySource;
        if (!bySource) return; // transient — the overall timeout above is the backstop

        const allDone = FEED_SOURCES.every(({ key }) => {
          const entry = bySource[key];
          if (!entry || !entry.finished_at) return false;
          const finishedAt = new Date(entry.finished_at);
          return !Number.isNaN(finishedAt.getTime()) && finishedAt >= triggeredAt;
        });

        if (allDone) {
          stopPolling();
          setRunning(false);
          // A completed run is not necessarily a successful one — mirror lib/feedStatus.js's
          // getSyncPillStatus() convention (status === 'error' is the failure signal, same
          // known feed-name list) rather than treating "finished_at is set" as "succeeded".
          // Without this, a source that errored out (e.g. NVD failed while KEV succeeded)
          // still reported ok: true here, hiding a real partial failure from the operator.
          const failed = FEED_SOURCES.filter(({ key }) => bySource[key] && bySource[key].status === 'error');
          const ok = failed.length === 0;
          const text = ok
            ? `Sync complete. ${summarizeBySource(bySource)}`
            : `Sync completed with errors (${failed.map((f) => f.label).join(', ')}). ${summarizeBySource(bySource)}`;
          setResult({ ok, text });
          router.refresh();
        }
      } catch (_err) {
        // Transient fetch failure while polling — keep going, POLL_TIMEOUT_MS is the backstop.
      }
    }, POLL_INTERVAL_MS);
  }

  async function handleSync() {
    if (running) return;
    setRunning(true);
    setResult(null);
    // Captured before the POST so the completion check below can tell "this click's run
    // finished" apart from "a previous run's stale finished_at is still sitting there".
    const triggeredAt = new Date();

    try {
      const res = await fetch('/api/feeds/sync', { method: 'POST' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) {
        throw new Error(data.error || 'Sync failed to start');
      }
    } catch (err) {
      setRunning(false);
      setResult({ ok: false, text: err.message || 'Sync failed to start' });
      return;
    }

    // Trigger accepted (`{ started: true }`) — the sync itself now runs in the background on
    // the server. Poll feed_sync_log via /api/feeds/status until every source has completed.
    pollStatus(triggeredAt);
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
      <Button type="button" variant="primary" onClick={handleSync} disabled={running}>
        {running && <LoadingSpinner size={14} />}
        {running ? 'Syncing…' : 'Sync Now'}
      </Button>
      {result && (
        <span style={{ fontSize: 'var(--text-base)', color: result.ok ? 'var(--green)' : 'var(--red)' }}>
          {result.text}
        </span>
      )}
      {running && (
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          Runs in the background — this can take several minutes across all {FEED_SOURCES.length} feed sources.
        </span>
      )}
    </div>
  );
}
