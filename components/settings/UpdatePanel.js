'use client';

// Interactive "Software Update" panel for the Settings page. Contract:
//   GET  /api/system/update-status  -> { current_version, latest_version,
//     current_commit, latest_commit, current_hash, latest_hash, up_to_date,
//     update_available, release_notes: string[], release_date, error? }
//   POST /api/system/update         -> { started: true } on success, or
//     { error } with a non-200 status on failure (401/400/500)
//   GET  /api/health                -> { status: 'ok' } while the app is up;
//     the fetch itself rejects while a restart has it down.
//
// Every piece here is a separate top-level function/const per CLAUDE.md's
// "never define a component inside another component" rule — including the
// countdown number and the full-screen updating overlay.

import { useEffect, useRef, useState } from 'react';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';
import Modal from '../ui/Modal';

const HEALTH_POLL_MS = 2000;
const HEALTH_ABORT_MS = 1800;
const HEALTH_TIMEOUT_MS = 600000; // 10 minutes
const RELOAD_COUNTDOWN_SECONDS = 15;
const REQUIRED_CONSECUTIVE_HEALTHY = 3;

function fmtReleaseDate(d) {
  if (!d) return '';
  const dt = new Date(`${d}T00:00:00`);
  if (Number.isNaN(dt.getTime())) return d;
  return dt.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
}

// Presentational-only, kept top-level rather than inlined into the overlay.
function CountdownNumber({ value }) {
  return (
    <div style={{ fontSize: 40, fontWeight: 800, lineHeight: 1, margin: '4px 0 10px', color: 'var(--primary)' }}>
      {value}
    </div>
  );
}

// Full-screen non-dismissible progress overlay shown once the update POST has
// been fired (or thrown — see handleStartUpdate). Runs its own health-poll
// state machine: starting -> down -> back_up (or timeout), then a 15s visible
// countdown before a full navigation reload so the freshly-restarted Next.js
// frontend (started after the API/service) has a moment to actually be ready.
function UpdatingOverlay({ preUpdateCommit }) {
  const [phase, setPhase] = useState('starting'); // starting | down | back_up | verify_failed | timeout
  const [countdown, setCountdown] = useState(RELOAD_COUNTDOWN_SECONDS);
  const wentDownRef = useRef(false);
  const consecutiveUpRef = useRef(0);

  async function verifyAndRedirect() {
    try {
      const ctrl = new AbortController();
      const abortId = setTimeout(() => ctrl.abort(), 5000);
      const res = await fetch('/api/system/update-status', { cache: 'no-store', signal: ctrl.signal });
      clearTimeout(abortId);
      const data = await res.json();
      const newCommit = (data && data.current_commit) || '';
      if (preUpdateCommit && newCommit && newCommit === preUpdateCommit) {
        setPhase('verify_failed');
        return;
      }
    } catch (_err) {
      // Verification itself failed (transient) — the service is confirmed back
      // up by the health poll already, so fall through and let the user land
      // on the dashboard rather than blocking on this secondary check.
    }
    window.location.href = '/?updated=true';
  }

  useEffect(() => {
    let active = true;
    const startedAt = Date.now();
    let pollId = null;

    async function tick() {
      if (!active) return;
      if (Date.now() - startedAt > HEALTH_TIMEOUT_MS) {
        if (pollId !== null) clearInterval(pollId);
        setPhase('timeout');
        return;
      }

      const ctrl = new AbortController();
      const abortId = setTimeout(() => ctrl.abort(), HEALTH_ABORT_MS);
      let ok = false;
      try {
        const res = await fetch('/api/health', { cache: 'no-store', signal: ctrl.signal });
        ok = res.ok;
      } catch (_err) {
        ok = false;
      } finally {
        clearTimeout(abortId);
      }

      if (!active) return;

      if (!ok) {
        // A failed probe resets the consecutive-success counter — during
        // startup the app can answer once then briefly drop again.
        consecutiveUpRef.current = 0;
        wentDownRef.current = true;
        setPhase('down');
        return;
      }

      // A healthy probe only counts toward "back up" once we've confirmed the
      // service actually went down first — otherwise this could declare
      // victory against the still-running pre-restart process.
      if (wentDownRef.current) {
        consecutiveUpRef.current += 1;
        if (consecutiveUpRef.current >= REQUIRED_CONSECUTIVE_HEALTHY) {
          setPhase('back_up');
          if (pollId !== null) clearInterval(pollId);
        }
      }
    }

    pollId = setInterval(tick, HEALTH_POLL_MS);
    tick();

    return () => {
      active = false;
      if (pollId !== null) clearInterval(pollId);
    };
  }, []);

  useEffect(() => {
    if (phase !== 'back_up') return undefined;
    if (countdown <= 0) {
      verifyAndRedirect();
      return undefined;
    }
    const id = setTimeout(() => setCountdown((c) => c - 1), 1000);
    return () => clearTimeout(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase, countdown]);

  let statusLine = 'Starting update…';
  if (phase === 'down') statusLine = 'Services restarting…';
  else if (phase === 'back_up') statusLine = `Services are back online. Reloading in ${countdown} second${countdown === 1 ? '' : 's'}…`;
  else if (phase === 'verify_failed') statusLine = 'Services restarted, but the version did not change. Try again or check server logs.';
  else if (phase === 'timeout') statusLine = 'Update is taking longer than expected. Try refreshing the page manually.';

  const isError = phase === 'timeout' || phase === 'verify_failed';

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 2000,
        background: 'rgba(15,23,42,0.72)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 16,
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: 440,
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          boxShadow: 'var(--shadow-lg)',
          padding: 28,
          textAlign: 'center',
        }}
      >
        {phase !== 'back_up' && !isError && <LoadingSpinner size={44} />}
        {phase === 'back_up' && <div style={{ fontSize: 40, color: 'var(--green)' }}>&#10003;</div>}
        {isError && <div style={{ fontSize: 40, color: 'var(--yellow)' }}>&#9888;</div>}

        <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)', marginTop: 14 }}>
          Updating SecVault…
        </div>
        <p style={{ color: 'var(--text-muted)', marginTop: 6, fontSize: 'var(--text-base)' }}>
          Pulling latest code and restarting services. Do not close this window.
        </p>
        <p style={{ fontWeight: 600, margin: '14px 0', color: 'var(--text-primary)', fontSize: 'var(--text-base)' }}>
          {statusLine}
        </p>

        {phase === 'back_up' && <CountdownNumber value={countdown} />}
        {phase !== 'back_up' && !isError && (
          <p style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>(This usually takes 1–3 minutes)</p>
        )}
        {isError && (
          <Button type="button" variant="primary" onClick={() => window.location.reload()} style={{ marginTop: 10 }}>
            Reload
          </Button>
        )}
      </div>
    </div>
  );
}

export default function UpdatePanel() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [checking, setChecking] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [updating, setUpdating] = useState(false);
  // Guards the window between the "Start Update" click and the POST
  // resolving/throwing -- without this, a rapid double-click (or a second
  // click before the confirm Modal has actually unmounted) can fire
  // POST /api/system/update twice. The route deletes+recreates+runs the
  // "SecVaultUpdate" scheduled task on every call with no idempotency check,
  // so a second concurrent call while the first Update-SecVault.ps1 run is
  // still executing (stop services -> git pull -> npm ci -> migrate -> build
  // -> start services, per CLAUDE.md) can disrupt it mid-run. Only reset on
  // the error path -- on success handleStartUpdate flips to the updating
  // overlay, which unmounts this button entirely, so there's nothing to
  // re-enable.
  const [starting, setStarting] = useState(false);
  const [updateError, setUpdateError] = useState(null);
  // Commit captured when status is first loaded (and refreshed on every
  // manual check) — compared against the post-restart commit to confirm the
  // update actually applied, not just that services came back up.
  const preUpdateCommitRef = useRef(null);

  async function loadStatus(isManualCheck) {
    if (isManualCheck) setChecking(true);
    else setLoading(true);
    try {
      const res = await fetch('/api/system/update-status');
      const data = await res.json().catch(() => ({}));
      setStatus(data);
      if (data && data.current_commit) preUpdateCommitRef.current = data.current_commit;
    } catch (err) {
      setStatus({ error: err.message || 'Could not check for updates' });
    } finally {
      if (isManualCheck) setChecking(false);
      else setLoading(false);
    }
  }

  useEffect(() => {
    loadStatus(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleStartUpdate() {
    if (starting) return; // already in flight -- physically can't double-fire
    setStarting(true);
    setConfirmOpen(false);
    setUpdateError(null);
    try {
      const res = await fetch('/api/system/update', { method: 'POST' });
      if (!res.ok) {
        // A clean non-2xx response (401/400/500) means the update never
        // started — that's different from the connection dropping mid-request
        // (caught below), so show an error instead of the progress overlay.
        const data = await res.json().catch(() => ({}));
        setUpdateError(data.error || 'Update request failed.');
        setStarting(false);
        return;
      }
    } catch (_err) {
      // Expected — the connection can drop mid-request if the restart is
      // fast. Treat this the same as a successful { started: true }.
    }
    setUpdating(true);
  }

  if (updating) {
    return <UpdatingOverlay preUpdateCommit={preUpdateCommitRef.current} />;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {loading && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--text-muted)', fontSize: 'var(--text-base)' }}>
          <LoadingSpinner size={18} />
          <span>Checking update status…</span>
        </div>
      )}

      {!loading && status && status.error && (
        <p style={{ fontSize: 'var(--text-base)', color: 'var(--red)', margin: 0 }}>{status.error}</p>
      )}

      {!loading && status && !status.error && status.up_to_date && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {/* Same dot + pill visual language as the "FEEDS OK" indicator in
              components/layout/Header.js, adapted to tint tokens (rather than
              Header's literal navy-topbar rgba values) since this panel sits
              on a light --bg-card surface, not the dark --navy topbar. */}
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 7,
              width: 'fit-content',
              padding: '5px 12px',
              background: 'var(--tint-success)',
              border: '1px solid var(--green)',
              borderRadius: 20,
            }}
          >
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--green)' }} />
            <span style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--tint-success-fg)', letterSpacing: '0.03em' }}>
              UP TO DATE
            </span>
          </div>
          <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', margin: 0 }}>
            Current version: <span className="mono">v{status.current_version}</span>
            {status.current_commit && (
              <>
                {' '}(<span className="mono">{status.current_commit}</span>)
              </>
            )}
          </p>
        </div>
      )}

      {!loading && status && !status.error && status.update_available && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <p style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            {status.current_version === status.latest_version
              ? `Patches available since v${status.current_version}`
              : `Update available: v${status.current_version} → v${status.latest_version}`}
          </p>
          <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', margin: 0 }}>
            Current: v{status.current_version}
            {status.current_commit && (
              <>
                {' '}(<span className="mono">{status.current_commit}</span>)
              </>
            )}
            {'  →  '}
            Latest: v{status.latest_version}
            {status.latest_commit && (
              <>
                {' '}(<span className="mono">{status.latest_commit}</span>)
              </>
            )}
          </p>

          {Array.isArray(status.release_notes) && status.release_notes.length > 0 && (
            <div
              style={{
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                padding: '12px 16px',
                background: 'var(--surface-subtle)',
              }}
            >
              <div style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>
                What&rsquo;s new in v{status.latest_version}
              </div>
              <ul style={{ margin: 0, paddingLeft: 18, fontSize: 'var(--text-base)', lineHeight: 1.6, color: 'var(--text-secondary)' }}>
                {status.release_notes.map((note, i) => (
                  <li key={i}>{note}</li>
                ))}
              </ul>
            </div>
          )}

          {status.release_date && (
            <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-muted)', margin: 0 }}>
              Released: {fmtReleaseDate(status.release_date)}
            </p>
          )}

          <p style={{ fontSize: 'var(--text-base)', color: 'var(--tint-warn-fg)', margin: 0 }}>
            Services will restart during the update — you may lose connection for 30–60 seconds.
          </p>
        </div>
      )}

      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Button type="button" variant="secondary" onClick={() => loadStatus(true)} disabled={checking}>
          {checking && <LoadingSpinner size={14} />}
          {checking ? 'Checking…' : 'Check for Updates'}
        </Button>
        {!loading && status && !status.error && status.update_available && (
          <Button type="button" variant="primary" onClick={() => setConfirmOpen(true)}>
            Update Now
          </Button>
        )}
      </div>

      {updateError && <p style={{ fontSize: 'var(--text-base)', color: 'var(--red)', margin: 0 }}>{updateError}</p>}

      <Modal open={confirmOpen} onClose={() => setConfirmOpen(false)} title="Start Update?">
        <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', marginBottom: 20 }}>
          Services will restart and you&rsquo;ll lose connection for 30–60 seconds. The page reloads automatically when the
          update completes.
        </p>
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <Button type="button" variant="secondary" onClick={() => setConfirmOpen(false)} disabled={starting}>
            Cancel
          </Button>
          <Button type="button" variant="primary" onClick={handleStartUpdate} disabled={starting}>
            {starting && <LoadingSpinner size={14} />}
            {starting ? 'Starting…' : 'Start Update'}
          </Button>
        </div>
      </Modal>
    </div>
  );
}
