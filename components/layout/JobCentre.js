'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { IconRefresh } from '../icons';

// THE JOB CENTRE — what is running, and how the last few things ended.
//
// ⛔ ═══ WHY THIS EXISTS, AND WHY §9 ALLOWS IT ═══════════════════════════
// The brief permits a job centre "only if real async job state exists". It
// does: `background_jobs` carries two real job types (device_collect,
// device_delete) with queued/running/succeeded/failed/cancelled, progress
// counters, an error column and a reaper that marks an abandoned job FAILED
// rather than assuming it worked.
//
// What was missing was any way to see a job you did not just start. The only
// reads were by job id or by device id, so a collect was visible on exactly
// the page that launched it — navigate away and the job continued with
// nothing in the product able to tell you how it ended, including when it
// failed. That is the case this panel is for.
//
// ⛔ ═══ POLLED ONLY WHILE SOMETHING IS LIVE ══════════════════════════════
// A fixed interval on a page that is open all day is a request every few
// seconds for a table that changes a handful of times a week. The poll is
// fast while a job is live and slow otherwise, and it is the SERVER's `live`
// count that decides — not a client-side re-derivation, which would be a
// second implementation of one number.

const LIVE_POLL_MS = 4000;
const IDLE_POLL_MS = 60000;

const STATUS = {
  queued:    { label: 'Queued',    tone: 'var(--text-muted)' },
  running:   { label: 'Running',   tone: 'var(--tint-info-fg)' },
  succeeded: { label: 'Succeeded', tone: 'var(--tint-success-fg)' },
  // ⛔ The one that must never be quiet. A failed collection is why this
  // panel exists.
  failed:    { label: 'Failed',    tone: 'var(--tint-danger-fg)' },
  cancelled: { label: 'Cancelled', tone: 'var(--text-muted)' },
};

const JOB_LABEL = {
  device_collect: 'Collect',
  device_delete: 'Delete',
};

function when(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString();
}

// ⛔ TRI-STATE, and the middle one is the point. A NULL total means the size
// is not known YET, not zero — `background_jobs`' own schema comment says a
// progress bar rendering unknown as 0/0 reads as "finished".
function progressText(job) {
  const cur = job.progress_current;
  const total = job.progress_total;
  if (cur === null || cur === undefined) return null;
  if (total === null || total === undefined) return `${cur}`;
  return `${cur} / ${total}`;
}

export default function JobCentre() {
  const [open, setOpen] = useState(false);
  // ⛔ `null`, NOT `[]`. An empty array is "nothing is running"; null is "we
  // have not been able to ask". The panel renders them differently, and a
  // failed read must never paint an all-clear over outstanding work.
  const [data, setData] = useState(null);
  const [failed, setFailed] = useState(false);
  const wrapRef = useRef(null);
  const btnRef = useRef(null);
  const aliveRef = useRef(true);

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/jobs');
      if (!res.ok) throw new Error(String(res.status));
      const body = await res.json();
      if (!aliveRef.current) return;
      setData(body);
      setFailed(false);
    } catch {
      if (!aliveRef.current) return;
      // ⛔ The LAST GOOD list is kept on screen rather than blanked. A blink
      // to empty during a transient error is the same false all-clear.
      setFailed(true);
    }
  }, []);

  useEffect(() => {
    aliveRef.current = true;
    load();
    let timer;
    const tick = () => {
      const live = data && data.live > 0;
      timer = setTimeout(async () => { await load(); tick(); },
        live ? LIVE_POLL_MS : IDLE_POLL_MS);
    };
    tick();
    return () => { aliveRef.current = false; clearTimeout(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load, data && data.live]);

  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => { if (e.key === 'Escape') { setOpen(false); btnRef.current?.focus(); } };
    const onClick = (e) => { if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false); };
    document.addEventListener('keydown', onKey);
    document.addEventListener('mousedown', onClick);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('mousedown', onClick);
    };
  }, [open]);

  const jobs = data && Array.isArray(data.jobs) ? data.jobs : null;
  const live = data ? data.live : 0;

  return (
    <div className="jobc" ref={wrapRef}>
      <button
        ref={btnRef}
        type="button"
        className="jobc-btn"
        aria-expanded={open}
        aria-haspopup="true"
        // ⛔ THE COUNT IS IN THE ACCESSIBLE NAME, not only in a coloured dot.
        aria-label={live > 0 ? `Background jobs — ${live} running` : 'Background jobs'}
        onClick={() => setOpen((v) => !v)}
      >
        <IconRefresh />
        {live > 0 && <span className="jobc-badge" aria-hidden="true">{live}</span>}
      </button>

      {open && (
        <div className="jobc-panel" role="dialog" aria-label="Background jobs">
          <div className="jobc-head">
            <strong>Background jobs</strong>
            {/* ⛔ A FAILED READ IS STATED, never swallowed. Without this the
                panel shows a stale list that looks current. */}
            {failed && <span className="jobc-stale">could not refresh</span>}
          </div>

          {/* ⛔ A FAILED FIRST READ IS NOT A READ IN FLIGHT. `jobs` stays null
              both before the first poll AND after a poll that failed — the
              catch deliberately leaves the last good list in place, which is
              right when there IS one and wrong when there is not. So a 503 on
              the first poll rendered "Loading…" for ever, re-polling every 60s,
              and the one state this panel exists to make unmistakable (a
              collection that failed while nobody was on its page) was presented
              as a fetch still running. */}
          {jobs === null && failed ? (
            <p className="jobc-empty">
              SecVault could not read the job list. Nothing is known about recent
              collections or deletions until this succeeds.
            </p>
          ) : jobs === null ? (
            <p className="jobc-empty">Loading…</p>
          ) : jobs.length === 0 ? (
            <p className="jobc-empty">
              Nothing has run recently. Collections and deletions started from a
              firewall&apos;s page appear here.
            </p>
          ) : (
            <ul className="jobc-list">
              {jobs.map((j) => {
                const st = STATUS[j.status] || { label: j.status, tone: 'var(--unmeasured)' };
                const prog = progressText(j);
                return (
                  <li key={j.id} className="jobc-item">
                    <div className="jobc-row">
                      <span className="jobc-type">
                        {JOB_LABEL[j.job_type] || j.job_type}
                        {/* ⛔ The device NAME is left-joined and may be null:
                            a finished DELETE is exactly the case where the
                            device is gone, and it is the job you most want to
                            still see. */}
                        {j.device_name ? ` · ${j.device_name}` : ''}
                      </span>
                      <span className="jobc-status" style={{ color: st.tone }}>{st.label}</span>
                    </div>
                    <div className="jobc-meta">
                      {prog && <span>{prog}</span>}
                      <span>{when(j.finished_at || j.started_at || j.created_at)}</span>
                      {j.device_id && (
                        <Link href={`/devices/${j.device_id}`} className="jobc-link">
                          Open firewall
                        </Link>
                      )}
                    </div>
                    {/* ⛔ THE ERROR IS SHOWN IN FULL, not behind a hover. The
                        whole value of this panel is the job that failed while
                        nobody was on its page. */}
                    {j.error && <p className="jobc-error">{j.error}</p>}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
