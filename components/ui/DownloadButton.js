'use client';

// components/ui/DownloadButton.js
//
// A download link that says something while the server is still building the file.
//
// ⛔ WHY THIS EXISTS. Several downloads in this product are generated on demand and
// take real time: GET /api/logs/export walks the syslog window in one-hour slices and
// can run to ~45 seconds, and the compliance/report PDFs are rendered per request. As
// plain <a href> links they gave the operator NOTHING — no spinner, no state, no
// failure — until the browser's own download appeared. Reported verbatim as "Now i
// dont see anything."
//
// It replaces two existing workarounds, both of which were honest about being
// workarounds:
//   - components/reports/ReportWorkspace.js's onDownload() — a 4-second TIMER whose own
//     comment says it "can only report that the request was made" and is "never
//     presented as proof the file exists". Here the fetch resolves when the bytes are
//     actually in hand, so `done` is a measurement rather than a guess.
//   - components/layout/NavProgress.js — the global nav bar deliberately SKIPS /api/*
//     links, because a download never changes the pathname and the bar would sit there
//     claiming a page was loading. That exclusion stays correct; this component is what
//     fills the gap it leaves.
//
// ⛔ PROGRESSIVE ENHANCEMENT IS NOT OPTIONAL. This renders a REAL <a href>. Before
// hydration, or with JS broken, the plain link behaves exactly as it does today — the
// server already handles a plain navigation correctly (a success downloads via
// Content-Disposition; a refusal 303-redirects back to the page and renders a banner).
// A <button> that does nothing without JS would be a regression, not an enhancement.
//
// ⛔ NO PROGRESS BAR AND NO PERCENTAGE, EVER. The server generates the whole file before
// it sends a byte, so there is no Content-Length to measure against and any bar would be
// a fabricated measurement — a confident number nobody took. Indeterminate only.
//
// All the judgement lives in lib/downloadState.js (pure, unit-tested); this file is the
// DOM and the lifecycle, nothing more.

import { useEffect, useRef, useState } from 'react';
import {
  STATES,
  nextState,
  shouldIntercept,
  filenameFromDisposition,
  describeFailure,
  coverageNote,
  DONE_LINGER_MS,
} from '../../lib/downloadState';
import LoadingSpinner from './LoadingSpinner';

// ⛔ MODULE TOP LEVEL, not nested inside the component (CLAUDE.md critical rule — a
// component defined inside a component remounts on every render).
//
// Hands the blob to the browser and then releases it. A 20 MB export leaked once per
// click is a real cost on a console tab that stays open all day.
function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  a.remove();
  // ⛔ Revoked on the NEXT task, not synchronously: the click only QUEUES the save, and
  // revoking in the same tick cancels the download in some browsers. Nothing here
  // touches component state, so an unmount between the click and the revoke is harmless
  // — the revoke is precisely the cleanup we want either way.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

export default function DownloadButton({
  href,
  className = 'btn btn-secondary',
  style,
  title,
  fallbackName = 'download',
  preparingLabel = 'Preparing…',
  // ⛔ THE WRAPPER NEEDS ITS OWN STYLE HOOK. This component adds a span
  // AROUND the anchor to carry the status region, and that span becomes the flex
  // item in whatever laid the original link out. A call site whose parent is a
  // column flex (the dashboard's Quick Actions) needs the wrapper to stretch, or
  // the entry silently shrinks to its text width and stops matching its
  // neighbours. Styling the anchor cannot fix that — it is no longer the child
  // the parent is laying out.
  wrapperStyle,
  children,
}) {
  const [state, setState] = useState(STATES.IDLE);
  const [failure, setFailure] = useState(null); // one operator-facing sentence, persists
  const [note, setNote] = useState(null); // coverage caveat from the last successful file

  const abortRef = useRef(null); // also doubles as the in-flight marker
  const lingerRef = useRef(null);
  const mountedRef = useRef(true);

  // ⛔ Unmount must not leave a request running or a timer pointing at a dead component.
  // mountedRef is re-armed on mount because React's dev double-invoke runs the cleanup
  // once before the real mount.
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (abortRef.current) abortRef.current.abort();
      if (lingerRef.current) clearTimeout(lingerRef.current);
      lingerRef.current = null;
    };
  }, []);

  async function handleClick(event) {
    // Ctrl/cmd/middle/shift-click, or anything already handled: the browser's job, not
    // ours. Leaving these alone is what keeps "open in a new tab" working.
    if (!shouldIntercept(event)) return;

    // From here on we own the click, including the refusals below — letting one fall
    // through would start a plain navigation on top of a download already in flight.
    event.preventDefault();

    // ⛔ ONE AT A TIME. Each export writes an audit row and costs a full window scan;
    // two in flight is real server load and an audit trail that misrepresents what the
    // operator did. The ref (not the state) is the guard, because a fast double-click
    // can land before React has re-rendered the disabled styling.
    if (abortRef.current) return;

    if (lingerRef.current) {
      clearTimeout(lingerRef.current);
      lingerRef.current = null;
    }
    setFailure(null);
    setNote(null);
    setState((s) => nextState(s, 'start'));

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const res = await fetch(href, {
        signal: controller.signal,
        credentials: 'same-origin',
        headers: { accept: 'text/csv, application/pdf, application/json' },
      });

      if (!res.ok) {
        // A refusal usually carries a structured reason; when it does not, the status is
        // still a fact worth reporting. describeFailure owns the wording either way.
        let body = null;
        try {
          body = await res.json();
        } catch (_err) {
          body = null;
        }
        const sentence = body && typeof body === 'object'
          ? describeFailure({ status: res.status, reason: body.reason, detail: body.detail || body.error })
          : describeFailure({ status: res.status });
        if (!mountedRef.current) return;
        setFailure(sentence);
        setState((s) => nextState(s, 'failure'));
        return;
      }

      // ⛔ NEVER SAVE A PAGE AS A FILE. `fetch` follows redirects transparently,
      // and /api/logs/export answers a refusal with a 303 back to /logs for any
      // request that does not ask for JSON — so without a guard the browser
      // lands on the HTML error page at status 200 and writes it out as
      // `export.csv`. A corrupt file that downloads successfully is worse than
      // a refusal: the operator has evidence they believe in.
      //
      // The `accept` header above already steers the server to a JSON refusal,
      // but that coupling lives in two files and is easy to break from either
      // end. This is the independent check: if the server did not send a file,
      // we do not write one, whatever the status said.
      const ctype = (res.headers.get('content-type') || '').toLowerCase();
      if (ctype.includes('text/html')) {
        if (!mountedRef.current) return;
        setFailure(describeFailure({
          status: res.status,
          detail:
            'The server returned a web page instead of a file, so nothing was saved. '
            + 'Reload the page and try again; if it persists, the export route is misrouting.',
        }));
        setState((s) => nextState(s, 'failure'));
        return;
      }

      const name = filenameFromDisposition(res.headers.get('content-disposition'), fallbackName);
      const coverage = coverageNote(res.headers);
      const blob = await res.blob();
      saveBlob(blob, name);

      if (!mountedRef.current) return;
      setNote(coverage || null);
      setState((s) => nextState(s, 'success'));
      lingerRef.current = setTimeout(() => {
        lingerRef.current = null;
        if (!mountedRef.current) return;
        setState((s) => nextState(s, 'reset'));
      }, DONE_LINGER_MS);
    } catch (err) {
      // An abort is OUR doing (unmount), not a failure to report to anyone.
      if (controller.signal.aborted) return;
      if (!mountedRef.current) return;
      setFailure(describeFailure({ detail: err && err.message ? err.message : String(err) }));
      setState((s) => nextState(s, 'failure'));
    } finally {
      if (abortRef.current === controller) abortRef.current = null;
    }
  }

  const preparing = state === STATES.PREPARING;
  const done = state === STATES.DONE;

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--s2)',
        flexWrap: 'wrap',
        ...wrapperStyle,
      }}
    >
      <a
        href={href}
        className={className}
        title={title}
        onClick={handleClick}
        aria-busy={preparing ? 'true' : undefined}
        aria-disabled={preparing ? 'true' : undefined}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 'var(--s2)',
          ...style,
          // ⛔ AFTER the caller's style, deliberately: "not clickable while preparing" is
          // a safety property, not a default a call site may override by accident.
          ...(preparing ? { pointerEvents: 'none', opacity: 0.6 } : null),
        }}
      >
        {preparing && <LoadingSpinner size={14} />}
        {preparing ? preparingLabel : children}
      </a>

      {/* Always in the DOM so a later change is announced — a live region inserted at the
          same moment as its text frequently is not. */}
      <span
        role="status"
        aria-live="polite"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 'var(--s2)',
          fontSize: 'var(--text-sm)',
        }}
      >
        {preparing && <span className="sr-only">{preparingLabel}</span>}

        {done && (
          // Says what was actually observed — the bytes arrived and were handed to the
          // browser. It does not claim the file is on disk; that is the browser's half.
          <span style={{ color: 'var(--text-muted)' }}>Received — your browser is saving it.</span>
        )}

        {failure && (
          // Persists until the next click. An error that clears itself after a few
          // seconds is an error the operator never read.
          <span style={{ color: 'var(--sev-crit)' }}>{failure}</span>
        )}

        {note && (
          // ⛔ WARN, NOT DANGER. The file is valid — it simply covers less than was asked
          // for, and tinting that red would read as a failed export.
          <span
            style={{
              background: 'var(--tint-warn)',
              color: 'var(--tint-warn-fg)',
              padding: 'var(--s1) var(--s2)',
              borderRadius: 'var(--radius-sm)',
            }}
          >
            {note}
          </span>
        )}
      </span>
    </span>
  );
}
