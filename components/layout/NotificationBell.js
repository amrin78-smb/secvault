'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { IconBell } from '../icons';

const POLL_MS = 60000;

function formatWhen(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleString();
}

const TYPE_DOT_COLOR = {
  patch_now: 'var(--red)',
  config_diff: 'var(--yellow)',
};

// Header notification bell — real counts from GET /api/notifications/summary
// (device_cve_assessments priority_band='patch_now' + unacknowledged
// config_diffs), polled every 60s. Rule-level findings are deliberately not
// counted here — see app/api/events/route.js's removal comment.
export default function NotificationBell() {
  const [open, setOpen] = useState(false);
  // ⛔ `null`, NOT a fabricated `{total: 0}`. The initial state used to be a
  // zero summary, and a failed first load left it in place — so a DB error on
  // /api/notifications/summary rendered no badge, "0 open", and a bold GREEN
  // "Nothing needs attention" on every page. The catch's own comment ("leave
  // last-known summary in place") is right for a LATER poll and wrong for the
  // first, when the "last known" value is one nobody measured.
  const [summary, setSummary] = useState(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const res = await fetch('/api/notifications/summary');
        const data = await res.json();
        if (cancelled) return;
        // ⛔ The route returns {error} with a 500 on any DB failure. Treat a
        // non-ok status or an error body as a FAILED READ, never as data.
        if (!res.ok || !data || data.error) {
          setLoadFailed(true);
          return;
        }
        setLoadFailed(false);
        setSummary(data);
      } catch (_err) {
        // A later poll failing keeps the last real summary on screen — that is
        // still the newest thing actually measured. It only sets the flag, so
        // the panel can say the figure may be stale rather than silently
        // presenting it as current.
        if (!cancelled) setLoadFailed(true);
      }
    }
    load();
    const t = setInterval(load, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  useEffect(() => {
    function onClickOutside(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, []);

  // ⛔ null total means UNKNOWN, not zero. The badge is suppressed for both,
  // but the panel below must say WHICH of the two it is.
  const total = summary ? summary.total || 0 : null;
  const unknown = summary === null;

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      {/* ⛔ aria-expanded AND aria-haspopup, which were both absent (confirmed
          live in the DOM). Without them this announces as a plain button and a
          screen-reader user is never told it opens a panel, nor whether the
          panel is currently open — so the only way to find out is to press it
          and listen for what changed. components/layout/JobCentre.js, the
          button immediately beside it in the same header, has had both since it
          shipped; this is house convention, not a judgement call. */}
      <button
        type="button"
        className={`sv-icon-btn${open ? ' open' : ''}`}
        onClick={() => setOpen((o) => !o)}
        title="Notifications"
        aria-label="Notifications"
        aria-expanded={open}
        aria-haspopup="true"
      >
        <IconBell width={18} height={18} />
        {total > 0 && (
          <span
            style={{
              position: 'absolute',
              top: -4,
              right: -4,
              minWidth: 17,
              height: 17,
              padding: '0 4px',
              background: 'var(--primary)',
              color: '#fff',
              borderRadius: 'var(--radius-pill)',
              fontSize: 'var(--text-xs)',
              fontWeight: 700,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              border: '2px solid var(--navy)',
            }}
          >
            {total > 99 ? '99+' : total}
          </span>
        )}
      </button>

      {open && (
        <div
          role="dialog"
          aria-label="Notifications"
          style={{
            position: 'absolute',
            top: 'calc(100% + 8px)',
            right: 0,
            width: 340,
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)',
            boxShadow: 'var(--shadow-md)',
            overflow: 'hidden',
            zIndex: 999,
            animation: 'fadeIn 0.15s ease',
          }}
        >
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-light)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ fontWeight: 600, fontSize: 'var(--text-md)', color: 'var(--text-primary)' }}>Notifications</div>
            <span style={{ fontSize: 'var(--text-xs)', color: unknown ? 'var(--unmeasured)' : 'var(--text-muted)' }}>
              {unknown ? 'count unavailable' : loadFailed ? total + ' open (may be stale)' : total + ' open'}
            </span>
          </div>
          {unknown ? (
            <div style={{ padding: '24px 16px', textAlign: 'center', fontSize: 'var(--text-base)', color: 'var(--unmeasured)' }}>
              Could not check for alerts — retry shortly.
              <div style={{ fontSize: 'var(--text-xs)', marginTop: 4 }}>
                This is not a statement that nothing needs attention.
              </div>
            </div>
          ) : summary.items && summary.items.length > 0 ? (
            <div style={{ maxHeight: 320, overflow: 'auto' }}>
              {/* ⛔ A LINK, NOT A `<div onClick>`. Every row navigates to
                  item.href, and as a bare div with no role, no tabIndex and no
                  key handler these per-alert deep links were MOUSE-ONLY (WCAG
                  2.1.1, Level A) on all 30 dashboard pages — the bell is in the
                  shared header.
                  ⛔ The fix is the right ELEMENT rather than role="button" plus
                  tabIndex plus an onKeyDown, because this is a navigation: an
                  anchor brings keyboard activation, a focus ring, the correct
                  announced role, the href in the status bar and middle-click /
                  open-in-new-tab with nothing to maintain. Bolting three
                  attributes onto a div reimplements half of that and still
                  cannot be opened in a new tab. JobCentre's rows next door are
                  already <Link>. */}
              {summary.items.map((item, i) => (
                <Link
                  key={`${item.type}-${i}`}
                  href={item.href}
                  onClick={() => setOpen(false)}
                  style={{ padding: '10px 16px', borderBottom: '1px solid var(--border-light)', display: 'flex', gap: 10, textDecoration: 'none', color: 'inherit' }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-subtle)')}
                  onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--bg-card)')}
                >
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: TYPE_DOT_COLOR[item.type] || 'var(--text-muted)', marginTop: 5, flexShrink: 0 }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', lineHeight: 1.4 }}>{item.label}</div>
                    <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>{formatWhen(item.occurredAt)}</div>
                  </div>
                </Link>
              ))}
            </div>
          ) : (
            <div style={{ padding: '24px 16px', textAlign: 'center', fontSize: 'var(--text-base)', color: 'var(--green)', fontWeight: 500 }}>
              Nothing needs attention
            </div>
          )}
          {/* Also a navigation, so also a Link. It was a <button> calling
              router.push, which IS keyboard-reachable — so unlike the rows above
              this was not an access failure — but it announced as a button, could
              not be opened in a new tab, and was the last thing keeping useRouter
              in this file. One mechanism for every navigation in the panel. */}
          <Link
            href="/alerts"
            onClick={() => setOpen(false)}
            style={{ display: 'block', width: '100%', padding: '11px 16px', background: 'var(--bg-card)', borderTop: '1px solid var(--border-light)', fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--primary)', textAlign: 'center', textDecoration: 'none' }}
            onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-subtle)')}
            onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--bg-card)')}
          >
            View All Alerts &rarr;
          </Link>
        </div>
      )}
    </div>
  );
}
