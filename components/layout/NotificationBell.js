'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
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
  const router = useRouter();
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
      <button
        type="button"
        className={`sv-icon-btn${open ? ' open' : ''}`}
        onClick={() => setOpen((o) => !o)}
        title="Notifications"
        aria-label="Notifications"
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
              {summary.items.map((item, i) => (
                <div
                  key={`${item.type}-${i}`}
                  onClick={() => {
                    setOpen(false);
                    router.push(item.href);
                  }}
                  style={{ padding: '10px 16px', borderBottom: '1px solid var(--border-light)', cursor: 'pointer', display: 'flex', gap: 10 }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-subtle)')}
                  onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--bg-card)')}
                >
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: TYPE_DOT_COLOR[item.type] || 'var(--text-muted)', marginTop: 5, flexShrink: 0 }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', lineHeight: 1.4 }}>{item.label}</div>
                    <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>{formatWhen(item.occurredAt)}</div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ padding: '24px 16px', textAlign: 'center', fontSize: 'var(--text-base)', color: 'var(--green)', fontWeight: 500 }}>
              Nothing needs attention
            </div>
          )}
          <button
            type="button"
            onClick={() => {
              setOpen(false);
              router.push('/alerts');
            }}
            style={{ width: '100%', padding: '11px 16px', background: 'var(--bg-card)', border: 'none', borderTop: '1px solid var(--border-light)', cursor: 'pointer', fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--primary)', textAlign: 'center' }}
            onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-subtle)')}
            onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--bg-card)')}
          >
            View All Alerts &rarr;
          </button>
        </div>
      )}
    </div>
  );
}
