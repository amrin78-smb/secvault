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
  const [summary, setSummary] = useState({ total: 0, items: [] });
  const ref = useRef(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const res = await fetch('/api/notifications/summary');
        const data = await res.json();
        if (!cancelled && data && !data.error) setSummary(data);
      } catch (_err) {
        // leave last-known summary in place
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

  const total = summary.total || 0;

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
              borderRadius: 9,
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
            borderRadius: 6,
            boxShadow: 'var(--shadow-md)',
            overflow: 'hidden',
            zIndex: 999,
            animation: 'fadeIn 0.15s ease',
          }}
        >
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-light)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ fontWeight: 600, fontSize: 'var(--text-md)', color: 'var(--text-primary)' }}>Notifications</div>
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{total} open</span>
          </div>
          {summary.items && summary.items.length > 0 ? (
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
            onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--tint-danger)')}
            onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--bg-card)')}
          >
            View All Alerts &rarr;
          </button>
        </div>
      )}
    </div>
  );
}
