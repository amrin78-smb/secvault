'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';

/**
 * Named filter/column/sort states for one table.
 *
 * ⛔ THE URL IS THE STATE. Every table in this app already encodes its filters,
 * sort and page in the query string — which is why a view can be pasted into a
 * ticket at all. So a saved view stores the QUERY STRING verbatim and restores
 * it by navigating. It never parses, normalises or reconstructs the filters.
 *
 * That is the whole design, and it is deliberate: a parser would need updating
 * every time a page adds a filter, and until someone remembered to update it,
 * a saved view would silently restore a DIFFERENT set of rows than the one that
 * was saved. On a security product, a filter that quietly drops a condition is
 * how a critical finding stops being on screen. Storing the string cannot do
 * that.
 *
 * @param {string} scope  Which table these views belong to ('devices', 'rules', ...).
 */
export default function SavedViews({ scope, label = 'View' }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const [views, setViews] = useState([]);
  const [canSave, setCanSave] = useState(false);
  const [open, setOpen] = useState(false);
  const [naming, setNaming] = useState(false);
  const [name, setName] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const wrapRef = useRef(null);
  const mountedRef = useRef(true);

  const currentQuery = searchParams.toString();

  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  const load = useCallback(async () => {
    try {
      const res = await fetch(`/api/saved-views?scope=${encodeURIComponent(scope)}`);
      const data = await res.json();
      if (!mountedRef.current) return;
      setViews(Array.isArray(data.views) ? data.views : []);
      // ⛔ An LDAP session authenticates fine but has no `users` row to own a
      // view. The API says so via canSave rather than erroring, and the control
      // hides the save action instead of offering a button that always fails.
      setCanSave(Boolean(data.canSave));
    } catch (_err) {
      if (mountedRef.current) setViews([]);
    }
  }, [scope]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    function onClickOutside(e) {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) {
        setOpen(false);
        setNaming(false);
        setError(null);
      }
    }
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, []);

  function apply(view) {
    setOpen(false);
    router.push(view.query ? `${pathname}?${view.query}` : pathname);
  }

  async function save() {
    const trimmed = name.trim();
    if (!trimmed) { setError('Give the view a name.'); return; }
    setBusy(true);
    setError(null);
    try {
      const res = await fetch('/api/saved-views', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scope, name: trimmed, query: currentQuery }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Could not save the view.');
      setName('');
      setNaming(false);
      await load();
    } catch (err) {
      if (mountedRef.current) setError(err.message);
    } finally {
      if (mountedRef.current) setBusy(false);
    }
  }

  async function remove(id) {
    setBusy(true);
    try {
      await fetch(`/api/saved-views/${id}`, { method: 'DELETE' });
      await load();
    } finally {
      if (mountedRef.current) setBusy(false);
    }
  }

  const activeView = views.find((v) => v.query === currentQuery);

  return (
    <div ref={wrapRef} style={{ position: 'relative', display: 'inline-block' }}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="btn btn-secondary"
        style={{ fontSize: 'var(--text-sm)', whiteSpace: 'nowrap' }}
      >
        {label}: {activeView ? activeView.name : 'Current filters'} ▾
      </button>

      {open && (
        <div
          style={{
            position: 'absolute',
            top: 'calc(100% + 6px)',
            right: 0,
            zIndex: 40,
            minWidth: 260,
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            boxShadow: 'var(--shadow-lg)',
            padding: 'var(--s2) 0',
          }}
        >
          {views.length === 0 ? (
            <div
              style={{
                padding: 'var(--s3) var(--s4)',
                fontSize: 'var(--text-sm)',
                color: 'var(--text-muted)',
              }}
            >
              No saved views yet.
            </div>
          ) : (
            views.map((v) => (
              <div
                key={v.id}
                style={{ display: 'flex', alignItems: 'center', gap: 'var(--s2)', padding: '0 var(--s2)' }}
              >
                <button
                  type="button"
                  onClick={() => apply(v)}
                  style={{
                    flex: 1,
                    textAlign: 'left',
                    background: 'transparent',
                    border: 'none',
                    cursor: 'pointer',
                    padding: 'var(--s2) var(--s2)',
                    borderRadius: 'var(--radius-sm)',
                    font: 'inherit',
                    fontSize: 'var(--text-sm)',
                    color: 'var(--text-primary)',
                  }}
                >
                  {v.name}
                  {v.shared && !v.owned && (
                    <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}> · shared</span>
                  )}
                </button>
                {/* Only the owner sees a delete: a shared view is visible to
                    everyone and removable only by whoever made it. The server
                    enforces this in the DELETE's own WHERE clause; this is
                    defence in depth, not the control. */}
                {v.owned && (
                  <button
                    type="button"
                    onClick={() => remove(v.id)}
                    disabled={busy}
                    aria-label={`Delete view ${v.name}`}
                    title="Delete this view"
                    style={{
                      background: 'transparent',
                      border: 'none',
                      cursor: 'pointer',
                      color: 'var(--text-muted)',
                      fontSize: 'var(--text-sm)',
                      padding: '0 var(--s2)',
                    }}
                  >
                    ×
                  </button>
                )}
              </div>
            ))
          )}

          {canSave && (
            <div style={{ borderTop: '1px solid var(--border-light)', marginTop: 'var(--s2)', padding: 'var(--s3) var(--s4)' }}>
              {naming ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
                  <input
                    className="input"
                    autoFocus
                    value={name}
                    maxLength={60}
                    placeholder="Name this view"
                    onChange={(e) => setName(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') save(); }}
                    style={{ fontSize: 'var(--text-sm)' }}
                  />
                  {error && (
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--red)' }}>{error}</span>
                  )}
                  <div style={{ display: 'flex', gap: 'var(--s2)' }}>
                    <button type="button" className="btn btn-primary" disabled={busy} onClick={save} style={{ fontSize: 'var(--text-sm)' }}>
                      Save
                    </button>
                    <button type="button" className="btn btn-secondary" onClick={() => { setNaming(false); setError(null); }} style={{ fontSize: 'var(--text-sm)' }}>
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <button
                  type="button"
                  onClick={() => setNaming(true)}
                  className="btn btn-secondary"
                  style={{ width: '100%', fontSize: 'var(--text-sm)' }}
                >
                  Save current filters as a view
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
