'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { IconSearch } from '../icons';

// Centered header search — debounced, "/" keyboard shortcut, hits
// GET /api/search (devices + advisories). Matches the suite's GlobalSearch
// convention (see DDIVault/NetVault's own component).
export default function HeaderSearch() {
  const router = useRouter();
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState({ devices: [], advisories: [] });
  const inputRef = useRef(null);
  const wrapRef = useRef(null);
  const debounceRef = useRef(null);

  useEffect(() => {
    function onKeyDown(e) {
      if (e.key === '/' && document.activeElement !== inputRef.current) {
        const tag = document.activeElement?.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA') return;
        e.preventDefault();
        inputRef.current?.focus();
      }
      if (e.key === 'Escape') {
        setOpen(false);
        inputRef.current?.blur();
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  useEffect(() => {
    function onClickOutside(e) {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, []);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    const q = query.trim();
    if (q.length < 2) {
      setResults({ devices: [], advisories: [] });
      setLoading(false);
      return undefined;
    }
    setLoading(true);
    debounceRef.current = setTimeout(async () => {
      try {
        const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
        const data = await res.json();
        setResults({ devices: data.devices || [], advisories: data.advisories || [] });
      } catch (_err) {
        setResults({ devices: [], advisories: [] });
      } finally {
        setLoading(false);
      }
    }, 250);
    return () => clearTimeout(debounceRef.current);
  }, [query]);

  const hasResults = results.devices.length > 0 || results.advisories.length > 0;

  function go(href) {
    setOpen(false);
    setQuery('');
    router.push(href);
  }

  return (
    <div ref={wrapRef} style={{ position: 'relative', width: '100%', maxWidth: 440 }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          background: 'rgba(255,255,255,0.08)',
          border: '1px solid rgba(255,255,255,0.12)',
          borderRadius: 8,
          padding: '7px 10px',
        }}
      >
        <IconSearch width={15} height={15} style={{ color: 'rgba(255,255,255,0.45)', flexShrink: 0 }} />
        <input
          ref={inputRef}
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onFocus={() => setOpen(true)}
          placeholder="Search devices, CVEs..."
          style={{
            flex: 1,
            background: 'transparent',
            border: 'none',
            outline: 'none',
            color: '#fff',
            fontSize: 'var(--text-base)',
            fontFamily: 'inherit',
            minWidth: 0,
          }}
        />
        {!query && (
          <span className="kbd" style={{ background: 'rgba(255,255,255,0.08)', borderColor: 'rgba(255,255,255,0.14)', color: 'rgba(255,255,255,0.45)' }}>
            /
          </span>
        )}
      </div>

      {open && query.trim().length >= 2 && (
        <div
          style={{
            position: 'absolute',
            top: 'calc(100% + 8px)',
            left: 0,
            right: 0,
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: 6,
            boxShadow: 'var(--shadow-md)',
            overflow: 'hidden',
            zIndex: 999,
            animation: 'fadeIn 0.15s ease',
            maxHeight: 400,
            overflowY: 'auto',
          }}
        >
          {loading ? (
            <div style={{ padding: '16px', fontSize: 'var(--text-base)', color: 'var(--text-muted)', textAlign: 'center' }}>
              Searching...
            </div>
          ) : !hasResults ? (
            <div style={{ padding: '16px', fontSize: 'var(--text-base)', color: 'var(--text-muted)', textAlign: 'center' }}>
              No results for &ldquo;{query}&rdquo;
            </div>
          ) : (
            <>
              {results.devices.length > 0 && (
                <div>
                  <div style={{ padding: '8px 14px 4px', fontSize: 'var(--text-xs)', fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                    Devices
                  </div>
                  {results.devices.map((d) => (
                    <button
                      key={d.id}
                      type="button"
                      onClick={() => go(`/devices/${d.id}`)}
                      style={resultRowStyle}
                      onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-subtle)')}
                      onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                    >
                      <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{d.name}</span>
                      <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                        {d.vendor}
                        {d.site ? ` · ${d.site}` : ''}
                      </span>
                    </button>
                  ))}
                </div>
              )}
              {results.advisories.length > 0 && (
                <div>
                  <div style={{ padding: '8px 14px 4px', fontSize: 'var(--text-xs)', fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                    Advisories
                  </div>
                  {results.advisories.map((a) => (
                    <button
                      key={a.cve_id}
                      type="button"
                      onClick={() => go(`/advisories/${encodeURIComponent(a.cve_id)}`)}
                      style={resultRowStyle}
                      onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-subtle)')}
                      onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                    >
                      <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>
                        {a.cve_id} {a.kev_listed ? <span className="badge badge-red" style={{ marginLeft: 6 }}>KEV</span> : null}
                      </span>
                      <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {a.title || a.vendor}
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

const resultRowStyle = {
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'flex-start',
  gap: 1,
  width: '100%',
  padding: '8px 14px',
  background: 'transparent',
  border: 'none',
  borderBottom: '1px solid var(--border-light)',
  cursor: 'pointer',
  textAlign: 'left',
  transition: 'background 0.1s',
};
