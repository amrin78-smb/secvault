'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { IconSearch } from '../icons';
import { NAV } from './Sidebar';
import { SETTINGS_TABS } from '../../lib/settingsTabs';

// ⛔ ONE SEARCH SURFACE, NOT TWO. The redesign called for a ⌘K command
// palette, and the cheapest way to get one wrong is to add a second
// overlay beside a search box that already works. This component already
// had debouncing, a stale-response guard and a "/" shortcut, so ⌘K became
// another way in rather than another thing to build.
//
// PAGES are matched client-side against the nav list — no API call, no
// round trip, and it stays correct automatically when a nav label is
// renamed, which just happened in Phase 2.
//
// `keywords` carry the OLD names and the words an operator would actually
// type. Someone who has used this product for a year will type "devices"
// long after the label became "Firewalls", and a palette that answers
// "no results" to the product’s own former vocabulary is worse than no
// palette. Same reasoning for "cve" -> Vulnerabilities.
const PAGE_KEYWORDS = {
  '/': ['dashboard', 'home', 'overview', 'summary'],
  '/alerts': ['notifications', 'events'],
  '/logs': ['syslog', 'search logs', 'traffic', 'events'],
  '/devices': ['devices', 'firewalls', 'inventory', 'fleet'],
  '/topology': ['map', 'network', 'path', 'route'],
  '/lifecycle': ['licences', 'licenses', 'support', 'expiry', 'ha', 'disk'],
  '/vulnerability': ['cve', 'cves', 'advisories', 'patch', 'vulnerability'],
  '/exposure': ['attack surface', 'internet facing', 'internet exposure', 'exposed'],
  '/analysis': ['rule analysis', 'rules', 'hygiene', 'shadow', 'unused'],
  '/compliance': ['audit', 'pci', 'iso', 'cis', 'nist', 'benchmark'],
  '/vpn': ['vpn', 'remote access', 'tunnel', 'users', 'identity'],
  '/settings': ['config', 'preferences', 'admin', 'notifications', 'appearance'],
  // Four pages shipped without keywords and were reachable only by typing their
  // exact label. ⛔ These carry the OLD vocabulary too, on purpose and for the
  // same reason the comment above the nav gives: someone who has used this for
  // a year types what they used to call the thing, and a palette that answers
  // "no results" to the product's own former words is worse than none. So
  // "cloud"/"office 365" find Applications, and "queue"/"todo" find Work.
  '/work': ['work queue', 'queue', 'todo', 'to do', 'outstanding', 'backlog'],
  // ⛔ TWO MORE PAGES SHIPPED WITHOUT KEYWORDS (found 2026-09-29 by
  // tests/navigation.test.js, which now fails the build on any registry entry
  // that has none). Same defect the four above had: reachable only by typing
  // the exact label, which is the one word an operator is least likely to
  // guess for a page they have never opened.
  '/coverage': ['coverage', 'blind spot', 'blind spots', 'gaps', 'not measured',
    'unmeasured', 'visibility'],
  '/conformance': ['conformance', 'odd one out', 'drift', 'deviation', 'outlier',
    'consistency', 'peers'],
  '/reports': ['report', 'reports', 'pdf', 'export', 'download', 'audit report'],
  // ⛔ BOTH ENTRIES SURVIVE THE SIDEBAR MERGE (2026-09-29). These two now share
  // ONE rendered nav entry, labelled "Intent" — but matchPages() filters over
  // NAV, so if the Applications item had been deleted rather than marked
  // `navHidden`, every keyword below it would have started answering "no
  // results". The label is no longer the word anyone types for either page,
  // which makes these keywords load-bearing rather than a convenience.
  '/segmentation': ['segmentation', 'zones', 'intent', 'east-west', 'boundary'],
  '/applications': ['applications', 'apps', 'flows', 'declared', 'cloud',
    'office 365', 'microsoft 365', 'saas', 'intent'],
};

// ⛔ SETTINGS TABS ARE DESTINATIONS TOO (v2.221.0). Measured: "password",
// "theme", "dark mode" and "sso" all answered NO RESULTS, and "users" matched
// /vpn — because the palette only knew about the eleven NAV entries, and
// Settings is eleven more destinations behind one of them. "Where do I change
// my password" is exactly the question a command palette exists for.
//
// ⛔ DERIVED FROM lib/settingsTabs.js, never a second list. A copy would go
// stale the first time a tab is renamed, and the palette would answer "no
// results" for a tab that works — the failure mode NAV's own comment warns
// about three lines up.
//
// ⛔ GATED TABS ARE INCLUDED, following the SAME decision NAV already records
// for capability-gated pages: the palette aids discovery and the route itself
// refuses. Excluding them would mean maintaining a capability check in a
// client component that cannot be the boundary anyway.
const SETTINGS_KEYWORDS = {
  general: ['appearance', 'theme', 'dark mode', 'light mode', 'density', 'corners'],
  security: ['password', 'change password', 'mfa', 'two-factor', '2fa', 'totp',
    'authenticator', 'my account', 'session', 'timeout', 'idle'],
  users: ['users', 'accounts', 'roles', 'rbac', 'permissions'],
  signon: ['sso', 'single sign-on', 'entra', 'azure', 'ldap', 'directory', 'saml', 'oidc'],
  profiles: ['credentials', 'credential profiles', 'secrets'],
  notifications: ['notifications', 'slack', 'teams', 'email', 'webhook', 'alerting'],
  certificate: ['certificate', 'tls', 'https', 'ssl', 'console address'],
  feeds: ['feeds', 'feed sync', 'poll interval', 'nvd'],
  updates: ['update', 'upgrade', 'version'],
  subscription: ['subscription', 'licence', 'license', 'server id', 'renewal', 'trial'],
  about: ['about', 'version'],
};

const SETTINGS_DESTINATIONS = SETTINGS_TABS.map((t) => ({
  href: `/settings?tab=${t.key}`,
  label: `Settings \u203a ${t.label}`,
  keywords: SETTINGS_KEYWORDS[t.key] || [],
}));

function matchPages(q) {
  const needle = q.trim().toLowerCase();
  if (needle.length < 2) return [];
  const pages = NAV.filter(({ href, label }) => {
    if (label.toLowerCase().includes(needle)) return true;
    return (PAGE_KEYWORDS[href] || []).some((k) => k.includes(needle));
  });
  // ⛔ AFTER the pages, never interleaved. A tab inside Settings is a more
  // specific answer than a top-level page, and burying "Vulnerabilities"
  // under four settings tabs for the query "u" would make the palette worse
  // at the thing it is already good at.
  const settings = SETTINGS_DESTINATIONS.filter(({ label, keywords }) =>
    label.toLowerCase().includes(needle) || keywords.some((k) => k.includes(needle)));
  return [...pages, ...settings].slice(0, 6);
}

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
  // Guards against two in-flight requests resolving out of order (the 250ms
  // debounce only limits how often a fetch FIRES, not the order responses
  // ARRIVE back in) and against setting state after unmount. Each fetch
  // captures its own sequence number; a response is only applied if it's
  // still the most recent one issued. Found in the final pre-deploy bug
  // check (2026-07-17).
  const requestSeqRef = useRef(0);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    function onKeyDown(e) {
      // ⌘K on macOS, Ctrl+K elsewhere. Unlike "/", this fires even from
      // inside an input: it is the shortcut people reach for precisely
      // when they are already typing somewhere else and want to leave.
      if ((e.key === 'k' || e.key === 'K') && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
        setOpen(true);
        return;
      }
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
    const mySeq = ++requestSeqRef.current;
    debounceRef.current = setTimeout(async () => {
      try {
        const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
        const data = await res.json();
        if (!mountedRef.current || requestSeqRef.current !== mySeq) return; // stale or unmounted
        // ⛔ res.ok WAS NEVER CHECKED. Both the error body and the thrown case
        // collapsed to empty arrays, which render as "No results for X" — so
        // during a DB problem, exactly when someone is searching in a hurry,
        // the product POSITIVELY STATED that no such firewall exists. A failed
        // search and an empty search are different answers.
        if (!res.ok || !data || data.error) {
          setResults(null);
          return;
        }
        setResults({ devices: data.devices || [], advisories: data.advisories || [] });
      } catch (_err) {
        if (!mountedRef.current || requestSeqRef.current !== mySeq) return;
        setResults(null);
      } finally {
        if (mountedRef.current && requestSeqRef.current === mySeq) setLoading(false);
      }
    }, 250);
    return () => clearTimeout(debounceRef.current);
  }, [query]);

  const pages = matchPages(query);
  // ⛔ results === null means the SEARCH FAILED, not that it was empty. Every
  // read below must tolerate it; the panel renders a distinct 'Search
  // unavailable' branch before any of these are reached.
  const hasResults =
    pages.length > 0 ||
    (results !== null && (results.devices.length > 0 || results.advisories.length > 0));

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
          borderRadius: 'var(--radius)',
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
          placeholder="Search firewalls, CVEs, pages…"
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
            borderRadius: 'var(--radius-sm)',
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
          ) : results === null ? (
            <div style={{ padding: '16px', fontSize: 'var(--text-base)', color: 'var(--unmeasured)', textAlign: 'center' }}>
              Search unavailable
              <div style={{ fontSize: 'var(--text-xs)', marginTop: 4 }}>
                SecVault could not run the search. This does NOT mean there is no match.
              </div>
            </div>
          ) : !hasResults ? (
            <div style={{ padding: '16px', fontSize: 'var(--text-base)', color: 'var(--text-muted)', textAlign: 'center' }}>
              No results for &ldquo;{query}&rdquo;
            </div>
          ) : (
            <>
              {/* Pages first: matched locally, so they are correct
                  instantly while the device/CVE fetch is still in flight. */}
              {pages.length > 0 && (
                <div>
                  <div style={{ padding: '8px 14px 4px', fontSize: 'var(--text-xs)', fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                    Pages
                  </div>
                  {pages.map((p) => (
                    <button
                      key={p.href}
                      type="button"
                      onClick={() => go(p.href)}
                      style={resultRowStyle}
                      onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-subtle)')}
                      onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                    >
                      <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <p.Icon width={14} height={14} />
                        {p.label}
                      </span>
                    </button>
                  ))}
                </div>
              )}
              {results.devices.length > 0 && (
                <div>
                  <div style={{ padding: '8px 14px 4px', fontSize: 'var(--text-xs)', fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                    Firewalls
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
                      onClick={() => go(`/vulnerability/advisories/${encodeURIComponent(a.cve_id)}`)}
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
