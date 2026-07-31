'use client';

import { useState, useMemo } from 'react';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';

// Live per-user active VPN session table (ManageEngine "Active VPN Users"
// equivalent), fed by vpn_active_sessions (see lib/engines/vpnSessions.js) —
// the per-user detail the management-plane commands already return, NOT syslog.
// A busy remote-access firewall can have hundreds of concurrent users, so this
// is a client component with a search box + pagination rather than one endless
// scroll. The page (a server component) queries the rows and passes them in as
// a plain-object prop.

const PAGE_SIZE = 25;

function formatDuration(seconds) {
  if (seconds == null) return '—';
  const s = Number(seconds);
  if (!Number.isFinite(s) || s < 0) return '—';
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return `${s}s`;
}

function formatBytes(n) {
  if (n == null) return null;
  const b = Number(n);
  if (!Number.isFinite(b) || b < 0) return null;
  if (b < 1024) return `${b} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = b / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v >= 10 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

function dataCell(bytesIn, bytesOut) {
  const din = formatBytes(bytesIn);
  const dout = formatBytes(bytesOut);
  if (din == null && dout == null) return '—';
  return `↓ ${din || '—'} / ↑ ${dout || '—'}`;
}

const SEARCH_FIELDS = ['username', 'source_ip', 'assigned_ip', 'client', 'tunnel_type', 'gateway'];

const PAGER_BTN = {
  fontSize: 'var(--text-sm)',
  padding: '4px 10px',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)',
  background: 'var(--bg-card)',
  color: 'var(--text-primary)',
  cursor: 'pointer',
};

export default function ActiveVpnUsersTable({ sessions }) {
  const all = Array.isArray(sessions) ? sessions : [];
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(0);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return all;
    return all.filter((r) =>
      SEARCH_FIELDS.some((f) => typeof r[f] === 'string' && r[f].toLowerCase().includes(q))
    );
  }, [all, query]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, pageCount - 1);
  const start = currentPage * PAGE_SIZE;
  const visible = filtered.slice(start, start + PAGE_SIZE);

  function onSearch(e) {
    setQuery(e.target.value);
    setPage(0);
  }

  return (
    <div>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 12,
          flexWrap: 'wrap',
          marginBottom: 8,
        }}
      >
        <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)' }}>
          Active VPN Users ({all.length})
        </div>
        {all.length > 0 && (
          <input
            type="text"
            value={query}
            onChange={onSearch}
            placeholder="Search user, IP, client…"
            className="input"
            style={{ width: 'auto', minWidth: 220, maxWidth: '100%' }}
            aria-label="Search active VPN users"
          />
        )}
      </div>

      {all.length === 0 ? (
        <EmptyState message="No users currently connected — or live per-user detail isn't available for this device/vendor yet (only the session count is collected there)." />
      ) : filtered.length === 0 ? (
        <EmptyState message={`No active users match "${query}".`} />
      ) : (
        <>
          <Table>
            <colgroup>
              <col style={{ width: '16%' }} />
              <col style={{ width: '10%' }} />
              <col style={{ width: '13%' }} />
              <col style={{ width: '13%' }} />
              <col style={{ width: '14%' }} />
              <col style={{ width: '8%' }} />
              <col style={{ width: '14%' }} />
              <col style={{ width: '12%' }} />
            </colgroup>
            <thead>
              <tr>
                <th>User</th>
                <th>Tunnel</th>
                <th>Source IP</th>
                <th>Assigned IP</th>
                <th>Login Time</th>
                <th>Duration</th>
                <th>Data</th>
                <th>Client</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((r, i) => (
                <tr key={start + i}>
                  <td className="mono" title={r.username || ''} style={{ wordBreak: 'break-word' }}>
                    {r.username || '—'}
                  </td>
                  <td>{r.tunnel_type ? <Badge color="info">{r.tunnel_type}</Badge> : '—'}</td>
                  <td className="mono">{r.source_ip || '—'}</td>
                  <td className="mono">{r.assigned_ip || '—'}</td>
                  <td className="mono" title={r.login_time || ''}>
                    {r.login_time || '—'}
                  </td>
                  <td>{formatDuration(r.duration_seconds)}</td>
                  <td className="mono" style={{ whiteSpace: 'normal' }}>
                    {dataCell(r.bytes_in, r.bytes_out)}
                  </td>
                  <td title={r.client || ''} style={{ wordBreak: 'break-word' }}>
                    {r.client || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 12,
              flexWrap: 'wrap',
              marginTop: 8,
            }}
          >
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              Showing {start + 1}–{start + visible.length} of {filtered.length}
              {filtered.length !== all.length ? ` (filtered from ${all.length})` : ''}
            </span>
            {pageCount > 1 && (
              <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <button
                  type="button"
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={currentPage === 0}
                  style={{ ...PAGER_BTN, opacity: currentPage === 0 ? 0.5 : 1 }}
                >
                  ← Prev
                </button>
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                  Page {currentPage + 1} / {pageCount}
                </span>
                <button
                  type="button"
                  onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
                  disabled={currentPage >= pageCount - 1}
                  style={{ ...PAGER_BTN, opacity: currentPage >= pageCount - 1 ? 0.5 : 1 }}
                >
                  Next →
                </button>
              </span>
            )}
          </div>
        </>
      )}
    </div>
  );
}
