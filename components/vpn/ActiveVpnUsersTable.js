import Link from 'next/link';
import Table from '../ui/Table';
import NotMeasured from '../ui/NotMeasured';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';
import Pagination from '../ui/Pagination';
import { paginateArray, buildPageHref } from '../../lib/pagination';

// Live per-user active VPN session table (ManageEngine "Active VPN Users"
// equivalent), fed by vpn_active_sessions (see lib/engines/vpnSessions.js) —
// the per-user detail the management-plane commands already return, NOT syslog.
//
// ⛔ SERVER component (it was a client component until 2026-09-08, and the
// change is the point). A busy remote-access firewall carries hundreds of
// concurrent users, so this needs both a filter and paging — but both used to
// live in useState, which meant every AutoRefresh/router.refresh() silently
// threw the operator back to page 1 of an unfiltered list, mid-read. Both now
// live in the URL (`?vpnq=` and `?page=`), the same server-driven convention as
// /logs' search form and TabBar's `?view=`: refresh-proof, linkable into a
// ticket, and no client JS at all. The search box is a plain GET <form> whose
// only job is to rewrite the query string.
//
// This table keeps the plain `?page=` param as the page's principal list;
// IpsecTunnelsTable below it uses `?tunnelPage=` so the two never move
// together (see components/ui/Pagination's `paramName` note).
//
// Paging is paginateArray() rather than SQL LIMIT/OFFSET because these rows are
// not a table read — getVpnSessions() returns an already-assembled snapshot for
// one device, and the free-text filter is applied over the whole set before the
// window is taken (filtering only the visible page would silently search 25 of
// 300 users and report "no match" for someone who is connected).

// Deliberately 25, not lib/pagination's DEFAULT_PAGE_SIZE of 50: this is a
// dense eight-column table and 25 was the size the original client-side pager
// used, so the change of mechanism does not also change what a page looks like.
const PAGE_SIZE = 25;

const SEARCH_FIELDS = ['username', 'source_ip', 'assigned_ip', 'client', 'tunnel_type', 'gateway'];

// ⛔ Every absent value on this table goes through NotMeasured WITH A REASON,
// never a bare em-dash. A dash on its own leaves the reader unable to tell
// whether the firewall does not report the field or SecVault failed to read it
// — which is the whole distinction this table exists to preserve (see
// components/ui/NotMeasured.js).
function formatDuration(seconds) {
  if (seconds == null) {
    return <NotMeasured reason="This vendor does not report a session duration for this tunnel type." />;
  }
  const s = Number(seconds);
  if (!Number.isFinite(s) || s < 0) {
    return <NotMeasured reason="The device reported a duration this app could not parse." />;
  }
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

// ⛔ Tri-state: a vendor that does not report per-session byte counters gets a
// NotMeasured marker, never "0 B" — "we did not measure" must not render as
// "this user moved no data".
function dataCell(bytesIn, bytesOut) {
  const din = formatBytes(bytesIn);
  const dout = formatBytes(bytesOut);
  if (din == null && dout == null) {
    return (
      <NotMeasured reason="This vendor does not report per-session byte counters. Not the same as this user moving no data." />
    );
  }
  return (
    <>
      &darr;{' '}
      {din == null ? <NotMeasured reason="No inbound counter reported for this session." /> : din} /
      &uarr;{' '}
      {dout == null ? <NotMeasured reason="No outbound counter reported for this session." /> : dout}
    </>
  );
}

function matches(row, q) {
  return SEARCH_FIELDS.some(
    (f) => typeof row[f] === 'string' && row[f].toLowerCase().includes(q)
  );
}

/**
 * @param {object[]} sessions      every active session for this device
 * @param {string}   basePath      the page's own path, e.g. `/devices/<id>/vpn`
 * @param {object}   searchParams  the page's searchParams (preserved on paging links)
 * @param {number}   page          1-based page from `?page=`
 * @param {string}   query         free-text filter from `?vpnq=`
 */
export default function ActiveVpnUsersTable({ sessions, basePath, searchParams, page, query }) {
  const all = Array.isArray(sessions) ? sessions : [];
  const sp = searchParams || {};
  const q = String(query || '').trim().toLowerCase();
  const filtered = q ? all.filter((r) => matches(r, q)) : all;
  const win = paginateArray(filtered, page, PAGE_SIZE);

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
          // Plain GET form: no client JS, the URL is the query. It deliberately
          // carries no `page` field, so a new search always lands on page 1
          // instead of page 7 of a set that no longer has seven pages.
          <form
            method="get"
            action={basePath}
            style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}
          >
            <input
              type="text"
              name="vpnq"
              defaultValue={query || ''}
              placeholder="Search user, IP, client…"
              className="input"
              style={{ width: 'auto', minWidth: 220, maxWidth: '100%' }}
              aria-label="Search active VPN users"
            />
            <button type="submit" className="btn btn-secondary">
              Search
            </button>
            {q ? (
              <Link href={buildPageHref(basePath, sp, { vpnq: null, page: null })} className="btn btn-secondary">
                Clear
              </Link>
            ) : null}
          </form>
        )}
      </div>

      {all.length === 0 ? (
        // ⛔ TWO DIFFERENT FACTS, and this component cannot tell them apart.
        // An empty `sessions` array means EITHER a measured zero (the device
        // answered, nobody is connected) OR that this vendor/transport does not
        // return per-user detail at all — only a session count. The caller
        // (app/(dashboard)/devices/[id]/vpn/page.js) knows which, because it
        // knows the adapter; this component is only handed the array. Until it
        // is told, the empty state must state BOTH possibilities rather than
        // pick the reassuring one. Do not "tidy" this into "No users
        // connected." — that is a failed read rendered as an affirmative fact.
        <EmptyState message="Nobody is connected right now — OR live per-user detail is not collected for this device's vendor/transport, which reports only a session count. This view cannot tell those two apart." />
      ) : filtered.length === 0 ? (
        <EmptyState message={`No active users match "${query}".`} />
      ) : (
        <>
          {/* ⛔ Says so when a filter is hiding rows. "3 users" and "3 of 412
              users matching your search" are different answers to "who is
              connected right now". */}
          {q ? (
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginBottom: 6 }}>
              Filtered to {filtered.length.toLocaleString()} of {all.length.toLocaleString()} connected
              users matching “{query}”.
            </div>
          ) : null}

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
              {win.rows.map((r, i) => (
                <tr key={`${win.page}-${i}`}>
                  <td className="mono" title={r.username || ''} style={{ wordBreak: 'break-word' }}>
                    {/* ⛔ An anonymous session is a real gap in what the device
                        tells us, not an empty string. Each of these says which
                        field the firewall withheld. */}
                    {r.username || (
                      <NotMeasured reason="This session carries no username — the device did not report one." />
                    )}
                  </td>
                  <td>
                    {r.tunnel_type ? (
                      <Badge color="info">{r.tunnel_type}</Badge>
                    ) : (
                      <NotMeasured reason="The device did not report a tunnel type for this session." />
                    )}
                  </td>
                  <td className="mono">
                    {r.source_ip || (
                      <NotMeasured reason="The device did not report a client source address for this session." />
                    )}
                  </td>
                  <td className="mono">
                    {r.assigned_ip || (
                      <NotMeasured reason="The device did not report an assigned tunnel address for this session." />
                    )}
                  </td>
                  <td className="mono" title={r.login_time || ''}>
                    {r.login_time || (
                      <NotMeasured reason="The device did not report a login time for this session." />
                    )}
                  </td>
                  <td>{formatDuration(r.duration_seconds)}</td>
                  <td className="mono" style={{ whiteSpace: 'normal' }}>
                    {dataCell(r.bytes_in, r.bytes_out)}
                  </td>
                  <td title={r.client || ''} style={{ wordBreak: 'break-word' }}>
                    {r.client || (
                      <NotMeasured reason="The device did not report a client/agent string for this session." />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>

          {/* Total is the FILTERED count, which is what the rows on screen are
              drawn from; the unfiltered total is stated in the notice above so
              neither number stands alone pretending to be the other. */}
          <Pagination
            basePath={basePath}
            searchParams={sp}
            page={win.page}
            pageSize={win.pageSize}
            total={win.total}
            label={q ? 'matching users' : 'connected users'}
          />
        </>
      )}
    </div>
  );
}
