import Link from 'next/link';
import { pool } from '../../../lib/db';
import PageHeader from '../../../components/ui/PageHeader';
import Table from '../../../components/ui/Table';
import Badge from '../../../components/ui/Badge';
import EmptyState from '../../../components/ui/EmptyState';
import Pagination from '../../../components/ui/Pagination';
import { resolvePage, pageWindow, DEFAULT_PAGE_SIZE } from '../../../lib/pagination';
import { summarizeVpnConfig } from '../../../lib/engines/vpnSummary';
import VpnSyslogActivity from '../../../components/vpn/VpnSyslogActivity';
import TabBar from '../../../components/ui/TabBar';
import { FLEET_VPN_TABS, resolveFleetVpnTab, buildVpnTabHrefs } from '../../../lib/vpnTabs';

export const dynamic = 'force-dynamic';

// Fleet-wide VPN exposure view. ⛔ THREE DIFFERENT VPN ANSWERS live on this
// page and must not be conflated:
//
//   1. CONFIG-derived (the table below, vpnSummary.js) — "is VPN configured
//      and enabled here", from device_configs.config_parsed.
//   2. SESSION counts (vpn_session_snapshots) — "how many are connected right
//      now", Fortinet API only.
//   3. LOG activity (VpnSyslogActivity, added 2026-09-08) — "what actually
//      happened", from syslog. This is the only one that covers Palo Alto.
//
// This comment previously said real usage data "needs syslog ingestion this
// app doesn't have yet". That stopped being true when services/collector.js
// shipped, and a stale caveat is worse than none: it would send the next
// reader looking for data that is now sitting right above the table.
//
// Server component queries the DB directly, same convention as every other
// fleet-wide page in this app (compliance/page.js, alerts/page.js).
//
// ── PAGINATION ────────────────────────────────────────────────────────────
// TWO independently paged lists live on this URL, so they get separate params:
// `?page=` drives the fleet status table below, `?evPage=` drives
// VpnSyslogActivity's event table. Sharing one param would mean paging the
// events silently repaginated the fleet table underneath it — see
// components/ui/Pagination's `paramName` note.
//
// Both use the shared lib/pagination.js helpers + components/ui/Pagination
// (server-rendered links, so a page survives AutoRefresh's router.refresh() and
// is pasteable into a ticket — client state would not be). Here the window is
// applied in SQL, not by slicing an already-fetched array: the two follow-up
// queries below fetch config and session rows PER DEVICE ON THIS PAGE, so
// paging bounds the work done rather than just what is drawn.

const PAGE_SIZE = DEFAULT_PAGE_SIZE;

async function countActiveDevices(dbPool) {
  const { rows } = await dbPool.query('SELECT count(*)::int AS total FROM devices WHERE active = true');
  return rows[0] ? rows[0].total : 0;
}

// One row per active device on the requested page: latest config_parsed (for
// the VPN summary) + latest vpn_session_snapshots.active_session_count (if this
// device's adapter supports session polling — currently Fortinet only). Two
// separate DISTINCT ON lookups rather than a single query with window
// functions — clearer to read, and this is a page of rows, not millions.
async function getFleetVpnStatus(dbPool, limit, offset) {
  const { rows: devices } = await dbPool.query(
    `SELECT id AS device_id, name AS device_name, vendor
     FROM devices
     WHERE active = true
     ORDER BY name ASC
     LIMIT $1 OFFSET $2`,
    [limit, offset]
  );

  // A page past the end of the table is possible (a device was deactivated
  // between the count and the fetch); returning [] here is correct — it means
  // "no rows on this page", not "no devices", and the count above is what the
  // pager reports.
  if (devices.length === 0) return [];

  const ids = devices.map((d) => d.device_id);

  const { rows: configRows } = await dbPool.query(
    `SELECT DISTINCT ON (device_id) device_id, config_parsed, collected_at
     FROM device_configs
     WHERE device_id = ANY($1::uuid[])
     ORDER BY device_id, collected_at DESC`,
    [ids]
  );
  const configByDevice = new Map(configRows.map((r) => [r.device_id, r]));

  const { rows: sessionRows } = await dbPool.query(
    `SELECT DISTINCT ON (device_id) device_id, active_session_count, sampled_at
     FROM vpn_session_snapshots
     WHERE device_id = ANY($1::uuid[])
     ORDER BY device_id, sampled_at DESC`,
    [ids]
  );
  const sessionByDevice = new Map(sessionRows.map((r) => [r.device_id, r]));

  return devices.map((d) => {
    const configRow = configByDevice.get(d.device_id);
    const summary = summarizeVpnConfig(d.vendor, configRow ? configRow.config_parsed : null);
    const session = sessionByDevice.get(d.device_id);
    return {
      ...d,
      summary,
      lastConfigAt: configRow ? configRow.collected_at : null,
      activeSessionCount: session ? session.active_session_count : null,
      sessionSampledAt: session ? session.sampled_at : null,
    };
  });
}

function formatDateTime(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

function statusBadge(summary) {
  if (!summary.supported) return <Badge color="muted">Not supported</Badge>;
  if (!summary.hasConfig) return <Badge color="muted">No VPN config</Badge>;
  if (summary.enabled === true) return <Badge color="success">Enabled</Badge>;
  if (summary.enabled === false) return <Badge color="muted">Disabled</Badge>;
  // enabled === null/undefined (Sangfor's tri-state, or a vendor like
  // Fortinet/Palo Alto whose config was found but this module doesn't infer
  // a confident on/off state for — see vpnSummary.js's own comments).
  return <Badge color="warning">Configured (state unknown)</Badge>;
}

export default async function VpnFleetPage({ searchParams }) {
  const sp = searchParams || {};
  const tab = resolveFleetVpnTab(sp.vtab);
  const { tabs, activeHref } = buildVpnTabHrefs(
    '/vpn', FLEET_VPN_TABS, sp, tab, ['page', 'evPage']
  );

  // ⛔ Only the ACTIVE tab queries. The log-activity view costs ~7s on a
  // COLD cache, and it is always cold: a 26 GB/day ingest evicts those rows
  // from a 4 GB buffer pool long before anyone next opens this page. Running
  // it unconditionally made every visit pay that, even to read the config
  // table. Same reasoning as the dashboard rendering only its active tab.
  const showStatus = tab === 'status';

  const total = showStatus ? await countActiveDevices(pool) : 0;
  // pageWindow clamps a past-the-end `?page=` to the LAST page rather than
  // rendering an empty table, which would read as "there are no devices".
  const win = pageWindow(resolvePage(sp.page), PAGE_SIZE, total);
  const devices = showStatus ? await getFleetVpnStatus(pool, win.limit, win.offset) : [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <PageHeader
        title="VPN"
        subtitle="Fleet-wide VPN/remote-access exposure, derived from each device's latest collected config."
        actions={
          <a href="/api/vpn/fleet?format=csv" className="btn btn-secondary">
            Export CSV
          </a>
        }
      />

      <TabBar tabs={tabs} activeHref={activeHref} ariaLabel="VPN views" />

      {tab === 'activity' && (
        /* Log-observed activity: the only VPN view that reflects what
           actually happened, and the only one covering Palo Alto. It pages on
           its OWN param (`?evPage=`) so it cannot move in step with the
           config table -- see components/ui/Pagination's paramName note. */
        <VpnSyslogActivity searchParams={sp} page={sp.evPage} />
      )}

      {showStatus && (total === 0 ? (
        <EmptyState message="No active devices." />
      ) : (
        <>
          <Table>
            <colgroup>
              <col style={{ width: '22%' }} />
              <col style={{ width: '12%' }} />
              <col style={{ width: '22%' }} />
              <col style={{ width: '16%' }} />
              <col style={{ width: '14%' }} />
              <col style={{ width: '14%' }} />
            </colgroup>
            <thead>
              <tr>
                <th>Device</th>
                <th>Vendor</th>
                <th>VPN Status</th>
                <th>Config as of</th>
                <th>Active Sessions</th>
                <th>Sampled</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.device_id}>
                  <td title={d.device_name}>
                    <Link href={`/devices/${d.device_id}/vpn`} className="link-quiet">
                      {d.device_name}
                    </Link>
                  </td>
                  <td>
                    <Badge color="info">{d.vendor}</Badge>
                  </td>
                  <td>{statusBadge(d.summary)}</td>
                  <td style={{ color: 'var(--text-secondary)' }}>{formatDateTime(d.lastConfigAt)}</td>
                  <td style={{ color: 'var(--text-secondary)' }}>
                    {/* ⛔ null = this vendor/adapter does not poll sessions at
                        all. A 0 would claim nobody is connected. */}
                    {d.activeSessionCount === null ? '—' : d.activeSessionCount}
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }}>{formatDateTime(d.sessionSampledAt)}</td>
                </tr>
              ))}
            </tbody>
          </Table>

          <Pagination
            basePath="/vpn"
            searchParams={sp}
            page={win.page}
            pageSize={win.pageSize}
            total={total}
            label="active devices"
          />
        </>
      ))}
    </div>
  );
}
