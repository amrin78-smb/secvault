import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import NotMeasured from '../ui/NotMeasured';
import IconChip from '../ui/IconChip';
import Pagination from '../ui/Pagination';
import { IconActivity } from '../icons';
import { resolvePage, pageWindow } from '../../lib/pagination';
import {
  getVpnActivityByDeviceRollup,
  getUserCoverageForClass,
} from '../../lib/syslog/trafficStats';

export const dynamic = 'force-dynamic';

// VPN activity OBSERVED IN LOGS, added 2026-09-08 alongside the syslog collector.
//
// This is the third and newest of three different VPN answers SecVault gives,
// and they must not be confused with one another:
//
//   1. CONFIG-derived  (vpnSummary.js)      — "is VPN configured/enabled here"
//   2. SESSION counts  (vpn_session_snapshots) — "how many are connected right
//                                              now", Fortinet API only
//   3. LOG activity    (this component)     — "what actually happened", from
//                                              syslog, and the only one that
//                                              covers Palo Alto
//
// ⛔ Coverage is stated, not implied. Only Palo Alto (GLOBALPROTECT) and
// Fortinet (event/vpn) emit VPN logs in this fleet — verified against real
// captured events, not vendor documentation. A device absent from this list has
// not sent VPN logs, which is NOT the same as "no VPN activity", and the empty
// state says so rather than showing a reassuring zero.
//
// ── WHY THIS RENDERS A TABLE AND NOT A LIST OF RAW LINES ──────────────────
// This block used to print the first 160 characters of each raw syslog line,
// ellipsis-clipped to one row. That is the least readable form of any data
// SecVault holds: a FortiOS VPN line is ~40 key=value pairs, so the only fields
// on screen were whichever ones the vendor happened to emit first. Every field
// an operator actually asks for — who connected, from where, to which firewall,
// and whether it worked — already has its own parsed column on syslog_events
// (src_user / src_ip / action / severity / log_subtype). So the columns come
// from those columns, and the raw line moves behind a per-row <details> toggle:
// still the evidence, no longer the presentation.
//
// ⛔ This table pages on `?evPage=`, NOT `?page=`. /vpn carries two
// independently paged lists (this one and the fleet status table below), and
// the shared Pagination's `paramName` exists precisely so they do not move
// together — clicking "next" here must not silently repaginate a table the
// reader is not looking at. `page` stays with the fleet table, which is the
// page's principal list.
//
// ⛔ OFFSET over a live table is honest about being a moving window: events
// arrive continuously, so page 3 an hour from now is not the same rows as page
// 3 today. That is stated on screen, and /logs?logClass=vpn — which pins an
// explicit time range — is linked as the stable way to look at a fixed window.

const EVENTS_PAGE_SIZE = 25;

// ⛔ DEPTH CAP. Without one this list offered ~1,823 clickable pages of OFFSET
// against the raw partition the collector is writing to at ~1,400 rows/sec.
// Measured on the live database, page 1800 took 13.5 SECONDS and did 18,796
// cold buffer reads — holding a page render that long AND evicting the
// ingest's working set. lib/syslog/logSearch.js caps at MAX_PAGE=200 for
// exactly this reason; the cap simply was not applied here.
//
// Deep history is answered by /logs?logClass=vpn, which is fixed-window and
// index-backed, and the UI says so rather than silently dead-ending.
const MAX_EVENT_PAGES = 40;
const WINDOW_HOURS = 24;
const DEVICE_ROWS = 10;

// RFC 5424 numeric severity -> the word. The index IS the value, so 0 = emergency.
// ⛔ Never rendered as a bare number: "3" and "error" are the same fact, but
// only one of them is readable next to a login failure.
const SEVERITY_WORDS = [
  'emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug',
];

// ⛔ Outcome tone, not activity tone. A `tunnel-down` or a `logout` is the
// NORMAL end of a session, not a failure — colouring every non-"up" action red
// would paint an ordinary working day as an incident and train the operator to
// ignore the colour entirely. Only a real failure is danger; an ordinary close
// is muted; only a confirmed establish is success.
const OPEN_ACTIONS = new Set([
  'tunnel-up', 'ssl-new-con', 'ssl-login', 'login', 'auth-success', 'tunnel-connect',
]);
const CLOSE_ACTIONS = new Set([
  'tunnel-down', 'tunnel-stats', 'ssl-exit', 'logout', 'close', 'ssl-logout',
]);
const FAILURE_HINTS = ['fail', 'denied', 'deny', 'reject', 'error', 'invalid', 'timeout'];

// Vendor CLI verbs, in words. The COLOUR logic below is already correct
// three-state; this is only about the label. "Did anyone fail to log in?" was
// answerable only by someone who knows FortiOS verbs -- ssl-login-fail is
// 2,773 events in a window, and it reads as jargon.
//
// ⛔ An unmapped verb falls through to the RAW STRING -- never to a guessed
// friendly name, and never to "Unknown", which would be a claim. The raw verb
// stays on the title attribute either way, because it is the evidence.
const ACTION_LABEL = {
  'ssl-new-con': 'SSL-VPN connect',
  'ssl-login': 'Login',
  'ssl-login-fail': 'Login failed',
  'ssl-exit': 'Disconnected',
  'ssl-exit-error': 'Disconnected (error)',
  'ssl-alert': 'SSL alert',
  'tunnel-up': 'Tunnel up',
  'tunnel-down': 'Tunnel down',
  'tunnel-stats': 'Tunnel statistics',
  negotiate: 'Negotiating',
  install_sa: 'Tunnel established',
  delete_ipsec_sa: 'Tunnel removed',
  'phase2-up': 'Phase 2 up',
  'phase1-down': 'Phase 1 down',
};

function actionLabel(action) {
  if (!action) return null;
  return ACTION_LABEL[String(action).toLowerCase()] || action;
}

function actionTone(action) {
  const a = String(action).toLowerCase();
  if (FAILURE_HINTS.some((h) => a.includes(h))) return 'danger';
  if (OPEN_ACTIONS.has(a)) return 'success';
  if (CLOSE_ACTIONS.has(a)) return 'muted';
  // An unrecognized vendor verb gets a neutral colour, never a guessed
  // good/bad one — a confident wrong colour is a fabricated verdict.
  return 'info';
}

function severityTone(sev) {
  if (sev <= 3) return 'danger';   // emergency .. error
  if (sev === 4) return 'warning'; // warning
  return 'muted';
}

function fmtTime(value, tzAssumed) {
  if (!value) return null;
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  const s = d.toISOString().replace('T', ' ').slice(0, 19);
  // The caveat travels with the value (same convention as LogResults): the
  // device sent no timezone, so the collector's own zone was assumed.
  return tzAssumed ? s + ' ~' : s;
}

// Which compressed archive file holds a raw line that is not in the DB. Mirrors
// lib/syslog/archive.js's fileNameFor() — UTC day, the same key as the
// partition. Locally duplicated per this codebase's small-helper-per-file
// convention (LogResults.js carries the identical three lines).
// The rollup buckets by HOUR. ⛔ Rendered as a range ("14:00–15:00 UTC")
// rather than a point in time, so nobody reads it as an exact last-seen.
function fmtHour(value) {
  if (!value) return null;
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  const h = d.getUTCHours();
  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(h)}:00–${pad((h + 1) % 24)}:00 UTC`;
}

function archiveFileFor(value) {
  if (!value) return 'the daily archive';
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return 'the daily archive';
  return 'syslog-' + d.toISOString().slice(0, 10).replace(/-/g, '') + '.log.gz';
}

function stripMask(ip) {
  return String(ip || '').replace('/32', '');
}

// Most recent VPN-class events with their PARSED columns, not just the raw line.
// Written here rather than reusing trafficStats.getVpnActivity(), which returns
// only (received_at, source_ip, vendor, device_name, severity, message) — no
// user, no action, no client IP, no subtype, which is exactly what this table
// exists to show.
//
// Index-backed: idx_syslog_events_class covers (log_class, received_at DESC)
// for every class except 'traffic', so this never scans the raw partitions the
// way a `message LIKE '%vpn%'` would.
async function getRecentVpnEvents(dbPool, hours, limit, offset) {
  const { rows } = await dbPool.query(
    `SELECT e.id, e.received_at, e.tz_assumed, e.source_ip::text AS source_ip,
            e.device_id, d.name AS device_name, e.vendor, e.severity,
            e.action, e.auth_outcome, e.log_subtype, e.src_user,
            e.src_ip::text AS src_ip, e.src_country, e.message
       FROM syslog_events e
       LEFT JOIN devices d ON d.id = e.device_id
      WHERE e.received_at >= now() - ($1::int * interval '1 hour')
        AND e.log_class = 'vpn'
      -- ⛔ id is a TIEBREAKER, not decoration. received_at is stamped per
      -- datagram at millisecond resolution, and live the VPN class had 6,222
      -- tied timestamps across 13,744 rows in six hours — the MAJORITY of rows
      -- share a timestamp. Without a total order, OFFSET paging lets Postgres
      -- order ties differently between the query for page 1 and the query for
      -- page 2, so a row can appear twice while another is never shown at all.
      -- An operator paging for a failed login could silently never see it.
      -- logSearch.js already orders by (received_at DESC, id DESC).
      ORDER BY e.received_at DESC, e.id DESC
      LIMIT $2 OFFSET $3`,
    [hours, limit, offset]
  );
  return rows;
}

// Named-user coverage now comes from getUserCoverageForClass() in
// trafficStats.js, which reads syslog_user_hourly. ⛔ The raw version that
// lived here measured 17.8 SECONDS cold -- ~35,000 VPN rows scattered across a
// 26 GB daily partition, never still in cache because the ingest evicts them
// long before anyone opens this tab. It was the last aggregate on this card
// touching syslog_events, and it dominated the entire page load. Deleted
// rather than left in place, so it cannot be reached for again.

// Plain functions returning JSX, called imperatively — NOT nested component
// definitions. CLAUDE.md's rule is about components rendered as <Tag/>.
//
// ⛔ Now delegates to the shared NotMeasured marker rather than painting its own
// muted em-dash. Same three reasons as everywhere else: it is hueless
// (--unmeasured, never a severity), it carries the REASON to a screen reader as
// well as to a tooltip, and it is the one visual vocabulary for "we did not
// measure this" across the whole product. Every call site already passes a
// reason, which is what makes the swap safe.
function dash(title) {
  return <NotMeasured reason={title} />;
}

// ── Presentation primitives ──────────────────────────────────────────────
// All plain objects / functions at module top level. Everything is built from
// app/globals.css custom properties so it inherits the suite's light and dark
// palettes; ⛔ no hardcoded hex on any tinted surface, or dark mode breaks.

// A bordered grid of cells sharing 1px gaps, so the KPI row reads as one
// instrument rather than four loose numbers.
const KPI_GRID = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
  gap: 1,
  background: 'var(--border)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius)',
  overflow: 'hidden',
  marginBottom: 20,
};

const SECTION_LABEL = {
  fontSize: 'var(--text-xs)',
  fontWeight: 700,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  color: 'var(--text-muted)',
  marginBottom: 8,
};

// tone: null | "warn" | "bad" — semantic only, never decorative.
function kpiCell(value, label, sub, tone) {
  const valueColor =
    tone === 'bad' ? 'var(--red)' : tone === 'warn' ? 'var(--yellow)' : 'var(--text-primary)';
  return (
    <div
      key={label}
      style={{ background: 'var(--bg-card)', padding: '14px 16px' }}
    >
      <div
        style={{
          fontSize: 'var(--text-xl)',
          fontWeight: 700,
          lineHeight: 1.1,
          letterSpacing: '-0.02em',
          fontVariantNumeric: 'tabular-nums',
          color: valueColor,
        }}
      >
        {value}
      </div>
      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginTop: 4 }}>
        {label}
      </div>
      {sub ? (
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>
          {sub}
        </div>
      ) : null}
    </div>
  );
}

// A proportional bar behind each source. The eye should rank the sources
// before it reads a single number — a column of right-aligned figures makes
// the reader do that work themselves.
function sourceBar(pct, unmanaged) {
  return (
    <div
      aria-hidden="true"
      style={{ height: 4, borderRadius: 2, background: 'var(--border)', overflow: 'hidden', marginTop: 5 }}
    >
      <div
        style={{
          width: Math.max(1.5, Math.min(100, pct)) + '%',
          height: '100%',
          background: unmanaged ? 'var(--yellow)' : 'var(--accent-teal)',
        }}
      />
    </div>
  );
}

/**
 * @param {object} searchParams  the /vpn page's searchParams, preserved on paging links
 * @param {*}      page          raw `?evPage=` value (resolved here, not by the caller)
 */
export default async function VpnSyslogActivity({ searchParams, page }) {
  const sp = searchParams || {};

  // ⛔ The per-source breakdown comes from the ROLLUP, not the raw table.
  // Scanning every VPN row in the window is 34,777 rows spread across a
  // 26 GB partition: milliseconds warm, SECONDS cold -- and it is always
  // cold, because the ingest evicts those pages long before anyone opens
  // this tab. The rollup answers the same question from 273 rows.
  const [byDevice, coverage] = await Promise.all([
    getVpnActivityByDeviceRollup(pool, WINDOW_HOURS),
    getUserCoverageForClass(pool, 'vpn', WINDOW_HOURS),
  ]);

  // ONE total, from ONE query, used by both the headline tile and the pager.
  // The per-source counts come from a separate query milliseconds apart and can
  // differ by a handful of events under live ingest; showing two subtly
  // different "totals" on one card would read as a bug in the data rather than
  // the ordinary consequence of counting a moving stream twice.
  const total = coverage.events;
  // Clamp BEFORE the query, so a pasted ?evPage=1500 cannot reach OFFSET.
  const cappedTotal = Math.min(total, MAX_EVENT_PAGES * EVENTS_PAGE_SIZE);
  const win = pageWindow(resolvePage(page), EVENTS_PAGE_SIZE, cappedTotal);
  const depthLimited = total > cappedTotal;
  // Skip the round trip entirely when the window is empty — an OFFSET query
  // against the raw partitions is not free.
  const recent = total > 0 ? await getRecentVpnEvents(pool, WINDOW_HOURS, win.limit, win.offset) : [];

  const unmanaged = byDevice.filter((r) => !r.deviceName).length;
  const shownDevices = byDevice.slice(0, DEVICE_ROWS);
  // Bars are scaled to the BUSIEST source, so the list ranks at a glance.
  const maxSourceEvents = byDevice.reduce((m, r) => Math.max(m, r.events), 0);

  // ⛔ Scoped to THIS PAGE of events, and the KPI caption says so. Counting
  // failures across the whole 24h window would mean a second full scan of the
  // raw table — the exact cost this rewrite removed — and quietly labelling a
  // page-scoped figure as a 24h one would be worse than not showing it.
  // ⛔ `action` ALONE MISSES EVERY PALO ALTO FAILURE. vendorParsers.js sets
  // `action` only on PAN-OS TRAFFIC rows, so every GlobalProtect row has
  // action = NULL — and this tile counted them as zero. The outcome IS stored,
  // in syslog_events.auth_outcome; the query simply did not select it.
  //
  // Live, a 20-minute window of log_class='vpn': 88 paloalto failures with
  // action NULL, 11 paloalto successes, 66 fortinet failures with action set.
  // Palo Alto is the majority of VPN rows, so a page of this table was
  // frequently all-PAN-OS and the tile read a flat 0 above rows that were
  // themselves authentication failures.
  //
  // ⛔ A row where BOTH are null is UNMEASURED, not a non-failure — and if the
  // whole page is unmeasurable the tile must say so rather than print 0.
  const outcomeKnown = recent.filter(
    (e) => e.auth_outcome != null || e.action != null
  );
  const failureCount = recent.filter(
    (e) => e.auth_outcome === 'failure' || actionTone(e.action) === 'danger'
  ).length;
  const failureCountMeasurable = outcomeKnown.length > 0;

  // Deep link into the forensic view, pre-filtered to the same class and the
  // same window this card summarises — so "show me the rest" lands on the same
  // set of events rather than a fresh unfiltered search.
  const searchHref =
    '/logs?logClass=vpn&from=' +
    encodeURIComponent(new Date(Date.now() - WINDOW_HOURS * 3600 * 1000).toISOString());

  // ⛔ A percentage only when there is something to divide by. 0/0 is not
  // "0% of events named a user", it is "no events".
  const userCoveragePct =
    coverage.events > 0 ? Math.round((coverage.withUser / coverage.events) * 100) : null;

  return (
    <Card>
      <CardHeader>
        <CardTitle style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <IconChip icon={IconActivity} color="var(--green)" bg="var(--tint-success)" />
          VPN Activity from Logs (24h)
        </CardTitle>
      </CardHeader>
      <CardBody>
        {byDevice.length === 0 ? (
          <div style={{ fontSize: 'var(--text-base)', color: 'var(--text-muted)' }}>
            No VPN log events received in the last 24 hours. Only Palo Alto
            (GlobalProtect) and Fortinet (SSL-VPN) send these; a device missing
            here has sent no VPN logs, which is not the same as having no VPN
            activity.
          </div>
        ) : (
          <>
            {/* KPI strip. A bordered grid rather than three numbers floating
                in a row: at a glance an operator should see the shape of the
                24 hours, and unlabelled digits side by side do not give it. */}
            <div style={KPI_GRID}>
              {kpiCell(total.toLocaleString(), 'VPN events', WINDOW_HOURS + 'h window')}
              {kpiCell(
                String(byDevice.length),
                'reporting sources',
                unmanaged > 0
                  ? unmanaged + ' not in inventory'
                  : 'all in inventory',
                unmanaged > 0 ? 'warn' : null
              )}
              {kpiCell(
                // ⛔ NotMeasured, not 0, and not a bare em-dash either. "No
                // firewall told us a username" and "zero people used the VPN"
                // are different facts; the marker carries the reason so the
                // reader can tell which one they are looking at.
                coverage.users > 0 ? (
                  coverage.users.toLocaleString()
                ) : (
                  <NotMeasured reason="No VPN event in this window carried a username. The devices are logging, but not identifying the user — this is not a count of zero users." />
                ),
                'named users',
                userCoveragePct === null
                  ? 'no events to measure'
                  : coverage.users === 0
                    ? 'no event carried a username'
                    : 'identified on ' + userCoveragePct + '% of events'
              )}
              {/* ⛔ A page on which NO row carries either an action or an
                  auth_outcome cannot report a failure count — printing 0 there
                  would be "we watched and saw none" over events nothing could
                  be read from. */}
              {kpiCell(
                failureCountMeasurable ? failureCount.toLocaleString() : '—',
                'failed / denied',
                failureCountMeasurable
                  ? 'on this page of events'
                  : 'no event on this page reported an outcome',
                failureCountMeasurable && failureCount > 0 ? 'bad' : null
              )}
            </div>

            <div style={SECTION_LABEL}>Reporting sources</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2, marginBottom: 18 }}>
              {shownDevices.map((r, i) => (
                <div
                  key={(r.deviceId || r.sourceIp || 'unmanaged') + '-' + i}
                  style={{ padding: '7px 0' }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'baseline',
                      gap: 12,
                    }}
                  >
                    <span style={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {r.deviceName ? (
                        <Link
                          href={`/devices/${r.deviceId}/vpn`}
                          style={{ color: 'var(--text-primary)', fontWeight: 600 }}
                        >
                          {r.deviceName}
                        </Link>
                      ) : (
                        <>
                          <span
                            style={{
                              color: 'var(--text-primary)',
                              fontWeight: 600,
                              fontFamily: 'var(--font-mono)',
                            }}
                          >
                            {stripMask(r.sourceIp) || (
                              <NotMeasured
                                text="unknown source"
                                reason="These events arrived without a resolvable sender address."
                              />
                            )}
                          </span>{' '}
                          {/* ⛔ A firewall sending us VPN logs that is not in
                              the inventory is a FINDING, not noise. */}
                          <Badge color="warning">not in inventory</Badge>
                        </>
                      )}
                      <span
                        style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)', marginLeft: 8 }}
                      >
                        {r.vendor || (
                          <NotMeasured
                            text="unidentified vendor"
                            reason="No vendor parser recognised these lines, so the sending product is unknown. The events are still stored and counted."
                          />
                        )}
                        {/* ⛔ Hour granularity, and labelled as such. The rollup
                            buckets by hour; presenting it as a precise time
                            would be a precision we do not have. */}
                        {r.lastActiveHour ? ' · active ' + fmtHour(r.lastActiveHour) : ''}
                      </span>
                    </span>
                    <span
                      style={{
                        fontVariantNumeric: 'tabular-nums',
                        fontWeight: 600,
                        color: 'var(--text-primary)',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {r.events.toLocaleString()}
                    </span>
                  </div>
                  {sourceBar(maxSourceEvents > 0 ? (r.events / maxSourceEvents) * 100 : 0, !r.deviceName)}
                </div>
              ))}
              {byDevice.length > shownDevices.length ? (
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                  Showing the {shownDevices.length} busiest of {byDevice.length} reporting sources.
                </div>
              ) : null}
            </div>

            {recent.length > 0 ? (
              <>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'baseline',
                    justifyContent: 'space-between',
                    gap: 12,
                    flexWrap: 'wrap',
                    marginBottom: 6,
                  }}
                >
                  <span
                    style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--text-primary)' }}
                  >
                    Most recent VPN events
                  </span>
                  {/* ⛔ The old block showed eight lines with no total, which
                      reads as "this is what happened". The pager below now
                      carries the honest range; this says the window MOVES, so
                      a page number here is not a stable citation, and points at
                      the view where a fixed time range is. */}
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                    newest first — arriving events shift later pages ·{' '}
                    <Link href={searchHref} style={{ color: 'var(--primary)' }}>
                      search a fixed time range →
                    </Link>
                  </span>
                </div>

                <Table>
                  <colgroup>
                    <col style={{ width: '16%' }} />
                    <col style={{ width: '10%' }} />
                    <col style={{ width: '17%' }} />
                    <col style={{ width: '15%' }} />
                    <col style={{ width: '15%' }} />
                    <col style={{ width: '15%' }} />
                    <col style={{ width: '12%' }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th>Time (UTC)</th>
                      <th>Severity</th>
                      <th>Event</th>
                      <th>User</th>
                      <th>Source</th>
                      <th>Firewall</th>
                      <th>Raw</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recent.map((e, i) => {
                      const time = fmtTime(e.received_at, e.tz_assumed);
                      const sev =
                        e.severity === null || e.severity === undefined ? null : Number(e.severity);
                      const sevWord = sev !== null && SEVERITY_WORDS[sev] ? SEVERITY_WORDS[sev] : null;
                      return (
                        <tr key={String(e.received_at) + '-' + i}>
                          <td className="mono" style={{ verticalAlign: 'top', whiteSpace: 'normal' }}>
                            {time || dash('The device sent no usable timestamp')}
                          </td>
                          <td style={{ verticalAlign: 'top' }}>
                            {/* ⛔ Tri-state. A missing severity is a dash, never
                                "info" — the vendor sending nothing and the
                                vendor saying "informational" are different
                                facts. */}
                            {sev === null ? (
                              dash('This event carried no syslog severity')
                            ) : (
                              <Badge color={severityTone(sev)}>{sevWord || 'level ' + sev}</Badge>
                            )}
                          </td>
                          <td style={{ verticalAlign: 'top' }}>
                            {/* The ACTION is the outcome, so it gets the colour.
                                The SUBTYPE is only the vendor's log family
                                (FortiOS "vpn", PAN-OS "globalprotect") and stays
                                plain muted text underneath — badging it the same
                                way would present a log category as an outcome.
                                PAN-OS carries no action on GlobalProtect rows at
                                all (vendorParsers.js sets action only for
                                TRAFFIC).
                                ⛔ But it DOES report the outcome, in
                                auth_outcome — so falling straight to a dash
                                here said "this vendor reports no outcome"
                                about rows whose outcome SecVault had stored.
                                The dash is now reserved for a row where both
                                are genuinely absent. */}
                            {e.action ? (
                              <Badge color={actionTone(e.action)} title={e.action}>{actionLabel(e.action)}</Badge>
                            ) : e.auth_outcome ? (
                              <Badge
                                color={e.auth_outcome === 'failure' ? 'danger' : 'success'}
                                title={`Authentication ${e.auth_outcome} (reported as an outcome, not an action)`}
                              >
                                {e.auth_outcome === 'failure' ? 'Auth failed' : 'Auth OK'}
                              </Badge>
                            ) : (
                              dash('This event carried neither an action nor an authentication outcome')
                            )}
                            {e.log_subtype ? (
                              <div
                                style={{
                                  fontSize: 'var(--text-xs)',
                                  color: 'var(--text-muted)',
                                  marginTop: 3,
                                }}
                              >
                                {e.log_subtype}
                              </div>
                            ) : null}
                          </td>
                          <td
                            style={{ verticalAlign: 'top', wordBreak: 'break-word' }}
                            title={e.src_user || ''}
                          >
                            {e.src_user ? (
                              <span style={{ color: 'var(--accent-teal)', fontWeight: 600 }}>
                                {e.src_user}
                              </span>
                            ) : (
                              dash('No username in this event')
                            )}
                          </td>
                          <td className="mono" style={{ verticalAlign: 'top', whiteSpace: 'normal' }}>
                            {stripMask(e.src_ip) || dash('No client address in this event')}
                            {e.src_country ? (
                              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                                {/* The firewall's own answer — SecVault holds no
                                    GeoIP database of its own. */}
                                {e.src_country}
                              </div>
                            ) : null}
                          </td>
                          <td style={{ verticalAlign: 'top', wordBreak: 'break-word' }}>
                            {e.device_id && e.device_name ? (
                              <Link
                                href={`/devices/${e.device_id}/vpn`}
                                style={{ color: 'var(--text-primary)' }}
                              >
                                {e.device_name}
                              </Link>
                            ) : (
                              <>
                                <span className="mono">{stripMask(e.source_ip)}</span>{' '}
                                <Badge color="warning">unmanaged</Badge>
                              </>
                            )}
                          </td>
                          <td style={{ verticalAlign: 'top' }}>
                            {/* ⛔ A null message does NOT mean nothing was
                                received: ordinary parsed traffic keeps its raw
                                text in the compressed archive rather than the
                                database (schema.sql — message became NULLABLE on
                                2026-09-08). An empty cell would read as "no
                                evidence", so this names the file it is in. The
                                previous version of this block called
                                e.message.slice() unconditionally, which throws
                                on exactly those rows. */}
                            {e.message ? (
                              <details>
                                <summary
                                  style={{
                                    cursor: 'pointer',
                                    color: 'var(--text-muted)',
                                    fontSize: 'var(--text-xs)',
                                  }}
                                >
                                  raw line
                                </summary>
                                <pre
                                  style={{
                                    margin: '4px 0 0',
                                    padding: 8,
                                    background: 'var(--bg-primary)',
                                    borderRadius: 'var(--radius-sm)',
                                    fontSize: 'var(--text-xs)',
                                    whiteSpace: 'pre-wrap',
                                    wordBreak: 'break-all',
                                  }}
                                >
                                  {e.message}
                                </pre>
                              </details>
                            ) : (
                              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                                in archive{' '}
                                <code style={{ fontSize: 'var(--text-xs)' }}>
                                  {archiveFileFor(e.received_at)}
                                </code>
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </Table>

                {/* paramName keeps this list independent of the fleet status
                    table's own `?page=` further down /vpn. */}
                <Pagination
                  basePath="/vpn"
                  searchParams={sp}
                  page={win.page}
                  pageSize={win.pageSize}
                  total={cappedTotal}
                  label="VPN events in 24h"
                  paramName="evPage"
                />
                {/* ⛔ Say that the list is capped. A pager that simply stops is
                    indistinguishable from having reached the end of the data. */}
                {depthLimited ? (
                  <div
                    style={{
                      marginTop: 8,
                      fontSize: 'var(--text-xs)',
                      color: 'var(--text-muted)',
                    }}
                  >
                    Showing the most recent {cappedTotal.toLocaleString()} of{' '}
                    {total.toLocaleString()} events. Deeper history is searchable
                    on the Log Search page, which is far faster than paging this
                    list.
                  </div>
                ) : null}
              </>
            ) : null}

            <div
              style={{
                marginTop: 10,
                paddingTop: 8,
                borderTop: '1px solid var(--border)',
                fontSize: 'var(--text-sm)',
                color: 'var(--text-muted)',
              }}
            >
              Observed in syslog — independent of the config-derived status and the
              Fortinet-only session counts in the table below.
              {unmanaged > 0
                ? ` ${unmanaged} source${unmanaged === 1 ? '' : 's'} sending VPN logs ${unmanaged === 1 ? 'is' : 'are'} not in the device inventory.`
                : ''}
            </div>
          </>
        )}
      </CardBody>
    </Card>
  );
}
