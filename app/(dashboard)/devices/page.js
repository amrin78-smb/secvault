import Link from 'next/link';
import { getDiscoveredDevices } from '../../../lib/engines/deviceDiscovery';
import { vendorLabel } from '../../../components/devices/vendorMeta';
import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { getServerSession } from 'next-auth/next';
import {
  loadScopeForSession, filterDevices, isScoped, SCOPE_STATES, canSeeDevice,
  scopesEmptiedByDeviceDeletion,
} from '../../../lib/deviceScope';
import { authOptions } from '../../api/auth/[...nextauth]/route';
import { isAdmin } from '../../../lib/rbac';
import { pool } from '../../../lib/db';
import Table from '../../../components/ui/Table';
import Badge from '../../../components/ui/Badge';
import Button from '../../../components/ui/Button';
import EmptyState from '../../../components/ui/EmptyState';
import Modal from '../../../components/ui/Modal';
import PageHeader from '../../../components/ui/PageHeader';
import AnswerHeader from '../../../components/ui/AnswerHeader';
import { buildDeviceInventoryAnswer } from '../../../lib/answers';
import { deviceInventoryEvidence } from '../../../lib/evidence';
import DeviceRowActions from '../../../components/devices/DeviceRowActions';
import InventorySummaryStrip from '../../../components/devices/InventorySummaryStrip';
import DeviceFilters from '../../../components/devices/DeviceFilters';
import { SecurityScoreCell, SupportCell, HaCell, CveCell, PollHealthDot, PollHealthNote } from '../../../components/devices/DevicePostureCells';
import { getDeviceInventory, computeTiles, SORT_DIRECTION } from '../../../lib/engines/deviceInventory';
import { resolveColumns, priorityOf } from '../../../lib/tableColumns';
import ColumnChooser from '../../../components/ui/ColumnChooser';

export const dynamic = 'force-dynamic';


// ────────────────────────────────────────────────────────────────────────
// NOTE on per-row actions:
// Collect Now / Test Connectivity used to be Server Actions (<form action={...}>)
// calling /api/devices/[id]/collect and /test via an internalFetch() cookie-
// forwarding helper -- no client JS in front of them, so clicking either one
// did a genuine top-level form navigation with zero pending UI, and just sat
// there (up to ~2 minutes on an unreachable device) until the response came
// back. Replaced with DeviceRowActions.js, a client component using the same
// fetch+pending+router.refresh() pattern as the device detail page's
// DeviceActions.js, styled to match this table's compact inline text links.
//   - View -> still a plain <Link> (no interactivity needed). The separate "Edit"
//     link that used to sit here was removed: it pointed at this same URL, and the
//     device detail page it led to has no field-editing form (identity/inventory
//     fields can only be changed via the PUT API directly, not from this UI) --
//     the link was dead/misleading, not a real affordance.
//   - Delete -> still a plain <Link href="?confirmDelete=<id>"> query-param flip
//     + the shared Modal component + a Confirm <form> Server Action -- a single
//     fast DB delete, not a network call to a firewall, so the blocking-
//     navigation cost that motivated the above change doesn't apply to it.
// ────────────────────────────────────────────────────────────────────────

async function deleteDeviceAction(formData) {
  'use server';
  // Server Actions can't return an HTTP status code the way an API route
  // can (see lib/rbac.js's own header comment) — the guard here redirects
  // back with ?error=forbidden instead, which the page renders as a
  // banner, rather than throwing an uncaught error into the framework's
  // generic error boundary.
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    redirect('/devices?error=forbidden');
  }
  const id = formData.get('deviceId');

  // ⛔ THE DEVICE ID COMES FROM THE FORM BODY, SO IT IS NOT TRUSTED. The page
  // is scope-aware, but a Server Action is reached by POSTing to the page's own
  // URL — middleware allows that, because the page is 'aware' — and the body
  // can name ANY device id. Without this a scoped admin could delete a firewall
  // it was never granted, which is strictly worse than the read the GET route
  // refuses. Same shape as the saved-views rule: what does the security work is
  // that the identity comes from the SESSION and the target is re-checked
  // server-side, never that the form was rendered with the right value.
  const session2 = await getServerSession(authOptions);
  const scope = await loadScopeForSession(session2, pool);
  if (!canSeeDevice(scope, id)) {
    redirect('/devices?error=forbidden');
  }

  // ⛔ THE SAME GUARD THE API ROUTE APPLIES, because this path does its own
  // DELETE rather than calling that route. `user_device_scopes.device_id` is ON
  // DELETE CASCADE and zero rows means UNSCOPED, so removing the last firewall
  // in an account's scope hands that account the whole fleet. One shared helper
  // rather than a second copy of the query: two implementations of "would this
  // widen someone's access" would eventually disagree, and the wrong one would
  // be the one that let the delete through.
  //
  // ⛔ A FAILED CHECK REFUSES. A delete is irreversible, so "we could not tell"
  // must not proceed.
  let emptied;
  try {
    emptied = await scopesEmptiedByDeviceDeletion(pool, id);
  } catch {
    redirect('/devices?error=scope_check_failed');
  }
  if (emptied.length > 0) {
    redirect(`/devices?error=scope_last_device&accounts=${encodeURIComponent(emptied.join(', '))}`);
  }

  await pool.query('DELETE FROM devices WHERE id = $1', [id]);
  revalidatePath('/devices');
  redirect('/devices');
}

function formatDateTime(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

// Filtering is applied to the FULL decorated row set (server-side), so a
// filter narrows the whole fleet rather than just the visible page. Every
// predicate here is a pure function of an already-fetched row — no extra query.
function matchesFilters(row, f) {
  if (f.q) {
    const hay = [row.name, row.mgmt_ip, row.smc_host, row.site, row.vendor]
      .filter(Boolean).join(' ').toLowerCase();
    if (!hay.includes(f.q.toLowerCase())) return false;
  }
  if (f.vendor && row.vendor !== f.vendor) return false;
  if (f.risk) {
    // 'unanalysed' is a REAL state, distinct from 'low' — a device with no
    // analysis rows has earned no band at all and must not be filed under the
    // best one.
    if (f.risk === 'unanalysed') { if (row.riskBand !== null) return false; }
    else if (row.riskBand !== f.risk) return false;
  }
  if (f.status) {
    if (f.status === 'online' && row.last_connectivity_ok !== true) return false;
    if (f.status === 'offline' && row.last_connectivity_ok !== false) return false;
    if (f.status === 'unchecked' && row.last_connectivity_ok !== null) return false;
  }
  if (f.support) {
    const expired = (row.expired_count || 0) > 0;
    const expiring =
      !expired && row.soonest_future_expiry &&
      new Date(row.soonest_future_expiry).getTime() - Date.now() <= 90 * 86400000;
    if (f.support === 'expired' && !expired) return false;
    if (f.support === 'expiring' && !expiring) return false;
    if (f.support === 'unknown' && (row.unknown_expiry_count || 0) === 0) return false;
  }
  if (f.site) {
    if (f.site === '__none__') { if (row.site) return false; }
    else if (row.site !== f.site) return false;
  }
  return true;
}


// Module-top-level so a future refactor toward client-side interactive sort
// controls can't accidentally turn this into a component defined inside a
// component (see CLAUDE.md's "NEVER define a React component inside another
// React component" rule). Currently invoked as a plain function call
// ({sortLink(...)}), not a JSX tag, so it isn't a component today -- but this
// keeps it that way even if a later change starts rendering it as
// <SortLink/>. Takes the previously-closed-over `sortKey` explicitly instead
// of relying on closure.
// ⛔ Every internal link on this page must PRESERVE the active filters. Before
// this, sorting, cancelling a delete, or opening the delete confirm all built
// `/devices?sort=X` from scratch, silently discarding whatever the operator had
// filtered to — the table would quietly repopulate with the whole fleet and
// look like the filter had failed. Builds from the CURRENT params, applying
// only the given overrides (a null value deletes that key).
function buildDevicesHref(searchParams, overrides = {}) {
  const next = new URLSearchParams();
  for (const [k, v] of Object.entries(searchParams || {})) {
    if (typeof v === 'string' && v !== '') next.set(k, v);
  }
  for (const [k, v] of Object.entries(overrides)) {
    if (v === null || v === undefined || v === '') next.delete(k);
    else next.set(k, v);
  }
  const qs = next.toString();
  return qs ? `/devices?${qs}` : '/devices';
}

// A sortable column header.
//
// ⛔ THE SORT CONTROLS MOVED OUT OF THEIR OWN ROW AND INTO THE TABLE HEAD.
// There used to be a "Sort by: Name | Security Score | CVE Count | Rules |
// Last Collected" line between the filter bar and the table — five link
// names that had to be mentally matched to five of the ten column headings
// directly beneath them, and a whole row of vertical space on a page whose
// problem was that the table started below the fold.
//
// ⛔ `aria-sort` IS ON THE <th>, WHICH IS WHERE THE SPEC PUTS IT, and it
// states the REAL direction from the engine's own SORT_DIRECTION map rather
// than a guess. A header announcing "ascending" over a descending column is
// worse than announcing nothing — WCAG 2.2's point is that the announcement
// matches the data, not that the attribute is present.
//
// ⛔ THERE IS NO DIRECTION TOGGLE, and that is unchanged behaviour rather
// than a gap: every key has one deliberate direction (worst score first, most
// rules first). Clicking an active header is therefore a no-op, so it is
// rendered as plain text rather than as a link that appears to do something.
function SortableTh({ activeSortKey, sortKey, label, title, searchParams, width, priority }) {
  const active = activeSortKey === sortKey;
  return (
    <th
      aria-sort={active ? SORT_DIRECTION[sortKey] || 'other' : 'none'}
      title={title}
      data-col-priority={priority}
      style={width ? { width } : undefined}
    >
      {active ? (
        <span className="th-sort" data-active="">
          {label}
          <span aria-hidden="true" className="th-sort-glyph">
            {SORT_DIRECTION[sortKey] === 'ascending' ? '\u2191' : '\u2193'}
          </span>
        </span>
      ) : (
        <Link
          href={buildDevicesHref(searchParams, { sort: sortKey, confirmDelete: null })}
          className="th-sort"
        >
          {label}
        </Link>
      )}
    </th>
  );
}

// The firewall table's columns.
//
// ⛔ `required` IS NOT A STYLE CHOICE. Device is how a row is identified at
// all and Actions is how anything is done to it; a chooser able to hide both
// is a way for an operator to break their own page and not know why.
//
// ⛔ `priority` DECIDES WHAT A NARROW VIEWPORT DROPS, and is deliberately
// independent of position. Vendor sits second because that is where it reads
// best and goes early because it is the least load-bearing; tying the two
// would force a column to be unimportant in order to be late. 1 never drops.
const DEVICE_COLUMNS = [
  { key: 'name', label: 'Device', required: true, priority: 1, width: '16%' },
  { key: 'vendor', label: 'Vendor', priority: 3, width: '9%' },
  { key: 'score', label: 'Score', priority: 1, width: '11%' },
  { key: 'version', label: 'Version', priority: 2, width: '11%' },
  { key: 'rules', label: 'Rules', priority: 3, width: '7%' },
  { key: 'cves', label: 'CVEs', priority: 1, width: '10%' },
  { key: 'support', label: 'Support', priority: 2, width: '11%' },
  { key: 'ha', label: 'HA', priority: 4, width: '8%' },
  { key: 'collected', label: 'Collected', priority: 2, width: '10%' },
  { key: 'actions', label: 'Actions', required: true, priority: 1, width: '7%' },
];

export default async function DevicesPage({ searchParams }) {
  // getDeviceInventory validates ?sort= against its own whitelist and returns
  // the key it actually used, so an unknown value can never reach any ordering.
  const { rows: inventoryRows, tiles: inventoryTiles, sortKey } = await getDeviceInventory(pool, {
    sort: searchParams?.sort,
  });

  // ⛔ SCOPE-AWARE (see lib/deviceScopeCoverage.js). A restricted account sees
  // only the firewalls it was granted.
  //
  // ⛔ THE TILES ARE RECOMPUTED, NOT REUSED. getDeviceInventory() returns
  // fleet-wide tiles; printing those above a narrowed table would state a
  // fleet fact to somebody who cannot see the fleet -- the same error as a
  // score averaged over more devices than the operator can see, and on this
  // page it would also disclose how many firewalls exist outside their scope.
  const deviceScope = await loadScopeForSession(
    await getServerSession(authOptions), pool
  );
  // ⛔ SET BY middleware.js WHEN IT REDIRECTED A SCOPED ACCOUNT HERE. Without
  // it the person lands on a different page than the one they asked for, with
  // no explanation, and concludes the product is broken -- which is worse than
  // a refusal, because the person looking at the screen is not the person who
  // set the restriction. Displayed as INFORMATION, not danger: nothing has
  // gone wrong.
  const blockedFrom = typeof searchParams?.scopeBlocked === 'string'
    ? searchParams.scopeBlocked.slice(0, 120)
    : null;
  const scopeNarrowed = isScoped(deviceScope) || deviceScope.state === SCOPE_STATES.UNKNOWN;
  const allRows = scopeNarrowed ? filterDevices(deviceScope, inventoryRows) : inventoryRows;
  const fleetTiles = scopeNarrowed ? computeTiles(allRows) : inventoryTiles;

  const filters = {
    q: searchParams?.q || '',
    vendor: searchParams?.vendor || '',
    risk: searchParams?.risk || '',
    status: searchParams?.status || '',
    support: searchParams?.support || '',
    site: searchParams?.site || '',
  };
  const devices = allRows.filter((r) => matchesFilters(r, filters));

  // Filter dropdowns are built from the FULL set, not the filtered one —
  // otherwise picking a vendor removes every other vendor from the dropdown
  // and the filter becomes a one-way trip.
  const vendors = [...new Set(allRows.map((r) => r.vendor))].sort();
  const sites = [...new Set(allRows.map((r) => r.site).filter(Boolean))].sort();

  // ⛔ Tiles reflect the CURRENT view. With a filter applied they describe what
  // is on screen, which is what the numbers sitting directly above the table
  // have to mean; unfiltered they are the whole fleet.
  const tiles = devices.length === allRows.length ? fleetTiles : computeTiles(devices);

  // ⛔ Built from fleetTiles, NOT `tiles`. `tiles` follows the active filter,
  // and a sentence that silently described the filtered subset while claiming
  // to describe the fleet would be the same class of error as a score averaged
  // over fewer devices than the operator can see.
  const inventoryAnswer = buildDeviceInventoryAnswer(fleetTiles);
  const inventoryEvidence = deviceInventoryEvidence(fleetTiles);

  // ⛔ FROM THE URL, so a column choice is linkable and — because /devices
  // already has saved views, which store the query string verbatim — nameable
  // for free. In localStorage it would be state a saved view silently does
  // not capture, restoring the wrong table.
  const { columns: deviceColumns } = resolveColumns(DEVICE_COLUMNS, searchParams?.cols);
  const shownCol = new Set(deviceColumns.filter((c) => !c.hidden).map((c) => c.key));
  const colPriority = Object.fromEntries(DEVICE_COLUMNS.map((c) => [c.key, String(priorityOf(c))]));
  const show = (key) => shownCol.has(key);

  const confirmDeleteId = searchParams?.confirmDelete || null;
  const confirmDevice = confirmDeleteId ? devices.find((d) => d.id === confirmDeleteId) : null;

  // Defense in depth only — deleteDeviceAction's own isAdmin() guard above
  // is the real enforcement. Hiding the Delete link/button for a viewer
  // just avoids a confusing "click Delete, land back with a forbidden
  // banner" round trip.
  const session = await getServerSession(authOptions);
  const canWrite = isAdmin(session);

  // ⛔ Counts only senders that are genuinely unmanaged — an HA passive peer we
  // already know about is not a device waiting to be added, and counting it
  // would invite the operator to duplicate a firewall. Best-effort: a failure
  // here must not take down the whole fleet inventory page, so it degrades to
  // no chip rather than an error.
  let discoveredCount = 0;
  try {
    const discovered = await getDiscoveredDevices(pool);
    discoveredCount = discovered.filter(
      (d) => d.status === 'new' && d.correlation.kind === 'unmanaged'
    ).length;
  } catch (_err) {
    // ⛔ null, NOT 0 — the read FAILED. Both render the same today (a bare
    // chip), and that is exactly why the variable has to stay honest: the next
    // reader to put a number beside it would otherwise print a measured zero
    // over a failed read.
    discoveredCount = null;
  }

  // ⛔ BOTH LINKS GO TO BLOCKED SURFACES FOR A SCOPED ACCOUNT, so offering them
  // is a UI that is LOOSER than the API behind it — the inverse of this
  // product's rule, and it lands the person on a redirect that looks like a
  // bug. Discovered senders and Add firewall are fleet-wide by nature (a sender
  // that is in nobody's inventory belongs to no scope), so they are hidden
  // rather than filtered.
  const fleetWideActionsAllowed = !scopeNarrowed;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <PageHeader
        title="Firewalls"
        actions={
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {/* ⛔ IN THE HEADER'S ACTION ROW, NOT IN A ROW OF ITS OWN. The
                first version gave it a line between the filter bar and the
                table, and tests/inventorySummary.test.js caught it: that is
                ~40px of the 190px Phase 3 recovered, spent on a control most
                operators touch once. It is a page-level control and the page
                already has a row for those.
                ⛔ It is deliberately NOT in the filter bar either. A filter
                changes WHICH ROWS match; this changes what you can see OF a
                row, and sitting among the filters would invite the reading
                that hiding a column narrows the result set. */}
            <ColumnChooser basePath="/devices" defs={DEVICE_COLUMNS} />
            {/* ⛔ The count excludes senders already matched to a managed
                device (HA peers), because presenting those as "devices to add"
                is exactly how an operator ends up with duplicate firewalls.
                Muted at zero — a zero-count chip must not read as an alert. */}
            {fleetWideActionsAllowed && (
              <Link
                href="/devices/discovered"
                className="btn btn-secondary"
                title="Firewalls sending syslog from an address that is not in the inventory"
              >
                Discovered senders
                {discoveredCount > 0 ? ` (${discoveredCount})` : ''}
              </Link>
            )}
            {canWrite && fleetWideActionsAllowed && (
              <Link href="/devices/new" className="btn btn-primary">
                Add firewall
              </Link>
            )}
          </div>
        }
      />

      <AnswerHeader answer={inventoryAnswer} evidence={inventoryEvidence} />

      {searchParams?.error === 'forbidden' && (
        <div
          style={{
            padding: '10px 14px',
            borderRadius: 'var(--radius-sm)',
            background: 'var(--tint-danger)',
            color: 'var(--tint-danger-fg)',
            fontSize: 'var(--text-base)',
          }}
        >
          You don&apos;t have permission to do that — admin role required.
        </div>
      )}

      {/* ⛔ A REFUSED DELETE MUST SAY WHY IT WAS REFUSED. Redirecting back with
          no explanation reads as a broken button, and the operator's next move
          is to try again rather than to fix the scope that is actually
          blocking them. */}
      {(searchParams?.error === 'scope_last_device'
        || searchParams?.error === 'scope_check_failed') && (
        <div
          style={{
            padding: '10px 14px',
            borderRadius: 'var(--radius-sm)',
            background: 'var(--tint-warn)',
            color: 'var(--tint-warn-fg)',
            fontSize: 'var(--text-base)',
          }}
        >
          {searchParams.error === 'scope_last_device' ? (
            <>
              Not deleted. This is the only firewall granted to{' '}
              <strong>{String(searchParams.accounts || 'one or more accounts').slice(0, 200)}</strong>
              , and an account with no firewalls granted sees <em>every</em> firewall in SecVault.
              Grant those accounts a different firewall first, then delete this one.
            </>
          ) : (
            <>
              Not deleted. SecVault could not check whether any account is restricted to this
              firewall, and a deletion cannot be undone. Try again; if it keeps happening, report
              it.
            </>
          )}
        </div>
      )}

      {/* ⛔ SEVEN STAT TILES BECAME A ONE-ROW STRIP. The tiles wrapped 6+1 at
          1440 and pushed the firewall table to roughly y=760 — one visible row
          on a 900px viewport, on the page whose job is listing firewalls. No
          figure was dropped; see InventorySummaryStrip.js for where each
          tile's sub-line went and why the two CVE figures now render as
          em-dashes over an unassessed fleet. */}
      <InventorySummaryStrip tiles={tiles} />

      {blockedFrom && (
        <div style={{
          padding: '10px 12px',
          borderRadius: 'var(--radius-sm)',
          background: 'var(--tint-info)',
          color: 'var(--tint-info-fg)',
          fontSize: 'var(--text-sm)',
          lineHeight: 1.6,
        }}>
          <strong>Your account is restricted to specific firewalls.</strong>{' '}
          <code style={{ fontFamily: 'var(--font-mono)' }}>{blockedFrom}</code> does not yet
          support that restriction, so it is not shown rather than showing you the whole fleet.
          Ask a Super Admin if you need it.
        </div>
      )}

      <DeviceFilters
        vendors={vendors}
        sites={sites}
        activeCount={devices.length}
        totalCount={allRows.length}
      />

      {devices.length === 0 ? (
        <EmptyState
          message={
            allRows.length === 0
              ? 'No devices yet. Add one to get started.'
              : 'No devices match these filters.'
          }
        />
      ) : (
        <Table>
          {/* 10 columns. The mockup had 13; Address and Monitor-band CVEs were
              dropped rather than shipped clipped -- this table already sits in
              Table's overflow-x box, but a column an operator cannot read
              without scrolling is not a column they will use. Address stays one
              click away on the device page. Site was dropped too (v2.56.2):
              exactly one of 16 devices has a value, so the column was spending
              9% of the width rendering em-dashes. It stays searchable and
              filterable -- only the column is gone. */}
          {/* ⛔ DRIVEN BY THE REGISTRY. Ten hand-written <col> widths beside
              ten hand-written <th>s is two lists that must agree, and a
              hidden column would otherwise leave its width behind — every
              remaining column shifted, for a reason nothing on screen
              explains. */}
          <colgroup>
            {deviceColumns.filter((c) => !c.hidden).map((c) => (
              <col key={c.key} style={{ width: c.width }} data-col-priority={colPriority[c.key]} />
            ))}
          </colgroup>
          <thead>
            <tr>
              {show('name') && <SortableTh activeSortKey={sortKey} sortKey="name" label="Device" searchParams={searchParams} priority={colPriority.name} />}
              {show('vendor') && <SortableTh activeSortKey={sortKey} sortKey="vendor" label="Vendor" searchParams={searchParams} priority={colPriority.vendor} />}
              {show('score') && <SortableTh
                priority={colPriority.score}
                activeSortKey={sortKey}
                sortKey="score"
                label="Score"
                title="Security Score — composite of vulnerability posture, rule hygiene and compliance (higher is better). Sorts worst first. Colour shows the rule-hygiene risk band."
                searchParams={searchParams}
              />}
              {show('version') && <th data-col-priority={colPriority.version}>Version</th>}
              {show('rules') && <SortableTh activeSortKey={sortKey} sortKey="rules" label="Rules" searchParams={searchParams} priority={colPriority.rules} />}
              {show('cves') && <SortableTh activeSortKey={sortKey} sortKey="cve_count" label="CVEs" searchParams={searchParams} priority={colPriority.cves} />}
              {/* ⛔ NOT SORTABLE, AND DELIBERATELY NOT FAKED. The engine has no
                  `support` sort key — support state is three different facts
                  (lapsed / expiring / unreadable) with no single ordering —
                  so this header stays plain. The first draft of this change
                  wired it to `site`, which is a real sort key: the fleet would
                  have reordered by site while the header announced it had
                  sorted by support, to a screen reader as well as on screen. */}
              {show('support') && (
                <th
                  data-col-priority={colPriority.support}
                  title="Support contract expiry from collected licences. NOT vendor OS end-of-life, which SecVault does not collect."
                >
                  Support
                </th>
              )}
              {show('ha') && <th data-col-priority={colPriority.ha}>HA</th>}
              {show('collected') && <SortableTh
                priority={colPriority.collected}
                activeSortKey={sortKey}
                sortKey="last_collected"
                label="Collected"
                searchParams={searchParams}
              />}
              {show('actions') && <th data-col-priority={colPriority.actions}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id}>
                {show('name') && (
                  <td data-col-priority={colPriority.name}>
                    {/* ⛔ The dot is driven by POLL HEALTH, not by
                        devices.last_connectivity_ok — that column is written only by
                        the manual "Test connectivity" button, so it could be weeks
                        stale and showed TSR_EKC green while every poll had failed
                        for 19 days. */}
                    <span style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <PollHealthDot band={d.pollBand} health={d.pollHealth} />
                        <Link href={`/devices/${d.id}`} className="link-quiet">
                          {d.name}
                        </Link>
                      </span>
                      <PollHealthNote band={d.pollBand} health={d.pollHealth} />
                    </span>
                  </td>
                )}
                {show('vendor') && (
                  <td data-col-priority={colPriority.vendor}>
                    <Badge color="info" title={vendorLabel(d.vendor)}>{vendorLabel(d.vendor, { short: true })}</Badge>
                  </td>
                )}
                {show('score') && (
                  <td data-col-priority={colPriority.score}>
                    <SecurityScoreCell
                      score={d.securityScore}
                      riskBand={d.riskBand}
                      components={d.securityComponents}
                    />
                  </td>
                )}
                {show('version') && (
                  <td data-col-priority={colPriority.version} title={d.version_string || undefined}>{d.version_string || '—'}</td>
                )}
                {show('rules') && (
                  <td data-col-priority={colPriority.rules}>
                    {d.rule_count > 0 ? (
                      <span title={`${d.enabled_rule_count} enabled`}>{d.rule_count.toLocaleString()}</span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)' }}>—</span>
                    )}
                  </td>
                )}
                {show('cves') && (
                  <td data-col-priority={colPriority.cves}>
                    {/* ⛔ All three coverage props matter, not just the counts.
                        versionString separates "the matcher skipped this device"
                        from a result; lastAssessedAt is the stamp
                        versionMatcher.js writes only on a COMPLETED per-device
                        match; assessmentCount is the corroborating evidence that
                        covers both the not-yet-stamped fleet and devices holding
                        only monitor-band rows (which this column does not show).
                        Drop any of them and a zero silently goes back to meaning
                        two different things. */}
                    <CveCell
                      patchNow={d.patch_now_count}
                      scheduled={d.scheduled_count}
                      versionString={d.version_string}
                      lastAssessedAt={d.last_cve_assessed_at}
                      assessmentCount={d.assessment_count}
                    />
                  </td>
                )}
                {show('support') && (
                  <td data-col-priority={colPriority.support}>
                    <SupportCell
                      expiredCount={d.expired_count}
                      soonestFutureExpiry={d.soonest_future_expiry}
                      unknownCount={d.unknown_expiry_count}
                    />
                  </td>
                )}
                {show('ha') && (
                  <td data-col-priority={colPriority.ha}>
                    <HaCell
                      enabled={d.ha_enabled}
                      mode={d.ha_mode}
                      localState={d.ha_local_state}
                      peerStatus={d.ha_peer_status}
                      versionCompatOk={d.ha_version_compat_ok}
                      configSyncState={d.ha_config_sync_state}
                      peerState={d.ha_peer_state}
                      lastNonfunctionalReason={d.ha_last_nonfunctional_reason}
                    />
                  </td>
                )}
                {show('collected') && (
                  <td data-col-priority={colPriority.collected} title={formatDateTime(d.last_collected_at)}>{formatDateTime(d.last_collected_at)}</td>
                )}
                {show('actions') && (
                  <td data-col-priority={colPriority.actions}>
                    <DeviceRowActions
                      deviceId={d.id}
                      baseHref={buildDevicesHref(searchParams, { confirmDelete: null })}
                      canWrite={canWrite}
                    />
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      {canWrite && (
        <Modal open={Boolean(confirmDevice)} title="Delete firewall">
          {confirmDevice && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
                Delete <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{confirmDevice.name}</span>?
                This removes all associated versions, rules, credentials, and CVE assessments.
              </p>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <form action={deleteDeviceAction}>
                  <input type="hidden" name="deviceId" value={confirmDevice.id} />
                  <Button type="submit" variant="danger">
                    Delete
                  </Button>
                </form>
                <Link
                  href={buildDevicesHref(searchParams, { confirmDelete: null })}
                  style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', textDecoration: 'underline' }}
                >
                  Cancel
                </Link>
              </div>
            </div>
          )}
        </Modal>
      )}
    </div>
  );
}
