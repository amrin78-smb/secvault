import Link from 'next/link';
import { pool } from '../../../lib/db';
import PageHeader from '../../../components/ui/PageHeader';
import Card, { CardBody } from '../../../components/ui/Card';
import Table from '../../../components/ui/Table';
import Badge from '../../../components/ui/Badge';
import EmptyState from '../../../components/ui/EmptyState';
import StatCard from '../../../components/ui/StatCard';
import { licenseStatus, signatureStatus, haStatus } from '../../../lib/engines/deviceHealth';

export const dynamic = 'force-dynamic';

// Fleet-wide lifecycle & health view over the four snapshot tables added
// 2026-08-03 (device_licenses / device_ha_status / device_content_versions --
// per-device disk detail stays on the device Overview card, since a fleet
// table of 7-9 mounts per device is noise, not a planning view).
//
// ⛔ Every verdict comes from lib/engines/deviceHealth.js. This page only
// queries, groups, sorts and labels — it never re-derives "is that expiring /
// stale / degraded", which would immediately drift from the device Overview
// card's answer to the same question.
//
// ⛔ COVERAGE GAPS ARE RENDERED, NOT OMITTED. Only adapters implementing the
// optional getLicenses()/getHaStatus() methods (and whose getVersion() returns
// contentVersions) populate these tables — Palo Alto, both transports, as of
// this add. Every other active device appears in every section as an explicit
// muted "Not collected" row, the same honesty rule the Fleet Map already
// follows by drawing devices that have zero device_interfaces rows. Silently
// dropping them would make a 5-device blind spot look like a clean fleet.

// ── Support-contract detection.
// Palo Alto reports support entitlements as a licence whose FEATURE is the
// service tier ('Premium'/'Standard'), with the human description carrying the
// actual words ('24 x 7 phone support advanced replacement hardware service').
// Matched on either, deliberately loosely: a false positive here only means one
// extra healthy row in the renewal table, whereas a false negative silently
// hides the single most consequential expiry date on the box.
const SUPPORT_TIER_FEATURES = /^(premium|standard|platinum|gold|silver|basic|partner)\b/i;

function isSupportContract(row) {
  if (!row) return false;
  const feature = typeof row.feature === 'string' ? row.feature.trim() : '';
  const description = typeof row.description === 'string' ? row.description : '';
  if (SUPPORT_TIER_FEATURES.test(feature)) return true;
  // ⛔ Fortinet names the entitlement DIRECTLY rather than by service tier —
  // 'Support', 'Comprehensive Support', 'Enhanced Support', 'Hardware RMA' —
  // and its descriptions are contract CODES ('Fortinet SPRT contract'), so
  // neither the tier regex nor a description /support/ match caught any of
  // them. Result: every Fortinet whose support contract was still healthy
  // vanished from the renewal table entirely, and only TUS appeared because
  // its contracts were expired and matched a different branch. Match the
  // feature name too.
  if (/support/i.test(feature)) return true;
  if (/^hardware\b/i.test(feature)) return true;
  // 'Firmware & General Updates' (Fortinet FMWR) is a renewable entitlement
  // bought alongside SPRT/HDWR/ENHN/COMP, but matches none of the tests above —
  // so a HEALTHY one silently vanished from the renewal table while its
  // siblings showed, which is the same defect this function was just fixed for.
  if (/^firmware\b/i.test(feature)) return true;
  return /support/i.test(description);
}

const COMPONENT_LABELS = {
  app: 'App',
  av: 'Antivirus',
  threat: 'Threat',
  wildfire: 'WildFire',
  url_filtering: 'URL Filtering',
  device_dictionary: 'Device Dictionary',
};

// Canonical display order for the signature columns; anything unexpected the
// collector starts returning later sorts after these rather than disappearing.
const COMPONENT_ORDER = ['app', 'av', 'threat', 'wildfire', 'url_filtering', 'device_dictionary'];

function componentLabel(component) {
  return COMPONENT_LABELS[component] || component;
}

// DATE columns arrive from node-postgres as a local-midnight Date, so local
// getters are the correct read — toISOString() would shift the day backwards on
// any positive-offset server (a licence expiring 2021-12-25 showing 2021-12-24).
function formatDate(value) {
  if (!value) return null;
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

// Display-only day delta. Kept separate from licenseStatus().daysRemaining,
// which is intentionally null whenever the DEVICE's own `expired` flag decided
// the verdict — that is the right call for banding, but an operator planning
// renewals still wants to see how long ago it lapsed.
const MS_PER_DAY = 24 * 60 * 60 * 1000;

function dayDelta(value, now) {
  if (!value) return null;
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return Math.floor((d.getTime() - now.getTime()) / MS_PER_DAY);
}

function daysText(delta) {
  if (delta === null) return '—';
  if (delta < 0) return `${Math.abs(delta)}d ago`;
  return `${delta}d`;
}

// Plain module-level functions returning JSX, invoked as {licenseBadge(...)} —
// NOT nested components (see CLAUDE.md's "NEVER define a React component inside
// another React component").
function licenseBadge(status) {
  if (status === 'expired') return <Badge color="danger">Expired</Badge>;
  if (status === 'expiring') return <Badge color="warning">Expiring</Badge>;
  if (status === 'perpetual') return <Badge color="info">Perpetual</Badge>;
  if (status === 'ok') return <Badge color="success">OK</Badge>;
  if (status === 'not_licensed') return <Badge color="muted">Not licensed</Badge>;
  return <Badge color="muted">Unknown</Badge>;
}

function haBadge(status) {
  if (status === 'degraded') return <Badge color="danger">Degraded</Badge>;
  if (status === 'healthy') return <Badge color="success">Healthy</Badge>;
  if (status === 'standalone') return <Badge color="muted">Standalone</Badge>;
  return <Badge color="muted">Unknown</Badge>;
}

function notCollectedBadge() {
  return <Badge color="muted">Not collected</Badge>;
}

function deviceLink(deviceId, name) {
  return (
    <Link href={`/devices/${deviceId}`} className="link-quiet">
      {name}
    </Link>
  );
}

const HA_SORT_RANK = { degraded: 0, standalone: 1, healthy: 2, unknown: 3 };

async function getLifecycleData() {
  const [devices, licenses, haRows, content] = await Promise.all([
    pool.query('SELECT id, name, vendor FROM devices WHERE active = true ORDER BY name ASC'),
    pool.query(
      `SELECT l.id, l.device_id, l.feature, l.description, l.expires_at, l.expires_raw, l.expired
       FROM device_licenses l
       JOIN devices d ON d.id = l.device_id
       WHERE d.active = true`
    ),
    pool.query(
      `SELECT h.device_id, h.enabled, h.mode, h.local_state, h.peer_state, h.peer_mgmt_ip,
              h.peer_connection_status, h.config_sync_state, h.last_nonfunctional_reason,
              h.version_compat_ok, h.version_compat, h.raw
       FROM device_ha_status h
       JOIN devices d ON d.id = h.device_id
       WHERE d.active = true`
    ),
    pool.query(
      `SELECT c.device_id, c.component, c.version, c.released_at
       FROM device_content_versions c
       JOIN devices d ON d.id = c.device_id
       WHERE d.active = true`
    ),
  ]);
  return {
    devices: devices.rows,
    licenses: licenses.rows,
    haRows: haRows.rows,
    content: content.rows,
  };
}


// Groups licences into RENEWAL EVENTS: one entry per (device, expiry date).
// A device typically carries several entitlements bought together on one
// contract — live, TUG has 7 expiring on the same day and SMT another 7 — so
// listing them individually turned one purchasing decision into seven rows and
// made the table a long scroll rather than a plan. The group's status is the
// WORST of its members so nothing urgent hides inside a collapsed group.
const LICENSE_SEVERITY_RANK = { expired: 4, expiring: 3, unknown: 2, ok: 1, perpetual: 1, not_licensed: 0 };

function groupLicenseRenewals(entries) {
  const groups = new Map();
  for (const entry of entries) {
    // Key on the parsed date when there is one, else the raw string, so
    // 'Never' and unparseable values still group per device rather than each
    // becoming its own singleton row.
    const dateKey = entry.row.expires_at
      ? formatDate(entry.row.expires_at)
      : `raw:${entry.row.expires_raw || 'none'}`;
    const key = `${entry.row.device_id}|${dateKey}`;
    let g = groups.get(key);
    if (!g) {
      g = {
        key,
        device: entry.device,
        expiresAt: entry.row.expires_at,
        expiresRaw: entry.row.expires_raw,
        delta: entry.delta,
        status: entry.status,
        items: [],
      };
      groups.set(key, g);
    }
    g.items.push(entry);
    if ((LICENSE_SEVERITY_RANK[entry.status] || 0) > (LICENSE_SEVERITY_RANK[g.status] || 0)) {
      g.status = entry.status;
    }
  }
  return Array.from(groups.values()).sort((a, b) => {
    // ⛔ Severity BEFORE date. A row whose expiry string did not parse, or whose
    // 'expired' verdict came from the device rather than a date, has no
    // timestamp to sort on and previously sank below healthy contracts 18
    // months out — burying exactly the rows that need attention, while the
    // summary tile still counted them as expired.
    const ar = LICENSE_SEVERITY_RANK[a.status] || 0;
    const br = LICENSE_SEVERITY_RANK[b.status] || 0;
    if (ar !== br) return br - ar;
    const av = a.expiresAt ? new Date(a.expiresAt).getTime() : Number.POSITIVE_INFINITY;
    const bv = b.expiresAt ? new Date(b.expiresAt).getTime() : Number.POSITIVE_INFINITY;
    if (av !== bv) return av - bv;
    return (a.device?.name || '').localeCompare(b.device?.name || '');
  });
}

// One-line label for a renewal group. A single entitlement shows its own name;
// several show a count that expands, so the detail is one click away rather
// than permanently occupying six rows.
function renewalLabel(group) {
  if (group.items.length === 1) return group.items[0].row.feature || '—';
  return `${group.items.length} entitlements`;
}

// Collapsed-section heading style. Native <details>/<summary> — server-rendered,
// zero client JS, matching this codebase's "a normal element over a client
// component when one suffices" instinct (same reasoning as the Fleet Map's
// plain <a> click-through).
const SECTION_SUMMARY_STYLE = {
  cursor: 'pointer',
  fontSize: 'var(--text-lg)',
  fontWeight: 700,
  color: 'var(--text-primary)',
};

const GAP_NOTE_STYLE = { margin: '12px 0 0', fontSize: 'var(--text-sm)', color: 'var(--text-muted)' };

// Human labels for PAN-OS's `<x>-compat` verdict keys.
const COMPAT_LABELS = {
  'build-compat': 'Software version',
  'url-compat': 'URL database',
  'app-compat': 'Application content',
  'iot-compat': 'IOT content',
  'av-compat': 'Antivirus',
  'threat-compat': 'Threat content',
  'vpnclient-compat': 'VPN client',
  'gpclient-compat': 'GlobalProtect client',
};

function compatLabel(key) {
  return COMPAT_LABELS[key] || key.replace(/-compat$/, '');
}

// Builds the per-pair "why is this degraded" evidence. Everything here comes
// from what the DEVICE reported — the mismatching components with BOTH sides'
// actual values, plus any licence on this device that plausibly explains a
// mismatch. Nothing is inferred: a lapsed URL-filtering licence is shown
// alongside a url-compat mismatch as CONTEXT, and deliberately not asserted as
// the cause, because SecVault only ever talks to the active member and cannot
// see the passive peer's own licence state.
function buildHaEvidence(row, licensesForDevice, now) {
  const compat = row.version_compat && typeof row.version_compat === 'object' ? row.version_compat : {};
  const versions = row.raw && typeof row.raw === 'object' && row.raw.versions ? row.raw.versions : {};

  const mismatches = Object.keys(compat)
    .filter((k) => String(compat[k]).toLowerCase() !== 'match')
    .map((k) => ({
      key: k,
      label: compatLabel(k),
      verdict: compat[k],
      local: versions[k] ? versions[k].local : null,
      peer: versions[k] ? versions[k].peer : null,
    }));

  // Surface only licences that are actually a problem — an expired/expiring
  // entitlement is the kind of thing that stops a content feed updating.
  const relevantLicences = (licensesForDevice || [])
    .map((l) => ({ row: l, st: licenseStatus(l, now) }))
    .filter(({ st }) => st.status === 'expired' || st.status === 'expiring')
    // Antisymmetric comparator: the previous form returned -1 for BOTH
    // cmp(a,b) and cmp(b,a) when both were expired, which is an invalid sort.
    .sort((a, b) => (a.st.status === 'expired' ? 0 : 1) - (b.st.status === 'expired' ? 0 : 1));

  return { mismatches, relevantLicences };
}
const SECTION_NOTE_STYLE = { margin: '8px 0 14px', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' };

export default async function LifecyclePage() {
  const { devices, licenses, haRows, content } = await getLifecycleData();
  const now = new Date();
  const deviceById = new Map(devices.map((d) => [d.id, d]));

  // ── Section 1: Support & Licence Expiry ────────────────────────────────
  // Everything that needs a human decision (expired / expiring / unparseable
  // expiry) PLUS every support contract regardless of status — a contract with
  // 18 months left is still the row a renewal budget is planned from.
  const licenseEntries = licenses
    .map((row) => ({ row, st: licenseStatus(row, now) }))
    .filter(
      ({ row, st }) =>
        st.status !== 'not_licensed' &&
        (st.status === 'expired' || st.status === 'expiring' || st.status === 'unknown' || isSupportContract(row))
    )
    .map(({ row, st }) => ({
      key: row.id,
      device: deviceById.get(row.device_id),
      row,
      status: st.status,
      delta: dayDelta(row.expires_at, now),
    }));

  const renewalGroups = groupLicenseRenewals(licenseEntries);
  const licenseDeviceIds = new Set(licenses.map((r) => r.device_id));
  const licenseGapDevices = devices.filter((d) => !licenseDeviceIds.has(d.id));

  // ── Section 2: High Availability ───────────────────────────────────────
  // Licences indexed per device so a degraded pair can show any expired /
  // expiring entitlement alongside its version mismatch.
  const licensesByDevice = new Map();
  for (const l of licenses) {
    if (!licensesByDevice.has(l.device_id)) licensesByDevice.set(l.device_id, []);
    licensesByDevice.get(l.device_id).push(l);
  }

  const haEntries = haRows
    .map((row) => ({ row, ha: haStatus(row), device: deviceById.get(row.device_id) }))
    .sort((a, b) => {
      const ar = HA_SORT_RANK[a.ha.status] ?? 9;
      const br = HA_SORT_RANK[b.ha.status] ?? 9;
      if (ar !== br) return ar - br;
      return (a.device?.name || '').localeCompare(b.device?.name || '');
    });

  const haDeviceIds = new Set(haRows.map((r) => r.device_id));
  const haGapDevices = devices.filter((d) => !haDeviceIds.has(d.id));

  // ── Section 3: Signature Freshness ─────────────────────────────────────
  const componentsPresent = Array.from(new Set(content.map((r) => r.component))).sort((a, b) => {
    const ai = COMPONENT_ORDER.indexOf(a);
    const bi = COMPONENT_ORDER.indexOf(b);
    if (ai !== bi) return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
    return a.localeCompare(b);
  });

  const sigByDevice = new Map();
  for (const row of content) {
    let entry = sigByDevice.get(row.device_id);
    if (!entry) {
      entry = { device: deviceById.get(row.device_id), byComponent: new Map(), worstAge: -1 };
      sigByDevice.set(row.device_id, entry);
    }
    const st = signatureStatus(row, now);
    entry.byComponent.set(row.component, { row, st });
    if (st.ageDays !== null && st.ageDays > entry.worstAge) entry.worstAge = st.ageDays;
  }
  const sigEntries = Array.from(sigByDevice.values()).sort((a, b) => {
    if (a.worstAge !== b.worstAge) return b.worstAge - a.worstAge;
    return (a.device?.name || '').localeCompare(b.device?.name || '');
  });
  const sigGapDevices = devices.filter((d) => !sigByDevice.has(d.id));

  // ── Summary tiles ──────────────────────────────────────────────────────
  // Counted over RENEWAL GROUPS, not individual entitlements, so the headline
  // number matches the number of rows (and real decisions) below it.
  const expiredCount = renewalGroups.filter((g) => g.status === 'expired').length;
  const expiringCount = renewalGroups.filter((g) => g.status === 'expiring').length;
  const degradedCount = haEntries.filter((e) => e.ha.status === 'degraded').length;
  const staleSigDevices = sigEntries.filter((e) =>
    Array.from(e.byComponent.values()).some((c) => c.st.status === 'stale')
  ).length;

  const haSummary = [
    `${haEntries.filter((e) => e.ha.status === 'healthy').length} healthy`,
    `${degradedCount} degraded`,
    `${haEntries.filter((e) => e.ha.status === 'standalone').length} standalone`,
    haGapDevices.length > 0 ? `${haGapDevices.length} not collected` : null,
  ]
    .filter(Boolean)
    .join(' · ');

  const oldestSig = sigEntries.length > 0 && sigEntries[0].worstAge >= 0 ? sigEntries[0].worstAge : null;
  // ⛔ TRI-STATE: a component whose device reported no release date resolves to
  // 'unknown', NOT 'stale'. Saying "all current" whenever the stale count is
  // zero therefore asserted freshness for devices whose age is simply unknown —
  // contradicting this very section's own note, and worse, the summary is what
  // is visible while the section is collapsed. Count unknowns explicitly.
  const unknownSigDevices = sigEntries.filter(
    (e) =>
      Array.from(e.byComponent.values()).some((c) => c.st.status === 'unknown') &&
      !Array.from(e.byComponent.values()).some((c) => c.st.status === 'stale')
  ).length;
  const sigSummary = [
    `${sigEntries.length} device${sigEntries.length === 1 ? '' : 's'}`,
    staleSigDevices > 0 ? `${staleSigDevices} with stale content` : null,
    unknownSigDevices > 0 ? `${unknownSigDevices} with unknown age` : null,
    staleSigDevices === 0 && unknownSigDevices === 0 && sigEntries.length > 0 ? 'all current' : null,
    oldestSig !== null ? `oldest ${oldestSig}d` : null,
    sigGapDevices.length > 0 ? `${sigGapDevices.length} not collected` : null,
  ]
    .filter(Boolean)
    .join(' · ');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <PageHeader
        title="Lifecycle &amp; Health"
        subtitle="Support contracts, HA state and signature freshness across the fleet."
      />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12 }}>
        <StatCard
          label="Expired"
          value={expiredCount}
          sub="renewal events"
          color={expiredCount > 0 ? 'var(--red)' : 'var(--text-muted)'}
        />
        <StatCard
          label="Expiring soon"
          value={expiringCount}
          sub="within 60 days"
          color={expiringCount > 0 ? 'var(--yellow)' : 'var(--text-muted)'}
        />
        <StatCard
          label="HA degraded"
          value={degradedCount}
          sub={`${haEntries.length} with HA data`}
          color={degradedCount > 0 ? 'var(--red)' : 'var(--text-muted)'}
        />
        <StatCard
          label="Stale content"
          value={staleSigDevices}
          sub="devices"
          color={staleSigDevices > 0 ? 'var(--yellow)' : 'var(--text-muted)'}
        />
        <StatCard
          label="Not collected"
          value={licenseGapDevices.length}
          sub="devices"
          color="var(--text-muted)"
        />
      </div>

      {/* Support &amp; Licence Renewals — expanded by default: the primary use. */}
      <Card>
        <CardBody>
          <div
            style={{
              fontSize: 'var(--text-lg)',
              fontWeight: 700,
              color: 'var(--text-primary)',
              marginBottom: 4,
            }}
          >
            Support &amp; Licence Renewals
          </div>
          <p style={{ margin: '0 0 14px', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            One row per renewal event — entitlements on the same device sharing an expiry date are grouped, since
            they renew together. Soonest first. Expand a group to see what it covers.
          </p>

          {renewalGroups.length === 0 && licenseGapDevices.length === 0 ? (
            <EmptyState message="No licence or support-contract data has been collected for any device yet." />
          ) : (
            <>
              <Table>
                <colgroup>
                  <col style={{ width: '20%' }} />
                  <col style={{ width: '42%' }} />
                  <col style={{ width: '14%' }} />
                  <col style={{ width: '12%' }} />
                  <col style={{ width: '12%' }} />
                </colgroup>
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>Covers</th>
                    <th>Expires</th>
                    <th>Status</th>
                    <th>Days</th>
                  </tr>
                </thead>
                <tbody>
                  {renewalGroups.map((g) => (
                    <tr key={g.key}>
                      <td title={g.device?.name || ''}>{g.device ? deviceLink(g.device.id, g.device.name) : '—'}</td>
                      <td>
                        {g.items.length === 1 ? (
                          <span title={g.items[0].row.description || ''}>{renewalLabel(g)}</span>
                        ) : (
                          <details>
                            <summary style={{ cursor: 'pointer' }}>{renewalLabel(g)}</summary>
                            <ul
                              style={{
                                margin: '6px 0 0',
                                paddingLeft: 18,
                                color: 'var(--text-secondary)',
                                fontSize: 'var(--text-sm)',
                              }}
                            >
                              {g.items.map((it) => (
                                <li key={it.key}>{it.row.feature || '—'}</li>
                              ))}
                            </ul>
                          </details>
                        )}
                      </td>
                      <td>{formatDate(g.expiresAt) || g.expiresRaw || '—'}</td>
                      <td>{licenseBadge(g.status)}</td>
                      <td style={{ color: g.status === 'expired' ? 'var(--red)' : 'var(--text-secondary)' }}>
                        {daysText(g.delta)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>

              {/* Coverage gaps stay VISIBLE (this page's honesty rule) but as one
                  line rather than one identical row per device. */}
              {licenseGapDevices.length > 0 && (
                <p style={GAP_NOTE_STYLE}>
                  {notCollectedBadge()}{' '}
                  <span style={{ marginLeft: 6 }}>
                    {`Licence data is not collected for ${licenseGapDevices.length} device${
                      licenseGapDevices.length === 1 ? '' : 's'
                    }: ${licenseGapDevices.map((d) => d.name).join(', ')}.`}
                  </span>
                </p>
              )}
            </>
          )}
        </CardBody>
      </Card>

      {/* High Availability — collapsed, with a one-line summary always visible. */}
      <Card>
        <CardBody>
          <details>
            <summary style={SECTION_SUMMARY_STYLE}>High Availability</summary>
            <p style={SECTION_NOTE_STYLE}>
              Degraded pairs first. &ldquo;Standalone&rdquo; is a fact the device reported, not a gap — a device that
              was never asked shows as &ldquo;Not collected&rdquo;.
            </p>

            {haEntries.length === 0 && haGapDevices.length === 0 ? (
              <EmptyState message="No HA state has been collected for any device yet." />
            ) : (
              <>
                <Table>
                  <colgroup>
                    <col style={{ width: '18%' }} />
                    <col style={{ width: '16%' }} />
                    <col style={{ width: '13%' }} />
                    <col style={{ width: '13%' }} />
                    <col style={{ width: '16%' }} />
                    <col style={{ width: '13%' }} />
                    <col style={{ width: '11%' }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th>Device</th>
                      <th>Mode</th>
                      <th>Local State</th>
                      <th>Peer State</th>
                      <th>Peer IP</th>
                      <th>Config Sync</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {haEntries.map(({ row, ha, device }) => {
                      const evidence = buildHaEvidence(row, licensesByDevice.get(row.device_id), now);
                      const showWhy =
                        ha.status === 'degraded' &&
                        (ha.reasons.length > 0 || evidence.mismatches.length > 0 || evidence.relevantLicences.length > 0);
                      const dataRow = (
                        <tr key={row.device_id}>
                          <td title={device?.name || ''}>{device ? deviceLink(device.id, device.name) : '—'}</td>
                          <td>{row.enabled ? row.mode || 'Enabled' : '—'}</td>
                          <td>{row.local_state || '—'}</td>
                          <td>{row.peer_state || '—'}</td>
                          <td className="mono">{row.peer_mgmt_ip || '—'}</td>
                          <td>{row.config_sync_state || '—'}</td>
                          <td>{haBadge(ha.status)}</td>
                        </tr>
                      );
                      // The evidence gets its OWN full-width row rather than living
                      // inside the ~11% Status column, where version strings and
                      // licence names were clipped at the table's right edge.
                      // <details> cannot span two <tr>s, so the disclosure itself
                      // moves down here with them.
                      const whyRow = showWhy ? (
                        <tr key={`${row.device_id}-why`}>
                          <td colSpan={7} style={{ paddingTop: 0 }}>
                            <details>
                              <summary
                                style={{ cursor: 'pointer', fontSize: 'var(--text-xs)', color: 'var(--primary)' }}
                              >
                                Why is {device?.name || 'this pair'} degraded?
                              </summary>
                              <div
                                style={{
                                  marginTop: 8,
                                  fontSize: 'var(--text-sm)',
                                  color: 'var(--text-secondary)',
                                  display: 'flex',
                                  flexWrap: 'wrap',
                                  gap: 24,
                                }}
                              >
                                <div style={{ minWidth: 280, flex: '1 1 320px' }}>
                                  {ha.reasons.length > 0 && (
                                    <ul style={{ margin: '0 0 8px', paddingLeft: 18 }}>
                                      {ha.reasons.map((r) => (
                                        <li key={r}>{r}</li>
                                      ))}
                                    </ul>
                                  )}
                                  {/* Only the XML/API transport reports both sides' actual
                                      version strings; the SSH form prints just the
                                      Match/Mismatch verdict. Without this fallback an
                                      SSH-managed pair rendered a useless "— (this) vs —
                                      (peer)" while the verdict it DID have went unshown. */}
                                  {evidence.mismatches.map((m) => (
                                    <div key={m.key} style={{ marginBottom: 4 }}>
                                      <span style={{ color: 'var(--text-primary)' }}>{m.label}: </span>
                                      {m.local || m.peer ? (
                                        <>
                                          <span className="mono">{m.local || '—'}</span>
                                          <span style={{ color: 'var(--text-muted)' }}> (this) vs </span>
                                          <span className="mono">{m.peer || '—'}</span>
                                          <span style={{ color: 'var(--text-muted)' }}> (peer)</span>
                                        </>
                                      ) : (
                                        <>
                                          <span className="mono">{m.verdict}</span>
                                          <span style={{ color: 'var(--text-muted)' }}>
                                            {' '}— this device reports the verdict only, not each side&apos;s version
                                          </span>
                                        </>
                                      )}
                                    </div>
                                  ))}
                                </div>
                                {evidence.relevantLicences.length > 0 && (
                                  <div style={{ minWidth: 260, flex: '1 1 300px' }}>
                                    <span style={{ color: 'var(--text-muted)' }}>
                                      Licences on this member that may be related:
                                    </span>
                                    <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
                                      {evidence.relevantLicences.map(({ row: l, st }) => (
                                        <li key={l.id}>
                                          {l.feature} — {st.status === 'expired' ? 'expired' : 'expiring'}{' '}
                                          {formatDate(l.expires_at) || l.expires_raw || ''}
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                              </div>
                            </details>
                          </td>
                        </tr>
                      ) : null;
                      return [dataRow, whyRow];
                    })}
                  </tbody>
                </Table>
                {haGapDevices.length > 0 && (
                  <p style={GAP_NOTE_STYLE}>
                    {notCollectedBadge()}{' '}
                    <span style={{ marginLeft: 6 }}>
                      {`HA state is not collected for ${haGapDevices.length} device${
                        haGapDevices.length === 1 ? '' : 's'
                      }: ${haGapDevices.map((d) => d.name).join(', ')}.`}
                    </span>
                  </p>
                )}
              </>
            )}
          </details>
          <p style={{ margin: '8px 0 0', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>{haSummary}</p>
        </CardBody>
      </Card>

      {/* Signature Freshness — collapsed, with a one-line summary always visible. */}
      <Card>
        <CardBody>
          <details>
            <summary style={SECTION_SUMMARY_STYLE}>Signature Freshness</summary>
            <p style={SECTION_NOTE_STYLE}>
              Content versions and their age, oldest fleet-wide first. A component whose device reported no release
              date shows its version with an unknown age — never a confident &ldquo;current&rdquo;.
            </p>

            {componentsPresent.length === 0 && sigGapDevices.length === 0 ? (
              <EmptyState message="No content or signature versions have been collected for any device yet." />
            ) : componentsPresent.length === 0 ? (
              <p style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
                Content and signature versions are not collected for any device in this fleet yet.
              </p>
            ) : (
              <>
                <Table>
                  <colgroup>
                    <col style={{ width: `${Math.max(16, 100 - componentsPresent.length * 14)}%` }} />
                    {componentsPresent.map((c) => (
                      <col key={c} style={{ width: '14%' }} />
                    ))}
                  </colgroup>
                  <thead>
                    <tr>
                      <th>Device</th>
                      {componentsPresent.map((c) => (
                        <th key={c}>{componentLabel(c)}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {sigEntries.map((entry) => (
                      <tr key={entry.device?.id || entry.worstAge}>
                        <td title={entry.device?.name || ''}>
                          {entry.device ? deviceLink(entry.device.id, entry.device.name) : '—'}
                        </td>
                        {componentsPresent.map((c) => {
                          const cell = entry.byComponent.get(c);
                          if (!cell) {
                            return (
                              <td key={c} style={{ color: 'var(--text-muted)' }}>
                                —
                              </td>
                            );
                          }
                          const ageLabel =
                            cell.st.ageDays === null
                              ? 'age unknown'
                              : cell.st.ageDays === 0
                                ? 'today'
                                : `${cell.st.ageDays}d old`;
                          return (
                            <td key={c} title={`${cell.row.version || '—'} · ${ageLabel}`}>
                              <div className="mono" style={{ color: 'var(--text-primary)' }}>
                                {cell.row.version || '—'}
                              </div>
                              <div
                                style={{
                                  fontSize: 'var(--text-xs)',
                                  color: cell.st.status === 'stale' ? 'var(--yellow)' : 'var(--text-muted)',
                                }}
                              >
                                {ageLabel}
                              </div>
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </Table>
                {sigGapDevices.length > 0 && (
                  <p style={GAP_NOTE_STYLE}>
                    {notCollectedBadge()}{' '}
                    <span style={{ marginLeft: 6 }}>
                      {`Content versions are not collected for ${sigGapDevices.length} device${
                        sigGapDevices.length === 1 ? '' : 's'
                      }: ${sigGapDevices.map((d) => d.name).join(', ')}.`}
                    </span>
                  </p>
                )}
              </>
            )}
          </details>
          <p style={{ margin: '8px 0 0', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>{sigSummary}</p>
        </CardBody>
      </Card>
    </div>
  );
}
