import Link from 'next/link';
import { pool } from '../../../lib/db';
import PageHeader from '../../../components/ui/PageHeader';
import Card, { CardBody } from '../../../components/ui/Card';
import Table from '../../../components/ui/Table';
import Badge from '../../../components/ui/Badge';
import EmptyState from '../../../components/ui/EmptyState';
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
  if (typeof row.feature === 'string' && SUPPORT_TIER_FEATURES.test(row.feature.trim())) return true;
  return typeof row.description === 'string' && /support/i.test(row.description);
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
              h.version_compat_ok
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

export default async function LifecyclePage() {
  const { devices, licenses, haRows, content } = await getLifecycleData();
  const now = new Date();
  const deviceById = new Map(devices.map((d) => [d.id, d]));

  // ── Section 1: Support & Licence Expiry ────────────────────────────────
  // Everything that needs a human decision (expired / expiring / unparseable
  // expiry) PLUS every support contract regardless of status — a contract with
  // 18 months left is still the row a renewal budget is planned from.
  const licenseRows = licenses
    .map((row) => ({ row, st: licenseStatus(row, now) }))
    .filter(({ row, st }) => st.status === 'expired' || st.status === 'expiring' || st.status === 'unknown' || isSupportContract(row))
    .map(({ row, st }) => ({
      key: row.id,
      device: deviceById.get(row.device_id),
      row,
      status: st.status,
      delta: dayDelta(row.expires_at, now),
    }))
    .sort((a, b) => {
      // Soonest expiry first; anything with no parsed date (perpetual or
      // unparseable) sorts last rather than to the top as an epoch-zero date.
      const av = a.row.expires_at ? new Date(a.row.expires_at).getTime() : Number.POSITIVE_INFINITY;
      const bv = b.row.expires_at ? new Date(b.row.expires_at).getTime() : Number.POSITIVE_INFINITY;
      if (av !== bv) return av - bv;
      return (a.device?.name || '').localeCompare(b.device?.name || '');
    });

  const licenseDeviceIds = new Set(licenses.map((r) => r.device_id));
  const licenseGapDevices = devices.filter((d) => !licenseDeviceIds.has(d.id));

  // ── Section 2: High Availability ───────────────────────────────────────
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <PageHeader
        title="Lifecycle & Health"
        subtitle="Support contracts, HA state, disk and signature freshness across the fleet."
      />

      {/* ── Support & Licence Expiry ─────────────────────────────────── */}
      <Card>
        <CardBody>
          <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
            Support &amp; Licence Expiry
          </div>
          <p style={{ margin: '0 0 16px', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            Every expired, expiring or unreadable entitlement, plus every support contract regardless of status.
            Soonest expiry first.
          </p>

          {licenseRows.length === 0 && licenseGapDevices.length === 0 ? (
            <EmptyState message="No licence or support-contract data has been collected for any device yet." />
          ) : (
            <Table>
              <colgroup>
                <col style={{ width: '16%' }} />
                <col style={{ width: '17%' }} />
                <col style={{ width: '29%' }} />
                <col style={{ width: '13%' }} />
                <col style={{ width: '13%' }} />
                <col style={{ width: '12%' }} />
              </colgroup>
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Feature</th>
                  <th>Description</th>
                  <th>Expires</th>
                  <th>Status</th>
                  <th>Days</th>
                </tr>
              </thead>
              <tbody>
                {licenseRows.map(({ key, device, row, status, delta }) => (
                  <tr key={key}>
                    <td title={device?.name || ''}>{device ? deviceLink(device.id, device.name) : '—'}</td>
                    <td title={row.feature || ''}>{row.feature || '—'}</td>
                    <td title={row.description || ''} style={{ color: 'var(--text-secondary)' }}>
                      {row.description || '—'}
                    </td>
                    <td>{formatDate(row.expires_at) || row.expires_raw || '—'}</td>
                    <td>{licenseBadge(status)}</td>
                    <td style={{ color: status === 'expired' ? 'var(--red)' : 'var(--text-secondary)' }}>
                      {daysText(delta)}
                    </td>
                  </tr>
                ))}
                {licenseGapDevices.map((d) => (
                  <tr key={`gap-${d.id}`}>
                    <td title={d.name}>{deviceLink(d.id, d.name)}</td>
                    <td colSpan={3} style={{ color: 'var(--text-muted)' }}>
                      Licence data is not collected for {d.vendor} devices yet.
                    </td>
                    <td>{notCollectedBadge()}</td>
                    <td style={{ color: 'var(--text-muted)' }}>—</td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </CardBody>
      </Card>

      {/* ── High Availability ────────────────────────────────────────── */}
      <Card>
        <CardBody>
          <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
            High Availability
          </div>
          <p style={{ margin: '0 0 16px', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            Degraded pairs first. &ldquo;Standalone&rdquo; is a fact the device reported, not a gap — a device that was
            never asked shows as &ldquo;Not collected&rdquo;.
          </p>

          {haEntries.length === 0 && haGapDevices.length === 0 ? (
            <EmptyState message="No HA state has been collected for any device yet." />
          ) : (
            <Table>
              <colgroup>
                <col style={{ width: '17%' }} />
                <col style={{ width: '15%' }} />
                <col style={{ width: '12%' }} />
                <col style={{ width: '12%' }} />
                <col style={{ width: '15%' }} />
                <col style={{ width: '15%' }} />
                <col style={{ width: '14%' }} />
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
                {haEntries.map(({ row, ha, device }) => (
                  <tr key={row.device_id}>
                    <td title={device?.name || ''}>{device ? deviceLink(device.id, device.name) : '—'}</td>
                    <td>{row.enabled ? row.mode || 'Enabled' : '—'}</td>
                    <td>{row.local_state || '—'}</td>
                    <td>{row.peer_state || '—'}</td>
                    <td className="mono">{row.peer_mgmt_ip || '—'}</td>
                    <td>{row.config_sync_state || '—'}</td>
                    {/* Reasons live in the title attribute (a single string, not
                        a JSX child) so a degraded pair explains itself on hover
                        without a seventh column of prose. */}
                    <td title={ha.reasons.join(' ') || undefined}>{haBadge(ha.status)}</td>
                  </tr>
                ))}
                {haGapDevices.map((d) => (
                  <tr key={`gap-${d.id}`}>
                    <td title={d.name}>{deviceLink(d.id, d.name)}</td>
                    <td colSpan={5} style={{ color: 'var(--text-muted)' }}>
                      HA state is not collected for {d.vendor} devices yet.
                    </td>
                    <td>{notCollectedBadge()}</td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </CardBody>
      </Card>

      {/* ── Signature Freshness ──────────────────────────────────────── */}
      <Card>
        <CardBody>
          <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
            Signature Freshness
          </div>
          <p style={{ margin: '0 0 16px', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
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
                        cell.st.ageDays === null ? 'age unknown'
                          : cell.st.ageDays === 0 ? 'today'
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
                {sigGapDevices.map((d) => (
                  <tr key={`gap-${d.id}`}>
                    <td title={d.name}>{deviceLink(d.id, d.name)}</td>
                    <td colSpan={componentsPresent.length} style={{ color: 'var(--text-muted)' }}>
                      {notCollectedBadge()}
                      <span style={{ marginLeft: 8 }}>
                        Content versions are not collected for {d.vendor} devices yet.
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
