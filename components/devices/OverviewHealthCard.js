import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import StatCard from '../ui/StatCard';
import {
  worstLicenseStatus,
  worstSignatureStatus,
  haStatus,
  diskStatus,
  licenseStatus,
} from '../../lib/engines/deviceHealth';

// Overview-tab card: the device's lifecycle & health snapshot (support/licence
// expiry, HA state, disk pressure, signature freshness) collected 2026-08-03
// into device_licenses / device_ha_status / device_disk_usage /
// device_content_versions. Async server component with its OWN queries — same
// "widget owns its DB access" convention as OverviewCveCard.js /
// OverviewComplianceCard.js.
//
// ⛔ Every derived verdict comes from lib/engines/deviceHealth.js — that module
// is the single place the expiry window / staleness threshold / disk bands /
// HA degradation reasons live, and it is already fixture-tested. Nothing here
// re-implements any of it; this file only turns its return values into labels
// and colours.
//
// COVERAGE GAP IS A FIRST-CLASS STATE. Only adapters implementing the optional
// getLicenses()/getHaStatus()/getDiskUsage() methods populate these tables
// (Palo Alto, both transports, as of this add) — every other vendor simply has
// zero rows. That renders as a calm one-liner, NOT an EmptyState box and NOT a
// zero: "0% disk used" or "no licences" would both read as collected facts
// about a healthy device, which is exactly the false reassurance the tri-state
// discipline in deviceHealth.js exists to prevent. Same calm-empty-state
// precedent as OverviewExposureCard.js.

// Friendly labels for device_content_versions.component's fixed vocabulary.
const COMPONENT_LABELS = {
  app: 'App',
  av: 'Antivirus',
  threat: 'Threat',
  wildfire: 'WildFire',
  url_filtering: 'URL Filtering',
  device_dictionary: 'Device Dictionary',
};

function componentLabel(component) {
  if (!component) return null;
  return COMPONENT_LABELS[component] || component;
}

// DATE columns come back from node-postgres as a local-midnight Date, so the
// local getters are the correct read — toISOString() would shift the day for
// any non-UTC server timezone (a licence expiring 2021-12-25 rendering as
// 2021-12-24 on a UTC+7 box).
function formatDate(value) {
  if (!value) return null;
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

// The expiry text for a licence row: the parsed date when there is one, else
// the vendor's own verbatim string (which is what distinguishes 'Never' from
// an unparseable value — see device_licenses.expires_raw's schema comment).
function expiryText(row) {
  if (!row) return null;
  return formatDate(row.expires_at) || row.expires_raw || null;
}

async function getHealthData(deviceId) {
  const [licenses, ha, disks, content] = await Promise.all([
    pool.query(
      `SELECT feature, description, expires_at, expires_raw, expired
       FROM device_licenses WHERE device_id = $1`,
      [deviceId]
    ),
    pool.query(
      `SELECT enabled, mode, local_state, peer_state, peer_mgmt_ip,
              peer_connection_status, config_sync_state, last_nonfunctional_reason,
              version_compat_ok
       FROM device_ha_status WHERE device_id = $1`,
      [deviceId]
    ),
    pool.query(
      `SELECT filesystem, mounted_on, use_percent
       FROM device_disk_usage WHERE device_id = $1`,
      [deviceId]
    ),
    pool.query(
      `SELECT component, version, released_at
       FROM device_content_versions WHERE device_id = $1`,
      [deviceId]
    ),
  ]);
  return {
    licenses: licenses.rows,
    haRow: ha.rows[0] || null,
    disks: disks.rows,
    content: content.rows,
  };
}

export default async function OverviewHealthCard({ deviceId }) {
  const { licenses, haRow, disks, content } = await getHealthData(deviceId);
  const now = new Date();

  const hasAnyData = licenses.length > 0 || haRow !== null || disks.length > 0 || content.length > 0;

  // ── Support / licences
  const worstLicense = worstLicenseStatus(licenses, now);
  const expiredCount = licenses.filter((r) => licenseStatus(r, now).status === 'expired').length;

  let licenseValue = 'Unknown';
  let licenseSub = null;
  let licenseColor = 'var(--text-muted)';
  if (worstLicense.status === 'expired') {
    licenseValue = `${expiredCount} expired`;
    licenseColor = 'var(--red)';
  } else if (worstLicense.status === 'expiring') {
    licenseValue = `Expires in ${worstLicense.daysRemaining}d`;
    licenseColor = 'var(--yellow)';
  } else if (worstLicense.status === 'ok' || worstLicense.status === 'perpetual') {
    licenseValue = 'OK';
    licenseColor = 'var(--text-muted)';
  } else if (worstLicense.status === 'not_licensed') {
    // The device DEFINITIVELY reported these components as unlicensed
    // ('Contract Expiry Date: n/a'). Falling through to 'Unknown' here implied
    // missing information and invited an investigation with nothing to find —
    // the same distinction licenseStatus() exists to preserve.
    licenseValue = 'None';
    licenseColor = 'var(--text-muted)';
  }
  if (worstLicense.row) {
    const when = expiryText(worstLicense.row);
    licenseSub = when ? `${worstLicense.row.feature} · expires ${when}` : worstLicense.row.feature;
  } else if (licenses.length === 0) {
    licenseSub = 'Not collected';
  }

  // ── HA
  const ha = haStatus(haRow);
  let haValue = 'Unknown';
  let haSub = haRow ? null : 'Not collected';
  let haColor = 'var(--text-muted)';
  if (ha.status === 'degraded') {
    haValue = 'Degraded';
    haColor = 'var(--red)';
    haSub = ha.reasons[0] || (haRow && haRow.mode) || null;
  } else if (ha.status === 'healthy') {
    haValue = (haRow && haRow.mode) || 'Enabled';
    haColor = 'var(--accent-teal)';
    haSub = haRow && haRow.peer_mgmt_ip ? `Peer ${haRow.peer_mgmt_ip}` : 'Peer healthy';
  } else if (ha.status === 'standalone') {
    haValue = 'Standalone';
    haColor = 'var(--text-muted)';
    haSub = 'Not part of an HA pair';
  }

  // ── Disk
  const disk = diskStatus(disks);
  const diskValue = disk.usePercent === null ? '—' : `${disk.usePercent}%`;
  const diskColor =
    disk.status === 'critical' ? 'var(--red)'
      : disk.status === 'warning' ? 'var(--yellow)'
        : 'var(--text-muted)';
  const diskSub =
    disk.row ? (disk.row.mounted_on || disk.row.filesystem || null)
      : disks.length === 0 ? 'Not collected'
        : 'No usable percentage reported';

  // ── Signatures
  const worstSig = worstSignatureStatus(content, now);
  let sigValue = 'Unknown';
  let sigColor = 'var(--text-muted)';
  if (worstSig.status === 'stale') {
    sigValue = `${worstSig.ageDays}d old`;
    sigColor = 'var(--yellow)';
  } else if (worstSig.status === 'ok') {
    sigValue = 'Current';
    sigColor = 'var(--text-muted)';
  }
  const sigSub =
    worstSig.row ? componentLabel(worstSig.row.component)
      : content.length === 0 ? 'Not collected'
        : 'No release dates reported';

  // These four tiles carry TEXT values ('Degraded', 'Expires in 17d') rather
  // than the short numerals .stat-value was designed for (--text-2xl with -1px
  // letter-spacing). At the default size and a 140px min column they wrapped
  // and ran into the tile edges, so the `compact` variant (--text-lg value,
  // smaller sub) plus a wider min column is the correct fit here — the same
  // reason the main Dashboard's denser grid uses it.

  return (
    <Card>
      <CardBody>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'baseline', justifyContent: 'space-between', gap: 12, marginBottom: 16 }}>
          <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)' }}>
            Lifecycle &amp; Health
          </div>
          <Link href="/lifecycle" style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
            Fleet view →
          </Link>
        </div>

        {!hasAnyData ? (
          <p style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
            Lifecycle data is not collected for this vendor yet.
          </p>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
            <StatCard compact label="Support / Licences" value={licenseValue} sub={licenseSub} color={licenseColor} />
            <StatCard compact label="HA" value={haValue} sub={haSub} color={haColor} />
            <StatCard compact label="Disk" value={diskValue} sub={diskSub} color={diskColor} />
            <StatCard compact label="Signatures" value={sigValue} sub={sigSub} color={sigColor} />
          </div>
        )}
      </CardBody>
    </Card>
  );
}
