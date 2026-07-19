import Link from 'next/link';
import { pool } from '../../../../../lib/db';
import PageHeader from '../../../../../components/ui/PageHeader';
import Badge from '../../../../../components/ui/Badge';
import Card, { CardBody } from '../../../../../components/ui/Card';
import EmptyState from '../../../../../components/ui/EmptyState';
import VpnSessionTrendChart from '../../../../../components/vpn/VpnSessionTrendChart';
import { summarizeVpnConfig } from '../../../../../lib/engines/vpnSummary';
import { isValidUuid } from '../../../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

// Per-device VPN Summary — config-derived (device_configs.config_parsed),
// NOT log/session-report data (that needs syslog ingestion — see CLAUDE.md's
// Phase 8 notes). Mirrors this app's "server component queries the DB
// directly" convention throughout (see compliance/[deviceId]/page.js,
// devices/[id]/analysis/page.js). lib/engines/vpnSummary.js does the actual
// per-vendor interpretation of config_parsed — this page only renders
// whatever it returns.

function formatDateTime(value) {
  if (!value) return 'Never';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'Never';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

async function getDevice(dbPool, id) {
  const result = await dbPool.query('SELECT id, name, vendor FROM devices WHERE id = $1', [id]);
  return result.rows[0] || null;
}

// Latest config_parsed snapshot for this device, or null if none collected
// yet — same "most recent row by collected_at" query shape used elsewhere
// in this app for device_configs (see lib/engines/applicability.js's
// getLatestConfigParsed, which this mirrors rather than imports, since that
// one is scoped to the Phase 6/7 predicate engines specifically).
async function getLatestConfigParsed(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT config_parsed, collected_at
     FROM device_configs
     WHERE device_id = $1
     ORDER BY collected_at DESC
     LIMIT 1`,
    [deviceId]
  );
  return result.rows[0] || null;
}

async function getVpnSessionHistory(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT active_session_count, sampled_at
     FROM vpn_session_snapshots
     WHERE device_id = $1
     ORDER BY sampled_at ASC`,
    [deviceId]
  );
  return result.rows;
}

function notFound() {
  return (
    <div>
      <Link href="/devices" style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
        ← Back to Devices
      </Link>
      <p style={{ marginTop: 16, color: 'var(--text-secondary)' }}>Device not found.</p>
    </div>
  );
}

// Plain function returning JSX, not a nested component — same pattern
// as this app's other imperatively-called JSX helpers (CLAUDE.md's
// "NEVER define a React component inside another React component" rule
// only applies to actual component definitions rendered as <Tag/>).
function fieldRow(label, value) {
  if (value === null || value === undefined || value === '') return null;
  return (
    <div key={label} style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
      <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>{label}</span>
      <span style={{ color: 'var(--text-primary)', fontSize: 'var(--text-sm)', fontWeight: 600 }} className="mono">
        {String(value)}
      </span>
    </div>
  );
}

export default async function DeviceVpnPage({ params }) {
  if (!isValidUuid(params.id)) {
    return notFound();
  }

  const device = await getDevice(pool, params.id);
  if (!device) {
    return notFound();
  }

  const [configRow, sessionHistory] = await Promise.all([
    getLatestConfigParsed(pool, device.id),
    getVpnSessionHistory(pool, device.id),
  ]);

  const summary = summarizeVpnConfig(device.vendor, configRow ? configRow.config_parsed : null);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <Link href={`/devices/${device.id}`} style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
          ← Back to {device.name}
        </Link>
      </div>

      <PageHeader
        title={`VPN — ${device.name}`}
        subtitle={
          <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Badge color="info">{device.vendor}</Badge>
            <span>Config as of: {formatDateTime(configRow ? configRow.collected_at : null)}</span>
          </span>
        }
        actions={
          sessionHistory.length > 0 && (
            <a href={`/api/devices/${device.id}/vpn?format=csv`} className="btn btn-secondary">
              Export Session History CSV
            </a>
          )
        }
      />

      {!summary.supported ? (
        <EmptyState message={`VPN config collection is not yet implemented for "${device.vendor}" devices.`} />
      ) : !summary.hasConfig ? (
        <EmptyState message="No VPN configuration found on this device's latest collected config (or none collected yet)." />
      ) : (
        <Card>
          <CardBody>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              <span style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)' }}>
                SSL-VPN / Remote Access
              </span>
              {summary.enabled === true && <Badge color="success">Enabled</Badge>}
              {summary.enabled === false && <Badge color="muted">Disabled</Badge>}
              {/* enabled === null/undefined (Sangfor's tri-state, or a vendor like
                  Fortinet/Palo Alto whose config was found but this module doesn't
                  infer a confident on/off state for — see vpnSummary.js's own
                  comments, and the identical fallback in the fleet vpn/page.js). */}
              {(summary.enabled === null || summary.enabled === undefined) && (
                <Badge color="warning">Configured (state unknown)</Badge>
              )}
              {summary.lowConfidence && (
                <Badge color="warning">Low confidence — doc-derived, unverified for this vendor</Badge>
              )}
            </div>

            {summary.foundAt && (
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginBottom: 12 }}>
                Found in config at: <span className="mono">{summary.foundAt}</span>
              </p>
            )}

            <div>
              {fieldRow('Source interface', summary.sourceInterface)}
              {fieldRow('Port', summary.port)}
              {fieldRow('Idle timeout', summary.idleTimeout)}
              {fieldRow('Minimum TLS version', summary.minTlsVersion)}
              {Object.keys(summary.fields || {}).length === 0 &&
                !summary.sourceInterface &&
                !summary.port && (
                  <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', paddingTop: 8 }}>
                    VPN block found but carries no directly-modeled fields — see raw config for detail.
                  </p>
                )}
            </div>
          </CardBody>
        </Card>
      )}

      {sessionHistory.length > 0 ? (
        <VpnSessionTrendChart points={sessionHistory} />
      ) : (
        <EmptyState message="No VPN session polling data yet. Active-session polling is currently only implemented for Fortinet devices (SSH/REST) — see CLAUDE.md's VPN Session Polling notes." />
      )}
    </div>
  );
}
