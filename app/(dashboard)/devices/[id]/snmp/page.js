import Link from 'next/link';
import { pool } from '../../../../../lib/db';
import PageHeader from '../../../../../components/ui/PageHeader';
import Badge from '../../../../../components/ui/Badge';
import Card, { CardBody } from '../../../../../components/ui/Card';
import StatCard from '../../../../../components/ui/StatCard';
import EmptyState from '../../../../../components/ui/EmptyState';
import SnmpMetricsCharts from '../../../../../components/snmp/SnmpMetricsCharts';
import SnmpConfigForm from '../../../../../components/devices/SnmpConfigForm';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { detectSnmpConfig, looksConfigured } from '../../../../../lib/engines/snmpConfigDetection';

export const dynamic = 'force-dynamic';

// Per-device SNMP monitoring page — config form + polled metric trend.
// Mirrors devices/[id]/vpn/page.js's shape exactly (server component
// queries the DB directly; the API route exists for CSV export and the
// client-side config form's own PUT).

const LOW_CONFIDENCE_VENDORS = new Set(['paloalto', 'forcepoint', 'sangfor']);

function formatDateTime(value) {
  if (!value) return 'Never';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'Never';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

function formatUptime(seconds) {
  if (seconds === null || seconds === undefined) return '—';
  const s = Number(seconds);
  if (!Number.isFinite(s) || s < 0) return '—';
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const mins = Math.floor((s % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

async function getDevice(dbPool, id) {
  const result = await dbPool.query(
    `SELECT id, name, vendor, mgmt_ip, snmp_enabled, snmp_host, snmp_port
     FROM devices WHERE id = $1`,
    [id]
  );
  return result.rows[0] || null;
}

async function hasSnmpCredential(dbPool, id) {
  const result = await dbPool.query(
    'SELECT 1 FROM device_credentials WHERE device_id = $1 AND credential_type = $2 LIMIT 1',
    [id, 'snmp']
  );
  return result.rows.length > 0;
}

async function getSnmpHistory(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT cpu_percent, memory_percent, session_count, uptime_seconds, sampled_at
     FROM snmp_metric_snapshots
     WHERE device_id = $1
     ORDER BY sampled_at ASC`,
    [deviceId]
  );
  return result.rows;
}

async function getLatestConfigParsed(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT config_parsed FROM device_configs WHERE device_id = $1 ORDER BY collected_at DESC LIMIT 1`,
    [deviceId]
  );
  return result.rows[0] || null;
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

export default async function DeviceSnmpPage({ params }) {
  if (!isValidUuid(params.id)) {
    return notFound();
  }

  const device = await getDevice(pool, params.id);
  if (!device) {
    return notFound();
  }

  const [history, hasCredential, configRow] = await Promise.all([
    getSnmpHistory(pool, device.id),
    hasSnmpCredential(pool, device.id),
    device.snmp_enabled ? Promise.resolve(null) : getLatestConfigParsed(pool, device.id),
  ]);

  const latest = history.length > 0 ? history[history.length - 1] : null;
  const lowConfidence = LOW_CONFIDENCE_VENDORS.has(device.vendor);
  const snmpDetected = configRow ? detectSnmpConfig(device.vendor, configRow.config_parsed) : null;
  const snmpDetectedLooksConfigured = snmpDetected ? looksConfigured(snmpDetected) : false;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <Link href={`/devices/${device.id}`} style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
          ← Back to {device.name}
        </Link>
      </div>

      <PageHeader
        title={`SNMP Monitoring — ${device.name}`}
        subtitle={
          <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Badge color="info">{device.vendor}</Badge>
            {device.snmp_enabled ? <Badge color="success">Polling Enabled</Badge> : <Badge color="muted">Disabled</Badge>}
            {lowConfidence && <Badge color="warning">Low confidence — doc-derived OIDs, unverified for this vendor</Badge>}
          </span>
        }
        actions={
          history.length > 0 && (
            <a href={`/api/devices/${device.id}/snmp?format=csv`} className="btn btn-secondary">
              Export Metrics CSV
            </a>
          )
        }
      />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16 }}>
        <StatCard label="CPU" value={latest?.cpu_percent !== null && latest?.cpu_percent !== undefined ? `${latest.cpu_percent}%` : '—'} color="var(--red)" />
        <StatCard label="Memory" value={latest?.memory_percent !== null && latest?.memory_percent !== undefined ? `${latest.memory_percent}%` : '—'} color="var(--blue)" />
        <StatCard label="Sessions" value={latest?.session_count ?? '—'} color="var(--accent-teal)" />
        <StatCard label="Uptime" value={formatUptime(latest?.uptime_seconds)} color="var(--text-muted)" />
      </div>
      {latest && (
        <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
          Last polled: {formatDateTime(latest.sampled_at)}
        </p>
      )}

      {history.length > 0 ? (
        <SnmpMetricsCharts points={history} />
      ) : (
        <EmptyState
          message={
            device.snmp_enabled
              ? 'No SNMP metrics polled yet — the engine worker polls on its own interval (SNMP_POLL_INTERVAL_MINUTES).'
              : 'No SNMP metrics polled yet. Enable SNMP polling below and add a credential to start collecting.'
          }
        />
      )}

      <Card>
        <CardBody>
          <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
            Configuration
          </div>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginBottom: 16 }}>
            {hasCredential
              ? 'An SNMP credential is stored for this device.'
              : 'No SNMP credential stored yet — add one below to enable polling.'}
          </p>
          {snmpDetectedLooksConfigured && (
            <div
              style={{
                marginBottom: 16,
                padding: '10px 12px',
                background: 'var(--tint-warn)',
                borderRadius: 'var(--radius-sm)',
              }}
            >
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--tint-warn-fg)', margin: 0 }}>
                SNMP appears to already be enabled on this device (found in its collected config
                {snmpDetected.foundAt ? <> at <code className="mono">{snmpDetected.foundAt}</code></> : null}).
                We can&apos;t read the actual community string or SNMPv3 credentials — those are never
                collected, or are redacted before storage. Confirm the version and enter the credential
                below to start polling.
              </p>
            </div>
          )}
          <SnmpConfigForm
            deviceId={device.id}
            vendor={device.vendor}
            initial={{
              snmpEnabled: device.snmp_enabled,
              snmpHost: device.snmp_host,
              snmpPort: device.snmp_port,
              hasCredential,
            }}
            detected={snmpDetectedLooksConfigured}
          />
        </CardBody>
      </Card>
    </div>
  );
}
