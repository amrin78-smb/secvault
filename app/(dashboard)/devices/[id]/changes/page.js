import Link from 'next/link';
import { pool } from '../../../../../lib/db';
import Badge from '../../../../../components/ui/Badge';
import EmptyState from '../../../../../components/ui/EmptyState';
import Table from '../../../../../components/ui/Table';
import PageHeader from '../../../../../components/ui/PageHeader';
import DiffViewer from '../../../../../components/config/DiffViewer';
import AcknowledgeButton from '../../../../../components/config/AcknowledgeButton';
import BackupActions from '../../../../../components/config/BackupActions';

export const dynamic = 'force-dynamic';

const BACKUP_LABEL_COLORS = {
  manual: 'info',
  auto: 'muted',
  'pre-change': 'warning',
};

const SECTION_HEADING_STYLE = {
  fontSize: 'var(--text-sm)',
  fontWeight: 600,
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
  color: 'var(--text-secondary)',
};

function formatDateTime(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

function formatBytes(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n)) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

async function getDevice(dbPool, id) {
  const result = await dbPool.query('SELECT id, name FROM devices WHERE id = $1', [id]);
  return result.rows[0] || null;
}

async function getDiffs(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT id, change_summary, detected_at, acknowledged_at, acknowledged_by
     FROM config_diffs
     WHERE device_id = $1
     ORDER BY detected_at DESC
     LIMIT 50`,
    [deviceId]
  );
  return result.rows;
}

async function getBackups(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT id, label, backed_up_at, octet_length(config_raw) AS size_bytes
     FROM config_backups
     WHERE device_id = $1
     ORDER BY backed_up_at DESC`,
    [deviceId]
  );
  return result.rows;
}

export default async function DeviceChangesPage({ params }) {
  const device = await getDevice(pool, params.id);

  if (!device) {
    return (
      <div>
        <Link href="/devices" style={{ fontSize: 'var(--text-base)', color: 'var(--primary)' }}>
          ← Back to devices
        </Link>
        <p style={{ marginTop: 16, color: 'var(--text-secondary)' }}>Device not found.</p>
      </div>
    );
  }

  const [diffs, backups] = await Promise.all([
    getDiffs(pool, device.id),
    getBackups(pool, device.id),
  ]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <Link href={`/devices/${device.id}`} style={{ fontSize: 'var(--text-base)', color: 'var(--primary)' }}>
          ← Back to {device.name}
        </Link>
      </div>

      <PageHeader title={device.name} subtitle="Configuration change tracking and config backups." />

      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <h2 style={SECTION_HEADING_STYLE}>Configuration Changes</h2>

        {diffs.length === 0 ? (
          <EmptyState message="No configuration changes detected yet" />
        ) : (
          <ul style={{ display: 'flex', flexDirection: 'column', gap: 12, listStyle: 'none' }}>
            {diffs.map((d) => (
              <li key={d.id} className="card" style={{ padding: 16 }}>
                <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
                      {formatDateTime(d.detected_at)}
                    </div>
                    <p style={{ marginTop: 4, fontSize: 'var(--text-base)', color: 'var(--text-primary)' }}>
                      {d.change_summary || 'Configuration change detected'}
                    </p>
                  </div>
                  <div>
                    {d.acknowledged_at ? (
                      <Badge color="success">
                        Acknowledged by {d.acknowledged_by || 'unknown'} · {formatDateTime(d.acknowledged_at)}
                      </Badge>
                    ) : (
                      <AcknowledgeButton deviceId={device.id} diffId={d.id} />
                    )}
                  </div>
                </div>
                <div style={{ marginTop: 12, borderTop: '1px solid var(--border)', paddingTop: 12 }}>
                  <DiffViewer deviceId={device.id} diffId={d.id} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <h2 style={SECTION_HEADING_STYLE}>Config Backups</h2>

        <BackupActions deviceId={device.id} />

        {backups.length === 0 ? (
          <EmptyState message="No config backups yet" />
        ) : (
          <Table>
            <colgroup>
              <col style={{ width: '20%' }} />
              <col style={{ width: '35%' }} />
              <col style={{ width: '25%' }} />
              <col style={{ width: '20%' }} />
            </colgroup>
            <thead>
              <tr>
                <th>Label</th>
                <th>Backed Up At</th>
                <th>Size</th>
                <th>Download</th>
              </tr>
            </thead>
            <tbody>
              {backups.map((b) => (
                <tr key={b.id}>
                  <td>
                    <Badge color={BACKUP_LABEL_COLORS[b.label] || 'muted'}>{b.label}</Badge>
                  </td>
                  <td>{formatDateTime(b.backed_up_at)}</td>
                  <td style={{ color: 'var(--text-secondary)' }}>{formatBytes(b.size_bytes)}</td>
                  <td>
                    <a
                      href={`/api/devices/${device.id}/backups/${b.id}`}
                      style={{ color: 'var(--primary)' }}
                    >
                      Download
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </div>
    </div>
  );
}
