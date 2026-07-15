import Link from 'next/link';
import { pool } from '../../../../../lib/db';
import Badge from '../../../../../components/ui/Badge';
import EmptyState from '../../../../../components/ui/EmptyState';
import Table from '../../../../../components/ui/Table';
import DiffViewer from '../../../../../components/config/DiffViewer';
import AcknowledgeButton from '../../../../../components/config/AcknowledgeButton';
import BackupActions from '../../../../../components/config/BackupActions';

export const dynamic = 'force-dynamic';

const BACKUP_LABEL_COLORS = {
  manual: 'info',
  auto: 'muted',
  'pre-change': 'warning',
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
        <Link href="/devices" className="text-sm text-accent hover:underline">
          ← Back to devices
        </Link>
        <p className="mt-4 text-text-secondary">Device not found.</p>
      </div>
    );
  }

  const [diffs, backups] = await Promise.all([
    getDiffs(pool, device.id),
    getBackups(pool, device.id),
  ]);

  return (
    <div className="space-y-6">
      <div>
        <Link href={`/devices/${device.id}`} className="text-sm text-accent hover:underline">
          ← Back to {device.name}
        </Link>
      </div>

      <div className="rounded border border-border bg-bg-surface p-4">
        <h1 className="text-xl font-semibold text-text-primary">{device.name}</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Configuration change tracking and config backups.
        </p>
      </div>

      <div className="space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-text-secondary">
          Configuration Changes
        </h2>

        {diffs.length === 0 ? (
          <EmptyState message="No configuration changes detected yet" />
        ) : (
          <ul className="space-y-3">
            {diffs.map((d) => (
              <li key={d.id} className="rounded border border-border bg-bg-surface p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-xs uppercase tracking-wide text-text-muted">
                      {formatDateTime(d.detected_at)}
                    </div>
                    <p className="mt-1 text-sm text-text-primary">
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
                <div className="mt-3 border-t border-border pt-3">
                  <DiffViewer deviceId={device.id} diffId={d.id} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-text-secondary">
          Config Backups
        </h2>

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
              <tr className="border-b border-border bg-bg-surface text-left text-text-secondary">
                <th className="px-2 py-2">Label</th>
                <th className="px-2 py-2">Backed Up At</th>
                <th className="px-2 py-2">Size</th>
                <th className="px-2 py-2">Download</th>
              </tr>
            </thead>
            <tbody>
              {backups.map((b) => (
                <tr key={b.id} className="border-b border-border">
                  <td className="px-2 py-2">
                    <Badge color={BACKUP_LABEL_COLORS[b.label] || 'muted'}>{b.label}</Badge>
                  </td>
                  <td className="px-2 py-2 text-text-primary">{formatDateTime(b.backed_up_at)}</td>
                  <td className="px-2 py-2 text-text-secondary">{formatBytes(b.size_bytes)}</td>
                  <td className="px-2 py-2">
                    <a
                      href={`/api/devices/${device.id}/backups/${b.id}`}
                      className="text-accent hover:underline"
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
