import Link from 'next/link';
import Badge from '../ui/Badge';
import StatusDot from '../ui/StatusDot';

// Plain JS relative-time helper — no date library needed for "Xh ago" granularity.
function timeAgo(timestamp) {
  if (!timestamp) return 'Never';
  const then = new Date(timestamp).getTime();
  if (Number.isNaN(then)) return 'Never';

  const diffMs = Date.now() - then;
  if (diffMs < 60000) return 'just now';

  const minutes = Math.floor(diffMs / 60000);
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function connectivityStatus(device) {
  if (device.last_connectivity_ok === true) return 'green';
  if (device.last_connectivity_ok === false) return 'red';
  return 'grey';
}

// Dashboard grid card. Expects a raw-ish device row (snake_case DB column names)
// optionally enriched with: version_string, patch_now_count, scheduled_count,
// monitor_count. All enrichment fields are optional and default to safe placeholders.
export default function DeviceCard({ device }) {
  const status = connectivityStatus(device);

  return (
    <Link
      href={`/devices/${device.id}`}
      className="card"
      style={{ display: 'block', padding: 20, textDecoration: 'none', transition: 'box-shadow 0.2s, transform 0.2s' }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
        <div style={{ display: 'flex', minWidth: 0, alignItems: 'center', gap: 8 }}>
          <StatusDot status={status} />
          <span
            style={{
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              fontWeight: 500,
              color: 'var(--text-primary)',
            }}
          >
            {device.name}
          </span>
        </div>
        <Badge color="info">{device.vendor || 'forcepoint'}</Badge>
      </div>

      <div
        style={{
          marginTop: 8,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          fontSize: 'var(--text-base)',
          color: 'var(--text-secondary)',
        }}
      >
        Version: {device.version_string || '—'}
      </div>

      <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 12, fontSize: 'var(--text-xs)' }}>
        <span style={{ color: 'var(--red)' }}>Patch Now: {device.patch_now_count ?? 0}</span>
        <span style={{ color: 'var(--yellow)' }}>Scheduled: {device.scheduled_count ?? 0}</span>
        <span style={{ color: 'var(--text-muted)' }}>Monitor: {device.monitor_count ?? 0}</span>
      </div>

      <div style={{ marginTop: 8, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
        Last collected: {timeAgo(device.last_collected_at)}
      </div>
    </Link>
  );
}
