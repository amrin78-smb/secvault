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
      className="block rounded-lg border border-border bg-bg-surface p-4 transition-colors hover:bg-bg-elevated"
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <StatusDot status={status} />
          <span className="truncate font-medium text-text-primary">{device.name}</span>
        </div>
        <Badge color="info">{device.vendor || 'forcepoint'}</Badge>
      </div>

      <div className="mt-2 truncate text-sm text-text-secondary">
        Version: {device.version_string || '—'}
      </div>

      <div className="mt-3 flex items-center gap-3 text-xs">
        <span className="text-danger">Patch Now: {device.patch_now_count ?? 0}</span>
        <span className="text-warning">Scheduled: {device.scheduled_count ?? 0}</span>
        <span className="text-text-muted">Monitor: {device.monitor_count ?? 0}</span>
      </div>

      <div className="mt-2 text-xs text-text-muted">
        Last collected: {timeAgo(device.last_collected_at)}
      </div>
    </Link>
  );
}
