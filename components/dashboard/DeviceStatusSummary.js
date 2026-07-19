import { pool } from '../../lib/db';
import Card from '../ui/Card';
import StatCard from '../ui/StatCard';
import EmptyState from '../ui/EmptyState';

// Dashboard widget: active-device counts by last_connectivity_ok, the same
// tri-state signal devices/page.js already renders (true =
// reachable/green, false = unreachable/red, null = never tested/grey). Async
// server component -- does its own pool.query, same convention as every
// other dashboard/analysis widget in this app. Do not add 'use client'.
//
// Deliberately titled/captioned around "last connectivity test", NOT "online"
// or "status" -- SecVault has no real-time ping/heartbeat monitoring, only
// point-in-time test results from the last connectivity check (manual "Test"
// click or a scheduled collect's own connectivity probe). Overclaiming this
// as live monitoring would be exactly the kind of "looks fine, isn't" gap
// this codebase's own honesty conventions (see the tri-state applicability
// rules in CLAUDE.md) exist to avoid.

async function getConnectivitySummary(dbPool) {
  const result = await dbPool.query(
    `SELECT
       COUNT(*)::int AS total,
       COUNT(*) FILTER (WHERE last_connectivity_ok = true)::int AS reachable,
       COUNT(*) FILTER (WHERE last_connectivity_ok = false)::int AS unreachable,
       COUNT(*) FILTER (WHERE last_connectivity_ok IS NULL)::int AS never_tested,
       MIN(last_collected_at) FILTER (WHERE last_collected_at IS NOT NULL) AS oldest_collected_at
     FROM devices
     WHERE active = true`
  );
  return result.rows[0];
}

function timeAgo(timestamp) {
  if (!timestamp) return null;
  const then = new Date(timestamp).getTime();
  if (Number.isNaN(then)) return null;

  const diffMs = Date.now() - then;
  if (diffMs < 60000) return 'just now';

  const minutes = Math.floor(diffMs / 60000);
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export default async function DeviceStatusSummary() {
  const summary = await getConnectivitySummary(pool);
  const total = Number(summary?.total) || 0;

  return (
    <Card>
      <div className="card-body-compact">
        <div
          style={{
            fontSize: 'var(--text-xs)',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            color: 'var(--text-muted)',
          }}
        >
          Device Connectivity
        </div>
        <div style={{ marginTop: 2, marginBottom: 8, fontSize: 10, color: 'var(--text-muted)' }}>
          Last connectivity test, not real-time monitoring.
        </div>

        {total === 0 ? (
          <EmptyState message="No active devices yet." />
        ) : (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
              <StatCard label="Reachable" value={summary.reachable} color="var(--green)" compact />
              <StatCard label="Unreachable" value={summary.unreachable} color="var(--red)" compact />
              <StatCard label="Never Tested" value={summary.never_tested} color="var(--text-muted)" compact />
            </div>
            {summary.oldest_collected_at && (
              <div style={{ marginTop: 8, fontSize: 10, color: 'var(--text-muted)' }}>
                Longest since last collect: {timeAgo(summary.oldest_collected_at)}
              </div>
            )}
          </>
        )}
      </div>
    </Card>
  );
}
