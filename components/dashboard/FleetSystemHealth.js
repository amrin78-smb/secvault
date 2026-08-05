import { pool } from '../../lib/db';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import { getFleetConnectivityNow } from '../../lib/engines/connectivityHistory';

export const dynamic = 'force-dynamic';

// Fleet-level roll-up of the per-device facts SecVault already collects.
//
// ⛔ EVERY ROW HERE STATES ITS OWN COVERAGE. These come from optional adapter
// capabilities that only some vendors implement (CLAUDE.md, Device Lifecycle &
// Health): CPU/memory from getPerformanceMetrics/getSnmpMetrics, disk and HA
// from Palo Alto only today. A fleet-wide "48%" computed from 6 of 16 devices,
// shown without saying so, is a number that invites exactly the wrong
// conclusion. Each row therefore renders "n of N devices" and a row with zero
// coverage says so instead of showing a confident dash.

async function getLatestMetrics(dbPool) {
  const { rows } = await dbPool.query(
    `WITH latest AS (
       SELECT DISTINCT ON (s.device_id) s.device_id, s.cpu_percent, s.memory_percent, s.uptime_seconds
         FROM snmp_metric_snapshots s
         JOIN devices d ON d.id = s.device_id
        WHERE d.active = true AND s.sampled_at > now() - interval '24 hours'
        ORDER BY s.device_id, s.sampled_at DESC
     )
     SELECT
       COUNT(*) FILTER (WHERE cpu_percent IS NOT NULL)::int AS cpu_devices,
       ROUND(AVG(cpu_percent) FILTER (WHERE cpu_percent IS NOT NULL))::int AS cpu_avg,
       ROUND(MAX(cpu_percent) FILTER (WHERE cpu_percent IS NOT NULL))::int AS cpu_max,
       COUNT(*) FILTER (WHERE memory_percent IS NOT NULL)::int AS mem_devices,
       ROUND(AVG(memory_percent) FILTER (WHERE memory_percent IS NOT NULL))::int AS mem_avg,
       ROUND(MAX(memory_percent) FILTER (WHERE memory_percent IS NOT NULL))::int AS mem_max
     FROM latest`
  );
  return rows[0] || {};
}

async function getDiskSummary(dbPool) {
  const { rows } = await dbPool.query(
    `SELECT COUNT(DISTINCT du.device_id)::int AS devices,
            MAX(du.use_percent)::int AS worst
       FROM device_disk_usage du
       JOIN devices d ON d.id = du.device_id
      WHERE d.active = true AND du.use_percent IS NOT NULL`
  );
  return rows[0] || { devices: 0, worst: null };
}

async function getHaSummary(dbPool) {
  const { rows } = await dbPool.query(
    `SELECT COUNT(*)::int AS reporting,
            COUNT(*) FILTER (WHERE ha.enabled)::int AS enabled,
            COUNT(*) FILTER (WHERE ha.enabled AND ha.peer_connection_status = 'up')::int AS peer_up
       FROM device_ha_status ha
       JOIN devices d ON d.id = ha.device_id
      WHERE d.active = true`
  );
  return rows[0] || { reporting: 0, enabled: 0, peer_up: 0 };
}

async function getLastBackup(dbPool) {
  const { rows } = await dbPool.query(
    `SELECT MAX(backed_up_at) AS latest, COUNT(DISTINCT device_id)::int AS devices FROM config_backups`
  );
  return rows[0] || { latest: null, devices: 0 };
}

function relativeAge(ts) {
  if (!ts) return null;
  const ms = Date.now() - new Date(ts).getTime();
  if (!Number.isFinite(ms) || ms < 0) return null;
  const mins = Math.floor(ms / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 48) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function toneFor(pct) {
  if (pct === null || pct === undefined) return 'var(--text-muted)';
  if (pct >= 90) return 'var(--red)';
  if (pct >= 75) return 'var(--yellow)';
  return 'var(--green)';
}

// One labelled row: value on the right, a proportional bar, and the coverage
// note that keeps the number honest.
function HealthRow({ label, value, pct, coverage, tone }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 8 }}>
        <span style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>{label}</span>
        <span style={{ fontWeight: 600, color: tone || 'var(--text-primary)', whiteSpace: 'nowrap' }}>{value}</span>
      </div>
      {pct !== null && pct !== undefined && (
        <div className="util-track">
          <div className="util-fill" style={{ width: `${Math.max(0, Math.min(100, pct))}%`, background: tone }} />
        </div>
      )}
      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{coverage}</span>
    </div>
  );
}

export default async function FleetSystemHealth() {
  const [metrics, disk, ha, backup, conn] = await Promise.all([
    getLatestMetrics(pool),
    getDiskSummary(pool),
    getHaSummary(pool),
    getLastBackup(pool),
    getFleetConnectivityNow(pool),
  ]);

  const cpuAvg = metrics.cpu_devices > 0 ? metrics.cpu_avg : null;
  const memAvg = metrics.mem_devices > 0 ? metrics.mem_avg : null;
  const total = conn.total;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Fleet System Health</CardTitle>
      </CardHeader>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <HealthRow
            label="Reachability"
            value={`${conn.reachable} / ${total}`}
            pct={total > 0 ? (conn.reachable / total) * 100 : null}
            tone={conn.unreachable > 0 ? 'var(--red)' : 'var(--green)'}
            coverage={
              conn.neverChecked > 0
                ? `${conn.unreachable} unreachable · ${conn.neverChecked} never checked`
                : `${conn.unreachable} unreachable`
            }
          />
          <HealthRow
            label="CPU (avg)"
            value={cpuAvg === null ? 'No data' : `${cpuAvg}%`}
            pct={cpuAvg}
            tone={toneFor(cpuAvg)}
            coverage={
              metrics.cpu_devices > 0
                ? `${metrics.cpu_devices} of ${total} devices reporting · peak ${metrics.cpu_max}%`
                : 'No device reported CPU in the last 24h'
            }
          />
          <HealthRow
            label="Memory (avg)"
            value={memAvg === null ? 'No data' : `${memAvg}%`}
            pct={memAvg}
            tone={toneFor(memAvg)}
            coverage={
              metrics.mem_devices > 0
                ? `${metrics.mem_devices} of ${total} devices reporting · peak ${metrics.mem_max}%`
                : 'No device reported memory in the last 24h'
            }
          />
          <HealthRow
            label="Disk (worst)"
            value={disk.worst === null ? 'No data' : `${disk.worst}%`}
            pct={disk.worst}
            tone={toneFor(disk.worst)}
            coverage={
              disk.devices > 0
                ? `${disk.devices} of ${total} devices reporting`
                : 'No device reports disk usage (Palo Alto only today)'
            }
          />
          <HealthRow
            label="HA pairs healthy"
            value={ha.enabled > 0 ? `${ha.peer_up} / ${ha.enabled}` : 'None'}
            pct={ha.enabled > 0 ? (ha.peer_up / ha.enabled) * 100 : null}
            tone={ha.enabled > 0 && ha.peer_up < ha.enabled ? 'var(--red)' : 'var(--green)'}
            coverage={
              ha.reporting > 0
                ? `${ha.enabled} HA-enabled of ${ha.reporting} reporting`
                : 'No device reports HA state'
            }
          />
          <HealthRow
            label="Last config backup"
            value={relativeAge(backup.latest) || 'Never'}
            pct={null}
            tone={backup.latest ? 'var(--text-primary)' : 'var(--text-muted)'}
            coverage={backup.devices > 0 ? `${backup.devices} device(s) have backups` : 'No backups stored'}
          />
        </div>
      </CardBody>
    </Card>
  );
}
