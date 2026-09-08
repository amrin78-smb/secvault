// lib/engines/logHit.js
//
// Produces `device_cve_assessments.log_hit` — decision rule 2 of CLAUDE.md's
// CVE priority tree.
//
// ── WHY THIS FILE EXISTS ──────────────────────────────────────────────────
// Rule 2 has been in the tree since the beginning and has never had a
// producer, so `log_hit` was `false` on every row in the fleet — not because
// nothing was ever reached, but because nothing ever looked. Phase 8's syslog
// ingestion is the first data source that can answer it.
//
// ⛔ Rule 2 sits ABOVE CVSS 9.0, immediately after KEV. Whatever sets this
// column is claiming confidence equal to "known exploited in the wild", so the
// bar is deliberately high and every uncertain case declines to fire. See
// CLAUDE.md's "What `log_hit` MEANS" for the definition this implements and
// for the definition that was REJECTED.
//
// The claim made here is narrow and literal: THE VULNERABLE SERVICE WAS
// REACHED ON THIS DEVICE, FROM THE INTERNET.

'use strict';

const { updatePrioritiesForDevice } = require('./prioritization');

// ⛔ Verified against live fleet logs, not vendor documentation (CLAUDE.md's
// "documentation lies" rule). Both lists are EXPLICIT and anything absent from
// both is treated as unknown -- see classifyAction.
//
// The subtle one is Fortinet's `close`/`client-rst`/`server-rst`: they describe
// a session that EXISTED and then ended, so the service was genuinely reached.
// Live proof this matters: port 10443 (FortiGate SSL-VPN) is reached from
// public sources and logged `close`/`client-rst`, never `allow`. Treating only
// `allow` as reached would miss the single most exposed service on the fleet.
const ALLOWED_ACTIONS = new Set([
  'allow', 'accept', 'permit', 'start', 'close', 'client-rst', 'server-rst',
]);

// `reset-both` is Palo Alto's IPS resetting BOTH ends -- a block, despite
// looking like Fortinet's session-teardown actions.
const BLOCKED_ACTIONS = new Set([
  'deny', 'drop', 'block', 'blocked', 'denied', 'block-url', 'block-ip',
  'block-continue', 'block-override', 'reset-both', 'reset-client',
  'reset-server', 'timeout',
]);

/**
 * @returns {'allowed'|'blocked'|'unknown'}
 *
 * ⛔ `unknown` is a real third answer and callers must NOT fold it into
 * `allowed`. A vendor action string this engine has never seen must not be
 * able to manufacture a `patch_now`.
 */
function classifyAction(action) {
  if (typeof action !== 'string') return 'unknown';
  const a = action.trim().toLowerCase();
  if (a === '') return 'unknown';
  if (ALLOWED_ACTIONS.has(a)) return 'allowed';
  if (BLOCKED_ACTIONS.has(a)) return 'blocked';
  return 'unknown';
}

// Kept as SQL so the filter runs in the database rather than dragging rows
// across the wire. RFC1918 + loopback + link-local + CGNAT: "public" here means
// "not obviously inside a private network", which is the conservative reading.
const PUBLIC_SRC_SQL = `
  src_ip IS NOT NULL
  AND NOT (src_ip <<= '10.0.0.0/8'::inet
        OR src_ip <<= '172.16.0.0/12'::inet
        OR src_ip <<= '192.168.0.0/16'::inet
        OR src_ip <<= '127.0.0.0/8'::inet
        OR src_ip <<= '169.254.0.0/16'::inet
        OR src_ip <<= '100.64.0.0/10'::inet)`;

/**
 * Curated `port_exposed` ports, per advisory.
 *
 * ⛔ An advisory with NO curated port produces NO row here, and therefore can
 * never set `log_hit`. That is correct, not a gap: without a curated port
 * there is nothing to look for, and inferring one from advisory prose is
 * exactly the trap CLAUDE.md bans. See /vulnerability/advisories to curate.
 */
async function getCuratedPorts(pool) {
  const { rows } = await pool.query(
    `SELECT advisory_id, predicate_config->>'port' AS port
       FROM advisory_conditions
      WHERE predicate_type = 'port_exposed'`
  );
  const byAdvisory = new Map();
  for (const r of rows) {
    const p = Number(r.port);
    if (!Number.isInteger(p) || p < 1 || p > 65535) continue;
    if (!byAdvisory.has(r.advisory_id)) byAdvisory.set(r.advisory_id, new Set());
    byAdvisory.get(r.advisory_id).add(p);
  }
  return byAdvisory;
}

/**
 * A device's own interface addresses, as plain IPs.
 *
 * `device_interfaces.ip_address` is TEXT and carries a prefix
 * (`27.254.29.130/24`), so the host part is split off here. Anything that is
 * not a clean dotted quad is skipped rather than guessed at.
 */
async function getDeviceInterfaceIps(pool) {
  const { rows } = await pool.query(
    `SELECT device_id, split_part(ip_address, '/', 1) AS ip
       FROM device_interfaces
      WHERE ip_address IS NOT NULL
        AND split_part(ip_address, '/', 1) ~ '^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$'`
  );
  const byDevice = new Map();
  for (const r of rows) {
    if (!byDevice.has(r.device_id)) byDevice.set(r.device_id, new Set());
    byDevice.get(r.device_id).add(r.ip);
  }
  return byDevice;
}

/**
 * Correlate observed inbound traffic against curated exposed ports and persist
 * `log_hit`, then re-derive the affected devices' priority bands.
 *
 * ⛔ NEVER THROWS (same contract as runConfigRetention). A syslog problem must
 * not take down the engine job that also does CVE matching.
 *
 * @param {import('pg').Pool} pool  always a parameter (CLAUDE.md)
 * @param {{lookbackDays?: number, now?: Date}} [opts]
 */
async function runLogHitCorrelation(pool, opts = {}) {
  const lookbackDays =
    Number.isFinite(opts.lookbackDays) && opts.lookbackDays > 0
      ? Math.min(opts.lookbackDays, 90)
      : 7;
  const now = opts.now instanceof Date ? opts.now : new Date();
  const since = new Date(now.getTime() - lookbackDays * 86400000);

  const summary = {
    lookbackDays,
    since: since.toISOString(),
    curatedAdvisories: 0,
    devicesConsidered: 0,
    devicesSkippedNoCoverage: 0,
    devicesSkippedNoInterfaces: 0,
    setTrue: 0,
    setFalse: 0,
    reprioritized: 0,
    hits: [],
    errors: [],
  };

  try {
    const portsByAdvisory = await getCuratedPorts(pool);
    summary.curatedAdvisories = portsByAdvisory.size;

    // Nothing curated -> nothing to look for. Return immediately rather than
    // scanning days of syslog to prove a foregone conclusion.
    if (portsByAdvisory.size === 0) return summary;

    const ipsByDevice = await getDeviceInterfaceIps(pool);

    // Only devices that actually have an assessment against a curated advisory.
    const { rows: pairs } = await pool.query(
      `SELECT dca.id, dca.device_id, dca.advisory_id, dca.log_hit
         FROM device_cve_assessments dca
        WHERE dca.advisory_id = ANY($1::uuid[])`,
      [Array.from(portsByAdvisory.keys())]
    );

    const byDevice = new Map();
    for (const p of pairs) {
      if (!byDevice.has(p.device_id)) byDevice.set(p.device_id, []);
      byDevice.get(p.device_id).push(p);
    }
    summary.devicesConsidered = byDevice.size;

    const touchedDevices = new Set();

    for (const [deviceId, rows] of byDevice) {
      try {
        const ips = ipsByDevice.get(deviceId);
        if (!ips || ips.size === 0) {
          // ⛔ No interface addresses collected -> we cannot tell traffic TO
          // this device from traffic THROUGH it. Leave log_hit untouched
          // rather than writing a false that would read as "not reached".
          summary.devicesSkippedNoInterfaces++;
          continue;
        }

        // ⛔ Coverage gate. A device sending no syslog at all is UNMEASURED,
        // not clean. Writing `false` here would convert "we were not
        // listening" into "nothing reached it" -- the exact
        // failed-read-as-a-fact bug this codebase keeps rediscovering.
        const { rows: cov } = await pool.query(
          `SELECT 1 FROM syslog_events
            WHERE device_id = $1 AND received_at >= $2::timestamptz LIMIT 1`,
          [deviceId, since]
        );
        if (cov.length === 0) {
          summary.devicesSkippedNoCoverage++;
          continue;
        }

        const wanted = new Set();
        for (const r of rows) {
          for (const p of portsByAdvisory.get(r.advisory_id) || []) wanted.add(p);
        }
        if (wanted.size === 0) continue;

        const { rows: reached } = await pool.query(
          `SELECT dst_port,
                  count(*)::bigint            AS events,
                  count(DISTINCT src_ip)::int AS sources,
                  max(received_at)            AS last_seen
             FROM syslog_events
            WHERE device_id = $1
              AND received_at >= $2::timestamptz
              AND dst_port = ANY($3::int[])
              AND dst_ip   = ANY($4::inet[])
              AND lower(action) = ANY($5::text[])
              AND ${PUBLIC_SRC_SQL}
            GROUP BY dst_port`,
          [
            deviceId,
            since,
            Array.from(wanted),
            Array.from(ips),
            Array.from(ALLOWED_ACTIONS),
          ]
        );

        const reachedPorts = new Map();
        for (const r of reached) reachedPorts.set(Number(r.dst_port), r);

        for (const r of rows) {
          const ports = Array.from(portsByAdvisory.get(r.advisory_id) || []);
          // ⛔ ANY, not ALL. Applicability ANDs its conditions because it asks
          // "does this advisory apply"; this asks "was the service reached",
          // and reaching one exposed port of several is still reaching it.
          const hitPort = ports.find((p) => reachedPorts.has(p));
          const value = hitPort !== undefined;
          if (value === (r.log_hit === true)) continue;

          await pool.query('UPDATE device_cve_assessments SET log_hit = $1 WHERE id = $2', [
            value,
            r.id,
          ]);
          touchedDevices.add(deviceId);
          if (value) {
            const ev = reachedPorts.get(hitPort);
            summary.setTrue++;
            summary.hits.push({
              deviceId,
              advisoryId: r.advisory_id,
              port: hitPort,
              events: Number(ev.events),
              sources: Number(ev.sources),
              lastSeen: ev.last_seen,
            });
          } else {
            summary.setFalse++;
          }
        }
      } catch (err) {
        summary.errors.push({ deviceId, error: err.message });
      }
    }

    // log_hit feeds rule 2, so a change to it changes the band.
    for (const deviceId of touchedDevices) {
      try {
        await updatePrioritiesForDevice(deviceId, pool);
        summary.reprioritized++;
      } catch (err) {
        summary.errors.push({ deviceId, error: 'reprioritize: ' + err.message });
      }
    }
  } catch (err) {
    summary.errors.push({ error: err.message });
  }

  return summary;
}

module.exports = {
  classifyAction,
  getCuratedPorts,
  getDeviceInterfaceIps,
  runLogHitCorrelation,
  ALLOWED_ACTIONS,
  BLOCKED_ACTIONS,
};
