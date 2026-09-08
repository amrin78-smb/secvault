// lib/engines/exposureQuery.js
//
// The database-facing half of Internet Exposure. `exposure.js` holds the pure
// path-construction and scoring so it can be unit-tested without a database;
// this file loads the rows and attaches observed-traffic evidence.
//
// ⛔ Computed on READ, not stored. The inputs (rules, NAT, interfaces) are
// already persisted snapshots and the observation window is relative to now,
// so a stored exposure table would be a second copy that goes stale silently —
// the same reasoning as deviceHealth.js and the baseline-drift comparison.

'use strict';

const { buildExposurePaths, scoreExposure } = require('./exposure');

// ⛔ READS THE ROLLUP, NEVER RAW `syslog_events` — same note as logHit.js and
// the table comment in lib/schema.sql. Measured 2026-09-08: the raw-event form
// of this query exceeds two minutes for ONE device over ONE day, which is not
// a page render. Action classification and public-source determination both
// happen once, at rollup time, instead of per query.

async function loadDeviceData(pool, deviceId) {
  const [rules, objects, natRules, interfaces] = await Promise.all([
    pool.query(
      `SELECT rule_name, rule_id_vendor, sequence_number, enabled, action,
              src_addresses, dst_addresses, services, log_enabled, vdom
         FROM firewall_rules WHERE device_id = $1
        ORDER BY sequence_number NULLS LAST`,
      [deviceId]
    ),
    pool.query(
      `SELECT name, object_type, value, members FROM network_objects WHERE device_id = $1`,
      [deviceId]
    ),
    pool.query(
      `SELECT sequence_number, enabled, nat_type,
              original_dst_addresses, translated_dst_addresses, original_services
         FROM nat_rules WHERE device_id = $1`,
      [deviceId]
    ),
    pool.query(
      `SELECT interface_name, ip_address, zone FROM device_interfaces WHERE device_id = $1`,
      [deviceId]
    ),
  ]);
  return {
    rules: rules.rows,
    objects: objects.rows,
    natRules: natRules.rows,
    interfaces: interfaces.rows,
  };
}

/**
 * Attach observed-traffic evidence to already-built paths.
 *
 * ⛔ The coverage probe runs FIRST and decides between `not_observed` and
 * `unmeasured`. Without it every path on a device that sends no syslog would
 * read as "no traffic seen", which is the failed-read-as-a-fact bug: we were
 * not listening, and that is not the same as nothing arriving.
 */
async function attachObservations(pool, deviceId, paths, since) {
  if (paths.length === 0) return { covered: false };

  // Probes the general hourly rollup, not the inbound one: the inbound rollup
  // is legitimately empty when nothing was addressed to the device, which is
  // precisely the state we must distinguish from "not listening".
  const { rows: cov } = await pool.query(
    `SELECT 1 FROM syslog_rollup_hourly
      WHERE device_id = $1 AND bucket_hour >= $2::timestamptz LIMIT 1`,
    [deviceId, since]
  );
  if (cov.length === 0) {
    for (const p of paths) p.observation = 'unmeasured';
    return { covered: false };
  }

  const ips = Array.from(new Set(paths.map((p) => p.publicIp)));
  const { rows } = await pool.query(
    `SELECT host(dst_ip) AS ip, dst_port,
            sum(event_count)::bigint   AS events,
            max(distinct_sources)::int AS sources,
            max(last_seen_at)          AS last_seen
       FROM syslog_device_inbound_hourly
      WHERE device_id = $1
        AND bucket_hour >= $2::timestamptz
        AND dst_ip = ANY($3::inet[])
        AND allowed IS TRUE
        AND public_source IS TRUE
      GROUP BY host(dst_ip), dst_port`,
    [deviceId, since, ips]
  );

  const byIp = new Map();
  for (const r of rows) {
    if (!byIp.has(r.ip)) byIp.set(r.ip, []);
    byIp.get(r.ip).push({
      port: r.dst_port === null ? null : Number(r.dst_port),
      events: Number(r.events),
      sources: Number(r.sources),
      lastSeen: r.last_seen,
    });
  }

  for (const p of paths) {
    const seen = byIp.get(p.publicIp) || [];
    // An any-service path is matched by any observed port on that address;
    // otherwise the observed port must fall inside one of the resolved ranges.
    const hits = seen.filter((s) => {
      if (p.service.isAny) return true;
      if (s.port === null) return false;
      return p.service.ports.some(
        (r) =>
          r.portStart !== null && s.port >= r.portStart && s.port <= (r.portEnd ?? r.portStart)
      );
    });
    if (hits.length === 0) {
      p.observation = 'not_observed';
      p.evidence = null;
      continue;
    }
    p.observation = 'observed';
    p.evidence = {
      events: hits.reduce((n, h) => n + h.events, 0),
      sources: Math.max(...hits.map((h) => h.sources)),
      ports: Array.from(new Set(hits.map((h) => h.port).filter((x) => x !== null))).sort(
        (a, b) => a - b
      ),
      lastSeen: hits.reduce((a, h) => (a > h.lastSeen ? a : h.lastSeen), hits[0].lastSeen),
    };
  }
  return { covered: true };
}

/**
 * Internet exposure for ONE device.
 *
 * @param {import('pg').Pool} pool  always a parameter (CLAUDE.md)
 */
async function computeDeviceExposure(pool, deviceId, opts = {}) {
  const lookbackDays =
    Number.isFinite(opts.lookbackDays) && opts.lookbackDays > 0
      ? Math.min(opts.lookbackDays, 90)
      : 7;
  const now = opts.now instanceof Date ? opts.now : new Date();
  const since = new Date(now.getTime() - lookbackDays * 86400000);

  const data = await loadDeviceData(pool, deviceId);
  const built = buildExposurePaths(data);
  const coverage = await attachObservations(pool, deviceId, built.paths, since);

  for (const p of built.paths) {
    const s = scoreExposure(p);
    p.score = s.score;
    p.severity = s.severity;
    p.reasons = s.reasons;
  }

  built.paths.sort((a, b) => b.score - a.score || String(a.publicIp).localeCompare(b.publicIp));

  return {
    deviceId,
    lookbackDays,
    since: since.toISOString(),
    syslogCovered: coverage.covered === true,
    publicIps: built.publicIps,
    unresolvedRules: built.unresolvedRules,
    paths: built.paths,
    counts: countBy(built.paths),
  };
}

function countBy(paths) {
  const c = {
    total: paths.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    observed: 0,
    notObserved: 0,
    unmeasured: 0,
  };
  for (const p of paths) {
    if (p.severity) c[p.severity]++;
    if (p.observation === 'observed') c.observed++;
    else if (p.observation === 'not_observed') c.notObserved++;
    else c.unmeasured++;
  }
  return c;
}

/**
 * Fleet-wide exposure across every active device.
 *
 * ⛔ NEVER THROWS on a per-device failure — a device whose data cannot be read
 * is reported as an ERROR entry, never omitted. Silently dropping it would
 * shrink the reported attack surface, which is the most dangerous direction to
 * be wrong in here.
 */
async function computeFleetExposure(pool, opts = {}) {
  const { rows: devices } = await pool.query(
    `SELECT id, name, vendor, asset_criticality FROM devices WHERE active = true ORDER BY name`
  );

  const results = [];
  const errors = [];
  for (const d of devices) {
    try {
      const r = await computeDeviceExposure(pool, d.id, opts);
      results.push({ ...r, name: d.name, vendor: d.vendor, assetCriticality: d.asset_criticality });
    } catch (err) {
      errors.push({ deviceId: d.id, name: d.name, error: err.message });
    }
  }

  const totals = {
    devices: devices.length,
    devicesWithExposure: results.filter((r) => r.paths.length > 0).length,
    devicesWithoutSyslog: results.filter((r) => !r.syslogCovered).length,
    paths: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    observed: 0,
    notObserved: 0,
    unmeasured: 0,
    publicIps: 0,
  };
  for (const r of results) {
    totals.paths += r.counts.total;
    totals.critical += r.counts.critical;
    totals.high += r.counts.high;
    totals.medium += r.counts.medium;
    totals.low += r.counts.low;
    totals.observed += r.counts.observed;
    totals.notObserved += r.counts.notObserved;
    totals.unmeasured += r.counts.unmeasured;
    totals.publicIps += r.publicIps.length;
  }

  return { totals, devices: results, errors };
}

module.exports = {
  loadDeviceData,
  attachObservations,
  computeDeviceExposure,
  computeFleetExposure,
};
