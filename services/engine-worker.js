// services/engine-worker.js
// SecVault-Engine — scheduled background worker (NSSM service).
// CommonJS ONLY — runs directly under plain `node`, not through Next.js's bundler.
// No HTTP server, no port. See CLAUDE.md "Engine Worker" section.

'use strict';

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// .env.local loader
// ---------------------------------------------------------------------------
// NSSM launches this file as plain `node services\engine-worker.js` with only
// NODE_ENV=production injected via AppEnvironmentExtra — there is no shell
// sourcing .env.local, and Next.js's automatic .env.local loading only applies
// to `next build`/`next start`/`next dev`, not arbitrary `node` invocations.
// Load it here, ourselves, before requiring anything that reads process.env
// at module-load time (lib/db.js constructs its Pool immediately on require).
// Values already present in process.env are never overridden.
function loadEnvLocal() {
  const envPath = path.join(__dirname, '..', '.env.local');
  try {
    const content = fs.readFileSync(envPath, 'utf8');
    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      const eq = line.indexOf('=');
      if (eq === -1) continue;
      const key = line.slice(0, eq).trim();
      let value = line.slice(eq + 1).trim();
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }
      if (process.env[key] === undefined) {
        process.env[key] = value;
      }
    }
  } catch (err) {
    // .env.local may legitimately be absent (e.g. dev/test environments where
    // env vars are already set another way). Don't crash on a missing file —
    // just proceed with whatever is already in process.env.
    // eslint-disable-next-line no-console
    console.warn(`[engine-worker] Could not load .env.local (${err.message}). Relying on existing process.env.`);
  }
}

loadEnvLocal();

const cron = require('node-cron');
const winston = require('winston');

const { pool } = require('../lib/db');
const { runFullSync } = require('../lib/feeds');
const { runMatchForAllDevices } = require('../lib/engines/versionMatcher');
const { collectAndStore, getAdapter, SUPPORTED_VENDORS } = require('../lib/adapters');
const { computeAndStoreDashboardSnapshot } = require('../lib/engines/dashboardSnapshot');
const { storeVpnSessions } = require('../lib/engines/vpnSessions');
const { storeVpnTunnels } = require('../lib/engines/vpnTunnels');
const { runNotificationDispatch } = require('../lib/engines/notificationDispatch');
const { dispatchMonthlyReport } = require('../lib/engines/complianceReport');
const { recordConnectivity } = require('../lib/engines/connectivityHistory');

// ---------------------------------------------------------------------------
// Logging (winston) — C:\Apps\SecVault\logs\engine.log, fallback to ./logs
// ---------------------------------------------------------------------------

const PROD_LOG_DIR = 'C:\\Apps\\SecVault\\logs';
const FALLBACK_LOG_DIR = path.join(__dirname, '..', 'logs');

function resolveLogDir() {
  try {
    if (!fs.existsSync(PROD_LOG_DIR)) {
      fs.mkdirSync(PROD_LOG_DIR, { recursive: true });
    }
    // Verify we can actually write to it (existsSync/mkdirSync can succeed on
    // paths we still can't write into, depending on ACLs).
    fs.accessSync(PROD_LOG_DIR, fs.constants.W_OK);
    return PROD_LOG_DIR;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(
      `[engine-worker] Cannot use log directory "${PROD_LOG_DIR}" (${err.message}). ` +
        `Falling back to "${FALLBACK_LOG_DIR}".`
    );
    try {
      if (!fs.existsSync(FALLBACK_LOG_DIR)) {
        fs.mkdirSync(FALLBACK_LOG_DIR, { recursive: true });
      }
    } catch (fallbackErr) {
      // eslint-disable-next-line no-console
      console.warn(
        `[engine-worker] Could not create fallback log directory either (${fallbackErr.message}). ` +
          `Continuing with console logging only.`
      );
      return null;
    }
    return FALLBACK_LOG_DIR;
  }
}

const logDir = resolveLogDir();

const logFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.printf(({ timestamp, level, message }) => {
    return `[${timestamp}] [${level.toUpperCase()}] ${message}`;
  })
);

const transports = [new winston.transports.Console({ format: logFormat })];

if (logDir) {
  transports.push(
    new winston.transports.File({
      filename: path.join(logDir, 'engine.log'),
      format: logFormat,
      maxsize: 10 * 1024 * 1024, // ~10MB
      maxFiles: 5,
      tailable: true,
    })
  );
}

const logger = winston.createLogger({
  level: 'info',
  format: logFormat,
  transports,
});

// ---------------------------------------------------------------------------
// Settings helpers
// ---------------------------------------------------------------------------

async function getFeedPollIntervalHours() {
  const fallback = parseInt(process.env.FEED_POLL_INTERVAL_HOURS, 10) || 6;
  try {
    const { rows } = await pool.query('SELECT value FROM settings WHERE key = $1', [
      'feed_poll_interval_hours',
    ]);
    if (rows.length > 0 && rows[0].value !== null && rows[0].value !== undefined) {
      const parsed = parseInt(rows[0].value, 10);
      if (Number.isInteger(parsed) && parsed >= 1 && parsed <= 24) {
        return parsed;
      }
      logger.warn(
        `settings.feed_poll_interval_hours value "${rows[0].value}" is not a valid integer between 1 and 24 — falling back to ${fallback}.`
      );
    }
  } catch (err) {
    logger.warn(`Could not read feed_poll_interval_hours from settings table: ${err.message}. Falling back to ${fallback}.`);
  }
  return fallback;
}

function getConfigPullIntervalHours() {
  const fallback = 24;
  const raw = parseInt(process.env.CONFIG_PULL_INTERVAL_HOURS, 10);
  if (Number.isInteger(raw) && raw >= 1 && raw <= 24) {
    return raw;
  }
  if (process.env.CONFIG_PULL_INTERVAL_HOURS) {
    logger.warn(
      `CONFIG_PULL_INTERVAL_HOURS value "${process.env.CONFIG_PULL_INTERVAL_HOURS}" is not a valid integer between 1 and 24 — falling back to ${fallback}.`
    );
  }
  return fallback;
}

function buildHourlyCron(intervalHours) {
  let n = parseInt(intervalHours, 10);
  if (!Number.isInteger(n) || n < 1 || n > 24) {
    logger.warn(`Invalid cron interval hours "${intervalHours}" — falling back to 6.`);
    n = 6;
  }
  return `0 */${n} * * *`;
}

// VPN session polling (added 2026-07-19) runs far more often than the other
// two jobs (a coarse "how many active sessions right now" trend needs
// minutes-scale sampling, not hours) — a separate minutes-based interval,
// clamped to 5-59 so `*/n * * * *` never needs to cross an hour boundary
// (a value >= 60 would silently produce a nonsensical cron expression).
function getVpnPollIntervalMinutes() {
  const fallback = 30;
  const raw = parseInt(process.env.VPN_POLL_INTERVAL_MINUTES, 10);
  if (Number.isInteger(raw) && raw >= 5 && raw <= 59) {
    return raw;
  }
  if (process.env.VPN_POLL_INTERVAL_MINUTES) {
    logger.warn(
      `VPN_POLL_INTERVAL_MINUTES value "${process.env.VPN_POLL_INTERVAL_MINUTES}" is not a valid integer between 5 and 59 — falling back to ${fallback}.`
    );
  }
  return fallback;
}

function buildMinutelyCron(intervalMinutes) {
  let n = parseInt(intervalMinutes, 10);
  if (!Number.isInteger(n) || n < 5 || n > 59) {
    logger.warn(`Invalid cron interval minutes "${intervalMinutes}" — falling back to 30.`);
    n = 30;
  }
  return `*/${n} * * * *`;
}

// SNMP metric polling (added 2026-07-21, see CLAUDE.md's "SNMP Monitoring"
// section) — same minutes-scale rationale as VPN session polling above, but
// SNMP over UDP is lighter-weight than an SSH/REST session, so the default
// interval is shorter. Same 5-59 clamp for the same `*/n * * * *` reason.
function getSnmpPollIntervalMinutes() {
  const fallback = 15;
  const raw = parseInt(process.env.SNMP_POLL_INTERVAL_MINUTES, 10);
  if (Number.isInteger(raw) && raw >= 5 && raw <= 59) {
    return raw;
  }
  if (process.env.SNMP_POLL_INTERVAL_MINUTES) {
    logger.warn(
      `SNMP_POLL_INTERVAL_MINUTES value "${process.env.SNMP_POLL_INTERVAL_MINUTES}" is not a valid integer between 5 and 59 — falling back to ${fallback}.`
    );
  }
  return fallback;
}

// Retention for vpn_session_snapshots/snmp_metric_snapshots (added 2026-07-30
// — see lib/schema.sql's "no retention/cleanup job yet" notes on both
// tables). Day-granularity, not hour/minute like the poll jobs above — this
// is a housekeeping job, not a data-freshness one.
// Outbound alerting (added 2026-08-01) — same minutes-scale rationale as VPN/
// SNMP polling above (patch_now CVEs/critical compliance failures/config
// diffs need to reach a human within minutes, not hours), same 5-59 clamp
// for the same `*/n * * * *` reason. Default shorter than SNMP's since a
// missed patch_now alert is more consequential than a missed metric sample.
function getNotificationsPollIntervalMinutes() {
  const fallback = 15;
  const raw = parseInt(process.env.NOTIFICATIONS_POLL_INTERVAL_MINUTES, 10);
  if (Number.isInteger(raw) && raw >= 5 && raw <= 59) {
    return raw;
  }
  if (process.env.NOTIFICATIONS_POLL_INTERVAL_MINUTES) {
    logger.warn(
      `NOTIFICATIONS_POLL_INTERVAL_MINUTES value "${process.env.NOTIFICATIONS_POLL_INTERVAL_MINUTES}" is not a valid integer between 5 and 59 — falling back to ${fallback}.`
    );
  }
  return fallback;
}

function getSnapshotRetentionDays() {
  const fallback = 180;
  const raw = parseInt(process.env.SNMP_VPN_RETENTION_DAYS, 10);
  if (Number.isInteger(raw) && raw >= 1) {
    return raw;
  }
  if (process.env.SNMP_VPN_RETENTION_DAYS) {
    logger.warn(
      `SNMP_VPN_RETENTION_DAYS value "${process.env.SNMP_VPN_RETENTION_DAYS}" is not a valid positive integer — falling back to ${fallback}.`
    );
  }
  return fallback;
}

// ---------------------------------------------------------------------------
// Job bodies — each independently try/catch'd. A single job failure must
// never crash the process or stop future scheduled runs.
// ---------------------------------------------------------------------------

async function runFeedSyncAndMatchJob() {
  const start = Date.now();
  logger.info('Job [feed-sync-and-match] starting.');
  try {
    const syncResult = await runFullSync(pool);
    logger.info(`Job [feed-sync-and-match] feed sync complete: ${JSON.stringify(syncResult)}`);

    const matchResult = await runMatchForAllDevices(pool);
    logger.info(`Job [feed-sync-and-match] CVE match complete: ${JSON.stringify(matchResult)}`);

    const durationMs = Date.now() - start;
    logger.info(`Job [feed-sync-and-match] finished successfully in ${durationMs}ms.`);
  } catch (err) {
    const durationMs = Date.now() - start;
    logger.error(`Job [feed-sync-and-match] failed after ${durationMs}ms: ${err.stack || err.message}`);
  }
}

// Vendor dispatch lives in lib/adapters (getAdapter inside collectAndStore) —
// this wrapper only guards against unknown vendors so the job loop logs a
// warning instead of an error for them.
async function collectForDevice(device) {
  if (SUPPORTED_VENDORS.includes(device.vendor)) {
    return collectAndStore(device, pool);
  }
  logger.warn(`Job [rule-version-pull] Skipping device ${device.id} (${device.name || 'unnamed'}) — unsupported vendor "${device.vendor}". Supported: ${SUPPORTED_VENDORS.join(', ')}.`);
  return null;
}

// ⛔ Overlap guards added 2026-07-19, found in a follow-up bug sweep:
// node-cron 3.x has NO overlap protection of its own — each scheduled tick
// fires unconditionally, even if the previous invocation of the SAME job is
// still running. This was a latent risk even before the VPN job existed
// (rule-version-pull can run for minutes on a real fleet, in principle
// overlapping its own next hourly-multiple tick), but became a routinely
// REACHABLE one once vpn-session-poll started running every 5-59 MINUTES:
// (a) vpn-session-poll can overlap itself if a poll cycle runs long, and
// (b) vpn-session-poll and rule-version-pull can run concurrently against
// the SAME device, opening two separate SSH/REST sessions to one firewall
// at once — lib/adapters/fortinet/api.js's own comment notes a concurrent
// admin-session cap that a second overlapping session can hit. Two simple
// boolean flags (not a full per-device lock — that's a bigger change,
// deferred) close the two most reachable cases: a job never re-enters
// itself, and vpn-session-poll (a coarse, can-wait-a-cycle trend signal)
// defers a whole tick rather than run concurrently with the
// higher-priority, authoritative rule-version-pull job.
let ruleVersionPullInFlight = false;
let vpnPollInFlight = false;
let snmpPollInFlight = false;

// One-time (per process) diagnostic sample of a real per-user VPN session,
// logged through winston (-> engine.log, unlike the adapters' console.log
// [*Debug] dumps whose stdout capture depends on the NSSM redirect config).
// Fires on the FIRST device that actually returns a session, so the sample has
// populated fields. Includes the normalized shape AND its `raw` (the device's
// own field names — XML entry keys, or the SSH text-block labels), which is
// exactly what's needed to correct any field mapping (e.g. Assigned IP /
// Duration) against real firmware output.
let loggedVpnUserSample = false;

async function runRuleVersionPullJob() {
  if (ruleVersionPullInFlight) {
    logger.warn('Job [rule-version-pull] previous run still in progress — skipping this tick.');
    return;
  }
  ruleVersionPullInFlight = true;
  const start = Date.now();
  logger.info('Job [rule-version-pull] starting.');
  try {
    const { rows: devices } = await pool.query('SELECT * FROM devices WHERE active = true');
    logger.info(`Job [rule-version-pull] processing ${devices.length} active device(s).`);

    let anyConfigChanged = false;

    for (const device of devices) {
      try {
        const collectResult = await collectForDevice(device);
        if (collectResult) {
          if (collectResult.configChanged) anyConfigChanged = true;
          // ⛔ "OK" was logged even when NOTHING was collected. TSR_EKC has been
          // fully unreachable since 2026-08-06 and every cycle still logged
          // "collected device ... OK — rules: n/a". A run that produced no rules
          // AND no config is a FAILURE and now says so, at WARN.
          const collectedSomething =
            collectResult.rulesCount != null || collectResult.configCollected === true;
          const level = collectedSomething ? 'info' : 'warn';
          await recordConnectivity(pool, device.id, {
            reachable: collectedSomething,
            source: 'collect',
            message: collectedSomething ? null : (collectResult.errors || []).join('; ') || 'nothing collected',
          });
          logger[level](
            `Job [rule-version-pull] device ${device.id} (${device.name || 'unnamed'}) ${collectedSomething ? 'collected OK' : 'COLLECTED NOTHING'} — ` +
              `rules: ${collectResult.rulesCount ?? 'n/a'}, findings: ${collectResult.analysisFindings ?? 'n/a'}, ` +
              `configChanged: ${collectResult.configChanged}` +
              (collectResult.errors.length ? `, partial errors: ${collectResult.errors.join('; ')}` : '')
          );
        }
      } catch (deviceErr) {
        logger.error(
          `Job [rule-version-pull] failed for device ${device.id} (${device.name || 'unnamed'}): ${deviceErr.stack || deviceErr.message}`
        );
      }
    }

    // Phase 6: a config change can flip config_applies on existing assessments.
    // Re-run the CVE match immediately rather than waiting up to 6h for the
    // next feed-sync-and-match cycle.
    if (anyConfigChanged) {
      logger.info('Job [rule-version-pull] config change detected — re-running CVE match/prioritization.');
      const matchResult = await runMatchForAllDevices(pool);
      logger.info(`Job [rule-version-pull] CVE re-match complete: ${JSON.stringify(matchResult)}`);
    }

    const durationMs = Date.now() - start;
    logger.info(`Job [rule-version-pull] finished successfully in ${durationMs}ms.`);
  } catch (err) {
    const durationMs = Date.now() - start;
    logger.error(`Job [rule-version-pull] failed after ${durationMs}ms: ${err.stack || err.message}`);
  } finally {
    ruleVersionPullInFlight = false;
  }
}

// VPN active-session snapshot poll — a coarse, no-syslog-ingestion-required
// substitute for real VPN usage telemetry (see lib/schema.sql's
// vpn_session_snapshots comment for the full rationale). Only devices whose
// adapter implements the OPTIONAL getVpnSessionSummary() capability are
// polled — most vendors don't (checked via `typeof ... === 'function'`,
// never assumed present). A row is only ever inserted on a successful poll;
// a failure for one device is logged and skipped, never fatal to the job or
// to other devices in the same run — same per-device isolation as
// runRuleVersionPullJob above.
async function runVpnSessionPollJob() {
  if (vpnPollInFlight) {
    logger.warn('Job [vpn-session-poll] previous run still in progress — skipping this tick.');
    return;
  }
  if (ruleVersionPullInFlight) {
    // A coarse trend signal can wait one cycle; rule-version-pull is the
    // higher-priority, authoritative collection and shouldn't share SSH/REST
    // sessions to the same devices with a concurrent VPN poll.
    logger.info('Job [vpn-session-poll] rule-version-pull is in progress — deferring this tick.');
    return;
  }
  // Symmetric counterpart to the guard in runSnmpPollJob(): that job now opens
  // SSH sessions too, so whichever starts first wins and the other skips a tick
  // rather than contending for the same device's admin sessions.
  if (snmpPollInFlight) {
    logger.info('Job [vpn-session-poll] snmp-poll is in progress — deferring this tick.');
    return;
  }
  vpnPollInFlight = true;
  const start = Date.now();
  logger.info('Job [vpn-session-poll] starting.');
  try {
    const { rows: devices } = await pool.query('SELECT * FROM devices WHERE active = true');

    let polled = 0;
    let skipped = 0;

    for (const device of devices) {
      if (!SUPPORTED_VENDORS.includes(device.vendor)) continue;

      let adapter;
      try {
        adapter = getAdapter(device, pool);
      } catch (err) {
        logger.warn(`Job [vpn-session-poll] could not build adapter for device ${device.id}: ${err.message}`);
        continue;
      }

      if (typeof adapter.getVpnSessionSummary !== 'function') {
        skipped += 1;
        continue;
      }

      try {
        const summary = await adapter.getVpnSessionSummary();
        await pool.query(
          `INSERT INTO vpn_session_snapshots (device_id, active_session_count, raw)
           VALUES ($1, $2, $3::jsonb)`,
          [device.id, summary.active_session_count, JSON.stringify(summary.raw || null)]
        );
        await recordConnectivity(pool, device.id, { reachable: true, source: 'vpn' });
        // Per-user active-session DETAIL (additive, 2026-07-31). Only when the
        // adapter provided it (vendors not yet emitting `sessions` are simply
        // skipped) — and only on THIS successful poll, so a failed pull never
        // wipes the last-known set. An empty array from a successful poll
        // legitimately clears the device's rows (nobody connected right now).
        if (Array.isArray(summary.sessions)) {
          if (!loggedVpnUserSample && summary.sessions.length > 0) {
            loggedVpnUserSample = true;
            try {
              logger.info(
                `[VPN-USER-SAMPLE] device ${device.name || device.id} (${device.vendor}) first of ${summary.sessions.length}: ${JSON.stringify(summary.sessions[0])}`
              );
            } catch (_logErr) {
              /* never let a diagnostic log break the poll */
            }
          }
          try {
            await storeVpnSessions(device.id, summary.sessions, pool);
          } catch (sessErr) {
            logger.warn(
              `Job [vpn-session-poll] stored the count for device ${device.id} but failed to store session detail: ${sessErr.message}`
            );
          }
        }

        // IPSec site-to-site tunnel status (additive, 2026-07-31) — a SEPARATE
        // optional adapter method + command. Isolated in its own try/catch so a
        // tunnel-pull failure (a different command, may have its own access
        // requirements) never fails the session poll above. Only a successful
        // pull writes; [] legitimately clears (no tunnels).
        if (typeof adapter.getVpnTunnels === 'function') {
          try {
            const tunnels = await adapter.getVpnTunnels();
            await storeVpnTunnels(device.id, tunnels, pool);
          } catch (tunErr) {
            logger.warn(
              `Job [vpn-session-poll] IPSec tunnel pull failed for device ${device.id} (${device.name || 'unnamed'}): ${tunErr.message}`
            );
          }
        }
        polled += 1;
      } catch (err) {
        // Full stack (not just err.message) plus vendor/mgmt_method — engine.log
        // is currently the ONLY trail for a device that fails every single
        // poll (no per-device error column exists to persist to yet). Keeping
        // this line grep-able by device id/vendor is what makes "genuinely
        // idle, 0 sessions" vs "silently failing every tick" diagnosable at
        // all until a DB-visible last-error column is added (out of scope
        // here — see devices table in lib/schema.sql).
        logger.warn(
          `Job [vpn-session-poll] failed for device ${device.id} (${device.name || 'unnamed'}, vendor=${device.vendor}, mgmt_method=${device.mgmt_method}): ${err.stack || err.message}`
        );
        // ⛔ Added 2026-08-25. Until now ONLY the metric poll wrote connectivity
        // history, so a device whose metric poll succeeded but whose VPN poll
        // failed read as 100% healthy. TUG was exactly that: 166/166 on metrics
        // while ~23% of its VPN polls timed out waiting for an SSH prompt.
        await recordConnectivity(pool, device.id, { reachable: false, source: 'vpn', message: err.message });
      }
    }

    const durationMs = Date.now() - start;
    logger.info(
      `Job [vpn-session-poll] finished in ${durationMs}ms — polled ${polled}, skipped (no VPN capability) ${skipped}, ${devices.length} active device(s) total.`
    );
  } catch (err) {
    const durationMs = Date.now() - start;
    logger.error(`Job [vpn-session-poll] failed after ${durationMs}ms: ${err.stack || err.message}`);
  } finally {
    vpnPollInFlight = false;
  }
}

// Device metric snapshot poll ("snmp-poll" by name, for job-log continuity) —
// same shape as runVpnSessionPollJob above. A device is polled if its adapter
// implements EITHER of two optional capabilities, preferring the first:
//   1. getPerformanceMetrics() — the management transport (SSH/REST) the device
//      is already configured for. Needs no extra credential and no per-device
//      opt-in, so it runs for every ACTIVE device (v2.50.0).
//   2. getSnmpMetrics() — the original path, additionally gated on the DEVICE's
//      own snmp_enabled flag, because SNMP needs a separately-configured
//      community credential and, for Forcepoint, an explicit engine IP.
// A row is only ever inserted on a successful poll — a failure leaves the
// previous snapshot standing rather than writing a zero.
//
// ⚠️ Since (1) exists this job is NO LONGER a lightweight UDP-only poll: it
// opens real management sessions, exactly like the VPN poll and the
// rule-version pull. It therefore defers to BOTH of those rather than treating
// concurrency as a soft precaution.
async function runSnmpPollJob() {
  if (snmpPollInFlight) {
    logger.warn('Job [snmp-poll] previous run still in progress — skipping this tick.');
    return;
  }
  if (ruleVersionPullInFlight) {
    logger.info('Job [snmp-poll] rule-version-pull is in progress — deferring this tick.');
    return;
  }
  // ⛔ Added 2026-08-04. Until v2.50.0 this job was UDP-only (SNMP), so it never
  // needed to coordinate with the VPN poll. getPerformanceMetrics() now uses the
  // SSH/REST management transport, and at the default 15/30-minute intervals the
  // two jobs coincide at :00 and :30 every hour — both iterating the whole fleet,
  // with the VPN poll opening two sessions per device. FortiOS caps concurrent
  // admin sessions, so overlapping runs cause intermittent failures in BOTH jobs.
  if (vpnPollInFlight) {
    logger.info('Job [snmp-poll] vpn-session-poll is in progress — deferring this tick.');
    return;
  }
  snmpPollInFlight = true;
  const start = Date.now();
  logger.info('Job [snmp-poll] starting.');
  try {
    // ⛔ NOT gated on snmp_enabled any more. Some adapters can report the same
    // metrics over the management transport they ALREADY use (Fortinet SSH's
    // `get system performance status`, added 2026-08-04), which needs no SNMP
    // credential, no snmp_enabled flag, and carries none of the doc-derived-OID
    // uncertainty that forces lowConfidence on the SNMP path. Those devices
    // would otherwise never be polled at all. Devices with neither capability
    // are still skipped below, so this widens the query without widening work.
    const { rows: devices } = await pool.query(
      'SELECT * FROM devices WHERE active = true'
    );

    let polled = 0;
    let skipped = 0;

    for (const device of devices) {
      if (!SUPPORTED_VENDORS.includes(device.vendor)) continue;

      let adapter;
      try {
        adapter = getAdapter(device, pool);
      } catch (err) {
        logger.warn(`Job [snmp-poll] could not build adapter for device ${device.id}: ${err.message}`);
        continue;
      }

      // Prefer the management-transport source when the adapter has one — it is
      // strictly better data (no separate credential, no OID guesswork). SNMP
      // remains the path for every vendor that only implements getSnmpMetrics(),
      // and is still gated on the device having SNMP switched on.
      const hasPerf = typeof adapter.getPerformanceMetrics === 'function';
      const hasSnmp = typeof adapter.getSnmpMetrics === 'function' && device.snmp_enabled;
      if (!hasPerf && !hasSnmp) {
        skipped += 1;
        continue;
      }

      try {
        // ⛔ FALLBACK. getPerformanceMetrics() goes over the management
        // transport, which can fail for reasons SNMP would not (a busy CLI, an
        // admin-session cap, a config-mode lock). Before v2.55.0 that failure
        // ended the device's poll outright even when SNMP was configured and
        // would have answered — the better source silently made the fleet LESS
        // observable than before it existed. Try it first, fall back to SNMP
        // only if the device is actually opted in to SNMP.
        let metrics = null;
        let usedSource = null;
        if (hasPerf) {
          try {
            metrics = await adapter.getPerformanceMetrics();
            usedSource = 'metrics';
          } catch (perfErr) {
            if (!hasSnmp) throw perfErr;
            logger.warn(
              `Job [snmp-poll] getPerformanceMetrics failed for ${device.name || device.id} (${perfErr.message}) — falling back to SNMP.`
            );
          }
        }
        if (metrics === null) {
          metrics = await adapter.getSnmpMetrics();
          usedSource = 'snmp';
        }
        await pool.query(
          `INSERT INTO snmp_metric_snapshots (device_id, cpu_percent, memory_percent, session_count, uptime_seconds, raw, source, low_confidence)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`,
          [
            device.id,
            metrics.cpuPercent ?? null,
            metrics.memoryPercent ?? null,
            metrics.sessionCount ?? null,
            metrics.uptimeSeconds ?? null,
            JSON.stringify(metrics.raw || null),
            usedSource,
            // The adapter states this per reading; only default when it says
            // nothing, and default to the CAUTIOUS value (true) for SNMP.
            typeof metrics.lowConfidence === 'boolean' ? metrics.lowConfidence : usedSource === 'snmp',
          ]
        );
        polled += 1;
        // A successful metric read PROVES the device answered — record it as a
        // reachability sample. Free: no extra connection, the session already
        // happened. This is the fleet's densest heartbeat (every
        // SNMP_POLL_INTERVAL_MINUTES) for the vendors that implement it.
        await recordConnectivity(pool, device.id, { reachable: true, source: 'metrics' });
      } catch (err) {
        logger.warn(`Job [snmp-poll] failed for device ${device.id} (${device.name || 'unnamed'}): ${err.message}`);
        await recordConnectivity(pool, device.id, { reachable: false, source: 'metrics', message: err.message });
      }
    }

    const durationMs = Date.now() - start;
    logger.info(
      `Job [snmp-poll] finished in ${durationMs}ms — polled ${polled}, skipped (no metrics capability) ${skipped}, ${devices.length} active device(s) considered.`
    );
  } catch (err) {
    const durationMs = Date.now() - start;
    logger.error(`Job [snmp-poll] failed after ${durationMs}ms: ${err.stack || err.message}`);
  } finally {
    snmpPollInFlight = false;
  }
}

// Fleet Dashboard trend snapshot — one row/day (see lib/schema.sql's
// fleet_dashboard_snapshots comment). Pure query-only work (no per-device
// SSH/REST sessions), so unlike rule-version-pull/vpn-session-poll it needs
// no in-flight guard against those jobs — it can't contend for a device
// connection with either. Runs once daily at a fixed time (not a
// configurable interval like the other jobs — "once a day" is the actual
// requirement here, a settings-driven N-hour interval would just add drift
// risk for no benefit).
async function runDashboardSnapshotJob() {
  const start = Date.now();
  logger.info('Job [dashboard-snapshot] starting.');
  try {
    const { cve, compliance } = await computeAndStoreDashboardSnapshot(pool);
    const durationMs = Date.now() - start;
    logger.info(
      `Job [dashboard-snapshot] finished in ${durationMs}ms — CVE critical=${cve.critical} high=${cve.high} medium=${cve.medium} low=${cve.low}, compliance overall=${compliance.overall}.`
    );
  } catch (err) {
    const durationMs = Date.now() - start;
    logger.error(`Job [dashboard-snapshot] failed after ${durationMs}ms: ${err.stack || err.message}`);
  }
}

// Snapshot retention — deletes rows older than getSnapshotRetentionDays() from
// vpn_session_snapshots and snmp_metric_snapshots (see lib/schema.sql's
// comments on both tables — this closes the "no retention/cleanup job yet"
// gap noted there). Pure query-only work, same "no in-flight guard needed"
// reasoning as runDashboardSnapshotJob — it never opens a per-device SSH/REST
// session, so it can't contend with rule-version-pull/vpn-session-poll/
// snmp-poll for a device connection. Each table's DELETE is independently
// try/caught so one table's failure doesn't block the other's cleanup.
async function runSnapshotRetentionJob() {
  const start = Date.now();
  const retentionDays = getSnapshotRetentionDays();
  logger.info(`Job [snapshot-retention] starting (retention: ${retentionDays}d).`);
  let vpnDeleted = 0;
  let snmpDeleted = 0;
  let connDeleted = 0;
  try {
    const vpnResult = await pool.query(
      `DELETE FROM vpn_session_snapshots WHERE sampled_at < now() - ($1 || ' days')::interval`,
      [retentionDays]
    );
    vpnDeleted = vpnResult.rowCount || 0;
  } catch (err) {
    logger.error(`Job [snapshot-retention] vpn_session_snapshots cleanup failed: ${err.stack || err.message}`);
  }
  try {
    const snmpResult = await pool.query(
      `DELETE FROM snmp_metric_snapshots WHERE sampled_at < now() - ($1 || ' days')::interval`,
      [retentionDays]
    );
    snmpDeleted = snmpResult.rowCount || 0;
  } catch (err) {
    logger.error(`Job [snapshot-retention] snmp_metric_snapshots cleanup failed: ${err.stack || err.message}`);
  }
  try {
    // device_connectivity_history (v2.54.0) — same window as the two above,
    // and its own try/catch so one table's failure never skips the others.
    const connResult = await pool.query(
      `DELETE FROM device_connectivity_history WHERE checked_at < now() - ($1 || ' days')::interval`,
      [retentionDays]
    );
    connDeleted = connResult.rowCount || 0;
  } catch (err) {
    logger.error(`Job [snapshot-retention] device_connectivity_history cleanup failed: ${err.stack || err.message}`);
  }
  const durationMs = Date.now() - start;
  logger.info(
    `Job [snapshot-retention] finished in ${durationMs}ms — deleted ${vpnDeleted} vpn_session_snapshots row(s), ${snmpDeleted} snmp_metric_snapshots row(s), ${connDeleted} device_connectivity_history row(s).`
  );
}

// Startup catch-up for the daily snapshot — see the call site's comment.
// Deliberately checks for TODAY's row rather than backfilling history: the
// counts it stores are all "as of now" values (current CVE bands, current
// compliance state), so a missed day cannot be reconstructed after the fact.
// Inventing one from today's numbers would fabricate history.
async function runDashboardSnapshotIfMissing() {
  try {
    const { rows } = await pool.query(
      'SELECT 1 FROM fleet_dashboard_snapshots WHERE snapshot_date = CURRENT_DATE LIMIT 1'
    );
    if (rows.length > 0) {
      logger.info('Startup [dashboard-snapshot] catch-up: today already recorded — skipping.');
      return;
    }
    logger.info("Startup [dashboard-snapshot] catch-up: today's snapshot missing — taking it now.");
    await runDashboardSnapshotJob();
  } catch (err) {
    logger.error(`Startup [dashboard-snapshot] catch-up check failed: ${err.stack || err.message}`);
  }
}

// Outbound alerting poll — checks for new patch_now CVEs / critical
// compliance failures / unacknowledged config diffs and dispatches to every
// enabled notification_channels row whose alert_types matches (see
// lib/engines/notificationDispatch.js for the full algorithm and
// lib/schema.sql's table comments for the dedup design). Decoupled from
// rule-version-pull/feed-sync-and-match (unrelated cadences: 24h/on-demand
// vs 6h) rather than hooked inline into either — a slow/dead webhook must
// never stall real data collection. Same "no in-flight guard needed"
// reasoning as runDashboardSnapshotJob/runSnapshotRetentionJob: this job
// never opens a per-device SSH/REST/SNMP session, so it can't contend for a
// device connection.
async function runNotificationDispatchJob() {
  const start = Date.now();
  logger.info('Job [notification-dispatch] starting.');
  try {
    const { dispatched, errors } = await runNotificationDispatch(pool);
    const durationMs = Date.now() - start;
    logger.info(
      `Job [notification-dispatch] finished in ${durationMs}ms — dispatched ${dispatched} alert(s), ${errors} error(s).`
    );
  } catch (err) {
    const durationMs = Date.now() - start;
    logger.error(`Job [notification-dispatch] failed after ${durationMs}ms: ${err.stack || err.message}`);
  }
}

// Monthly fleet compliance PDF report — email to every notification_channels
// row of channel_type='email' whose alert_types includes 'compliance_report'
// (see lib/engines/complianceReport.js's dispatchMonthlyReport, the SAME
// function POST /api/compliance/report/generate calls for a manual/ops send
// — one code path, not two). Idempotent per calendar month via
// compliance_report_log's partial unique index; a call that finds a
// 'success' row already logged this period is a fast, cheap no-op. Fixed
// monthly cron (not a configurable interval env var), same "housekeeping,
// not freshness" bucket as runDashboardSnapshotJob/runSnapshotRetentionJob.
// Same "no in-flight guard needed" reasoning as those two jobs as well —
// this never opens a per-device SSH/REST/SNMP session.
async function runComplianceReportJob() {
  const start = Date.now();
  logger.info('Job [compliance-report] starting.');
  try {
    const result = await dispatchMonthlyReport(pool);
    const durationMs = Date.now() - start;
    if (result.skipped) {
      logger.info(`Job [compliance-report] finished in ${durationMs}ms — skipped (${result.reason}).`);
    } else {
      logger.info(
        `Job [compliance-report] finished in ${durationMs}ms — period ${result.period}, sent to ${result.sent} channel(s).`
      );
    }
  } catch (err) {
    const durationMs = Date.now() - start;
    logger.error(`Job [compliance-report] failed after ${durationMs}ms: ${err.stack || err.message}`);
  }
}

// ---------------------------------------------------------------------------
// isJobRunning tracking (for graceful shutdown)
// ---------------------------------------------------------------------------

// ⛔ Bug fixed 2026-07-19, found while adding the VPN poll job above: this
// was a boolean, not a counter. runTrackedJob() set it true on entry and
// false on exit (in `finally`) — correct for exactly one job in flight at a
// time, but the two PRE-EXISTING jobs' cron cadences (every N hours, every
// M hours) were unlikely to ever overlap in practice, so this was a latent
// bug, not yet a reachable one. The new VPN poll job runs every 5-59
// MINUTES specifically so it produces a meaningful trend — meaning it will
// routinely overlap with the still-long-running rule-version-pull job
// (which sequentially collects every device over SSH/REST, credibly
// minutes to complete on a real fleet). With a boolean, job A finishing
// while job B is still running would flip the flag to false, and shutdown()
// would proceed to stop the process while job B was still mid-collect —
// exactly the "finish current job then exit" contract violation this
// codebase has already fixed once before (see the hardCeilingMs history
// below) reintroduced through a different mechanism. A counter tracks how
// many jobs are actually in flight, not just whether any one job's own
// finally block has run.
let runningJobCount = 0;

async function runTrackedJob(jobFn, jobName) {
  runningJobCount += 1;
  try {
    await jobFn();
  } catch (err) {
    // Should not normally reach here since job bodies self-catch, but guard
    // anyway so a scheduled job can never crash the process.
    logger.error(`Job [${jobName}] threw unexpectedly: ${err.stack || err.message}`);
  } finally {
    runningJobCount -= 1;
  }
}

// ---------------------------------------------------------------------------
// Startup sequence
// ---------------------------------------------------------------------------

let scheduledTasks = [];
let shuttingDown = false;

async function verifyDbConnectivity() {
  try {
    await pool.query('SELECT 1');
    logger.info('Database connectivity verified.');
  } catch (err) {
    logger.error(`Database connectivity check failed: ${err.message}`);
    // eslint-disable-next-line no-console
    console.error(`[engine-worker] FATAL: cannot connect to database. ${err.message}`);
    process.exit(1);
  }
}

async function scheduleJobs() {
  const feedPollIntervalHours = await getFeedPollIntervalHours();
  const feedCronExpr = buildHourlyCron(feedPollIntervalHours);
  logger.info(`Scheduling [feed-sync-and-match] with cron "${feedCronExpr}" (every ${feedPollIntervalHours}h).`);
  const feedTask = cron.schedule(feedCronExpr, () => {
    if (shuttingDown) return;
    runTrackedJob(runFeedSyncAndMatchJob, 'feed-sync-and-match');
  });

  const configPullIntervalHours = getConfigPullIntervalHours();
  const configCronExpr = buildHourlyCron(configPullIntervalHours);
  logger.info(`Scheduling [rule-version-pull] with cron "${configCronExpr}" (every ${configPullIntervalHours}h).`);
  const configTask = cron.schedule(configCronExpr, () => {
    if (shuttingDown) return;
    runTrackedJob(runRuleVersionPullJob, 'rule-version-pull');
  });

  const vpnPollIntervalMinutes = getVpnPollIntervalMinutes();
  const vpnCronExpr = buildMinutelyCron(vpnPollIntervalMinutes);
  logger.info(`Scheduling [vpn-session-poll] with cron "${vpnCronExpr}" (every ${vpnPollIntervalMinutes}m).`);
  const vpnTask = cron.schedule(vpnCronExpr, () => {
    if (shuttingDown) return;
    runTrackedJob(runVpnSessionPollJob, 'vpn-session-poll');
  });

  const snmpPollIntervalMinutes = getSnmpPollIntervalMinutes();
  const snmpCronExpr = buildMinutelyCron(snmpPollIntervalMinutes);
  logger.info(`Scheduling [snmp-poll] with cron "${snmpCronExpr}" (every ${snmpPollIntervalMinutes}m).`);
  const snmpTask = cron.schedule(snmpCronExpr, () => {
    if (shuttingDown) return;
    runTrackedJob(runSnmpPollJob, 'snmp-poll');
  });

  // Fixed daily time (00:10 UTC) rather than a configurable interval — see
  // runDashboardSnapshotJob()'s own comment for why.
  // ⛔ Catch-up. This job fires ONLY on the 00:10 UTC tick, so any restart or
  // outage spanning that minute loses that day permanently — the trend chart
  // showed 18 days of span but only 14 snapshots, i.e. 4 silently missing
  // days. Snapshots are the sole source of every day-over-day delta, so a lost
  // day is a lost comparison. On startup, take today's snapshot if it is not
  // already recorded; the upsert is keyed on snapshot_date, so this is
  // idempotent and a same-day restart just refreshes the row.
  runDashboardSnapshotIfMissing().catch((err) =>
    logger.error(`Startup [dashboard-snapshot] catch-up failed: ${err.stack || err.message}`)
  );

  logger.info('Scheduling [dashboard-snapshot] with cron "10 0 * * *" (daily).');
  const dashboardSnapshotTask = cron.schedule('10 0 * * *', () => {
    if (shuttingDown) return;
    runTrackedJob(runDashboardSnapshotJob, 'dashboard-snapshot');
  });

  // Fixed daily time (00:30 UTC, offset from dashboard-snapshot above so the
  // two don't tick at the exact same second) — same "housekeeping, not
  // freshness" reasoning as dashboard-snapshot for why this isn't a
  // configurable interval.
  logger.info('Scheduling [snapshot-retention] with cron "30 0 * * *" (daily).');
  const snapshotRetentionTask = cron.schedule('30 0 * * *', () => {
    if (shuttingDown) return;
    runTrackedJob(runSnapshotRetentionJob, 'snapshot-retention');
  });

  const notificationsPollIntervalMinutes = getNotificationsPollIntervalMinutes();
  const notificationsCronExpr = buildMinutelyCron(notificationsPollIntervalMinutes);
  logger.info(
    `Scheduling [notification-dispatch] with cron "${notificationsCronExpr}" (every ${notificationsPollIntervalMinutes}m).`
  );
  const notificationsTask = cron.schedule(notificationsCronExpr, () => {
    if (shuttingDown) return;
    runTrackedJob(runNotificationDispatchJob, 'notification-dispatch');
  });

  // Fixed monthly time (06:00 UTC on the 1st) — same "housekeeping, not
  // freshness" reasoning as dashboard-snapshot/snapshot-retention for why
  // this isn't a configurable interval; dispatchMonthlyReport()'s own
  // per-period idempotency check makes the immediate startup run in main()
  // below a safe no-op mid-month.
  logger.info('Scheduling [compliance-report] with cron "0 6 1 * *" (monthly).');
  const complianceReportTask = cron.schedule('0 6 1 * *', () => {
    if (shuttingDown) return;
    runTrackedJob(runComplianceReportJob, 'compliance-report');
  });

  scheduledTasks = [
    feedTask,
    configTask,
    vpnTask,
    snmpTask,
    dashboardSnapshotTask,
    snapshotRetentionTask,
    notificationsTask,
    complianceReportTask,
  ];
}

async function main() {
  logger.info('==================================================');
  logger.info('SecVault-Engine starting up.');
  logger.info(`Log directory: ${logDir || '(console only)'}`);
  logger.info('==================================================');

  await verifyDbConnectivity();

  // Immediate on-startup passes so data is fresh before any scheduled cycle fires.
  await runTrackedJob(runFeedSyncAndMatchJob, 'feed-sync-and-match');
  await runTrackedJob(runRuleVersionPullJob, 'rule-version-pull');
  await runTrackedJob(runVpnSessionPollJob, 'vpn-session-poll');
  await runTrackedJob(runSnmpPollJob, 'snmp-poll');
  await runTrackedJob(runDashboardSnapshotJob, 'dashboard-snapshot');
  // Runs on every startup (not just its 00:30 UTC cron tick) — cheap,
  // idempotent DELETEs, and this service restarts on every deploy (see
  // installer/Update-SecVault.ps1), so relying on the cron tick alone meant
  // it rarely ran in practice, leaving vpn_session_snapshots/
  // snmp_metric_snapshots to grow unbounded — the exact gap it exists to close.
  await runTrackedJob(runSnapshotRetentionJob, 'snapshot-retention');
  await runTrackedJob(runNotificationDispatchJob, 'notification-dispatch');
  // Safe no-op mid-month — dispatchMonthlyReport()'s own per-period
  // idempotency check (compliance_report_log) skips instantly once a
  // 'success' row already exists this period, same as every other job's
  // immediate-on-startup run.
  await runTrackedJob(runComplianceReportJob, 'compliance-report');

  await scheduleJobs();

  logger.info('SecVault-Engine startup complete. Scheduled jobs active.');
}

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info(`Received ${signal}. Stopping scheduled jobs and waiting for any in-flight job to finish.`);

  for (const task of scheduledTasks) {
    try {
      task.stop();
    } catch (err) {
      logger.warn(`Error stopping a scheduled task: ${err.message}`);
    }
  }

  const pollIntervalMs = 500;
  // Was 30000ms, sized for the original single lightweight SMC-only adapter.
  // The Tier-1 SSH adapters (Fortinet, Palo Alto, Cisco ASA, Sangfor) now
  // legitimately run a single config pull up to 120000ms, and devices are
  // collected sequentially in one job — a stop landing mid-pull used to be
  // hard-killed well before that pull could finish, silently truncating the
  // scheduled run for every device still queued behind it (found in a
  // follow-up bug sweep, 2026-07-17; the DELETE+reinsert itself is already
  // transaction-safe, so this was never a data-corruption risk, only a
  // "finish current job then exit" contract violation). Raised past the
  // largest single-adapter timeout so a mid-pull stop can actually finish.
  const hardCeilingMs = 150000;
  let waited = 0;
  while (runningJobCount > 0 && waited < hardCeilingMs) {
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    waited += pollIntervalMs;
  }

  if (runningJobCount > 0) {
    logger.warn(
      `Shutdown hard ceiling (${hardCeilingMs}ms) reached with ${runningJobCount} job(s) still in flight. Exiting anyway.`
    );
  } else {
    logger.info('No job in flight. Shutting down cleanly.');
  }

  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

main().catch((err) => {
  logger.error(`Unhandled error during startup: ${err.stack || err.message}`);
  // eslint-disable-next-line no-console
  console.error(`[engine-worker] FATAL during startup: ${err.stack || err.message}`);
  process.exit(1);
});
