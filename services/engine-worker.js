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
      } else {
        // ⛔ Strip an UNQUOTED trailing comment — see the identical guard in
        // services/collector.js. An inline '# ...' after a value was being read
        // AS the value, which is truthy, so the setting's own default never
        // engaged. Both loaders need this or the trap simply moves.
        const hash = value.indexOf('#');
        if (hash !== -1) value = value.slice(0, hash).trim();
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
const {
  storeVpnSessions,
  runVpnSessionRetention,
  DEFAULT_VPN_SESSION_RETENTION_DAYS,
} = require('../lib/engines/vpnSessions');
const { storeVpnTunnels } = require('../lib/engines/vpnTunnels');
const { runNotificationDispatch } = require('../lib/engines/notificationDispatch');
const { dispatchMonthlyReport, reportingPeriod } = require('../lib/engines/complianceReport');
const { recordConnectivity } = require('../lib/engines/connectivityHistory');
const { isCapabilityUnavailable } = require('../lib/adapters/interface');
const { runLogHitCorrelation } = require('../lib/engines/logHit');
const { runDeviceDiscovery } = require('../lib/engines/deviceDiscovery');
const {
  claimNextJob,
  reportProgress,
  finishJob,
  reapStaleJobs,
} = require('../lib/engines/backgroundJobs');
const {
  runConfigRetention,
  formatRetentionSummary,
  DEFAULT_CONFIG_RETENTION_DAYS,
  DEFAULT_BACKUP_RETENTION_DAYS,
} = require('../lib/engines/configRetention');

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

// Retention for vpn_sessions (added 2026-09-10, Phase B). A SEPARATE, much
// longer window than getSnapshotRetentionDays() above, and deliberately not
// folded into it: vpn_session_snapshots is a per-poll count sampled every
// 5-59 minutes (thousands of rows per device per month, a trend signal that
// ages out fine), while vpn_sessions is ONE ROW PER CONNECTION — ~180/day on
// the whole reference fleet — and is the record that "who was on the VPN when"
// is answered from. It is also far longer than SYSLOG_RETENTION_DAYS (30), on
// purpose: these rows are the durable index into evidence that is itself
// short-lived. Shrinking this to match either neighbour would delete the
// answer in order to keep the question.
function getVpnSessionRetentionDays() {
  const fallback = DEFAULT_VPN_SESSION_RETENTION_DAYS;
  const raw = parseInt(process.env.VPN_SESSION_RETENTION_DAYS, 10);
  if (Number.isInteger(raw) && raw >= 1) {
    return raw;
  }
  if (process.env.VPN_SESSION_RETENTION_DAYS) {
    logger.warn(
      `VPN_SESSION_RETENTION_DAYS value "${process.env.VPN_SESSION_RETENTION_DAYS}" is not a valid positive integer — falling back to ${fallback}.`
    );
  }
  return fallback;
}

// Retention for device_configs/config_backups (added 2026-08-25). Same
// day-granularity housekeeping shape as getSnapshotRetentionDays() above, but
// TWO windows because the two tables hold different things: device_configs is
// one full snapshot per device per pull whether or not anything changed (447 MB
// of a 529 MB database when this shipped), while config_backups only gains a
// row when a diff was actually detected — each of its rows is a real moment of
// change, ~1.5% of the volume, and deserves a far longer window.
//
// Fallbacks are imported from lib/engines/configRetention.js rather than
// re-declared here (unlike the older helpers above, which predate having a
// module to import from) so this file, .env.local.example and CLAUDE.md's env
// list cannot drift apart on the default.
// How far back [log-hit] looks for traffic reaching a curated exposed port.
//
// Deliberately SHORTER than SYSLOG_RETENTION_DAYS: the question is "is this
// service being reached now", and a 30-day window would keep a band elevated
// for a month after an exposure was actually closed. Clamped in the engine to
// 90 days regardless of what is set here.
// Window the discovery job looks back over.
//
// ⛔ MUST stay far shorter than SYSLOG_RETENTION_DAYS. The rollup copies
// device_id verbatim and never re-resolves it, so historical rows for a
// now-promoted sender keep device_id NULL permanently — an unbounded lookback
// would re-list every promoted device forever.
function getDiscoveryLookbackHours() {
  const fallback = 48;
  const raw = parseInt(process.env.DISCOVERY_LOOKBACK_HOURS, 10);
  if (Number.isInteger(raw) && raw >= 2) return raw;
  if (process.env.DISCOVERY_LOOKBACK_HOURS) {
    logger.warn(
      `DISCOVERY_LOOKBACK_HOURS value "${process.env.DISCOVERY_LOOKBACK_HOURS}" is not a valid integer >= 2 — falling back to ${fallback}.`
    );
  }
  return fallback;
}

function getLogHitLookbackDays() {
  const fallback = 7;
  const raw = parseInt(process.env.LOG_HIT_LOOKBACK_DAYS, 10);
  if (Number.isInteger(raw) && raw >= 1) {
    return raw;
  }
  if (process.env.LOG_HIT_LOOKBACK_DAYS) {
    logger.warn(
      `LOG_HIT_LOOKBACK_DAYS value "${process.env.LOG_HIT_LOOKBACK_DAYS}" is not a valid positive integer — falling back to ${fallback}.`
    );
  }
  return fallback;
}

function getConfigRetentionDays() {
  const fallback = DEFAULT_CONFIG_RETENTION_DAYS;
  const raw = parseInt(process.env.CONFIG_RETENTION_DAYS, 10);
  if (Number.isInteger(raw) && raw >= 1) {
    return raw;
  }
  if (process.env.CONFIG_RETENTION_DAYS) {
    logger.warn(
      `CONFIG_RETENTION_DAYS value "${process.env.CONFIG_RETENTION_DAYS}" is not a valid positive integer — falling back to ${fallback}.`
    );
  }
  return fallback;
}

function getConfigBackupRetentionDays() {
  const fallback = DEFAULT_BACKUP_RETENTION_DAYS;
  const raw = parseInt(process.env.CONFIG_BACKUP_RETENTION_DAYS, 10);
  if (Number.isInteger(raw) && raw >= 1) {
    return raw;
  }
  if (process.env.CONFIG_BACKUP_RETENTION_DAYS) {
    logger.warn(
      `CONFIG_BACKUP_RETENTION_DAYS value "${process.env.CONFIG_BACKUP_RETENTION_DAYS}" is not a valid positive integer — falling back to ${fallback}.`
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

// ⛔ THERE IS DELIBERATELY NO SEPARATE rule-cleanup-verification JOB, and adding
// one would be a false safety net rather than extra coverage.
//
// Verification runs inside collectAndStore, immediately after a SUCCESSFUL
// rules pull. That is not merely a convenient hook — it is the only moment at
// which any new evidence exists. Its two inputs are firewall_rules (rewritten
// ONLY by a successful pull) and devices.last_rules_collected_at (stamped ONLY
// by a successful pull). Between pulls both are byte-identical to what the last
// verification already read, so a sweep on its own schedule could not reach a
// different conclusion; the only thing it could change is flipping a `pending`
// item to `unverifiable` on no new information, which reads to an operator as
// activity where there was none.
//
// A request submitted while collection is idle is therefore not stranded: it is
// picked up by the very next successful pull of that device — this job, or an
// on-demand collect from /api/devices/[id]/collect, which is the "verify now"
// path. Until then it stays honestly pending/unverifiable, which is the correct
// answer, not a gap to be papered over by re-asking the same question hourly.
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
          // Rule-cleanup verification summary, when it ran (it only runs after
          // a SUCCESSFUL rules pull — see collectAndStore). Logged separately
          // from the counts above because the operator-visible claim here is
          // "SecVault confirmed these rules are gone", and an `unverifiable`
          // count is the honest statement that no usable pull has happened
          // since the request was submitted — never a failure, and never to be
          // read as still_present.
          const rcv = collectResult.ruleChangeVerification;
          const rcvSummary = rcv && rcv.checked > 0
            ? `, ruleCleanup: checked ${rcv.checked} (removed ${rcv.removed}, stillPresent ${rcv.stillPresent}, unverifiable ${rcv.unverifiable})`
            : '';
          logger[level](
            `Job [rule-version-pull] device ${device.id} (${device.name || 'unnamed'}) ${collectedSomething ? 'collected OK' : 'COLLECTED NOTHING'} — ` +
              `rules: ${collectResult.rulesCount ?? 'n/a'}, findings: ${collectResult.analysisFindings ?? 'n/a'}, ` +
              `configChanged: ${collectResult.configChanged}` +
              rcvSummary +
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
    // vpn_sessions history counters (Phase B). `vpnUnsessionizable` is the one
    // that matters most in the log: it is the number of connected users whose
    // device gave no usable login_time, so they cannot be keyed into history
    // and are simply MISSING from it. Counting them keeps that gap visible
    // instead of letting history quietly under-report the fleet.
    let vpnHistoryUpserted = 0;
    let vpnHistoryEnded = 0;
    let vpnUnsessionizable = 0;

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
            // ⛔ THIS LINE IS INSIDE THE SUCCESS PATH, and that placement is
            // load-bearing for vpn_sessions history (Phase B, 2026-09-10):
            // storeVpnSessions() ends every open session for this device that
            // the poll did not list, so reaching it after a FAILED
            // getVpnSessionSummary() would fabricate a mass disconnection of
            // every user on one unreachable firewall. The await above throws
            // straight to the per-device catch, so a failed poll never gets
            // here — do not hoist this call out of the try, and do not add a
            // catch around getVpnSessionSummary() that falls through to it.
            //
            // The poll interval is passed through and stored per row as the
            // ERROR BAR on that session's end time: we only ever learn a
            // session ended by not seeing it again, so the end is known to
            // within one interval and the duration is a lower bound.
            const sessResult = await storeVpnSessions(device.id, summary.sessions, pool, {
              pollIntervalSeconds: getVpnPollIntervalMinutes() * 60,
            });
            vpnHistoryUpserted += sessResult.historyUpserted || 0;
            vpnHistoryEnded += sessResult.ended || 0;
            vpnUnsessionizable += sessResult.unsessionizable || 0;
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
        //
        // ⛔ REFINED 2026-09-09: not every failure here is reachability
        // evidence. A CapabilityUnavailableError means the transport worked —
        // SSH connected, logged in, ran the command — and only the FEATURE was
        // unreadable, almost always because it is not configured. Recording
        // that as `reachable: false` reported "this device is down" about a
        // firewall that had answered; OKF(F2) showed "Failing 0% of polls
        // succeeding" with a full collection minutes old. `reachable: true` is
        // the honest reading, because the device demonstrably WAS reached; the
        // capability gap is preserved in the message, which is a different
        // fact from reachability and does not belong in the same boolean.
        if (isCapabilityUnavailable(err)) {
          await recordConnectivity(pool, device.id, {
            reachable: true,
            source: 'vpn',
            message: `reached, but the VPN session count could not be read: ${err.message}`,
          });
        } else {
          await recordConnectivity(pool, device.id, { reachable: false, source: 'vpn', message: err.message });
        }
      }
    }

    const durationMs = Date.now() - start;
    logger.info(
      `Job [vpn-session-poll] finished in ${durationMs}ms — polled ${polled}, skipped (no VPN capability) ${skipped}, ${devices.length} active device(s) total; history: ${vpnHistoryUpserted} session(s) upserted, ${vpnHistoryEnded} ended, ${vpnUnsessionizable} not sessionizable (no usable login_time — connected, but absent from history).`
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
        // ⛔ THREE outcomes, not two (2026-09-09). Until now this poll knew only
        // "a row was written" and "something threw", and filed the second as
        // `reachable: false` — the same conflation that made the VPN poll report
        // "Failing 0% of polls succeeding" about a firewall answering every other
        // poll, except this is the fleet's DENSEST heartbeat, so one unreadable
        // capability here outweighs every other source in worstRate.
        //
        //   1. metrics stored            → reachable: true  (above; the read itself is the proof)
        //   2. CapabilityUnavailableError → reachable: true  (here; connect + login +
        //      command all succeeded and only the FEATURE was unreadable — the
        //      device demonstrably answered. The gap is kept in the message,
        //      which is a different fact from reachability and does not belong
        //      in the same boolean.)
        //   3. anything else             → reachable: false (a connect, login,
        //      auth or timeout failure IS reachability evidence and must keep
        //      counting against the device — including a missing credential and
        //      the pre-network snmp_host checks, which is exactly why those
        //      throws stay bare Errors in the adapters.)
        //
        // ⛔ Detection is by the err.deviceWasReached FLAG via
        // isCapabilityUnavailable(), never instanceof: adapters and engines load
        // through several paths here and an instanceof across two module
        // instances of interface.js silently returns false — which would fail
        // CLOSED into case 3 and quietly restore the bug.
        if (isCapabilityUnavailable(err)) {
          await recordConnectivity(pool, device.id, {
            reachable: true,
            source: 'metrics',
            message: `reached, but the metric reading could not be taken: ${err.message}`,
          });
        } else {
          await recordConnectivity(pool, device.id, { reachable: false, source: 'metrics', message: err.message });
        }
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
//
// `options.ifAbsent` is used only by the startup catch-up below: it makes the
// write an INSERT ... ON CONFLICT DO NOTHING, so an already-recorded day is
// left exactly as measured. The 00:10 tick calls this with no options and
// keeps its original upsert semantics.
async function runDashboardSnapshotJob(options = {}) {
  const ifAbsent = (options && options.ifAbsent) === true;
  const start = Date.now();
  logger.info(`Job [dashboard-snapshot] starting${ifAbsent ? ' (catch-up: write only if today is unrecorded).' : '.'}`);
  try {
    const { cve, compliance, stored } = await computeAndStoreDashboardSnapshot(pool, { ifAbsent });
    const durationMs = Date.now() - start;
    logger.info(
      `Job [dashboard-snapshot] finished in ${durationMs}ms — ${stored ? 'row written' : "today already recorded, left untouched"}; CVE critical=${cve.critical} high=${cve.high} medium=${cve.medium} low=${cve.low}, compliance overall=${compliance.overall}.`
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
//
// TWO WINDOWS, not one: the three sampled-telemetry tables share
// getSnapshotRetentionDays(), while vpn_sessions gets its own far longer
// getVpnSessionRetentionDays() — see that helper for why they must not be
// merged.
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
  // vpn_sessions (Phase B, 2026-09-10) — its OWN, much longer window, keyed on
  // last_seen_at so a session still being observed is never aged out however
  // long it has been up. runVpnSessionRetention() never throws and reports its
  // own error; the try/catch here is the same belt-and-braces the three DELETEs
  // above carry, so one table can never skip another's cleanup.
  const vpnSessionRetentionDays = getVpnSessionRetentionDays();
  let vpnSessionsDeleted = 0;
  try {
    const sessionResult = await runVpnSessionRetention(pool, { retentionDays: vpnSessionRetentionDays });
    vpnSessionsDeleted = sessionResult.deleted;
    if (sessionResult.error) {
      logger.error(`Job [snapshot-retention] vpn_sessions cleanup failed: ${sessionResult.error}`);
    }
  } catch (err) {
    logger.error(`Job [snapshot-retention] vpn_sessions cleanup failed: ${err.stack || err.message}`);
  }
  const durationMs = Date.now() - start;
  logger.info(
    `Job [snapshot-retention] finished in ${durationMs}ms — deleted ${vpnDeleted} vpn_session_snapshots row(s), ${snmpDeleted} snmp_metric_snapshots row(s), ${connDeleted} device_connectivity_history row(s), ${vpnSessionsDeleted} vpn_sessions row(s) (${vpnSessionRetentionDays}d window).`
  );
}

// Config retention — device_configs/config_backups, the two config-snapshot
// tables (added 2026-08-25; device_configs was 84% of the whole database and
// had no retention of any kind). Same "housekeeping, not freshness" shape as
// snapshot-retention above: query-only work that never opens a device session,
// so it cannot contend with rule-version-pull/vpn-session-poll/snmp-poll.
//
// runConfigRetention() never throws and reports per-table errors inside its
// summary; the extra try/catch here is the same belt-and-braces every other
// job body carries. Its log line deliberately states what was KEPT and why
// (baselines, newest-per-device, min-keep, within-window) alongside what was
// deleted, so an operator reading engine.log can tell retention from data loss.
async function runConfigRetentionJob() {
  const start = Date.now();
  const configRetentionDays = getConfigRetentionDays();
  const backupRetentionDays = getConfigBackupRetentionDays();
  logger.info(
    `Job [config-retention] starting (device_configs: ${configRetentionDays}d, config_backups: ${backupRetentionDays}d, 'auto' label only).`
  );
  try {
    const summary = await runConfigRetention(pool, { configRetentionDays, backupRetentionDays });
    const durationMs = Date.now() - start;
    logger.info(`Job [config-retention] finished in ${durationMs}ms.`);
    for (const line of formatRetentionSummary(summary)) {
      if (line.includes('FAILED')) logger.error(`Job [config-retention] ${line}`);
      else logger.info(`Job [config-retention] ${line}`);
    }
  } catch (err) {
    const durationMs = Date.now() - start;
    logger.error(`Job [config-retention] failed after ${durationMs}ms: ${err.stack || err.message}`);
  }
}

// Surfaces firewalls sending syslog from an address matching no device row.
//
// ⛔ SURFACES ONLY — it never inserts into `devices`. Promotion requires an
// admin to supply working credentials, which is what keeps an unauthenticated,
// trivially spoofable syslog packet out of the CVE / compliance / security-score
// denominators.
//
// Hourly at :35, offset from [log-hit] at :20 so two syslog-reading jobs do not
// overlap. Cheap by construction: it reads the small hourly rollup, plus one
// narrow 15-minute slice of raw events for hostnames.
async function runDeviceDiscoveryJob() {
  const start = Date.now();
  logger.info(`Job [device-discovery] starting.`);
  try {
    const s = await runDeviceDiscovery(pool, {
      lookbackHours: getDiscoveryLookbackHours(),
    });
    const durationMs = Date.now() - start;
    logger.info(
      `Job [device-discovery] finished in ${durationMs}ms: ${s.candidates} candidate sender(s), ` +
        `${s.inserted} new, ${s.updated} updated` +
        (s.reset ? `, ${s.reset} reset to new (their device was deleted)` : '') +
        ` (thresholds: seen in >=${s.minHours} distinct hours, >=${s.minEvents} events ` +
        `over ${s.lookbackHours}h).`
    );
    for (const e of s.errors) logger.error(`Job [device-discovery] error: ${JSON.stringify(e)}`);
  } catch (err) {
    const durationMs = Date.now() - start;
    logger.error(`Job [device-discovery] failed after ${durationMs}ms: ${err.stack || err.message}`);
  }
}

// Produces `log_hit`, decision rule 2 of the CVE priority tree.
//
// Runs in the ENGINE and never on page load: it reads the pre-aggregated
// `syslog_device_inbound_hourly` rollup (NOT raw `syslog_events` -- that form of
// the query was measured at over two minutes for one device-day, which is
// why the rollup exists)
// over a bounded lookback, which is a background cost, not an interactive
// one. Hourly rather than per-poll because "was this service reached in the
// last week" does not change minute to minute, and each pass re-derives the
// priority band for any device whose value moved.
//
// With `advisory_conditions` empty this returns immediately without touching
// syslog at all — see runLogHitCorrelation.
async function runLogHitJob() {
  const start = Date.now();
  const lookbackDays = getLogHitLookbackDays();
  logger.info(`Job [log-hit] starting (lookback ${lookbackDays}d).`);
  try {
    const s = await runLogHitCorrelation(pool, { lookbackDays });
    const durationMs = Date.now() - start;
    if (s.curatedAdvisories === 0) {
      // ⛔ Say WHY nothing happened. A silent zero here reads as "nothing is
      // reachable", when it actually means nobody has curated a port yet.
      logger.info(
        `Job [log-hit] finished in ${durationMs}ms: no advisory has a curated port_exposed ` +
          `condition, so log_hit cannot be evaluated. Curate at /vulnerability/advisories.`
      );
    } else {
      logger.info(
        `Job [log-hit] finished in ${durationMs}ms: ${s.curatedAdvisories} curated advisories, ` +
          `${s.devicesConsidered} devices, set true=${s.setTrue} false=${s.setFalse}, ` +
          `reprioritized ${s.reprioritized}; skipped ${s.devicesSkippedNoCoverage} for no syslog ` +
          `coverage and ${s.devicesSkippedNoInterfaces} for no collected interfaces (UNMEASURED, not clean).`
      );
      for (const h of s.hits) {
        logger.warn(
          `Job [log-hit] REACHED device=${h.deviceId} advisory=${h.advisoryId} port=${h.port} ` +
            `events=${h.events} distinct_public_sources=${h.sources} last=${h.lastSeen}`
        );
      }
    }
    for (const e of s.errors) logger.error(`Job [log-hit] error: ${JSON.stringify(e)}`);
  } catch (err) {
    const durationMs = Date.now() - start;
    logger.error(`Job [log-hit] failed after ${durationMs}ms: ${err.stack || err.message}`);
  }
}

// Startup catch-up for the daily snapshot. The [dashboard-snapshot] cron
// fires ONLY on the 00:10 tick, and node-cron does not re-run a tick missed
// while the process was down — so a deploy or outage spanning that minute
// loses that day permanently (measured on the live fleet: 21 snapshots across
// the last 28 days, with no weekly pattern, consistent with deploy restarts).
// Snapshots are the sole source of every day-over-day delta, so a lost day is
// a lost comparison.
//
// ⛔ TODAY ONLY, and NEVER an overwrite. Two rules, for two different reasons:
//
//  1. No backfill of any other date. Every column here is an "as of now"
//     value — current CVE bands, current compliance findings, current rule
//     analysis. Aug 19's numbers no longer exist anywhere and cannot be
//     reconstructed. Stamping today's numbers on an older snapshot_date would
//     fabricate history, which is strictly worse than a gap: the chart already
//     renders the gaps honestly, and an honest gap is a true statement.
//  2. No rewrite of today. If the 00:10 measurement already landed, a restart
//     at 14:00 must not replace it with 14:00's numbers under the same date —
//     that silently rewrites a point-in-time measurement and every delta drawn
//     from it. The SELECT below is only for a clear log line; the actual
//     guarantee is the ifAbsent write's ON CONFLICT (snapshot_date) DO NOTHING
//     against the table's own UNIQUE constraint, so nothing rests on the
//     read-then-write window.
//
// Never throws — same reliability contract as every other job here.
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
  } catch (err) {
    // A failed check is NOT a measurement either: fall through to the write
    // rather than skipping. The write is safe on its own (DO NOTHING), so the
    // worst case of a failed pre-check is a wasted compute pass, never a lost
    // day and never an overwrite.
    logger.error(`Startup [dashboard-snapshot] catch-up check failed (attempting the guarded write anyway): ${err.stack || err.message}`);
  }
  await runDashboardSnapshotJob({ ifAbsent: true });
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
  // ⛔ The period is computed HERE, from the same server-local clock the cron
  // tick fires on, and passed in explicitly — rather than letting the engine
  // infer it from a second, different clock. It used to be derived inside
  // dispatchMonthlyReport() from getUTC*(), while this cron ran in server-local
  // time (Asia/Bangkok on the reference deployment), so 06:00 ICT on the 1st
  // asked about the wrong month and the once-a-month guarantee broke both ways:
  // a double send in the first month, then a permanently skipped tick from
  // month two. Full arithmetic in reportingPeriod()'s own comment.
  const period = reportingPeriod();
  logger.info(`Job [compliance-report] starting for period ${period} (the month that just ended, server-local).`);
  try {
    const result = await dispatchMonthlyReport(pool, { period });
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
// Background job queue (background_jobs) — the on-demand work that used to run
// on the HTTP request path
// ---------------------------------------------------------------------------
//
// ⛔ WHY. On 2026-09-09 an operator clicked Collect Now on a FortiGate.
// collectAndStore ran getVersion + getRules + getConfig in sequence — 111
// seconds — and POST /api/devices/[id]/collect held the request open for all of
// it. The collection itself was correct (38 rules, 44 licences, a config and a
// version); what was wrong is that a 111-second FOREGROUND request existed at
// all. The API now only enqueues; this worker executes; the UI polls
// GET /api/jobs/[id]. See lib/engines/backgroundJobs.js for the queue itself.
//
// ⛔ THE WORKER, NOT THE APP. A deploy restarts SecVault-App at any moment, and
// a half-finished delete owned by a dead HTTP request is the one state nothing
// can report on afterwards.

const JOB_QUEUE_TYPES = ['device_collect', 'device_delete'];

// Every 5 seconds. This is a BUTTON's latency budget, not a housekeeping
// cadence — the operator is watching a spinner — so it is a setInterval rather
// than one of this file's cron tasks, whose natural unit here is the minute.
const JOB_QUEUE_POLL_MS = 5000;

// ⛔ Reaping matters as much as running. A job whose worker died leaves a row
// saying 'running' forever, which the UI cannot tell from work in progress and
// so spins on indefinitely. reapStaleJobs() moves it to 'failed' WITH A REASON
// — never to 'succeeded', which on a delete would claim a device was removed
// when it may not have been.
const JOB_REAP_INTERVAL_MS = 5 * 60 * 1000;

// A tick drains at most this many jobs, then yields to the next tick. Bounds
// how long a single tracked job can hold up a graceful shutdown.
const JOB_QUEUE_MAX_PER_TICK = 5;

let jobQueueInFlight = false;
let jobQueueTimer = null;
let jobReaperTimer = null;

// ⛔ HOW A STRUCTURED RESULT SURVIVES THE TRIP TO THE UI.
// background_jobs has no JSON column, so a job's structured result is written
// into `detail` as a JSON object and parsed back out by GET /api/jobs/[id].
// That indirection exists for ONE reason: collectAndStore's `rulesCount` is
// TRI-STATE — NULL when the rule pull FAILED, and a number (including a genuine
// 0) when it succeeded, the same tri-state as hit_count. A human sentence alone
// cannot be re-read by the client, and any step that reduced the value to "a
// count" would turn a failed pull into "Collected — 0 rules." in the one place
// the operator is actively watching for the result. JSON carries null as null.
// The route treats a `detail` that is not JSON as plain progress text, so
// another job type's onProgress may pass a bare string.
function jobDetail(message, extra) {
  return JSON.stringify(Object.assign({ message }, extra || {}));
}

// Progress reporting must never be able to fail a job: losing a progress line
// is cosmetic, losing the work is not.
async function safeProgress(jobId, patch) {
  try {
    const p = typeof patch === 'string' ? { detail: patch } : patch || {};
    await reportProgress(pool, jobId, {
      current: p.current === undefined ? null : p.current,
      total: p.total === undefined ? null : p.total,
      detail: typeof p.detail === 'string' ? p.detail : null,
    });
  } catch (err) {
    logger.warn(`Job [job-queue] progress update failed for job ${jobId}: ${err.message}`);
  }
}

// Returns {status, error?, detail?} — never throws for an expected condition.
async function runDeviceCollectJob(job) {
  const { rows } = await pool.query('SELECT * FROM devices WHERE id = $1', [job.device_id]);
  const device = rows[0];
  if (!device) {
    return {
      status: 'failed',
      error: 'Device no longer exists — it may have been deleted while this collect was queued. Nothing was collected.',
    };
  }
  if (!SUPPORTED_VENDORS.includes(device.vendor)) {
    return {
      status: 'failed',
      error: `Unsupported vendor "${device.vendor}". Supported: ${SUPPORTED_VENDORS.join(', ')}. Nothing was collected.`,
    };
  }

  // ⛔ progress_total is left NULL, deliberately. collectAndStore reports no
  // step count, and this worker must not invent one: a bar rendering an unknown
  // total as 0/0 reads as FINISHED. NULL means "the size is not known", which
  // is the truth here, and the UI renders it without a hue.
  await safeProgress(job.id, {
    detail: jobDetail(
      `Contacting ${device.name || device.mgmt_ip || device.smc_host || 'the device'} — version, rules and configuration…`
    ),
  });

  const result = await collectAndStore(device, pool);

  // ⛔ NOT `result.rulesCount ?? 0` and NOT `|| 0`. null here means the rule
  // pull FAILED; a number (including 0) means it succeeded and that is what the
  // device reported. See the header comment on jobDetail().
  const rulesCount =
    result.rulesCount === null || result.rulesCount === undefined ? null : Number(result.rulesCount);
  const errors = Array.isArray(result.errors) ? result.errors : [];

  const message =
    rulesCount === null
      ? 'Collected, but the device reported no rule count — the ruleset was NOT updated.'
      : `Collected — ${rulesCount} rules.`;

  const detail = jobDetail(message, {
    rulesCount,
    version: result.version && result.version.version_string ? result.version.version_string : null,
    configCollected: result.configCollected === true,
    configChanged: result.configChanged === true,
    errors,
  });

  if (errors.length > 0) {
    // A partial collect is not a success. The structured detail still travels
    // with it so the operator can see what DID land alongside what did not.
    return {
      status: 'failed',
      error: `Collected with ${errors.length} error(s): ${errors[0]}`,
      detail,
    };
  }
  return { status: 'succeeded', detail };
}

// ⛔ lib/engines/deviceDeletion.js is required LAZILY, inside the handler.
// A missing or broken module at the top of this file would take the whole
// engine service down — every scheduled job with it — for a feature that is
// only reachable from one button. Here, its absence fails exactly ONE job, with
// a message that says plainly that the device was NOT deleted.
async function runDeviceDeleteJobHandler(job) {
  let mod = null;
  try {
    // eslint-disable-next-line global-require
    mod = require('../lib/engines/deviceDeletion');
  } catch (err) {
    return {
      status: 'failed',
      error:
        `Device deletion is not available in this build (${err.message}). ` +
        'The device was NOT deleted.',
    };
  }
  if (!mod || typeof mod.runDeviceDeleteJob !== 'function') {
    return {
      status: 'failed',
      error:
        'Device deletion is not available in this build — lib/engines/deviceDeletion.js exports no ' +
        'runDeviceDeleteJob(pool, job, { onProgress }). The device was NOT deleted.',
    };
  }
  // ⛔ The engine deliberately does NOT close the job out itself: the worker
  // claimed it, so the worker owns the terminal status, and nothing else may
  // write 'succeeded'. See the integration-seam comment in deviceDeletion.js.
  try {
    const summary = await mod.runDeviceDeleteJob(pool, job, {
      onProgress: (patch) => safeProgress(job.id, patch),
    });
    return {
      status: 'succeeded',
      detail: summary && typeof summary.detail === 'string' ? summary.detail : null,
    };
  } catch (err) {
    // A DeviceDeleteError carries the PARTIAL work it had completed before it
    // stopped. Keeping that alongside the error is the difference between "the
    // delete failed" and "the delete failed, and here is exactly how far it
    // got" — which is what tells the operator whether re-running is safe.
    const partial =
      err && err.summary && typeof err.summary.detail === 'string' ? err.summary.detail : null;
    return { status: 'failed', error: err.message || String(err), detail: partial };
  }
}

async function executeOneJob(job) {
  const startedAt = Date.now();
  logger.info(
    `Job [job-queue] start ${job.job_type} ${job.id} (device ${job.device_id || 'n/a'}, requested by ${job.requested_by || 'unknown'}).`
  );

  let outcome;
  try {
    if (job.job_type === 'device_collect') {
      outcome = await runDeviceCollectJob(job);
    } else if (job.job_type === 'device_delete') {
      outcome = await runDeviceDeleteJobHandler(job);
    } else {
      outcome = {
        status: 'failed',
        error: `Unknown job type "${job.job_type}" — this worker has no handler for it.`,
      };
    }
  } catch (err) {
    // ⛔ One failed job must NEVER crash the service (CLAUDE.md Reliability
    // Rules). It also must never be left 'running' — see the finishJob below.
    outcome = { status: 'failed', error: err.message || String(err) };
    logger.error(`Job [job-queue] ${job.job_type} ${job.id} threw: ${err.stack || err.message}`);
  }

  // ⛔ ALWAYS close the row out. A row left 'running' by a handler that returned
  // without finishing is indistinguishable from work still in progress, and the
  // UI polls it forever. If even this write fails, the reaper is the backstop —
  // which fails it, honestly, rather than assuming it worked.
  try {
    await finishJob(pool, job.id, outcome.status, {
      error: outcome.error || null,
      detail: outcome.detail || null,
    });
  } catch (err) {
    logger.error(
      `Job [job-queue] could not record the result of ${job.id} (${err.message}). ` +
        'It will be reaped to failed; whether the work completed is unknown.'
    );
  }

  const ms = Date.now() - startedAt;
  const line = `Job [job-queue] end ${job.job_type} ${job.id} → ${outcome.status} in ${ms}ms.${outcome.error ? ` ${outcome.error}` : ''}`;
  if (outcome.status === 'succeeded') logger.info(line);
  else logger.warn(line);
}

async function runJobQueueTick() {
  // Silent, not logged: this fires every 5 seconds and a long collect would
  // otherwise write a warning line every tick for two minutes.
  if (jobQueueInFlight) return;
  jobQueueInFlight = true;
  try {
    let drained = 0;
    while (!shuttingDown && drained < JOB_QUEUE_MAX_PER_TICK) {
      // eslint-disable-next-line no-await-in-loop
      const job = await claimNextJob(pool, JOB_QUEUE_TYPES);
      if (!job) break;
      drained += 1;
      // eslint-disable-next-line no-await-in-loop
      await executeOneJob(job);
    }
  } catch (err) {
    // Reaching here means the CLAIM failed (e.g. the DB went away), not a job —
    // executeOneJob self-catches. Log and let the next tick retry.
    logger.error(`Job [job-queue] tick failed: ${err.stack || err.message}`);
  } finally {
    jobQueueInFlight = false;
  }
}

async function runJobReaperTick() {
  try {
    const reaped = await reapStaleJobs(pool);
    if (reaped.length > 0) {
      logger.warn(
        `Job [job-reaper] reaped ${reaped.length} stale job(s) to 'failed': ` +
          `${reaped.map((r) => `${r.job_type}/${r.id}`).join(', ')}. ` +
          'Whether that work completed is unknown — it was not assumed to have succeeded.'
      );
    }
  } catch (err) {
    logger.error(`Job [job-reaper] failed: ${err.message}`);
  }
}

// ⛔ Started EARLY in main(), before the long immediate-on-startup passes
// (feed sync, rule-version pull), not from scheduleJobs(). Those run for
// minutes on a real fleet, and a queue that only comes alive after them would
// leave a Collect Now clicked just after a deploy sitting untouched the whole
// time — reintroducing the wait this whole change exists to remove.
function startJobQueue() {
  logger.info(
    `Starting [job-queue] polling every ${JOB_QUEUE_POLL_MS}ms for ${JOB_QUEUE_TYPES.join(', ')}, ` +
      `with [job-reaper] every ${JOB_REAP_INTERVAL_MS}ms.`
  );
  jobQueueTimer = setInterval(() => {
    if (shuttingDown) return;
    runTrackedJob(runJobQueueTick, 'job-queue');
  }, JOB_QUEUE_POLL_MS);
  jobReaperTimer = setInterval(() => {
    if (shuttingDown) return;
    runTrackedJob(runJobReaperTick, 'job-reaper');
  }, JOB_REAP_INTERVAL_MS);
}

function stopJobQueue() {
  if (jobQueueTimer) clearInterval(jobQueueTimer);
  if (jobReaperTimer) clearInterval(jobReaperTimer);
  jobQueueTimer = null;
  jobReaperTimer = null;
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

  // Fixed daily time (00:10) rather than a configurable interval — see
  // runDashboardSnapshotJob()'s own comment for why. Unchanged: this tick is
  // still the authoritative daily measurement, and still upserts.
  //
  // The startup catch-up for a tick missed while the service was down lives in
  // main()'s startup block (runDashboardSnapshotIfMissing), NOT here — this
  // function is called at the END of main(), so a catch-up placed here would
  // run after the startup passes have already settled and, historically, after
  // an unconditional snapshot run had already created today's row, which made
  // the guard a permanent no-op.
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

  // 00:45 UTC — same daily housekeeping band as the two jobs above, offset
  // again so no two tick on the same second. Deliberately AFTER
  // rule-version-pull's usual window rather than before it: retention's
  // per-device minimum-keep is computed from what is currently stored, so
  // running it once the day's fresh snapshot already exists is the ordering
  // that keeps the most useful rows.
  logger.info('Scheduling [config-retention] with cron "45 0 * * *" (daily).');
  const configRetentionTask = cron.schedule('45 0 * * *', () => {
    if (shuttingDown) return;
    runTrackedJob(runConfigRetentionJob, 'config-retention');
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

  // Hourly at :20. "Was this service reached in the last week" does not
  // change minute to minute, and the job re-derives priority bands for any
  // device whose value moved, so a tighter cadence would buy nothing and
  // rewrite bands repeatedly. :20 keeps it off the top-of-hour crowd.
  logger.info('Scheduling [device-discovery] with cron "35 * * * *" (hourly).');
  const discoveryTask = cron.schedule('35 * * * *', () => {
    if (shuttingDown) return;
    runTrackedJob(runDeviceDiscoveryJob, 'device-discovery');
  });

  logger.info('Scheduling [log-hit] with cron "20 * * * *" (hourly).');
  const logHitTask = cron.schedule('20 * * * *', () => {
    if (shuttingDown) return;
    runTrackedJob(runLogHitJob, 'log-hit');
  });

  // Fixed monthly time: 06:00 on the 1st in the SERVER'S LOCAL ZONE — 06:00
  // Asia/Bangkok (UTC+7) on the reference deployment, which is 23:00 UTC on the
  // LAST DAY OF THE PREVIOUS MONTH. ⛔ This comment claimed the tick was in UTC
  // until 2026-09-09 and was simply wrong: node-cron is registered here with no
  // `timezone` option, so like every other fixed HH:MM job in this file it
  // fires local, not UTC (see CLAUDE.md's Engine Worker note).
  //
  // ⛔ The zone of this cron and the derivation of the report's period are ONE
  // decision — CLAUDE.md's rule, and this job is what it was written about.
  // runComplianceReportJob() above now computes the period from this same local
  // clock (reportingPeriod(), "the month that just ended") and passes it in.
  // Adding a `timezone` here without moving that function to the same zone in
  // the same commit re-opens the double-send-then-silence bug documented in
  // lib/engines/complianceReport.js.
  //
  // Same "housekeeping, not freshness" reasoning as dashboard-snapshot/
  // snapshot-retention for why this isn't a configurable interval;
  // dispatchMonthlyReport()'s own per-period idempotency check makes the
  // immediate startup run in main() below a safe no-op mid-month — and it is
  // only genuinely safe now that every call anywhere within a given local month
  // answers with the SAME period string.
  logger.info('Scheduling [compliance-report] with cron "0 6 1 * *" (monthly, server-local zone).');
  const complianceReportTask = cron.schedule('0 6 1 * *', () => {
    if (shuttingDown) return;
    runTrackedJob(runComplianceReportJob, 'compliance-report');
  });

  scheduledTasks = [
    discoveryTask,
    logHitTask,
    feedTask,
    configTask,
    vpnTask,
    snmpTask,
    dashboardSnapshotTask,
    snapshotRetentionTask,
    configRetentionTask,
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

  // ⛔ FIRST, before every long startup pass below. A job row left 'running' by
  // the process this one is replacing (a deploy restart is exactly that) must be
  // failed with a reason immediately, not in five minutes' time — until it is,
  // the partial unique index on (job_type, device_id) also blocks the operator
  // from re-queueing the same work.
  await runTrackedJob(runJobReaperTick, 'job-reaper');
  // Then bring the queue up, so a Collect Now clicked seconds after a deploy is
  // served while the startup passes below are still running.
  startJobQueue();

  // Immediate on-startup passes so data is fresh before any scheduled cycle fires.
  await runTrackedJob(runFeedSyncAndMatchJob, 'feed-sync-and-match');
  await runTrackedJob(runRuleVersionPullJob, 'rule-version-pull');
  await runTrackedJob(runVpnSessionPollJob, 'vpn-session-poll');
  await runTrackedJob(runSnmpPollJob, 'snmp-poll');
  // ⛔ GUARDED, not unconditional. This used to be a plain
  // runDashboardSnapshotJob() call, which ran on every startup and — because
  // the write is keyed ON CONFLICT (snapshot_date) — REPLACED today's already
  // recorded row with mid-day numbers on every deploy restart. Visible on the
  // live fleet as rows whose recorded_at is 12:56 / 15:32 / 23:31 instead of
  // the 00:10 tick that actually measured them. It also made the separate
  // catch-up guard downstream a permanent no-op, since the row it checked for
  // had just been written by this line. Now the ONE startup path, and it only
  // ever fills TODAY when today is unrecorded. See
  // runDashboardSnapshotIfMissing() for why it never backfills older days.
  await runTrackedJob(runDashboardSnapshotIfMissing, 'dashboard-snapshot');
  // Runs on every startup (not just its 00:30 UTC cron tick) — cheap,
  // idempotent DELETEs, and this service restarts on every deploy (see
  // installer/Update-SecVault.ps1), so relying on the cron tick alone meant
  // it rarely ran in practice, leaving vpn_session_snapshots/
  // snmp_metric_snapshots to grow unbounded — the exact gap it exists to close.
  await runTrackedJob(runSnapshotRetentionJob, 'snapshot-retention');
  // Same reasoning as snapshot-retention's startup run directly above: this
  // service restarts on every deploy, so a job that only ever fired on its
  // 00:45 cron tick would rarely run in practice. Idempotent by construction —
  // a second run immediately after the first deletes nothing.
  await runTrackedJob(runConfigRetentionJob, 'config-retention');
  await runTrackedJob(runNotificationDispatchJob, 'notification-dispatch');

  // Cron registration happens only after every startup job above finishes,
  // so the first scheduled [log-hit] tick can land more than an hour after a
  // deploy. Running it once here makes the wiring verifiable immediately.
  // Cheap by construction: with no curated port_exposed condition it returns
  // without touching syslog at all.
  await runTrackedJob(runLogHitJob, 'log-hit');

  // Same reasoning as the log-hit startup run: cron registers only after every
  // startup job finishes, so without this the first discovery pass could be an
  // hour after a deploy.
  await runTrackedJob(runDeviceDiscoveryJob, 'device-discovery');
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

  // The job queue's timers are not in scheduledTasks (they are started earlier,
  // in main(), and scheduleJobs() reassigns that array wholesale). Stop them
  // here so no NEW job is claimed while we drain — a job already in flight is
  // still waited for below, via runningJobCount.
  stopJobQueue();

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
