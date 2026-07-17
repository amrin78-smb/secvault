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

async function runRuleVersionPullJob() {
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
          logger.info(
            `Job [rule-version-pull] collected device ${device.id} (${device.name || 'unnamed'}) OK — ` +
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
        polled += 1;
      } catch (err) {
        logger.warn(
          `Job [vpn-session-poll] failed for device ${device.id} (${device.name || 'unnamed'}): ${err.message}`
        );
      }
    }

    const durationMs = Date.now() - start;
    logger.info(
      `Job [vpn-session-poll] finished in ${durationMs}ms — polled ${polled}, skipped (no VPN capability) ${skipped}, ${devices.length} active device(s) total.`
    );
  } catch (err) {
    const durationMs = Date.now() - start;
    logger.error(`Job [vpn-session-poll] failed after ${durationMs}ms: ${err.stack || err.message}`);
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

  scheduledTasks = [feedTask, configTask, vpnTask];
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
