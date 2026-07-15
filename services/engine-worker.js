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
const { collectAndStore } = require('../lib/adapters/forcepoint');

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

// Dispatch on device.vendor. Structured so adding new vendors later is a
// small diff (one more `if`/case), not a rewrite.
async function collectForDevice(device) {
  if (device.vendor === 'forcepoint') {
    await collectAndStore(device, pool);
  } else {
    logger.warn(`Job [rule-version-pull] Skipping device ${device.id} (${device.name || 'unnamed'}) — unsupported vendor "${device.vendor}".`);
  }
}

async function runRuleVersionPullJob() {
  const start = Date.now();
  logger.info('Job [rule-version-pull] starting.');
  try {
    const { rows: devices } = await pool.query('SELECT * FROM devices WHERE active = true');
    logger.info(`Job [rule-version-pull] processing ${devices.length} active device(s).`);

    for (const device of devices) {
      try {
        await collectForDevice(device);
        logger.info(`Job [rule-version-pull] collected device ${device.id} (${device.name || 'unnamed'}) OK.`);
      } catch (deviceErr) {
        logger.error(
          `Job [rule-version-pull] failed for device ${device.id} (${device.name || 'unnamed'}): ${deviceErr.stack || deviceErr.message}`
        );
      }
    }

    const durationMs = Date.now() - start;
    logger.info(`Job [rule-version-pull] finished successfully in ${durationMs}ms.`);
  } catch (err) {
    const durationMs = Date.now() - start;
    logger.error(`Job [rule-version-pull] failed after ${durationMs}ms: ${err.stack || err.message}`);
  }
}

// ---------------------------------------------------------------------------
// isJobRunning tracking (for graceful shutdown)
// ---------------------------------------------------------------------------

let isJobRunning = false;

async function runTrackedJob(jobFn, jobName) {
  isJobRunning = true;
  try {
    await jobFn();
  } catch (err) {
    // Should not normally reach here since job bodies self-catch, but guard
    // anyway so a scheduled job can never crash the process.
    logger.error(`Job [${jobName}] threw unexpectedly: ${err.stack || err.message}`);
  } finally {
    isJobRunning = false;
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

  scheduledTasks = [feedTask, configTask];
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
  const hardCeilingMs = 30000;
  let waited = 0;
  while (isJobRunning && waited < hardCeilingMs) {
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    waited += pollIntervalMs;
  }

  if (isJobRunning) {
    logger.warn(`Shutdown hard ceiling (${hardCeilingMs}ms) reached with a job still in flight. Exiting anyway.`);
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
