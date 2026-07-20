// Runs lib/schema.sql against DATABASE_URL, then seeds a default local admin
// account if one does not already exist. Safe to re-run (idempotent).
//
// Usage: node lib/migrate.js

const fs = require('fs');
const path = require('path');

// Invoked as plain `node lib/migrate.js` (by the installer and
// Update-SecVault.ps1), not through Next.js — Next's automatic .env.local
// loading only applies to `next build`/`next start`/`next dev`, not
// arbitrary `node` invocations. Without this, process.env.DATABASE_URL is
// undefined by the time `./db` builds its Pool below (at require-time),
// and pg falls back to default connection params with no password,
// surfacing as a confusing "SASL: ... password must be a string" error
// instead of a clear "DATABASE_URL missing" one. Same fix already applied
// to services/engine-worker.js — load env vars before requiring ./db.
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
    console.warn(`[migrate] Could not load .env.local (${err.message}). Relying on existing process.env.`);
  }
}

loadEnvLocal();

const bcrypt = require('bcryptjs');
const { pool } = require('./db');
const { seedAuditChecks } = require('./auditChecksSeed');
const { backfillVulnerabilityCategories } = require('./engines/vulnerabilityCategory');
const { cleanupVolatileConfigDiffs, regenerateOversizedChangeSummaries } = require('./engines/configDiff');

const DEFAULT_ADMIN_USERNAME = 'admin';
const DEFAULT_ADMIN_PASSWORD = 'changeme';

async function runSchema(pool) {
  const schemaPath = path.join(__dirname, 'schema.sql');
  const sql = fs.readFileSync(schemaPath, 'utf8');
  await pool.query(sql);
}

// RBAC (users table) replaces the old single-identity settings.admin_username
// / settings.admin_password_hash pair. Guarded on `users` being empty, so
// this only ever does something once per database, not on every migrate run:
//  - An install that already ran migrate.js before RBAC shipped has its
//    admin identity sitting in `settings` -- migrate that row forward into
//    `users` (role 'admin') so the existing username/password keep working,
//    rather than forcing every upgrade back to the fresh-install default.
//  - A genuinely fresh install (neither `users` nor the legacy settings keys
//    exist yet) seeds the same well-known default identity the old
//    seedDefaultAdmin() used to, just directly into `users` instead of
//    `settings`.
// The legacy settings rows are deliberately left in place after migrating
// (not deleted) -- app/api/settings/route.js's HIDDEN_KEYS filter already
// hides admin_password_hash from the settings API either way, and nothing
// reads those two keys as the source of truth anymore once this has run.
async function seedUsers(pool) {
  const { rows: existingUsers } = await pool.query('SELECT id FROM users LIMIT 1');
  if (existingUsers.length > 0) {
    return { migrated: false, seeded: false };
  }

  const legacy = await pool.query(
    "SELECT key, value FROM settings WHERE key IN ('admin_username', 'admin_password_hash')"
  );
  const legacyMap = Object.fromEntries(legacy.rows.map((r) => [r.key, r.value]));

  if (legacyMap.admin_username && legacyMap.admin_password_hash) {
    await pool.query(
      `INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'admin')
       ON CONFLICT (username) DO NOTHING`,
      [legacyMap.admin_username, legacyMap.admin_password_hash]
    );
    return { migrated: true, seeded: false, username: legacyMap.admin_username };
  }

  const hash = await bcrypt.hash(DEFAULT_ADMIN_PASSWORD, 10);
  await pool.query(
    `INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'admin')
     ON CONFLICT (username) DO NOTHING`,
    [DEFAULT_ADMIN_USERNAME, hash]
  );
  return { migrated: false, seeded: true, username: DEFAULT_ADMIN_USERNAME };
}

async function main() {
  console.log('[migrate] Running schema migration...');
  await runSchema(pool);
  console.log('[migrate] Schema migration complete.');

  const { migrated, seeded, username } = await seedUsers(pool);
  if (migrated) {
    console.log(`[migrate] Migrated existing admin identity '${username}' into the users table (role: admin).`);
  } else if (seeded) {
    console.log('[migrate] Seeded default local admin account:');
    console.log(`[migrate]   username: ${DEFAULT_ADMIN_USERNAME}`);
    console.log(`[migrate]   password: ${DEFAULT_ADMIN_PASSWORD}`);
    console.log('[migrate]   CHANGE THIS PASSWORD after first login.');
  } else {
    console.log('[migrate] Users already configured — skipping seed.');
  }

  // Phase 7 compliance check library. Unlike lib/schema-grants.sql's
  // best-effort tolerance, a seed failure here is NOT swallowed — it is
  // allowed to throw and fail the whole migrate run loudly. audit_checks
  // silently ending up empty means the compliance feature has zero checks,
  // which is a real, actionable problem worth surfacing, not hiding.
  const { count } = await seedAuditChecks(pool);
  console.log(`[migrate] Seeded/updated ${count} compliance check(s).`);

  // Dashboard "Risk by Category" backfill — best-effort, never fails the
  // whole migrate run: unlike audit_checks (curated data with no valid
  // "partially seeded" state), a backfill failure here just means some
  // advisories keep showing 'Other' until the next successful run, not a
  // broken feature. Only ever touches rows with vulnerability_category IS
  // NULL, so it's cheap on every re-run after the first (see
  // backfillVulnerabilityCategories()'s own comment for why 'Other' is a
  // real, final answer, not a "try again next time" placeholder).
  try {
    const { processed } = await backfillVulnerabilityCategories(pool);
    console.log(`[migrate] Backfilled vulnerability_category for ${processed} advisory row(s).`);
  } catch (err) {
    console.warn(`[migrate] vulnerability_category backfill failed (non-fatal): ${err.message}`);
  }

  // Retroactive cleanup for config_diffs rows recorded before (a) the
  // system_info volatile-field allowlist and (b) secret-value redaction
  // existed in lib/engines/configDiff.js -- (a) device clock/uptime/auto-
  // updating signature versions were recorded as "changes" even though no
  // admin touched anything; (b) at least one row captured a raw, unredacted
  // secret verbatim (see configDiff.js's SECRET_PATH_PATTERN comment for the
  // full incident). Best-effort, never fails the whole migrate run, same
  // reasoning as the backfill above -- but ALWAYS attempted, unlike a purely
  // cosmetic cleanup would be, precisely because it's also this codebase's
  // remediation path for the secret-disclosure half of the problem.
  try {
    const { checked, deleted, updated } = await cleanupVolatileConfigDiffs(pool);
    console.log(
      `[migrate] Config diff cleanup: checked ${checked}, deleted ${deleted} pure-noise row(s), updated ${updated} row(s) to drop noise/redact secrets while keeping real changes.`
    );
  } catch (err) {
    console.warn(`[migrate] config_diffs cleanup failed (non-fatal): ${err.message}`);
  }

  // Retroactive fix for a distinct config_diffs bug found 2026-07-20: a
  // corrupted PATH (not just a value) from the same brace-corruption
  // incident above can make summarizeDiff()'s "e.g. <examples>" preview
  // balloon to thousands of characters -- one production row hit 13,647
  // chars, rendering as an unreadable wall of text on the Changes page
  // BEFORE a user ever expands "View diff" (classifyDiff()/DiffViewer.js's
  // fix only covers the expanded view, not this cached one-line summary).
  // summarizeDiff() itself now caps/sanitizes each example path
  // (lib/engines/configDiff.js's sanitizeExamplePath()), but that only
  // affects summaries computed from now on -- this regenerates any
  // already-stored oversized one. Best-effort, safe to rerun indefinitely.
  try {
    const { checked, updated } = await regenerateOversizedChangeSummaries(pool);
    console.log(
      `[migrate] Config diff summary backfill: checked ${checked} oversized row(s), regenerated ${updated}.`
    );
  } catch (err) {
    console.warn(`[migrate] config_diffs summary backfill failed (non-fatal): ${err.message}`);
  }
}

if (require.main === module) {
  main()
    .then(() => {
      console.log('[migrate] Done.');
      process.exit(0);
    })
    .catch((err) => {
      console.error('[migrate] Migration failed:', err);
      process.exit(1);
    });
}

module.exports = { runSchema, seedUsers };
