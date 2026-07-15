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

const DEFAULT_ADMIN_USERNAME = 'admin';
const DEFAULT_ADMIN_PASSWORD = 'changeme';

async function runSchema(pool) {
  const schemaPath = path.join(__dirname, 'schema.sql');
  const sql = fs.readFileSync(schemaPath, 'utf8');
  await pool.query(sql);
}

async function seedDefaultAdmin(pool) {
  const existing = await pool.query("SELECT value FROM settings WHERE key = 'admin_password_hash'");
  if (existing.rows.length > 0) {
    return { seeded: false };
  }

  const hash = await bcrypt.hash(DEFAULT_ADMIN_PASSWORD, 10);
  await pool.query(
    `INSERT INTO settings (key, value) VALUES ($1, $2), ($3, $4)
     ON CONFLICT (key) DO NOTHING`,
    ['admin_username', DEFAULT_ADMIN_USERNAME, 'admin_password_hash', hash]
  );
  return { seeded: true };
}

async function main() {
  console.log('[migrate] Running schema migration...');
  await runSchema(pool);
  console.log('[migrate] Schema migration complete.');

  const { seeded } = await seedDefaultAdmin(pool);
  if (seeded) {
    console.log('[migrate] Seeded default local admin account:');
    console.log(`[migrate]   username: ${DEFAULT_ADMIN_USERNAME}`);
    console.log(`[migrate]   password: ${DEFAULT_ADMIN_PASSWORD}`);
    console.log('[migrate]   CHANGE THIS PASSWORD after first login.');
  } else {
    console.log('[migrate] Admin account already configured — skipping seed.');
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

module.exports = { runSchema, seedDefaultAdmin };
