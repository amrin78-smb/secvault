const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// REQUIRED in production: without an 'error' listener on the pool, a network blip or
// DB restart that kills an idle client emits an unhandled 'error' event, which Node
// treats as an uncaught exception and crashes the entire process (both SecVault-App
// and SecVault-Engine share this singleton). This never shows up at build time or in
// short-lived local testing -- only against a live DB connection over real uptime.
pool.on('error', (err) => {
  console.error('[db] Unexpected error on idle PostgreSQL client:', err.message);
});

module.exports = { pool };
