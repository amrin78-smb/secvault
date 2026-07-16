// lib/activityLog.js
// Operator-action audit trail (Rule Analysis Dashboard Phase 4). CommonJS —
// required from Next.js API routes (via `import`, which Next's bundler
// interops with `module.exports` transparently, same as every other lib/*.js
// file in this app).
//
// NOT a general app log — scheduled/background jobs already have
// C:\Apps\SecVault\logs\engine.log for that (services/engine-worker.js).
// This table is populated only at HTTP route call-sites representing a
// meaningful in-app action: run-analysis, acknowledge-finding,
// acknowledge-config-diff. See CLAUDE.md's activity_log section.

'use strict';

/**
 * Records one activity_log row. NEVER throws — a failure to log an audit
 * trail entry must never break the primary action it's describing (the same
 * "one failure must not cascade" principle CLAUDE.md already applies to
 * engine-worker job isolation and best-effort system-info fetches
 * elsewhere in this codebase). Logs a console.warn on failure instead.
 *
 * @param {import('pg').Pool} pool
 * @param {{actor?: string, action: string, deviceId?: string|null, detail?: string|null}} entry
 */
async function logActivity(pool, entry) {
  // Destructure from a local `|| {}` rather than a parameter default -- a
  // parameter default only substitutes on `undefined`, not on an explicit
  // `null` (e.g. a caller doing `logActivity(pool, null)`), which would
  // otherwise throw a TypeError before the try block below and violate this
  // function's own "NEVER throws" contract. Found in a follow-up bug sweep
  // (2026-07-17); no known call site triggers it today, but the contract is
  // unconditional and other code may come to rely on it.
  const { actor, action, deviceId = null, detail = null } = entry || {};
  try {
    await pool.query(
      'INSERT INTO activity_log (actor, action, device_id, detail) VALUES ($1, $2, $3, $4)',
      [actor || 'unknown', action, deviceId, detail]
    );
  } catch (err) {
    console.warn(`[activityLog] Failed to record activity (action=${action}): ${err.message}`);
  }
}

module.exports = { logActivity };
