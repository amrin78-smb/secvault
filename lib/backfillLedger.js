'use strict';

// ONE-SHOT DATA BACKFILL LEDGER (v2.116.0).
//
// ⛔ ═══ WHY THIS EXISTS ═══════════════════════════════════════════════════
// `node lib/migrate.js` was measured at 601-823 SECONDS of a 740-980 second
// deploy — 84% of every update. Almost none of that was schema work. It was
// seven retroactive DATA REPAIRS re-scanning converged tables on every deploy,
// forever. Their own log lines proved it:
//
//   re-redaction:          checked 423, rewrote 0, redacted 0
//   advisory matchability: classified 1004, 0 labels written
//   config diff cleanup:   checked 157, deleted 0, updated 0
//   unmeasurable facts:    set 0 hit_counts, cleared 0
//
// `device_configs` is 776 MB. One candidate scan over it measured 39 s, and
// the redaction pass runs two regexes plus a `config_parsed::text LIKE` across
// that AND config_backups, then fetches 423 multi-megabyte rows one at a time.
// Ten minutes to change nothing, on every single deploy.
//
// ⛔ ═══ WHAT IS AND IS NOT GATED ═════════════════════════════════════════
// THE SCHEMA MIGRATION IS NEVER GATED. `lib/schema.sql` runs unconditionally on
// every deploy — that is how a new table or column reaches an existing install,
// it is idempotent by construction, and it is cheap. Only retroactive DATA
// REPAIRS pass through this ledger. If you find yourself reaching for
// `runOnce()` around anything that creates or alters a relation, stop: that is
// the one thing that must keep running every time.
//
// ⛔ ═══ THE REVISION IS THE WHOLE SAFETY MECHANISM ═══════════════════════
// A marker is keyed on (name, REVISION), not on name alone. If a backfill's
// LOGIC is ever corrected — which has happened repeatedly in this codebase, the
// PAN-OS re-redaction alone shipped twice because the first pass was XML-only
// and missed 343 rows stored in CLI brace grammar — then bumping its revision
// makes every existing install run the corrected version exactly once.
//
// Keying on name alone would mean a fixed backfill NEVER RUNS on the installs
// that have the broken data. That failure is silent, permanent, and lands on
// stored secrets. If you edit a backfill's behaviour, bump its revision in the
// same commit; there is a test asserting every registered name carries one.
//
// ⛔ ═══ ONLY SUCCESS IS RECORDED ═════════════════════════════════════════
// A backfill that throws is NOT marked done, so the next deploy retries it.
// These are all best-effort and non-fatal by design (a data repair must never
// block the deploy that also ships the forward-looking parser fix), which makes
// it entirely possible for one to fail quietly — and marking a failed repair as
// complete would be this codebase's oldest bug, a failed read recorded as an
// affirmative fact, applied to its own maintenance.

const LEDGER_TABLE = 'data_backfills';

/**
 * Creates the ledger. Called by migrate BEFORE any gated backfill.
 *
 * Deliberately created here rather than in schema.sql: the ledger is machinery
 * for the migration process itself, and a chicken-and-egg failure where the
 * ledger is missing should simply mean "nothing is recorded, run everything",
 * which is exactly the safe direction.
 */
async function ensureLedger(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ${LEDGER_TABLE} (
      id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name        TEXT NOT NULL,
      revision    INTEGER NOT NULL,
      completed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      duration_ms INTEGER,
      summary     TEXT,
      UNIQUE (name, revision)
    )`);
}

/**
 * Has this exact (name, revision) already completed on this installation?
 */
async function isDone(pool, name, revision) {
  try {
    const { rows } = await pool.query(
      `SELECT 1 FROM ${LEDGER_TABLE} WHERE name = $1 AND revision = $2 LIMIT 1`,
      [name, revision]
    );
    return rows.length > 0;
  } catch (_err) {
    // ⛔ FAILS OPEN, and that is correct HERE and nowhere else in this codebase.
    // If the ledger cannot be read we do not know whether the repair ran, and
    // the safe answer to "did we fix the stored secrets?" is to do it again.
    // Re-running is idempotent and costs minutes; skipping wrongly leaves
    // plaintext secrets in the database.
    return false;
  }
}

async function markDone(pool, name, revision, durationMs, summary) {
  try {
    await pool.query(
      `INSERT INTO ${LEDGER_TABLE} (name, revision, duration_ms, summary)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (name, revision) DO NOTHING`,
      [name, revision, Math.round(durationMs), summary ? String(summary).slice(0, 2000) : null]
    );
  } catch (err) {
    // Losing the marker only costs a re-run next deploy. Never fail a migrate
    // over bookkeeping.
    console.warn(`[migrate] could not record backfill '${name}': ${err.message}`);
  }
}

/**
 * Run a one-shot data repair, at most once per (name, revision), and TIME IT.
 *
 * @param {object}   pool
 * @param {string}   name      stable identifier, never reused for a different repair
 * @param {number}   revision  bump when the LOGIC changes, so installs re-run it
 * @param {Function} fn        async () => summaryString|undefined. Throwing means
 *                             not-done: it is logged and retried next deploy.
 * @returns {Promise<{ran:boolean, ms:number}>}
 */
async function runOnce(pool, name, revision, fn) {
  if (await isDone(pool, name, revision)) {
    console.log(`[migrate] ${name}: already completed (rev ${revision}) — skipped.`);
    return { ran: false, ms: 0 };
  }

  const started = Date.now();
  try {
    const summary = await fn();
    const ms = Date.now() - started;
    await markDone(pool, name, revision, ms, summary);
    console.log(`[migrate] ${name}: ${summary || 'done'} (${(ms / 1000).toFixed(1)}s, rev ${revision})`);
    return { ran: true, ms };
  } catch (err) {
    const ms = Date.now() - started;
    // ⛔ NOT marked done. Next deploy retries.
    console.warn(
      `[migrate] ${name} FAILED after ${(ms / 1000).toFixed(1)}s (non-fatal, will retry next update): ${err.message}`
    );
    return { ran: true, ms, failed: true };
  }
}

module.exports = { ensureLedger, isDone, markDone, runOnce, LEDGER_TABLE };
