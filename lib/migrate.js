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
const {
  cleanupVolatileConfigDiffs,
  cleanupTypeCoercionConfigDiffs,
  cleanupSystemInfoReadFailureDiffs,
  regenerateOversizedChangeSummaries,
  collapseHistoricalArrayShiftCascades,
} = require('./engines/configDiff');
const { backfillPaloAltoVersionRanges } = require('./feeds/paloalto');
const { backfillNvdNativeVersionRanges } = require('./feeds/nvd');
// The LIVE CLI redactor, reused verbatim so the backfill cannot drift from
// what a real SSH collection stores.
const sshParser = require('./adapters/paloalto/sshParser');
// The LIVE tree redactor, for the JSONB column.
const paParser = require('./adapters/paloalto/parser');

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

// Migrates an already-deployed server's zone_classifications table from its
// original GLOBAL shape (zone_name TEXT UNIQUE, no device_id -- shipped and
// found unusable in the same session: a real fleet's zone names turned out
// to be per-device/per-tunnel identifiers, not shared role names) to the
// PER-DEVICE shape lib/schema.sql now defines. CREATE TABLE IF NOT EXISTS
// alone can't do this (see this file's own standing warning on that), and
// the constraint change (drop the old single-column UNIQUE, add the new
// composite one) needs real conditional logic plain SQL "IF NOT EXISTS"
// can't express for constraints the way it can for columns/tables.
//
// Best-effort, safe to re-run indefinitely: adding an already-present
// column, dropping an already-absent constraint, or adding an
// already-present one are all safe no-ops on a subsequent run (or on a
// fresh install, where CREATE TABLE already produced the final shape and
// every step here finds nothing to do). Any pre-existing GLOBAL-scoped row
// (device_id IS NULL after the column is added) is deleted rather than
// migrated -- there is no way to know which device a legacy zone_name row
// was even collected for, and this table shipped mere hours before this
// fix, with every row still "Unclassified" on the one deployment checked
// directly -- discarding it is confirmed harmless, not a guess.
//
// ⛔ The composite UNIQUE constraint name below, 'zone_classifications_
// device_id_zone_name_key', is Postgres's own DEFAULT auto-generated name
// for an unnamed table-level `UNIQUE (device_id, zone_name)` constraint
// (the "<table>_<col1>_<col2>_key" convention) -- deliberately matched
// exactly, not an arbitrary name, so a FRESH install (where CREATE TABLE
// already produces this constraint under that auto-generated name) and an
// UPGRADED install (where this function adds it explicitly) converge on
// the identical constraint, rather than an upgraded server ending up with
// two differently-named UNIQUE constraints covering the same two columns.
//
// idx_zone_classifications_device_id is created HERE, not in schema.sql --
// see schema.sql's own comment on this table for why a bare CREATE INDEX
// statement in that file broke every already-deployed server on 2026-07-22
// (it ran before device_id existed on an upgrading server's table). Placed
// LAST, after device_id is unconditionally guaranteed to exist.
async function migrateZoneClassificationsToPerDevice(pool) {
  await pool.query(
    'ALTER TABLE zone_classifications ADD COLUMN IF NOT EXISTS device_id UUID REFERENCES devices(id) ON DELETE CASCADE'
  );
  const { rowCount } = await pool.query('DELETE FROM zone_classifications WHERE device_id IS NULL');
  await pool.query('ALTER TABLE zone_classifications DROP CONSTRAINT IF EXISTS zone_classifications_zone_name_key');
  // Cleans up a stray, incorrectly-named duplicate UNIQUE(device_id, zone_name)
  // constraint that this same function (an earlier revision, live for ~23
  // minutes before being superseded) would have created under the WRONG name
  // on any server fresh-installed during that narrow window -- that revision
  // checked pg_constraint for 'zone_classifications_device_zone_key' instead
  // of the correct auto-generated name below, didn't find it, and added a
  // second, redundant constraint under it. Harmless no-op everywhere else.
  await pool.query('ALTER TABLE zone_classifications DROP CONSTRAINT IF EXISTS zone_classifications_device_zone_key');
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'zone_classifications_device_id_zone_name_key'
      ) THEN
        ALTER TABLE zone_classifications
          ADD CONSTRAINT zone_classifications_device_id_zone_name_key UNIQUE (device_id, zone_name);
      END IF;
    END $$;
  `);
  await pool.query('ALTER TABLE zone_classifications ALTER COLUMN device_id SET NOT NULL');
  await pool.query(
    'CREATE INDEX IF NOT EXISTS idx_zone_classifications_device_id ON zone_classifications(device_id)'
  );
  return { discardedGlobalRows: rowCount };
}

// ---------------------------------------------------------------------------
// Retroactive re-redaction of stored Palo Alto configs (added 2026-09-09)
// ---------------------------------------------------------------------------
//
// ⛔ WHY THIS EXISTS AT ALL. A code fix to a redactor does not un-leak a secret
// that is already sitting in the database — the same reason
// backfillPaloAltoVersionRanges() exists next door. Two independent defects let
// PAN-OS secret-bearing tags reach device_configs.config_raw and
// config_backups.config_raw unredacted, and BOTH tables are GRANT SELECT'd to
// claude_readonly / nocvault_readonly, the exact roles CLAUDE.md bars from
// credential material:
//   1. parser.js's element matcher required a BARE opening tag, so every node
//      Panorama pushes from a template (`<private-key ptpl="…">`,
//      `<bind-password ptpl="…">`) slipped past it.
//   2. `wmi-password`, `agent-user-override-key` and `community` were simply
//      absent from the tag lists, and matching there is exact-name — so
//      `wmi-password` was never covered by `password`.
// Measured on the live fleet before the fix: ~1,019 affected rows across the two
// tables. The `wmi-password` one matters most: it sits beside a cleartext
// `<wmi-account>` naming a Windows DOMAIN service account used for User-ID
// probing, so the blast radius reaches past the firewall itself.
//
// ⛔ ACCURACY, because it changes how urgent this is but not whether it is a
// leak: these values are PAN-OS `-AQ=`-prefixed MASTER-KEY-ENCRYPTED blobs, not
// literal plaintext passwords. They are reversible with the device master key,
// and they are exactly the field class SECRET_TAGS exists to strip. The SNMP
// `<community>` values are the exception — those are ordinary strings.
//
// ⛔ HOW IT DECIDES WHAT IS A SECRET BODY — and what it does when unsure.
// It rewrites ONLY a TEXT-LEAF body: the span between a matching
// `<tag …>` / `</tag>` pair that contains no `<` at all. That restriction is
// the whole safety argument, and it is structural rather than a judgement call:
// a body with no markup in it cannot contain an element, an attribute or a
// nested tag, so replacing it can only ever destroy the secret and provably
// cannot delete or reshape any surrounding config. It covers 100% of the
// measured exposure (an `-AQ=` blob is base64, a PEM body and an SNMP community
// string are plain text — none contain markup).
//
// Everything else is left ALONE and COUNTED, never guessed at:
//   - a secret tag that is a CONTAINER (its body holds child elements) — the
//     live redactor blanks that whole subtree, but doing so to already-stored
//     history would discard real content this function cannot re-derive;
//   - an EMPTY body (`<phash></phash>`), which is not a secret and whose
//     rewriting would be a pure, pointless mutation of stored history.
// Both are reported in the summary so an operator can see what was left.
//
// ⛔ It does NOT touch config_parsed. That column redacts correctly via
// redactConfigTree(), and it is the column lib/engines/configDiff.js actually
// diffs — so nothing here can manufacture a false config-change alert. Rows are
// only ever UPDATEd; nothing is deleted.
//
// Idempotent by construction: after a rewrite the body is `<redacted>`, which
// contains `<`, so the leaf matcher can never match it again. Re-running is a
// no-op, and re-running is expected — migrate.js runs on every deploy.
const { SECRET_TAGS, SECRET_LEAF_TAGS } = require('./adapters/paloalto/parser');

const REDACTED_RAW = '<redacted>';

// Longest name first so the alternation cannot settle on a shorter prefix
// (`password` ahead of `password-hash`) before trying the full name. Anchoring
// on the `<` and requiring the tag to end at whitespace or `>` already prevents
// a wrong match, but ordering makes that independent of regex backtracking.
const PA_SECRET_TAG_NAMES = [...new Set([...SECRET_TAGS, ...SECRET_LEAF_TAGS])].sort(
  (a, b) => b.length - a.length
);
const PA_TAG_ALTERNATION = PA_SECRET_TAG_NAMES.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');

// `([^<]*)` is the leaf-only guarantee described above. `\1` forces the closing
// tag to be the SAME tag that opened, so a match can never span two elements.
const PA_LEAF_SECRET_RE = new RegExp(
  `(<(${PA_TAG_ALTERNATION})(?:\\s[^>]*)?>)([^<]*)(<\\/\\2>)`,
  'gi'
);
// A secret tag whose body is NOT a text leaf — i.e. the next thing after the
// opening tag is another element. Detection only; never rewritten.
const PA_CONTAINER_SECRET_RE = new RegExp(
  `<(${PA_TAG_ALTERNATION})(?:\\s[^>]*)?>\\s*<(?!redacted>)`,
  'gi'
);
// The SQL-side prefilter. Deliberately the same shape as PA_LEAF_SECRET_RE's
// opening half so the database never hands back a row JS would decline anyway.
// The CLI/brace-grammar prefilter. PAN-OS stores an encrypted value as a
// -prefixed base64 blob, so the BLOB itself is the reliable marker in a
// grammar that has no tags. Deliberately blob-shaped rather than keyword-shaped:
// the keyword list is exactly what proved incomplete.
const PA_CLI_SECRET_SQL_RE = '-AQ=';

// Cheap shape test for the brace grammar. sshParser.looksLikePanosConfig is the
// authoritative one but is tuned to a full config dump; a stored row may be a
// fragment, so accept anything that is clearly not XML and carries a brace body.
function looksLikePanosCliConfig(text) {
  if (typeof text !== 'string' || text.length === 0) return false;
  if (text.trimStart().startsWith('<')) return false;
  return text.includes('{') && text.includes('}');
}

const PA_LEAF_SECRET_SQL_RE = `<(${PA_TAG_ALTERNATION})(\\s[^>]*)?>[^<]`;

/**
 * Rewrite every text-leaf secret body in one raw config.
 * @param {string} text
 * @returns {{text:string, redacted:number, skippedContainer:number, skippedEmpty:number}}
 */
function redactStoredPaloAltoConfigRaw(text) {
  if (typeof text !== 'string' || text.length === 0) {
    return { text, redacted: 0, skippedContainer: 0, skippedEmpty: 0 };
  }
  let redacted = 0;
  let skippedEmpty = 0;
  const out = text.replace(PA_LEAF_SECRET_RE, (whole, open, _tag, body, close) => {
    // An empty/whitespace-only body carries no secret. Rewriting it would be a
    // mutation of stored history that buys nothing — leave it exactly as found.
    if (body.trim() === '') {
      skippedEmpty += 1;
      return whole;
    }
    redacted += 1;
    return `${open}${REDACTED_RAW}${close}`;
  });
  PA_CONTAINER_SECRET_RE.lastIndex = 0;
  const skippedContainer = (text.match(PA_CONTAINER_SECRET_RE) || []).length;
  return { text: out, redacted, skippedContainer, skippedEmpty };
}

/**
 * Re-redact already-stored Palo Alto config snapshots and backups.
 * Best-effort and safe to re-run; the caller treats a throw as non-fatal.
 */
async function backfillPaloAltoConfigRedaction(pool) {
  let checked = 0;
  let updated = 0;
  let secretsRedacted = 0;
  let leftContainers = 0;
  let cliRows = 0;
  let parsedRows = 0;

  for (const table of ['device_configs', 'config_backups']) {
    // ⛔ ONLY device_configs HAS config_parsed. config_backups stores config_raw
    // alone — confirmed against information_schema, and caught by
    // tests/sqlColumns.test.js when this pass was first written table-blind.
    // Every config_parsed reference below is gated on this flag.
    const hasParsed = table === 'device_configs';
    const parsedCandidateSql = hasParsed
      ? " OR c.config_parsed::text LIKE '%' || $2 || '%'"
      : '';

    // Scoped to Palo Alto devices: this is PAN-OS tag grammar, and a narrower
    // candidate set is also a cheaper scan on a table measured at ~450 MB.
    //
    // The table name is interpolated, not bound — a table name cannot be a bind
    // parameter in PostgreSQL. It is safe because `table` only ever takes one of
    // the two literals in this loop's own array; nothing external reaches it. It
    // is spelled out as an explicit ternary rather than a bare `${table}` so BOTH
    // names stay statically visible in the source, which is what lets
    // tests/sqlColumns.test.js check these columns against lib/schema.sql (see
    // gotchas.md: "A wrong COLUMN NAME passes every gate").
    // The secret-tag regex IS bound, as $1.
    const { rows } = await pool.query(
      `SELECT c.id
         FROM ${table === 'device_configs' ? 'device_configs' : 'config_backups'} c
         JOIN devices d ON d.id = c.device_id
        WHERE d.vendor = 'paloalto'
          AND (c.config_raw ~ $1 OR c.config_raw ~ $2${parsedCandidateSql})
        ORDER BY c.id`,
      [PA_LEAF_SECRET_SQL_RE, PA_CLI_SECRET_SQL_RE]
    );

    for (const { id } of rows) {
      checked += 1;
      const cur = await pool.query(
        hasParsed
          ? 'SELECT config_raw, config_parsed FROM device_configs WHERE id = $1'
          : 'SELECT config_raw FROM config_backups WHERE id = $1',
        [id]
      );
      if (!cur.rows[0]) continue;
      const before = cur.rows[0].config_raw;
      const res = redactStoredPaloAltoConfigRaw(before);
      leftContainers += res.skippedContainer;

      // ⛔ TWO GRAMMARS, TWO REDACTORS. The pass above is XML-only, and the
      // first deploy of this backfill (v2.95.0) left 343 device_configs and 56
      // config_backups rows still holding PAN-OS `-AQ=` blobs because of it:
      // those rows are stored in the CLI BRACE syntax, not XML —
      //   `setting { wmi-account tfm\vitida; wmi-password -AQ=…; }`
      // — which has no tags for the XML matcher to find. The forward-looking
      // fix was already complete (sshParser's SECRET_TOKENS gained the same
      // three names), so new collections were clean while the history stayed
      // exposed; verifying only the XML tag names post-deploy reported zero and
      // looked closed. Check for the BLOB, not for the tag.
      //
      // sshParser.redactConfig is the live CLI redactor — the same code path a
      // real SSH collection runs, so this cannot drift from it.
      let text = res.text;
      let cliRedacted = 0;
      if (looksLikePanosCliConfig(text)) {
        const after = sshParser.redactConfig(text);
        if (typeof after === 'string' && after !== text) {
          // Count is approximate (the redactor reports none), so it is reported
          // separately rather than folded into the exact XML tally.
          cliRedacted = 1;
          text = after;
        }
      }
      cliRows += cliRedacted;

      // ⛔ THIRD COLUMN, THIRD GRAMMAR. config_parsed is JSONB and is
      // redacted by redactConfigTree(), which keys off the OBJECT KEY rather
      // than tag or line syntax. It therefore had its own copy of the same
      // defect: `wmi-password` and `agent-user-override-key` were absent from
      // SECRET_TAGS, so 772 device_configs rows kept an encrypted blob in the
      // JSON even after BOTH raw passes reported clean.
      //
      // ⛔ This is the third time in one fix that verifying the column I had
      // just changed reported success while a sibling column stayed exposed.
      // The lesson is in the check, not the code: search for the SECRET
      // (`-AQ=`, a PEM header) across EVERY column that stores config, never
      // for the tag or key you happen to have fixed.
      //
      // redactConfigTree is the live redactor, reused verbatim so this cannot
      // drift from what a real collection stores.
      const parsedBefore = cur.rows[0].config_parsed;
      let parsedText = null;
      if (parsedBefore && typeof parsedBefore === 'object') {
        const redactedTree = paParser.redactConfigTree(parsedBefore);
        const a = JSON.stringify(parsedBefore);
        const b = JSON.stringify(redactedTree);
        if (a !== b) {
          parsedText = b;
          parsedRows += 1;
        }
      }

      if (text === before && parsedText === null) continue;
      res.text = text;

      if (table === 'device_configs') {
        // ⛔ content_hash is derived from config_raw, so rewriting one without
        // the other would leave the column meaning nothing for this row (see
        // lib/adapters/index.js's CONTENT_HASH_SQL comment). This expression is
        // character-for-character the one in lib/schema.sql's own content_hash
        // backfill — same coalesce, same chr(10), same UTF8, same sha256/hex —
        // and must stay in step with it and with CONTENT_HASH_SQL.
        // ⛔ config_parsed is written FIRST in the same statement so the
        // content_hash expression sees the NEW value of both columns. Writing
        // the hash off a config_parsed this statement is also changing would
        // leave the column meaningless for exactly the rows being repaired.
        await pool.query(
          `UPDATE device_configs
              SET config_raw = $2,
                  config_parsed = COALESCE($3::jsonb, config_parsed),
                  content_hash = encode(
                    sha256(convert_to(coalesce($2, '') || chr(10)
                      || coalesce(COALESCE($3::jsonb, config_parsed)::text, ''), 'UTF8')),
                    'hex')
            WHERE id = $1`,
          [id, res.text, parsedText]
        );
      } else {
        // config_backups has no config_parsed column and no content_hash.
        await pool.query('UPDATE config_backups SET config_raw = $2 WHERE id = $1', [
          id,
          res.text,
        ]);
      }
      updated += 1;
      secretsRedacted += res.redacted;
    }
  }

  // ⛔ FOURTH AND LAST COLUMN. config_diffs.diff is a JSONB {added,removed,
  // modified} payload, and when a secret-bearing subtree was added or removed
  // the raw value travelled INTO the diff — 4 rows on the live fleet, found
  // only by scanning all 211 text/JSONB columns in the database for the SECRET
  // rather than for a tag, a key or a table anyone had thought of.
  //
  // ⛔ Scrubbed BY VALUE, not by path. The four live rows carry the blob nested
  // inside a subtree value whose own path names nothing secret, so every
  // key-based matcher in this file is blind to them. A PAN-OS `-AQ=` blob or a
  // PEM body has no legitimate reason to appear in a diff payload, so matching
  // the secret's own shape is both sufficient and the only thing that works.
  //
  // Structure, paths and the FACT that something changed are all preserved —
  // only the value is replaced, so the change record stays intact and no
  // acknowledgement or alert is invalidated.
  let diffRows = 0;
  const SECRET_VALUE_RE = /-AQ=|-----BEGIN[^-]*PRIVATE KEY-----/;
  const scrubValues = (node) => {
    if (Array.isArray(node)) return node.map(scrubValues);
    if (node && typeof node === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(node)) out[k] = scrubValues(v);
      return out;
    }
    if (typeof node === 'string' && SECRET_VALUE_RE.test(node)) return REDACTED_RAW;
    return node;
  };

  const { rows: diffCandidates } = await pool.query(
    `SELECT cd.id, cd.diff
       FROM config_diffs cd
       JOIN devices d ON d.id = cd.device_id
      WHERE d.vendor = 'paloalto'
        AND cd.diff::text LIKE '%-AQ=%'
      ORDER BY cd.id`
  );
  for (const row of diffCandidates) {
    if (!row.diff || typeof row.diff !== 'object') continue;
    const before = JSON.stringify(row.diff);
    const after = JSON.stringify(scrubValues(row.diff));
    if (after === before) continue;
    await pool.query('UPDATE config_diffs SET diff = $2::jsonb WHERE id = $1', [row.id, after]);
    diffRows += 1;
  }

  return { checked, updated, secretsRedacted, leftContainers, cliRows, parsedRows, diffRows };
}

/**
 * Two data repairs for values that were written before the code that makes
 * them honest existed. Both are idempotent and safe to re-run.
 */
async function backfillUnmeasurableFacts(pool) {
  // ── 1. hit_count zeros on a transport that CANNOT measure hit counts ──
  //
  // ⛔ firewall_rules.hit_count is TRI-STATE: a real count, a genuine measured
  // 0, or NULL = NOT MEASURED. It was NOT NULL DEFAULT 0 until 2026-08-25, so
  // every vendor/transport that cannot read hit counts asserted "zero hits" —
  // and ruleAnalysis turned that into a fabricated `unused` finding.
  //
  // The code fix landed; the DATA did not. Measured 2026-09-09: TSR_EKC
  // (fortinet/ssh) still holds 30 zeros and 0 nulls, while every OTHER
  // fortinet/ssh device is 100% NULL — because TSR_EKC has had no successful
  // rules pull since 2026-08-06 and its rows are frozen from before the fix.
  // Those 30 zeros are producing 22 live `unused` findings, 6 of which
  // SecVault's own syslog directly contradicts with up to 126,300 logged hits.
  //
  // ⛔ SCOPED TO TRANSPORTS THAT CANNOT MEASURE AT ALL. On those, a 0 is never
  // a real reading, so rewriting it destroys nothing. Palo Alto's API DOES
  // measure — its 456 zeros across 10 devices are genuine measured zeros and
  // are exactly the evidence the cleanup feature runs on. Widening this to all
  // zeros would delete the product's best signal.
  const { rowCount: hitCountFixed } = await pool.query(
    `UPDATE firewall_rules fr
        SET hit_count = NULL
       FROM devices d
      WHERE d.id = fr.device_id
        AND fr.hit_count = 0
        AND (d.vendor, COALESCE(d.mgmt_method, '')) IN
            (('fortinet','ssh'), ('paloalto','ssh'), ('sangfor','ssh'))`
  );

  // ── 2. device_interfaces.ip_address holding a placeholder string ──
  //
  // ⛔ A vendor saying "this interface has no address" was stored as the
  // literal text 'N/A'. It is a TEXT column so nothing errors, but every
  // `ip_address IS NOT NULL` test counts these as addressed. Measured: 95 of
  // 241 rows (39%) across 10 devices. Same rule as everywhere else — absence
  // is NULL, never a string that looks like an answer.
  const { rowCount: ifacesFixed } = await pool.query(
    // ⛔ The list and the case-insensitive comparison MIRROR normalizeInterfaceIp()
    // in the adapters, added the same day. If the two drift, a sentinel the
    // collector now nulls would still sit in history as a fake address.
    // Measured live before the fix: 95 of 241 rows (39%), 10 devices, all
    // paloalto/api, all the literal 'N/A' — and zero existing NULLs.
    `UPDATE device_interfaces
        SET ip_address = NULL
      WHERE ip_address IS NOT NULL
        AND lower(btrim(ip_address)) IN
            ('n/a', 'na', 'none', 'unassigned', '-', '--', 'null', 'unknown', '')`
  );

  return { hitCountFixed, ifacesFixed };
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
    const coercion = await cleanupTypeCoercionConfigDiffs(pool);
    console.log(
      `[migrate] Config diff type-coercion cleanup: checked ${coercion.checked}, deleted ${coercion.deleted} row(s) that were coercion-only, updated ${coercion.updated} row(s) to drop coercion entries while keeping real changes.`
    );

    const sysInfoNoise = await cleanupSystemInfoReadFailureDiffs(pool);
    console.log(
      `[migrate] Config diff system-info-read-failure cleanup: checked ${sysInfoNoise.checked}, deleted ${sysInfoNoise.deleted} row(s), updated ${sysInfoNoise.updated} row(s) that mixed real changes with the artefact.`
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

  // Retroactive fix for HISTORICAL config_diffs rows recorded before the
  // value-based primitive-array diff existed: a one-element insert/remove into
  // a set-like primitive array (a user-group membership list) was reported as a
  // long run of positional "modified" entries plus a MIS-NAMED tail add/remove
  // -- misleading ("whole list changed" for one user leaving) and often naming
  // the wrong element. collapsePrimitiveArrayShifts() reconstructs the changed
  // region from the stored entries and re-diffs it with LCS to the true
  // added/removed; this applies that to every stored row and re-derives
  // change_summary so header/summary/detail agree. New diffs never produce this
  // (their array branch already uses LCS). Best-effort, idempotent, non-fatal.
  try {
    const { checked, updated } = await collapseHistoricalArrayShiftCascades(pool);
    console.log(
      `[migrate] Config diff shift-cascade collapse: checked ${checked} row(s), collapsed ${updated} to the real add/remove.`
    );
  } catch (err) {
    console.warn(`[migrate] config_diffs shift-cascade collapse failed (non-fatal): ${err.message}`);
  }

  // zone_classifications global -> per-device migration (see that function's
  // own comment). Best-effort, same reasoning as every other retroactive
  // cleanup above -- a failure here must not fail the whole migrate run.
  try {
    const { discardedGlobalRows } = await migrateZoneClassificationsToPerDevice(pool);
    console.log(
      `[migrate] zone_classifications per-device migration complete${discardedGlobalRows > 0 ? ` (discarded ${discardedGlobalRows} legacy global-scoped row(s))` : ''}.`
    );
  } catch (err) {
    console.warn(`[migrate] zone_classifications per-device migration failed (non-fatal): ${err.message}`);
  }

  // Retroactive re-redaction of PAN-OS secrets already sitting in
  // device_configs.config_raw / config_backups.config_raw — see
  // backfillPaloAltoConfigRedaction()'s own comment for the two defects that
  // put them there and for why it only ever rewrites a text-leaf body.
  // Best-effort like every other backfill here: a failure must not fail the
  // whole migrate (and so must not block the deploy that also ships the
  // forward-looking parser fix), but it IS logged at warn level because an
  // unfinished run here means the exposure is still open.
  try {
    const { checked, updated, secretsRedacted, leftContainers, cliRows, parsedRows, diffRows } =
      await backfillPaloAltoConfigRedaction(pool);
    console.log(
      `[migrate] Palo Alto stored-config re-redaction: checked ${checked} row(s), rewrote ${updated}, redacted ${secretsRedacted} secret value(s).` +
        (cliRows > 0 ? ` Also re-redacted ${cliRows} CLI/brace-grammar row(s).` : '') +
        (parsedRows > 0 ? ` Re-redacted config_parsed on ${parsedRows} row(s).` : '') +
        (diffRows > 0 ? ` Scrubbed ${diffRows} config_diffs payload(s).` : '') +
        (leftContainers > 0
          ? ` Left ${leftContainers} non-leaf (container) secret element(s) untouched — not confidently identifiable as a secret body, see this function's comment.`
          : '')
    );
  } catch (err) {
    console.warn(
      `[migrate] Palo Alto stored-config re-redaction failed (non-fatal, EXPOSURE MAY REMAIN): ${err.message}`
    );
  }

  // Retroactive cleanup for advisories.affected_version_ranges/fixed_in_versions
  // rows computed before the 2026-07-17 looksLikeVersion() guard existed in
  // lib/feeds/paloalto.js -- see backfillPaloAltoVersionRanges()'s own comment
  // for the full incident (confirmed live 2026-07-23 via repeat
  // "[versionComparator] Unparseable version segment" log spam tracing back to
  // stale, pre-fix ranges). Best-effort, safe to rerun indefinitely -- only
  // ever narrows an already-known-garbage range toward correct/empty, never
  // worsens one.
  try {
    const { checked, updated } = await backfillPaloAltoVersionRanges(pool);
    console.log(
      `[migrate] Palo Alto version-range backfill: checked ${checked} advisory row(s), cleaned up ${updated}.`
    );
  } catch (err) {
    console.warn(`[migrate] Palo Alto version-range backfill failed (non-fatal): ${err.message}`);
  }

  // Same retroactive cleanup as immediately above, generalized to the other five
  // vendors' NVD-native-shaped rows -- see backfillNvdNativeVersionRanges()'s own
  // comment for why Palo Alto is excluded here (already fully covered above).
  try {
    const { checked, updated } = await backfillNvdNativeVersionRanges(pool);
    console.log(
      `[migrate] NVD-native version-range backfill (non-Palo-Alto vendors): checked ${checked} advisory row(s), cleaned up ${updated}.`
    );
  } catch (err) {
    console.warn(`[migrate] NVD-native version-range backfill failed (non-fatal): ${err.message}`);
  }

  // Best-effort like every other backfill here: a failure must not fail the
  // migrate and block a deploy, but it IS logged, because until it runs the
  // fabricated values are still on screen.
  try {
    const { hitCountFixed, ifacesFixed } = await backfillUnmeasurableFacts(pool);
    console.log(
      `[migrate] Unmeasurable-value backfill: set ${hitCountFixed} hit_count(s) to NULL on `
        + `transports that cannot measure them, and cleared ${ifacesFixed} placeholder interface address(es).`
    );
  } catch (err) {
    console.warn(`[migrate] Unmeasurable-value backfill failed (non-fatal): ${err.message}`);
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

module.exports = {
  runSchema,
  seedUsers,
  // Exported for tests/paloaltoRedaction.test.js — the pure text transform is the
  // part worth pinning; the DB plumbing around it takes a stub pool.
  backfillPaloAltoConfigRedaction,
  redactStoredPaloAltoConfigRaw,
};
