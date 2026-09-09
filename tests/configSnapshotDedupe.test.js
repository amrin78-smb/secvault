'use strict';
// Pins lib/adapters/index.js's storeConfigSnapshot() — write-time dedupe for
// device_configs.
//
// WHY THIS FILE EXISTS. device_configs stored one full snapshot per device per
// pull whether or not anything had changed (540 MB of a 540-ish MB problem, and
// 93.3% of consecutive pairs on the live fleet were no change at all). The fix
// was deferred for a month for one good reason, recorded in CLAUDE.md: **a
// stored row is also evidence that a collection succeeded at time T**, so
// silently not inserting it would record a successful read as nothing — the
// mirror image of this codebase's most-repeated bug.
//
// So the tests here are not "does it dedupe". They are:
//   1. the evidence of a successful collection survives a dedupe;
//   2. change detection (config_diffs / config_backups) fires exactly when it
//      did before;
//   3. an operator's baseline row is never mutated;
//   4. ⛔ THE UNMEASURABLE CASE — when the change engine cannot answer, the
//      snapshot is STORED, never collapsed. "We could not compare these" is not
//      "these are the same". That is the case that would regress silently,
//      because collapsing produces a smaller database rather than a crash.
//
// ⛔ NO DATABASE. storeConfigSnapshot(deviceId, raw, parsed, vendor, pool) only
// ever calls pool.query(sql, params), so every test hands it a stub that records
// the statements it was given and returns canned rows. The diff engine used for
// the dedupe decision is the REAL lib/engines/configDiff.js — the whole design
// rests on the dedupe key being that engine's own definition of "no change", so
// stubbing it out would test nothing.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { storeConfigSnapshot } = require('../lib/adapters/index.js');

const ADAPTERS_SRC = fs.readFileSync(path.join(__dirname, '..', 'lib', 'adapters', 'index.js'), 'utf8');
const SCHEMA_SRC = fs.readFileSync(path.join(__dirname, '..', 'lib', 'schema.sql'), 'utf8');

// --------------------------------------------------------------------------
// Stub pool
// --------------------------------------------------------------------------

const isPrevLookup = (sql) => sql.includes('SELECT id, config_parsed, is_baseline');
const isUpdate = (sql) => sql.includes('UPDATE device_configs');
const isInsert = (sql) => sql.includes('INSERT INTO device_configs');

/**
 * @param {object|null} previous - the row the "newest snapshot" lookup returns
 * @param {{updateRowCount?:number, observationCount?:number}} [opts]
 */
function stubPool(previous, opts = {}) {
  const calls = [];
  return {
    calls,
    find(pred) {
      return calls.find((c) => pred(c.sql));
    },
    count(pred) {
      return calls.filter((c) => pred(c.sql)).length;
    },
    query(sql, params) {
      const text = String(sql);
      calls.push({ sql: text, params });
      if (isPrevLookup(text)) {
        return Promise.resolve({ rows: previous ? [previous] : [], rowCount: previous ? 1 : 0 });
      }
      if (isUpdate(text)) {
        const rowCount = opts.updateRowCount === undefined ? 1 : opts.updateRowCount;
        return Promise.resolve({
          rows: rowCount ? [{ id: 'existing-row', observation_count: opts.observationCount || 7 }] : [],
          rowCount,
        });
      }
      if (isInsert(text)) {
        return Promise.resolve({ rows: [{ id: 'new-row', observation_count: 1 }], rowCount: 1 });
      }
      return Promise.reject(new Error(`unexpected statement: ${text.slice(0, 80)}`));
    },
  };
}

// A small but realistic parsed config. Two objects built from the same literal
// are what a genuinely unchanged pull looks like to the diff engine.
const config = () => ({
  system_info: { hostname: 'edge-fw-01', model: 'PA-3220', serial: 'X', ip: '10.0.0.1' },
  tree: {
    rulebase: { security: { rules: { 'allow-web': { action: 'allow', to: ['untrust'] } } } },
    address: { 'srv-1': { 'ip-netmask': '10.1.1.1/32' } },
  },
});

const previousRow = (overrides = {}) => ({
  id: 'existing-row',
  config_parsed: config(),
  is_baseline: false,
  ...overrides,
});

// --------------------------------------------------------------------------
// A. The evidence of a successful collection survives a dedupe
// --------------------------------------------------------------------------

describe('storeConfigSnapshot: an unchanged pull is still recorded as a successful collection', () => {
  it('UPDATEs the surviving row instead of inserting a duplicate', async () => {
    const pool = stubPool(previousRow());
    const out = await storeConfigSnapshot('dev-1', 'raw text', config(), 'paloalto', pool);

    assert.equal(out.deduped, true, 'an unchanged config must not create a second row');
    assert.equal(pool.count(isInsert), 0, 'no INSERT may be issued for an unchanged pull');
    assert.equal(pool.count(isUpdate), 1);
  });

  it('moves collected_at forward — that IS the "a collection succeeded at time T" record', async () => {
    const pool = stubPool(previousRow());
    await storeConfigSnapshot('dev-1', 'raw text', config(), 'paloalto', pool);
    const sql = pool.find(isUpdate).sql;
    // Without this the row would claim the config was last seen weeks ago, and
    // every "Config as of ..." / lastConfigAt reader in the app would report a
    // live device as stale. Skipping the write entirely would be worse still:
    // a successful read recorded as nothing.
    assert.match(sql, /collected_at\s*=\s*now\(\)/i, 'the dedupe lost the proof that a pull succeeded');
  });

  it('increments observation_count so N collections are still countable', async () => {
    const pool = stubPool(previousRow(), { observationCount: 31 });
    const out = await storeConfigSnapshot('dev-1', 'raw text', config(), 'paloalto', pool);
    assert.match(pool.find(isUpdate).sql, /observation_count\s*=\s*observation_count\s*\+\s*1/i);
    assert.equal(out.observationCount, 31, 'the caller must be able to report how many pulls this row stands for');
  });

  it('never touches first_collected_at — the start of the run is the fact it preserves', async () => {
    const pool = stubPool(previousRow());
    await storeConfigSnapshot('dev-1', 'raw text', config(), 'paloalto', pool);
    assert.ok(
      !/first_collected_at/i.test(pool.find(isUpdate).sql),
      'overwriting first_collected_at would collapse the observation window to a point'
    );
  });

  it('refreshes the stored payload, so the row is not a stale copy wearing a fresh timestamp', async () => {
    const pool = stubPool(previousRow());
    await storeConfigSnapshot('dev-1', 'newest raw text', config(), 'paloalto', pool);
    const call = pool.find(isUpdate);
    // Also what keeps the NEXT real diff honest: detectAndStoreDiff compares
    // against this row, and it must hold the same bytes the old insert-always
    // code would have left there.
    assert.match(call.sql, /config_raw\s*=\s*\$2/i);
    assert.match(call.sql, /config_parsed\s*=\s*\$3::jsonb/i);
    assert.equal(call.params[1], 'newest raw text');
  });
});

// --------------------------------------------------------------------------
// B. Change detection must fire exactly when it did before
// --------------------------------------------------------------------------

describe('storeConfigSnapshot: a real change always produces a new row', () => {
  it('INSERTs when the parsed config differs, leaving two rows for the diff engine to compare', async () => {
    const changed = config();
    changed.tree.rulebase.security.rules['allow-web'].action = 'deny';
    const pool = stubPool(previousRow());
    const out = await storeConfigSnapshot('dev-1', 'raw', changed, 'paloalto', pool);

    assert.equal(out.deduped, false);
    assert.equal(pool.count(isUpdate), 0, 'a changed config must never be folded into the previous row');
    assert.equal(pool.count(isInsert), 1);
  });

  it('INSERTs the very first snapshot for a device', async () => {
    const pool = stubPool(null);
    const out = await storeConfigSnapshot('dev-1', 'raw', config(), 'paloalto', pool);
    assert.equal(out.deduped, false);
    assert.equal(pool.count(isInsert), 1);
  });

  it('INSERTs when the previous row has no usable parsed config', async () => {
    for (const bad of [null, undefined, 'not-an-object', 42]) {
      const pool = stubPool(previousRow({ config_parsed: bad }));
      const out = await storeConfigSnapshot('dev-1', 'raw', config(), 'paloalto', pool);
      assert.equal(out.deduped, false, `previous config_parsed=${JSON.stringify(bad)} must not be deduped against`);
      assert.equal(pool.count(isUpdate), 0);
    }
  });

  it('the caller skips the diff step ONLY on a dedupe, which is when the diff is empty by construction', () => {
    // Source-level, because the equivalence argument lives in collectAndStore's
    // control flow: dedupe <=> "diffConfigs(previous, incoming) is empty" <=>
    // detectAndStoreDiff would have returned {changed:false} and written
    // nothing. If this guard were ever widened (e.g. to skip on any collect), a
    // real config_diffs row and its 'auto' config_backups copy would go missing
    // with no error anywhere.
    assert.match(
      ADAPTERS_SRC,
      /if\s*\(result\.configCollected\s*&&\s*!result\.configDeduped\)\s*\{\s*\n\s*const diffResult = await detectAndStoreDiff\(/,
      'the diff/backup block must be gated on exactly (configCollected && !configDeduped)'
    );
    // The compliance audit deliberately is NOT gated on it: a deduped pull is a
    // successful collection and must still be audited, as it was before.
    assert.match(
      ADAPTERS_SRC,
      /if\s*\(result\.configCollected\)\s*\{\s*\n\s*const audit = await runComplianceAuditForDevice\(/,
      'a deduped pull is still a collection and must still be audited'
    );
  });
});

// --------------------------------------------------------------------------
// C. ⛔ The unmeasurable case: an uncomputable diff is NOT "no change"
// --------------------------------------------------------------------------

describe('storeConfigSnapshot: a comparison that could not be made never collapses a snapshot', () => {
  it('stores a new row when the diff engine throws', async () => {
    // A previous payload that explodes on any property access — a stand-in for
    // whatever future shape makes diffConfigs throw. Swallowing that as
    // "unchanged" would discard a snapshot nobody ever actually compared, which
    // is the same error as recording a failed read as a fact, inverted.
    const exploding = new Proxy(
      {},
      {
        get() {
          throw new Error('cannot read this config');
        },
        ownKeys() {
          throw new Error('cannot read this config');
        },
      }
    );
    const pool = stubPool(previousRow({ config_parsed: exploding }));
    const out = await storeConfigSnapshot('dev-1', 'raw', config(), 'paloalto', pool);

    assert.equal(out.deduped, false, 'an uncomputable diff must fall back to storing, never to collapsing');
    assert.equal(pool.count(isInsert), 1);
    assert.equal(pool.count(isUpdate), 0);
  });

  it('falls back to an INSERT when the UPDATE matched no row', async () => {
    // Race: the target became a baseline (or was removed) between the lookup
    // and the UPDATE, so the is_baseline guard in the WHERE rejected it. A lost
    // snapshot is the one outcome worse than a duplicated one.
    const pool = stubPool(previousRow(), { updateRowCount: 0 });
    const out = await storeConfigSnapshot('dev-1', 'raw', config(), 'paloalto', pool);
    assert.equal(out.deduped, false);
    assert.equal(pool.count(isUpdate), 1);
    assert.equal(pool.count(isInsert), 1);
  });
});

// --------------------------------------------------------------------------
// D. The baseline row is never the dedupe target
// --------------------------------------------------------------------------

describe('storeConfigSnapshot: an operator-designated baseline is never mutated', () => {
  it('INSERTs rather than UPDATEs when the newest row is the baseline', async () => {
    const pool = stubPool(previousRow({ is_baseline: true }));
    const out = await storeConfigSnapshot('dev-1', 'raw', config(), 'paloalto', pool);

    // is_baseline is the comparison target for drift, guaranteed unique per
    // device by a partial index. Moving its timestamps or rewriting its payload
    // would silently redefine "known good".
    assert.equal(out.deduped, false);
    assert.equal(pool.count(isUpdate), 0, 'the baseline row must never be the dedupe target');
    assert.equal(pool.count(isInsert), 1);
  });

  it('guards is_baseline a SECOND time inside the UPDATE itself', async () => {
    const pool = stubPool(previousRow());
    await storeConfigSnapshot('dev-1', 'raw', config(), 'paloalto', pool);
    // Same double-expression discipline configRetention.js uses for this flag:
    // the in-JS choice of target is one guard, the WHERE is the other, and a
    // row can only be folded into if it fails the test twice.
    assert.match(pool.find(isUpdate).sql, /WHERE\s+id\s*=\s*\$1\s*\n?\s*AND\s+is_baseline\s*=\s*false/i);
  });
});

// --------------------------------------------------------------------------
// E. content_hash: computed in SQL, and the two copies must not drift
// --------------------------------------------------------------------------

// The two expressions differ in exactly one respect — the write path binds
// $2/$3, the schema.sql backfill names the columns — so both operand spellings
// are normalised to the same placeholder and everything else must match.
function normalizeHashExpr(sql) {
  return sql
    .replace(/\s+/g, ' ')
    .replace(/\$2::text/g, 'RAW')
    .replace(/\bconfig_raw\b/g, 'RAW')
    .replace(/\(\$3::jsonb\)::text/g, 'PARSED')
    .replace(/\bconfig_parsed::text\b/g, 'PARSED')
    .trim();
}

function extractHashExpr(sql) {
  const m = sql.match(/encode\(\s*sha256\([\s\S]*?'hex'\)/);
  assert.ok(m, 'expected an encode(sha256(...), \'hex\') expression');
  return normalizeHashExpr(m[0]);
}

describe('content_hash: the stored fingerprint is computed over what is actually stored', () => {
  it('is written by both the INSERT and the dedupe UPDATE', async () => {
    const insertPool = stubPool(null);
    await storeConfigSnapshot('dev-1', 'raw', config(), 'paloalto', insertPool);
    assert.match(insertPool.find(isInsert).sql, /content_hash/);

    const changed = config();
    changed.tree.address['srv-1']['ip-netmask'] = '10.1.1.2/32';
    const updatePool = stubPool(previousRow());
    await storeConfigSnapshot('dev-1', 'raw', config(), 'paloalto', updatePool);
    assert.match(updatePool.find(isUpdate).sql, /content_hash\s*=\s*encode\(/);
  });

  it('uses the SAME expression in the write path and in schema.sql\'s backfill', async () => {
    // Drift here is invisible: both sides keep working, and a backfilled row
    // and a freshly written one holding identical content simply stop hashing
    // to the same value, which quietly breaks any future duplicate-collapse
    // pass that trusts the column.
    const pool = stubPool(null);
    await storeConfigSnapshot('dev-1', 'raw', config(), 'paloalto', pool);
    const fromCode = extractHashExpr(pool.find(isInsert).sql);

    const backfill = SCHEMA_SRC.match(/SET content_hash = (encode\(\s*sha256\([\s\S]*?'hex'\))/);
    assert.ok(backfill, 'lib/schema.sql lost its content_hash backfill');
    const fromSchema = normalizeHashExpr(backfill[1]);

    assert.equal(fromCode, fromSchema, 'the write path and the schema backfill hash differently');
  });

  it('hashes the STORED (already-redacted) text, not the pre-redaction input', async () => {
    // CLAUDE.md: stored configs are redacted before getConfig() returns, and the
    // hash must cover the same text that is stored — a hash taken over anything
    // else would depend on secrets and could differ for identical stored rows.
    // config_parsed is jsonb, which PostgreSQL re-normalises on storage, so the
    // hash is computed in SQL over the value as stored rather than in Node.
    const pool = stubPool(null);
    await storeConfigSnapshot('dev-1', 'raw', config(), 'paloalto', pool);
    const sql = pool.find(isInsert).sql;
    assert.match(sql, /\(\$3::jsonb\)::text/, 'the parsed side must hash the jsonb-normalised text');
    assert.ok(!/JSON\.stringify/.test(sql));
  });
});

// --------------------------------------------------------------------------
// F. Schema shape — the columns this all rests on must reach deployed servers
// --------------------------------------------------------------------------

describe('device_configs schema: new columns reach servers that already have the table', () => {
  it('adds every new column with ALTER TABLE ... ADD COLUMN IF NOT EXISTS', () => {
    // CREATE TABLE IF NOT EXISTS is a no-op on an existing table, so a column
    // added to the CREATE body alone never reaches a deployed server and the
    // first query selecting it crashes. Documented in CLAUDE.md; repeated often
    // enough to deserve a gate.
    for (const col of ['first_collected_at', 'observation_count', 'content_hash']) {
      assert.match(
        SCHEMA_SRC,
        new RegExp(`ALTER TABLE device_configs ADD COLUMN IF NOT EXISTS ${col}\\b`),
        `device_configs.${col} needs a companion ALTER TABLE`
      );
    }
  });

  it('backfills first_collected_at from collected_at rather than from now()', () => {
    // ADD COLUMN ... DEFAULT now() would have stamped every historical row with
    // the migration time — a fabricated fact about when a device was first
    // collected. The default is attached after the column exists instead.
    assert.match(
      SCHEMA_SRC,
      /UPDATE device_configs SET first_collected_at = collected_at WHERE first_collected_at IS NULL;/,
      'historical rows must be backfilled from their own collected_at'
    );
    assert.ok(
      !/ADD COLUMN IF NOT EXISTS first_collected_at TIMESTAMPTZ\s+(NOT NULL\s+)?DEFAULT/.test(SCHEMA_SRC),
      'ADD COLUMN with a default would fill every existing row with the migration time'
    );
  });

  it('backfills content_hash idempotently and deletes nothing', () => {
    const m = SCHEMA_SRC.match(/UPDATE device_configs\s*\n\s*SET content_hash =[\s\S]*?;/);
    assert.ok(m, 'lib/schema.sql lost its content_hash backfill');
    assert.match(m[0], /WHERE content_hash IS NULL;/, 'the backfill must be a no-op on every run after the first');
    assert.ok(
      !/DELETE\s+FROM\s+device_configs/i.test(SCHEMA_SRC),
      'computing a hash is safe; collapsing existing history is a separate decision'
    );
  });
});
