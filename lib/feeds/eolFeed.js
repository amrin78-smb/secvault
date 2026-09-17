// lib/feeds/eolFeed.js
//
// Pull the central NocVault hardware-EOL catalogue into `eol_seed`.
//
// ⛔ SecVault had NO hardware-EOL concept at all before this: nothing in
// schema.sql, no engine. `/lifecycle` covers the support CONTRACTS a device
// reports about itself, never "this chassis stops being supported on this date".
//
// ⛔ WRITES ONLY `eol_seed`. Never `devices`, never `device_versions`, never an
// assessment. Matching happens at READ time in lib/engines/hardwareEol.js, so a
// bad catalogue can never corrupt device data and reverting a sync is one
// statement: DELETE FROM eol_seed WHERE added_by = 'feed'.
//
// ⛔ "PULL THE SEED, NEVER PUSH THE DEVICES" — the hub's own founding rule. This
// fetches a generic vendor/model catalogue and matches locally. It never tells
// the hub what hardware the customer runs. nocvault-eol DELETED an earlier live
// query API for exactly that leak; do not reintroduce one here.

'use strict';

const https = require('https');
const http = require('http');
const zlib = require('zlib');
const { createHash, createPublicKey, verify: cryptoVerify } = require('crypto');
const { NORMALIZER_VERSION, normalizeForMatch } = require('../eolNormalize');

// Ed25519 public key (spki DER, base64). The private half exists only in the
// nocvault-eol build environment as FEED_SIGNING_KEY.
//
// ⛔ THE SAME KEY NETVAULT BUNDLES. Verified against the live feed 2026-09-17:
// feed_version 2026-09-01.1, sha256 fd11ed64…, signature verified true.
const FEED_PUBLIC_KEY_B64 = 'MCowBQYDK2VwAyEAI+nk9JoWunzPTASALa5PLWwcLe9NNWRrZ72tMY8ZU2k=';
const DEFAULT_FEED_URL = 'https://nocvault-eol.netlify.app';
const FETCH_TIMEOUT_MS = 30000;

/** Only these vendors are stored — SecVault manages firewalls, not switches. */
const KEEP_VENDORS = new Set([
  'palo alto', 'fortinet', 'forcepoint', 'cisco', 'check point', 'checkpoint', 'sangfor',
]);

function feedBase() {
  return (process.env.NOCVAULT_EOL_FEED_URL || DEFAULT_FEED_URL).replace(/\/+$/, '');
}

/**
 * GET a feed path, returning `{status, headers, body}` with the body already
 * decompressed.
 *
 * ⛔ `accept-encoding: gzip` IS SENT EXPLICITLY. Node's http client does NOT
 * negotiate compression for you, and nothing fails if you forget — you simply
 * transfer 4.4 MB instead of 180 KB, every sync, on every install, and the only
 * evidence is a slow job. Measured on the live feed: 96% saving.
 */
function fetchFeed(path, headers) {
  return new Promise((resolve, reject) => {
    const base = feedBase();
    const isHttps = base.startsWith('https://');
    const lib = isHttps ? https : http;
    const url = new URL(base + path);
    const req = lib.request({
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method: 'GET',
      headers: { 'accept-encoding': 'gzip', ...headers },
      timeout: FETCH_TIMEOUT_MS,
    }, (res) => {
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => {
        let body = Buffer.concat(chunks);
        try {
          if (res.headers['content-encoding'] === 'gzip') body = zlib.gunzipSync(body);
        } catch (err) {
          reject(new Error('feed body could not be decompressed: ' + err.message));
          return;
        }
        resolve({ status: res.statusCode, headers: res.headers, body });
      });
    });
    req.on('error', (err) => reject(err));
    req.on('timeout', () => { req.destroy(); reject(new Error('feed request timed out')); });
    req.end();
  });
}

/**
 * Verify the body against the bundled public key.
 *
 * ⛔ BOTH CHECKS, AND BEFORE ANY ROW IS WRITTEN. The sha256 catches a truncated
 * or corrupted transfer; the Ed25519 signature catches a substituted one. A
 * feed that failed either is not written at all — a partially-applied catalogue
 * is worse than none, because the rows that DID land look authoritative.
 *
 * @returns {{ok: true} | {ok: false, reason: string}}
 */
function verifyFeed(body, headers) {
  const claimedSha = headers['x-feed-sha256'];
  const sigB64 = headers['x-feed-signature'];

  if (!sigB64) return { ok: false, reason: 'the feed carried no signature header' };

  if (claimedSha) {
    const actual = createHash('sha256').update(body).digest('hex');
    if (actual !== claimedSha) {
      return {
        ok: false,
        reason: `the feed body does not match its own checksum (expected ${claimedSha.slice(0, 16)}…, `
          + `got ${actual.slice(0, 16)}…) — it was truncated or altered in transit`,
      };
    }
  }

  try {
    const key = createPublicKey({
      key: Buffer.from(FEED_PUBLIC_KEY_B64, 'base64'), format: 'der', type: 'spki',
    });
    if (!cryptoVerify(null, body, key, Buffer.from(sigB64, 'base64'))) {
      return { ok: false, reason: 'the feed signature did not verify against the bundled public key' };
    }
  } catch (err) {
    return { ok: false, reason: 'the feed signature could not be checked: ' + err.message };
  }
  return { ok: true };
}

/** Is this a vendor SecVault manages? */
function keepVendor(vendor) {
  return KEEP_VENDORS.has(String(vendor || '').trim().toLowerCase());
}

/**
 * Turn feed rows into catalogue rows.
 *
 * ⛔ A ROW WITH NO USABLE DATE AND NO EXPLICIT "no date published" IS SKIPPED,
 * not stored with nulls. Stored, it would match a device and then resolve to
 * "unknown" anyway — but it would ALSO make the catalogue look like it covers
 * that model, which is the difference between "we have no data" and "we looked
 * and there is nothing", and those are the two states this whole feature turns
 * on. Keeping them apart in the catalogue is what lets the engine keep them
 * apart on screen.
 */
function toCatalogueRows(models) {
  const rows = [];
  for (const m of models || []) {
    if (!m || !Array.isArray(m.matches) || m.matches.length === 0) continue;
    if (!keepVendor(m.vendor)) continue;

    const noDate = m.no_date_published === true;
    if (!noDate && !m.support_end_date && !m.os_eol_date) continue;

    const modelRaw = String(m.matches[0]);
    const normalized = normalizeForMatch(m.vendor, modelRaw);
    if (!normalized) continue;

    rows.push({
      vendor: String(m.vendor || '').trim(),
      modelRaw,
      modelNormalized: normalized,
      aliases: m.matches.slice(1).map(String),
      supportEndDate: m.support_end_date || null,
      osEolDate: m.os_eol_date || null,
      endOfSale: m.end_of_sale || null,
      noDatePublished: noDate,
      checkedAt: m.checked_at || null,
      confidence: m.confidence || null,
      source: m.source || null,
      note: m.note || null,
    });
  }
  return rows;
}

/**
 * Fetch, verify, and replace the feed-sourced half of `eol_seed`.
 *
 * @returns {Promise<object>} a summary shaped like the other feed runners
 */
async function syncEolFeed(pool, opts = {}) {
  const licenseKey = opts.licenseKey || '';
  const errors = [];

  let res;
  try {
    res = await fetchFeed('/api/v1/feed', {
      // ⛔ The hub requires a NON-EMPTY key today and does not yet validate it.
      // A trial install has no key by design, so it sends its server id instead
      // — refusing a trial would demo a crippled product, and the catalogue is
      // public vendor data, not a secret. See the proposal's §7.2.
      'x-license-key': licenseKey || ('trial:' + (opts.serverId || 'unknown')),
    });
  } catch (err) {
    return { ok: false, inserted: 0, updated: 0, errors: [{ message: 'feed unreachable: ' + err.message }] };
  }

  if (res.status !== 200) {
    // ⛔ A 403/401 means "no NEW catalogue", never "discard what you have" and
    // never "stop assessing". Nothing is deleted on this path.
    return {
      ok: false,
      inserted: 0,
      updated: 0,
      httpStatus: res.status,
      errors: [{ message: `the lifecycle feed answered HTTP ${res.status}. Existing catalogue data is kept.` }],
    };
  }

  const verdict = verifyFeed(res.body, res.headers);
  if (!verdict.ok) {
    return { ok: false, inserted: 0, updated: 0, errors: [{ message: 'feed REJECTED: ' + verdict.reason }] };
  }

  let feed;
  try {
    feed = JSON.parse(res.body.toString('utf8'));
  } catch (err) {
    return { ok: false, inserted: 0, updated: 0, errors: [{ message: 'feed body was not JSON: ' + err.message }] };
  }

  // ⛔ NORMALIZER DRIFT IS REPORTED, NOT IGNORED. If the hub has moved to a
  // newer matching contract than this copy implements, some models will quietly
  // stop matching and the only symptom is a device that used to show a date
  // showing "unknown". It is a warning, not a refusal — a mismatched version
  // still matches most models, and refusing the whole feed would be worse.
  if (typeof feed.normalizer_version === 'number' && feed.normalizer_version !== NORMALIZER_VERSION) {
    errors.push({
      message: `the feed was built with normalizer version ${feed.normalizer_version} but this `
        + `installation implements version ${NORMALIZER_VERSION}. Some hardware models may stop `
        + 'matching until SecVault is updated.',
    });
  }

  const rows = toCatalogueRows(feed.models);
  if (rows.length === 0) {
    // ⛔ A PLAUSIBILITY FLOOR, same rule as the cloud catalogue. A verified,
    // well-formed but EMPTY feed must not be allowed to empty the catalogue —
    // that would turn every dated device into "unknown" in one sync.
    return {
      ok: false,
      inserted: 0,
      updated: 0,
      feedVersion: feed.feed_version || null,
      errors: [{ message: 'the feed verified but contained no usable rows for this product\'s vendors; nothing was written.' }],
    };
  }

  let inserted = 0;
  let updated = 0;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const r of rows) {
      const q = await client.query(
        `INSERT INTO eol_seed
           (vendor, model_raw, model_normalized, aliases, support_end_date, os_eol_date,
            end_of_sale, no_date_published, checked_at, confidence, source_url, note,
            added_by, feed_version, synced_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'feed',$13, now())
         ON CONFLICT (vendor, model_normalized) DO UPDATE SET
           model_raw = EXCLUDED.model_raw,
           aliases = EXCLUDED.aliases,
           support_end_date = EXCLUDED.support_end_date,
           os_eol_date = EXCLUDED.os_eol_date,
           end_of_sale = EXCLUDED.end_of_sale,
           no_date_published = EXCLUDED.no_date_published,
           checked_at = EXCLUDED.checked_at,
           confidence = EXCLUDED.confidence,
           source_url = EXCLUDED.source_url,
           note = EXCLUDED.note,
           feed_version = EXCLUDED.feed_version,
           synced_at = now()
         RETURNING (xmax = 0) AS was_insert`,
        [r.vendor, r.modelRaw, r.modelNormalized, r.aliases, r.supportEndDate, r.osEolDate,
          r.endOfSale, r.noDatePublished, r.checkedAt, r.confidence, r.source, r.note,
          feed.feed_version || null]
      );
      if (q.rows[0] && q.rows[0].was_insert) inserted++; else updated++;
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    return { ok: false, inserted: 0, updated: 0, errors: [{ message: 'catalogue write failed, rolled back: ' + err.message }] };
  } finally {
    client.release();
  }

  return {
    ok: true,
    inserted,
    updated,
    rowsOffered: (feed.models || []).length,
    rowsKept: rows.length,
    feedVersion: feed.feed_version || null,
    generatedAt: feed.generated_at || null,
    errors,
  };
}

/** Catalogue rows in the shape `hardwareEol.buildIndex()` expects. */
async function loadCatalogue(pool) {
  const { rows } = await pool.query(
    `SELECT vendor, model_raw, aliases, support_end_date, os_eol_date,
            no_date_published, checked_at, confidence, source_url
       FROM eol_seed`
  );
  return rows.map((r) => ({
    vendor: r.vendor,
    modelRaw: r.model_raw,
    aliases: r.aliases || [],
    supportEndDate: r.support_end_date,
    osEolDate: r.os_eol_date,
    noDatePublished: r.no_date_published === true,
    checkedAt: r.checked_at,
    confidence: r.confidence,
    source: r.source_url,
  }));
}

/**
 * How old the catalogue is.
 *
 * ⛔ THIS IS THE HUB-MONITORING SIGNAL, and it is a DIFFERENT question from
 * "did the last sync succeed". A hub that answers 200 with a three-month-old
 * feed is up and useless; a hub that is down for a day over a fresh catalogue is
 * fine. `feed_sync_log` records reachability; this records usefulness.
 */
async function catalogueFreshness(pool) {
  const { rows } = await pool.query(
    `SELECT count(*)::int AS rows, max(synced_at) AS last_sync,
            max(feed_version) AS feed_version
       FROM eol_seed WHERE added_by = 'feed'`
  );
  const r = rows[0] || {};
  const last = r.last_sync ? new Date(r.last_sync) : null;
  return {
    rows: r.rows || 0,
    lastSync: last,
    feedVersion: r.feed_version || null,
    // null, never 0 — "never synced" is not "synced today".
    ageDays: last ? Math.floor((Date.now() - last.getTime()) / 86400000) : null,
  };
}

module.exports = {
  FEED_PUBLIC_KEY_B64,
  KEEP_VENDORS,
  fetchFeed,
  verifyFeed,
  toCatalogueRows,
  syncEolFeed,
  loadCatalogue,
  catalogueFreshness,
};
