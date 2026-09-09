// lib/feedStatus.js
// Shared feed_sync_log status helper. Previously this exact query lived
// inline in the Advisories page's getLastSyncs() (now
// components/vulnerability/AdvisoriesTab.js, merged into /vulnerability's
// Advisories tab) — pulled out here so the header's sync-status pill and the
// Advisories tab read from the same source instead of maintaining two copies
// of the same SQL.
//
// ⛔ 'partial' IS A FAILURE STATE, AND THIS FILE USED TO SAY IT WAS NOT.
// The pill was `ok = !anyError`, matching only status === 'error'. But
// lib/feeds/index.js writes 'partial' EXACTLY WHEN a run collected errors
// (`result.errors.length > 0 ? 'partial' : 'success'`), and logSyncStart()
// INSERTs 'partial' at run start, so a run that dies mid-flight stays
// 'partial' forever. Measured on the live fleet 2026-09-09: the newest nvd run
// was 'partial' with 33 errors and fortinet_psirt 'partial' with 50 — and nvd
// had 464 'partial' runs against ZERO 'success' runs, i.e. it has never once
// logged a clean sync. The header read green FEEDS OK throughout, on every
// page, over the advisory set every CVE count, band and security score in this
// product is computed from.
//
// ⛔ ONE OPINION ONLY. lib/formatDisplay.js's feedStatusRank() already ranks
// 'partial' WITH the failures, and an unrecognised status with them too. This
// file REUSES it rather than restating "is this feed ok" a third time — two
// implementations of that question is how this drifted in the first place.

'use strict';

const { FEED_LABELS, feedStatusRank } = require('./formatDisplay');

// paloalto_psirt/fortinet_psirt were added alongside nvd/kev when those feeds
// shipped.
const KNOWN_FEEDS = ['nvd', 'paloalto_psirt', 'fortinet_psirt', 'kev'];

// A row with status 'partial' and no finished_at is either a sync running
// RIGHT NOW (logSyncStart's opening INSERT) or one that was abandoned and will
// carry that row forever. Only the clock can tell them apart. The longest
// completed run on the live fleet is ~769 s (NVD), so two hours is generously
// past "still working" without ever letting an abandoned run sit in a
// non-alarming state indefinitely.
const RUNNING_GRACE_MS = 2 * 60 * 60 * 1000;

/**
 * @param {import('pg').Pool} pool
 * @returns {Promise<object[]>} up to 10 most recent feed_sync_log rows
 */
async function getLastSyncs(pool) {
  const result = await pool.query(
    `SELECT feed_name, status, started_at, finished_at
     FROM feed_sync_log
     ORDER BY started_at DESC
     LIMIT 10`
  );
  return result.rows;
}

/**
 * Newest run per known feed, with the SIZE of its error array.
 *
 * ⛔ DISTINCT ON, not "the 10 newest rows overall, then find each feed in
 * them". The old LIMIT 10 was a latent hole: a feed whose runs are outnumbered
 * by another's falls off the end of that window and reads as "never run",
 * which this file deliberately does NOT treat as a problem. Asking per feed
 * cannot miss.
 *
 * ⛔ jsonb_array_length in SQL, never the errors payload itself — a partial NVD
 * run carries dozens of error objects and the pill needs one integer.
 */
async function getLatestPerFeed(pool) {
  const { rows } = await pool.query(
    `SELECT DISTINCT ON (feed_name)
            feed_name, status, started_at, finished_at,
            CASE WHEN jsonb_typeof(errors) = 'array' THEN jsonb_array_length(errors) ELSE 0 END AS error_count
       FROM feed_sync_log
      WHERE feed_name = ANY($1)
      ORDER BY feed_name, started_at DESC`,
    [KNOWN_FEEDS]
  );
  return rows;
}

/**
 * Per-feed verdict for one feed_sync_log row.
 * @returns {'ok'|'running'|'degraded'|'error'|'missing'}
 */
function feedState(row, nowMs) {
  if (!row) return 'missing';
  const rank = feedStatusRank(row.status);
  if (rank === 0) return 'error'; // 'error' / 'failed'
  if (rank === 3) return 'ok'; // 'success'
  if (rank === 2) return 'running'; // literal 'running'
  // rank 1 — 'partial', or a status this app has never seen. feedStatusRank
  // deliberately sorts the unknown one here too: a status we cannot interpret
  // is not evidence that things are fine.
  if (row.finished_at) return 'degraded'; // it finished, and it collected errors
  const started = row.started_at ? new Date(row.started_at).getTime() : NaN;
  if (Number.isFinite(started) && nowMs - started < RUNNING_GRACE_MS) return 'running';
  // Started long ago and never finished. That row will stay 'partial' for
  // good, so it must never be allowed to age quietly into green.
  return 'degraded';
}

const STATE_SEVERITY = { error: 0, degraded: 1, running: 2, ok: 3 };

function feedLabel(name) {
  return FEED_LABELS[name] || name;
}

/**
 * Condensed status for the header pill.
 *
 * ⛔ TRI-STATE (plus two honest edge states), never a boolean:
 *   error     — a feed's newest run recorded status 'error'.
 *   degraded  — a feed's newest run finished 'partial' (it collected errors),
 *               or was abandoned mid-run. The advisory set is INCOMPLETE.
 *   running   — a sync is in flight right now. Not a verdict either way.
 *   ok        — every known feed that has run completed its newest run cleanly.
 *   none      — no known feed has ever run.
 * `ok` (the boolean) is kept for older callers and is true ONLY for state 'ok'.
 *
 * A feed that has genuinely never run (fresh deploy, before the engine's first
 * scheduled sync) is still not treated as an error — only a feed that ran and
 * did not come back clean is.
 *
 * @param {import('pg').Pool} pool
 * @param {{now?: number}} [opts]
 */
async function getSyncPillStatus(pool, { now = Date.now() } = {}) {
  const rows = await getLatestPerFeed(pool);
  const byFeed = new Map(rows.map((r) => [r.feed_name, r]));

  const feeds = KNOWN_FEEDS.map((name) => {
    const row = byFeed.get(name) || null;
    return {
      feed: name,
      label: feedLabel(name),
      status: row ? row.status : null,
      state: feedState(row, now),
      errorCount: row ? Number(row.error_count) || 0 : 0,
      startedAt: row ? row.started_at : null,
      finishedAt: row ? row.finished_at : null,
    };
  });

  // `lastSyncs` keeps the old key name (the Advisories tab's original shape);
  // it is now one row per feed rather than the 10 newest rows overall.
  const lastSyncs = rows;

  if (feeds.every((f) => f.state === 'missing')) {
    return {
      state: 'none',
      ok: false,
      label: 'NO SYNC YET',
      title:
        'No advisory feed has ever completed a sync on this server. Every CVE count in this product is empty for want of data, not because nothing matched.',
      feeds,
      lastSyncs,
    };
  }

  const rated = feeds.filter((f) => f.state !== 'missing');
  const worst = rated.reduce(
    (acc, f) => (STATE_SEVERITY[f.state] < STATE_SEVERITY[acc] ? f.state : acc),
    'ok'
  );

  // Name the feeds and their error counts — a pill that says "degraded"
  // without saying WHICH source is incomplete cannot be acted on.
  const problems = feeds.filter((f) => f.state === 'error' || f.state === 'degraded');
  const detail = problems
    .map((f) => {
      const errs =
        f.errorCount > 0
          ? `${f.errorCount} error${f.errorCount === 1 ? '' : 's'}`
          : 'errors not recorded';
      const shape = f.state === 'error' ? 'failed' : f.finishedAt ? 'partial sync' : 'sync never finished';
      return `${f.label}: ${shape}, ${errs}`;
    })
    .join(' · ');

  if (worst === 'error') {
    return {
      state: 'error',
      ok: false,
      label: 'FEED ERROR',
      title: `${detail}. Advisory data from the failed source is missing entirely — the CVE counts, bands and scores in this product are computed from what did arrive.`,
      feeds,
      lastSyncs,
    };
  }

  if (worst === 'degraded') {
    return {
      state: 'degraded',
      ok: false,
      label: 'FEEDS DEGRADED',
      title: `${detail}. A partial sync means advisories were dropped, so every CVE count, priority band and security score in this product is computed from an INCOMPLETE advisory set.`,
      feeds,
      lastSyncs,
    };
  }

  if (worst === 'running') {
    const inFlight = feeds
      .filter((f) => f.state === 'running')
      .map((f) => f.label)
      .join(', ');
    return {
      state: 'running',
      ok: false,
      label: 'FEEDS SYNCING',
      title: `A sync is in progress (${inFlight}). Its result is not known yet — this is neither a pass nor a failure.`,
      feeds,
      lastSyncs,
    };
  }

  return {
    state: 'ok',
    ok: true,
    label: 'FEEDS OK',
    title: `Every advisory feed that has run completed its most recent sync cleanly (${rated
      .map((f) => f.label)
      .join(', ')}).`,
    feeds,
    lastSyncs,
  };
}

module.exports = {
  getLastSyncs,
  getLatestPerFeed,
  getSyncPillStatus,
  feedState,
  KNOWN_FEEDS,
  RUNNING_GRACE_MS,
};
