// lib/feeds/epss.js
// FIRST.org EPSS (Exploit Prediction Scoring System) — probability that a CVE
// will be exploited in the wild in the next 30 days, plus its percentile.
//
// CommonJS ONLY — this file is `require()`d by services/engine-worker.js (plain node).
//
// ─────────────────────────────────────────────────────────────────────────────
// ⛔ THE RULE THAT DEFINES THIS FEED: ENRICHMENT-ONLY. IT MAY NEVER INSERT.
// ─────────────────────────────────────────────────────────────────────────────
// `advisories.cve_id` is UNIQUE across the whole table and carries exactly ONE
// vendor, so any feed that INSERTs can permanently squat a CVE under the wrong
// vendor. That harm is demonstrated, not theoretical: CVE-2022-0778 is an
// OpenSSL bug Fortinet republished, and in this database it belongs to
// `paloalto` with 6 real version ranges — whichever feed inserted first owned
// it (see .ai-codex/cve-pipeline.md and roadmap.md).
//
// EPSS covers ~371,000 CVEs; SecVault tracks ~1,004 advisories. Inserting even
// a fraction would flood a firewall-management product with CVEs about
// browsers, kernels and word processors. So this file reads the EPSS corpus,
// UPDATEs the rows that ALREADY EXIST, and COUNTS (never stores) the rest.
// Every write statement in here is an `UPDATE ... WHERE cve_id = ...`; there is
// no INSERT, by construction. `kev.js` is the same shape and the precedent.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⛔ NO SCORE IS NULL. IT IS NEVER 0.
// ─────────────────────────────────────────────────────────────────────────────
// An EPSS of 0.0 is a real measurement ("essentially never exploited"). The
// absence of a score is not a measurement at all. Collapsing the two is this
// codebase's most-repeated bug (`hit_count` NOT NULL DEFAULT 0, `getRules()`
// returning `[]`, an unanswerable compliance check scored as a warning).
//
// The three states are distinguishable in the schema:
//   epss_checked_at IS NULL                     never looked up (feed has not
//                                               run since this advisory landed)
//   epss_checked_at set, epss_score IS NULL     looked up, FIRST publishes no
//                                               score for this identifier
//   epss_score = 0                              FIRST published a genuine zero
// and in this file: `parseProbability()` returns null — never 0 — for anything
// it cannot read, and a null is skipped rather than written.
//
// Measured live 2026-09-10 against the fleet's 1,004 advisories: 945 scored, 59
// unscored, and ALL 59 are `PAN-SA-*` Palo Alto advisory identifiers, which are
// not CVE ids at all. That is exactly the case that must not be reported as
// "probability zero".
//
// ─────────────────────────────────────────────────────────────────────────────
// ⛔ A SCORE WITH NO MEASUREMENT DATE IS NOT STORED.
// ─────────────────────────────────────────────────────────────────────────────
// EPSS is re-modelled and republished DAILY and the numbers move. A stored
// score with no date is unfalsifiable — it cannot be told from one frozen in
// place by a feed that silently stopped running months ago. So `epss_score_date`
// (FIRST's own date for that score) is mandatory: no date, no write. Staleness
// is then a readable fact, via `epssFreshness()`, not an assumption.
//
// ⛔ This feed NEVER clears a score. A CVE dropping out of the EPSS corpus
// (withdrawn/rejected records do) is not evidence the last score was wrong, and
// blanking it would be a failed read stored as a fact. The row keeps its score
// with its old `epss_score_date` while `epss_checked_at` advances — which reads
// exactly as what happened: "we looked today; FIRST no longer scores this".
//
// ⛔ This feed does NOT touch `priority_band`. CLAUDE.md's priority decision
// tree may only change after CLAUDE.md itself is changed. EPSS is stored and
// exposed here; whether it earns a branch in that tree is a separate decision.
//
// ─────────────────────────────────────────────────────────────────────────────
// ENDPOINT + FORMAT — VERIFIED LIVE 2026-09-10, NOT READ FROM DOCUMENTATION
// ─────────────────────────────────────────────────────────────────────────────
// Per CLAUDE.md's "documentation lies" rule, both sources were probed and their
// real bytes logged before this parser was written.
//
// PRIMARY (bulk, preferred — one request instead of ~1,004):
//   GET https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
//     → 302 to `epss_scores-<YYYY-MM-DD>.csv.gz` (RELATIVE Location header;
//       node-fetch@2 follows redirects by default), then 200,
//       Content-Type: binary/octet-stream, Content-Length 2,617,620.
//   The older host `https://epss.cyentia.com/epss_scores-current.csv.gz` still
//   works and 301s here; this is the canonical name now.
//   Decompressed, the file's first three lines are literally:
//     #model_version:v2026.06.15,score_date:2026-09-10T12:00:22Z
//     cve,epss,percentile
//     CVE-1999-0001,0.03351,0.87967
//   371,256 data rows. Values are 5-decimal strings; observed corpus range
//   0.00047 .. 0.99999 with ZERO rows at exactly 0.00000 today.
//
// FALLBACK (per-CVE, same publisher):
//   GET https://api.first.org/data/v1/epss?cve=<comma-separated ids>&limit=N
//     → {"status":"OK", ..., "total":1, "data":[{"cve":"CVE-2022-0778",
//        "epss":"0.731880000","percentile":"0.994230000","date":"2026-09-10"}]}
//   Verified: 120 ids in one URL (1,799 chars) is accepted; unknown ids are
//   simply ABSENT from `data` — no error, no placeholder, no zero. Response
//   header `x-total: 371256` confirms the same corpus. The API pads values to 9
//   decimals ("0.999990000") but carries no model version.
//
// ⛔ Both hosts were confirmed reachable from the production server
// (192.168.7.69) over TCP 443 with live 200s, unlike `services.nvd.nist.gov`,
// which is blocked at that network's edge.
//
// ⛔ The fallback here triggers on ANY unusable bulk response, not only a
// network-level failure — and that is DELIBERATELY different from nvd.js's
// CIRCL rule. NVD→CIRCL swaps to a DIFFERENT PUBLISHER with coarser data, so it
// is gated hard. Here both endpoints are FIRST's own publication of the same
// daily model run, so preferring "get the data another way" costs nothing in
// provenance. The reason is always recorded in `errors`, so a run that fell back
// is logged `partial`, never painted green.

const zlib = require('zlib');

// node-fetch@2's package.json declares BOTH "main" (CJS) and "module" (ESM);
// Next.js's bundler resolves "module" even for a plain require() inside an API
// route bundle, handing back the namespace object rather than the callable.
// Same guard as kev.js/nvd.js — see kev.js's comment for the full history.
const fetchModule = require('node-fetch');
const fetch = fetchModule.default || fetchModule;

const EPSS_CSV_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';
const EPSS_API_URL = 'https://api.first.org/data/v1/epss';

// Same name, same value, independently defined per feed file — this codebase's
// established "duplicated, not imported" convention for feed constants.
// node-fetch@2 has NO default timeout at all; without this a silently-dropped
// packet hangs the whole sequential feed cycle forever.
const FETCH_TIMEOUT_MS = 20000;

// node-fetch@2 `size` option: hard cap on the response body. The real file is
// ~2.6 MB; this only stops a misdirected/hostile response eating the heap.
const MAX_BULK_BYTES = 64 * 1024 * 1024;

// 120 ids in one URL is live-verified to work; 100 keeps the URL ~1.5 KB.
const API_CHUNK_SIZE = 100;
const API_CHUNK_DELAY_MS = 250;

// Read-side helper only (see epssFreshness). EPSS republishes daily, so a score
// older than a month means OUR feed stopped, not that FIRST went quiet.
const EPSS_STALE_AFTER_DAYS = 30;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Parse an EPSS probability/percentile.
 * ⛔ Returns null — NEVER 0 — for anything unreadable. `Number('')` is 0 and 0
 * is FINITE, which is precisely how an absent value becomes a confident
 * "essentially never exploited" (the same trap documented for clampInt in
 * .ai-codex/gotchas.md), so the empty/whitespace case is rejected BEFORE
 * Number() ever sees it.
 * @returns {number|null} a probability in [0,1], or null if not measurable
 */
function parseProbability(raw) {
  if (raw === null || raw === undefined) return null;
  const s = String(raw).trim();
  if (s === '') return null;
  const n = Number(s);
  if (!Number.isFinite(n)) return null;
  if (n < 0 || n > 1) return null; // a probability outside [0,1] is corrupt, not a value
  return n;
}

/**
 * Normalize FIRST's date forms to a plain calendar date.
 * The CSV header carries `2026-09-10T12:00:22Z`; the API carries `2026-09-10`.
 * @returns {string|null} 'YYYY-MM-DD', or null when there is no usable date
 */
function parseScoreDate(raw) {
  if (raw === null || raw === undefined) return null;
  const m = String(raw).trim().match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (!m) return null;
  const iso = `${m[1]}-${m[2]}-${m[3]}`;
  const parsed = new Date(`${iso}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime())) return null;
  return iso;
}

/**
 * Parse the decompressed bulk CSV. Pure — no network, no clock, no DB.
 *
 * ⛔ Columns are located BY NAME from the header row, never by position. If
 * FIRST ever reorders `cve,epss,percentile`, positional parsing would silently
 * swap the probability and the percentile — two different quantities, both
 * plausible-looking numbers in [0,1], and nothing would error. A missing header
 * name is a hard failure that stores nothing.
 *
 * @param {string} text decompressed CSV
 * @param {Set<string>|null} wanted only keep these cve ids (the advisories we have)
 */
function parseEpssCsv(text, wanted) {
  const out = {
    scoreDate: null,
    modelVersion: null,
    scores: new Map(),
    feedRows: 0,
    malformed: 0,
    error: null,
  };

  const lines = String(text || '').split('\n');
  let i = 0;

  // Leading `#key:value,key:value` metadata comment(s).
  for (; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === '') continue;
    if (!line.startsWith('#')) break;
    for (const part of line.slice(1).split(',')) {
      const sep = part.indexOf(':');
      if (sep < 0) continue;
      const key = part.slice(0, sep).trim();
      const value = part.slice(sep + 1).trim();
      // score_date's value contains its own colons (…T12:00:22Z) — split on the
      // FIRST colon only, never on every one.
      if (key === 'score_date') out.scoreDate = parseScoreDate(value);
      else if (key === 'model_version') out.modelVersion = value || null;
    }
  }

  const header = (lines[i] || '').trim().split(',').map((h) => h.trim().toLowerCase());
  i++;
  const cveIdx = header.indexOf('cve');
  const epssIdx = header.indexOf('epss');
  const pctIdx = header.indexOf('percentile');
  if (cveIdx < 0 || epssIdx < 0 || pctIdx < 0) {
    out.error =
      `EPSS CSV header did not carry cve/epss/percentile (got: ${JSON.stringify(header.slice(0, 6))}) — `
      + 'refusing to parse positionally, which could swap probability and percentile';
    return out;
  }

  for (; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === '' || line.startsWith('#')) continue;
    const cols = line.split(',');
    const cve = (cols[cveIdx] || '').trim();
    if (cve === '') {
      out.malformed++;
      continue;
    }
    out.feedRows++;
    // ⛔ Filtered HERE: the ~370,000 records that match no advisory of ours are
    // counted (feedRows) and dropped. They are never stored, and there is no
    // code path in this file that could store them.
    if (wanted && !wanted.has(cve)) continue;
    const score = parseProbability(cols[epssIdx]);
    const percentile = parseProbability(cols[pctIdx]);
    if (score === null || percentile === null) {
      out.malformed++;
      continue; // unreadable is not zero
    }
    out.scores.set(cve, {
      score,
      percentile,
      scoreDate: out.scoreDate,
      modelVersion: out.modelVersion,
    });
  }

  return out;
}

/**
 * Parse one FIRST API envelope. Pure.
 * ⛔ An id we asked about that is ABSENT from `data` has NO score. It must not
 * become a row — verified live: unknown ids are simply omitted.
 */
function parseEpssApiPayload(json) {
  const out = { scores: new Map(), returned: 0, malformed: 0, total: null, error: null };
  if (!json || typeof json !== 'object' || !Array.isArray(json.data)) {
    out.error = 'EPSS API response carried no `data` array';
    return out;
  }
  const total = Number(json.total);
  out.total = Number.isFinite(total) ? total : null;
  for (const rec of json.data) {
    if (!rec || typeof rec !== 'object') {
      out.malformed++;
      continue;
    }
    const cve = typeof rec.cve === 'string' ? rec.cve.trim() : '';
    const score = parseProbability(rec.epss);
    const percentile = parseProbability(rec.percentile);
    const scoreDate = parseScoreDate(rec.date);
    if (cve === '' || score === null || percentile === null) {
      out.malformed++;
      continue;
    }
    out.returned++;
    out.scores.set(cve, {
      score,
      percentile,
      scoreDate,
      // ⛔ The API carries no model version. Writing NULL is correct: carrying
      // the PREVIOUS run's model version forward beside a NEW score would
      // label it with a model that did not produce it.
      modelVersion: null,
    });
  }
  return out;
}

/**
 * Download + parse the daily bulk file. Throws on anything unusable — the
 * caller falls back to the API and records why.
 */
async function fetchEpssBulk(wanted) {
  const res = await fetch(EPSS_CSV_URL, { timeout: FETCH_TIMEOUT_MS, size: MAX_BULK_BYTES });
  if (!res.ok) throw new Error(`EPSS bulk download failed: HTTP ${res.status}`);

  const body = Buffer.from(await res.arrayBuffer());
  // ⛔ Classify the response BEFORE parsing it — the FortiGuard lesson. An
  // HTTP 200 that is not gzip is a proxy/captive-portal/interstitial page, and
  // saying so is a different (and true) statement from "the CSV was malformed".
  if (body.length < 2 || body[0] !== 0x1f || body[1] !== 0x8b) {
    throw new Error(
      `EPSS bulk response is not gzip (${body.length} bytes, starts 0x${body.slice(0, 4).toString('hex')}) `
      + '— almost certainly an interstitial or proxy page, not the score file'
    );
  }

  const text = zlib.gunzipSync(body).toString('utf8');
  const parsed = parseEpssCsv(text, wanted);
  if (parsed.error) throw new Error(parsed.error);
  if (parsed.feedRows === 0) throw new Error('EPSS bulk file decompressed but contained zero score rows');
  if (!parsed.scoreDate) {
    throw new Error(
      'EPSS bulk file carries no usable score_date — a score with no measurement date is '
      + 'unfalsifiable and is not stored'
    );
  }
  return {
    source: 'bulk',
    scoreDate: parsed.scoreDate,
    modelVersion: parsed.modelVersion,
    scores: parsed.scores,
    feedRows: parsed.feedRows,
    malformed: parsed.malformed,
    truncatedChunks: 0,
  };
}

/**
 * Per-CVE fallback against api.first.org, in chunks.
 * ⛔ `feedRows` is NULL here, not 0: this path only ever SEES the ids it asked
 * about, so "how many EPSS records matched nothing" is genuinely unknown from
 * it. Reporting 0 would be a fabricated number.
 */
async function fetchEpssApi(cveIds) {
  const out = {
    source: 'api',
    scoreDate: null,
    modelVersion: null,
    scores: new Map(),
    feedRows: null,
    malformed: 0,
    truncatedChunks: 0,
  };

  for (let i = 0; i < cveIds.length; i += API_CHUNK_SIZE) {
    const chunk = cveIds.slice(i, i + API_CHUNK_SIZE);
    const url = `${EPSS_API_URL}?envelope=true&pretty=false&limit=${chunk.length}`
      + `&cve=${encodeURIComponent(chunk.join(','))}`;
    const res = await fetch(url, { timeout: FETCH_TIMEOUT_MS });
    if (!res.ok) throw new Error(`EPSS API request failed: HTTP ${res.status}`);
    const json = await res.json();
    const parsed = parseEpssApiPayload(json);
    if (parsed.error) throw new Error(parsed.error);

    // The envelope's own `total` exceeding what it returned means the page was
    // truncated and some scores are missing from this chunk. Counted, not hidden.
    if (parsed.total !== null && parsed.total > parsed.returned) out.truncatedChunks++;

    out.malformed += parsed.malformed;
    for (const [cve, rec] of parsed.scores) {
      out.scores.set(cve, rec);
      if (!out.scoreDate && rec.scoreDate) out.scoreDate = rec.scoreDate;
    }

    if (i + API_CHUNK_SIZE < cveIds.length) await sleep(API_CHUNK_DELAY_MS);
  }

  return out;
}

/**
 * Cross-reference EPSS against the `advisories` table. ENRICHMENT ONLY —
 * every write is an UPDATE keyed on an existing `cve_id`.
 *
 * Returns the shape lib/feeds/index.js's other feed wrappers expect
 * (`inserted`/`updated`/`errors`) plus a `summary` the wrapper can append to
 * the log's errors jsonb as ONE clearly-marked informational entry, exactly as
 * runNvdSync does with its per-vendor breakdown.
 *
 * ⛔ `inserted` is 0 and is a structural invariant, not a coincidence.
 *
 * @param {import('pg').Pool} pool
 */
async function fetchAndUpsertEpssScores(pool) {
  const errors = [];
  const summary = {
    source: null,
    score_date: null,
    model_version: null,
    advisories_considered: 0,
    matched: 0,
    score_changed: 0,
    no_score: 0,
    failed: 0,
    feed_records: null,
    feed_records_unmatched: null,
    malformed_records: 0,
    truncated_chunks: 0,
  };

  // 1. The ONLY rows this feed may ever touch. Reading the previous score here
  //    too means the "did the number actually move" question costs no extra query.
  let existing;
  try {
    const result = await pool.query(`SELECT cve_id, epss_score FROM advisories`);
    existing = result.rows || [];
  } catch (err) {
    errors.push({ cve_id: null, message: `Failed to read advisories for EPSS enrichment: ${err.message}` });
    return { inserted: 0, updated: 0, errors, summary };
  }

  const wanted = new Set();
  const previousScore = new Map();
  for (const row of existing) {
    if (!row || typeof row.cve_id !== 'string' || row.cve_id === '') continue;
    wanted.add(row.cve_id);
    // pg returns NUMERIC as a string; null stays null and must not become 0.
    previousScore.set(
      row.cve_id,
      row.epss_score === null || row.epss_score === undefined ? null : Number(row.epss_score)
    );
  }
  summary.advisories_considered = wanted.size;
  if (wanted.size === 0) {
    // Nothing to enrich is not a failure — a fresh install has no advisories yet.
    return { inserted: 0, updated: 0, errors, summary };
  }

  // 2. Fetch: bulk first, per-CVE API as the fallback.
  let feed = null;
  try {
    feed = await fetchEpssBulk(wanted);
  } catch (bulkErr) {
    errors.push({
      cve_id: null,
      message: `[EPSS bulk unusable] ${bulkErr.message} — falling back to the FIRST per-CVE API`,
    });
    try {
      feed = await fetchEpssApi([...wanted]);
    } catch (apiErr) {
      errors.push({ cve_id: null, message: `EPSS API fallback also failed: ${apiErr.message}` });
      // ⛔ Write NOTHING — not even epss_checked_at. Stamping "checked" after a
      // failed fetch would assert we looked and found no score, which is the
      // failed-read-as-a-fact bug this whole file is written against.
      return { inserted: 0, updated: 0, errors, summary };
    }
  }

  summary.source = feed.source;
  summary.score_date = feed.scoreDate;
  summary.model_version = feed.modelVersion;
  summary.feed_records = feed.feedRows;
  summary.malformed_records = feed.malformed;
  summary.truncated_chunks = feed.truncatedChunks;
  if (feed.truncatedChunks > 0) {
    errors.push({
      cve_id: null,
      message: `${feed.truncatedChunks} EPSS API chunk(s) reported more results than were returned; some scores may be missing from this run`,
    });
  }

  // 3. UPDATE only. One statement per matched CVE, same shape as kev.js — it
  //    keeps a single bad row from costing the batch, and keeps every SQL
  //    identifier checkable by tests/sqlColumns.test.js.
  const written = new Set();
  const failed = new Set();
  for (const [cveId, rec] of feed.scores) {
    if (!wanted.has(cveId)) continue; // belt and braces; both fetch paths already scope to `wanted`
    if (!rec.scoreDate) {
      errors.push({ cve_id: cveId, message: 'EPSS record carries no score date; not stored' });
      failed.add(cveId);
      continue;
    }
    const previous = previousScore.get(cveId);
    // The column is NUMERIC(6,5), so compare at the precision actually stored.
    const scoreChanged =
      previous === null || previous === undefined || !Number.isFinite(previous)
        ? true
        : previous !== Number(rec.score.toFixed(5));
    try {
      const result = await pool.query(
        `UPDATE advisories
         SET epss_score = $1::numeric,
             epss_percentile = $2::numeric,
             epss_score_date = $3::date,
             epss_model_version = $4,
             epss_checked_at = now(),
             updated_at = CASE WHEN $5::boolean THEN now() ELSE updated_at END
         WHERE cve_id = $6`,
        [rec.score, rec.percentile, rec.scoreDate, rec.modelVersion, scoreChanged, cveId]
      );
      if (result.rowCount > 0) {
        summary.matched += result.rowCount;
        if (scoreChanged) summary.score_changed += result.rowCount;
        written.add(cveId);
      }
    } catch (err) {
      failed.add(cveId);
      errors.push({ cve_id: cveId, message: err.message });
    }
  }
  summary.failed = failed.size;

  if (feed.feedRows !== null && feed.feedRows !== undefined) {
    // The ~370,000 EPSS records that match nothing SecVault tracks: counted and
    // reported here, never stored.
    summary.feed_records_unmatched = Math.max(0, feed.feedRows - summary.matched);
  }

  // 4. "We asked, and FIRST has no score for this identifier" is itself a fact
  //    worth recording — it is what separates an unscored advisory from one this
  //    feed has never seen. Rows whose UPDATE errored are excluded: we did not
  //    successfully check those.
  const unscored = [...wanted].filter((cveId) => !written.has(cveId) && !failed.has(cveId));
  summary.no_score = unscored.length;
  if (unscored.length > 0) {
    try {
      await pool.query(
        `UPDATE advisories SET epss_checked_at = now() WHERE cve_id = ANY($1::text[])`,
        [unscored]
      );
    } catch (err) {
      errors.push({ cve_id: null, message: `Failed to stamp epss_checked_at on unscored advisories: ${err.message}` });
    }
  }

  return { inserted: 0, updated: summary.matched, errors, summary };
}

/**
 * How much a stored EPSS score can be trusted right now. Pure — `now` is
 * injectable so this is testable and so no caller has to invent a clock.
 *
 * ⛔ There is no default of 'fresh'. Anything indeterminate says so.
 *   'never_checked'  the feed has not looked this advisory up yet
 *   'no_score'       looked up; FIRST publishes no score for this identifier
 *   'unknown'        a score exists but carries no usable date (should be
 *                    unreachable — this feed refuses to write one)
 *   'stale'          scored, but FIRST's own date is older than the window;
 *                    EPSS republishes daily, so this means OUR feed stopped
 *   'fresh'          scored within the window
 *
 * @param {{epss_score?: any, epss_score_date?: any, epss_checked_at?: any}} row
 * @param {Date} [now]
 */
function epssFreshness(row, now = new Date()) {
  if (!row || typeof row !== 'object') return 'unknown';
  const score = row.epss_score;
  if (score === null || score === undefined || score === '') {
    return row.epss_checked_at ? 'no_score' : 'never_checked';
  }
  const scoreDate = parseScoreDate(
    row.epss_score_date instanceof Date ? row.epss_score_date.toISOString() : row.epss_score_date
  );
  if (!scoreDate) return 'unknown';
  const ageDays = (now.getTime() - new Date(`${scoreDate}T00:00:00Z`).getTime()) / 86400000;
  if (!Number.isFinite(ageDays)) return 'unknown';
  return ageDays > EPSS_STALE_AFTER_DAYS ? 'stale' : 'fresh';
}

module.exports = {
  fetchAndUpsertEpssScores,
  epssFreshness,
  // exported for tests / diagnostics
  parseEpssCsv,
  parseEpssApiPayload,
  parseProbability,
  parseScoreDate,
  EPSS_CSV_URL,
  EPSS_API_URL,
  EPSS_STALE_AFTER_DAYS,
  FETCH_TIMEOUT_MS,
};
