'use strict';

// lib/feeds/osHub.js
// OS/firmware BRANCH LIFECYCLE feed consumer — the hub's third signed corpus.
// CommonJS ONLY — required by services/engine-worker.js under plain node.
//
// ⛔ ═══ IT IS cveHub.js's TRANSPORT, DELIBERATELY ════════════════════════════
// Same host, same Ed25519 detached signature in X-Feed-Signature, same
// X-Feed-Sha256, same X-Feed-Checked-At, same `x-license-key`, same signing
// key. So this file writes NO new client: `lib/feeds/hubFeed.js` holds the
// pinned key, the verifier and the transport, and both feeds call it. ⛔ And NO
// new environment variables: `CVE_HUB_URL`, `CVE_HUB_LICENSE_KEY` and
// `CVE_HUB_PUBLIC_KEY` govern both, because they describe ONE publisher and one
// commercial relationship — the hub meters both corpora off the same key list.
// A second trio would be three more things to configure before a customer can
// pull, with the same answer in all three.
//
// ⛔ ═══ WHERE IT DELIBERATELY DIVERGES, AND WHY COPYING cveHub WOULD BE WRONG ══
// Two of cveHub's health signals are inverted here, and applying them unchanged
// would make this feed permanently amber for a hub working exactly as designed —
// which CLAUDE.md records as the thing that teaches an operator to ignore the
// chip that matters.
//
//   1. `generated_at` NOT ADVANCING IS NORMAL HERE. cveHub treats 14 days
//      without a new corpus as `not_advancing`, because its corpus is machine-
//      ingested hourly and a still version means the ingest died. THIS corpus is
//      refreshed by a person running `npm run build:os-cycles` against vendor
//      EOL pages that change a few times a YEAR. A fortnight of stillness is
//      the resting state, not a fault, so there is no corpus-advance check — and
//      its absence is a decision, recorded here, not an omission.
//
//   2. A MISSING `checked_at` IS `unknown` AND DOES NOT TURN THE PILL. On the
//      CVE feed an absent header means an old hub build and is pushed into
//      `errors`. Here it is the KNOWN CURRENT STATE: the hub's daily source
//      watch has not had its first run, so `/latest` reports
//      `"checked_at": null` today (verified 2026-11-16). Reporting that as a
//      failure every six hours would be a permanent warning for a condition
//      nobody can act on. ⛔ It is NOT read as healthy either — the state is
//      `unknown`, it is carried in the result and the log summary, and it never
//      claims freshness. The blind spot this leaves is narrow and named: a watch
//      that has NEVER produced a stamp is indistinguishable from one that is
//      about to. Once ANY stamp exists, ageing works and a watch that stops is
//      reported `stale`.

const {
  hubUrl, fetchWithTimeout, verifyFeedBytes, stampAge,
} = require('./hubFeed');
const { cycleIsMatchable, normaliseConfidence } = require('../osBranch');

// The whole corpus is ~23 KB (54 cycles, measured 2026-11-16) against the CVE
// feed's 3.3 MB, so this is generous rather than tight.
const FETCH_TIMEOUT_MS = 30000;

// ⛔ A STATED CADENCE, NOT A DERIVATION, and labelled as such for the same
// reason A6's `reviewOverdue` is. The hub's source watch runs DAILY, so seven
// days is seven missed runs. It is deliberately looser than the CVE feed's 24
// hours because the consequence is different in kind: a stalled CVE ingest means
// new vulnerabilities are not arriving, while a stalled lifecycle watch means a
// set of vendor dates that move a few times a year has not been re-read.
const STALE_AFTER_MS = 7 * 24 * 60 * 60 * 1000;

// The hub pins its payload shape at 1 (OS_SCHEMA_VERSION in lib/eol/os-feed.ts).
// ⛔ A HIGHER schema_version IS APPLIED WITH A WARNING, NOT REFUSED. The fields
// this consumer reads are named individually below, so an added field cannot
// break it, and refusing the corpus the day the publisher adds one would turn a
// forward-compatible change into an outage of the feature. A LOWER one is also
// only warned about: it means the hub was rolled back, and its data did not
// become wrong.
const EXPECTED_SCHEMA_VERSION = 1;

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
// How many refused cycles an error entry names before it stops listing them.
// The entry always states the true TOTAL; the list is there so the first person
// to see it can look one up by hand.
const REFUSAL_SAMPLE = 6;

/**
 * How old is the hub's last successful SOURCE WATCH?
 *
 * @returns {{state:'fresh'|'stale'|'unknown', ageMs:number|null, checkedAt:string|null, reason:string}}
 */
function feedFreshness(checkedAtRaw, nowMs) {
  const { ageMs, stamp, problem } = stampAge(checkedAtRaw, nowMs);
  if (problem === 'absent') {
    return {
      state: 'unknown', ageMs: null, checkedAt: null,
      reason: 'the hub did not report when it last checked its upstream sources (no '
        + 'checked_at), so this corpus\'s liveness is unknown — expected while the hub\'s '
        + 'daily source watch has not yet had a first successful run',
    };
  }
  if (problem === 'unparseable') {
    return {
      state: 'unknown', ageMs: null, checkedAt: stamp,
      reason: `the hub reported an unparseable checked_at (${stamp})`,
    };
  }
  if (problem === 'no_offset') {
    return {
      state: 'unknown', ageMs: null, checkedAt: stamp,
      reason: `the hub reported checked_at without a timezone offset (${stamp}), which this `
        + 'server would have to read in its own zone — a shift of hours either way',
    };
  }
  if (problem === 'future') {
    return {
      state: 'unknown', ageMs, checkedAt: stamp,
      reason: `the hub reports it last checked its sources in the FUTURE (${stamp}); this `
        + 'server and the hub disagree about the time, so the age cannot be read',
    };
  }
  if (ageMs > STALE_AFTER_MS) {
    const days = Math.round(ageMs / 86400000);
    return {
      state: 'stale', ageMs, checkedAt: stamp,
      reason: `the hub last checked its lifecycle sources ${days} days ago (threshold `
        + `${Math.round(STALE_AFTER_MS / 86400000)}), so these branch dates may no longer `
        + 'reflect what the vendors publish',
    };
  }
  return {
    state: 'fresh', ageMs, checkedAt: stamp,
    reason: `the hub last checked its lifecycle sources ${Math.round(ageMs / 3600000)}h ago`,
  };
}

/**
 * The error entries a run contributes, composed as ONE exported function.
 *
 * ⛔ COMPOSED HERE RATHER THAN INLINE, BECAUSE THE WIRING IS THE PART THAT GOES
 * UNTESTED. CLAUDE.md records this exactly: with cveHub's list composed inline,
 * deleting the `corpusAdvanceErrors` contributor left all 44 tests GREEN — every
 * arm of the verdict was pinned and nothing asserted that anybody consulted it.
 *
 * ⛔ `unknown` FRESHNESS CONTRIBUTES NOTHING, AND ONLY HERE. See the header: a
 * null `checked_at` is this hub's known present state, and a permanent `partial`
 * for it would be a chip nobody can clear. `stale` DOES contribute — once a
 * stamp has existed, its ageing is a real measurement.
 */
function syncErrors({ stats, freshness } = {}) {
  const out = [];
  if (freshness && freshness.state === 'stale') {
    out.push({ cve_id: null, message: `[OS branch feed stale] ${freshness.reason}` });
  }
  if (stats && Array.isArray(stats.refused) && stats.refused.length > 0) {
    const named = stats.refused.slice(0, REFUSAL_SAMPLE)
      .map((r) => `${r.cycle} (${r.reason})`).join('; ');
    out.push({
      cve_id: null,
      message: `[OS branch feed] ${stats.refused.length} cycle(s) in the verified corpus could `
        + 'not be read and were NOT stored, so firewalls on those branches read "branch '
        + `unknown": ${named}${stats.refused.length > REFUSAL_SAMPLE ? '; …' : ''}`,
    });
  }
  if (stats && Array.isArray(stats.errors)) out.push(...stats.errors);
  return out;
}

/**
 * Fetch the signed OS feed and verify it.
 *
 * ⛔ VERIFICATION FAILS CLOSED AND THROWS — in `hubFeed.verifyFeedBytes`, which
 * is the same code path the CVE feed uses and is tested by behaviour against the
 * real published bytes of both feeds.
 *
 * ⛔ A VERIFIED-BUT-EMPTY CORPUS IS REFUSED. A publisher bug emitting zero
 * cycles would otherwise be a correctly-signed instruction to delete every row
 * we hold (see `applyOsFeed`'s delete-absent rule), reported as a clean success.
 */
async function fetchSignedOsFeed(licenseKey) {
  const res = await fetchWithTimeout(`${hubUrl()}/api/v1/os-feed`, {
    'x-license-key': licenseKey,
    'accept-encoding': 'gzip',
  }, FETCH_TIMEOUT_MS);
  if (!res.ok) {
    const err = new Error(`OS branch hub responded HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  const signature = res.headers.get('x-feed-signature');
  const expectedSha = res.headers.get('x-feed-sha256');
  const checkedAt = res.headers.get('x-feed-checked-at');
  const body = Buffer.from(await res.arrayBuffer());

  const sha256 = verifyFeedBytes({ body, signature, expectedSha, label: 'OS feed' });

  let feed;
  try {
    feed = JSON.parse(body.toString('utf8'));
  } catch (err) {
    throw new Error(`OS feed body verified but did not parse: ${err.message}`);
  }
  if (!feed || !Array.isArray(feed.cycles)) {
    throw new Error('OS feed verified but carried no cycles array');
  }
  if (feed.cycles.length === 0) {
    throw new Error(
      'OS feed verified but contained 0 cycles — refusing (publisher fault, not an empty world)'
    );
  }
  return { feed, sha256, checkedAt };
}

/**
 * Can this cycle row be stored as a lifecycle statement?
 *
 * ⛔ WE VALIDATE WHAT THE PUBLISHER ALREADY VALIDATED, AND THAT IS NOT
 * REDUNDANT. The hub runs `checkCycle` before it publishes, so a row failing
 * here means our reading of the corpus and theirs have diverged — which is
 * precisely the state in which trusting the bytes is wrong. The two checks that
 * earn their place:
 *
 *   • NEITHER DATE — nothing to tell a consumer, and storing it would produce
 *     `cycle_unreadable` on every firewall on that branch.
 *   • EXTENDED BEFORE STANDARD — the single most likely mistake when a vendor
 *     table has an empty spacer column between the two, as Palo Alto's does.
 *     Stored as-is it does not fail, it ANSWERS WRONG: `branchState` would read
 *     a live branch as `eol`, or a dead one as `extended_only`.
 */
function checkCycleRow(row) {
  const c = row || {};
  const id = `${c.vendor || '?'}/${c.product || '?'}/${c.cycle || '?'}`;
  if (!c.vendor || !c.product || !c.cycle) {
    return { cycle: id, reason: 'vendor, product and cycle are all required' };
  }
  if (!/^\d+\.\d+/.test(String(c.cycle))) {
    return { cycle: id, reason: `cycle "${c.cycle}" is not major.minor` };
  }
  for (const field of ['release_date', 'support_end_date', 'extended_end_date']) {
    const v = c[field];
    if (v !== null && v !== undefined && !ISO_DATE.test(String(v))) {
      return { cycle: id, reason: `${field} must be YYYY-MM-DD or null, got ${JSON.stringify(v)}` };
    }
  }
  const std = c.support_end_date || null;
  const ext = c.extended_end_date || null;
  if (!std && !ext) {
    return { cycle: id, reason: 'neither support_end_date nor extended_end_date' };
  }
  if (std && ext && ext < std) {
    return {
      cycle: id,
      reason: `extended_end_date ${ext} precedes support_end_date ${std} — columns likely swapped`,
    };
  }
  if (c.release_date && std && std < c.release_date) {
    return { cycle: id, reason: `support_end_date ${std} precedes release_date ${c.release_date}` };
  }
  return null;
}

/**
 * Apply the verified corpus.
 *
 * ⛔ ROWS ABSENT FROM THE FEED ARE DELETED, and that is only safe because of the
 * two refusals above it: the signature must verify and the corpus must be
 * non-empty. The corpus is fully regenerated by the publisher every time, so a
 * branch that disappears upstream must disappear here — a retained row would go
 * on telling an operator that a long-dead branch is the vendor's current
 * statement, which is the frozen-corpus failure cveHub exists to catch, one
 * table across.
 *
 * ⛔ A REFUSED ROW IS DELETED TOO, AND THE ALTERNATIVE WAS CONSIDERED. Keeping
 * our previous copy would preserve a statement that was valid when it was
 * stored; but we would then be rendering a date the publisher has just contradicted,
 * with nothing on screen saying so. Dropping it degrades that branch to
 * `unknown` — a stated gap — and the refusal is pushed into `errors`, so the
 * feed reads `partial` rather than quietly losing coverage. Degrade toward "we
 * do not know", never toward a confident answer nobody stands behind.
 *
 * ⛔ AN ALL-REFUSED CORPUS THROWS AND CHANGES NOTHING. Applying it would delete
 * every row we hold on the strength of a disagreement between two validators,
 * taking the whole feature down with no vendor data having changed at all.
 */
async function applyOsFeed(pool, feed) {
  const stats = {
    received: 0, stored: 0, removed: 0, unmatchable: 0,
    refused: [], errors: [], byProduct: {},
  };
  const cycles = Array.isArray(feed && feed.cycles) ? feed.cycles : [];
  stats.received = cycles.length;

  if (Number(feed && feed.schema_version) !== EXPECTED_SCHEMA_VERSION) {
    stats.errors.push({
      cve_id: null,
      message: `[OS branch feed] schema_version ${JSON.stringify(feed && feed.schema_version)} is `
        + `not the expected ${EXPECTED_SCHEMA_VERSION}; the fields this consumer reads were `
        + 'applied anyway, but the payload shape should be reviewed',
    });
  }

  const accepted = [];
  for (const row of cycles) {
    const violation = checkCycleRow(row);
    if (violation) { stats.refused.push(violation); continue; }
    accepted.push(row);
    const key = `${row.vendor} ${row.product}`;
    stats.byProduct[key] = (stats.byProduct[key] || 0) + 1;
    // ⛔ COUNTED, NOT REFUSED. A cycle key `branchOf()` can never return (the
    // live corpus holds PAN-OS "9.0-XFR" and "9.0-xfr") is a perfectly valid
    // lifecycle statement about a branch this product cannot match a device to.
    // Storing it is harmless; pretending it is reachable is not, so the count is
    // reported rather than left to be rediscovered by someone asking why a
    // branch they can see reads "unknown".
    if (!cycleIsMatchable(row.cycle)) stats.unmatchable += 1;
  }

  if (accepted.length === 0) {
    throw new Error(
      `OS feed verified and carried ${cycles.length} cycle(s), but NONE could be read `
      + '— refusing to apply, so the previously stored corpus is left intact'
    );
  }

  const col = (pick) => accepted.map(pick);
  const nullable = (v) => (v === undefined || v === '' ? null : v);

  // ⛔ ONE ROUND TRIP, not one INSERT per row — the same call the hub's own
  // apply makes, and the lesson `ensureTargets()` learned when 32 sequential
  // round trips ate a whole function budget.
  const upsert = await pool.query(
    `INSERT INTO os_branch_cycles
       (vendor, product, cycle, release_date, support_end_date, extended_end_date,
        latest_version, lts, confidence, source, vendor_link, feed_version, applied_at)
     SELECT v, p, c, rd::date, sed::date, eed::date, lv, l, cf, s, vl, $12, now()
       FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[],
                   $7::text[], $8::boolean[], $9::text[], $10::text[], $11::text[])
              AS t(v, p, c, rd, sed, eed, lv, l, cf, s, vl)
     ON CONFLICT (vendor, product, cycle) DO UPDATE
        SET release_date      = EXCLUDED.release_date,
            support_end_date  = EXCLUDED.support_end_date,
            extended_end_date = EXCLUDED.extended_end_date,
            latest_version    = EXCLUDED.latest_version,
            lts               = EXCLUDED.lts,
            confidence        = EXCLUDED.confidence,
            source            = EXCLUDED.source,
            vendor_link       = EXCLUDED.vendor_link,
            feed_version      = EXCLUDED.feed_version,
            applied_at        = now()`,
    [
      col((c) => String(c.vendor)),
      col((c) => String(c.product)),
      col((c) => String(c.cycle)),
      col((c) => nullable(c.release_date)),
      col((c) => nullable(c.support_end_date)),
      col((c) => nullable(c.extended_end_date)),
      col((c) => nullable(c.latest_version)),
      // ⛔ TRI-STATE, NOT A BOOLEAN. `lts` is null for every PAN-OS row in the
      // live corpus: Palo Alto's table does not state it. Coercing that to
      // `false` would assert "this is not a long-term-support branch" on the
      // strength of a field the vendor never published — the house bug, in a
      // column nobody would think to check.
      col((c) => (typeof c.lts === 'boolean' ? c.lts : null)),
      col((c) => normaliseConfidence(c.confidence)),
      col((c) => String(c.source || '')),
      col((c) => nullable(c.vendor_link)),
      String((feed && feed.feed_version) || ''),
    ]
  );
  stats.stored = Number(upsert && upsert.rowCount) || 0;

  const del = await pool.query(
    `DELETE FROM os_branch_cycles
      WHERE (vendor, product, cycle) NOT IN (
        SELECT v, p, c FROM unnest($1::text[], $2::text[], $3::text[]) AS t(v, p, c))`,
    [col((c) => String(c.vendor)), col((c) => String(c.product)), col((c) => String(c.cycle))]
  );
  stats.removed = Number(del && del.rowCount) || 0;

  return stats;
}

/**
 * Pull, verify and apply the OS branch lifecycle corpus.
 *
 * ⛔ NOT CONFIGURED IS NOT AN ERROR. Without `CVE_HUB_LICENSE_KEY` this returns
 * `notRun` and the orchestrator logs it `skipped` WITH A REASON — a feed that
 * simply stops appearing is indistinguishable from one that silently broke. It
 * is the same key the CVE feed needs, so a site with one has both.
 */
async function fetchAndUpsertOsCycles(pool) {
  const licenseKey = (process.env.CVE_HUB_LICENSE_KEY || '').trim();
  if (!licenseKey) {
    return {
      received: 0, stored: 0, removed: 0, errors: [], notRun: true,
      reason: 'CVE_HUB_LICENSE_KEY is not set — the OS branch lifecycle feed is not configured',
    };
  }

  const { feed, sha256, checkedAt } = await fetchSignedOsFeed(licenseKey);

  // ⛔ JUDGED BEFORE THE APPLY AND NEVER BLOCKING IT. A stale corpus is still
  // VALID data — PAN-OS 10.0 did not stop being end-of-life because the hub
  // failed to re-read the page — so refusing it would throw away good
  // information to protest a different problem. Reported instead.
  const freshness = feedFreshness(checkedAt, Date.now());
  const stats = await applyOsFeed(pool, feed);
  const errors = syncErrors({ stats, freshness });

  return {
    ...stats,
    errors,
    feed_version: feed.feed_version,
    feed_sha256: sha256,
    feed_rows: feed.cycles.length,
    schema_version: feed.schema_version,
    generated_at: feed.generated_at || null,
    freshness: freshness.state,
    freshness_reason: freshness.reason,
    checked_at: freshness.checkedAt,
    age_hours: freshness.ageMs === null ? null : Math.round(freshness.ageMs / 3600000),
  };
}

module.exports = {
  fetchAndUpsertOsCycles,
  // exported for tests — the first three are pure, applyOsFeed takes a stub pool
  feedFreshness,
  syncErrors,
  checkCycleRow,
  applyOsFeed,
  // ⛔ EXPORTED SO THE SIGNATURE PATH IS TESTED BY BEHAVIOUR, AGAINST THE REAL
  // PUBLISHED BYTES. cveHub's twin carried this same comment with no test
  // behind it for its whole life; tests/hubFeed.test.js now drives both.
  fetchSignedOsFeed,
  STALE_AFTER_MS,
  EXPECTED_SCHEMA_VERSION,
};
