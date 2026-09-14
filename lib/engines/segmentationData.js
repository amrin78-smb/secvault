'use strict';

// lib/engines/segmentationData.js
//
// The database half of segmentation intent: loads the fleet's rules with their
// traffic evidence, and evaluates every declared intent against them.
//
// ⛔ SPLIT FROM segmentation.js DELIBERATELY. That file is pure — zone matching
// and verdicts, no pool — which is what lets tests drive every branch with
// literal rules. This file is the plumbing. Keeping the judgement out of the
// plumbing is what makes the judgement testable.
//
// ⛔ TRAFFIC EVIDENCE IS NOT RE-DERIVED HERE. lib/engines/ruleHitCorrelation.js
// already knows how to tell a MEASURED zero from an absence of coverage, and
// getting that distinction wrong is the whole failure mode of this feature. Two
// implementations would eventually disagree, and the wrong one would be the one
// recommending rule deletions.

const { getDeviceLogCoverage, getLoggedRuleHits, enrichRulesWithLogEvidence } =
  require('./ruleHitCorrelation');
const {
  evaluateIntent,
  summarise,
  normaliseZone,
  isUnrecognisedAction,
} = require('./segmentation');

const DEFAULT_WINDOW_DAYS = 30;

// ⛔ THE WINDOW IS RESOLVED ONCE, AND THE RESOLVED VALUE IS WHAT IS REPORTED.
//
// There used to be TWO resolutions of the same parameter, in two files, and they
// disagreed. `?days=-5` passed the route's `Number.isFinite` check;
// evaluateSegmentation's `opts.windowDays || 30` kept -5 and REPORTED it, while
// loadFleetRulesWithEvidence's own `> 0 ? … : 30` quietly measured 30 instead.
// The page printed "Evaluated over -5 days against 1,757 rules" and the evidence
// drawer said "over the last -5 days", over a 30-day measurement. `?days=3` is
// the subtler and more dangerous version: the page says 3, ruleHitCorrelation's
// clampDays floors the evidence at 7, and nothing anywhere looks broken.
//
// A window that is misreported is worse than a window that is wrong: every
// number on the page is a measurement, and the stated span is how the reader
// decides what the measurement is worth.
//
// ⛔ THE FLOOR OF 7 AND CAP OF 400 MIRROR ruleHitCorrelation.clampDays, which is
// not exported. They are not a style choice there: with a shorter floor a single
// day of logs satisfies both coverage tests and can certify a rule as a MEASURED
// zero, which is exactly the fabricated `unused` finding this product spent a
// release removing. If that function's bounds ever change, this must follow —
// tests/segmentation.test.js pins the two together by asserting that the window
// this function reports equals the window getDeviceLogCoverage was actually
// handed, so a drift fails the build rather than quietly mislabelling a page.
const MIN_WINDOW_DAYS = 7;
const MAX_WINDOW_DAYS = 400;

function resolveWindowDays(days) {
  const n = Number(days);
  if (!Number.isFinite(n)) return DEFAULT_WINDOW_DAYS;
  return Math.min(Math.max(Math.trunc(n), MIN_WINDOW_DAYS), MAX_WINDOW_DAYS);
}

/**
 * Validate a raw `?days=` query value.
 *
 * ⛔ LIVES HERE, NOT IN THE ROUTE, so it can be tested. A Next.js route module
 * may only export HTTP handlers, so anything exported from one for a test is a
 * build hazard — and an unvalidated boundary is exactly how `-5` reached the
 * page in the first place.
 *
 * Nonsense (`-5`, `0`, `7abc`, `1.5`) is REFUSED rather than coerced: a caller
 * who asked for something impossible should be told, not handed a plausible
 * page built over a window nobody requested. An in-range-but-clamped value
 * (`3` -> 7, `9999` -> 400) is accepted, because there the request is
 * meaningful and the honest answer is to measure what can be measured and SAY
 * which span that was.
 *
 * @returns {{ok:true, days:number|undefined} | {ok:false, error:string}}
 */
function parseWindowDaysParam(raw) {
  if (raw === null || raw === undefined || String(raw).trim() === '') {
    return { ok: true, days: undefined };
  }
  const n = Number(raw);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n <= 0) {
    return { ok: false, error: '`days` must be a positive whole number of days.' };
  }
  return { ok: true, days: n };
}

/**
 * Every zone name the fleet's rules actually reference.
 *
 * ⛔ DERIVED FROM THE RULES, not typed by the operator. A matrix axis of
 * hand-entered zone names would drift from the firewalls the moment anyone
 * renamed one, and every cell referencing the old name would silently evaluate
 * against nothing — reporting "blocked" for a zone that no longer exists.
 *
 * ⛔ `any` is excluded as an AXIS while remaining a wildcard in matching. It is
 * not a place; offering it as a row would invite an intent about nowhere.
 */
async function listFleetZones(pool) {
  const { rows } = await pool.query(
    `SELECT DISTINCT lower(trim(z)) AS zone
       FROM firewall_rules fr
       JOIN devices d ON d.id = fr.device_id,
            LATERAL jsonb_array_elements_text(
              coalesce(fr.src_zones, '[]'::jsonb) || coalesce(fr.dst_zones, '[]'::jsonb)
            ) AS z
      WHERE d.active = true
        AND trim(z) <> ''
        AND lower(trim(z)) <> 'any'
      ORDER BY 1`
  );
  return rows.map((r) => r.zone);
}

/** Declared intents, newest first. */
async function listIntents(pool) {
  const { rows } = await pool.query(
    `SELECT id, source_zone, dest_zone, expectation, note, created_by, created_at, updated_at
       FROM segmentation_intents
      ORDER BY source_zone, dest_zone`
  );
  return rows.map((r) => ({
    id: r.id,
    sourceZone: r.source_zone,
    destZone: r.dest_zone,
    expectation: r.expectation,
    note: r.note,
    createdBy: r.created_by,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  }));
}

/**
 * Every active device's rules, enriched with traffic evidence.
 *
 * ⛔ Returns `rulesCollected: false` when the fleet has no rules at all, so the
 * caller can report UNKNOWN rather than letting every deny-intent come back
 * "blocked" — a perfect segmentation score computed entirely from missing data.
 *
 * ⛔ AND IT REPORTS WHICH DEVICES ARE MISSING, not just whether ALL of them are.
 * The all-or-nothing flag above only fires when the fleet has NO rules at all.
 * With 1 of 16 devices collected it stays `true`, the other 15 are simply absent
 * from the array, and every deny-intent whose permitting rule lives on one of
 * them evaluates to "Blocked, as intended" against rules nobody has ever read.
 * `devicesWithoutRules` is what lets evaluateIntent refuse that claim. Today all
 * 16 active devices carry rules; this is the state a newly added device, or one
 * whose collection is failing, drops the fleet into.
 */
async function loadFleetRulesWithEvidence(pool, windowDays, now) {
  // ⛔ ONE resolution of the window, and the resolved value is returned — see
  // resolveWindowDays. Never re-derive it downstream.
  const days = resolveWindowDays(windowDays);
  const at = now instanceof Date ? now : new Date();

  const [{ rows }, activeDevices] = await Promise.all([
    pool.query(
      `SELECT fr.id, fr.device_id, d.name AS device_name, d.vendor,
              fr.rule_name, fr.rule_id_vendor, fr.sequence_number,
              fr.enabled, fr.action, fr.src_zones, fr.dst_zones,
              fr.hit_count, fr.log_enabled
         FROM firewall_rules fr
         JOIN devices d ON d.id = fr.device_id
        WHERE d.active = true
        ORDER BY fr.device_id, fr.sequence_number NULLS LAST`
    ),
    // The denominator. Without it "which devices are missing" cannot be asked:
    // a device with no rules produces no row in the query above, so it is
    // indistinguishable from a device that does not exist.
    pool.query('SELECT id, name FROM devices WHERE active = true'),
  ]);

  const activeRows = (activeDevices && activeDevices.rows) || [];

  if (rows.length === 0) {
    return {
      rules: [],
      rulesCollected: false,
      deviceCount: 0,
      windowDays: days,
      activeDeviceCount: activeRows.length,
      devicesWithoutRules: activeRows.map((d) => d.name || d.id),
      rulesWithUnrecognisedAction: 0,
    };
  }

  const coverageMap = await getDeviceLogCoverage(pool, days, at);

  // Per device, because getLoggedRuleHits is scoped that way and a vendor rule
  // id is only unique within one firewall.
  const byDevice = new Map();
  for (const r of rows) {
    if (!byDevice.has(r.device_id)) byDevice.set(r.device_id, []);
    byDevice.get(r.device_id).push(r);
  }

  // ⛔ THE PER-DEVICE LOOP IS AN N+1 AND IS KEPT ON PURPOSE (one
  // getLoggedRuleHits per firewall — 16 queries on the live fleet). Collapsing
  // it into one fleet-wide query would mean reimplementing what that function
  // does: excluding Fortinet's `policyid=0` implicit deny, preferring the vendor
  // rule id over the name (a name collides across VDOMs), and merging duplicate
  // identities. This file's own header says traffic evidence is not re-derived
  // here for exactly that reason — two implementations would eventually
  // disagree, and the wrong one would be the one recommending rule deletions.
  // The page-view cost was halved instead, by removing the duplicate evaluation
  // (see app/(dashboard)/segmentation/page.js). If this ever needs batching, the
  // batched query belongs in ruleHitCorrelation.js beside the logic it shares,
  // not copied in here.
  const enriched = [];
  for (const [deviceId, deviceRules] of byDevice) {
    // eslint-disable-next-line no-await-in-loop
    const hitMaps = await getLoggedRuleHits(pool, deviceId, days, at);
    const coverage = coverageMap instanceof Map ? coverageMap.get(deviceId) : null;
    enriched.push(...enrichRulesWithLogEvidence(deviceRules, coverage, hitMaps));
  }

  return {
    rules: enriched,
    rulesCollected: true,
    deviceCount: byDevice.size,
    windowDays: days,
    activeDeviceCount: activeRows.length,
    devicesWithoutRules: activeRows
      .filter((d) => !byDevice.has(d.id))
      .map((d) => d.name || d.id),
    // Surfaced as a coverage caveat rather than left to be discovered per pair:
    // a verb this engine cannot classify is a gap in SecVault's reading of the
    // rulebase, and the operator should see the fleet-wide size of it.
    rulesWithUnrecognisedAction: enriched.filter(
      (r) => r.enabled !== false && isUnrecognisedAction(r.action)
    ).length,
  };
}

/**
 * Evaluate every declared intent. The one call the page makes.
 */
async function evaluateSegmentation(pool, options) {
  const opts = options || {};

  const [intents, fleet] = await Promise.all([
    listIntents(pool),
    loadFleetRulesWithEvidence(pool, opts.windowDays, opts.now),
  ]);

  const results = intents.map((intent) =>
    evaluateIntent(intent, fleet.rules, {
      rulesCollected: fleet.rulesCollected,
      activeDeviceCount: fleet.activeDeviceCount,
      devicesWithRules: fleet.deviceCount,
      devicesWithoutRules: fleet.devicesWithoutRules,
    }));

  return {
    // ⛔ The window the evidence ACTUALLY spans, not the number the caller asked
    // for. `?days=3` reports 7 because 7 is what was measured; see
    // resolveWindowDays for why the page may not print the request instead.
    windowDays: fleet.windowDays,
    requestedWindowDays: Number.isFinite(Number(opts.windowDays))
      ? Math.trunc(Number(opts.windowDays))
      : null,
    deviceCount: fleet.deviceCount,
    activeDeviceCount: fleet.activeDeviceCount,
    devicesWithoutRules: fleet.devicesWithoutRules,
    rulesWithUnrecognisedAction: fleet.rulesWithUnrecognisedAction,
    rulesCollected: fleet.rulesCollected,
    ruleCount: fleet.rules.length,
    // ⛔ Reported so the page can say how much of its own answer rests on
    // measurable traffic. A fleet where most rules cannot report hits produces a
    // matrix full of honest unknowns, and the operator needs to know that is why.
    rulesWithoutHitData: fleet.rules.filter(
      (r) => r.effectiveHitCount === null || r.effectiveHitCount === undefined
    ).length,
    intents: results,
    summary: summarise(results),
  };
}

/** Create or update one declared intent. */
async function upsertIntent(pool, { sourceZone, destZone, expectation, note, createdBy }) {
  const src = normaliseZone(sourceZone);
  const dst = normaliseZone(destZone);

  if (!src || !dst) throw new Error('Both zones are required.');
  // ⛔ A zone cannot be segmented from itself; the cell is meaningless and would
  // match every intra-zone rule.
  if (src === dst) throw new Error('Source and destination zones must be different.');
  if (src === 'any' || dst === 'any') throw new Error('"any" is not a zone.');

  const exp = expectation === 'allow' ? 'allow' : 'deny';

  const { rows } = await pool.query(
    `INSERT INTO segmentation_intents (source_zone, dest_zone, expectation, note, created_by)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (source_zone, dest_zone) DO UPDATE
       SET expectation = EXCLUDED.expectation,
           note = EXCLUDED.note,
           updated_at = now()
     RETURNING id`,
    [src, dst, exp, note || null, createdBy || null]
  );
  return { id: rows[0].id, sourceZone: src, destZone: dst, expectation: exp };
}

async function deleteIntent(pool, id) {
  const { rowCount } = await pool.query('DELETE FROM segmentation_intents WHERE id = $1', [id]);
  return { deleted: rowCount > 0 };
}

module.exports = {
  resolveWindowDays,
  parseWindowDaysParam,
  listFleetZones,
  listIntents,
  loadFleetRulesWithEvidence,
  evaluateSegmentation,
  upsertIntent,
  deleteIntent,
  DEFAULT_WINDOW_DAYS,
};
