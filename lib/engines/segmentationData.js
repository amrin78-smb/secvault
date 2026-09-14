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
const { evaluateIntent, summarise, normaliseZone } = require('./segmentation');

const DEFAULT_WINDOW_DAYS = 30;

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
 */
async function loadFleetRulesWithEvidence(pool, windowDays, now) {
  const days = Number.isFinite(windowDays) && windowDays > 0 ? windowDays : DEFAULT_WINDOW_DAYS;
  const at = now instanceof Date ? now : new Date();

  const { rows } = await pool.query(
    `SELECT fr.id, fr.device_id, d.name AS device_name, d.vendor,
            fr.rule_name, fr.rule_id_vendor, fr.sequence_number,
            fr.enabled, fr.action, fr.src_zones, fr.dst_zones,
            fr.hit_count, fr.log_enabled
       FROM firewall_rules fr
       JOIN devices d ON d.id = fr.device_id
      WHERE d.active = true
      ORDER BY fr.device_id, fr.sequence_number NULLS LAST`
  );

  if (rows.length === 0) return { rules: [], rulesCollected: false, deviceCount: 0 };

  const coverageMap = await getDeviceLogCoverage(pool, days, at);

  // Per device, because getLoggedRuleHits is scoped that way and a vendor rule
  // id is only unique within one firewall.
  const byDevice = new Map();
  for (const r of rows) {
    if (!byDevice.has(r.device_id)) byDevice.set(r.device_id, []);
    byDevice.get(r.device_id).push(r);
  }

  const enriched = [];
  for (const [deviceId, deviceRules] of byDevice) {
    // eslint-disable-next-line no-await-in-loop
    const hitMaps = await getLoggedRuleHits(pool, deviceId, days, at);
    const coverage = coverageMap instanceof Map ? coverageMap.get(deviceId) : null;
    enriched.push(...enrichRulesWithLogEvidence(deviceRules, coverage, hitMaps));
  }

  return { rules: enriched, rulesCollected: true, deviceCount: byDevice.size };
}

/**
 * Evaluate every declared intent. The one call the page makes.
 */
async function evaluateSegmentation(pool, options) {
  const opts = options || {};
  const days = opts.windowDays || DEFAULT_WINDOW_DAYS;

  const [intents, fleet] = await Promise.all([
    listIntents(pool),
    loadFleetRulesWithEvidence(pool, days, opts.now),
  ]);

  const results = intents.map((intent) =>
    evaluateIntent(intent, fleet.rules, { rulesCollected: fleet.rulesCollected }));

  return {
    windowDays: days,
    deviceCount: fleet.deviceCount,
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
  listFleetZones,
  listIntents,
  loadFleetRulesWithEvidence,
  evaluateSegmentation,
  upsertIntent,
  deleteIntent,
  DEFAULT_WINDOW_DAYS,
};
