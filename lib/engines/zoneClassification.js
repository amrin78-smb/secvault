// lib/engines/zoneClassification.js
//
// Operator-provided (never auto-inferred) mapping of firewall zone names to
// a role: 'internal' | 'external' | 'dmz'. See lib/schema.sql's
// zone_classifications table comment and CLAUDE.md's "Zone Classification"
// section for the full reasoning — in short: a prior feature (the
// Compliance page's Network Details card) already tried and correctly
// rejected AUTOMATIC zone-name pattern matching, since this deployment's
// real zone names ("TFM-HQ"/"YCC"/"VRZ") aren't reliably classifiable by
// name. An explicit, admin-supplied mapping sidesteps that exact risk
// entirely, since it's a fact the operator supplies, not a guess this app
// makes.
//
// Every consumer of this data MUST treat "no row for this zone name" as
// "unclassified" — never silently assumed internal, external, or dmz. This
// is the same tri-state-honesty discipline already applied throughout this
// codebase (CVE applicability's "unknown never collapses to no", the
// compliance engine's "na when nothing is measurable").
//
// CommonJS only, matching every other lib/engines/*.js file in this
// codebase.

'use strict';

const VALID_ROLES = new Set(['internal', 'external', 'dmz']);

// Same wildcard vocabulary as ruleAnalysis.js's ANY_ALIASES /
// reachabilityMatrix.js's local copy — a literal "any"/"all"/"any4"/"any6"
// is never a real zone name to classify.
const ANY_ALIASES = new Set(['any', 'all', 'any4', 'any6']);

function normalizeZoneName(zoneName) {
  return String(zoneName || '').trim().toLowerCase();
}

/**
 * Every classified zone, as a plain lookup map -- the shape
 * ruleAnalysis.js/configAuditor.js actually consume. Zones with no row are
 * simply absent from this object; callers must treat a missing key as
 * "unclassified", never as any particular role.
 *
 * @param {import('pg').Pool} pool
 * @returns {Promise<Record<string, 'internal'|'external'|'dmz'>>}
 */
async function getZoneRoleMap(pool) {
  const { rows } = await pool.query('SELECT zone_name, role FROM zone_classifications');
  const map = {};
  for (const row of rows) map[row.zone_name] = row.role;
  return map;
}

/**
 * Every distinct REAL (non-wildcard) zone name observed anywhere across the
 * whole fleet's firewall_rules (both src_zones and dst_zones), left-joined
 * against its current classification -- the shape the Settings > Zones
 * admin UI needs to render "here's every zone we've ever seen, tell us what
 * it is". `role` is `null` for an unclassified zone, never coerced to a
 * default.
 *
 * Wrapped in try/catch, returning [] on any failure, rather than throwing --
 * this is an enrichment/listing query over a jsonb shape that varies by
 * vendor (a malformed src_zones/dst_zones on some row is a reachable, not
 * theoretical, failure mode elsewhere in this app), and a failure here must
 * not break the whole Settings page. Guarded with jsonb_typeof(...) =
 * 'array' before unnesting, same defensive pattern the Compliance page's
 * Network Details card already uses for the identical shape.
 *
 * @param {import('pg').Pool} pool
 * @returns {Promise<{zone_name: string, role: 'internal'|'external'|'dmz'|null}[]>}
 */
async function getDistinctFleetZones(pool) {
  try {
    const { rows } = await pool.query(`
      WITH zone_names AS (
        SELECT DISTINCT LOWER(TRIM(z.value)) AS zone_name
        FROM firewall_rules fr,
             LATERAL jsonb_array_elements_text(fr.src_zones) AS z(value)
        WHERE jsonb_typeof(fr.src_zones) = 'array'
        UNION
        SELECT DISTINCT LOWER(TRIM(z.value)) AS zone_name
        FROM firewall_rules fr,
             LATERAL jsonb_array_elements_text(fr.dst_zones) AS z(value)
        WHERE jsonb_typeof(fr.dst_zones) = 'array'
      )
      SELECT zn.zone_name, zc.role
      FROM zone_names zn
      LEFT JOIN zone_classifications zc ON zc.zone_name = zn.zone_name
      WHERE zn.zone_name <> '' AND zn.zone_name NOT IN ('any', 'all', 'any4', 'any6')
      ORDER BY zn.zone_name ASC
    `);
    return rows;
  } catch (err) {
    console.warn('[zoneClassification] Failed to load distinct fleet zones:', err.message);
    return [];
  }
}

/**
 * Set (create or update) one zone's role. Throws on an invalid role or an
 * empty zone name -- caller (the API route) is expected to have already
 * validated both, this is a defensive second guard, not the primary check.
 *
 * @param {string} zoneName
 * @param {'internal'|'external'|'dmz'} role
 * @param {import('pg').Pool} pool
 */
async function setZoneRole(zoneName, role, pool) {
  const normalized = normalizeZoneName(zoneName);
  if (!normalized || ANY_ALIASES.has(normalized)) {
    throw new Error('A real zone name is required.');
  }
  if (!VALID_ROLES.has(role)) {
    throw new Error(`Invalid role "${role}" — must be one of: internal, external, dmz.`);
  }
  await pool.query(
    `INSERT INTO zone_classifications (zone_name, role)
     VALUES ($1, $2)
     ON CONFLICT (zone_name) DO UPDATE SET role = EXCLUDED.role, updated_at = now()`,
    [normalized, role]
  );
}

/**
 * Revert one zone back to unclassified (delete its row, if any).
 *
 * @param {string} zoneName
 * @param {import('pg').Pool} pool
 */
async function clearZoneRole(zoneName, pool) {
  const normalized = normalizeZoneName(zoneName);
  await pool.query('DELETE FROM zone_classifications WHERE zone_name = $1', [normalized]);
}

module.exports = {
  VALID_ROLES,
  normalizeZoneName,
  getZoneRoleMap,
  getDistinctFleetZones,
  setZoneRole,
  clearZoneRole,
};
