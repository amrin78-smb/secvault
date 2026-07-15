import { pool } from '../../../../lib/db';

export const dynamic = 'force-dynamic';

// cvss_band -> [min, max) score range. max === null means no upper bound.
const CVSS_BANDS = {
  critical: [9.0, null],
  high: [7.0, 9.0],
  medium: [4.0, 7.0],
  low: [0, 4.0],
};

const PRIORITY_RANK = { patch_now: 3, scheduled: 2, monitor: 1 };
const RANK_LABEL = { 3: 'patch_now', 2: 'scheduled', 1: 'monitor' };

// GET /api/cve/fleet
// Query params (all optional, applied as parameterized WHERE/HAVING clauses):
//   priority_band = patch_now | scheduled | monitor  (fleet-level band, post-aggregation)
//   kev_only      = true | 1
//   cvss_band     = critical | high | medium | low
//   vendor        = <vendor string>
export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const priorityBand = searchParams.get('priority_band');
    const kevOnly = searchParams.get('kev_only');
    const cvssBand = searchParams.get('cvss_band');
    const vendor = searchParams.get('vendor');

    // Every filter value is bound as a $N param -- never string-interpolated.
    const params = [];
    const whereConditions = ['dca.version_affected = true'];
    const havingConditions = [];

    if (kevOnly === 'true' || kevOnly === '1') {
      params.push(true);
      whereConditions.push(`a.kev_listed = $${params.length}`);
    }

    if (vendor) {
      params.push(vendor);
      whereConditions.push(`a.vendor = $${params.length}`);
    }

    if (cvssBand && CVSS_BANDS[cvssBand]) {
      const [min, max] = CVSS_BANDS[cvssBand];
      params.push(min);
      whereConditions.push(`a.cvss_score >= $${params.length}`);
      if (max !== null) {
        params.push(max);
        whereConditions.push(`a.cvss_score < $${params.length}`);
      }
    }

    // priority_band is a fleet-level (post-aggregation) value: the highest
    // priority_band across all devices assessed against this CVE. This is an
    // equality comparison against a known enum-like value, bound as a param
    // (no whitelist needed -- whitelisting only matters for identifiers like
    // column/direction names, not for bound WHERE/HAVING values).
    if (priorityBand && PRIORITY_RANK[priorityBand]) {
      params.push(PRIORITY_RANK[priorityBand]);
      havingConditions.push(
        `MAX(CASE dca.priority_band WHEN 'patch_now' THEN 3 WHEN 'scheduled' THEN 2 ELSE 1 END) = $${params.length}`
      );
    }

    const query = `
      SELECT a.cve_id, a.cvss_score, a.kev_listed, a.vendor,
             COUNT(DISTINCT dca.device_id) AS affected_device_count,
             MAX(CASE dca.priority_band WHEN 'patch_now' THEN 3 WHEN 'scheduled' THEN 2 ELSE 1 END) AS priority_rank,
             MIN(dca.fixed_in) AS fixed_in,
             BOOL_OR(dca.is_fixed_recommended) AS is_fixed_recommended
      FROM device_cve_assessments dca
      JOIN advisories a ON a.id = dca.advisory_id
      WHERE ${whereConditions.join(' AND ')}
      GROUP BY a.id
      ${havingConditions.length ? `HAVING ${havingConditions.join(' AND ')}` : ''}
      ORDER BY priority_rank DESC, a.cvss_score DESC NULLS LAST
    `;

    const { rows } = await pool.query(query, params);

    const cves = rows.map((row) => ({
      cve_id: row.cve_id,
      cvss_score: row.cvss_score,
      kev_listed: row.kev_listed,
      vendor: row.vendor,
      affected_device_count: Number(row.affected_device_count),
      priority_band: RANK_LABEL[row.priority_rank] || 'monitor',
      fixed_in: row.fixed_in,
      is_fixed_recommended: row.is_fixed_recommended,
    }));

    // Fleet-wide summary: counts of distinct advisories by priority_band
    // (unfiltered -- an overall fleet posture snapshot).
    const { rows: summaryRows } = await pool.query(
      `SELECT priority_band, COUNT(DISTINCT advisory_id) AS count
       FROM device_cve_assessments
       GROUP BY priority_band`
    );

    const summary_by_priority_band = summaryRows.map((r) => ({
      priority_band: r.priority_band,
      count: Number(r.count),
    }));

    return Response.json({
      total_unique_cves: cves.length,
      summary_by_priority_band,
      cves,
    });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
