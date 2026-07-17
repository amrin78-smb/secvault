import { pool } from '../../../../../lib/db';
import { isValidUuid } from '../../../../../lib/apiUtils';

export const dynamic = 'force-dynamic';

// GET /api/devices/[id]/cve
// Returns device_cve_assessments rows for one device, joined with advisories,
// ordered by priority_band (patch_now first) then cvss_score DESC.
export async function GET(request, { params }) {
  try {
    const { id } = params;

    if (!isValidUuid(id)) {
      return Response.json({ error: 'Invalid device id' }, { status: 400 });
    }

    const { rows } = await pool.query(
      `SELECT dca.*, a.cve_id, a.cvss_score, a.kev_listed AS advisory_kev_listed, a.title
       FROM device_cve_assessments dca
       JOIN advisories a ON a.id = dca.advisory_id
       WHERE dca.device_id = $1
       ORDER BY
         CASE dca.priority_band
           WHEN 'patch_now' THEN 0
           WHEN 'scheduled' THEN 1
           ELSE 2
         END,
         a.cvss_score DESC NULLS LAST`,
      [id]
    );

    return Response.json({ assessments: rows });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
