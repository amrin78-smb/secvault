import { pool } from '../../../../../../lib/db';
import {
  getLatestConfigParsed,
  evaluateConditionsDetailed,
} from '../../../../../../lib/engines/applicability';

export const dynamic = 'force-dynamic';

// POST /api/advisories/[cveId]/conditions/test
// Dry-runs this advisory's conditions against one device's latest parsed config.
// Body: { device_id }
export async function POST(request, { params }) {
  try {
    const { cveId } = params;

    let body = {};
    try {
      body = await request.json();
    } catch {
      // Falls through to the device_id check below.
    }
    const deviceId = body && body.device_id;

    if (!deviceId) {
      return Response.json({ error: 'device_id is required' }, { status: 400 });
    }

    const advisoryResult = await pool.query(
      `SELECT id, cve_id, title, vendor FROM advisories WHERE cve_id = $1`,
      [cveId]
    );
    const advisory = advisoryResult.rows[0];
    if (!advisory) {
      return Response.json({ error: 'Advisory not found' }, { status: 404 });
    }

    const { rows: conditions } = await pool.query(
      `SELECT * FROM advisory_conditions
       WHERE advisory_id = $1
       ORDER BY created_at ASC`,
      [advisory.id]
    );

    const configParsed = await getLatestConfigParsed(deviceId, pool);
    if (!configParsed) {
      return Response.json({
        config_applies: 'unknown',
        per_condition: [],
        note: 'No config collected for this device yet',
      });
    }

    const result = evaluateConditionsDetailed(conditions, configParsed);
    return Response.json(result);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
