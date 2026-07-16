import { pool } from '../../../lib/db';

export const dynamic = 'force-dynamic';

// GET /api/search?q=... — powers the header search dropdown. Small ILIKE
// lookups against devices + advisories, same shape as the existing list
// pages' own filters (app/(dashboard)/devices/page.js, .../advisories/page.js).
export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const q = (searchParams.get('q') || '').trim();

    if (q.length < 2) {
      return Response.json({ devices: [], advisories: [] });
    }

    const like = `%${q}%`;

    const [devicesResult, advisoriesResult] = await Promise.all([
      pool.query(
        `SELECT id, name, vendor, site
         FROM devices
         WHERE name ILIKE $1 OR vendor ILIKE $1 OR site ILIKE $1 OR mgmt_ip ILIKE $1
         ORDER BY name ASC
         LIMIT 6`,
        [like]
      ),
      pool.query(
        `SELECT cve_id, title, vendor, cvss_score, kev_listed
         FROM advisories
         WHERE cve_id ILIKE $1 OR title ILIKE $1
         ORDER BY cvss_score DESC NULLS LAST
         LIMIT 6`,
        [like]
      ),
    ]);

    return Response.json({
      devices: devicesResult.rows,
      advisories: advisoriesResult.rows,
    });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
