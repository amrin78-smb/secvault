import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../../../lib/rbac';
import { pool } from '../../../../../lib/db';

export const dynamic = 'force-dynamic';

const PREDICATE_TYPES = [
  'config_key_exists',
  'config_value_equals',
  'config_value_matches',
  'feature_enabled',
  'port_exposed',
  'admin_access_from_zone',
];

// Resolves the [cveId] route param (a CVE string, e.g. CVE-2024-1234) to the
// advisory row. Returns null if no such advisory exists.
async function getAdvisoryByCveId(cveId) {
  const { rows } = await pool.query(
    `SELECT id, cve_id, title, vendor FROM advisories WHERE cve_id = $1`,
    [cveId]
  );
  return rows[0] || null;
}

// GET /api/advisories/[cveId]/conditions
// Lists the applicability conditions (curated data) attached to one advisory.
export async function GET(request, { params }) {
  try {
    const { cveId } = params;

    const advisory = await getAdvisoryByCveId(cveId);
    if (!advisory) {
      return Response.json({ error: 'Advisory not found' }, { status: 404 });
    }

    const { rows } = await pool.query(
      `SELECT * FROM advisory_conditions
       WHERE advisory_id = $1
       ORDER BY created_at ASC`,
      [advisory.id]
    );

    return Response.json({ advisory, conditions: rows });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}

// POST /api/advisories/[cveId]/conditions
// Adds a new applicability condition to an advisory.
// Body: { condition_description, predicate_type, predicate_config }
export async function POST(request, { params }) {
  try {
    const session = await getServerSession(authOptions);
    if (!isAdmin(session)) {
      return forbiddenResponse();
    }

    const { cveId } = params;

    const advisory = await getAdvisoryByCveId(cveId);
    if (!advisory) {
      return Response.json({ error: 'Advisory not found' }, { status: 404 });
    }

    const body = await request.json();
    const { condition_description, predicate_type, predicate_config } = body || {};

    if (!PREDICATE_TYPES.includes(predicate_type)) {
      return Response.json(
        { error: `predicate_type must be one of: ${PREDICATE_TYPES.join(', ')}` },
        { status: 400 }
      );
    }

    if (
      !predicate_config ||
      typeof predicate_config !== 'object' ||
      Array.isArray(predicate_config)
    ) {
      return Response.json({ error: 'predicate_config must be an object' }, { status: 400 });
    }

    const { rows } = await pool.query(
      `INSERT INTO advisory_conditions
         (advisory_id, vendor, condition_description, predicate_type, predicate_config)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [
        advisory.id,
        advisory.vendor,
        condition_description || null,
        predicate_type,
        JSON.stringify(predicate_config),
      ]
    );

    return Response.json(rows[0], { status: 201 });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
