import { pool } from '../../../../../../lib/db';

export const dynamic = 'force-dynamic';

const PREDICATE_TYPES = [
  'config_key_exists',
  'config_value_equals',
  'config_value_matches',
  'feature_enabled',
  'port_exposed',
  'admin_access_from_zone',
];

// Resolves the [cveId] route param (a CVE string) to the advisory row.
async function getAdvisoryByCveId(cveId) {
  const { rows } = await pool.query(
    `SELECT id, cve_id, title, vendor FROM advisories WHERE cve_id = $1`,
    [cveId]
  );
  return rows[0] || null;
}

// PUT /api/advisories/[cveId]/conditions/[conditionId]
// Updates any of: condition_description, predicate_type, predicate_config.
// Only fields present in the body are updated.
export async function PUT(request, { params }) {
  try {
    const { cveId, conditionId } = params;

    const advisory = await getAdvisoryByCveId(cveId);
    if (!advisory) {
      return Response.json({ error: 'Advisory not found' }, { status: 404 });
    }

    const body = (await request.json()) || {};

    const sets = [];
    const values = [];

    if (body.condition_description !== undefined) {
      values.push(body.condition_description || null);
      sets.push(`condition_description = $${values.length}`);
    }

    if (body.predicate_type !== undefined) {
      if (!PREDICATE_TYPES.includes(body.predicate_type)) {
        return Response.json(
          { error: `predicate_type must be one of: ${PREDICATE_TYPES.join(', ')}` },
          { status: 400 }
        );
      }
      values.push(body.predicate_type);
      sets.push(`predicate_type = $${values.length}`);
    }

    if (body.predicate_config !== undefined) {
      if (
        !body.predicate_config ||
        typeof body.predicate_config !== 'object' ||
        Array.isArray(body.predicate_config)
      ) {
        return Response.json({ error: 'predicate_config must be an object' }, { status: 400 });
      }
      values.push(JSON.stringify(body.predicate_config));
      sets.push(`predicate_config = $${values.length}`);
    }

    if (sets.length === 0) {
      return Response.json({ error: 'No updatable fields provided' }, { status: 400 });
    }

    values.push(conditionId);
    const idIdx = values.length;
    values.push(advisory.id);
    const advisoryIdIdx = values.length;

    const { rows } = await pool.query(
      `UPDATE advisory_conditions
       SET ${sets.join(', ')}
       WHERE id = $${idIdx} AND advisory_id = $${advisoryIdIdx}
       RETURNING *`,
      values
    );

    if (rows.length === 0) {
      return Response.json({ error: 'Condition not found' }, { status: 404 });
    }

    return Response.json(rows[0]);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}

// DELETE /api/advisories/[cveId]/conditions/[conditionId]
export async function DELETE(request, { params }) {
  try {
    const { cveId, conditionId } = params;

    const advisory = await getAdvisoryByCveId(cveId);
    if (!advisory) {
      return Response.json({ error: 'Advisory not found' }, { status: 404 });
    }

    const { rows } = await pool.query(
      `DELETE FROM advisory_conditions
       WHERE id = $1 AND advisory_id = $2
       RETURNING id`,
      [conditionId, advisory.id]
    );

    if (rows.length === 0) {
      return Response.json({ error: 'Condition not found' }, { status: 404 });
    }

    return Response.json({ ok: true, id: rows[0].id });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
