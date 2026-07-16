import { pool } from '../../../../../lib/db';

export const dynamic = 'force-dynamic';

// Same 9 finding types lib/engines/ruleAnalysis.js emits — kept in step
// manually (no shared module exports this list as a constant today).
const FINDING_TYPES = new Set([
  'any_any',
  'risky_service',
  'shadow',
  'reorder_candidate',
  'redundant',
  'overly_permissive',
  'unused',
  'expiring_soon',
  'log_disabled',
]);

const STATUSES = new Set(['new', 'acknowledged', 'dismissed', 'actioned']);

// POST /api/devices/[id]/acknowledgements
// Upserts one finding_acknowledgements row: { rule_id_vendor, finding_type, status, note? }.
//
// Read side deliberately has no GET here — every Cleanup/Optimization/Reorder
// tab is a server component that LEFT JOINs finding_acknowledgements directly
// in its own query, the same "server components query the DB directly, API
// routes exist for client-triggered writes" convention already used
// throughout this app (see e.g. /api/devices/[id]/analysis's POST).
//
// Keyed on (device_id, rule_id_vendor, finding_type) -- NOT firewall_rules.id
// or rule_analysis_results.id, both of which are rewritten on every pull. See
// lib/schema.sql's finding_acknowledgements comment for why.
export async function POST(request, { params }) {
  try {
    const { id } = params;

    const deviceResult = await pool.query('SELECT id FROM devices WHERE id = $1', [id]);
    if (deviceResult.rows.length === 0) {
      return Response.json({ error: 'Device not found' }, { status: 404 });
    }

    const body = await request.json().catch(() => ({}));
    const ruleIdVendor = typeof body.rule_id_vendor === 'string' ? body.rule_id_vendor.trim() : '';
    const findingType = typeof body.finding_type === 'string' ? body.finding_type : '';
    const status = typeof body.status === 'string' ? body.status : '';
    const note = typeof body.note === 'string' && body.note.trim() !== '' ? body.note.trim() : null;

    if (ruleIdVendor === '') {
      return Response.json({ error: 'rule_id_vendor is required' }, { status: 400 });
    }
    if (!FINDING_TYPES.has(findingType)) {
      return Response.json(
        { error: `finding_type must be one of: ${Array.from(FINDING_TYPES).join(', ')}` },
        { status: 400 }
      );
    }
    if (!STATUSES.has(status)) {
      return Response.json(
        { error: `status must be one of: ${Array.from(STATUSES).join(', ')}` },
        { status: 400 }
      );
    }

    const { rows } = await pool.query(
      `INSERT INTO finding_acknowledgements (device_id, rule_id_vendor, finding_type, status, note)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (device_id, rule_id_vendor, finding_type) DO UPDATE SET
         status = EXCLUDED.status,
         note = EXCLUDED.note,
         updated_at = now()
       RETURNING id, device_id, rule_id_vendor, finding_type, status, note, updated_at`,
      [id, ruleIdVendor, findingType, status, note]
    );

    return Response.json(rows[0]);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
