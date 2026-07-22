import { pool } from '../../../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { logActivity } from '../../../../../lib/activityLog';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { isAdmin, forbiddenResponse } from '../../../../../lib/rbac';

export const dynamic = 'force-dynamic';

// Same 11 finding types lib/engines/ruleAnalysis.js emits — kept in step
// manually (no shared module exports this list as a constant today). See
// CLAUDE.md's "Rule Analysis Engine" section for the documented incident
// where 'correlation' was left out of this exact list and permanently
// 400'd every acknowledge attempt for that finding type — do not repeat
// that omission for 'generalization'.
const FINDING_TYPES = new Set([
  'any_any',
  'risky_service',
  'shadow',
  'reorder_candidate',
  'redundant',
  'correlation',
  'overly_permissive',
  'unused',
  'expiring_soon',
  'log_disabled',
  'generalization',
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

    if (!isValidUuid(id)) {
      return Response.json({ error: 'Invalid device id' }, { status: 400 });
    }

    const session = await getServerSession(authOptions);
    if (!isAdmin(session)) {
      return forbiddenResponse();
    }

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

    // Audit logging is best-effort and must never turn a successful
    // acknowledge into a reported failure to the client — see the identical
    // reasoning in app/api/devices/[id]/analysis/route.js.
    try {
      const actor = (session && session.user && session.user.name) || 'unknown';
      await logActivity(pool, {
        actor,
        action: 'acknowledge_finding',
        deviceId: id,
        detail: `${findingType} on rule "${ruleIdVendor}" → ${status}`,
      });
    } catch (auditErr) {
      console.warn(`[acknowledgements route] Failed to record activity log: ${auditErr.message}`);
    }

    return Response.json(rows[0]);
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
