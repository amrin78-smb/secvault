import { getServerSession } from 'next-auth/next';
import { pool } from '../../../../../lib/db';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { isAdmin, forbiddenResponse } from '../../../../../lib/rbac';
import { logActivity } from '../../../../../lib/activityLog';
import {
  getCleanupCandidates,
  createRequest,
  listRequests,
} from '../../../../../lib/engines/ruleChangeRequests';

export const dynamic = 'force-dynamic';

// Rule change requests for ONE device — the cleanup loop's write end.
//
// GET  -> { candidates: { eligible, withheld }, requests }
// POST -> create a draft request from a set of rule_id_vendor strings
//
// ⛔ GET RETURNS `withheld`, ALWAYS, AND THE UI IS EXPECTED TO SHOW IT. The
// engine refuses to offer a rule whose hit count was never measured, or which
// carries no vendor identifier that would survive the next ruleset
// DELETE+reinsert. If this route quietly dropped that half of the engine's
// answer, every consumer would render a shorter list that looks complete —
// which is the failed-read-as-a-fact bug wearing a cleanup screen. The count
// and the reasons travel with the candidates, not in a footnote.
//
// ⛔ POST is admin-gated. Unlike /api/saved-views (per-user preference) or
// /api/devices/[id]/access-path (a pure computation that persists nothing),
// this WRITES shared state that another operator will act on at the firewall.
// It is a mutation in every sense that matters, so isAdmin() applies.
//
// ⛔ There is deliberately NO endpoint here that marks a request done. A
// request becomes `verified` only because verifyRequestsForDevice() found the
// rules gone from a ruleset collected AFTER submission. See
// lib/engines/ruleChangeRequests.js's header.

// createRequest()'s guard rejections are the caller's fault, not the server's
// — an ineligible rule id, or an empty selection. They must read as 400 so the
// UI can show the engine's own sentence, which names the rules it refused and
// why. A 500 would bury that behind "Internal error".
function isClientError(message) {
  if (!message) return false;
  return (
    message.startsWith('Select at least one rule') ||
    message.startsWith('These rules cannot be included') ||
    message.startsWith('deviceId is required')
  );
}

export async function GET(request, { params }) {
  try {
    const { id } = params;
    if (!isValidUuid(id)) {
      return Response.json({ error: 'Invalid device id' }, { status: 400 });
    }
    const candidates = await getCleanupCandidates(pool, id);
    const requests = await listRequests(pool, id);
    return Response.json({ candidates, requests });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}

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

    const deviceResult = await pool.query('SELECT id, name FROM devices WHERE id = $1', [id]);
    if (deviceResult.rows.length === 0) {
      return Response.json({ error: 'Device not found' }, { status: 404 });
    }

    const body = await request.json().catch(() => ({}));
    const title = typeof body.title === 'string' && body.title.trim() !== '' ? body.title.trim() : null;
    const note = typeof body.note === 'string' && body.note.trim() !== '' ? body.note.trim() : null;
    const ruleIds = Array.isArray(body.ruleIds)
      ? body.ruleIds.filter((v) => typeof v === 'string' && v.trim() !== '').map((v) => v.trim())
      : [];

    if (ruleIds.length === 0) {
      return Response.json({ error: 'Select at least one rule' }, { status: 400 });
    }

    const createdBy = (session && session.user && session.user.name) || null;
    const created = await createRequest(pool, {
      deviceId: id,
      title,
      note,
      createdBy,
      ruleIds,
    });

    // Best-effort audit, same as every other mutating route here: a logging
    // failure must never turn a successful write into a reported failure.
    try {
      await logActivity(pool, {
        actor: createdBy || 'unknown',
        action: 'create_rule_change_request',
        deviceId: id,
        detail: `${ruleIds.length} rule(s) proposed for removal: "${created.title}"`,
      });
    } catch (auditErr) {
      console.warn(`[rule-change-requests route] Failed to record activity log: ${auditErr.message}`);
    }

    return Response.json(created, { status: 201 });
  } catch (err) {
    const status = isClientError(err.message) ? 400 : 500;
    return Response.json({ error: err.message }, { status });
  }
}
