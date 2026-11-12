import { getServerSession } from 'next-auth/next';
import { pool } from '../../../../../lib/db';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { can, OPERATE, forbiddenResponse } from '../../../../../lib/rbac';
import { logActivity } from '../../../../../lib/activityLog';
import {
  getCleanupCandidates,
  createRequest,
  listRequests,
  REQUEST_TYPES,
  DELETION_TYPE,
} from '../../../../../lib/engines/ruleChangeRequests';

export const dynamic = 'force-dynamic';

// Rule change requests for ONE device — the cleanup loop's write end.
//
// GET  -> { candidates: { eligible, withheld }, requests }
// POST -> create a draft request:
//           { ruleIds: [...] }                       rule_deletion (the default)
//           { requestType, items: [{subject, requestedChange}] }   every other kind
//           { requiresApproval: true }               -> approval_state 'pending'
//
// ⛔ A REQUEST WITH NO `requestType` IS A DELETION, because that is the only
// kind this route could build before v2.225.0 and every existing caller posts
// exactly that. ⛔ `requiresApproval` must be STRICTLY true: an absent or
// unparseable value means no approval step, the same asymmetry schema.sql's
// `not_required` default encodes, so a malformed body can never strand a
// request in a state nobody is watching for.
//
// ⛔ THE DELETION PATH IS UNCHANGED, INCLUDING ITS REFUSALS. The
// unmeasured-hit_count guard applies to `rule_deletion` ONLY — it exists
// because "we cannot tell whether this rule is used" is not a reason to DELETE
// it, which is meaningless for an addition. It is NOT relaxed for deletions,
// and the engine, not this route, is where that is enforced.
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
// It is a mutation in every sense that matters, so the OPERATE capability
//
// ⛔ There is deliberately NO endpoint here that marks a request done. A
// request becomes `verified` only because verifyRequestsForDevice() found the
// rules gone from a ruleset collected AFTER submission. See
// lib/engines/ruleChangeRequests.js's header.

// createRequest()'s guard rejections are the caller's fault, not the server's
// — an ineligible rule id, or an empty selection. They must read as 400 so the
// UI can show the engine's own sentence, which names the rules it refused and
// why. A 500 would bury that behind "Internal error".
//
// ⛔ EVERY NEW ENGINE REFUSAL NEEDS AN ENTRY HERE, or it ships as a 500 and the
// operator sees "Internal error" for a request they could have fixed in ten
// seconds. The list is prefixes/patterns rather than error classes because the
// engine is dependency-free CommonJS and throws plain Errors.
const CLIENT_ERROR_PATTERNS = [
  /^Select at least one rule/,
  /^These rules cannot be included/,
  /^deviceId is required/,
  /^Unknown request type/,
  /^Add at least one item/,
  /^Every item needs a subject/,
  /has no requested change/,
  /appears twice in this request/,
  /^An approval-gated request needs a named requester/,
];

function isClientError(message) {
  if (!message) return false;
  return CLIENT_ERROR_PATTERNS.some((re) => re.test(message));
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
    if (!can(session, OPERATE)) {
      return forbiddenResponse(OPERATE);
    }

    const deviceResult = await pool.query('SELECT id, name FROM devices WHERE id = $1', [id]);
    if (deviceResult.rows.length === 0) {
      return Response.json({ error: 'Device not found' }, { status: 404 });
    }

    const body = await request.json().catch(() => ({}));
    const title = typeof body.title === 'string' && body.title.trim() !== '' ? body.title.trim() : null;
    const note = typeof body.note === 'string' && body.note.trim() !== '' ? body.note.trim() : null;

    // ⛔ ABSENT MEANS `rule_deletion`, WHICH IS THE BEHAVIOUR THIS ROUTE HAS
    // ALWAYS HAD. Every existing caller posts `ruleIds` and no type; reading
    // that as anything else would silently refile their cleanup requests.
    const requestType = typeof body.requestType === 'string' && body.requestType.trim() !== ''
      ? body.requestType.trim()
      : DELETION_TYPE;
    if (!REQUEST_TYPES.includes(requestType)) {
      return Response.json({ error: `Unknown request type "${requestType}"` }, { status: 400 });
    }

    // ⛔ STRICT TRUE. A missing/garbage value means NO approval step — the same
    // asymmetry the schema's `not_required` default encodes. `Boolean(body.x)`
    // would turn the string "false" into a request nobody can submit.
    const requiresApproval = body.requiresApproval === true;

    const ruleIds = Array.isArray(body.ruleIds)
      ? body.ruleIds.filter((v) => typeof v === 'string' && v.trim() !== '').map((v) => v.trim())
      : [];

    // Non-deletion items: {subject, requestedChange}. The engine does the real
    // validation (and is the guarantee); this only shapes the input.
    const items = Array.isArray(body.items)
      ? body.items
        .filter((v) => v && typeof v === 'object')
        .map((v) => ({
          subject: typeof v.subject === 'string' ? v.subject.trim() : '',
          requestedChange: typeof v.requestedChange === 'string' ? v.requestedChange.trim() : '',
        }))
      : [];

    if (requestType === DELETION_TYPE && ruleIds.length === 0) {
      return Response.json({ error: 'Select at least one rule' }, { status: 400 });
    }
    if (requestType !== DELETION_TYPE && items.length === 0) {
      return Response.json({ error: 'Add at least one item to the request' }, { status: 400 });
    }

    // ⛔ FROM THE SESSION, NEVER FROM THE BODY — the call
    // compliance_exceptions.accepted_by already makes. It is also the value the
    // self-approval refusal compares against, so a body-supplied name would let
    // a requester approve their own change by typing somebody else's.
    const createdBy = (session && session.user && session.user.name) || null;
    const created = await createRequest(pool, {
      deviceId: id,
      title,
      note,
      createdBy,
      ruleIds,
      requestType,
      items,
      requiresApproval,
    });

    const itemCount = requestType === DELETION_TYPE ? ruleIds.length : items.length;

    // Best-effort audit, same as every other mutating route here: a logging
    // failure must never turn a successful write into a reported failure.
    try {
      await logActivity(pool, {
        actor: createdBy || 'unknown',
        action: 'create_rule_change_request',
        deviceId: id,
        detail: `${requestType}: ${itemCount} item(s) in "${created.title}"`
          + (requiresApproval ? ' (awaiting approval)' : ''),
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
