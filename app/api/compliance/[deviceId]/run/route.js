import { pool } from '../../../../../lib/db';
import { runComplianceAuditForDevice } from '../../../../../lib/engines/configAuditor';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { logActivity } from '../../../../../lib/activityLog';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { isAdmin, forbiddenResponse } from '../../../../../lib/rbac';

export const dynamic = 'force-dynamic';

// POST /api/compliance/[deviceId]/run
// Re-runs the compliance audit for this device on demand (no body).
export async function POST(request, { params }) {
  try {
    const { deviceId } = params;

    if (!isValidUuid(deviceId)) {
      return Response.json({ error: 'Invalid device id' }, { status: 400 });
    }

    const session = await getServerSession(authOptions);
    if (!isAdmin(session)) {
      return forbiddenResponse();
    }

    let result;
    try {
      result = await runComplianceAuditForDevice(deviceId, pool);
    } catch (err) {
      // runComplianceAuditForDevice throws a clear "Device not found: ..."
      // error when the device row doesn't exist — surface that as a 404
      // rather than a generic 500, same convention as the other device-
      // scoped routes in this app.
      if (/^Device not found/.test(err.message)) {
        return Response.json({ error: 'Device not found' }, { status: 404 });
      }
      throw err;
    }

    // Audit logging is best-effort and must never turn a successful run into
    // a reported failure to the client — same idiom as
    // app/api/devices/[id]/analysis/route.js and
    // app/api/devices/[id]/acknowledgements/route.js.
    try {
      const actor = (session && session.user && session.user.name) || 'unknown';
      await logActivity(pool, {
        actor,
        action: 'run_compliance_audit',
        deviceId,
        detail: `${result.findings.length} checks evaluated`,
      });
    } catch (auditErr) {
      console.warn(`[compliance run route] Failed to record activity log: ${auditErr.message}`);
    }

    return Response.json({
      deviceId,
      ranAt: new Date().toISOString(),
      findings: result.findings.map((f) => ({
        id: f.id,
        checkId: f.check_id,
        checkSlug: f.check_id_slug,
        name: f.name,
        severity: f.severity,
        standards: f.standards,
        status: f.status,
        detail: f.detail,
        remediationGuidance: f.remediation_guidance,
        detectedAt: f.detected_at,
      })),
    });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
