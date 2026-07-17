// Minimal liveness probe for the frontend's post-update polling loop (the
// browser polls this after triggering POST /api/system/update to detect when
// SecVault-App has come back up). No DB dependency -- a DB hiccup during a
// service restart must not make health-polling itself throw. Stays behind
// the app's normal auth: middleware.js already gates every /api/* route, no
// exemption here.
export const dynamic = 'force-dynamic';

export async function GET() {
  return Response.json({ status: 'ok' });
}
