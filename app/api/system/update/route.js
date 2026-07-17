import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../auth/[...nextauth]/route';
import { execSync } from 'child_process';
import path from 'path';
import { pool } from '../../../../lib/db';
import { logActivity } from '../../../../lib/activityLog';
import { findGitRoot } from '../../../../lib/updateCheck';

export const dynamic = 'force-dynamic';

// POST /api/system/update
// Schedules installer/Update-SecVault.ps1 as a one-time SYSTEM scheduled task
// and kicks it off immediately, then returns { started: true } without
// waiting for the update to finish (the script stops this app's own service
// partway through). Pattern copied from netvault's app/api/system/update/route.ts.
//
// Auth: SecVault has no role/RBAC split anywhere in this app -- confirmed by
// grep across app/api for session.user.role/user.role/isAdmin: the only hits
// are in app/api/auth/[...nextauth]/route.js's jwt()/session() callbacks,
// which always set role to 'admin' (both the local-admin and LDAP authorize()
// functions hardcode role: 'admin'; there is no admin-vs-viewer distinction
// anywhere, unlike netvault's admin/super_admin gate on this same route). An
// authenticated session is therefore the same bar every other write route in
// this codebase already uses (e.g. app/api/devices/[id]/acknowledgements) --
// that's the bar here too, deliberately not a role check that doesn't exist
// elsewhere in this app.
export async function POST() {
  const session = await getServerSession(authOptions);
  if (!session) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const serverIp = process.env.SERVER_IP || '';
  if (!serverIp) {
    return Response.json({ error: 'SERVER_IP not configured in .env.local' }, { status: 400 });
  }

  const repoRoot = findGitRoot(process.cwd());
  const scriptPath = path.join(repoRoot, 'installer', 'Update-SecVault.ps1').replace(/\//g, '\\');

  try {
    try {
      execSync('schtasks /delete /tn "SecVaultUpdate" /f', { stdio: 'ignore' });
    } catch (_e) {
      // no pre-existing task -- expected on first run
    }

    // Update-SecVault.ps1 takes NO -ServerIp (or any other) parameter --
    // unlike netvault's equivalent script, it reads everything it needs from
    // the already-deployed .env.local and its own hardcoded $InstallRoot =
    // 'C:\Apps\SecVault'. SERVER_IP is still required to be set (checked
    // above, per CLAUDE.md's documented required .env.local vars) but is not
    // passed on the command line.
    execSync(
      `schtasks /create /tn "SecVaultUpdate" ` +
      `/tr "powershell.exe -NonInteractive -ExecutionPolicy Bypass ` +
      `-File \\"${scriptPath}\\"" ` +
      `/sc once /st 00:00 /f /ru SYSTEM`,
      { stdio: 'pipe' }
    );
    execSync('schtasks /run /tn "SecVaultUpdate"', { stdio: 'pipe' });
    console.log('[Update] Task scheduled under SYSTEM');
  } catch (err) {
    console.error('[Update] schtasks error:', err.message);
    return Response.json({ error: 'Failed to schedule update: ' + err.message }, { status: 500 });
  }

  // Audit logging is best-effort and must never turn a successful schedule
  // into a reported failure to the client -- same pattern as every other
  // logActivity call-site in this app (see e.g.
  // app/api/devices/[id]/acknowledgements/route.js).
  try {
    const actor = (session.user && session.user.name) || 'unknown';
    await logActivity(pool, {
      actor,
      action: 'trigger_update',
      deviceId: null,
      detail: 'Update scheduled via SYSTEM task',
    });
  } catch (auditErr) {
    console.warn(`[update route] Failed to record activity log: ${auditErr.message}`);
  }

  return Response.json({ started: true });
}
