import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../../lib/rbac';
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
// Auth: gated on the `admin` role via lib/rbac.js's isAdmin(session) -- a
// `viewer`-role session (or no session at all) is rejected with a 403. This
// route used to only require ANY authenticated session (no role/RBAC split
// existed anywhere in this app at the time). That has since changed: a
// `users` table + `admin`|`viewer` role now exists, and triggering a
// full application update/restart is exactly the kind of write-adjacent
// action a viewer must not be able to do -- so this route was upgraded from
// a session-only check to a real admin-role check, matching the RBAC model's
// "viewer = strictly read-only, no actions" rule used everywhere else.
export async function POST() {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
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
