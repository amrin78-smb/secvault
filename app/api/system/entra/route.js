import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import path from 'path';
import { authOptions } from '../../auth/[...nextauth]/route';
import { can, MANAGE_USERS, forbiddenResponse } from '../../../../lib/rbac';
import { setEnvValue, readEnvFile } from '../../../../lib/envFile';
import { findGitRoot } from '../../../../lib/updateCheck';
import { pool } from '../../../../lib/db';
import { logActivity } from '../../../../lib/activityLog';

export const dynamic = 'force-dynamic';

// Entra ID SSO configuration, written to .env.local. Phase 2b of
// .ai-codex/entra-sso-proposal.md.
//
// ⛔ GATED ON MANAGE_USERS, NOT MANAGE_SETTINGS — so super_admin only, and
// deliberately STRICTER than the console-address panel this is modelled on.
//
// Whoever sets the tenant decides WHICH DIRECTORY IS TRUSTED TO ISSUE
// IDENTITIES for this platform. An `admin` who could point ENTRA_TENANT_ID at
// a tenant they control, map a group they own to Super Admin, and sign in,
// would have escalated past every other guard in the product without touching
// the Users panel at all. That is the same authority as creating an account,
// which is exactly the reasoning /api/ldap-mappings already uses for the
// mappings themselves — configuring the issuer cannot be a lesser privilege
// than configuring the groups.
//
// ⛔ THE SECRET IS WRITE-ONLY AND IS NEVER RETURNED. GET reports only whether
// one is SET, the same contract `product_license_key` has via HIDDEN_KEYS: a
// value nothing needs back must not be readable back, because the only thing a
// read adds is a way to exfiltrate it.
//
// ⛔ IT LIVES IN .env.local RATHER THAN THE DATABASE, and that is forced rather
// than chosen. NextAuth builds its provider array ONCE, at module load, from
// process.env — a tenant stored in a table is not available at that moment, so
// the provider could not be registered at all. The restart this implies is
// stated in the response rather than left to be discovered.

const KEYS = ['ENTRA_TENANT_ID', 'ENTRA_CLIENT_ID', 'ENTRA_CLIENT_SECRET'];

function envPath() {
  return path.join(findGitRoot(process.cwd()) || process.cwd(), '.env.local');
}

/** A GUID, which is what both the tenant and client ids are. */
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session || !session.user) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }
  if (!can(session, MANAGE_USERS)) return forbiddenResponse(MANAGE_USERS);

  let saved = {};
  try {
    saved = readEnvFile(envPath()).values || {};
  } catch {
    // ⛔ UNREADABLE IS NOT "UNCONFIGURED". Reporting an empty form for a file
    // we could not read would invite an administrator to retype a tenant that
    // is already there, and the write would then be made against a file whose
    // current contents are unknown.
    return NextResponse.json(
      { error: 'The environment file could not be read, so the current Entra settings are unknown.' },
      { status: 500 }
    );
  }

  // ⛔ THE REFUSALS ARE THE POINT OF THIS ENDPOINT NOW, not a decoration.
  // resolveEntraRole produces a named reason for every way a sign-in can fail,
  // and until v2.211.0 all of it was stored on the token where nobody could
  // read it: an operator met "No Role" in the header and had nothing to act
  // on. Surfaced HERE, beside the settings that cause them, because that is
  // where the fix is made.
  //
  // ⛔ READ-ONLY and best-effort: a failure to list refusals must not stop the
  // settings themselves loading, or a logging problem becomes a configuration
  // outage.
  let refusals = [];
  try {
    const { rows } = await pool.query(
      `SELECT actor, detail, occurred_at
         FROM activity_log
        WHERE action = 'entra_signin_refused'
        ORDER BY occurred_at DESC
        LIMIT 5`
    );
    refusals = rows.map((r) => ({ actor: r.actor, detail: r.detail, at: r.occurred_at }));
  } catch {
    refusals = [];
  }

  const val = (k) => (saved[k] || '').trim();
  return NextResponse.json({
    refusals,
    tenantId: val('ENTRA_TENANT_ID'),
    clientId: val('ENTRA_CLIENT_ID'),
    // ⛔ NEVER the value. Only whether one exists.
    clientSecretSet: val('ENTRA_CLIENT_SECRET') !== '',
    // ⛔ SAVED vs RUNNING are different facts and the panel shows both, the
    // same rule the console-address and session-policy panels follow: the
    // process read its environment at startup, so a value saved a moment ago
    // is not yet in force.
    runningConfigured: Boolean(
      process.env.ENTRA_TENANT_ID && process.env.ENTRA_CLIENT_ID && process.env.ENTRA_CLIENT_SECRET
    ),
    // The exact string the Entra app registration must carry. Shown rather
    // than described, because a mismatch here fails on Microsoft's side with
    // an error that never reaches our logs.
    redirectUri: `${(process.env.NEXTAUTH_URL || '').replace(/\/+$/, '')}/api/auth/callback/entra`,
    consoleUrl: process.env.NEXTAUTH_URL || '',
  });
}

export async function PUT(request) {
  const session = await getServerSession(authOptions);
  if (!session || !session.user) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }
  if (!can(session, MANAGE_USERS)) return forbiddenResponse(MANAGE_USERS);

  const body = await request.json().catch(() => ({}));
  const tenantId = typeof body.tenantId === 'string' ? body.tenantId.trim() : '';
  const clientId = typeof body.clientId === 'string' ? body.clientId.trim() : '';
  // ⛔ `undefined` means LEAVE THE STORED SECRET ALONE; an empty string means
  // CLEAR IT. Collapsing those would make every save of the tenant id wipe the
  // secret, because the form cannot pre-fill a value it is never given.
  const clientSecret = typeof body.clientSecret === 'string' ? body.clientSecret : undefined;

  const disabling = tenantId === '' && clientId === '' && clientSecret === '';

  if (!disabling) {
    if (!GUID.test(tenantId)) {
      return NextResponse.json(
        { error: 'The Directory (tenant) ID must be a GUID, e.g. 8f4a1c2e-9b7d-4e6a-bc13-5d2f70a9e4c1.' },
        { status: 400 }
      );
    }
    if (!GUID.test(clientId)) {
      return NextResponse.json(
        { error: 'The Application (client) ID must be a GUID. Copy it from the app registration '
            + 'Overview page — not the Object ID, and not the secret ID.' },
        { status: 400 }
      );
    }
  }

  const file = envPath();
  const written = [];
  try {
    // ⛔ THE SECRET IS WRITTEN FIRST. setEnvValue backs up, writes and then
    // RE-VERIFIES every other key, so each call is independently safe — but if
    // one of three fails, the ones already written have landed. Writing the
    // secret first means a partial failure leaves a tenant WITHOUT a usable
    // secret, which is refused at sign-in, rather than a secret sitting beside
    // a tenant id that no longer matches it.
    if (clientSecret !== undefined) {
      setEnvValue(file, 'ENTRA_CLIENT_SECRET', clientSecret);
      written.push('ENTRA_CLIENT_SECRET');
    }
    setEnvValue(file, 'ENTRA_TENANT_ID', tenantId);
    written.push('ENTRA_TENANT_ID');
    setEnvValue(file, 'ENTRA_CLIENT_ID', clientId);
    written.push('ENTRA_CLIENT_ID');
  } catch (err) {
    return NextResponse.json(
      {
        error: 'The Entra settings could not be saved: ' + (err.message || String(err)),
        written,
      },
      { status: 500 }
    );
  }

  // ⛔ AUDITED, AND THE SECRET IS NOT IN THE AUDIT LINE EITHER. Best-effort,
  // like every other logActivity call site: a failure here must not report a
  // completed write as a failure.
  try {
    await logActivity(pool, {
      actor: (session.user && session.user.name) || 'unknown',
      action: disabling ? 'entra_sso_disabled' : 'entra_sso_configured',
      // ⛔ deviceId is OMITTED, not passed as null. logActivity defaults it to
      // null anyway, so the explicit field added nothing -- except that it made
      // this file's source mention a device identifier, which is exactly what
      // deviceScopeCoverage's raw-source scan looks for. A route that touches no
      // firewall data should not read as though it does. Same shape as
      // app/api/system/tls/route.js.
      detail: disabling
        ? 'Entra ID SSO settings cleared'
        : `Entra ID SSO configured for tenant ${tenantId}`
          + (clientSecret !== undefined ? ' (client secret replaced)' : ''),
    });
  } catch (auditErr) {
    console.warn(`[entra] activity log failed: ${auditErr.message}`);
  }

  return NextResponse.json({
    ok: true,
    disabled: disabling,
    // ⛔ ALWAYS TRUE, and said plainly. NextAuth reads its provider array once
    // at startup, so nothing here takes effect until SecVault-App restarts —
    // and an administrator who does not know that will conclude the feature is
    // broken when the sign-in button does not appear.
    restartRequired: true,
    redirectUri: `${(process.env.NEXTAUTH_URL || '').replace(/\/+$/, '')}/api/auth/callback/entra`,
  });
}
