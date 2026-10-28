import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import path from 'path';
import { authOptions } from '../../auth/[...nextauth]/route';
import { can, MANAGE_USERS, forbiddenResponse } from '../../../../lib/rbac';
import { setEnvValue, readEnvFile } from '../../../../lib/envFile';
// ⛔ THE DECISION LAYER IS A PURE, SEPARATELY TESTED MODULE, for the reason
// lib/consoleUrl.js gives about NEXTAUTH_URL and for a field that is strictly
// more dangerous than that one. This file does I/O and nothing else; every
// refusal, the write ORDER, and the saved-vs-running comparison live in
// lib/entraSettings.js, where tests/entraSettingsRoute.test.js requires them
// plainly. They used to live HERE, which is why none of them had a test:
// next-auth and next/server do not resolve under plain node.
import {
  ENTRA_KEYS,
  REFUSAL_WINDOW_DAYS,
  normaliseEntraInput,
  duplicateEntraKeys,
  planEntraWrite,
  applyEntraWrites,
  entraWriteFailureAnswer,
  entraRestartPending,
  refusalQuery,
  entraRefusalAnswer,
} from '../../../../lib/entraSettings';
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
// read adds is a way to exfiltrate it. ⛔ THAT RULE ALSO BINDS THE
// RESTART-PENDING COMPARISON: `entraRestartPending` compares the saved and
// running secrets server-side, and only the FIELD LABEL of a difference
// travels. Returning setEnvValue's `previous` the way the console-address route
// does would put the OLD SECRET in an HTTP response body — do not copy that
// route wholesale, and do not forward `previous` from this file.
//
// ⛔ IT LIVES IN .env.local RATHER THAN THE DATABASE, and that is forced rather
// than chosen. NextAuth builds its provider array ONCE, at module load, from
// process.env — a tenant stored in a table is not available at that moment, so
// the provider could not be registered at all. The restart this implies is
// stated in the response rather than left to be discovered.

function envPath() {
  return path.join(findGitRoot(process.cwd()) || process.cwd(), '.env.local');
}

// ─── handlers ───────────────────────────────────────────────────────────────

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
  // outage. It is reported as `unknown`, never as "none" — see
  // entraRefusalAnswer.
  //
  // ⛔ BOUNDED BY TIME AS WELL AS BY COUNT. `LIMIT 5` alone cannot age anything
  // out, so a problem that has been fixed stays on screen for ever.
  let refusalRows = null;
  let refusalReadFailed = false;
  try {
    const q = refusalQuery(REFUSAL_WINDOW_DAYS);
    const { rows } = await pool.query(q.text, q.values);
    refusalRows = rows.map((r) => ({ actor: r.actor, detail: r.detail, at: r.occurred_at }));
  } catch (err) {
    refusalReadFailed = true;
    console.warn(`[entra] refused sign-in list unavailable: ${err.message}`);
  }

  const val = (k) => (saved[k] || '').trim();
  const restart = entraRestartPending(saved, process.env);
  return NextResponse.json({
    ...entraRefusalAnswer(refusalRows, refusalReadFailed),
    tenantId: val('ENTRA_TENANT_ID'),
    clientId: val('ENTRA_CLIENT_ID'),
    // ⛔ NEVER the value. Only whether one exists.
    clientSecretSet: val('ENTRA_CLIENT_SECRET') !== '',
    configured: ENTRA_KEYS.every((k) => val(k) !== ''),
    // ⛔ SAVED vs RUNNING are different facts and the panel shows both, the
    // same rule the console-address and session-policy panels follow: the
    // process read its environment at startup, so a value saved a moment ago
    // is not yet in force. ⛔ COMPUTED HERE, NOT IN THE BROWSER, because the
    // comparison needs the secret and the secret may not leave the server.
    restartPending: restart.pending,
    restartPendingFields: restart.fields,
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
  const input = normaliseEntraInput(body);
  const file = envPath();

  // ⛔ THE FILE IS READ BEFORE ANYTHING IS PLANNED, and an unreadable one is
  // refused. The same rule GET follows: a write made against a file whose
  // current contents are unknown is the one thing lib/envFile.js exists to
  // prevent.
  let current;
  try {
    current = readEnvFile(file);
  } catch (err) {
    return NextResponse.json({
      error: 'The environment file could not be read, so nothing was changed. Check it on the '
        + `server before saving again (${err.message}).`,
      nothingChanged: true,
    }, { status: 500 });
  }

  // ⛔ PRE-FLIGHT, SO A REFUSAL CANNOT LAND MID-SEQUENCE. A duplicated key is
  // refused by setEnvValue per key, which would stop the off-change-on sequence
  // somewhere in the middle for a reason that was knowable before it started —
  // and it is the reproduced cause of this route's silent-success bug, because
  // following both .env.local.example and docs/ENTRA-SSO-SETUP.md duplicates
  // all three keys.
  const duplicates = duplicateEntraKeys(current.text, ENTRA_KEYS);
  if (duplicates.length > 0) {
    return NextResponse.json({
      error: `${duplicates.join(', ')} appear more than once in .env.local, so a save would have no `
        + 'reliable effect — which copy a loader honours is a property of the loader. Remove the '
        + 'duplicate lines on the server first. Nothing was changed.',
      duplicateKeys: duplicates,
      nothingChanged: true,
    }, { status: 409 });
  }

  const plan = planEntraWrite(input, {
    storedSecret: (current.values.ENTRA_CLIENT_SECRET || '').trim() !== '',
  });
  if (!plan.ok) {
    return NextResponse.json({ error: plan.error }, { status: plan.status || 400 });
  }

  // ⛔ THE RETURN VALUE IS CHECKED. See applyEntraWrites' own header for what
  // happened while it was not.
  const outcome = applyEntraWrites(plan.writes, (key, value) => setEnvValue(file, key, value));
  if (!outcome.ok) {
    const answer = entraWriteFailureAnswer(outcome);
    // ⛔ AUDITED EVEN THOUGH IT FAILED, because a part-finished change to which
    // directory is trusted to issue identities is exactly the event an audit
    // trail is for — and the failure path is the one nobody will remember.
    try {
      await logActivity(pool, {
        actor: (session.user && session.user.name) || 'unknown',
        action: 'entra_sso_write_failed',
        detail: answer.nothingChanged
          ? `Entra ID SSO save refused, nothing changed (${answer.failedField})`
          : `Entra ID SSO save failed part-way at ${answer.failedField}; single sign-on is now off. `
            + `Written: ${answer.writtenFields.join(', ')}`,
      });
    } catch (auditErr) {
      console.warn(`[entra] activity log failed: ${auditErr.message}`);
    }
    return NextResponse.json(answer, { status: 500 });
  }

  // ⛔ AUDITED, AND THE SECRET IS NOT IN THE AUDIT LINE EITHER. Best-effort,
  // like every other logActivity call site: a failure here must not report a
  // completed write as a failure.
  try {
    await logActivity(pool, {
      actor: (session.user && session.user.name) || 'unknown',
      action: plan.disabling ? 'entra_sso_disabled' : 'entra_sso_configured',
      // ⛔ deviceId is OMITTED, not passed as null. logActivity defaults it to
      // null anyway, so the explicit field added nothing -- except that it made
      // this file's source mention a device identifier, which is exactly what
      // deviceScopeCoverage's raw-source scan looks for. A route that touches no
      // firewall data should not read as though it does. Same shape as
      // app/api/system/tls/route.js.
      detail: plan.disabling
        ? 'Entra ID SSO settings cleared'
        : `Entra ID SSO configured for tenant ${input.tenantId}`
          + (plan.secretReplaced ? ' (client secret replaced)' : '')
          + (plan.secretCleared ? ' (stored client secret removed)' : ''),
    });
  } catch (auditErr) {
    console.warn(`[entra] activity log failed: ${auditErr.message}`);
  }

  return NextResponse.json({
    ok: true,
    disabled: plan.disabling,
    // Is the trio complete on disk now? ⛔ An explicitly cleared secret leaves
    // a tenant with no credential, which is a legitimate request and leaves SSO
    // off — said plainly rather than reported as a successful configure.
    configured: plan.configured,
    // ⛔ DEDUPED, because ENTRA_TENANT_ID is written TWICE by design (blanked
    // first, restored last) and a response listing it twice reads like a bug in
    // the thing it is reporting.
    written: [...new Set(outcome.landed)],
    changed: [...new Set(outcome.changed)],
    // ⛔ ALWAYS TRUE, and said plainly. NextAuth reads its provider array once
    // at startup, so nothing here takes effect until SecVault-App restarts —
    // and an administrator who does not know that will conclude the feature is
    // broken when the sign-in button does not appear.
    restartRequired: true,
    message: plan.disabling
      ? 'Entra single sign-on settings cleared. Restart SecVault-App to apply.'
      : plan.configured
        ? 'Saved. Restart SecVault-App to apply — the sign-in button appears after the restart.'
        : 'Saved, but single sign-on is OFF because no client secret is stored. Paste the secret '
          + 'value to switch it on, then restart SecVault-App.',
    redirectUri: `${(process.env.NEXTAUTH_URL || '').replace(/\/+$/, '')}/api/auth/callback/entra`,
  });
}
