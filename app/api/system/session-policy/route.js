import fs from 'node:fs';
import path from 'node:path';
import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '../../auth/[...nextauth]/route';
import { can, forbiddenResponse, MANAGE_SETTINGS } from '../../../../lib/rbac';
import {
  clientPolicy, idleMinutes, validateIdleMinutes, MIN_IDLE_MINUTES, MAX_IDLE_MINUTES,
} from '../../../../lib/sessionPolicy';
import { setEnvValue, readEnvFile } from '../../../../lib/envFile';
import { findGitRoot } from '../../../../lib/updateCheck';

// Reads and writes .env.local, so it can never be prerendered.
export const dynamic = 'force-dynamic';

// The sign-out-after-inactivity policy.
//
// ⛔ GET IS OPEN TO ANY SIGNED-IN USER, AND HAS TO BE. The browser arms its own
// warning from this, so an operator who cannot read it gets signed out with no
// notice — the one outcome the modal exists to prevent. It returns the window
// and nothing else: no paths, no file contents, no other environment value.
//
// ⛔ PUT IS `manage_settings`. Lengthening the window is a security decision and
// shortening it is an availability one, so it sits with whoever already decides
// how the console behaves.

function envPath() {
  const root = findGitRoot() || process.cwd();
  return path.join(root, '.env.local');
}

export async function GET() {
  const session = await getServerSession(authOptions);
  // ⛔ Not a capability check — any authenticated session may read its own
  // timeout. An unauthenticated caller gets nothing, because the value is a
  // small disclosure about how the console is configured.
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  return NextResponse.json(clientPolicy(process.env));
}

export async function PUT(request) {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_SETTINGS)) return forbiddenResponse(MANAGE_SETTINGS);

  const body = await request.json().catch(() => ({}));
  const verdict = validateIdleMinutes(body.idleMinutes);
  if (!verdict.ok) {
    return NextResponse.json({ error: verdict.error }, { status: 400 });
  }

  const file = envPath();
  try {
    fs.accessSync(file, fs.constants.W_OK);
  } catch {
    return NextResponse.json({
      error: 'The configuration file could not be written. Set SESSION_IDLE_MINUTES in .env.local '
        + 'on the server and restart the SecVault-App service.',
    }, { status: 500 });
  }

  // ⛔ setEnvValue RETURNS {ok:false, error}; IT DOES NOT THROW for any of its
  // real failure modes. An earlier version of this route wrapped it in
  // try/catch and never inspected the return value, so a REFUSED write — a
  // duplicated key, an unreadable file, a failed backup — fell through to an
  // HTTP 200 saying "Saved. Restart the service." An administrator would then
  // restart believing a security control was in force when the write had been
  // declined. The sibling console-url route gets this right; this now matches it.
  let result;
  try {
    result = setEnvValue(file, 'SESSION_IDLE_MINUTES', String(verdict.value));
  } catch (err) {
    // ⛔ The message can carry the absolute path to .env.local, so it is not
    // echoed. The caller already knows where the file is; a stack trace in a
    // settings panel is a disclosure for no benefit.
    return NextResponse.json({ error: 'Could not save the timeout.' }, { status: 500 });
  }
  if (!result || !result.ok) {
    return NextResponse.json({
      error: (result && result.error) || 'Could not save the timeout.',
      backupPath: (result && result.backupPath) || null,
    }, { status: 500 });
  }

  // ⛔ THE RUNNING VALUE AND THE SAVED VALUE ARE REPORTED SEPARATELY. NextAuth
  // reads its session options ONCE, at startup, so this change does nothing at
  // all until the service restarts — and a settings page that showed the new
  // number as though it were in force would be stating a security control the
  // product is not applying. Same rule the console-address panel follows.
  const running = idleMinutes(process.env);
  let saved = verdict.value;
  try {
    const { values } = readEnvFile(file);
    saved = Number(values.SESSION_IDLE_MINUTES);
  } catch { /* the write already succeeded; reporting it back is best-effort */ }

  return NextResponse.json({
    ok: true,
    saved,
    previous: result.previous ?? null,
    unchanged: Boolean(result.unchanged),
    backupPath: result.backupPath || null,
    running,
    restartRequired: running !== verdict.value,
    disabled: verdict.disabled,
    limits: { min: MIN_IDLE_MINUTES, max: MAX_IDLE_MINUTES },
    message: running === verdict.value
      ? 'Saved. This is already the value in force.'
      : 'Saved. Restart the SecVault-App service for it to take effect — until then sessions still '
        + `use the previous window${running === 0 ? ' (no timeout)' : ` of ${running} minutes`}.`,
  });
}
