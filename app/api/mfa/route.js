import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '../auth/[...nextauth]/route';
import { pool } from '../../../lib/db';
import QRCode from 'qrcode';
import * as mfa from '../../../lib/mfa';
import { logActivity } from '../../../lib/activityLog';

export const dynamic = 'force-dynamic';

// Self-service MFA for the SIGNED-IN user only.
//
// ⛔ NOT CAPABILITY-GATED, and that is deliberate — it is the third documented
// exception to the mutating-route rule, after "change your own password" and
// saved views. An Operator must be able to protect their own account; requiring
// an administrative capability to turn on MFA would mean the least privileged
// users are the least able to secure themselves.
//
// ⛔ EVERY HANDLER ACTS ON session.user.id AND NEVER ON A BODY PARAMETER. There
// is no user id in any request shape here. That is what stops this becoming an
// endpoint that resets someone else's second factor — the authorisation is
// structural rather than a check that could be forgotten.

function sessionUserId(session) {
  // Local accounts have a UUID with a `users` row; LDAP gives the bare username
  // and no row at all, so per-user storage cannot work for them. Callers check
  // the SHAPE of the id rather than trusting the provider name.
  const id = session && session.user && session.user.id;
  return typeof id === 'string' && /^[0-9a-f-]{36}$/i.test(id) ? id : null;
}

const LDAP_UNSUPPORTED = {
  error:
    'MFA is only available for local accounts. Directory accounts authenticate against '
    + 'your directory, which is where their MFA belongs.',
};

/** Current MFA state for the signed-in user. Never includes the secret. */
export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });

  const userId = sessionUserId(session);
  if (!userId) return NextResponse.json({ ...LDAP_UNSUPPORTED, supported: false }, { status: 200 });

  const status = await mfa.getStatus(pool, userId);
  return NextResponse.json({ supported: true, ...status });
}

/** Begin enrolment: returns the secret and otpauth URI for the QR code. */
export async function POST() {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });

  const userId = sessionUserId(session);
  if (!userId) return NextResponse.json(LDAP_UNSUPPORTED, { status: 400 });

  // ⛔ Refuse to re-issue over a CONFIRMED enrolment. Silently replacing a
  // working secret would break the authenticator the user is currently relying
  // on, with no way back except recovery codes. Disable first, deliberately.
  const existing = await mfa.getStatus(pool, userId);
  if (existing.enabled) {
    return NextResponse.json(
      { error: 'MFA is already active. Turn it off first if you want to re-enrol a new device.' },
      { status: 409 }
    );
  }

  const { secret, otpauthUri } = await mfa.startEnrolment(pool, userId, session.user.name || 'user');

  // ⛔ RENDERED SERVER-SIDE into a data: URI, the same way NetVault does it.
  // Nothing is fetched at display time, so this works on an air-gapped install
  // — the same reason the fonts are vendored rather than loaded from a CDN —
  // and the QR never enters the client bundle.
  //
  // ⛔ If rendering fails the enrolment still proceeds: the setup key below it
  // is sufficient on its own, and failing the whole request over a picture
  // would block a user from protecting their account.
  let qrDataUri = null;
  try {
    qrDataUri = await QRCode.toDataURL(otpauthUri, { width: 220, margin: 1 });
  } catch (err) {
    console.warn('[mfa route] QR render failed, falling back to the setup key:', err.message);
  }

  return NextResponse.json({ secret, otpauthUri, qrDataUri });
}

/** Confirm enrolment with a code. Returns the recovery codes ONCE. */
export async function PUT(request) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });

  const userId = sessionUserId(session);
  if (!userId) return NextResponse.json(LDAP_UNSUPPORTED, { status: 400 });

  const body = await request.json().catch(() => ({}));
  const result = await mfa.confirmEnrolment(pool, userId, body && body.code);

  if (!result.ok) {
    const message = result.reason === 'not_enrolled'
      ? 'Start enrolment before confirming.'
      : result.reason === 'already_enabled'
        ? 'MFA is already active on this account.'
        : 'That code was not correct. Check your authenticator and try again.';
    return NextResponse.json({ error: message }, { status: 400 });
  }

  try {
    await logActivity(pool, {
      actor: session.user.name || 'unknown',
      action: 'mfa_enabled',
      detail: 'Multi-factor authentication enabled for own account',
    });
  } catch (err) {
    console.warn(`[mfa route] activity log failed: ${err.message}`);
  }

  // ⛔ The only time these are ever readable. They are stored bcrypt-hashed.
  return NextResponse.json({ ok: true, recoveryCodes: result.recoveryCodes });
}

/** Turn MFA off for the signed-in user. */
export async function DELETE(request) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });

  const userId = sessionUserId(session);
  if (!userId) return NextResponse.json(LDAP_UNSUPPORTED, { status: 400 });

  const status = await mfa.getStatus(pool, userId);

  // ⛔ A user an administrator has REQUIRED to use MFA cannot switch it off for
  // themselves — otherwise the requirement is advisory. They can still re-enrol
  // a new device (disable is refused, POST after a reset is not), and a Super
  // Admin can lift the requirement.
  if (status.required) {
    return NextResponse.json(
      { error: 'An administrator requires multi-factor authentication on this account.' },
      { status: 403 }
    );
  }

  // ⛔ Prove possession before removing the factor. Without this, anyone who
  // walks up to an unlocked browser can strip MFA off the account in one click,
  // which makes the second factor worth very little.
  const body = await request.json().catch(() => ({}));
  if (status.enabled) {
    const verdict = await mfa.verifyForLogin(pool, userId, (body && body.code) || '');
    if (!verdict.ok) {
      return NextResponse.json(
        { error: 'Enter a current authenticator code to turn MFA off.' },
        { status: 400 }
      );
    }
  }

  await mfa.resetFor(pool, userId);

  try {
    await logActivity(pool, {
      actor: session.user.name || 'unknown',
      action: 'mfa_disabled',
      detail: 'Multi-factor authentication disabled for own account',
    });
  } catch (err) {
    console.warn(`[mfa route] activity log failed: ${err.message}`);
  }

  return NextResponse.json({ ok: true });
}
