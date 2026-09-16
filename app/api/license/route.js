import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { pool } from '../../../lib/db';
import { authOptions } from '../auth/[...nextauth]/route';
import { can, MANAGE_LICENSE, forbiddenResponse } from '../../../lib/rbac';
import {
  getLicenseVerdict, activateLicense, clearLicense,
} from '../../../lib/productLicenseData';

export const dynamic = 'force-dynamic';

/**
 * The current subscription state.
 *
 * ⛔ OPEN TO ANY SIGNED-IN USER, deliberately. The banner this feeds renders on
 * every page for every role, and an operator who cannot see "the subscription
 * lapses in nine days" is the person most likely to be the one still using the
 * product on day ten. It exposes the organisation's own commercial state to its
 * own staff — not a secret, and withholding it only delays the renewal.
 *
 * ⛔ THE STORED KEY IS NEVER RETURNED. Nothing needs it back — the verdict
 * carries everything the UI renders — and echoing it would put a licence key
 * into any browser session's network log for no purpose.
 */
export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session || !session.user) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }

  try {
    const v = await getLicenseVerdict(pool);
    return NextResponse.json({
      status: v.status,
      daysRemaining: v.daysRemaining,
      renewalDue: v.renewalDue,
      reason: v.reason,
      sentence: v.sentence,
      customer: v.customer,
      expiry: v.expiry,
      modules: v.modules,
      maxDevices: v.maxDevices,
      deviceCount: v.deviceCount,
      devicesRemaining: v.devicesRemaining,
      withinDeviceLimit: v.withinDeviceLimit,
      trialDaysTotal: v.trialDaysTotal,
      graceDays: v.graceDays,
      serverId: v.serverId,
      serverIdWeak: v.serverIdWeak,
      installDate: v.installDate,
      installDateDerived: v.installDateDerived,
      // ⛔ Surfaced, not swallowed. A verdict computed over a device count that
      // failed to load is a different thing from one computed over a real count,
      // and the panel says so rather than showing a confident number.
      readErrors: v.readErrors,
      canManage: can(session, MANAGE_LICENSE),
    });
  } catch (err) {
    return NextResponse.json(
      { error: 'The subscription state could not be read: ' + (err.message || String(err)) },
      { status: 500 }
    );
  }
}

/** Install a key. */
export async function POST(request) {
  const session = await getServerSession(authOptions);
  if (!session || !session.user) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }
  if (!can(session, MANAGE_LICENSE)) return forbiddenResponse(MANAGE_LICENSE);

  const body = await request.json().catch(() => ({}));
  const key = typeof body.key === 'string' ? body.key.trim() : '';
  if (!key) {
    return NextResponse.json({ error: 'A licence key is required.' }, { status: 400 });
  }

  try {
    const res = await activateLicense(pool, key);
    if (!res.ok) {
      // ⛔ 400 WITH THE SPECIFIC REASON, not a flat "invalid key". Wrong server,
      // wrong product, unreadable and expired need four different next actions
      // from the customer, and the code lets the UI say which.
      return NextResponse.json(
        { error: res.error, code: res.code, serverId: res.serverId },
        { status: 400 }
      );
    }
    const v = await getLicenseVerdict(pool, { force: true });
    return NextResponse.json({
      ok: true,
      status: v.status,
      customer: v.customer,
      expiry: v.expiry,
      maxDevices: v.maxDevices,
      deviceCount: v.deviceCount,
      sentence: v.sentence,
      // ⛔ A key can be genuine, installed, and still cover fewer firewalls than
      // are already being monitored. That is not a reason to refuse it — the
      // customer is better off licensed and over-subscribed than unlicensed —
      // but it must be said plainly at the moment of activation rather than
      // discovered the next time someone tries to add a device.
      overDeviceLimit: v.withinDeviceLimit === false,
    });
  } catch (err) {
    return NextResponse.json(
      { error: 'The licence could not be stored: ' + (err.message || String(err)) },
      { status: 500 }
    );
  }
}

/**
 * Remove the stored key.
 *
 * ⛔ EXISTS FOR THE HARDWARE-MIGRATION CASE. A key names one machine, so after a
 * move to new hardware the old key sits there reporting `invalid` forever. With
 * no way to clear it from the UI the only route back is a manual DELETE against
 * the production database, which is a support call and a chance to mistype a
 * WHERE clause on a security platform's settings table.
 */
export async function DELETE() {
  const session = await getServerSession(authOptions);
  if (!session || !session.user) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }
  if (!can(session, MANAGE_LICENSE)) return forbiddenResponse(MANAGE_LICENSE);

  try {
    await clearLicense(pool);
    const v = await getLicenseVerdict(pool, { force: true });
    return NextResponse.json({ ok: true, status: v.status, sentence: v.sentence });
  } catch (err) {
    return NextResponse.json(
      { error: 'The licence could not be removed: ' + (err.message || String(err)) },
      { status: 500 }
    );
  }
}
