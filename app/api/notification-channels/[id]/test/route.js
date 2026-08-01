import { NextResponse } from 'next/server';
import { pool } from '../../../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../../../lib/rbac';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { getChannelPlaintext, recordChannelSuccess, recordChannelError } from '../../../../../lib/notificationChannels';
import { dispatchNotification } from '../../../../../lib/notify';

export const dynamic = 'force-dynamic';

// POST /api/notification-channels/[id]/test — sends a synthetic message
// through this channel immediately and reports success/failure. Deliberately
// does NOT touch notification_dispatch_log (this is a manual verification
// send, not a real alert) — without this route, verifying a new webhook URL/
// SMTP config means waiting up to NOTIFICATIONS_POLL_INTERVAL_MINUTES for a
// real alert, or manually triggering a real patch_now/compliance condition.
export async function POST(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid channel id' }, { status: 400 });
  }

  const channel = await getChannelPlaintext(params.id, pool);
  if (!channel) {
    return NextResponse.json({ error: 'Notification channel not found' }, { status: 404 });
  }

  const baseUrl = (process.env.NEXTAUTH_URL || '').replace(/\/$/, '');
  const message = {
    alertType: 'test',
    title: 'SecVault Test Notification',
    summary: `This is a test message from the "${channel.name}" notification channel. If you can see this, it's configured correctly.`,
    deviceName: null,
    url: baseUrl ? `${baseUrl}/settings` : '/settings',
  };

  try {
    await dispatchNotification(channel, message);
    await recordChannelSuccess(channel.id, pool);
    return NextResponse.json({ ok: true });
  } catch (err) {
    await recordChannelError(channel.id, err.message, pool);
    return NextResponse.json({ error: err.message || 'Test notification failed to send' }, { status: 502 });
  }
}
