import { NextResponse } from 'next/server';
import { pool } from '../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../lib/rbac';
import {
  NOTIFICATION_CHANNEL_TYPES,
  ALERT_TYPES,
  listChannels,
  createChannel,
  buildChannelPlaintext,
} from '../../../lib/notificationChannels';

export const dynamic = 'force-dynamic';

// GET /api/notification-channels — list configured channels (metadata only —
// never encrypted_data/iv). Admin-gated: same "credential-adjacent" posture
// as GET /api/credential-profiles, there is no viewer-facing use for this.
export async function GET() {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }
  try {
    const channels = await listChannels(pool);
    return NextResponse.json({ channels });
  } catch (err) {
    return NextResponse.json(
      { error: err.message || 'Failed to list notification channels' },
      { status: 500 }
    );
  }
}

// POST /api/notification-channels — create a channel. Body:
//   { name, channel_type, alert_types?, webhook_url?, smtp?: {host, port, secure, from, to, user, password} }
// alert_types defaults to all three (DB column default) when omitted.
// webhook_url is required for slack_webhook/teams_webhook/generic_webhook;
// smtp.host + smtp.to are required for email (see lib/notify.js's sendEmail).
export async function POST(request) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }

  const body = await request.json().catch(() => ({}));
  const { name, channel_type, alert_types, webhook_url, smtp } = body || {};

  const trimmedName = typeof name === 'string' ? name.trim() : '';
  if (!trimmedName) {
    return NextResponse.json({ error: 'name is required' }, { status: 400 });
  }
  if (!NOTIFICATION_CHANNEL_TYPES.includes(channel_type)) {
    return NextResponse.json(
      { error: `channel_type must be one of: ${NOTIFICATION_CHANNEL_TYPES.join(', ')}` },
      { status: 400 }
    );
  }
  let resolvedAlertTypes = ALERT_TYPES;
  if (alert_types !== undefined) {
    if (!Array.isArray(alert_types) || alert_types.some((t) => !ALERT_TYPES.includes(t)) || alert_types.length === 0) {
      return NextResponse.json(
        { error: `alert_types must be a non-empty subset of: ${ALERT_TYPES.join(', ')}` },
        { status: 400 }
      );
    }
    resolvedAlertTypes = alert_types;
  }

  const plaintext = buildChannelPlaintext(channel_type, {
    webhookUrl: webhook_url,
    smtpPassword: smtp && smtp.password,
  });
  if (plaintext === null) {
    return NextResponse.json(
      {
        error:
          channel_type === 'email'
            ? 'Missing SMTP config'
            : 'webhook_url is required for this channel type',
      },
      { status: 400 }
    );
  }
  const config = channel_type === 'email'
    ? {
        host: smtp && smtp.host,
        port: smtp && smtp.port,
        secure: !!(smtp && smtp.secure),
        from: smtp && smtp.from,
        to: smtp && smtp.to,
        user: smtp && smtp.user,
      }
    : {};
  if (channel_type === 'email' && (!config.host || !config.to)) {
    return NextResponse.json({ error: 'smtp.host and smtp.to are required for an email channel' }, { status: 400 });
  }

  try {
    const dupe = await pool.query('SELECT id FROM notification_channels WHERE name = $1', [trimmedName]);
    if (dupe.rows.length > 0) {
      return NextResponse.json({ error: 'A channel with that name already exists' }, { status: 409 });
    }
    const channel = await createChannel(
      { name: trimmedName, channelType: channel_type, alertTypes: resolvedAlertTypes, config, plaintext },
      pool
    );
    return NextResponse.json({ channel }, { status: 201 });
  } catch (err) {
    // Same race-to-409 translation as POST /api/credential-profiles.
    if (err.code === '23505') {
      return NextResponse.json({ error: 'A channel with that name already exists' }, { status: 409 });
    }
    return NextResponse.json(
      { error: err.message || 'Failed to create notification channel' },
      { status: 500 }
    );
  }
}
