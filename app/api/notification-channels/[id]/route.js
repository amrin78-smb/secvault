import { NextResponse } from 'next/server';
import { pool } from '../../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../../lib/rbac';
import { isValidUuid } from '../../../../lib/apiUtils';
import {
  ALERT_TYPES,
  getChannelMeta,
  updateChannel,
  deleteChannel,
  buildChannelPlaintext,
} from '../../../../lib/notificationChannels';

export const dynamic = 'force-dynamic';

// PUT /api/notification-channels/[id] — rename/enable-disable/reroute/rotate.
// Body: { name?, enabled?, alert_types?, webhook_url?, smtp? }. Every field
// optional (undefined = leave alone) — same partial-update contract as PUT
// /api/credential-profiles/[id]. channel_type is immutable (a shape change
// means creating a new channel, same reasoning as credential_type there).
export async function PUT(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid channel id' }, { status: 400 });
  }

  const existing = await getChannelMeta(params.id, pool);
  if (!existing) {
    return NextResponse.json({ error: 'Notification channel not found' }, { status: 404 });
  }

  const body = await request.json().catch(() => ({}));
  const { name, enabled, alert_types, webhook_url, smtp } = body || {};

  const trimmedName = typeof name === 'string' ? name.trim() : undefined;
  if (trimmedName !== undefined && !trimmedName) {
    return NextResponse.json({ error: 'name cannot be empty' }, { status: 400 });
  }

  let resolvedAlertTypes;
  if (alert_types !== undefined) {
    if (!Array.isArray(alert_types) || alert_types.some((t) => !ALERT_TYPES.includes(t)) || alert_types.length === 0) {
      return NextResponse.json(
        { error: `alert_types must be a non-empty subset of: ${ALERT_TYPES.join(', ')}` },
        { status: 400 }
      );
    }
    resolvedAlertTypes = alert_types;
  }

  const rotating = Boolean(webhook_url || (smtp && (smtp.password !== undefined || smtp.host)));
  let plaintext;
  let config;
  if (rotating) {
    plaintext = buildChannelPlaintext(existing.channel_type, {
      webhookUrl: webhook_url,
      smtpPassword: smtp && smtp.password,
    });
    if (plaintext === null) {
      return NextResponse.json({ error: 'No usable secret provided for this channel type' }, { status: 400 });
    }
    if (existing.channel_type === 'email' && smtp) {
      config = {
        host: smtp.host !== undefined ? smtp.host : existing.config.host,
        port: smtp.port !== undefined ? smtp.port : existing.config.port,
        secure: smtp.secure !== undefined ? !!smtp.secure : existing.config.secure,
        from: smtp.from !== undefined ? smtp.from : existing.config.from,
        to: smtp.to !== undefined ? smtp.to : existing.config.to,
        user: smtp.user !== undefined ? smtp.user : existing.config.user,
      };
      if (!config.host || !config.to) {
        return NextResponse.json({ error: 'smtp.host and smtp.to are required for an email channel' }, { status: 400 });
      }
    }
  }

  if (
    trimmedName === undefined &&
    enabled === undefined &&
    resolvedAlertTypes === undefined &&
    plaintext === undefined &&
    config === undefined
  ) {
    return NextResponse.json({ error: 'Nothing to update' }, { status: 400 });
  }

  try {
    if (trimmedName !== undefined && trimmedName !== existing.name) {
      const dupe = await pool.query('SELECT id FROM notification_channels WHERE name = $1 AND id <> $2', [
        trimmedName,
        params.id,
      ]);
      if (dupe.rows.length > 0) {
        return NextResponse.json({ error: 'A channel with that name already exists' }, { status: 409 });
      }
    }
    const channel = await updateChannel(
      params.id,
      { name: trimmedName, enabled, alertTypes: resolvedAlertTypes, config, plaintext },
      pool
    );
    return NextResponse.json({ channel });
  } catch (err) {
    return NextResponse.json(
      { error: err.message || 'Failed to update notification channel' },
      { status: 500 }
    );
  }
}

export async function DELETE(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid channel id' }, { status: 400 });
  }

  const existing = await getChannelMeta(params.id, pool);
  if (!existing) {
    return NextResponse.json({ error: 'Notification channel not found' }, { status: 404 });
  }

  try {
    await deleteChannel(params.id, pool);
    return NextResponse.json({ ok: true });
  } catch (err) {
    return NextResponse.json(
      { error: err.message || 'Failed to delete notification channel' },
      { status: 500 }
    );
  }
}
