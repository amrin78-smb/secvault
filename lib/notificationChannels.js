// lib/notificationChannels.js
//
// Named outbound notification targets (Slack/Teams incoming webhooks, email,
// a generic JSON webhook) — see lib/schema.sql's notification_channels table
// comment for the full design rationale (not device-scoped, mirrors
// credential_profiles). CommonJS, required directly by
// app/api/notification-channels/** and lib/engines/notificationDispatch.js.
//
// credStore.js's encrypt/decrypt are reused directly, same as
// lib/credentialProfiles.js does — getCredential/setCredential are
// device_id-scoped and don't apply here.
//
// ⛔ NEVER return `encrypted_data`/`iv`, or a decrypted plaintext, from any
// function here except getChannelPlaintext / listEnabledChannelsWithSecrets
// — both exist ONLY for server-side use (building an outbound request in
// lib/notify.js). Every other function here returns metadata-only rows that
// are safe to hand straight to NextResponse.json.

'use strict';

const { encrypt, decrypt } = require('./credStore');

const NOTIFICATION_CHANNEL_TYPES = ['slack_webhook', 'teams_webhook', 'email', 'generic_webhook'];

const ALERT_TYPES = ['patch_now_cve', 'compliance_critical', 'config_diff'];

// Builds a channel's secret plaintext directly from channel_type -- mirrors
// lib/credentialProfiles.js's buildProfilePlaintext shape (a small,
// per-purpose builder rather than a shared import, same convention). The
// three webhook types store the raw webhook URL as the whole secret (the
// URL itself IS the credential -- no separate username/password); email
// stores the SMTP password only, with host/port/from/to living in the
// non-secret `config` JSONB instead (see createChannel/updateChannel).
function buildChannelPlaintext(channelType, { webhookUrl, smtpPassword } = {}) {
  if (channelType === 'slack_webhook' || channelType === 'teams_webhook' || channelType === 'generic_webhook') {
    return typeof webhookUrl === 'string' && webhookUrl.trim() !== '' ? webhookUrl.trim() : null;
  }
  if (channelType === 'email') {
    // A password-less SMTP relay (common on an internal relay with IP allowlisting)
    // is a real, legitimate shape -- store an empty string rather than reject it,
    // matching nodemailer's own "auth optional" transport contract.
    return typeof smtpPassword === 'string' ? smtpPassword : '';
  }
  return null;
}

// Metadata only — never encrypted_data/iv. Safe to return to the browser.
async function listChannels(pool) {
  if (!pool) throw new Error('listChannels requires pool parameter');
  const { rows } = await pool.query(
    `SELECT id, name, channel_type, enabled, alert_types, config,
            last_success_at, last_error, last_error_at, created_at, updated_at
     FROM notification_channels ORDER BY name ASC`
  );
  return rows;
}

async function getChannelMeta(id, pool) {
  if (!pool) throw new Error('getChannelMeta requires pool parameter');
  const { rows } = await pool.query(
    `SELECT id, name, channel_type, enabled, alert_types, config,
            last_success_at, last_error, last_error_at, created_at, updated_at
     FROM notification_channels WHERE id = $1`,
    [id]
  );
  return rows[0] || null;
}

// Decrypts a single channel's plaintext for SERVER-SIDE use only (the test-send
// route). Returns null when the channel doesn't exist.
async function getChannelPlaintext(id, pool) {
  if (!pool) throw new Error('getChannelPlaintext requires pool parameter');
  const { rows } = await pool.query(
    `SELECT id, name, channel_type, alert_types, config, encrypted_data, iv
     FROM notification_channels WHERE id = $1`,
    [id]
  );
  if (rows.length === 0) return null;
  const row = rows[0];
  return {
    id: row.id,
    name: row.name,
    channelType: row.channel_type,
    alertTypes: row.alert_types,
    config: row.config,
    plaintext: decrypt(row.encrypted_data, row.iv),
  };
}

// Decrypts every ENABLED channel's plaintext in one query — used by
// lib/engines/notificationDispatch.js's poll job, which needs the full set
// up front rather than one-at-a-time. SERVER-SIDE use only, same contract as
// getChannelPlaintext above.
async function listEnabledChannelsWithSecrets(pool) {
  if (!pool) throw new Error('listEnabledChannelsWithSecrets requires pool parameter');
  const { rows } = await pool.query(
    `SELECT id, name, channel_type, alert_types, config, encrypted_data, iv
     FROM notification_channels WHERE enabled = true`
  );
  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    channelType: row.channel_type,
    alertTypes: row.alert_types,
    config: row.config,
    plaintext: decrypt(row.encrypted_data, row.iv),
  }));
}

async function createChannel({ name, channelType, alertTypes, config, plaintext }, pool) {
  if (!pool) throw new Error('createChannel requires pool parameter');
  const { encrypted, iv } = encrypt(plaintext);
  const { rows } = await pool.query(
    `INSERT INTO notification_channels (name, channel_type, alert_types, config, encrypted_data, iv)
     VALUES ($1, $2, $3, $4::jsonb, $5, $6)
     RETURNING id, name, channel_type, enabled, alert_types, config,
               last_success_at, last_error, last_error_at, created_at, updated_at`,
    [name, channelType, alertTypes, JSON.stringify(config || {}), encrypted, iv]
  );
  return rows[0];
}

// `name`/`enabled`/`alertTypes`/`config`/`plaintext` may each be omitted
// (undefined means "leave alone", distinct from an empty value) — same
// partial-update convention as lib/credentialProfiles.js's updateProfile.
// channel_type is immutable once created, same reasoning as credential_type
// there: a shape change is a different channel, not an edit.
async function updateChannel(id, { name, enabled, alertTypes, config, plaintext }, pool) {
  if (!pool) throw new Error('updateChannel requires pool parameter');
  const sets = [];
  const values = [];
  let i = 1;
  if (name !== undefined) {
    sets.push(`name = $${i++}`);
    values.push(name);
  }
  if (enabled !== undefined) {
    sets.push(`enabled = $${i++}`);
    values.push(enabled);
  }
  if (alertTypes !== undefined) {
    sets.push(`alert_types = $${i++}`);
    values.push(alertTypes);
  }
  if (config !== undefined) {
    sets.push(`config = $${i++}::jsonb`);
    values.push(JSON.stringify(config));
  }
  if (plaintext !== undefined) {
    const { encrypted, iv } = encrypt(plaintext);
    sets.push(`encrypted_data = $${i++}`, `iv = $${i++}`);
    values.push(encrypted, iv);
  }
  if (sets.length === 0) {
    return getChannelMeta(id, pool);
  }
  sets.push('updated_at = now()');
  values.push(id);
  const { rows } = await pool.query(
    `UPDATE notification_channels SET ${sets.join(', ')} WHERE id = $${i}
     RETURNING id, name, channel_type, enabled, alert_types, config,
               last_success_at, last_error, last_error_at, created_at, updated_at`,
    values
  );
  return rows[0] || null;
}

async function deleteChannel(id, pool) {
  if (!pool) throw new Error('deleteChannel requires pool parameter');
  await pool.query('DELETE FROM notification_channels WHERE id = $1', [id]);
}

// Called by lib/notify.js's dispatchNotification after every send attempt —
// visible failure is the whole point of this table's last_error columns
// (see lib/schema.sql's comment: a silently-failing channel defeats the
// purpose of this feature).
async function recordChannelSuccess(id, pool) {
  if (!pool) throw new Error('recordChannelSuccess requires pool parameter');
  await pool.query(
    `UPDATE notification_channels SET last_success_at = now(), last_error = NULL, last_error_at = NULL WHERE id = $1`,
    [id]
  );
}

async function recordChannelError(id, message, pool) {
  if (!pool) throw new Error('recordChannelError requires pool parameter');
  await pool.query(
    `UPDATE notification_channels SET last_error = $1, last_error_at = now() WHERE id = $2`,
    [message, id]
  );
}

module.exports = {
  NOTIFICATION_CHANNEL_TYPES,
  ALERT_TYPES,
  buildChannelPlaintext,
  listChannels,
  getChannelMeta,
  getChannelPlaintext,
  listEnabledChannelsWithSecrets,
  createChannel,
  updateChannel,
  deleteChannel,
  recordChannelSuccess,
  recordChannelError,
};
