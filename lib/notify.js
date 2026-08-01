// lib/notify.js
// CommonJS ONLY — required by lib/engines/notificationDispatch.js (via
// services/engine-worker.js, plain node) and app/api/notification-channels/
// [id]/test/route.js.
//
// Pure dispatch — no DB access here (callers pass an already-decrypted
// channel object from lib/notificationChannels.js and record success/error
// back to the DB themselves). One function per channel_type; dispatchNotification
// is the single entry point every caller uses.

'use strict';

// See lib/adapters/forcepoint/smc.js's identical comment: node-fetch@2's
// package.json declares both "main" (CJS) and "module" (ESM) fields, and
// Next.js's webpack bundler resolves "module" even for a plain require() —
// the callable function lives at `.default`, not the raw require() result.
const fetchModule = require('node-fetch');
const fetch = fetchModule.default || fetchModule;
const nodemailer = require('nodemailer');

// Shorter than every other outbound timeout in this codebase (15000-120000ms
// elsewhere) — those bound a data-collection call the app is synchronously
// waiting on; this bounds a fire-and-forget notification POST inside a poll
// job's loop over N channels x M items, where a single dead endpoint must
// never stall the whole tick.
const NOTIFY_TIMEOUT_MS = 8000;

// Teams incoming-webhook payload shape is a live-verification risk, not a
// settled spec (Microsoft has been phasing out the legacy Office 365
// Connector "MessageCard" format tenant-by-tenant since 2024/2025 in favor
// of Power Automate "Workflows" webhooks, which expect an Adaptive Card
// wrapped in a `message` envelope — the shape built below). Per CLAUDE.md's
// "documentation lies, verify against live responses" rule, log the raw
// response once on first live send so a wrong shape for a given tenant is
// diagnosable in engine.log instead of silently swallowed — same
// `loggedFirst*` one-shot-debug-log convention used throughout the vendor
// adapters.
let loggedFirstTeamsResponse = false;

function buildSlackPayload(message) {
  const link = message.url ? `<${message.url}|View in SecVault>` : '';
  return {
    text: `*${message.title}*\n${message.summary}${link ? `\n${link}` : ''}`,
  };
}

function buildTeamsPayload(message) {
  const body = [
    { type: 'TextBlock', text: message.title, weight: 'Bolder', size: 'Medium', wrap: true },
    { type: 'TextBlock', text: message.summary, wrap: true },
  ];
  const actions = message.url
    ? [{ type: 'Action.OpenUrl', title: 'View in SecVault', url: message.url }]
    : [];
  return {
    type: 'message',
    attachments: [
      {
        contentType: 'application/vnd.microsoft.card.adaptive',
        content: {
          $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
          type: 'AdaptiveCard',
          version: '1.4',
          body,
          actions,
        },
      },
    ],
  };
}

function buildGenericWebhookPayload(message) {
  return {
    alert_type: message.alertType,
    title: message.title,
    summary: message.summary,
    device_name: message.deviceName || null,
    url: message.url || null,
  };
}

async function postJson(url, payload) {
  let response;
  try {
    response = await fetch(url, {
      method: 'POST',
      timeout: NOTIFY_TIMEOUT_MS,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    throw new Error(`webhook request failed: ${err.message}`);
  }
  const bodyText = await response.text().catch(() => '');
  if (!response.ok) {
    throw new Error(`webhook returned HTTP ${response.status}${bodyText ? `: ${bodyText.slice(0, 500)}` : ''}`);
  }
  return bodyText;
}

async function sendSlackWebhook(channel, message) {
  await postJson(channel.plaintext, buildSlackPayload(message));
}

async function sendTeamsWebhook(channel, message) {
  const responseBody = await postJson(channel.plaintext, buildTeamsPayload(message));
  if (!loggedFirstTeamsResponse) {
    console.log(`[Notify Debug] Teams webhook raw response (first live send):\n${responseBody.slice(0, 2000)}`);
    loggedFirstTeamsResponse = true;
  }
}

async function sendGenericWebhook(channel, message) {
  await postJson(channel.plaintext, buildGenericWebhookPayload(message));
}

// channel.config holds { host, port, secure, from, to } (all non-secret);
// channel.plaintext holds the SMTP password (may be an empty string for a
// password-less relay — see lib/notificationChannels.js's buildChannelPlaintext).
async function sendEmail(channel, message) {
  const { host, port, secure, from, to, user } = channel.config || {};
  if (!host || !to) {
    throw new Error('email channel is missing required config (host/to)');
  }
  const transporter = nodemailer.createTransport({
    host,
    port: port || 587,
    secure: !!secure,
    auth: user ? { user, pass: channel.plaintext || '' } : undefined,
    connectionTimeout: NOTIFY_TIMEOUT_MS,
    greetingTimeout: NOTIFY_TIMEOUT_MS,
    socketTimeout: NOTIFY_TIMEOUT_MS,
  });
  await transporter.sendMail({
    from: from || user || 'secvault@localhost',
    to,
    subject: message.title,
    text: `${message.summary}${message.url ? `\n\n${message.url}` : ''}`,
  });
}

// Single entry point — dispatches `message` ({ alertType, title, summary, url,
// deviceName }) through `channel` ({ channelType, plaintext, config, ... }, an
// already-decrypted object from lib/notificationChannels.js). Throws on any
// failure; callers (lib/engines/notificationDispatch.js, the test-send route)
// are responsible for their own try/catch and for recording success/error
// back to notification_channels via recordChannelSuccess/recordChannelError.
async function dispatchNotification(channel, message) {
  switch (channel.channelType) {
    case 'slack_webhook':
      return sendSlackWebhook(channel, message);
    case 'teams_webhook':
      return sendTeamsWebhook(channel, message);
    case 'generic_webhook':
      return sendGenericWebhook(channel, message);
    case 'email':
      return sendEmail(channel, message);
    default:
      throw new Error(`unknown channel_type: ${channel.channelType}`);
  }
}

module.exports = { dispatchNotification };
