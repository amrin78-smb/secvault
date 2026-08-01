'use client';

// Notification Channels (admin-only) — outbound Slack/Teams/email/generic
// webhook targets for patch_now CVEs, critical compliance failures, and
// unacknowledged config changes. Backend already built
// (app/api/notification-channels/*, admin-gated server-side, dispatched by
// services/engine-worker.js's notification-dispatch job) — this file is UI
// only, structurally mirroring CredentialProfilesPanel.js: fetch-on-mount
// list + inline create form + Table with row actions, same visible/loadError
// 403-vs-network distinction (the API route's own isAdmin() check is the
// real security boundary — this component just reflects it).

import { Fragment, useEffect, useState } from 'react';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';

const CHANNEL_TYPES = ['slack_webhook', 'teams_webhook', 'email', 'generic_webhook'];
const CHANNEL_TYPE_BADGE = { slack_webhook: 'purple', teams_webhook: 'info', email: 'teal', generic_webhook: 'muted' };
const CHANNEL_TYPE_LABEL = {
  slack_webhook: 'Slack',
  teams_webhook: 'Microsoft Teams',
  email: 'Email',
  generic_webhook: 'Generic Webhook',
};

const ALERT_TYPES = ['patch_now_cve', 'compliance_critical', 'config_diff'];
const ALERT_TYPE_LABEL = {
  patch_now_cve: 'Patch Now CVEs',
  compliance_critical: 'Critical Compliance Failures',
  config_diff: 'Config Changes',
};

// Fresh, empty field-state object for either the create form or an in-place
// rotation — same shape used by both, same convention as
// CredentialProfilesPanel.js's emptyFields().
function emptyFields() {
  return {
    webhookUrl: '',
    smtpHost: '',
    smtpPort: '587',
    smtpSecure: false,
    smtpFrom: '',
    smtpTo: '',
    smtpUser: '',
    smtpPassword: '',
    alertTypes: [...ALERT_TYPES],
  };
}

function isReady(channelType, fields) {
  if (channelType === 'email') return Boolean(fields.smtpHost && fields.smtpTo);
  return Boolean(fields.webhookUrl);
}

function fieldsForRequest(channelType, fields) {
  const body = { alert_types: fields.alertTypes };
  if (channelType === 'email') {
    body.smtp = {
      host: fields.smtpHost,
      port: fields.smtpPort ? Number(fields.smtpPort) : undefined,
      secure: fields.smtpSecure,
      from: fields.smtpFrom || undefined,
      to: fields.smtpTo,
      user: fields.smtpUser || undefined,
      password: fields.smtpPassword || undefined,
    };
  } else {
    body.webhook_url = fields.webhookUrl;
  }
  return body;
}

// Render helper (NOT a nested component, per CLAUDE.md's no-nested-component
// rule) for the channel_type-dependent secret/target fields, plus the
// alert-type checkboxes shared by every channel type.
function renderChannelFields(channelType, fields, setFields, idPrefix) {
  return (
    <>
      {channelType === 'email' ? (
        <>
          <div className="form-field">
            <label htmlFor={`${idPrefix}_smtp_host`}>SMTP Host</label>
            <input
              id={`${idPrefix}_smtp_host`}
              type="text"
              value={fields.smtpHost}
              onChange={(e) => setFields({ ...fields, smtpHost: e.target.value })}
              className="input"
            />
          </div>
          <div className="form-field">
            <label htmlFor={`${idPrefix}_smtp_port`}>SMTP Port</label>
            <input
              id={`${idPrefix}_smtp_port`}
              type="number"
              value={fields.smtpPort}
              onChange={(e) => setFields({ ...fields, smtpPort: e.target.value })}
              className="input"
            />
          </div>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 'var(--text-base)' }}>
            <input
              type="checkbox"
              checked={fields.smtpSecure}
              onChange={(e) => setFields({ ...fields, smtpSecure: e.target.checked })}
            />
            Use TLS (port 465)
          </label>
          <div className="form-field">
            <label htmlFor={`${idPrefix}_smtp_from`}>From address (optional)</label>
            <input
              id={`${idPrefix}_smtp_from`}
              type="email"
              value={fields.smtpFrom}
              onChange={(e) => setFields({ ...fields, smtpFrom: e.target.value })}
              className="input"
            />
          </div>
          <div className="form-field">
            <label htmlFor={`${idPrefix}_smtp_to`}>To address</label>
            <input
              id={`${idPrefix}_smtp_to`}
              type="email"
              value={fields.smtpTo}
              onChange={(e) => setFields({ ...fields, smtpTo: e.target.value })}
              className="input"
            />
          </div>
          <div className="form-field">
            <label htmlFor={`${idPrefix}_smtp_user`}>SMTP Username (optional)</label>
            <input
              id={`${idPrefix}_smtp_user`}
              type="text"
              autoComplete="off"
              value={fields.smtpUser}
              onChange={(e) => setFields({ ...fields, smtpUser: e.target.value })}
              className="input"
            />
          </div>
          <div className="form-field">
            <label htmlFor={`${idPrefix}_smtp_password`}>SMTP Password (optional)</label>
            <input
              id={`${idPrefix}_smtp_password`}
              type="password"
              autoComplete="new-password"
              value={fields.smtpPassword}
              onChange={(e) => setFields({ ...fields, smtpPassword: e.target.value })}
              className="input"
            />
          </div>
        </>
      ) : (
        <div className="form-field">
          <label htmlFor={`${idPrefix}_webhook_url`}>
            {channelType === 'slack_webhook'
              ? 'Slack Incoming Webhook URL'
              : channelType === 'teams_webhook'
              ? 'Teams Workflow Webhook URL'
              : 'Webhook URL'}
          </label>
          <input
            id={`${idPrefix}_webhook_url`}
            type="password"
            autoComplete="new-password"
            value={fields.webhookUrl}
            onChange={(e) => setFields({ ...fields, webhookUrl: e.target.value })}
            className="input"
          />
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        <span style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>Alert on</span>
        {ALERT_TYPES.map((t) => (
          <label key={t} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 'var(--text-base)' }}>
            <input
              type="checkbox"
              checked={fields.alertTypes.includes(t)}
              onChange={(e) =>
                setFields({
                  ...fields,
                  alertTypes: e.target.checked
                    ? [...fields.alertTypes, t]
                    : fields.alertTypes.filter((x) => x !== t),
                })
              }
            />
            {ALERT_TYPE_LABEL[t]}
          </label>
        ))}
      </div>
    </>
  );
}

function lastStatusText(channel) {
  if (channel.last_error) {
    const when = channel.last_error_at ? new Date(channel.last_error_at).toLocaleString() : '';
    return { text: `Last failure: ${when} — ${channel.last_error}`, color: 'var(--red)' };
  }
  if (channel.last_success_at) {
    return { text: `Last sent: ${new Date(channel.last_success_at).toLocaleString()}`, color: 'var(--text-secondary)' };
  }
  return { text: 'Never sent', color: 'var(--text-muted)' };
}

export default function NotificationsPanel() {
  const [channels, setChannels] = useState(null); // null = loading/forbidden, [] = loaded
  const [visible, setVisible] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const [status, setStatus] = useState('');

  const [newName, setNewName] = useState('');
  const [newType, setNewType] = useState(CHANNEL_TYPES[0]);
  const [newFields, setNewFields] = useState(emptyFields());

  const [testingId, setTestingId] = useState(null);
  const [testResult, setTestResult] = useState({});

  async function loadChannels() {
    try {
      const res = await fetch('/api/notification-channels');
      if (res.status === 403) {
        setVisible(false);
        setChannels(null);
        setLoadError(false);
        return;
      }
      const data = await res.json().catch(() => ({}));
      setChannels(data.channels || []);
      setVisible(true);
      setLoadError(false);
    } catch (err) {
      setVisible(true);
      setLoadError(true);
    }
  }

  useEffect(() => {
    loadChannels();
  }, []);

  async function handleCreate(e) {
    e.preventDefault();
    if (!newName || !isReady(newType, newFields) || newFields.alertTypes.length === 0) return;
    setStatus('Creating...');
    const res = await fetch('/api/notification-channels', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: newName, channel_type: newType, ...fieldsForRequest(newType, newFields) }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      setStatus('Channel created.');
      setNewName('');
      setNewType(CHANNEL_TYPES[0]);
      setNewFields(emptyFields());
      loadChannels();
    } else {
      setStatus(data.error || 'Failed to create channel.');
    }
  }

  async function handleToggleEnabled(channel) {
    const res = await fetch(`/api/notification-channels/${channel.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !channel.enabled }),
    });
    if (res.ok) loadChannels();
  }

  async function handleTest(channelId) {
    setTestingId(channelId);
    setTestResult((prev) => ({ ...prev, [channelId]: null }));
    const res = await fetch(`/api/notification-channels/${channelId}/test`, { method: 'POST' });
    const data = await res.json().catch(() => ({}));
    setTestResult((prev) => ({
      ...prev,
      [channelId]: res.ok ? { ok: true, text: 'Test message sent.' } : { ok: false, text: data.error || 'Test failed.' },
    }));
    setTestingId(null);
    loadChannels();
  }

  async function handleDelete(channelId, name) {
    if (!window.confirm(`Delete notification channel "${name}"? This cannot be undone.`)) return;
    setStatus('Deleting...');
    const res = await fetch(`/api/notification-channels/${channelId}`, { method: 'DELETE' });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      setStatus('Channel deleted.');
      loadChannels();
    } else {
      setStatus(data.error || 'Failed to delete channel.');
    }
  }

  if (!visible) return null;

  if (loadError) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Notifications</CardTitle>
        </CardHeader>
        <CardBody>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', margin: 0 }}>
              Failed to load notification channels.
            </p>
            <Button variant="secondary" onClick={loadChannels}>
              Retry
            </Button>
          </div>
        </CardBody>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Notifications</CardTitle>
      </CardHeader>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', margin: 0 }}>
            Send an alert to Slack, Microsoft Teams, email, or a generic webhook when a device reaches
            Patch Now on a CVE, fails a critical compliance check, or has an unacknowledged config change.
            Checked every few minutes — see the About tab for the current poll interval.
          </p>

          {channels && channels.length > 0 && (
            <Table>
              <thead>
                <tr>
                  <th style={{ width: '18%' }}>Name</th>
                  <th style={{ width: '14%' }}>Type</th>
                  <th style={{ width: '10%' }}>Enabled</th>
                  <th style={{ width: '30%' }}>Status</th>
                  <th style={{ width: '28%' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {channels.map((c) => {
                  const last = lastStatusText(c);
                  const result = testResult[c.id];
                  return (
                    <Fragment key={c.id}>
                      <tr>
                        <td>{c.name}</td>
                        <td>
                          <Badge color={CHANNEL_TYPE_BADGE[c.channel_type] || 'muted'}>
                            {CHANNEL_TYPE_LABEL[c.channel_type] || c.channel_type}
                          </Badge>
                        </td>
                        <td>
                          <Button variant="secondary" onClick={() => handleToggleEnabled(c)}>
                            {c.enabled ? 'Enabled' : 'Disabled'}
                          </Button>
                        </td>
                        <td style={{ fontSize: 'var(--text-sm)', color: last.color }}>{last.text}</td>
                        <td style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                          <Button
                            variant="secondary"
                            disabled={testingId === c.id}
                            onClick={() => handleTest(c.id)}
                          >
                            {testingId === c.id ? 'Sending…' : 'Test'}
                          </Button>
                          <Button variant="danger" onClick={() => handleDelete(c.id, c.name)}>
                            Delete
                          </Button>
                        </td>
                      </tr>
                      {result && (
                        <tr>
                          <td colSpan={5} style={{ fontSize: 'var(--text-sm)', color: result.ok ? 'var(--green)' : 'var(--red)' }}>
                            {result.text}
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </Table>
          )}

          <form onSubmit={handleCreate} style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 420 }}>
            <div className="form-field">
              <label htmlFor="new_channel_name">New channel — name</label>
              <input
                id="new_channel_name"
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                required
                className="input"
              />
            </div>
            <div className="form-field">
              <label htmlFor="new_channel_type">Channel type</label>
              <select
                id="new_channel_type"
                className="select"
                value={newType}
                onChange={(e) => {
                  setNewType(e.target.value);
                  setNewFields(emptyFields());
                }}
              >
                {CHANNEL_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {CHANNEL_TYPE_LABEL[t]}
                  </option>
                ))}
              </select>
            </div>

            {renderChannelFields(newType, newFields, setNewFields, 'new_channel')}

            {status && <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>{status}</p>}

            <Button
              type="submit"
              variant="primary"
              style={{ alignSelf: 'flex-start' }}
              disabled={!newName || !isReady(newType, newFields) || newFields.alertTypes.length === 0}
            >
              Create Channel
            </Button>
          </form>
        </div>
      </CardBody>
    </Card>
  );
}
