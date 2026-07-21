'use client';

// Credential Profiles (admin-only) — reusable named username/password/API-key
// bundles an operator can save once and reuse when adding devices, instead of
// retyping the same SSH/REST creds for every firewall. Backend already built
// (app/api/credential-profiles/*, admin-gated server-side) — this file is UI
// only, structurally mirroring UsersPanel.js: fetch-on-mount list + inline
// create form + Table with row actions, same visible/loadError 403-vs-network
// distinction (the API route's own isAdmin() check is the real security
// boundary — this component just reflects it, never a second client-side
// role check).

import { Fragment, useEffect, useState } from 'react';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import { CREDENTIAL_TYPES } from '../devices/vendorMeta';

const TYPE_BADGE = { smc_api: 'teal', rest_api: 'info', ssh: 'purple' };
const TYPE_BADGE_LABEL = { smc_api: 'SMC API Key', rest_api: 'REST API', ssh: 'SSH' };
const TYPE_CREATE_LABEL = {
  smc_api: 'SMC API Key (Forcepoint)',
  rest_api: 'REST API (Fortinet / Palo Alto / Check Point)',
  ssh: 'SSH (Fortinet / Palo Alto / Cisco ASA / Sangfor)',
};

const AUTH_MODE_OPTIONS = [
  { value: 'apikey', label: 'API Key / Token' },
  { value: 'userpass', label: 'Username & Password' },
];

// Fresh, empty field-state object for either the create form or an in-place
// secret rotation — same shape used by both, so one blank object works for
// either call site.
function emptyFields() {
  return { authMode: 'apikey', secret: '', username: '', password: '', enablePassword: '' };
}

// Whether `fields` currently has enough to submit, given `credentialType`.
// Mirrors CredentialForm.js's `ready` boolean, generalized across all three
// credential_type shapes instead of one resolved vendor/method config.
function isReady(credentialType, fields) {
  if (credentialType === 'smc_api') return Boolean(fields.secret);
  if (credentialType === 'rest_api') {
    return fields.authMode === 'userpass'
      ? Boolean(fields.username && fields.password)
      : Boolean(fields.secret);
  }
  if (credentialType === 'ssh') return Boolean(fields.username && fields.password);
  return false;
}

// Builds the request-body fields to send for a given credential_type + form
// state (create POST or rotate PUT — both send the same shape).
function fieldsForRequest(credentialType, fields) {
  if (credentialType === 'smc_api') {
    return { secret: fields.secret };
  }
  if (credentialType === 'rest_api') {
    return fields.authMode === 'userpass'
      ? { auth_mode: 'userpass', username: fields.username, password: fields.password }
      : { auth_mode: 'apikey', secret: fields.secret };
  }
  if (credentialType === 'ssh') {
    const body = { username: fields.username, password: fields.password };
    if (fields.enablePassword) body.enable_password = fields.enablePassword;
    return body;
  }
  return {};
}

// Render helper (NOT a nested component — a plain function returning JSX,
// called from both the create form and the inline rotate-secret row, per
// CLAUDE.md's no-nested-component rule) for the credential_type-dependent
// secret/username/password fields. `idPrefix` keeps label htmlFor values
// unique between the create form and whichever row is mid-rotation.
function renderCredentialFields(credentialType, fields, setFields, idPrefix) {
  if (!credentialType) return null;

  if (credentialType === 'smc_api') {
    return (
      <div className="form-field">
        <label htmlFor={`${idPrefix}_secret`}>SMC API Key</label>
        <input
          id={`${idPrefix}_secret`}
          type="password"
          autoComplete="new-password"
          value={fields.secret}
          onChange={(e) => setFields({ ...fields, secret: e.target.value })}
          className="input"
        />
      </div>
    );
  }

  if (credentialType === 'rest_api') {
    return (
      <>
        <div className="form-field">
          <label htmlFor={`${idPrefix}_auth_mode`}>Authentication mode</label>
          <select
            id={`${idPrefix}_auth_mode`}
            className="select"
            value={fields.authMode}
            onChange={(e) =>
              setFields({ ...fields, authMode: e.target.value, secret: '', username: '', password: '' })
            }
          >
            {AUTH_MODE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
        {fields.authMode === 'userpass' ? (
          <>
            <div className="form-field">
              <label htmlFor={`${idPrefix}_username`}>Username</label>
              <input
                id={`${idPrefix}_username`}
                type="text"
                autoComplete="off"
                value={fields.username}
                onChange={(e) => setFields({ ...fields, username: e.target.value })}
                className="input"
              />
            </div>
            <div className="form-field">
              <label htmlFor={`${idPrefix}_password`}>Password</label>
              <input
                id={`${idPrefix}_password`}
                type="password"
                autoComplete="new-password"
                value={fields.password}
                onChange={(e) => setFields({ ...fields, password: e.target.value })}
                className="input"
              />
            </div>
          </>
        ) : (
          <div className="form-field">
            <label htmlFor={`${idPrefix}_secret`}>API Key / Token</label>
            <input
              id={`${idPrefix}_secret`}
              type="password"
              autoComplete="new-password"
              value={fields.secret}
              onChange={(e) => setFields({ ...fields, secret: e.target.value })}
              className="input"
            />
          </div>
        )}
      </>
    );
  }

  if (credentialType === 'ssh') {
    return (
      <>
        <div className="form-field">
          <label htmlFor={`${idPrefix}_username`}>Username</label>
          <input
            id={`${idPrefix}_username`}
            type="text"
            autoComplete="off"
            value={fields.username}
            onChange={(e) => setFields({ ...fields, username: e.target.value })}
            className="input"
          />
        </div>
        <div className="form-field">
          <label htmlFor={`${idPrefix}_password`}>Password</label>
          <input
            id={`${idPrefix}_password`}
            type="password"
            autoComplete="new-password"
            value={fields.password}
            onChange={(e) => setFields({ ...fields, password: e.target.value })}
            className="input"
          />
        </div>
        <div className="form-field">
          <label htmlFor={`${idPrefix}_enable_password`}>
            Enable Password (optional, Cisco ASA only)
          </label>
          <input
            id={`${idPrefix}_enable_password`}
            type="password"
            autoComplete="new-password"
            value={fields.enablePassword}
            onChange={(e) => setFields({ ...fields, enablePassword: e.target.value })}
            className="input"
          />
        </div>
      </>
    );
  }

  return null;
}

export default function CredentialProfilesPanel() {
  const [profiles, setProfiles] = useState(null); // null = loading/forbidden, [] = loaded
  const [visible, setVisible] = useState(false);
  const [loadError, setLoadError] = useState(false); // fetch() itself failed (network) -- distinct from a 403 hide
  const [status, setStatus] = useState('');

  // Create form state
  const [newName, setNewName] = useState('');
  const [newType, setNewType] = useState(CREDENTIAL_TYPES[0]);
  const [newFields, setNewFields] = useState(emptyFields());

  // Inline rotate-secret state -- at most one row expanded at a time.
  const [rotatingId, setRotatingId] = useState(null);
  const [rotateFields, setRotateFields] = useState(emptyFields());
  const [rotateStatus, setRotateStatus] = useState('');

  async function loadProfiles() {
    try {
      const res = await fetch('/api/credential-profiles');
      if (res.status === 403) {
        setVisible(false);
        setProfiles(null);
        setLoadError(false);
        return;
      }
      const data = await res.json().catch(() => ({}));
      setProfiles(data.profiles || []);
      setVisible(true);
      setLoadError(false);
    } catch (err) {
      // Network-level failure (fetch() rejected) -- distinct from a 403. Keep
      // the panel visible and show a retry-able error instead of silently
      // rendering nothing, which would be indistinguishable from the
      // deliberate viewer-role hide above.
      setVisible(true);
      setLoadError(true);
    }
  }

  useEffect(() => {
    loadProfiles();
  }, []);

  async function handleCreate(e) {
    e.preventDefault();
    if (!newName || !isReady(newType, newFields)) return;
    setStatus('Creating...');
    const res = await fetch('/api/credential-profiles', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: newName,
        credential_type: newType,
        ...fieldsForRequest(newType, newFields),
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      setStatus('Profile created.');
      setNewName('');
      setNewType(CREDENTIAL_TYPES[0]);
      setNewFields(emptyFields());
      loadProfiles();
    } else {
      setStatus(data.error || 'Failed to create profile.');
    }
  }

  async function handleRename(profileId, currentName) {
    const name = window.prompt('New profile name:', currentName);
    if (!name || name === currentName) return;
    setStatus('Saving...');
    const res = await fetch(`/api/credential-profiles/${profileId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      setStatus('Profile renamed.');
      loadProfiles();
    } else {
      setStatus(data.error || 'Failed to rename profile.');
    }
  }

  function startRotate(profileId) {
    setRotatingId(profileId);
    setRotateFields(emptyFields());
    setRotateStatus('');
  }

  function cancelRotate() {
    setRotatingId(null);
    setRotateFields(emptyFields());
    setRotateStatus('');
  }

  async function handleRotateSave(profile) {
    if (!isReady(profile.credential_type, rotateFields)) return;
    setRotateStatus('Saving...');
    const res = await fetch(`/api/credential-profiles/${profile.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(fieldsForRequest(profile.credential_type, rotateFields)),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      setStatus('Secret rotated.');
      cancelRotate();
      loadProfiles();
    } else {
      setRotateStatus(data.error || 'Failed to rotate secret.');
    }
  }

  async function handleDelete(profileId, name) {
    if (!window.confirm(`Delete credential profile "${name}"? This cannot be undone.`)) return;
    setStatus('Deleting...');
    const res = await fetch(`/api/credential-profiles/${profileId}`, { method: 'DELETE' });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      setStatus('Profile deleted.');
      if (rotatingId === profileId) cancelRotate();
      loadProfiles();
    } else {
      setStatus(data.error || 'Failed to delete profile.');
    }
  }

  if (!visible) return null;

  if (loadError) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Credential Profiles</CardTitle>
        </CardHeader>
        <CardBody>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', margin: 0 }}>
              Failed to load credential profiles.
            </p>
            <Button variant="secondary" onClick={loadProfiles}>
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
        <CardTitle>Credential Profiles</CardTitle>
      </CardHeader>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', margin: 0 }}>
            Save reusable named credential bundles here, then apply one when adding a device instead
            of retyping the same username/password/API key every time.
          </p>

          {profiles && profiles.length > 0 && (
            <Table>
              <thead>
                <tr>
                  <th style={{ width: '24%' }}>Name</th>
                  <th style={{ width: '16%' }}>Type</th>
                  <th style={{ width: '18%' }}>Username</th>
                  <th style={{ width: '14%' }}>Created</th>
                  <th style={{ width: '28%' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {profiles.map((p) => (
                  <Fragment key={p.id}>
                    <tr>
                      <td>{p.name}</td>
                      <td>
                        <Badge color={TYPE_BADGE[p.credential_type] || 'muted'}>
                          {TYPE_BADGE_LABEL[p.credential_type] || p.credential_type}
                        </Badge>
                      </td>
                      <td>{p.username || (p.credential_type === 'ssh' ? '—' : 'API key')}</td>
                      <td>{p.created_at ? new Date(p.created_at).toLocaleDateString() : '—'}</td>
                      <td style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        <Button variant="secondary" onClick={() => handleRename(p.id, p.name)}>
                          Rename
                        </Button>
                        <Button
                          variant="secondary"
                          onClick={() => (rotatingId === p.id ? cancelRotate() : startRotate(p.id))}
                        >
                          {rotatingId === p.id ? 'Cancel' : 'Rotate Secret'}
                        </Button>
                        <Button variant="danger" onClick={() => handleDelete(p.id, p.name)}>
                          Delete
                        </Button>
                      </td>
                    </tr>
                    {rotatingId === p.id && (
                      <tr>
                        <td colSpan={5} style={{ background: 'var(--bg-primary)' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, maxWidth: 420 }}>
                            {renderCredentialFields(
                              p.credential_type,
                              rotateFields,
                              setRotateFields,
                              `rotate_${p.id}`
                            )}
                            {rotateStatus && (
                              <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', margin: 0 }}>
                                {rotateStatus}
                              </p>
                            )}
                            <Button
                              type="button"
                              variant="primary"
                              style={{ alignSelf: 'flex-start' }}
                              disabled={!isReady(p.credential_type, rotateFields)}
                              onClick={() => handleRotateSave(p)}
                            >
                              Save New Secret
                            </Button>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </Table>
          )}

          <form onSubmit={handleCreate} style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 420 }}>
            <div className="form-field">
              <label htmlFor="new_profile_name">New profile — name</label>
              <input
                id="new_profile_name"
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                required
                className="input"
              />
            </div>
            <div className="form-field">
              <label htmlFor="new_profile_type">Credential type</label>
              <select
                id="new_profile_type"
                className="select"
                value={newType}
                onChange={(e) => {
                  setNewType(e.target.value);
                  setNewFields(emptyFields());
                }}
              >
                {CREDENTIAL_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {TYPE_CREATE_LABEL[t] || t}
                  </option>
                ))}
              </select>
            </div>

            {renderCredentialFields(newType, newFields, setNewFields, 'new_profile')}

            {status && <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>{status}</p>}

            <Button
              type="submit"
              variant="primary"
              style={{ alignSelf: 'flex-start' }}
              disabled={!newName || !isReady(newType, newFields)}
            >
              Create Profile
            </Button>
          </form>
        </div>
      </CardBody>
    </Card>
  );
}
