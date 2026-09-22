'use client';

// Users management (RBAC). Fetches GET /api/users on mount, which is
// itself admin-gated server-side (see app/api/users/route.js) — a 403
// response means the logged-in user is a viewer, and this component
// renders nothing at all rather than an "admins only" placeholder. This
// is deliberately how the admin-only visibility is achieved: the API
// route's own isAdmin() check is the real security boundary, and this
// component just reflects it, instead of duplicating a client-side role
// check that could drift out of sync with the server-side one. Settings
// page itself stays a plain 'use client' component (unchanged) — no
// server-side session plumbing needed here.

import { useEffect, useState } from 'react';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import { ASSIGNABLE_ROLES, ROLE_LABELS, ROLE_DESCRIPTIONS } from '../../lib/rbac';
import Button from '../ui/Button';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import DeviceScopeEditor from './DeviceScopeEditor';

// ⛔ RED IS RESERVED FOR DANGER. 'admin' was `danger`, so every administrator
// wore the same red this product uses for "critically exposed" and
// `patch_now` — on the normal, intended state of the account the reader is
// most likely logged in as. A role is an attribute, not an alarm: purple is
// the palette's non-ramp identity hue and carries no severity reading.
// ⛔ Three roles, and none of them red — red is reserved for danger and a role
// is an attribute, not an alarm. Super Admin is the strongest tint so the
// account that can create other accounts is identifiable at a glance.
const ROLE_BADGE = { super_admin: 'purple', admin: 'info', operator: 'muted' };

export default function UsersPanel() {
  const [users, setUsers] = useState(null); // null = loading/forbidden, [] = loaded
  const [visible, setVisible] = useState(false);
  const [loadError, setLoadError] = useState(false); // true = fetch() itself failed (network), distinct from a 403 hide
  const [status, setStatus] = useState('');
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  // ⛔ Defaults to the LEAST privileged role, matching the server default in
// app/api/users/route.js. A create form that defaults to a powerful role
// makes over-granting the path of least resistance.
  const [newRole, setNewRole] = useState('operator');
  // Per-user device scope (v2.169.0). `scopes` is keyed by user id; a missing
  // entry renders as a dash rather than as "All firewalls", because not having
  // READ the scope yet is not the same fact as the account having none.
  const [scopes, setScopes] = useState({});
  const [devices, setDevices] = useState([]);
  const [scopeFor, setScopeFor] = useState(null);

  // ⛔ Best-effort: a failure here must not take down user management. The
  // column degrades to a dash, which reads as "not known" rather than
  // inventing either answer.
  async function loadScopes(list) {
    try {
      const res = await fetch('/api/devices');
      if (res.ok) setDevices(await res.json());
    } catch { /* column still renders, editor reports its own error */ }
    const out = {};
    await Promise.all((list || []).map(async (u) => {
      try {
        const r = await fetch(`/api/users/${u.id}/device-scope`);
        if (r.ok) out[u.id] = await r.json();
      } catch { /* leave this user's cell as a dash */ }
    }));
    setScopes(out);
  }

  async function loadUsers() {
    try {
      const res = await fetch('/api/users');
      if (res.status === 403) {
        setVisible(false);
        setUsers(null);
        setLoadError(false);
        return;
      }
      const data = await res.json().catch(() => ({}));
      setUsers(data.users || []);
      setVisible(true);
      setLoadError(false);
      loadScopes(data.users || []);
    } catch (err) {
      // Network-level failure (fetch() rejected) -- distinct from a 403.
      // Keep the panel visible and show a retry-able error instead of
      // silently rendering nothing, which would be indistinguishable from
      // the deliberate viewer-role hide above.
      setVisible(true);
      setLoadError(true);
    }
  }

  useEffect(() => {
    loadUsers();
  }, []);

  async function handleCreate(e) {
    e.preventDefault();
    setStatus('Creating...');
    const res = await fetch('/api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: newUsername, password: newPassword, role: newRole }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      setStatus('User created.');
      setNewUsername('');
      setNewPassword('');
      setNewRole('operator');
      loadUsers();
    } else {
      setStatus(data.error || 'Failed to create user.');
    }
  }

  async function handleRoleChange(userId, role) {
    setStatus('Saving...');
    const res = await fetch(`/api/users/${userId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      setStatus('Role updated.');
      loadUsers();
    } else {
      setStatus(data.error || 'Failed to update role.');
    }
  }

  async function handleResetPassword(userId) {
    const password = window.prompt('New password (min 8 characters):');
    if (!password) return;
    setStatus('Saving...');
    const res = await fetch(`/api/users/${userId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    });
    const data = await res.json().catch(() => ({}));
    setStatus(res.ok ? 'Password reset.' : data.error || 'Failed to reset password.');
  }

  async function handleDelete(userId, username) {
    if (!window.confirm(`Delete user "${username}"? This cannot be undone.`)) return;
    setStatus('Deleting...');
    const res = await fetch(`/api/users/${userId}`, { method: 'DELETE' });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      setStatus('User deleted.');
      loadUsers();
    } else {
      setStatus(data.error || 'Failed to delete user.');
    }
  }

  if (!visible) return null;

  if (loadError) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Users</CardTitle>
        </CardHeader>
        <CardBody>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', margin: 0 }}>
              Failed to load users.
            </p>
            <Button variant="secondary" onClick={loadUsers}>
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
        <CardTitle>Users</CardTitle>
      </CardHeader>
      <CardBody>
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {scopeFor && (
        <DeviceScopeEditor
          user={scopeFor}
          devices={devices}
          onClose={() => setScopeFor(null)}
          onSaved={(userId, data) => setScopes((prev) => ({ ...prev, [userId]: data }))}
        />
      )}
      {users && users.length > 0 && (
        <Table>
          <thead>
            <tr>
              <th style={{ width: '26%' }}>Username</th>
              <th style={{ width: '14%' }}>Role</th>
              <th style={{ width: '22%' }}>Firewalls</th>
              <th style={{ width: '38%' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{u.username}</td>
                <td>
                  <Badge color={ROLE_BADGE[u.role] || 'muted'} title={ROLE_DESCRIPTIONS[u.role]}>
                    {ROLE_LABELS[u.role] || u.role}
                  </Badge>
                </td>
                {/* ⛔ "All firewalls" is the DEFAULT and is drawn neutrally,
                    not as a warning: it is how every account has always worked,
                    and tinting it would make the normal state look wrong. */}
                <td>
                  {(() => {
                    const sc = scopes[u.id];
                    if (!sc) return <span style={{ color: 'var(--unmeasured)' }}>&mdash;</span>;
                    if (sc.state !== 'scoped') {
                      return <span style={{ color: 'var(--text-secondary)' }}>All firewalls</span>;
                    }
                    return (
                      <span title={(sc.devices || []).map((d) => d.name).join(', ')}>
                        {sc.devices.length} of {devices.length}
                      </span>
                    );
                  })()}
                </td>
                <td style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <Button variant="secondary" onClick={() => setScopeFor(u)}>
                    Firewalls
                  </Button>
                  <select
                    className="select"
                    value={u.role}
                    onChange={(e) => handleRoleChange(u.id, e.target.value)}
                    style={{ width: 'auto' }}
                  >
                    {ASSIGNABLE_ROLES.map((r) => (
                      <option key={r} value={r}>{ROLE_LABELS[r]}</option>
                    ))}
                  </select>
                  <Button variant="secondary" onClick={() => handleResetPassword(u.id)}>
                    Reset Password
                  </Button>
                  <Button variant="danger" onClick={() => handleDelete(u.id, u.username)}>
                    Delete
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <form onSubmit={handleCreate} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div className="form-field">
          <label htmlFor="new_username">New user — username</label>
          <input
            id="new_username"
            type="text"
            value={newUsername}
            onChange={(e) => setNewUsername(e.target.value)}
            required
            className="input"
          />
        </div>
        <div className="form-field">
          <label htmlFor="new_user_password">Password</label>
          <input
            id="new_user_password"
            type="password"
            autoComplete="new-password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
            minLength={8}
            className="input"
          />
        </div>
        <div className="form-field">
          <label htmlFor="new_user_role">Role</label>
          <select
            id="new_user_role"
            className="select"
            value={newRole}
            onChange={(e) => setNewRole(e.target.value)}
          >
            {/* ⛔ Sourced from ASSIGNABLE_ROLES, like the per-row select above.
                This list was hardcoded and still offered `viewer`, a role the
                server no longer accepts — the form would have looked fine and
                then silently created an Operator instead. */}
            {ASSIGNABLE_ROLES.map((r) => (
              <option key={r} value={r}>{ROLE_LABELS[r]}</option>
            ))}
          </select>
        </div>

        {status && <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>{status}</p>}

        <Button type="submit" variant="primary" style={{ alignSelf: 'flex-start' }}>
          Add User
        </Button>
      </form>
    </div>
      </CardBody>
    </Card>
  );
}
