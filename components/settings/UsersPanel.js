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
import Button from '../ui/Button';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';

const ROLE_BADGE = { admin: 'danger', viewer: 'muted' };

export default function UsersPanel() {
  const [users, setUsers] = useState(null); // null = loading/forbidden, [] = loaded
  const [visible, setVisible] = useState(false);
  const [status, setStatus] = useState('');
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('viewer');

  async function loadUsers() {
    const res = await fetch('/api/users');
    if (res.status === 403) {
      setVisible(false);
      setUsers(null);
      return;
    }
    const data = await res.json().catch(() => ({}));
    setUsers(data.users || []);
    setVisible(true);
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
      setNewRole('viewer');
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

  return (
    <Card>
      <CardHeader>
        <CardTitle>Users</CardTitle>
      </CardHeader>
      <CardBody>
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {users && users.length > 0 && (
        <Table>
          <thead>
            <tr>
              <th style={{ width: '40%' }}>Username</th>
              <th style={{ width: '20%' }}>Role</th>
              <th style={{ width: '40%' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{u.username}</td>
                <td>
                  <Badge color={ROLE_BADGE[u.role] || 'muted'}>{u.role}</Badge>
                </td>
                <td style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <select
                    className="select"
                    value={u.role}
                    onChange={(e) => handleRoleChange(u.id, e.target.value)}
                    style={{ width: 'auto' }}
                  >
                    <option value="admin">admin</option>
                    <option value="viewer">viewer</option>
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
            <option value="viewer">viewer (read-only)</option>
            <option value="admin">admin (full access)</option>
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
