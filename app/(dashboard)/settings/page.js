'use client';

import { useEffect, useState } from 'react';
import PageHeader from '../../../components/ui/PageHeader';
import Card, { CardHeader, CardTitle, CardBody } from '../../../components/ui/Card';
import Button from '../../../components/ui/Button';
import UpdatePanel from '../../../components/settings/UpdatePanel';
import UsersPanel from '../../../components/settings/UsersPanel';

export default function SettingsPage() {
  const [feedPollIntervalHours, setFeedPollIntervalHours] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [loading, setLoading] = useState(true);
  const [generalStatus, setGeneralStatus] = useState('');
  const [passwordStatus, setPasswordStatus] = useState('');

  useEffect(() => {
    let cancelled = false;

    async function loadSettings() {
      try {
        const res = await fetch('/api/settings');
        const data = await res.json();
        if (!cancelled) {
          setFeedPollIntervalHours(data.feed_poll_interval_hours || '');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadSettings();

    return () => {
      cancelled = true;
    };
  }, []);

  async function handleGeneralSubmit(e) {
    e.preventDefault();
    setGeneralStatus('Saving...');

    const res = await fetch('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ feed_poll_interval_hours: feedPollIntervalHours }),
    });

    if (res.ok) {
      setGeneralStatus('Saved.');
    } else {
      const data = await res.json().catch(() => ({}));
      setGeneralStatus(data.error || 'Failed to save settings.');
    }
  }

  async function handlePasswordSubmit(e) {
    e.preventDefault();
    setPasswordStatus('Saving...');

    const res = await fetch('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    });

    const data = await res.json().catch(() => ({}));

    if (res.ok) {
      setPasswordStatus('Password updated.');
      setCurrentPassword('');
      setNewPassword('');
    } else {
      setPasswordStatus(data.error || 'Failed to update password.');
    }
  }

  return (
    <div style={{ maxWidth: 576, display: 'flex', flexDirection: 'column', gap: 32 }}>
      <PageHeader title="Settings" />

      <Card>
        <CardHeader>
          <CardTitle>Feed Sync</CardTitle>
        </CardHeader>
        <CardBody>
          <form onSubmit={handleGeneralSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="form-field">
              <label htmlFor="feed_poll_interval_hours">Feed poll interval (hours)</label>
              <input
                id="feed_poll_interval_hours"
                type="number"
                min="1"
                disabled={loading}
                value={feedPollIntervalHours}
                onChange={(e) => setFeedPollIntervalHours(e.target.value)}
                className="input"
              />
            </div>

            {generalStatus && (
              <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>{generalStatus}</p>
            )}

            <Button type="submit" variant="primary" style={{ alignSelf: 'flex-start' }}>
              Save
            </Button>
          </form>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Change Your Password</CardTitle>
        </CardHeader>
        <CardBody>
          <form onSubmit={handlePasswordSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="form-field">
              <label htmlFor="current_password">Current password</label>
              <input
                id="current_password"
                type="password"
                autoComplete="current-password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                required
                className="input"
              />
            </div>

            <div className="form-field">
              <label htmlFor="new_password">New password</label>
              <input
                id="new_password"
                type="password"
                autoComplete="new-password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                minLength={8}
                className="input"
              />
            </div>

            {passwordStatus && (
              <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>{passwordStatus}</p>
            )}

            <Button type="submit" variant="primary" style={{ alignSelf: 'flex-start' }}>
              Update Password
            </Button>
          </form>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Software Update</CardTitle>
        </CardHeader>
        <CardBody>
          <UpdatePanel />
        </CardBody>
      </Card>

      <UsersPanel />
    </div>
  );
}
