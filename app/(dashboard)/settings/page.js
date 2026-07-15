'use client';

import { useEffect, useState } from 'react';

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
    <div className="max-w-xl space-y-8">
      <h1 className="text-xl font-semibold text-text-primary">Settings</h1>

      <section className="rounded-lg border border-border bg-bg-surface p-6">
        <h2 className="mb-4 text-sm font-medium text-text-primary">Feed Sync</h2>
        <form onSubmit={handleGeneralSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="feed_poll_interval_hours"
              className="mb-1 block text-sm text-text-secondary"
            >
              Feed poll interval (hours)
            </label>
            <input
              id="feed_poll_interval_hours"
              type="number"
              min="1"
              disabled={loading}
              value={feedPollIntervalHours}
              onChange={(e) => setFeedPollIntervalHours(e.target.value)}
              className="w-full rounded-md border border-border bg-bg-elevated px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
            />
          </div>

          {generalStatus && <p className="text-sm text-text-secondary">{generalStatus}</p>}

          <button
            type="submit"
            className="rounded-md bg-accent px-3 py-2 text-sm font-medium text-white hover:bg-accent-hover transition-colors"
          >
            Save
          </button>
        </form>
      </section>

      <section className="rounded-lg border border-border bg-bg-surface p-6">
        <h2 className="mb-4 text-sm font-medium text-text-primary">Change Admin Password</h2>
        <form onSubmit={handlePasswordSubmit} className="space-y-4">
          <div>
            <label htmlFor="current_password" className="mb-1 block text-sm text-text-secondary">
              Current password
            </label>
            <input
              id="current_password"
              type="password"
              autoComplete="current-password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
              className="w-full rounded-md border border-border bg-bg-elevated px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
            />
          </div>

          <div>
            <label htmlFor="new_password" className="mb-1 block text-sm text-text-secondary">
              New password
            </label>
            <input
              id="new_password"
              type="password"
              autoComplete="new-password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              minLength={8}
              className="w-full rounded-md border border-border bg-bg-elevated px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
            />
          </div>

          {passwordStatus && <p className="text-sm text-text-secondary">{passwordStatus}</p>}

          <button
            type="submit"
            className="rounded-md bg-accent px-3 py-2 text-sm font-medium text-white hover:bg-accent-hover transition-colors"
          >
            Update Password
          </button>
        </form>
      </section>
    </div>
  );
}
