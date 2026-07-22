'use client';

import { useEffect, useState } from 'react';
import PageHeader from '../../../components/ui/PageHeader';
import Card, { CardHeader, CardTitle, CardBody } from '../../../components/ui/Card';
import Button from '../../../components/ui/Button';
import UpdatePanel from '../../../components/settings/UpdatePanel';
import UsersPanel from '../../../components/settings/UsersPanel';
import CredentialProfilesPanel from '../../../components/settings/CredentialProfilesPanel';
import pkg from '../../../package.json';

const TABS = [
  { key: 'general', label: 'General' },
  { key: 'users', label: 'Users' },
  { key: 'profiles', label: 'Credential Profiles' },
  { key: 'updates', label: 'Updates' },
  { key: 'about', label: 'About' },
];

const ABOUT_ROWS = [
  ['Product', 'SecVault — Firewall Security Platform'],
  ['Version', `v${pkg.version}`],
  ['Port', '3010'],
  ['Runtime', 'Node.js v20 · Next.js 14.2.35 · React 18.3'],
  ['Database', 'PostgreSQL 16'],
];

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState('general');

  const [feedPollIntervalHours, setFeedPollIntervalHours] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [loading, setLoading] = useState(true);
  const [generalStatus, setGeneralStatus] = useState('');
  const [passwordStatus, setPasswordStatus] = useState('');

  // Admin-only gate for the Feed Sync Save button and the Updates tab.
  // This page is (and stays) a plain 'use client' component with no
  // server-passed session prop, so — unlike the sibling pages that resolve
  // canWrite via getServerSession() server-side — role is read from
  // NextAuth's own built-in GET /api/auth/session endpoint. Defaults to
  // false (fail closed) until resolved, same "hidden until proven admin"
  // posture as UsersPanel's own self-gating `visible` state below.
  const [isAdminUser, setIsAdminUser] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function loadSession() {
      try {
        const res = await fetch('/api/auth/session');
        const data = await res.json();
        if (!cancelled) setIsAdminUser(data?.user?.role === 'admin');
      } catch {
        // Fail closed -- stay non-admin if the session check itself errors.
      }
    }

    loadSession();

    return () => {
      cancelled = true;
    };
  }, []);

  // Deep-link convenience only, read once on mount — after this, tab
  // switching is purely client-side state (matches the suite's own
  // Settings tab pattern; see SETTINGS-STANDARDIZATION.md).
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const tab = params.get('tab');
    if (tab && TABS.some((t) => t.key === tab)) {
      setActiveTab(tab);
    }
  }, []);

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
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24, width: '100%' }}>
      <PageHeader title="Settings" subtitle="Manage app configuration, users, and updates." />

      <div
        style={{
          display: 'flex',
          borderBottom: '1px solid var(--border)',
          marginBottom: 8,
          flexWrap: 'wrap',
          position: 'sticky',
          top: 0,
          zIndex: 20,
          background: 'var(--bg-primary)',
        }}
      >
        {TABS.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            style={{
              padding: '9px 16px',
              fontSize: 'var(--text-md)',
              fontWeight: activeTab === tab.key ? 600 : 400,
              color: activeTab === tab.key ? 'var(--primary)' : 'var(--text-muted)',
              background: 'none',
              border: 'none',
              borderBottom: activeTab === tab.key ? '2px solid var(--primary)' : '2px solid transparent',
              cursor: 'pointer',
              marginBottom: '-1px',
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'general' && (
        <div style={{ maxWidth: 576, display: 'flex', flexDirection: 'column', gap: 32 }}>
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
                    disabled={loading || !isAdminUser}
                    value={feedPollIntervalHours}
                    onChange={(e) => setFeedPollIntervalHours(e.target.value)}
                    className="input"
                  />
                </div>

                {generalStatus && (
                  <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>{generalStatus}</p>
                )}

                {isAdminUser && (
                  <Button type="submit" variant="primary" style={{ alignSelf: 'flex-start' }}>
                    Save
                  </Button>
                )}
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
        </div>
      )}

      {activeTab === 'users' && <UsersPanel />}

      {activeTab === 'profiles' && isAdminUser && <CredentialProfilesPanel />}

      {activeTab === 'updates' && isAdminUser && (
        <div style={{ maxWidth: 576 }}>
          <Card>
            <CardHeader>
              <CardTitle>Software Update</CardTitle>
            </CardHeader>
            <CardBody>
              <UpdatePanel />
            </CardBody>
          </Card>
        </div>
      )}

      {activeTab === 'about' && (
        <div style={{ maxWidth: 576 }}>
          <Card>
            <CardHeader>
              <CardTitle>About</CardTitle>
            </CardHeader>
            <CardBody>
              <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
                <tbody>
                  {ABOUT_ROWS.map(([label, value]) => (
                    <tr key={label} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td
                        style={{
                          padding: '10px 0',
                          fontSize: 'var(--text-base)',
                          color: 'var(--text-muted)',
                          width: '40%',
                        }}
                      >
                        {label}
                      </td>
                      <td
                        style={{
                          padding: '10px 0',
                          fontSize: 'var(--text-base)',
                          color: 'var(--text-primary)',
                        }}
                      >
                        {value}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <div style={{ marginTop: 20 }}>
                <p style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                  SecVault v{pkg.version}
                </p>
                <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', margin: '4px 0 0' }}>
                  Standalone firewall security and management platform.
                </p>
              </div>
            </CardBody>
          </Card>
        </div>
      )}
    </div>
  );
}
