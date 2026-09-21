'use client';

import { useEffect, useState } from 'react';
import PageHeader from '../../../components/ui/PageHeader';
import Card, { CardHeader, CardTitle, CardBody } from '../../../components/ui/Card';
import Button from '../../../components/ui/Button';
import UpdatePanel from '../../../components/settings/UpdatePanel';
import LicensePanel from '../../../components/settings/LicensePanel';
import UsersPanel from '../../../components/settings/UsersPanel';
import LdapRolesPanel from '../../../components/settings/LdapRolesPanel';
import SecurityPanel from '../../../components/settings/SecurityPanel';
import SessionTimeoutPanel from '../../../components/settings/SessionTimeoutPanel';
import TlsPanel from '../../../components/settings/TlsPanel';
import ConsoleAddressPanel from '../../../components/settings/ConsoleAddressPanel';
import { capabilitiesOf } from '../../../lib/rbac';
import { PRODUCT_NAME, PRODUCT_TAGLINE } from '../../../lib/branding';
import CredentialProfilesPanel from '../../../components/settings/CredentialProfilesPanel';
import NotificationsPanel from '../../../components/settings/NotificationsPanel';
import AppearancePanel from '../../../components/settings/AppearancePanel';
import pkg from '../../../package.json';

// ⛔ `requires` is the capability needed to SEE the tab at all. A tab with no
// requirement is open to every authenticated role — today that is General
// (which holds per-user appearance and your own password, both self-service)
// and About.
//
// ⛔ Hiding a tab is NOT the security boundary. Every panel behind these tabs
// is backed by a route that checks the same capability server-side; this list
// exists so an Operator is not shown five doors that all refuse to open.
const TABS = [
  { key: 'general', label: 'General' },
  { key: 'security', label: 'Security' },
  { key: 'users', label: 'Users', requires: 'manage_users' },
  { key: 'profiles', label: 'Credential Profiles', requires: 'manage_credential_profiles' },
  { key: 'notifications', label: 'Notifications', requires: 'manage_settings' },
  { key: 'certificate', label: 'Certificate', requires: 'manage_settings' },
  // ⛔ VISIBLE TO EVERY ROLE, unlike the other administrative tabs. The panel
  // is where the Server ID lives, and an operator asked to read it off the
  // server for a renewal should not have to borrow a Super Admin account to
  // do it. Only the ACTIVATION controls are gated, by MANAGE_LICENSE, both in
  // the panel and in the route behind it.
  { key: 'subscription', label: 'Subscription' },
  { key: 'updates', label: 'Updates', requires: 'run_update' },
  { key: 'about', label: 'About' },
];

const ABOUT_ROWS = [
  ['Product', `${PRODUCT_NAME} — ${PRODUCT_TAGLINE}`],
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
  // ⛔ CAPABILITIES, NOT A ROLE COMPARISON. This was `role === 'admin'`, which
  // the three-role change would have quietly broken in the most confusing
  // direction possible: a SUPER ADMIN — the most privileged account — would have
  // failed that equality and lost the Updates, Notifications and Credential
  // Profile panels, while an ordinary admin kept them.
  //
  // Starts as an all-false object so the page fails CLOSED while the session is
  // still resolving, same posture as before.
  const [caps, setCaps] = useState(() => ({}));

  // ⛔ Derived, not stored. If the session resolves to fewer capabilities than
  // the tab currently open (a deep link to ?tab=users as an Operator), the
  // active tab must fall back to one that exists — otherwise the page renders
  // a tab bar with nothing under it, which looks like a broken page rather
  // than a restriction.
  const visibleTabs = TABS.filter((t) => !t.requires || caps[t.requires]);
  const effectiveTab = visibleTabs.some((t) => t.key === activeTab)
    ? activeTab
    : (visibleTabs[0] ? visibleTabs[0].key : 'general');

  useEffect(() => {
    let cancelled = false;

    async function loadSession() {
      try {
        const res = await fetch('/api/auth/session');
        const data = await res.json();
        // capabilitiesOf() takes a session-shaped object, which is exactly what
        // /api/auth/session returns.
        if (!cancelled) setCaps(capabilitiesOf(data));
      } catch {
        // Fail closed -- no capabilities if the session check itself errors.
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
        {visibleTabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            style={{
              padding: '9px 16px',
              fontSize: 'var(--text-md)',
              fontWeight: effectiveTab === tab.key ? 600 : 400,
              color: effectiveTab === tab.key ? 'var(--primary)' : 'var(--text-muted)',
              background: 'none',
              border: 'none',
              borderBottom: effectiveTab === tab.key ? '2px solid var(--primary)' : '2px solid transparent',
              cursor: 'pointer',
              marginBottom: '-1px',
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {effectiveTab === 'general' && (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(440px, 1fr))',
            gap: 24,
            alignItems: 'start',
            maxWidth: 1200,
          }}
        >
          <AppearancePanel />

          {/* ⛔ A GLOBAL app setting, so it is gated even though the tab that
              holds it is open to everyone. The General tab also carries the
              per-user Appearance controls and your own password, both of which
              are self-service and stay available to every role. */}
          {caps.manage_settings && (
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
                    disabled={loading || !caps.manage_settings}
                    value={feedPollIntervalHours}
                    onChange={(e) => setFeedPollIntervalHours(e.target.value)}
                    className="input"
                  />
                </div>

                {generalStatus && (
                  <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>{generalStatus}</p>
                )}

                {caps.manage_settings && (
                  <Button type="submit" variant="primary" style={{ alignSelf: 'flex-start' }}>
                    Save
                  </Button>
                )}
              </form>
            </CardBody>
          </Card>
          )}

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

      {effectiveTab === 'security' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s5)' }}>
          <SecurityPanel />
          {/* ⛔ SHOWN TO EVERY ROLE, EDITABLE ONLY WITH manage_settings. Every
              role is SUBJECT to the timeout, and someone signed out after half
              an hour who cannot find out why concludes the product is broken
              rather than that a policy is in force. */}
          <SessionTimeoutPanel canManage={Boolean(caps.manage_settings)} />
        </div>
      )}

      {effectiveTab === 'certificate' && caps.manage_settings && (
        /* The address sits BESIDE the certificate because that is when it
           matters: a new certificate for a new hostname is useless until
           SecVault is told it is reached on that hostname, and the two changes
           are made in the same sitting. */
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <TlsPanel />
          <ConsoleAddressPanel />
        </div>
      )}

      {effectiveTab === 'users' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s6)' }}>
          <UsersPanel />
          {/* ⛔ UNDER USERS, NOT SETTINGS, because it is gated on the SAME
              capability as the route behind it (manage_users, super_admin
              only). A mapping here says "everyone in this directory group
              administers the firewall platform", which is the same authority as
              creating an account — reached through a group whose membership
              SecVault cannot see. */}
          <LdapRolesPanel />
        </div>
      )}

      {effectiveTab === 'profiles' && caps.manage_credential_profiles && <CredentialProfilesPanel />}

      {effectiveTab === 'notifications' && caps.manage_settings && <NotificationsPanel />}

      {/* ⛔ No capability guard on the tab BODY either, matching the tab list.
          The panel self-gates its write controls on canManage, which the
          route computes from MANAGE_LICENSE — so what a reader can SEE here is
          exactly what the API would let them do, per this product's rule that a
          UI gate must never be stricter than the route it fronts. */}
      {effectiveTab === 'subscription' && (
        <div style={{ maxWidth: 760 }}>
          <LicensePanel />
        </div>
      )}

      {effectiveTab === 'updates' && caps.run_update && (
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

      {effectiveTab === 'about' && (
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
                  Standalone firewall intelligence and management platform.
                </p>
              </div>
            </CardBody>
          </Card>
        </div>
      )}
    </div>
  );
}
