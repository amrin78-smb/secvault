'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import PageHeader from '../../../components/ui/PageHeader';
import Card, { CardHeader, CardTitle, CardBody } from '../../../components/ui/Card';
import Button from '../../../components/ui/Button';
import UpdatePanel from '../../../components/settings/UpdatePanel';
import LicensePanel from '../../../components/settings/LicensePanel';
import UsersPanel from '../../../components/settings/UsersPanel';
import LdapRolesPanel from '../../../components/settings/LdapRolesPanel';
import EntraSsoPanel from '../../../components/settings/EntraSsoPanel';
import EntraRolesPanel from '../../../components/settings/EntraRolesPanel';
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
import {
  SETTINGS_TABS, visibleSettingsGroups, visibleSettingsTabs, resolveSettingsTab,
} from '../../../lib/settingsTabs';

// ⛔ THE TAB LIST MOVED TO lib/settingsTabs.js AND GREW A GROUPING. Ten
// tabs sat in one flat row, and the two an ordinary operator could open both
// MIXED their own settings with the whole installation's — Appearance and
// your password beside the server's feed schedule, your MFA beside the idle
// timeout that signs out every user. Three groups now: My preferences,
// Administration, System. See that file for why the session timeout stayed
// personal when the feed schedule did not.
//
// ⛔ Hiding a tab is NOT the security boundary. Every panel behind these is
// backed by a route that checks the same capability server-side; the list
// exists so an Operator is not shown five doors that all refuse to open.

const ABOUT_ROWS = [
  ['Product', `${PRODUCT_NAME} — ${PRODUCT_TAGLINE}`],
  ['Version', `v${pkg.version}`],
  ['Port', '3010'],
  ['Runtime', 'Node.js v20 · Next.js 14.2.35 · React 18.3'],
  ['Database', 'PostgreSQL 16'],
];

export default function SettingsPage() {
  // ⛔ THE URL IS THE TAB (v2.221.0). This was `useState('general')` plus a
  // mount-only effect that read `?tab=` exactly once — which meant a link
  // INTO a tab worked only if you were not already on Settings. The command
  // palette now offers all eleven tabs as destinations, so navigating from
  // /settings?tab=general to /settings?tab=users changed the address bar and
  // nothing else: the palette would have looked broken on the one page it
  // was just taught about.
  //
  // ⛔ IT ALSO MAKES BACK WORK. Tab state was client-only, so the browser's
  // Back button left Settings entirely rather than returning to the previous
  // tab, and a tab could not be linked to from anywhere. Reading the URL is
  // what every other multi-view surface in this product already does
  // (?tab= on the device pages, ?vtab= on VPN, ?view= on topology).
  const urlParams = useSearchParams();
  const activeTab = resolveSettingsTab(urlParams.get('tab'));
  const router = useRouter();
  const setActiveTab = useCallback((key) => {
    // replace, not push: eleven tabs would otherwise fill the history with
    // steps nobody wants to walk back through one at a time.
    router.replace(`/settings?tab=${key}`, { scroll: false });
  }, [router]);

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
  const groups = visibleSettingsGroups(caps);
  const visibleTabs = visibleSettingsTabs(caps);
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
    // ⛔ gap 24 -> 0 AND the header's own margin suppressed, because the space
    // between the title and the tab bar was THREE spacings stacked: this flex
    // gap (24), .page-header's own margin-bottom (20), and the 24px of padding
    // the sticky tab bar carries to cover the scroller's top padding (see the
    // ⛔ block on that element). About 68px of nothing.
    //
    // ⛔ THE TAB BAR'S PADDING IS NOT NEGOTIABLE — remove it and page content
    // scrolls visibly through the band above the stuck bar again (v2.209.1).
    // So the two REDUNDANT spacings go instead: the flex gap here was doing the
    // same job as the header's margin, and `.settings-head` zeroes that margin
    // for this page only, leaving the bar's padding as the single separator.
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0, width: '100%' }}>
      <div className="settings-head">
        <PageHeader title="Settings" subtitle="Manage app configuration, users, and updates." />
      </div>

      {/* ⛔ A VERTICAL RAIL, NOT A GROUPED HORIZONTAL ROW — AND THE HORIZONTAL
          VERSION'S OWN COMMENT CLAIMED IT "never reads as a disabled tab".
          It did. Reported by the person using it: "seems like an unfinished
          non-clickable menu."

          ⛔ THE REASON IS STRUCTURAL, NOT A MATTER OF STYLING IT HARDER. A
          label placed BEFORE items on one horizontal baseline is read as a
          PEER of those items — the eye groups by position first and by type
          treatment second, so "MY PREFERENCES" sitting to the left of
          "Appearance" at the same height reads as a tab that happens to be
          greyed out. The same label ABOVE a vertical list reads as a heading,
          because the list's left edge makes the hierarchy explicit. That is
          why essentially every settings UI with groups is vertical, and no
          amount of tracking, size or colour fixes the horizontal case.

          ⛔ IT ALSO FIXES A PROBLEM THE ROW ALREADY HAD. Eleven tabs plus
          three labels is a long row; at narrow widths it wrapped into two
          ragged lines whose second line had no heading at all. A rail has
          room for every label at any width, and the panels it sits beside are
          narrow by nature. */}
      <div className="settings-layout">
        <nav className="settings-rail" aria-label="Settings sections">
          {groups.map((g) => (
            <div key={g.key} className="settings-rail-group">
              {/* ⛔ A REAL HEADING, not a styled <span>. A screen reader now
                  announces the grouping that the eye gets from the indent. */}
              <h2 className="settings-rail-label" id={`settings-group-${g.key}`}>{g.label}</h2>
              <ul className="settings-rail-list" aria-labelledby={`settings-group-${g.key}`}>
                {g.tabs.map((tab) => (
                  <li key={tab.key}>
                    <button
                      type="button"
                      className="settings-rail-item"
                      data-active={effectiveTab === tab.key ? '' : undefined}
                      aria-current={effectiveTab === tab.key ? 'page' : undefined}
                      onClick={() => setActiveTab(tab.key)}
                    >
                      {tab.label}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>

        <div className="settings-panel">

      {/* ⛔ APPEARANCE ONLY NOW. This tab held Appearance (yours), Change
          password (yours) AND Feed Sync (the server's collection schedule,
          affecting every user) in one two-column grid — and it is the tab with
          no capability requirement, so every role met a global control beside
          their own theme picker. Feed Sync moved to Administration; the
          password moved to My account, beside the second factor it belongs
          with. */}
      {effectiveTab === 'general' && <AppearancePanel />}

      {/* ⛔ "MY ACCOUNT" — the things that are yours and nobody else's: your
          password and your second factor, which were in two different tabs.
          ⛔ THE KEY IS STILL `security`, so every ?tab=security link already
          written down lands on the control it always did. */}
      {effectiveTab === 'security' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s5)' }}>
          <SecurityPanel />
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
          {/* ⛔ SHOWN TO EVERY ROLE, EDITABLE ONLY WITH manage_settings. Every
              role is SUBJECT to the timeout, and someone signed out after half
              an hour who cannot find out why concludes the product is broken
              rather than that a policy is in force. */}
          <SessionTimeoutPanel canManage={Boolean(caps.manage_settings)} />
        </div>
      )}

      {/* ⛔ MOVED OUT OF GENERAL. The feed poll interval is the server's
          collection schedule; it has no personal aspect at all and was living
          in the one tab every role can open. The capability check is on the
          TAB now rather than wrapped around the card, so an Operator is not
          shown a heading over a control that is not there. */}
      {effectiveTab === 'feeds' && caps.manage_settings && (
        <div style={{ maxWidth: 620 }}>
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
        </div>
      )}

      {effectiveTab === 'signon' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s6)' }}>
          {/* ⛔ ENTRA FIRST, LDAP SECOND, and that is not alphabetical or
              chronological — it is the order of consequence. Entra is the path
              a new installation is actually set up on; LDAP is the legacy one,
              and its panel carries the loudest warning in the product (with
              zero mappings, EVERY directory user is an Administrator). Putting
              the legacy integration first buried the thing most people came to
              configure under four screens of something most of them do not
              use — which is what made the old Users tab unusable. */}

          {/* ⛔ CONFIGURATION ABOVE MAPPINGS, because that is the order the
              work happens in: a mapping is meaningless until a tenant exists,
              and the mapping panel's own "not configured" notice points at
              exactly the panel above it. */}
          <EntraSsoPanel />
          {/* ⛔ A SEPARATE PANEL from the LDAP one below, not a tab inside it:
              an empty mapping list means the OPPOSITE thing for each directory
              (LDAP empty = everyone is an Administrator; Entra empty = nobody
              can sign in), and those two sentences cannot share one table
              without one of them becoming ambiguous. */}
          <EntraRolesPanel />
          {/* ⛔ GATED ON manage_users LIKE THE REST OF THIS TAB, because the
              route behind it is. A mapping here says "everyone in this
              directory group administers the firewall platform" — the same
              authority as creating an account, reached through a group whose
              membership SecVault cannot see. */}
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
      </div>
    </div>
  );
}
