'use client';

// Settings -> Security -> Directory access.
//
// ⛔ THE WARNING IS THE POINT OF THIS PANEL, not the table. With LDAP switched
// on and no mappings configured, EVERY person who can bind to the directory is
// an Administrator of this firewall-management platform right now. That is the
// state the product shipped in for its whole life, and an empty table does not
// look like a problem — it looks like a feature nobody has used yet.

import { useEffect, useState } from 'react';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import Table from '../ui/Table';
import LoadingSpinner from '../ui/LoadingSpinner';

const ROLES = [
  { value: 'operator', label: 'Operator', hint: 'Act on findings. No administration.' },
  { value: 'admin', label: 'Administrator', hint: 'Manage firewalls and settings. Cannot manage accounts.' },
  { value: 'super_admin', label: 'Super Admin', hint: 'Everything, including accounts and this page.' },
];

const ROLE_LABEL = Object.fromEntries(ROLES.map((r) => [r.value, r.label]));
const ROLE_COLOR = { super_admin: 'danger', admin: 'warning', operator: 'info' };

export default function LdapRolesPanel() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [groupDn, setGroupDn] = useState('');
  const [role, setRole] = useState('operator');
  const [description, setDescription] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);

  async function load() {
    setLoading(true);
    try {
      const res = await fetch('/api/ldap-mappings');
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || 'Failed to read the mappings');
      setData(body);
      setLoadError(null);
    } catch (err) {
      // ⛔ Reported as unreadable, never as an empty list — an empty list here
      // means "legacy mode", which is a completely different fact.
      setData(null);
      setLoadError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function save() {
    setBusy(true);
    setNotice(null);
    try {
      const res = await fetch('/api/ldap-mappings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ groupDn, role, description }),
      });
      const body = await res.json();
      if (!res.ok) {
        setNotice({ tone: 'bad', text: body.error || 'The mapping was not saved.' });
      } else {
        setGroupDn('');
        setDescription('');
        setNotice(body.legacyModeEnded
          ? {
            tone: 'ok',
            text: 'Mapping saved — and this was the first one. Directory users who are not in a '
              + 'mapped group will now be refused at login instead of receiving Administrator.',
          }
          : { tone: 'ok', text: 'Mapping saved.' });
        await load();
      }
    } catch (err) {
      setNotice({ tone: 'bad', text: err.message || String(err) });
    } finally {
      setBusy(false);
    }
  }

  async function remove(m) {
    const last = data && data.mappings.length === 1;
    const msg = last
      ? `Remove the mapping for ${m.groupDn}?\n\nThis is the LAST mapping. Removing it returns `
        + 'SecVault to granting Administrator to every directory user who can sign in.'
      : `Remove the mapping for ${m.groupDn}?`;
    if (!window.confirm(msg)) return;
    setBusy(true);
    try {
      const res = await fetch(`/api/ldap-mappings?id=${encodeURIComponent(m.id)}`, { method: 'DELETE' });
      const body = await res.json();
      if (body.legacyModeReopened) {
        setNotice({
          tone: 'bad',
          text: 'The last mapping was removed. Every directory user will receive Administrator at '
            + 'their next sign-in.',
        });
      } else {
        setNotice(null);
      }
      await load();
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <LoadingSpinner />;

  if (loadError) {
    return (
      <Card>
        <CardBody>
          <div style={{ color: 'var(--sev-crit)', fontSize: 'var(--text-sm)' }}>
            The LDAP role mappings could not be read: {loadError}
          </div>
        </CardBody>
      </Card>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s5)' }}>

      {/* ── The state, first ──────────────────────────────────────────── */}
      {!data.ldapConfigured ? (
        <Card>
          <CardBody>
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              <strong>LDAP is not configured on this installation.</strong> Mappings can be prepared
              here, but nothing uses them until <code>LDAP_URL</code> is set in <code>.env.local</code>.
            </div>
          </CardBody>
        </Card>
      ) : null}

      {data.legacyModeActive ? (
        <Card>
          <CardBody style={{ background: 'var(--tint-danger)', color: 'var(--tint-danger-fg)' }}>
            <div style={{ fontWeight: 600, marginBottom: 'var(--s2)' }}>
              Every directory user is currently an Administrator.
            </div>
            <div style={{ fontSize: 'var(--text-sm)', lineHeight: 1.6 }}>
              No group-to-role mappings are configured, so anyone who can sign in against your
              directory receives the Administrator role — they can add and remove firewalls, change
              settings and trigger updates. This is how SecVault behaved before mappings existed, and
              it stays that way until you add the first one below. <strong>As soon as one mapping
              exists, a user in no mapped group is refused.</strong>
            </div>
          </CardBody>
        </Card>
      ) : null}

      {/* ⛔ A mapping cannot work without a service account, because the
          direct-bind fallback cannot SEARCH the directory and therefore cannot
          read anyone's group membership. Saying so here is the difference
          between "my mappings do nothing" and knowing why. */}
      {data.ldapConfigured && !data.bindAccountConfigured ? (
        <Card>
          <CardBody style={{ background: 'var(--tint-warn)', color: 'var(--tint-warn-fg)' }}>
            <div style={{ fontSize: 'var(--text-sm)', lineHeight: 1.6 }}>
              <strong>No directory service account is configured.</strong> Without
              {' '}<code>LDAP_BIND_DN</code> and <code>LDAP_BIND_PASSWORD</code>, SecVault cannot
              search the directory and cannot read anyone&rsquo;s group membership — so no mapping
              below can ever match, and every login will be refused once a mapping exists.
            </div>
          </CardBody>
        </Card>
      ) : null}

      {/* ── Mappings ──────────────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle>Directory group access</CardTitle>
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 'var(--s1)' }}>
            A user in several mapped groups receives the most privileged of them.
          </div>
        </CardHeader>
        <CardBody>
          {data.mappings.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
              No mappings configured.
            </div>
          ) : (
            <Table minWidth={720}>
              <colgroup>
                <col style={{ width: '52%' }} />
                <col style={{ width: '16%' }} />
                <col style={{ width: '22%' }} />
                <col style={{ width: '10%' }} />
              </colgroup>
              <thead>
                <tr>
                  <th>Group</th>
                  <th>Role</th>
                  <th>Note</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.mappings.map((m) => (
                  <tr key={m.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', wordBreak: 'break-all' }}>
                      {m.groupDn}
                    </td>
                    <td>
                      <Badge color={ROLE_COLOR[m.role] || 'muted'}>
                        {ROLE_LABEL[m.role] || m.role}
                      </Badge>
                    </td>
                    <td style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                      {m.description || <span style={{ color: 'var(--unmeasured)' }}>—</span>}
                    </td>
                    <td>
                      <Button variant="secondary" onClick={() => remove(m)} disabled={busy}>
                        Remove
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </CardBody>
      </Card>

      {/* ── Add ───────────────────────────────────────────────────────── */}
      <Card>
        <CardHeader><CardTitle>Add a mapping</CardTitle></CardHeader>
        <CardBody>
          <label style={{ display: 'block', fontSize: 'var(--text-sm)', marginBottom: 'var(--s2)' }}>
            Group distinguished name
          </label>
          <input
            type="text"
            value={groupDn}
            onChange={(e) => setGroupDn(e.target.value)}
            disabled={busy}
            placeholder="CN=Firewall Admins,OU=Groups,DC=example,DC=com"
            style={{
              width: '100%', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)',
              padding: 'var(--s2) var(--s3)', borderRadius: 'var(--radius)',
              border: '1px solid var(--border)', background: 'var(--bg-card)',
              color: 'var(--text-primary)',
            }}
          />
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 'var(--s1)' }}>
            Copy it from the group&rsquo;s Attribute Editor. Capitalisation and spaces around the
            commas do not matter.
          </div>

          <label style={{ display: 'block', fontSize: 'var(--text-sm)', margin: 'var(--s4) 0 var(--s2)' }}>
            Role
          </label>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            disabled={busy}
            style={{
              fontSize: 'var(--text-sm)', padding: 'var(--s2) var(--s3)',
              borderRadius: 'var(--radius)', border: '1px solid var(--border)',
              background: 'var(--bg-card)', color: 'var(--text-primary)',
            }}
          >
            {ROLES.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
          </select>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 'var(--s1)' }}>
            {(ROLES.find((r) => r.value === role) || {}).hint}
          </div>

          <label style={{ display: 'block', fontSize: 'var(--text-sm)', margin: 'var(--s4) 0 var(--s2)' }}>
            Note <span style={{ color: 'var(--text-muted)' }}>(optional)</span>
          </label>
          <input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            disabled={busy}
            placeholder="Network security team"
            style={{
              width: '100%', fontSize: 'var(--text-sm)', padding: 'var(--s2) var(--s3)',
              borderRadius: 'var(--radius)', border: '1px solid var(--border)',
              background: 'var(--bg-card)', color: 'var(--text-primary)',
            }}
          />

          <div style={{ marginTop: 'var(--s4)' }}>
            <Button onClick={save} disabled={busy || !groupDn.trim()}>
              {busy ? 'Saving…' : 'Add mapping'}
            </Button>
          </div>

          {notice ? (
            <div style={{
              marginTop: 'var(--s4)', padding: 'var(--s3)', borderRadius: 'var(--radius)',
              background: notice.tone === 'ok' ? 'var(--tint-success)' : 'var(--tint-danger)',
              color: notice.tone === 'ok' ? 'var(--tint-success-fg)' : 'var(--tint-danger-fg)',
              fontSize: 'var(--text-sm)', lineHeight: 1.6,
            }}
            >
              {notice.text}
            </div>
          ) : null}

          <div style={{
            marginTop: 'var(--s5)', paddingTop: 'var(--s4)',
            borderTop: '1px solid var(--border-light)',
            fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.6,
          }}
          >
            {/* ⛔ THE STALENESS WINDOW IS STATED, not hidden. Two different
                changes take effect at two different times, and an administrator
                who expects both to be instant will conclude a revocation
                silently failed. */}
            <strong>When a change takes effect.</strong> Editing a mapping here applies to every
            signed-in directory user immediately. Moving someone between groups in the directory
            applies at their next sign-in — SecVault reads group membership once, when they
            authenticate, rather than on every request.
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
