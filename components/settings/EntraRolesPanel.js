'use client';

// components/settings/EntraRolesPanel.js
//
// Microsoft Entra ID group-to-role mappings. Phase 2 of
// .ai-codex/entra-sso-proposal.md.
//
// ⛔ A SEPARATE PANEL FROM LdapRolesPanel, DELIBERATELY. The two share an API
// and a table, and merging the UI was considered and rejected: an EMPTY
// MAPPING LIST MEANS THE OPPOSITE THING IN EACH. Empty LDAP mappings means
// every directory user is an Administrator right now; empty Entra mappings
// means nobody can sign in at all. Those are the single most important
// sentences on each panel, and one combined table would have to render both
// warnings over one list — or, worse, pick one. Two panels, two states, two
// unambiguous sentences.
//
// ⛔ The role dropdown is sourced from ASSIGNABLE_ROLES, not hardcoded — the
// Users panel shipped a hardcoded list that still offered `viewer` after the
// server stopped accepting it, and the form looked fine while silently
// creating an Operator.

import { useState, useEffect, useCallback } from 'react';
import Card, { CardBody, CardHeader } from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import { ASSIGNABLE_ROLES, ROLE_LABELS } from '../../lib/rbac';

export default function EntraRolesPanel() {
  const [data, setData] = useState(null);
  const [loadError, setLoadError] = useState('');
  const [groupId, setGroupId] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [role, setRole] = useState('operator');
  const [description, setDescription] = useState('');
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/ldap-mappings');
      if (!res.ok) {
        const b = await res.json().catch(() => ({}));
        setLoadError(b.error || `HTTP ${res.status}`);
        return;
      }
      setData(await res.json());
      setLoadError('');
    } catch (err) {
      setLoadError(err.message || String(err));
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function save() {
    setBusy(true);
    setStatus('');
    try {
      const res = await fetch('/api/ldap-mappings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: 'entra', groupDn: groupId, displayName, role, description }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setStatus(body.error || `HTTP ${res.status}`);
      } else {
        // ⛔ Said at the moment it becomes true. The FIRST Entra mapping is
        // what opens sign-in at all — the opposite of LDAP, where the first
        // mapping CLOSES access. Reporting it the same way would be backwards.
        setStatus(body.entraFirstMapping
          ? 'Saved. This is the first Entra mapping, so Entra sign-in is now open to this group.'
          : 'Saved.');
        setGroupId('');
        setDisplayName('');
        setDescription('');
        await load();
      }
    } catch (err) {
      setStatus(err.message || String(err));
    } finally {
      setBusy(false);
    }
  }

  async function remove(m) {
    const last = (data?.entraMappings || []).length === 1;
    // ⛔ The LAST mapping is a different act from any other removal: it does not
    // narrow access, it ENDS it for every Entra user. Said before, not after.
    const msg = last
      ? `Remove the mapping for ${m.displayName || m.groupDn}?\n\nThis is the LAST Entra mapping. `
        + 'Removing it means NO Entra user will be able to sign in.'
      : `Remove the mapping for ${m.displayName || m.groupDn}?`;
    if (!window.confirm(msg)) return;
    setBusy(true);
    try {
      const res = await fetch(`/api/ldap-mappings?id=${encodeURIComponent(m.id)}`, { method: 'DELETE' });
      if (!res.ok) {
        const b = await res.json().catch(() => ({}));
        setStatus(b.error || `HTTP ${res.status}`);
      } else {
        await load();
      }
    } finally {
      setBusy(false);
    }
  }

  if (loadError) {
    return (
      <Card>
        <CardBody>
          <div style={{ color: 'var(--sev-crit)', fontSize: 'var(--text-sm)' }}>
            The Entra role mappings could not be read: {loadError}
          </div>
        </CardBody>
      </Card>
    );
  }
  if (!data) return null;

  const mappings = data.entraMappings || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s5)' }}>

      {/* ⛔ NOT CONFIGURED IS NOT AN ERROR, and this says so in those words.
          This product installs air-gapped by design, where Entra is
          unreachable and that is correct. A red "not configured" banner would
          train operators to ignore the banner that matters. */}
      {!data.entraConfigured ? (
        <Card>
          <CardBody>
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              <strong>Entra ID single sign-on is not configured, which is not a fault.</strong>{' '}
              Mappings can be prepared here, but nothing uses them until{' '}
              <code>ENTRA_TENANT_ID</code>, <code>ENTRA_CLIENT_ID</code> and{' '}
              <code>ENTRA_CLIENT_SECRET</code> are all set in <code>.env.local</code>. Local
              sign-in is unaffected either way.
            </div>
          </CardBody>
        </Card>
      ) : null}

      {/* ⛔ THE INVERSE OF LDAP'S LEGACY WARNING. Empty here means NOBODY can
          sign in — a closed door, not an open one. It is tinted as warning
          rather than danger because the fail-closed state is SAFE; what it is
          not is discoverable from a table that simply looks empty. */}
      {data.entraNoMappings ? (
        <Card>
          <CardBody style={{ background: 'var(--tint-warn)', color: 'var(--tint-warn-fg)' }}>
            <div style={{ fontWeight: 600, marginBottom: 'var(--s2)' }}>
              No Entra user can sign in yet.
            </div>
            <div style={{ fontSize: 'var(--text-sm)', lineHeight: 1.6 }}>
              Entra is configured, but no group is mapped to a role — so every Entra sign-in is
              refused. Map at least one group below to open access. This is deliberately unlike
              LDAP, where an empty mapping list grants every directory user Administrator:
              SecVault has never shipped Entra sign-in, so there is no existing access to preserve
              and the safe default is to grant nothing.
            </div>
          </CardBody>
        </Card>
      ) : null}

      <Card>
        <CardHeader>Entra group access</CardHeader>
        <CardBody>
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--s4)', lineHeight: 1.6 }}>
            A user in several mapped groups receives the most privileged of them. A mapping change
            applies immediately; a change to a user&rsquo;s group membership in Entra applies at
            their next sign-in.
          </div>

          {mappings.length === 0 ? (
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              No Entra mappings configured.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
              {mappings.map((m) => (
                <div
                  key={m.id}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    gap: 'var(--s3)', padding: 'var(--s3)',
                    border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    {/* ⛔ THE NAME LEADS AND THE GUID FOLLOWS, because a GUID
                        alone is unadministrable — "which of these four is
                        Firewall Admins?" is not a question anyone can answer.
                        But the GUID is always SHOWN, because the name is only a
                        label this panel stores: Entra group names are mutable
                        and two groups may share one, so the id is the fact. */}
                    <div style={{ fontWeight: 600 }}>
                      {m.displayName || <span style={{ color: 'var(--unmeasured)' }}>Unnamed group</span>}
                    </div>
                    <div style={{
                      fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)',
                      color: 'var(--text-muted)', wordBreak: 'break-all',
                    }}>
                      {m.groupDn}
                    </div>
                    {m.description ? (
                      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>
                        {m.description}
                      </div>
                    ) : null}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--s3)', flexShrink: 0 }}>
                    <Badge>{ROLE_LABELS[m.role] || m.role}</Badge>
                    <Button variant="danger" onClick={() => remove(m)} disabled={busy}>Remove</Button>
                  </div>
                </div>
              ))}
            </div>
          )}

          <div className="form-grid" style={{ marginTop: 'var(--s5)' }}>
            <div className="form-field">
              <label htmlFor="entra_group_id">Entra group object ID</label>
              <input
                id="entra_group_id"
                className="input"
                value={groupId}
                onChange={(e) => setGroupId(e.target.value)}
                placeholder="8f4a1c2e-9b7d-4e6a-bc13-5d2f70a9e4c1"
                spellCheck={false}
              />
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 4 }}>
                Copy the <strong>Object ID</strong> from the group&rsquo;s Overview page in Entra,
                not the group name.
              </div>
            </div>
            <div className="form-field">
              <label htmlFor="entra_display_name">Group name (for this list only)</label>
              <input
                id="entra_display_name"
                className="input"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Firewall Admins"
              />
            </div>
            <div className="form-field">
              <label htmlFor="entra_role">Role</label>
              <select
                id="entra_role"
                className="select"
                value={role}
                onChange={(e) => setRole(e.target.value)}
              >
                {ASSIGNABLE_ROLES.map((r) => (
                  <option key={r} value={r}>{ROLE_LABELS[r]}</option>
                ))}
              </select>
            </div>
            <div className="form-field">
              <label htmlFor="entra_description">Note (optional)</label>
              <input
                id="entra_description"
                className="input"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
            {status ? (
              <div className="span-2" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>{status}</div>
            ) : null}
            <div className="span-2">
              <Button variant="primary" onClick={save} disabled={busy || !groupId.trim()}>
                Add mapping
              </Button>
            </div>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
