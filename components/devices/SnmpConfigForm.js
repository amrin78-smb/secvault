'use client';

// SNMP monitoring config for one device — enable/disable, target host/port,
// and the SNMP credential (separate from the device's management-plane
// credential — see lib/adapters/interface.js's getSnmpMetrics() contract
// comment and CLAUDE.md's "SNMP Monitoring" section). Structurally mirrors
// CredentialForm.js (saved-profile picker + manual entry + "save as
// profile"), but for the 'snmp' credential_type and this device's own
// snmp_enabled/snmp_host/snmp_port columns instead of vendor/mgmt_method.

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Button from '../ui/Button';
import LoadingSpinner from '../ui/LoadingSpinner';

const SNMP_VERSION_OPTIONS = [
  { value: 'v3', label: 'SNMPv3 (recommended)' },
  { value: 'v2c', label: 'SNMPv2c (cleartext community string)' },
  { value: 'v1', label: 'SNMPv1 (cleartext community string)' },
];
const AUTH_PROTOCOL_OPTIONS = ['SHA', 'MD5'];
const PRIV_PROTOCOL_OPTIONS = ['AES', 'DES'];

// `detected` (optional): true when lib/engines/snmpConfigDetection.js found
// SNMP looking already-enabled in this device's own collected config — used
// ONLY to pre-check the "Enable" toggle as a convenience default on first
// landing (never to pre-fill a credential; the actual secret is never
// available to detect in the first place — see that module's header
// comment). Only applies while nothing is stored yet (`initial.snmpEnabled`
// is false) — never overrides an operator's own already-saved choice.
export default function SnmpConfigForm({ deviceId, vendor, initial, detected = false }) {
  const router = useRouter();
  const [enabled, setEnabled] = useState(Boolean(initial?.snmpEnabled) || detected);
  const [host, setHost] = useState(initial?.snmpHost || '');
  const [port, setPort] = useState(initial?.snmpPort ? String(initial.snmpPort) : '161');

  const [selectedProfileId, setSelectedProfileId] = useState('');
  const [profiles, setProfiles] = useState([]);

  const [snmpVersion, setSnmpVersion] = useState('v3');
  const [community, setCommunity] = useState('');
  const [username, setUsername] = useState('');
  const [authProtocol, setAuthProtocol] = useState('SHA');
  const [authPassword, setAuthPassword] = useState('');
  const [privProtocol, setPrivProtocol] = useState('AES');
  const [privPassword, setPrivPassword] = useState('');
  const [insecureAck, setInsecureAck] = useState(false);

  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState(null);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null); // { ok, text, metrics? }

  useEffect(() => {
    fetch('/api/credential-profiles')
      .then((res) => (res.ok ? res.json() : { profiles: [] }))
      .then((data) =>
        setProfiles(Array.isArray(data.profiles) ? data.profiles.filter((p) => p.credential_type === 'snmp') : [])
      )
      .catch(() => setProfiles([]));
  }, []);

  const isV3 = snmpVersion === 'v3';
  const isForcepoint = vendor === 'forcepoint';
  const hasCredentialInput = selectedProfileId
    ? true
    : isV3
      ? Boolean(username)
      : Boolean(community) && insecureAck;
  const hostRequired = isForcepoint && !host && !initial?.snmpHost;
  const ready = !hostRequired && (hasCredentialInput || Boolean(initial?.hasCredential));

  async function handleSave() {
    if (saving || (enabled && hostRequired)) return;
    setSaving(true);
    setResult(null);
    try {
      const body = { enabled, host: host || null, port: Number(port) || 161 };
      if (selectedProfileId) {
        body.credential_profile_id = selectedProfileId;
      } else if (hasCredentialInput) {
        body.snmp_version = snmpVersion;
        if (isV3) {
          body.username = username;
          if (authPassword) {
            body.auth_protocol = authProtocol;
            body.auth_password = authPassword;
            if (privPassword) {
              body.priv_protocol = privProtocol;
              body.priv_password = privPassword;
            }
          }
        } else {
          body.community = community;
          body.insecure_ack = insecureAck;
        }
      }
      const res = await fetch(`/api/devices/${deviceId}/snmp`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || 'Failed to save SNMP config');
      setResult({ ok: true, text: 'SNMP configuration saved.' });
      setCommunity('');
      setAuthPassword('');
      setPrivPassword('');
      setSelectedProfileId('');
      setTestResult(null);
      // Refreshes the server-rendered `initial` prop (in particular
      // hasCredential) so the "Test Connectivity" button below appears
      // immediately after a first-time save, without a manual reload.
      router.refresh();
    } catch (err) {
      setResult({ ok: false, text: err.message || 'Failed to save SNMP config' });
    } finally {
      setSaving(false);
    }
  }

  // Tests the ALREADY-SAVED SNMP credential against the live device — see
  // app/api/devices/[id]/snmp/test/route.js. Deliberately separate from
  // handleSave: mirrors DeviceActions.js's "Test Connectivity" pattern for
  // the device's main management credential (save first, then test what
  // was saved as its own action), not a pre-save dry run.
  async function handleTest() {
    if (testing) return;
    setTesting(true);
    setTestResult(null);
    try {
      const res = await fetch(`/api/devices/${deviceId}/snmp/test`, { method: 'POST' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || 'Test failed');
      setTestResult({ ok: data.ok === true, text: data.message || (data.ok ? 'Connected' : 'Test failed'), metrics: data.metrics });
      if (data.ok) router.refresh(); // a real snapshot was just recorded — refresh the trend chart/tiles above
    } catch (err) {
      setTestResult({ ok: false, text: err.message || 'Test failed' });
    } finally {
      setTesting(false);
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, maxWidth: 480 }}>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 'var(--text-base)' }}>
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        Enable SNMP polling for this device
      </label>

      {isForcepoint && (
        <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
          Forcepoint SNMP polls the individual firewall engine directly — a deliberate exception to the
          SMC-only rule (SNMP only; rule/config collection still goes exclusively through the SMC REST
          API). Enter the engine&apos;s own management IP below, not the SMC host.
        </p>
      )}

      <div className="form-field">
        <label htmlFor="snmp-host">
          SNMP Host {isForcepoint ? '(required — engine IP)' : '(optional — defaults to management IP)'}
        </label>
        <input
          id="snmp-host"
          type="text"
          value={host}
          onChange={(e) => setHost(e.target.value)}
          placeholder={isForcepoint ? 'e.g. 10.1.2.3' : 'defaults to management IP'}
          className="input"
        />
      </div>
      <div className="form-field">
        <label htmlFor="snmp-port">SNMP Port</label>
        <input
          id="snmp-port"
          type="number"
          value={port}
          onChange={(e) => setPort(e.target.value)}
          placeholder="161"
          className="input"
        />
      </div>

      {initial?.hasCredential && (
        <p style={{ fontSize: 'var(--text-xs)', color: 'var(--green)', margin: 0 }}>
          An SNMP credential is already stored for this device. Leave the fields below blank to keep it,
          or fill them in to rotate it.
        </p>
      )}

      {profiles.length > 0 && (
        <div className="form-field">
          <label htmlFor="snmp-profile">Use Saved Profile</label>
          <select
            id="snmp-profile"
            className="input"
            value={selectedProfileId}
            onChange={(e) => setSelectedProfileId(e.target.value)}
          >
            <option value="">— Enter credentials manually —</option>
            {profiles.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
                {p.username ? ` — ${p.username}` : ''}
              </option>
            ))}
          </select>
        </div>
      )}

      {!selectedProfileId && (
        <>
          <div className="form-field">
            <label htmlFor="snmp-version">SNMP Version</label>
            <select
              id="snmp-version"
              className="input"
              value={snmpVersion}
              onChange={(e) => {
                setSnmpVersion(e.target.value);
                setInsecureAck(false);
              }}
            >
              {SNMP_VERSION_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          {isV3 ? (
            <>
              <div className="form-field">
                <label htmlFor="snmp-username">Username</label>
                <input
                  id="snmp-username"
                  type="text"
                  autoComplete="off"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="input"
                />
              </div>
              <div className="form-field">
                <label htmlFor="snmp-auth-protocol">Auth Protocol</label>
                <select
                  id="snmp-auth-protocol"
                  className="input"
                  value={authProtocol}
                  onChange={(e) => setAuthProtocol(e.target.value)}
                >
                  {AUTH_PROTOCOL_OPTIONS.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
              </div>
              <div className="form-field">
                <label htmlFor="snmp-auth-password">Auth Password</label>
                <input
                  id="snmp-auth-password"
                  type="password"
                  autoComplete="new-password"
                  value={authPassword}
                  onChange={(e) => setAuthPassword(e.target.value)}
                  className="input"
                />
              </div>
              {authPassword && (
                <>
                  <div className="form-field">
                    <label htmlFor="snmp-priv-protocol">Privacy Protocol</label>
                    <select
                      id="snmp-priv-protocol"
                      className="input"
                      value={privProtocol}
                      onChange={(e) => setPrivProtocol(e.target.value)}
                    >
                      {PRIV_PROTOCOL_OPTIONS.map((p) => (
                        <option key={p} value={p}>
                          {p}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="form-field">
                    <label htmlFor="snmp-priv-password">Privacy Password</label>
                    <input
                      id="snmp-priv-password"
                      type="password"
                      autoComplete="new-password"
                      value={privPassword}
                      onChange={(e) => setPrivPassword(e.target.value)}
                      className="input"
                    />
                  </div>
                </>
              )}
            </>
          ) : (
            <>
              <div className="form-field">
                <label htmlFor="snmp-community">Community String</label>
                <input
                  id="snmp-community"
                  type="password"
                  autoComplete="new-password"
                  value={community}
                  onChange={(e) => setCommunity(e.target.value)}
                  className="input"
                />
              </div>
              <label
                style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 'var(--text-base)', color: 'var(--red)' }}
              >
                <input type="checkbox" checked={insecureAck} onChange={(e) => setInsecureAck(e.target.checked)} />
                I understand SNMP{snmpVersion} sends this community string in cleartext on the network.
              </label>
            </>
          )}
        </>
      )}

      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8 }}>
        <Button type="button" variant="primary" onClick={handleSave} disabled={saving || (enabled && hostRequired)}>
          {saving ? 'Saving…' : 'Save SNMP Configuration'}
        </Button>
        {initial?.hasCredential && (
          <Button type="button" variant="secondary" onClick={handleTest} disabled={testing}>
            {testing && <LoadingSpinner size={14} />}
            {testing ? 'Testing…' : 'Test Connectivity'}
          </Button>
        )}
      </div>
      {enabled && hostRequired && (
        <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
          Set an SNMP host before enabling polling for this device.
        </p>
      )}
      {result && (
        <span style={{ fontSize: 'var(--text-base)', color: result.ok ? 'var(--green)' : 'var(--red)' }}>
          {result.text}
        </span>
      )}
      {testResult && (
        <div>
          <span style={{ fontSize: 'var(--text-base)', color: testResult.ok ? 'var(--green)' : 'var(--red)' }}>
            {testResult.text}
          </span>
          {testResult.ok && testResult.metrics && (
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: '4px 0 0' }}>
              CPU {testResult.metrics.cpuPercent ?? '—'}% · Memory {testResult.metrics.memoryPercent ?? '—'}% ·
              Sessions {testResult.metrics.sessionCount ?? '—'} — recorded as a new data point above.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
