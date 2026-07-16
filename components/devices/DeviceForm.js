'use client';

import { useState } from 'react';
import Button from '../ui/Button';
import {
  VENDOR_META,
  VENDOR_SLUGS,
  buildCredentialPlaintext,
  resolveAccessMethod,
  hasMultipleAccessMethods,
} from './vendorMeta';

const CRITICALITY_OPTIONS = [
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' },
];

const AUTH_MODE_OPTIONS = [
  { value: 'apikey', label: 'API Key / Token' },
  { value: 'userpass', label: 'Username & Password' },
];

// Add device form, driven by VENDOR_META (frozen Tier 1 vendor table).
//
// Two independent axes, both sourced from VENDOR_META — do not conflate them:
//   meta.connection  → PER VENDOR. 'smc' uses smc_host/smc_port, 'mgmt' uses
//                      mgmt_ip/mgmt_port. Never changes with the access method.
//   accessMethod     → PER VENDOR+METHOD. Drives the port default, the
//                      credential_type, the credential input shape, and whether
//                      the self-signed SSL toggle is meaningful. Sent as
//                      mgmt_method and validated server-side against
//                      VENDOR_META[vendor].accessMethods.
//
// Forcepoint keeps the original behavior: Save is only enabled once a
// "Test Connectivity" call against POST /api/devices/test-smc has succeeded in this
// session, and any change to a connection-relevant field invalidates the previous
// test result so a stale "Connected" state can never be carried into Save.
// Other vendors have no pre-save test endpoint yet, so Save is gated only on the
// required fields being present.
export default function DeviceForm({ onSubmit }) {
  const [name, setName] = useState('');
  const [vendor, setVendor] = useState('forcepoint');
  const [accessMethod, setAccessMethod] = useState(VENDOR_META.forcepoint.defaultAccessMethod);
  const [smcHost, setSmcHost] = useState('');
  const [smcPort, setSmcPort] = useState('');
  const [mgmtIp, setMgmtIp] = useState('');
  const [mgmtPort, setMgmtPort] = useState('');
  const [authMode, setAuthMode] = useState('apikey');
  const [secret, setSecret] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [enablePassword, setEnablePassword] = useState('');
  const [allowSelfSignedSsl, setAllowSelfSignedSsl] = useState(true);
  const [site, setSite] = useState('');
  const [assetCriticality, setAssetCriticality] = useState('medium');

  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null); // { ok, message, engineCount }
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');

  const meta = VENDOR_META[vendor] || VENDOR_META.forcepoint;
  // resolveAccessMethod falls back to the vendor's default when accessMethod is
  // stale (e.g. mid-render right after a vendor switch), so `config` is never
  // undefined and the port/credential UI can never key off garbage.
  const { method, config } = resolveAccessMethod(vendor, accessMethod) ||
    resolveAccessMethod('forcepoint', null);

  const isSmc = meta.connection === 'smc';
  const showMethodSelector = hasMultipleAccessMethods(vendor);
  const shape = config.credentialShape;
  const isSecretShape = shape === 'secret';
  const isApiKeyOrUserPass = shape === 'apikey_or_userpass';
  const hasEnable = shape === 'userpass_enable';
  // A single secret input is shown for 'secret', and for 'apikey_or_userpass'
  // while the operator has the API-key mode selected.
  const showSecretInput = isSecretShape || (isApiKeyOrUserPass && authMode === 'apikey');
  // "Allow Self-Signed SSL" only means anything for TLS transports. SSH does not
  // present an X.509 cert, so the toggle is hidden (and left at its default) for
  // ssh methods rather than implying it has an effect.
  const showSslToggle = method !== 'ssh';

  function invalidateTest() {
    setTestResult(null);
  }

  // Clearing the credential inputs on any vendor/method switch is deliberate: the
  // credential SHAPE changes with the method (an API token is not an SSH
  // password), so carrying a value across would silently store the wrong thing.
  function resetCredentialInputs() {
    setAuthMode('apikey');
    setSecret('');
    setUsername('');
    setPassword('');
    setEnablePassword('');
  }

  // Both ports are cleared back to "" — an empty port field means "use this
  // method's default", which is what the placeholder shows and what handleSubmit
  // resolves it to. This is the reset the task calls for: fortinet api (443) →
  // ssh (22) must not leave 443 behind.
  //
  // Judgement call: this DOES discard a port the operator typed by hand. That is
  // the intended trade. The field is never silently wrong — it returns to a
  // visible, labelled default (the placeholder updates to 22), and switching
  // vendor or access method is a deliberate, rare act after which a previously
  // typed port is almost certainly meaningless. Preserving a "deliberate" 443
  // across an api→ssh switch is exactly the silent-connect-failure trap this
  // reset exists to close; retyping a custom port costs seconds, debugging an
  // SSH device that dials 443 costs an afternoon.
  function resetPorts() {
    setSmcPort('');
    setMgmtPort('');
  }

  function handleVendorChange(nextVendor) {
    setVendor(nextVendor);
    // The previous method almost never exists on the new vendor; resolve to the
    // new vendor's default rather than leaving a value its accessMethods lack.
    const nextMeta = VENDOR_META[nextVendor];
    setAccessMethod(nextMeta ? nextMeta.defaultAccessMethod : 'smc');
    resetPorts();
    resetCredentialInputs();
    invalidateTest();
  }

  function handleAccessMethodChange(nextMethod) {
    setAccessMethod(nextMethod);
    resetPorts();
    resetCredentialInputs();
    invalidateTest();
  }

  async function handleTest() {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await fetch('/api/devices/test-smc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          smc_host: smcHost,
          smc_port: Number(smcPort) || config.defaultPort,
          api_key: secret,
          allow_self_signed_ssl: allowSelfSignedSsl,
        }),
      });
      const data = await res.json().catch(() => ({}));
      setTestResult({
        ok: Boolean(data.ok),
        message: data.message || (data.ok ? 'Connected' : 'Connection test failed'),
        engineCount: data.engineCount,
      });
    } catch (err) {
      setTestResult({ ok: false, message: err.message || 'Connection test failed' });
    } finally {
      setTesting(false);
    }
  }

  // Forcepoint keeps the test-before-save gate; other vendors can save directly.
  const saveBlocked = isSmc ? !testResult?.ok : false;

  const credentialProvided = showSecretInput ? Boolean(secret) : Boolean(username && password);

  async function handleSubmit(e) {
    e.preventDefault();
    if (saveBlocked || submitting) return;

    setSubmitting(true);
    setSubmitError('');
    try {
      const payload = {
        name,
        vendor,
        mgmt_method: method,
        allow_self_signed_ssl: allowSelfSignedSsl,
        site,
        asset_criticality: assetCriticality,
      };
      // Connection fields key off the VENDOR (meta.connection), never the method.
      if (isSmc) {
        payload.smc_host = smcHost;
        payload.smc_port = Number(smcPort) || config.defaultPort;
      } else {
        payload.mgmt_ip = mgmtIp;
        payload.mgmt_port = Number(mgmtPort) || config.defaultPort;
      }
      if (credentialProvided) {
        payload.credential = buildCredentialPlaintext(vendor, method, {
          authMode,
          secret,
          username,
          password,
          enablePassword,
        });
        // The server re-derives credential_type from (vendor, mgmt_method) and
        // does not trust this value beyond its CREDENTIAL_TYPES check.
        payload.credential_type = config.credentialType;
      }
      await onSubmit(payload);
    } catch (err) {
      setSubmitError(err.message || 'Failed to save device');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="form-field">
        <label htmlFor="device-name">Name</label>
        <input
          id="device-name"
          type="text"
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="input"
        />
      </div>

      <div className="form-field">
        <label htmlFor="device-vendor">Vendor</label>
        <select
          id="device-vendor"
          value={vendor}
          onChange={(e) => handleVendorChange(e.target.value)}
          className="input"
        >
          {VENDOR_SLUGS.map((slug) => (
            <option key={slug} value={slug}>
              {VENDOR_META[slug].label}
            </option>
          ))}
        </select>
      </div>

      {showMethodSelector && (
        <div className="form-field">
          <label htmlFor="device-access-method">Access Method</label>
          <select
            id="device-access-method"
            value={method}
            onChange={(e) => handleAccessMethodChange(e.target.value)}
            className="input"
          >
            {Object.entries(meta.accessMethods).map(([key, cfg]) => (
              <option key={key} value={key}>
                {cfg.label}
              </option>
            ))}
          </select>
        </div>
      )}

      {isSmc ? (
        <>
          <div className="form-field">
            <label htmlFor="device-smc-host">SMC Host</label>
            <input
              id="device-smc-host"
              type="text"
              required
              value={smcHost}
              onChange={(e) => {
                setSmcHost(e.target.value);
                invalidateTest();
              }}
              className="input"
            />
          </div>

          <div className="form-field">
            <label htmlFor="device-smc-port">SMC Port</label>
            <input
              id="device-smc-port"
              type="number"
              placeholder={String(config.defaultPort)}
              value={smcPort}
              onChange={(e) => {
                setSmcPort(e.target.value);
                invalidateTest();
              }}
              className="input"
            />
          </div>
        </>
      ) : (
        <>
          <div className="form-field">
            <label htmlFor="device-mgmt-ip">Management IP / Host</label>
            <input
              id="device-mgmt-ip"
              type="text"
              required
              value={mgmtIp}
              onChange={(e) => setMgmtIp(e.target.value)}
              className="input"
            />
          </div>

          <div className="form-field">
            <label htmlFor="device-mgmt-port">Management Port</label>
            <input
              id="device-mgmt-port"
              type="number"
              placeholder={String(config.defaultPort)}
              value={mgmtPort}
              onChange={(e) => setMgmtPort(e.target.value)}
              className="input"
            />
          </div>
        </>
      )}

      {isApiKeyOrUserPass && (
        <div className="form-field">
          <label htmlFor="device-auth-mode">Authentication</label>
          <select
            id="device-auth-mode"
            value={authMode}
            onChange={(e) => {
              setAuthMode(e.target.value);
              // The two modes have disjoint inputs — don't carry a half-typed
              // token into a username/password submission or vice versa.
              setSecret('');
              setUsername('');
              setPassword('');
              invalidateTest();
            }}
            className="input"
          >
            {AUTH_MODE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      )}

      {showSecretInput ? (
        <div className="form-field">
          <label htmlFor="device-secret">{config.secretLabel}</label>
          <input
            id="device-secret"
            type="password"
            autoComplete="new-password"
            value={secret}
            onChange={(e) => {
              setSecret(e.target.value);
              invalidateTest();
            }}
            className="input"
          />
        </div>
      ) : (
        <>
          <div className="form-field">
            <label htmlFor="device-cred-username">Username</label>
            <input
              id="device-cred-username"
              type="text"
              autoComplete="off"
              value={username}
              onChange={(e) => {
                setUsername(e.target.value);
                invalidateTest();
              }}
              className="input"
            />
          </div>

          <div className="form-field">
            <label htmlFor="device-cred-password">Password</label>
            <input
              id="device-cred-password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                invalidateTest();
              }}
              className="input"
            />
          </div>

          {hasEnable && (
            <div className="form-field">
              <label htmlFor="device-cred-enable">Enable Password (optional)</label>
              <input
                id="device-cred-enable"
                type="password"
                autoComplete="new-password"
                value={enablePassword}
                onChange={(e) => setEnablePassword(e.target.value)}
                className="input"
              />
            </div>
          )}
        </>
      )}

      {showSslToggle && (
        <label
          style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}
        >
          <input
            type="checkbox"
            checked={allowSelfSignedSsl}
            onChange={(e) => {
              setAllowSelfSignedSsl(e.target.checked);
              invalidateTest();
            }}
          />
          Allow Self-Signed SSL
        </label>
      )}

      <div className="form-field">
        <label htmlFor="device-site">Site</label>
        <input
          id="device-site"
          type="text"
          value={site}
          onChange={(e) => setSite(e.target.value)}
          className="input"
        />
      </div>

      <div className="form-field">
        <label htmlFor="device-criticality">Asset Criticality</label>
        <select
          id="device-criticality"
          value={assetCriticality}
          onChange={(e) => setAssetCriticality(e.target.value)}
          className="input"
        >
          {CRITICALITY_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </div>

      {isSmc && (
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            gap: 12,
            borderTop: '1px solid var(--border)',
            paddingTop: 16,
          }}
        >
          <Button type="button" variant="secondary" onClick={handleTest} disabled={testing || !smcHost}>
            {testing ? 'Testing…' : 'Test Connectivity'}
          </Button>
          {testResult && (
            <span style={{ fontSize: 'var(--text-base)', color: testResult.ok ? 'var(--green)' : 'var(--red)' }}>
              {testResult.ok
                ? `Connected — ${testResult.engineCount ?? 0} engines found`
                : testResult.message}
            </span>
          )}
        </div>
      )}

      {submitError && <p style={{ fontSize: 'var(--text-base)', color: 'var(--red)' }}>{submitError}</p>}

      <Button type="submit" variant="primary" disabled={saveBlocked || submitting}>
        {submitting ? 'Saving…' : 'Save'}
      </Button>
      {saveBlocked && (
        <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          Run a successful connectivity test before saving.
        </p>
      )}
    </form>
  );
}
