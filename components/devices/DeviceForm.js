'use client';

import { useState } from 'react';
import Button from '../ui/Button';
import { VENDOR_META, VENDOR_SLUGS, buildCredentialPlaintext } from './vendorMeta';

const CRITICALITY_OPTIONS = [
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' },
];

const inputClasses =
  'w-full rounded border border-border bg-bg-base px-2 py-1.5 text-sm text-text-primary focus:border-accent focus:outline-none';

// Add/Edit device form, driven by VENDOR_META (frozen Tier 1 vendor table).
//
// Forcepoint keeps the original behavior: Save is only enabled once a
// "Test Connectivity" call against POST /api/devices/test-smc has succeeded in this
// session, and any change to a connection-relevant field invalidates the previous
// test result so a stale "Connected" state can never be carried into Save.
// Other vendors have no pre-save test endpoint yet, so Save is gated only on the
// required fields being present.
//
// mgmt_method is derived from the vendor (VENDOR_META) — never user-editable, and
// the API re-derives it server-side anyway.
export default function DeviceForm({ onSubmit }) {
  const [name, setName] = useState('');
  const [vendor, setVendor] = useState('forcepoint');
  const [smcHost, setSmcHost] = useState('');
  const [smcPort, setSmcPort] = useState('');
  const [mgmtIp, setMgmtIp] = useState('');
  const [mgmtPort, setMgmtPort] = useState('');
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
  const isSmc = meta.connection === 'smc';
  const isSecretShape = meta.credentialShape === 'secret';
  const hasEnable = meta.credentialShape === 'userpass_enable';

  function invalidateTest() {
    setTestResult(null);
  }

  function handleVendorChange(nextVendor) {
    setVendor(nextVendor);
    // Ports and credentials are vendor-specific — reset them so the new vendor's
    // default-port placeholder shows and no stale credential is carried across.
    setSmcPort('');
    setMgmtPort('');
    setSecret('');
    setUsername('');
    setPassword('');
    setEnablePassword('');
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
          smc_port: Number(smcPort) || VENDOR_META.forcepoint.defaultPort,
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

  const credentialProvided = isSecretShape ? Boolean(secret) : Boolean(username && password);

  async function handleSubmit(e) {
    e.preventDefault();
    if (saveBlocked || submitting) return;

    setSubmitting(true);
    setSubmitError('');
    try {
      const payload = {
        name,
        vendor,
        allow_self_signed_ssl: allowSelfSignedSsl,
        site,
        asset_criticality: assetCriticality,
      };
      if (isSmc) {
        payload.smc_host = smcHost;
        payload.smc_port = Number(smcPort) || meta.defaultPort;
      } else {
        payload.mgmt_ip = mgmtIp;
        payload.mgmt_port = Number(mgmtPort) || meta.defaultPort;
      }
      if (credentialProvided) {
        payload.credential = buildCredentialPlaintext(vendor, {
          secret,
          username,
          password,
          enablePassword,
        });
        payload.credential_type = meta.credentialType;
      }
      await onSubmit(payload);
    } catch (err) {
      setSubmitError(err.message || 'Failed to save device');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label htmlFor="device-name" className="mb-1 block text-sm text-text-secondary">
          Name
        </label>
        <input
          id="device-name"
          type="text"
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
          className={inputClasses}
        />
      </div>

      <div>
        <label htmlFor="device-vendor" className="mb-1 block text-sm text-text-secondary">
          Vendor
        </label>
        <select
          id="device-vendor"
          value={vendor}
          onChange={(e) => handleVendorChange(e.target.value)}
          className={inputClasses}
        >
          {VENDOR_SLUGS.map((slug) => (
            <option key={slug} value={slug}>
              {VENDOR_META[slug].label}
            </option>
          ))}
        </select>
      </div>

      {isSmc ? (
        <>
          <div>
            <label htmlFor="device-smc-host" className="mb-1 block text-sm text-text-secondary">
              SMC Host
            </label>
            <input
              id="device-smc-host"
              type="text"
              required
              value={smcHost}
              onChange={(e) => {
                setSmcHost(e.target.value);
                invalidateTest();
              }}
              className={inputClasses}
            />
          </div>

          <div>
            <label htmlFor="device-smc-port" className="mb-1 block text-sm text-text-secondary">
              SMC Port
            </label>
            <input
              id="device-smc-port"
              type="number"
              placeholder={String(meta.defaultPort)}
              value={smcPort}
              onChange={(e) => {
                setSmcPort(e.target.value);
                invalidateTest();
              }}
              className={inputClasses}
            />
          </div>
        </>
      ) : (
        <>
          <div>
            <label htmlFor="device-mgmt-ip" className="mb-1 block text-sm text-text-secondary">
              Management IP / Host
            </label>
            <input
              id="device-mgmt-ip"
              type="text"
              required
              value={mgmtIp}
              onChange={(e) => setMgmtIp(e.target.value)}
              className={inputClasses}
            />
          </div>

          <div>
            <label htmlFor="device-mgmt-port" className="mb-1 block text-sm text-text-secondary">
              Management Port
            </label>
            <input
              id="device-mgmt-port"
              type="number"
              placeholder={String(meta.defaultPort)}
              value={mgmtPort}
              onChange={(e) => setMgmtPort(e.target.value)}
              className={inputClasses}
            />
          </div>
        </>
      )}

      {isSecretShape ? (
        <div>
          <label htmlFor="device-secret" className="mb-1 block text-sm text-text-secondary">
            {meta.secretLabel}
          </label>
          <input
            id="device-secret"
            type="password"
            autoComplete="new-password"
            value={secret}
            onChange={(e) => {
              setSecret(e.target.value);
              invalidateTest();
            }}
            className={inputClasses}
          />
        </div>
      ) : (
        <>
          <div>
            <label htmlFor="device-cred-username" className="mb-1 block text-sm text-text-secondary">
              Username
            </label>
            <input
              id="device-cred-username"
              type="text"
              autoComplete="off"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className={inputClasses}
            />
          </div>

          <div>
            <label htmlFor="device-cred-password" className="mb-1 block text-sm text-text-secondary">
              Password
            </label>
            <input
              id="device-cred-password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={inputClasses}
            />
          </div>

          {hasEnable && (
            <div>
              <label htmlFor="device-cred-enable" className="mb-1 block text-sm text-text-secondary">
                Enable Password (optional)
              </label>
              <input
                id="device-cred-enable"
                type="password"
                autoComplete="new-password"
                value={enablePassword}
                onChange={(e) => setEnablePassword(e.target.value)}
                className={inputClasses}
              />
            </div>
          )}
        </>
      )}

      <label className="flex items-center gap-2 text-sm text-text-secondary">
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

      <div>
        <label htmlFor="device-site" className="mb-1 block text-sm text-text-secondary">
          Site
        </label>
        <input
          id="device-site"
          type="text"
          value={site}
          onChange={(e) => setSite(e.target.value)}
          className={inputClasses}
        />
      </div>

      <div>
        <label htmlFor="device-criticality" className="mb-1 block text-sm text-text-secondary">
          Asset Criticality
        </label>
        <select
          id="device-criticality"
          value={assetCriticality}
          onChange={(e) => setAssetCriticality(e.target.value)}
          className={inputClasses}
        >
          {CRITICALITY_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </div>

      {isSmc && (
        <div className="flex flex-wrap items-center gap-3 border-t border-border pt-4">
          <Button type="button" variant="secondary" onClick={handleTest} disabled={testing || !smcHost}>
            {testing ? 'Testing…' : 'Test Connectivity'}
          </Button>
          {testResult && (
            <span className={`text-sm ${testResult.ok ? 'text-success' : 'text-danger'}`}>
              {testResult.ok
                ? `Connected — ${testResult.engineCount ?? 0} engines found`
                : testResult.message}
            </span>
          )}
        </div>
      )}

      {submitError && <p className="text-sm text-danger">{submitError}</p>}

      <Button type="submit" variant="primary" disabled={saveBlocked || submitting}>
        {submitting ? 'Saving…' : 'Save'}
      </Button>
      {saveBlocked && (
        <p className="text-xs text-text-muted">Run a successful connectivity test before saving.</p>
      )}
    </form>
  );
}
