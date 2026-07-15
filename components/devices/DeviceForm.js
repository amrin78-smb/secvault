'use client';

import { useState } from 'react';
import Button from '../ui/Button';

const CRITICALITY_OPTIONS = [
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' },
];

// Add/Edit device form. Save is only enabled once a "Test Connectivity" call against
// POST /api/devices/test-smc has succeeded in this session (per spec). Any change to a
// connection-relevant field invalidates the previous test result so a stale "Connected"
// state can never be carried into Save.
export default function DeviceForm({ onSubmit }) {
  const [name, setName] = useState('');
  const [vendor] = useState('forcepoint'); // Phase 1+2: Forcepoint-only, fixed.
  const [smcHost, setSmcHost] = useState('');
  const [smcPort, setSmcPort] = useState(8082);
  const [smcApiKey, setSmcApiKey] = useState('');
  const [allowSelfSignedSsl, setAllowSelfSignedSsl] = useState(true);
  const [site, setSite] = useState('');
  const [assetCriticality, setAssetCriticality] = useState('medium');

  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null); // { ok, message, engineCount }
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');

  function invalidateTest() {
    setTestResult(null);
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
          smc_port: Number(smcPort) || 8082,
          api_key: smcApiKey,
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

  async function handleSubmit(e) {
    e.preventDefault();
    if (!testResult?.ok || submitting) return;

    setSubmitting(true);
    setSubmitError('');
    try {
      await onSubmit({
        name,
        vendor,
        mgmt_method: 'smc',
        smc_host: smcHost,
        smc_port: Number(smcPort) || 8082,
        allow_self_signed_ssl: allowSelfSignedSsl,
        site,
        asset_criticality: assetCriticality,
        smc_api_key: smcApiKey,
      });
    } catch (err) {
      setSubmitError(err.message || 'Failed to save device');
    } finally {
      setSubmitting(false);
    }
  }

  const inputClasses =
    'w-full rounded border border-border bg-bg-base px-2 py-1.5 text-sm text-text-primary focus:border-accent focus:outline-none';

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
        <select id="device-vendor" value={vendor} disabled className={`${inputClasses} disabled:opacity-70`}>
          <option value="forcepoint">Forcepoint</option>
        </select>
      </div>

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
          value={smcPort}
          onChange={(e) => {
            setSmcPort(e.target.value);
            invalidateTest();
          }}
          className={inputClasses}
        />
      </div>

      <div>
        <label htmlFor="device-smc-api-key" className="mb-1 block text-sm text-text-secondary">
          SMC API Key
        </label>
        <input
          id="device-smc-api-key"
          type="password"
          autoComplete="new-password"
          value={smcApiKey}
          onChange={(e) => {
            setSmcApiKey(e.target.value);
            invalidateTest();
          }}
          className={inputClasses}
        />
      </div>

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

      {submitError && <p className="text-sm text-danger">{submitError}</p>}

      <Button type="submit" variant="primary" disabled={!testResult?.ok || submitting}>
        {submitting ? 'Saving…' : 'Save'}
      </Button>
      {!testResult?.ok && (
        <p className="text-xs text-text-muted">Run a successful connectivity test before saving.</p>
      )}
    </form>
  );
}
