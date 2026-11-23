'use client';

import { useState, useEffect } from 'react';
import Button from '../ui/Button';
import {
  VENDOR_META,
  VENDOR_SLUGS,
  buildCredentialPlaintext,
  resolveAccessMethod,
  hasMultipleAccessMethods,
} from './vendorMeta';
// ⛔ ONE wording for this state, shared with the work-queue item, the device
// routes and the inventory marker. A form that explained it in its own words
// would be a fourth description of one fact.
import {
  MONITORING_ONLY_METHOD,
  MONITORING_ONLY_CLAIM,
  MONITORING_ONLY_REMEDY,
} from '../../lib/monitoringOnly';

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

// Spans both columns of the DeviceForm grid (see the <form> comment below) —
// used for text prose, checkboxes, the connectivity-test row, and the submit
// button, which read better full-width than squeezed into one grid column.
const FULL_WIDTH = { gridColumn: '1 / -1' };

// Add/Edit device form, driven by VENDOR_META (frozen Tier 1 vendor table).
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
// Forcepoint keeps the original behavior IN CREATE MODE: Save is only enabled
// once a "Test Connectivity" call against POST /api/devices/test-smc has
// succeeded in this session, and any change to a connection-relevant field
// invalidates the previous test result so a stale "Connected" state can never
// be carried into Save. Other vendors have no pre-save test endpoint yet, so
// Save is gated only on the required fields being present. In EDIT MODE this
// gate is skipped entirely (see `saveBlocked` below) — the device was already
// tested when it was created/last edited, and forcing a fresh Test
// Connectivity (which would need the stored secret retyped, since it never
// comes back down to the browser) just to change something unrelated like
// `site` would be an unreasonable tax on the common case.
//
// mode: 'create' | 'edit'. In 'edit' mode, `initialDevice` (the full devices
// row) pre-fills every field and the caller's `onSubmit` is expected to PUT
// rather than POST.
//
// ⛔ CREDENTIAL INPUTS ARE HIDDEN IN EDIT MODE (all `{!isEdit && …}` below).
// Credential rotation lives in ONE place — the dedicated, credential-only
// `components/devices/CredentialForm.js` ("Rotate Credentials" on the Manage
// tab), which PUTs ONLY `{credential, credential_type}` and never `mgmt_method`
// or any other device field. This modal is metadata-only (name/vendor/access
// method/connection/SSL/site/criticality); with no credential inputs, its own
// handleSubmit never puts a credential (credentialProvided stays false), so a
// metadata edit can never touch the stored secret. Deliberate de-duplication
// (chosen 2026-07-31) — the two used to overlap. Create mode STILL shows every
// credential input, since a brand-new device has no stored credential to keep.
// (Minor accepted trade: changing a device's access method here, then rotating
// its credential, is now two steps — method in this modal, new secret in Rotate
// Credentials — but that's a rare flow and the separation is cleaner/safer.)
//
// This component never picks the HTTP method or URL itself — same as create
// mode, that's the caller's job (see app/(dashboard)/devices/new/page.js for
// create, components/devices/EditDeviceModal.js for edit) — it only ever calls
// `onSubmit(payload)`.
export default function DeviceForm({
  onSubmit, mode = 'create', initialDevice = null, prefill = null,
}) {
  const isEdit = Boolean(mode === 'edit' && initialDevice);

  // ⛔ CREATE-MODE PREFILL, FROM THE URL — AND IT HAD NEVER WORKED (v2.237.0).
  //
  // `DiscoveredDeviceActions` has built `/devices/new?mgmt_ip=…&name=…&vendor=…`
  // since the discovered list shipped, and `app/(dashboard)/devices/new/page.js`
  // rendered `<DeviceForm onSubmit={…} />` and read no search params at all —
  // its comment said "a blank add-device form has nothing to pre-load from the
  // DB", which is true of the DATABASE and misses that the prefill comes from
  // the URL. So every "Add to inventory" click opened a BLANK FORCEPOINT form:
  // the operator had to retype the address they had just been shown and pick
  // the vendor again.
  //
  // ⛔ AND IT MADE A CAREFULLY-REASONED GUARD UNFIREABLE. That file argues at
  // length for withholding the vendor when SecVault cannot manage it, because
  // otherwise "an operator clicking Add to inventory on a detected Juniper
  // would be three fields away from creating a Forcepoint device pointing at
  // an SRX". The form was ALREADY always Forcepoint — the guard was protecting
  // against a prefill that did not happen. Prose defending a guard that cannot
  // fire is the pattern CLAUDE.md names most often.
  //
  // ⛔ THE URL IS NOT TRUSTED. `vendor` is resolved against VENDOR_META and an
  // unknown slug falls back to the default rather than rendering a form
  // labelled for a vendor this build does not have — which is the real version
  // of the hazard above, now that it can actually occur.
  const seed = (() => {
    if (isEdit || !prefill) return null;
    const vendorOk = prefill.vendor
      && Object.prototype.hasOwnProperty.call(VENDOR_META, prefill.vendor);
    const slug = vendorOk ? prefill.vendor : 'forcepoint';
    return {
      name: prefill.name || '',
      vendor: slug,
      // ⛔ The address goes to the field the CONNECTION SHAPE uses. Prefilling
      // mgmt_ip on an SMC vendor fills a box the form does not render, so the
      // address would silently vanish.
      smcHost: VENDOR_META[slug].connection === 'smc' ? (prefill.mgmt_ip || '') : '',
      mgmtIp: VENDOR_META[slug].connection === 'smc' ? '' : (prefill.mgmt_ip || ''),
    };
  })();

  // Lazy initializers so pre-fill only ever runs once, on mount — this
  // component is remounted (via a `key` prop) by EditDeviceModal every time
  // the modal re-opens, rather than kept alive and re-synced, so there is no
  // need to react to `initialDevice` changing after mount.
  const [name, setName] = useState(() => (isEdit ? initialDevice.name || '' : (seed ? seed.name : '')));
  const [vendor, setVendor] = useState(() =>
    isEdit ? initialDevice.vendor : (seed ? seed.vendor : 'forcepoint'));
  const [accessMethod, setAccessMethod] = useState(() => {
    if (isEdit) {
      const resolved = resolveAccessMethod(initialDevice.vendor, initialDevice.mgmt_method);
      return resolved ? resolved.method : VENDOR_META.forcepoint.defaultAccessMethod;
    }
    // ⛔ THE PREFILLED VENDOR'S OWN DEFAULT, never Forcepoint's. Seeding the
    // vendor while leaving the method on `smc` would render an SMC form under
    // a FortiGate heading. And ⛔ never the SYSLOG method: appearing in the
    // discovered list means we have seen logs from the address, which says
    // nothing about whether the operator holds credentials — defaulting to
    // log-only would nudge them into an UNASSESSED firewall when a managed one
    // was available. The selector offers it; the form does not choose it.
    const slug = seed ? seed.vendor : 'forcepoint';
    return VENDOR_META[slug].defaultAccessMethod;
  });
  const [smcHost, setSmcHost] = useState(() =>
    isEdit ? initialDevice.smc_host || '' : (seed ? seed.smcHost : ''));
  const [smcPort, setSmcPort] = useState(() =>
    isEdit && initialDevice.smc_port != null ? String(initialDevice.smc_port) : ''
  );
  const [mgmtIp, setMgmtIp] = useState(() =>
    isEdit ? initialDevice.mgmt_ip || '' : (seed ? seed.mgmtIp : ''));
  const [mgmtPort, setMgmtPort] = useState(() =>
    isEdit && initialDevice.mgmt_port != null ? String(initialDevice.mgmt_port) : ''
  );
  const [authMode, setAuthMode] = useState('apikey');
  const [secret, setSecret] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [enablePassword, setEnablePassword] = useState('');
  const [allowSelfSignedSsl, setAllowSelfSignedSsl] = useState(() =>
    isEdit ? initialDevice.allow_self_signed_ssl !== false : true
  );
  const [site, setSite] = useState(() => (isEdit ? initialDevice.site || '' : ''));
  const [assetCriticality, setAssetCriticality] = useState(() =>
    isEdit ? initialDevice.asset_criticality || 'medium' : 'medium'
  );

  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null); // { ok, message, engineCount }
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');

  // Saved connection-profile picker (ManageEngine parity). Deliberately NOT
  // offered for Forcepoint's 'smc' shape — see the `isSmc` gates below. Fetched
  // once on mount; a non-2xx (403 on a stale session, network error) just
  // leaves the list empty rather than showing an error banner, since this form
  // is only ever reachable by an admin already.
  const [profiles, setProfiles] = useState([]);
  const [selectedProfileId, setSelectedProfileId] = useState('');
  const [saveAsProfile, setSaveAsProfile] = useState(false);
  const [newProfileName, setNewProfileName] = useState('');

  useEffect(() => {
    fetch('/api/credential-profiles')
      .then((res) => (res.ok ? res.json() : { profiles: [] }))
      .then((data) => setProfiles(Array.isArray(data.profiles) ? data.profiles : []))
      .catch(() => setProfiles([]));
  }, []);

  const meta = VENDOR_META[vendor] || VENDOR_META.forcepoint;
  // resolveAccessMethod falls back to the vendor's default when accessMethod is
  // stale (e.g. mid-render right after a vendor switch), so `config` is never
  // undefined and the port/credential UI can never key off garbage.
  const { method, config } = resolveAccessMethod(vendor, accessMethod) ||
    resolveAccessMethod('forcepoint', null);

  // ⛔ THE VENDOR'S CONNECTION SHAPE, WHICH IS NOT THE SAME AS "THERE IS A
  // CONNECTION". `isSmc` drives the SMC host/port fields AND the
  // test-before-save gate, and `meta.connection` is a property of the VENDOR,
  // so it stayed `'smc'` for Forcepoint even on the log-only method. Result
  // (found in review, v2.237.0): a Forcepoint could be offered "Syslog only",
  // be shown a paragraph saying SecVault will not connect to it, and then be
  // refused a Save until it passed a connectivity test — using a secret the
  // form no longer renders an input for, so the test could only ever fail.
  // A permanent dead end, and the one house rule named in CLAUDE.md that this
  // broke: the UI gate was STRICTER than the API, which accepts the device.
  const isSmc = meta.connection === 'smc';
  // ⛔ Is SecVault going to open a connection to this device AT ALL? Keyed on
  // the METHOD, so it is false for log-only on every vendor.
  const willConnect = method !== MONITORING_ONLY_METHOD;
  const showMethodSelector = hasMultipleAccessMethods(vendor);
  const shape = config.credentialShape;
  const isSecretShape = shape === 'secret';
  const isApiKeyOrUserPass = shape === 'apikey_or_userpass';
  const hasEnable = shape === 'userpass_enable';
  // ⛔ A MONITORING-ONLY VENDOR HAS NO CREDENTIAL AND MUST SHOW NO CREDENTIAL
  // UI. Without this the form falls through to the Username/Password branch
  // below — the else arm, reached by anything that is not a `secret` or
  // `apikey_or_userpass` shape — and asks for credentials for a firewall
  // SecVault is never going to connect to. The operator would supply them,
  // `buildCredentialPlaintext` returns null for this shape so nothing is
  // stored, and they would be left believing a management connection exists.
  const needsCredential = shape !== 'none';
  // A single secret input is shown for 'secret', and for 'apikey_or_userpass'
  // while the operator has the API-key mode selected.
  const showSecretInput = isSecretShape || (isApiKeyOrUserPass && authMode === 'apikey');
  // "Allow Self-Signed SSL" only means anything for TLS transports. SSH does not
  // present an X.509 cert, so the toggle is hidden (and left at its default) for
  // ssh methods rather than implying it has an effect.
  //
  // ⛔ AND THE SYSLOG METHOD HAS NO TRANSPORT AT ALL (v2.237.0), so this file's
  // own rule above covers it with more force: there is no connection, no
  // handshake and no certificate to accept, and a rendered toggle would be a
  // control that cannot do anything — on the one form whose job is to say what
  // SecVault will and will not do with this firewall.
  const showSslToggle = method !== 'ssh' && method !== MONITORING_ONLY_METHOD;

  // Recomputed on every render — cheap, and `profiles` only ever changes once
  // (the mount-time fetch), so there's no benefit to memoizing this.
  const matchingProfiles = profiles.filter((p) => p.credential_type === config.credentialType);

  function invalidateTest() {
    setTestResult(null);
  }

  // Clearing the credential inputs on any vendor/method switch is deliberate: the
  // credential SHAPE changes with the method (an API token is not an SSH
  // password), so carrying a value across would silently store the wrong thing.
  // A profile picked for one credential_type is not valid after switching to a
  // different vendor/method, for the same reason — reset it alongside the rest.
  function resetCredentialInputs() {
    setAuthMode('apikey');
    setSecret('');
    setUsername('');
    setPassword('');
    setEnablePassword('');
    setSelectedProfileId('');
    setSaveAsProfile(false);
    setNewProfileName('');
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
    // ⛔ CARRY THE ADDRESS ACROSS THE TWO FIELDS. The form renders `smc_host`
    // OR `mgmt_ip` depending on the vendor's connection shape, and they are
    // separate state. Switching vendor used to leave the typed address in the
    // field that is no longer rendered — so it vanished from the screen while
    // still sitting in unsubmitted state. Harmless while nothing prefilled
    // those boxes; since v2.237.0 the discovered-senders link fills one of them
    // with an address the operator was just shown, and changing a wrongly
    // detected vendor silently lost it.
    const nextIsSmc = nextMeta ? nextMeta.connection === 'smc' : true;
    const address = (meta.connection === 'smc' ? smcHost : mgmtIp) || '';
    if (nextIsSmc) { setSmcHost(address); setMgmtIp(''); }
    else { setMgmtIp(address); setSmcHost(''); }
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

  // Forcepoint keeps the test-before-save gate in CREATE mode only; other
  // vendors, and Forcepoint in EDIT mode, can save directly (see the header
  // comment for why edit mode skips this).
  // ⛔ `&& willConnect`: there is nothing to test when SecVault will never dial
  // the device, so requiring a passing test would block the save for ever.
  const saveBlocked = isSmc && willConnect && mode === 'create' ? !testResult?.ok : false;

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
      // ⛔ The PORT keys off the METHOD, because a port is a claim that
      // something is listening on it. `willConnect` is false for log-only, and
      // an explicit null is sent rather than the field being omitted — the PUT
      // route only resets a port it was handed, so omitting it would leave a
      // stale port behind on an edit.
      if (isSmc) {
        payload.smc_host = smcHost;
        payload.smc_port = willConnect ? (Number(smcPort) || config.defaultPort) : null;
      } else {
        payload.mgmt_ip = mgmtIp;
        payload.mgmt_port = willConnect ? (Number(mgmtPort) || config.defaultPort) : null;
      }
      if (selectedProfileId) {
        // A saved profile's plaintext never reaches the browser — the server
        // applies it directly. Mutually exclusive with credential/credential_type.
        payload.credential_profile_id = selectedProfileId;
      } else if (credentialProvided) {
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
        if (saveAsProfile && newProfileName.trim()) {
          payload.save_as_profile_name = newProfileName.trim();
        }
      }
      await onSubmit(payload);
    } catch (err) {
      setSubmitError(err.message || 'Failed to save device');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    // Responsive 2-column grid: paired inputs (vendor/method, IP/port,
    // username/password, site/criticality) sit side by side when there's room
    // and collapse to a single column on a narrow container (auto-fit +
    // minmax). Text, checkboxes, the connectivity-test row, and the submit
    // button span the full width via FULL_WIDTH. This roughly halves the form's
    // height so it doesn't run off the bottom of the Edit Device modal.
    // Unchanged in create mode (devices/new) — the same grid just renders in a
    // wider page container there.
    <form
      onSubmit={handleSubmit}
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: 16,
        alignItems: 'start',
      }}
    >
      <div className="form-field" style={FULL_WIDTH}>
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
          disabled={isEdit}
          title={isEdit ? 'Vendor cannot be changed on an existing device — delete and re-add it instead.' : undefined}
        >
          {VENDOR_SLUGS.map((slug) => (
            <option key={slug} value={slug}>
              {VENDOR_META[slug].label}
            </option>
          ))}
        </select>
        {/* Edit mode: vendor is locked, not just hidden-credential-guarded. This
            modal never shows credential inputs (see header comment), so a vendor
            switch here would submit metadata-only. The server's PUT handler
            deletes any stored device_credentials row whose credential_type no
            longer matches the (possibly new) vendor+method when no replacement
            credential is supplied in the same request — silently leaving the
            device with zero working credentials. Locking the dropdown forces a
            vendor change through device recreation instead, which is the only
            path that also collects a fresh credential. */}
        {isEdit && (
          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 4 }}>
            Vendor can’t be changed on an existing device — delete and re-add it to switch vendors.
          </p>
        )}
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
            {/* ⛔ IN EDIT MODE, LOG-ONLY IS OFFERED ONLY TO A DEVICE ALREADY
                ON IT. `PUT /api/devices/[id]` answers 409 for a managed →
                log-only conversion, because this route deletes credentials and
                NOTHING ELSE: the stored version, ruleset, config, CVE
                assessment and compliance findings would survive while
                `collectAndStore` skipped the device for ever, so they would be
                reported as current indefinitely — including as urgent CVE
                work. Offering a control that always errors is the mirror of
                the rule about a UI gate being stricter than its API: here the
                UI would be LOOSER, which costs the operator a destructive-
                looking failure on a form that had already closed. Delete and
                re-add is the honest path, and it is the precedent the locked
                vendor dropdown above already sets. */}
            {Object.entries(meta.accessMethods)
              .filter(([key]) => !(
                isEdit
                && key === MONITORING_ONLY_METHOD
                && (initialDevice || {}).mgmt_method !== MONITORING_ONLY_METHOD
              ))
              .map(([key, cfg]) => (
              <option key={key} value={key}>
                {cfg.label}
              </option>
            ))}
          </select>
        </div>
      )}

      {/* ⛔ PICKING THIS IS A DECISION WITH A COST, AND THE FORM USED TO MAKE
          IT IN SILENCE: the credential inputs simply vanished. An operator who
          CHOOSES log-only when they do hold credentials gets a firewall that
          produces no CVEs, no compliance result and no rule findings for ever
          — which lib/monitoringOnly.js calls "silently the cleanest device on
          the fleet" — and an operator who MUST choose it needs to know the log
          collection is unaffected. Both read the same two sentences, imported,
          so this form and the work-queue item cannot word the state
          differently. */}
      {!needsCredential && (
        <p
          // ⛔ FULL_WIDTH, like every other prose block in this file. The grid
          // is `repeat(auto-fit, minmax(220px, 1fr))`, so without it a
          // ~290-character sentence reflows into a 220px column about eleven
          // lines tall, beside a single-line field and on a different grid row
          // from the selector it explains.
          style={{ ...FULL_WIDTH, fontSize: 'var(--text-xs)', color: 'var(--unmeasured)', margin: 0 }}
        >
          {MONITORING_ONLY_CLAIM} {MONITORING_ONLY_REMEDY}
        </p>
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

          {/* ⛔ No port field when nothing will be dialled — and the
              placeholder would read the literal string "null", since
              `String(null)` is "null" and the log-only method declares no
              defaultPort. */}
          {willConnect && (
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
          )}
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

          {/* ⛔ SAME REFUSAL AS THE SSL TOGGLE, AND IT ENFORCES A GUARANTEE
              SOMEBODY ELSE WROTE DOWN. `SYSLOG_ONLY_METHOD` in vendorMeta.js
              says "No defaultPort. A port here would be written to
              `mgmt_port` and would claim SecVault talks to something on it" —
              but a missing DEFAULT does not stop a TYPED value, and the field
              was still rendered and still submitted, so an operator typing
              443 out of habit stored exactly the assertion that comment
              forbids. (It also showed the literal placeholder "null".) */}
          {willConnect && (
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
          )}
        </>
      )}

      {!isSmc && !isEdit && needsCredential && (
        <div className="form-field">
          <label htmlFor="device-cred-profile">Use Saved Profile</label>
          <select
            id="device-cred-profile"
            value={selectedProfileId}
            onChange={(e) => {
              setSelectedProfileId(e.target.value);
              invalidateTest();
            }}
            className="input"
          >
            <option value="">— Enter credentials manually —</option>
            {matchingProfiles.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
                {p.username ? ` — ${p.username}` : ''}
              </option>
            ))}
          </select>
        </div>
      )}

      {!isEdit && !selectedProfileId && needsCredential && isApiKeyOrUserPass && (
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

      {/* Credential inputs — create mode only. In edit mode these are hidden
          entirely (see the header comment): rotation lives in CredentialForm
          ("Rotate Credentials" on the Manage tab), so this modal stays
          metadata-only and its handleSubmit never sends a credential. */}
      {!isEdit && !selectedProfileId && needsCredential &&
        (showSecretInput ? (
          <div className="form-field">
            <label htmlFor="device-secret">{config.secretLabel}</label>
            <input
              id="device-secret"
              type="password"
              autoComplete="new-password"
              placeholder={isEdit ? 'Leave blank to keep the existing credential' : undefined}
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
                placeholder={isEdit ? 'Leave blank to keep existing' : undefined}
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
                placeholder={isEdit ? 'Leave blank to keep existing' : undefined}
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
        ))}

      {!isEdit && !selectedProfileId && needsCredential && (
        <div className="form-field" style={FULL_WIDTH}>
          <label
            style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}
          >
            <input
              type="checkbox"
              checked={saveAsProfile}
              onChange={(e) => setSaveAsProfile(e.target.checked)}
            />
            Save these credentials as a reusable profile
          </label>
          {saveAsProfile && (
            <input
              type="text"
              placeholder="Profile name"
              value={newProfileName}
              onChange={(e) => setNewProfileName(e.target.value)}
              className="input"
              style={{ marginTop: 8 }}
            />
          )}
        </div>
      )}

      {showSslToggle && (
        <label
          style={{ ...FULL_WIDTH, display: 'flex', alignItems: 'center', gap: 8, fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}
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

      {/* SMC in-form Test Connectivity is create-mode only — it tests using the
          api-key typed above, which no longer exists in edit mode. Post-edit
          testing uses the page-level Test Connectivity in Device Actions, which
          runs against the STORED credential. */}
      {isSmc && willConnect && !isEdit && (
        <div
          style={{
            ...FULL_WIDTH,
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

      {submitError && <p style={{ ...FULL_WIDTH, fontSize: 'var(--text-base)', color: 'var(--red)' }}>{submitError}</p>}

      <Button type="submit" variant="primary" disabled={saveBlocked || submitting} style={FULL_WIDTH}>
        {submitting ? 'Saving…' : 'Save'}
      </Button>
      {saveBlocked && (
        <p style={{ ...FULL_WIDTH, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          Run a successful connectivity test before saving.
        </p>
      )}
    </form>
  );
}
