// ─────────────────────────────────────────────────────────────────────────────
// FROZEN Tier 1 vendor table — single source of truth for vendor slugs AND the
// access methods each vendor supports.
//
// Slugs are load-bearing: they drive adapter dispatch (lib/adapters/index.js),
// version comparator selection (lib/engines/versionComparator.js), and NVD feed
// CPE matching (lib/feeds/nvd.js). Do NOT rename or add slugs casually.
//
// This module is plain constants + pure helpers (no 'use client', no React, no
// node builtins) so it is importable from BOTH client components (DeviceForm,
// CredentialForm) and server-side API routes (app/api/devices/*). Keep it
// isomorphic — anything node-only here breaks the browser bundle.
//
// ── Shape ────────────────────────────────────────────────────────────────────
// connection:          'smc'  → device uses smc_host + smc_port
//                      'mgmt' → device uses mgmt_ip + mgmt_port
// accessMethods:       map of mgmt_method → per-method config. A vendor with
//                      more than one entry is user-selectable in the Add Device
//                      form; the key IS the value stored in devices.mgmt_method.
// defaultAccessMethod: preselected in the form; also the fallback used by
//                      adapter dispatch for legacy rows whose mgmt_method is
//                      null/unrecognised.
//
// Per-method:
//   defaultPort      → seeds the port field
//   credentialType   → credStore credential_type (must be in CREDENTIAL_TYPES)
//   credentialShape  → how the plaintext is built/parsed:
//        'secret'             single secret string, stored RAW (not JSON)
//        'apikey_or_userpass' JSON {"api_key"} OR {"username","password"}
//        'userpass'           JSON {"username","password"}
//        'userpass_enable'    JSON {"username","password","enable_password"?}
//   secretLabel      → UI label for the single-secret / api-key input
// ─────────────────────────────────────────────────────────────────────────────

export const VENDOR_META = {
  forcepoint: {
    label: 'Forcepoint (SMC)',
    connection: 'smc',
    defaultAccessMethod: 'smc',
    accessMethods: {
      // SMC only, deliberately. CLAUDE.md: NEVER SSH directly to Forcepoint
      // engines — the SMC is the management plane and all operations go there.
      smc: {
        label: 'SMC REST API (HTTPS)',
        defaultPort: 8082,
        credentialType: 'smc_api',
        credentialShape: 'secret',
        secretLabel: 'SMC API Key',
      },
    },
  },
  fortinet: {
    label: 'Fortinet FortiGate',
    connection: 'mgmt',
    defaultAccessMethod: 'api',
    accessMethods: {
      api: {
        label: 'REST API (HTTPS)',
        defaultPort: 443,
        credentialType: 'rest_api',
        credentialShape: 'apikey_or_userpass',
        secretLabel: 'API Token',
      },
      ssh: {
        label: 'SSH',
        defaultPort: 22,
        credentialType: 'ssh',
        credentialShape: 'userpass',
      },
    },
  },
  paloalto: {
    label: 'Palo Alto PAN-OS',
    connection: 'mgmt',
    defaultAccessMethod: 'api',
    accessMethods: {
      api: {
        label: 'XML API (HTTPS)',
        defaultPort: 443,
        credentialType: 'rest_api',
        // PAN-OS natively turns username+password into an API key via
        // ?type=keygen — so user/pass is a first-class auth mode, not a shim.
        credentialShape: 'apikey_or_userpass',
        secretLabel: 'API Key',
      },
      ssh: {
        label: 'SSH',
        defaultPort: 22,
        credentialType: 'ssh',
        credentialShape: 'userpass',
      },
    },
  },
  checkpoint: {
    label: 'Check Point (Mgmt API)',
    connection: 'mgmt',
    defaultAccessMethod: 'api',
    accessMethods: {
      // Connects to the MANAGEMENT SERVER, not the gateway.
      api: {
        label: 'Management API (HTTPS)',
        defaultPort: 443,
        credentialType: 'rest_api',
        credentialShape: 'apikey_or_userpass',
        secretLabel: 'API Key',
      },
    },
  },
  cisco_asa: {
    label: 'Cisco ASA',
    connection: 'mgmt',
    defaultAccessMethod: 'ssh',
    accessMethods: {
      ssh: {
        label: 'SSH',
        defaultPort: 22,
        credentialType: 'ssh',
        credentialShape: 'userpass_enable',
      },
    },
  },
  sangfor: {
    label: 'Sangfor',
    connection: 'mgmt',
    defaultAccessMethod: 'ssh',
    accessMethods: {
      ssh: {
        label: 'SSH',
        defaultPort: 22,
        credentialType: 'ssh',
        credentialShape: 'userpass',
      },
    },
  },
};

export const VENDOR_SLUGS = Object.keys(VENDOR_META);

// The only credential_type values credStore rows may carry.
//
// 'snmp' (added 2026-07-21) is deliberately NOT part of any vendor's
// accessMethods above — SNMP is an optional, orthogonal MONITORING
// credential (device_credentials credential_type='snmp'), never the
// management-plane credential adapter dispatch resolves via
// resolveAccessMethod(). It is applied through its own dedicated route
// (app/api/devices/[id]/snmp) and its own form (components/devices/
// SnmpConfigForm.js), not through DeviceForm.js/CredentialForm.js's
// vendor+method-driven flow — a device's SNMP config doesn't change when
// its mgmt_method does. Listed here so it can be validated/reused by the
// shared credential_profiles system (CREDENTIAL_TYPES is also this file's
// contribution to that reuse — see lib/credentialProfiles.js).
export const CREDENTIAL_TYPES = ['smc_api', 'rest_api', 'ssh', 'snmp'];

// The only devices.mgmt_method values that may be stored.
export const ACCESS_METHODS = ['smc', 'api', 'ssh'];

/**
 * Resolves the per-method config for a vendor, falling back to the vendor's
 * default method when `accessMethod` is null/unknown (legacy rows predate the
 * mgmt_method selector and may carry null or a stale value).
 * @returns {{method: string, config: object}|null}
 */
export function resolveAccessMethod(vendorSlug, accessMethod) {
  const meta = VENDOR_META[vendorSlug];
  if (!meta) return null;
  const method =
    accessMethod && meta.accessMethods[accessMethod] ? accessMethod : meta.defaultAccessMethod;
  const config = meta.accessMethods[method];
  if (!config) return null;
  return { method, config };
}

/** true when the vendor exposes a choice worth rendering a selector for. */
export function hasMultipleAccessMethods(vendorSlug) {
  const meta = VENDOR_META[vendorSlug];
  return !!meta && Object.keys(meta.accessMethods).length > 1;
}

/**
 * Builds the plaintext handed to credStore.setCredential.
 *
 * NOTE the asymmetry, it is deliberate:
 *  - 'secret' (forcepoint) stays a RAW string. It already works in production
 *    and its adapter reads the plaintext directly — do not "tidy" it into JSON.
 *  - everything else is JSON, so the adapter can tell an api-key from a
 *    username/password without guessing.
 *
 * @param {string} vendorSlug
 * @param {string} accessMethod   key of VENDOR_META[vendor].accessMethods
 * @param {object} input
 * @param {'apikey'|'userpass'} [input.authMode]  required for 'apikey_or_userpass'
 * @returns {string|null} plaintext, or null when the vendor/method is unknown
 */
export function buildCredentialPlaintext(
  vendorSlug,
  accessMethod,
  { authMode, secret, username, password, enablePassword } = {}
) {
  const resolved = resolveAccessMethod(vendorSlug, accessMethod);
  if (!resolved) return null;
  const { credentialShape } = resolved.config;

  if (credentialShape === 'secret') {
    return secret || '';
  }

  if (credentialShape === 'apikey_or_userpass') {
    // Default to apikey when unspecified — matches the pre-existing behaviour
    // for fortinet/paloalto, whose only auth mode used to be a bare token.
    if (authMode === 'userpass') {
      return JSON.stringify({ username: username || '', password: password || '' });
    }
    return JSON.stringify({ api_key: secret || '' });
  }

  const obj = { username: username || '', password: password || '' };
  if (credentialShape === 'userpass_enable' && enablePassword) {
    obj.enable_password = enablePassword;
  }
  return JSON.stringify(obj);
}
