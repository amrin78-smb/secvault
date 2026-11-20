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

// ⛔ ONE access-method config, shared by every monitoring-only vendor, so two
// of them cannot drift into describing the same state differently.
//
// ⛔ `credentialShape: 'none'` IS LOAD-BEARING. Without it
// `buildCredentialPlaintext` falls through to its userpass branch and returns
// `{"username":"","password":""}` — an EMPTY CREDENTIAL stored in
// `device_credentials`, which reads as "credentials were supplied and are
// blank" rather than "this device has none by design", and would send a future
// adapter off to authenticate with it.
const SYSLOG_ONLY_METHOD = {
  label: 'Syslog only (no management connection)',
  // ⛔ No defaultPort. A port here would be written to `mgmt_port` and would
  // claim SecVault talks to something on it.
  defaultPort: null,
  credentialType: null,
  credentialShape: 'none',
};

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
  sophos: {
    label: 'Sophos Firewall (SFOS)',
    connection: 'mgmt',
    defaultAccessMethod: 'api',
    // ⛔ ONE access method, although the adapter speaks TWO protocols.
    // connectors.md 13b: the XML API has no version/licence/HA surface and the
    // SSH console cannot dump a rulebase, so the adapter uses SSH internally
    // for getVersion/getHaStatus/getDiskUsage. SSH is NOT a standalone way to
    // manage this device — it cannot list rules — so there is deliberately no
    // `ssh` entry here: a method an operator can pick must be able to collect a
    // policy. The adapter falls back to this `rest_api` credential for its SSH
    // connection when no separate `ssh` credential is stored.
    accessMethods: {
      api: {
        label: 'XML API (HTTPS)',
        // ⛔ 4444, NOT 443 — the SFOS web-admin port, verified live against
        // SFOS 22.0.3 MR-3-Build576 (connectors.md 13b). 443 is the user portal
        // on this appliance, not the API.
        defaultPort: 4444,
        credentialType: 'rest_api',
        // ⛔ 'userpass', NOT 'apikey_or_userpass'. Palo Alto and Check Point use
        // the latter because PAN-OS mints an API key from username+password via
        // ?type=keygen. SFOS has NO API-key auth mode at all — the XML API
        // carries a <Login><Username>/<Password> block inside the body of EVERY
        // request. An api-key field here would render a credential input that
        // cannot work, and no secretLabel is declared for the same reason.
        credentialShape: 'userpass',
      },
    },
  },
  // ⛔ MONITORING-ONLY VENDORS. SecVault parses their syslog (verified against
  // real corpora — see .ai-codex/connectors.md sections 14 and 15) and has NO
  // ADAPTER for either, so `syslog` is their ONLY access method. Before this
  // they could not be added at all, and their events were stored unattributed.
  //
  // ⛔ `connection: 'mgmt'` AND `mgmt_ip` IS REQUIRED, which is not a leftover:
  // the collector's IP->device map is vendor-agnostic and matches on
  // `mgmt_ip`/`snmp_host`/`smc_host` plus `device_syslog_sources`, so for a
  // log-only firewall `mgmt_ip` IS the address its syslog arrives from. It is
  // the one field that makes attribution work.
  juniper: {
    label: 'Juniper SRX (logs only)',
    connection: 'mgmt',
    defaultAccessMethod: 'syslog',
    monitoringOnly: true,
    accessMethods: {
      syslog: SYSLOG_ONLY_METHOD,
    },
  },
  sonicwall: {
    label: 'SonicWall SonicOS (logs only)',
    connection: 'mgmt',
    defaultAccessMethod: 'syslog',
    monitoringOnly: true,
    accessMethods: {
      syslog: SYSLOG_ONLY_METHOD,
    },
  },
};

export const VENDOR_SLUGS = Object.keys(VENDOR_META);

// ⛔ THE VENDORS A CVE CAN EVER BE FILED AGAINST — DERIVED, NEVER LISTED.
//
// A managed vendor is registered in SEVEN places; `VENDOR_CPES` (lib/feeds/
// nvd.js) and a `VENDOR_PARSERS` version scheme are two of them, and a
// MONITORING-ONLY vendor is in none. So no `advisories` row and no
// `device_cve_assessments` row can ever carry `juniper` or `sonicwall`, and a
// vendor filter offering them would be a control that can only ever return
// "no results" — which reads as "this firewall has no vulnerabilities" and is
// this codebase's failed-read-as-a-fact rule wearing a dropdown.
//
// ⛔ DO NOT "COMPLETE" THE LIST by adding the monitoring-only slugs. The day
// one of them gains an adapter it gains CPEs in the same commit and appears
// here on its own — which is the whole reason this is a filter over the
// registry and not six hardcoded <option> elements. Those six were how the
// Advisories and CVE Posture filters silently omitted Sophos for three
// releases after it shipped as the seventh managed vendor.
export const MANAGED_VENDOR_SLUGS = VENDOR_SLUGS.filter(
  (slug) => !VENDOR_META[slug].monitoringOnly
);

// Short forms for narrow table columns. The full `label` stays available for
// the `title` attribute, so nothing is lost by using these.
export const VENDOR_SHORT_LABEL = {
  forcepoint: 'Forcepoint',
  fortinet: 'FortiGate',
  paloalto: 'Palo Alto',
  checkpoint: 'Check Point',
  cisco_asa: 'Cisco ASA',
  sangfor: 'Sangfor',
  sophos: 'Sophos',
  // ⛔ The short label carries NO "(logs only)" qualifier, deliberately. It is
  // used in narrow fleet-table columns beside managed firewalls, and a
  // parenthetical there would be truncated to noise. The monitoring-only state
  // is carried by a STATE marker on the row, never by the vendor's name.
  juniper: 'Juniper',
  sonicwall: 'SonicWall',
};

/**
 * Human name for a vendor slug.
 *
 * ⛔ WHY THIS EXISTS: `paloalto`, `cisco_asa` and `checkpoint` are internal
 * DISPATCH KEYS, not product names, and they were rendered raw at 18 sites —
 * the fleet Devices table, the dashboard's Top Risky Devices, every compliance
 * header, the advisories table and the VPN page. The damning part was the
 * inconsistency: VendorDistribution.js on the SAME dashboard already resolved
 * the label correctly, and AdvisoriesTab's own filter dropdown read "Cisco ASA"
 * while the rows beneath it read `cisco_asa`.
 *
 * ⛔ Falls back to the slug itself, never to a blank or a prettified guess. An
 * unrecognised slug is a real signal (a vendor added to the DB but not to this
 * table) and hiding it would make that invisible.
 *
 * @param {string} slug
 * @param {{short?: boolean}} [opts] short form for narrow columns
 */
export function vendorLabel(slug, opts) {
  if (!slug) return null;
  if (opts && opts.short) {
    return VENDOR_SHORT_LABEL[slug] || (VENDOR_META[slug] && VENDOR_META[slug].label) || slug;
  }
  return (VENDOR_META[slug] && VENDOR_META[slug].label) || slug;
}

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

  // ⛔ NULL, NEVER AN EMPTY OBJECT. A monitoring-only device has no credential
  // by design; the fall-through below would build `{"username":"","password":""}`
  // and store it, which is a different claim entirely.
  if (credentialShape === 'none') return null;

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
