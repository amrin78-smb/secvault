// ─────────────────────────────────────────────────────────────────────────────
// FROZEN Tier 1 vendor table — single source of truth for vendor slugs.
// Slugs are load-bearing: they drive adapter dispatch, version comparator
// selection, and NVD feed CPE matching. Do NOT rename or add slugs casually.
//
// This module is plain constants + pure helpers (no 'use client', no React) so
// it is importable from both client components (DeviceForm, CredentialForm)
// and server-side API routes (app/api/devices/*).
//
// connection:       'smc'  → device uses smc_host + smc_port
//                   'mgmt' → device uses mgmt_ip + mgmt_port
// credentialShape:  'secret'          → single secret string, stored raw
//                   'userpass'        → {"username","password"} stored as JSON string
//                   'userpass_enable' → {"username","password","enable_password"?} JSON string
// ─────────────────────────────────────────────────────────────────────────────

export const VENDOR_META = {
  forcepoint: {
    label: 'Forcepoint (SMC)',
    mgmtMethod: 'smc',
    connection: 'smc',
    defaultPort: 8082,
    credentialType: 'smc_api',
    credentialShape: 'secret',
    secretLabel: 'SMC API Key',
  },
  fortinet: {
    label: 'Fortinet FortiGate',
    mgmtMethod: 'api',
    connection: 'mgmt',
    defaultPort: 443,
    credentialType: 'rest_api',
    credentialShape: 'secret',
    secretLabel: 'API Token',
  },
  paloalto: {
    label: 'Palo Alto PAN-OS',
    mgmtMethod: 'api',
    connection: 'mgmt',
    defaultPort: 443,
    credentialType: 'rest_api',
    credentialShape: 'secret',
    secretLabel: 'API Key',
  },
  checkpoint: {
    label: 'Check Point (Mgmt API)',
    mgmtMethod: 'api',
    connection: 'mgmt',
    defaultPort: 443,
    credentialType: 'rest_api',
    credentialShape: 'userpass',
  },
  cisco_asa: {
    label: 'Cisco ASA (SSH)',
    mgmtMethod: 'ssh',
    connection: 'mgmt',
    defaultPort: 22,
    credentialType: 'ssh',
    credentialShape: 'userpass_enable',
  },
  sangfor: {
    label: 'Sangfor (SSH)',
    mgmtMethod: 'ssh',
    connection: 'mgmt',
    defaultPort: 22,
    credentialType: 'ssh',
    credentialShape: 'userpass',
  },
};

export const VENDOR_SLUGS = Object.keys(VENDOR_META);

// The only credential_type values credStore rows may carry.
export const CREDENTIAL_TYPES = ['smc_api', 'rest_api', 'ssh'];

// Builds the plaintext string handed to credStore.setCredential for a vendor:
// raw secret for single-secret vendors, JSON string for username/password vendors.
// enable_password is only included when provided (it is optional for cisco_asa).
export function buildCredentialPlaintext(vendorSlug, { secret, username, password, enablePassword } = {}) {
  const meta = VENDOR_META[vendorSlug];
  if (!meta) return null;
  if (meta.credentialShape === 'secret') {
    return secret || '';
  }
  const obj = { username: username || '', password: password || '' };
  if (meta.credentialShape === 'userpass_enable' && enablePassword) {
    obj.enable_password = enablePassword;
  }
  return JSON.stringify(obj);
}
