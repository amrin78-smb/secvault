// lib/adapters/snmpCredential.js
// Shared credential-plaintext parsing/building for the 'snmp' credential_type.
// CommonJS ONLY — required by vendor adapters (in turn required by
// services/engine-worker.js, plain node) and by app/api/devices/[id]/snmp
// and app/api/credential-profiles routes.
//
// Mirrors lib/adapters/credentials.js's parseApiCredential / lib/adapters/
// sshClient.js's parseJsonCredential: the write side lives in
// lib/credentialProfiles.js's buildProfilePlaintext ('snmp' branch) and
// app/api/devices/[id]/snmp/route.js (buildSnmpDevicePlaintext below). Keep
// all three in step.
//
// Stored plaintext shapes:
//   v1/v2c: {"version":"v1"|"v2c","community":"..."}
//   v3:     {"version":"v3","username":"...","authProtocol":"SHA"|"MD5"|null,
//            "authPassword":"..."|null,"privProtocol":"AES"|"DES"|null,
//            "privPassword":"..."|null}
//
// ⛔ NEVER include the decrypted plaintext (or any fragment) in a thrown
// error, log line, or API response — same discipline as credentials.js.

'use strict';

const VALID_AUTH_PROTOCOLS = ['MD5', 'SHA'];
const VALID_PRIV_PROTOCOLS = ['DES', 'AES'];

/**
 * @param {string} plaintext decrypted credential (JSON)
 * @returns {{version:'v1'|'v2c',community:string}|{version:'v3',username:string,authProtocol:string|null,authPassword:string|null,privProtocol:string|null,privPassword:string|null}}
 * @throws {Error} secret-free, actionable message when unusable
 */
function parseSnmpCredential(plaintext) {
  if (typeof plaintext !== 'string' || plaintext.trim() === '') {
    throw new Error('No SNMP credential stored for this device — configure one under the device SNMP tab.');
  }
  let parsed;
  try {
    parsed = JSON.parse(plaintext);
  } catch (err) {
    throw new Error('Stored SNMP credential is not valid JSON. Re-save it under the device SNMP tab.');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Stored SNMP credential JSON must be an object.');
  }

  if (parsed.version === 'v3') {
    if (!parsed.username || typeof parsed.username !== 'string') {
      throw new Error('Stored SNMPv3 credential is missing "username". Re-save it under the device SNMP tab.');
    }
    return {
      version: 'v3',
      username: parsed.username,
      authProtocol: VALID_AUTH_PROTOCOLS.includes(parsed.authProtocol) ? parsed.authProtocol : null,
      authPassword: typeof parsed.authPassword === 'string' && parsed.authPassword !== '' ? parsed.authPassword : null,
      privProtocol: VALID_PRIV_PROTOCOLS.includes(parsed.privProtocol) ? parsed.privProtocol : null,
      privPassword: typeof parsed.privPassword === 'string' && parsed.privPassword !== '' ? parsed.privPassword : null,
    };
  }

  const version = parsed.version === 'v1' ? 'v1' : 'v2c';
  if (!parsed.community || typeof parsed.community !== 'string') {
    throw new Error(`Stored SNMP${version} credential is missing "community". Re-save it under the device SNMP tab.`);
  }
  return { version, community: parsed.community };
}

module.exports = { parseSnmpCredential, VALID_AUTH_PROTOCOLS, VALID_PRIV_PROTOCOLS };
