// lib/syslog/authOutcomes.js
//
// Did a VPN authentication SUCCEED, FAIL, or is this not an authentication at
// all? One vocabulary, mirroring lib/syslog/actions.js in shape and intent.
//
// ⛔ THREE-STATE. `null` means "not an authentication event" and is the answer
// for the overwhelming majority of VPN rows — IPsec tunnel negotiation, HIP
// checks, tunnel-latency reports, pre-login page fetches. Folding any of those
// into success or failure is how this feature would lie.
//
// ⛔ THE TRAP THAT MAKES THIS A MODULE RATHER THAN AN INLINE CHECK, verified on
// live data: PAN-OS GlobalProtect writes `status=success` on rows that are not
// logins at all.
//
//   portal-prelogin / before-login   status=success   3,399 rows in 3 hours
//       The portal serving its pre-login page to an anonymous browser. It
//       carries NO username, which is the tell.
//   gateway-connected / gateway-register / gateway-setup-ipsec
//       Later stages of the SAME login — counting them turns one login into
//       four.
//
// So the rule is: gate on the EVENT ID being an authentication stage FIRST,
// then read status. Reading status alone inflates successful logins by roughly
// an order of magnitude.
//
// ⛔ COVERAGE IS LOPSIDED AND CALLERS MUST SAY SO. Measured over 12 hours on
// this fleet: Fortinet produced 2,037 `ssl-login-fail` and ~4 successes. Its
// SSL-VPN success logids are effectively absent — a device-side logging
// setting, not a SecVault gap. Any UI built on this must show the two vendors
// separately and render Fortinet's success count as "not reported", never 0,
// or it reports a device configuration gap as a security fact.

'use strict';

// PAN-OS GlobalProtect: the only event ids that ARE an authentication.
const PAN_AUTH_EVENT_IDS = new Set(['gateway-auth', 'portal-auth']);

// FortiOS SSL-VPN. `ssl-login-fail` is the failure signal and is abundant here;
// the success verbs are listed for completeness even though this fleet's
// FortiGates do not currently emit them.
// ⛔ `tunnel-up` IS NOT HERE, AND MUST NOT BE PUT BACK UNCONDITIONALLY.
// FortiOS emits the same verb for a site-to-site IPsec tunnel completing
// phase 2 (`tunneltype="ipsec"`, logid 0101037138, logdesc "IPsec
// connection status changed") and for a real SSL-VPN tunnel-mode login
// (`tunneltype="ssl-web"` / `"ssl-tunnel"`). A gateway is not a person:
// counting the IPsec form turned site-to-site tunnels into "successful VPN
// logins".
//
// Measured live 2026-09-10 BEFORE the fix: every Fortinet VPN "success" on
// this fleet was an IPsec tunnel — 6 rows in 12h, 14 rows / 19 events in the
// PERMANENT rollup — and 6 of 6 carried an IP address where the username
// should be. Over 36h: 15 IPsec tunnel-up against 3 ssl-web + 2 ssl-tunnel.
// So deleting the verb outright would have destroyed 5 REAL logins to remove
// 15 fake ones. That is why this is gated on tunnel type rather than removed.
const FORTINET_SUCCESS_ACTIONS = new Set(['ssl-login']);
const FORTINET_TUNNEL_UP_ACTION = 'tunnel-up';
const FORTINET_FAILURE_ACTIONS = new Set(['ssl-login-fail']);

// SSL-VPN tunnel types seen live: ssl, ssl-web, ssl-tunnel.
function isSslTunnelType(tunnelType) {
  return String(tunnelType || '').trim().toLowerCase().startsWith('ssl');
}

/**
 * @param {string|null} vendor
 * @param {string|null} logSubtype  PAN-OS: the GlobalProtect event id
 * @param {string|null} status      PAN-OS: success | failure
 * @param {string|null} action      FortiOS: ssl-login-fail | ssl-login | ...
 * @param {string|null} tunnelType  FortiOS: ssl-web | ssl-tunnel | ipsec | null
 * @returns {'success'|'failure'|null} null = NOT an authentication event
 */
function classifyAuthOutcome(vendor, logSubtype, status, action, tunnelType) {
  const v = String(vendor || '').toLowerCase();

  if (v === 'paloalto') {
    const evt = String(logSubtype || '').trim().toLowerCase();
    // ⛔ The gate. Without it, pre-login page fetches read as successful logins.
    if (!PAN_AUTH_EVENT_IDS.has(evt)) return null;
    const s = String(status || '').trim().toLowerCase();
    if (s === 'success') return 'success';
    if (s === 'failure') return 'failure';
    // An auth event whose status we do not recognise is UNKNOWN, not a failure.
    return null;
  }

  if (v === 'fortinet') {
    const a = String(action || '').trim().toLowerCase();
    if (FORTINET_FAILURE_ACTIONS.has(a)) return 'failure';
    if (FORTINET_SUCCESS_ACTIONS.has(a)) return 'success';
    // ⛔ tunnel-up is a success ONLY for an SSL-VPN tunnel. An IPsec
    // tunnel-up is two gateways establishing a site-to-site link, not a
    // person logging in.
    // ⛔ An ABSENT or unrecognised tunnel type resolves to null, NEVER to
    // success — the same rule actions.js applies to an unknown vendor verb:
    // an unrecognised shape must not be able to manufacture an affirmative.
    if (a === FORTINET_TUNNEL_UP_ACTION) {
      return isSslTunnelType(tunnelType) ? 'success' : null;
    }
    return null;
  }

  // No parser exists for the other four supported vendors, so there is nothing
  // to classify — and the UI must say they are unrepresented rather than imply
  // fleet-wide coverage.
  return null;
}

module.exports = {
  classifyAuthOutcome,
  isSslTunnelType,
  FORTINET_TUNNEL_UP_ACTION,
  PAN_AUTH_EVENT_IDS,
  FORTINET_SUCCESS_ACTIONS,
  FORTINET_FAILURE_ACTIONS,
};
