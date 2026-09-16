// lib/productLicense.js
//
// SecVault's own commercial licence: a 30-day trial by default, then a
// per-device yearly subscription.
//
// ⛔ NAMED `productLicense`, NOT `license`, DELIBERATELY. This codebase already
// has a `device_licenses` table, a `getLicenses()` adapter capability and a
// `/lifecycle` page — all about the FIREWALL VENDOR'S licences (FortiGuard
// contracts, PAN-OS support entitlements). Those answer "is the customer's
// firewall still entitled to signatures"; this file answers "is the customer
// entitled to SecVault". Two unrelated things one word apart is how a later
// session edits the wrong one, so the name carries the distinction.
//
// ⛔ SECVAULT IS A SEPARATE PRODUCT AND VALIDATES ITS OWN KEY. LogVault,
// DDIVault and SpanVault do not validate anything — they HTTP-GET NetVault's
// `/api/license` and cache the verdict, because they are suite modules sold with
// the hub. SecVault is sold on its own and CLAUDE.md forbids any runtime
// dependency on a sibling app, so it follows NetVault's shape (validate
// locally) rather than the satellites'.
//
// The KEY FORMAT is byte-compatible with the existing NocVault licence
// generator, so one generator issues keys for the whole range:
//
//     base64( ivHex + ':' + aes-256-cbc-ciphertext-hex )
//     cipher key = sha256(LICENSE_SECRET)
//     plaintext  = JSON {customer, serverId, expiry, modules, maxDevices, issuedAt}
//
// PURE except for `getServerId()`, which reads the machine's own identity. Every
// decision function takes its inputs as arguments so it can be tested without a
// database, a registry or a clock.

'use strict';

const { execSync } = require('child_process');
const { createHash, createDecipheriv } = require('crypto');
const os = require('os');
// ⛔ The banner rule lives in its own import-free module because a 'use client'
// component needs it and THIS file requires child_process/crypto — importing
// this one from the browser bundle fails the build. Re-exported below so there
// is exactly one definition of when to warn someone their licence has lapsed.
const { bannerFor } = require('./licenceBanner');

// ⛔ THE SHARED SECRET, AND WHAT IT IS AND IS NOT WORTH.
//
// This is the same symmetric secret every NocVault product uses, carried here
// on purpose: the customer-facing requirement is that ONE generator issues keys
// for the whole range, and a different secret here would mean a second
// generator and a second thing to keep in step.
//
// Be clear-eyed about what that buys. Anyone who can read this file can forge a
// key. It is not a licence SERVER and there is no revocation — it raises the
// cost of casual copying (a key is bound to one machine and one expiry) and
// nothing more. That is the accepted trade for an on-premises product with no
// call-home, and it is the same trade NetVault documented and deliberately kept.
//
// ⛔ THE REAL FIX, IF THIS EVER BECOMES WORTH ATTACKING, IS ASYMMETRIC SIGNING —
// keep a private signing key out of every repo and ship only the public half, so
// reading the source stops being enough to mint licences. Rotating this literal
// is NOT that fix: it re-issues every key in the field for the same weakness.
//
// The env var is a per-install rotation hook. Setting it means only that server
// needs re-issued keys. No installer provisions it, so the literal is what runs.
const LICENSE_SECRET = process.env.SECVAULT_LICENSE_SECRET
  || process.env.NETVAULT_LICENSE_SECRET
  || 'NocVault-License-Secret-2026-X9K';

/** Days of full function before any key is needed. */
const TRIAL_DAYS = 30;

// ⛔ LONGER THAN NETVAULT'S 7. This is a YEARLY subscription: a renewal runs
// through a purchase order, and a customer whose PO is sitting in someone's
// approval queue has not stopped being a customer. Two weeks is the difference
// between a reminder and an outage, and an outage on a firewall-security
// platform is an event the customer's auditor asks about.
const GRACE_DAYS = 14;

/** How far ahead a yearly renewal starts being surfaced. */
const RENEWAL_NOTICE_DAYS = 60;

// ⛔ THE PRODUCT ENTITLEMENT THIS FILE EXISTS TO CHECK. A licence lists the
// products it covers; SecVault is only covered when its own name is on it.
const MODULE = 'secvault';

const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * Statuses. FIVE, not four.
 *
 * ⛔ `invalid` IS ITS OWN STATE, and adding it is the one substantive
 * correction to the shape inherited from NetVault. There, a key that fails to
 * validate falls straight through to the trial branch — so a customer who pastes
 * a key issued for the wrong server, or for a different product, is told
 * "trial, 12 days remaining" and never learns their key did nothing. The key was
 * READ AND REJECTED; reporting that as "no key" is this codebase's own
 * failed-read-as-a-fact bug wearing a commercial hat, and it generates a support
 * call that the reason string answers by itself.
 */
const STATUS = {
  TRIAL: 'trial',
  ACTIVE: 'active',
  GRACE: 'grace',
  EXPIRED: 'expired',
  INVALID: 'invalid',
};

// ─────────────────────────────────────────────────────────────────────────────
// Machine identity
// ─────────────────────────────────────────────────────────────────────────────

function machineGuid() {
  try {
    const out = execSync(
      'reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid',
      { encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] }
    );
    const m = out.match(/MachineGuid\s+REG_SZ\s+([^\r\n]+)/);
    return m ? m[1].trim() : '';
  } catch {
    return '';
  }
}

/**
 * A stable secondary fingerprint for when the registry cannot be read.
 *
 * ⛔ WITHOUT THIS, A FAILED REGISTRY READ IS A LICENCE HOLE. NetVault's
 * getMachineGuid() returns '' on failure and the server id becomes a hash of
 * `hostname-` alone — so every machine that failed the same way AND shares a
 * hostname gets the SAME server id, and one key unlocks all of them. Falling
 * back to a MAC address keeps the identity machine-specific; `weak` records
 * that we are on the fallback, because an identity we are less sure of should
 * say so rather than look identical to a confident one.
 */
function macFingerprint() {
  try {
    const ifaces = os.networkInterfaces();
    const macs = [];
    for (const name of Object.keys(ifaces).sort()) {
      for (const a of ifaces[name] || []) {
        if (a && !a.internal && a.mac && a.mac !== '00:00:00:00:00:00') macs.push(a.mac);
      }
    }
    return macs.sort()[0] || '';
  } catch {
    return '';
  }
}

/**
 * Build the server id from supplied parts. Separated from `getServerId()` so
 * the derivation is testable without touching the real machine.
 *
 * @returns {{serverId: string, weak: boolean, source: string, hash: string}}
 */
function deriveServerId(hostname, guid, mac, prefix = 'SCV') {
  const host = String(hostname || '');
  let ident = String(guid || '');
  let source = 'machine-guid';
  let weak = false;

  if (!ident) {
    ident = String(mac || '');
    source = ident ? 'mac-address' : 'hostname-only';
    // ⛔ Both fallbacks are weaker than the registry GUID, and `hostname-only`
    // is weak enough to be collidable. We still PRODUCE an id rather than
    // refusing to start: a product that will not boot because it could not
    // fingerprint the machine has turned a licensing detail into an outage.
    weak = true;
  }

  const hash = createHash('sha256').update(host + '-' + ident).digest('hex').slice(0, 32);
  return { serverId: prefix + '-' + hash, weak, source, hash };
}

// Constant for the life of the process, and `execSync` blocks the event loop,
// so it is computed once.
let _serverId = null;

/** @returns {{serverId: string, weak: boolean, source: string, hash: string}} */
function getServerId() {
  if (_serverId) return _serverId;
  _serverId = deriveServerId(os.hostname(), machineGuid(), macFingerprint());
  return _serverId;
}

/** Test seam only — resets the memoised identity. */
function _resetServerId() {
  _serverId = null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Key validation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Does this payload's serverId name THIS machine?
 *
 * ⛔ THE PREFIX IS NOT PART OF THE MACHINE'S IDENTITY — the 32-hex hash is. A
 * key issued as `NCV-<hash>` and a key issued as `SCV-<hash>` name the same
 * physical server, and which one the generator emits depends on a tool this
 * repo does not contain. Accepting both means a working key is a working key
 * whichever prefix the generator chose; it loosens nothing, because the hash
 * still has to match and the PRODUCT boundary is enforced separately by
 * `modules`. Getting this wrong in the other direction would reject every
 * legitimately-issued key for a reason no error message could explain.
 */
function serverIdMatches(payloadServerId, localHash) {
  if (typeof payloadServerId !== 'string' || !localHash) return false;
  const m = payloadServerId.trim().match(/^[A-Z]{2,5}-([0-9a-f]{32})$/i);
  if (!m) return false;
  return m[1].toLowerCase() === String(localHash).toLowerCase();
}

/**
 * Does this licence cover SecVault?
 *
 * ⛔ FAILS CLOSED ON AN EMPTY MODULE LIST, and this is the one place SecVault
 * deliberately does the OPPOSITE of its siblings. LogVault/DDIVault/SpanVault
 * treat an empty `modules` as "allow" so that legacy suite keys issued before
 * per-module gating existed are never bricked. SecVault has no legacy keys —
 * it has never shipped a licence — so there is nothing to protect, and failing
 * open would silently turn every NocVault suite key already in the field into a
 * free SecVault licence. That is not so much a security bug as giving the
 * product away.
 */
function coversSecVault(modules) {
  return Array.isArray(modules) && modules.some(
    (m) => String(m).trim().toLowerCase() === MODULE
  );
}

function parseDate(v) {
  if (!v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Whole days from `now` to `then`, rounded up. Negative once past. */
function daysUntil(then, now) {
  return Math.ceil((then.getTime() - now.getTime()) / MS_PER_DAY);
}

/**
 * Decrypt and check a key.
 *
 * ⛔ A REJECTION ALWAYS CARRIES A REASON, and the reason distinguishes the four
 * genuinely different failures — unreadable, wrong machine, wrong product,
 * expired — because the customer's next action differs in each case (re-type it
 * / get it re-issued for this server / buy SecVault / renew). One flat "invalid
 * licence key" makes all four into the same support call.
 *
 * @returns {{valid: boolean, payload?: object, error?: string, code?: string}}
 */
function validateLicenseKey(key, localHash, now = new Date()) {
  let payload;
  try {
    const decoded = Buffer.from(String(key || '').trim(), 'base64').toString('utf8');
    const i = decoded.indexOf(':');
    if (i === -1) throw new Error('bad format');
    const iv = Buffer.from(decoded.slice(0, i), 'hex');
    const secretKey = createHash('sha256').update(LICENSE_SECRET).digest();
    const decipher = createDecipheriv('aes-256-cbc', secretKey, iv);
    let plain = decipher.update(decoded.slice(i + 1), 'hex', 'utf8');
    plain += decipher.final('utf8');
    payload = JSON.parse(plain);
  } catch {
    return {
      valid: false,
      code: 'unreadable',
      error: 'This licence key could not be read. Check it was copied in full, with no line breaks.',
    };
  }

  if (!payload || typeof payload !== 'object') {
    return { valid: false, code: 'unreadable', error: 'This licence key could not be read.' };
  }

  if (!serverIdMatches(payload.serverId, localHash)) {
    return {
      valid: false,
      code: 'wrong_server',
      payload,
      error: 'This licence key was issued for a different server. '
        + 'Send the Server ID shown on this page to have it re-issued.',
    };
  }

  if (!coversSecVault(payload.modules)) {
    return {
      valid: false,
      code: 'wrong_product',
      payload,
      error: 'This licence key is valid for this server but does not include SecVault. '
        + 'SecVault is licensed separately from the rest of the NocVault suite.',
    };
  }

  const expiry = parseDate(payload.expiry);
  if (!expiry) {
    return {
      valid: false,
      code: 'unreadable',
      payload,
      error: 'This licence key carries no readable expiry date.',
    };
  }
  if (expiry.getTime() < now.getTime()) {
    // ⛔ NOT `valid`, but NOT nothing either — the payload comes back so the
    // caller can offer grace and name the customer and the date it lapsed.
    return {
      valid: false,
      code: 'expired',
      payload,
      error: 'This licence expired on ' + payload.expiry + '.',
    };
  }

  return { valid: true, payload };
}

// ─────────────────────────────────────────────────────────────────────────────
// Status
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Days left in the trial.
 *
 * ⛔ AN UNKNOWN INSTALL DATE IS NOT A FRESH TRIAL. NetVault returns the full
 * TRIAL_DAYS when `install_date` is missing, which makes deleting one settings
 * row an unlimited trial extension. Here a missing date resolves to `null` and
 * the CALLER is expected to have derived one from the oldest thing in the
 * database (see productLicenseData.resolveInstallDate), so the trial is anchored
 * to evidence rather than to a row anyone can remove.
 */
function trialDaysRemaining(installDate, now = new Date()) {
  const start = parseDate(installDate);
  if (!start) return null;
  return TRIAL_DAYS - Math.floor((now.getTime() - start.getTime()) / MS_PER_DAY);
}

/**
 * How many devices this licence covers. `null` means UNLIMITED.
 *
 * ⛔ A TRIAL IS UNLIMITED, ON PURPOSE. The thing being evaluated is whether
 * SecVault can see a whole estate; a trial capped at some small number
 * demonstrates the opposite of the product. Thirty days is the limit.
 *
 * ⛔ A BARE `Number.isFinite(Number(x))` WOULD ACCEPT AN ABSENT LIMIT AS ZERO —
 * `Number(null)` is 0 and 0 is finite — turning "this licence does not state a
 * device count" into "this licence covers no devices" and locking a paying
 * customer out of their own fleet. A licence that does not say is unlimited.
 */
function deviceAllowance(status, payload) {
  if (status !== STATUS.ACTIVE && status !== STATUS.GRACE) return null;
  if (!payload) return null;
  const raw = payload.maxDevices;
  if (raw === null || raw === undefined || raw === '') return null;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.floor(n);
}

/**
 * Attach the device-count verdict.
 *
 * ⛔ `deviceCount === null` MEANS WE COULD NOT COUNT, NOT THAT THERE ARE NONE.
 * An uncountable fleet leaves `withinDeviceLimit` null — unknown — and the
 * caller must not read that as permission OR as refusal. A failed SELECT must
 * never be the reason a customer cannot add a firewall, and it must never be
 * the reason one slips past the limit either; it means ask again.
 */
function decorate(v, deviceCount) {
  const limit = deviceAllowance(v.status, v.payload);
  const count = Number.isInteger(deviceCount) ? deviceCount : null;
  return {
    status: v.status,
    daysRemaining: v.daysRemaining,
    payload: v.payload || null,
    renewalDue: v.renewalDue,
    reason: v.reason || null,
    code: v.code || null,
    customer: v.payload ? v.payload.customer || null : null,
    expiry: v.payload ? v.payload.expiry || null : null,
    modules: v.payload && Array.isArray(v.payload.modules) ? v.payload.modules : [],
    maxDevices: limit,
    deviceCount: count,
    devicesRemaining: limit === null || count === null ? null : limit - count,
    withinDeviceLimit: limit === null ? true : (count === null ? null : count <= limit),
    trialDaysTotal: TRIAL_DAYS,
    graceDays: GRACE_DAYS,
  };
}

/**
 * The whole verdict, from already-loaded inputs.
 *
 * @param {object} o
 * @param {string} o.installDate
 * @param {string} o.licenseKey
 * @param {string} o.localHash         the 32-hex machine hash from getServerId()
 * @param {number|null} o.deviceCount  active devices, or null if uncountable
 * @param {Date} [o.now]
 */
function getLicenseStatus({
  installDate, licenseKey, localHash, deviceCount = null, now = new Date(),
}) {
  const hasKey = typeof licenseKey === 'string' && licenseKey.trim() !== '';

  if (hasKey) {
    const res = validateLicenseKey(licenseKey, localHash, now);

    if (res.valid) {
      const daysRemaining = daysUntil(parseDate(res.payload.expiry), now);
      return decorate({
        status: STATUS.ACTIVE,
        daysRemaining,
        payload: res.payload,
        renewalDue: daysRemaining <= RENEWAL_NOTICE_DAYS,
        reason: null,
      }, deviceCount);
    }

    // An expired-but-otherwise-genuine key earns grace; the other rejections do
    // not, because nothing about them resolves itself with the passage of time.
    if (res.code === 'expired' && res.payload) {
      const daysRemaining = daysUntil(parseDate(res.payload.expiry), now);
      return decorate({
        status: daysRemaining >= -GRACE_DAYS ? STATUS.GRACE : STATUS.EXPIRED,
        daysRemaining,
        payload: res.payload,
        renewalDue: true,
        reason: res.error,
      }, deviceCount);
    }

    return decorate({
      status: STATUS.INVALID,
      daysRemaining: 0,
      payload: res.payload || null,
      renewalDue: false,
      reason: res.error,
      code: res.code,
    }, deviceCount);
  }

  const trial = trialDaysRemaining(installDate, now);

  if (trial === null) {
    // ⛔ No key and no derivable install date. Treated as a trial that has NOT
    // started rather than one that has run out: refusing a customer on the
    // strength of a fact we could not establish is the wrong direction, and the
    // install date is derived from evidence precisely so this stays rare.
    return decorate({
      status: STATUS.TRIAL,
      daysRemaining: TRIAL_DAYS,
      payload: null,
      renewalDue: false,
      reason: 'The install date could not be established, so the trial is reported from its full length.',
    }, deviceCount);
  }
  if (trial > 0) {
    return decorate({
      status: STATUS.TRIAL, daysRemaining: trial, payload: null, renewalDue: trial <= 7, reason: null,
    }, deviceCount);
  }
  if (trial >= -GRACE_DAYS) {
    return decorate({
      status: STATUS.GRACE, daysRemaining: trial, payload: null, renewalDue: true,
      reason: 'The 30-day trial has ended.',
    }, deviceCount);
  }
  return decorate({
    status: STATUS.EXPIRED, daysRemaining: trial, payload: null, renewalDue: true,
    reason: 'The 30-day trial has ended.',
  }, deviceCount);
}

// ─────────────────────────────────────────────────────────────────────────────
// What the licence actually gates
// ─────────────────────────────────────────────────────────────────────────────

/**
 * May this install take on ANOTHER firewall?
 *
 * ⛔ THIS IS THE ONLY THING THE DEVICE LIMIT DOES. It refuses to take on a NEW
 * firewall. It does not stop collecting from, assessing, scoring or alerting on
 * a firewall already in the inventory, in any licence state, ever — see
 * `monitoringAllowed` below for why the line is drawn exactly there.
 *
 * @returns {{allowed: boolean, reason: string|null, code: string|null}}
 */
function canAddDevice(verdict) {
  if (!verdict) {
    return { allowed: false, reason: 'The licence state could not be determined.', code: 'unknown' };
  }

  if (verdict.status === STATUS.EXPIRED) {
    return {
      allowed: false,
      code: 'expired',
      reason: 'The SecVault subscription has expired, so new firewalls cannot be added. '
        + 'Monitoring of the firewalls already in the inventory continues.',
    };
  }
  if (verdict.status === STATUS.INVALID) {
    return {
      allowed: false,
      code: 'invalid',
      reason: verdict.reason || 'The licence key on this install is not valid.',
    };
  }

  if (verdict.maxDevices === null) return { allowed: true, reason: null, code: null };

  if (verdict.deviceCount === null) {
    // ⛔ Unknown, not allowed-by-default. If we cannot count the fleet we cannot
    // say whether this device is the one that crosses the line.
    return {
      allowed: false,
      code: 'uncountable',
      reason: 'The number of monitored firewalls could not be read, so the licensed limit '
        + 'could not be checked. Try again.',
    };
  }

  if (verdict.deviceCount >= verdict.maxDevices) {
    return {
      allowed: false,
      code: 'device_limit',
      reason: 'This subscription covers ' + verdict.maxDevices + ' firewall'
        + (verdict.maxDevices === 1 ? '' : 's') + ' and ' + verdict.deviceCount + ' '
        + (verdict.deviceCount === 1 ? 'is' : 'are') + ' already monitored. '
        + 'Deactivate a firewall or extend the subscription to add another.',
    };
  }
  return { allowed: true, reason: null, code: null };
}

/**
 * ⛔ THE LINE THIS PRODUCT WILL NOT CROSS.
 *
 * Monitoring, assessment, scoring, alerting and reporting run in EVERY licence
 * state, including fully expired. There is no state in which SecVault stops
 * telling a customer that one of their firewalls is exposed.
 *
 * This is not generosity. A firewall that has silently stopped being assessed
 * shows no CVEs, no failing checks and no rule findings — it renders as the
 * HEALTHIEST device on the fleet. That is this codebase's most-repeated bug
 * class (a failed read recorded as an affirmative value) with a commercial
 * motive attached, aimed at exactly the customer least likely to be watching.
 * An unpaid invoice is a commercial problem; a security blind spot the customer
 * cannot see is a breach waiting to be attributed to us.
 *
 * Expiry withholds GROWTH and ADMINISTRATION — new firewalls, settings, users —
 * which the customer can see, can act on, and which does not endanger them.
 */
function monitoringAllowed() {
  return true;
}

/**
 * May a state-changing ADMINISTRATIVE action proceed?
 *
 * ⛔ ACKNOWLEDGING A FINDING IS NOT AN ADMINISTRATIVE WRITE. An operator
 * clearing an alert or acknowledging a config diff is part of READING the
 * product, and blocking it would leave an expired install unable to work the
 * queue it is still being shown. Gate device, settings and user changes; leave
 * the analyst's own workflow alone.
 */
function writeAllowed(verdict) {
  if (!verdict) return true;
  return verdict.status !== STATUS.EXPIRED && verdict.status !== STATUS.INVALID;
}

/**
 * One sentence, for a banner. Answer first.
 *
 * ⛔ NAMES THE NUMBER AND THE DATE. "Licence expiring soon" tells an operator
 * nothing they can act on; a date and a device count is what goes into the email
 * to whoever signs the renewal.
 */
function licenceSentence(v) {
  if (!v) return { tone: 'unknown', text: 'The licence state could not be determined.' };

  const devices = v.maxDevices === null
    ? ''
    : ' Covers ' + v.maxDevices + ' firewall' + (v.maxDevices === 1 ? '' : 's')
      + (v.deviceCount === null ? '' : ', ' + v.deviceCount + ' in use') + '.';

  switch (v.status) {
    case STATUS.TRIAL:
      return {
        tone: v.daysRemaining <= 7 ? 'warn' : 'info',
        text: 'Trial — ' + v.daysRemaining + ' of ' + TRIAL_DAYS + ' day'
          + (v.daysRemaining === 1 ? '' : 's') + ' remaining. All features are enabled and the '
          + 'number of firewalls is not limited during the trial.',
      };
    case STATUS.ACTIVE:
      return {
        tone: v.renewalDue ? 'warn' : 'ok',
        text: 'Licensed to ' + (v.customer || 'this organisation') + ' until ' + v.expiry
          + (v.renewalDue
            ? ' — renews in ' + v.daysRemaining + ' day' + (v.daysRemaining === 1 ? '' : 's') + '.'
            : '.')
          + devices,
      };
    case STATUS.GRACE: {
      const left = Math.max(0, GRACE_DAYS + v.daysRemaining);
      return {
        tone: 'warn',
        text: (v.reason || 'The subscription has lapsed.') + ' SecVault is running on a '
          + GRACE_DAYS + '-day grace period with ' + left + ' day' + (left === 1 ? '' : 's')
          + ' left. Monitoring is unaffected.',
      };
    }
    case STATUS.EXPIRED:
      return {
        tone: 'bad',
        text: 'The SecVault subscription has expired. Monitoring, assessment and alerting '
          + 'continue, but firewalls cannot be added and settings cannot be changed until it '
          + 'is renewed.',
      };
    case STATUS.INVALID:
      return { tone: 'bad', text: v.reason || 'The licence key on this install is not valid.' };
    default:
      return { tone: 'unknown', text: 'The licence state could not be determined.' };
  }
}

module.exports = {
  STATUS,
  TRIAL_DAYS,
  GRACE_DAYS,
  RENEWAL_NOTICE_DAYS,
  MODULE,
  getServerId,
  deriveServerId,
  serverIdMatches,
  coversSecVault,
  validateLicenseKey,
  trialDaysRemaining,
  getLicenseStatus,
  deviceAllowance,
  canAddDevice,
  monitoringAllowed,
  writeAllowed,
  licenceSentence,
  bannerFor,
  _resetServerId,
};
