// lib/engines/deviceHealth.js
//
// Derived status for the device lifecycle & health data collected 2026-08-03
// (device_licenses / device_ha_status / device_disk_usage /
// device_content_versions).
//
// PURE — no DB access, no I/O, no Date.now() baked in (every function takes an
// explicit `now`), so every branch is fixture-testable without Postgres. Same
// convention as riskScore.js, which is likewise a scoring/banding layer over
// data another module already collected.
//
// Status is computed HERE at read time rather than stored as findings. The raw
// facts (dates, states, percentages) are what's persisted; "is that expiring /
// stale / degraded" is a pure function of those facts plus the current time, so
// storing it would only create a second thing that can go stale. Wiring these
// statuses into the fleet alert feed and outbound notifications is a deliberate
// follow-up, not an oversight.
//
// ⛔ TRI-STATE DISCIPLINE (the same rule CLAUDE.md enforces for config_applies
// and compliance pass_when): missing or unparseable data resolves to 'unknown',
// NEVER to a confident 'ok'. A licence whose expiry string didn't parse is not
// "fine" — it is unknown, and must be visibly unknown, because silently calling
// it fine is exactly how a support contract lapses unnoticed.
//
// CommonJS only, matching every other lib/engines/*.js file.

'use strict';

const MS_PER_DAY = 24 * 60 * 60 * 1000;

// Support/licence expiry warning window. 60 days is deliberately generous
// relative to ruleAnalysis.js's 14-day rule-expiry window: a firewall support
// contract needs procurement lead time, not a fortnight's notice.
const DEFAULT_LICENSE_WARN_DAYS = 60;

// Signature staleness threshold. Palo Alto ships AV/threat content at least
// daily (confirmed live: av released the previous day, wildfire the same day),
// so a week without an update is a real signal rather than normal variance.
const DEFAULT_SIGNATURE_STALE_DAYS = 7;

const DISK_WARNING_PERCENT = 80;
const DISK_CRITICAL_PERCENT = 90;

function toDate(value) {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value !== 'string' || value.trim() === '') return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

function daysBetween(from, to) {
  return Math.floor((to.getTime() - from.getTime()) / MS_PER_DAY);
}

/**
 * Status of one device_licenses row.
 *
 * @param {object} row - { expires_at, expires_raw, expired }
 * @param {Date} now
 * @param {number} [warnDays]
 * @returns {{status:'expired'|'expiring'|'ok'|'perpetual'|'unknown', daysRemaining:number|null}}
 *
 * The device's own `expired` verdict wins when it says true — it knows better
 * than our date arithmetic (clock skew, grace periods, vendor-side changes).
 * `expired === false` is NOT treated as authoritative the other way: a licence
 * the device currently considers valid can still be days from lapsing, which is
 * the whole point of the warning window.
 */
function licenseStatus(row, now, warnDays = DEFAULT_LICENSE_WARN_DAYS) {
  const at = now instanceof Date ? now : new Date();
  if (!row || typeof row !== 'object') return { status: 'unknown', daysRemaining: null };

  if (row.expired === true) return { status: 'expired', daysRemaining: null };

  const expiresAt = toDate(row.expires_at !== undefined ? row.expires_at : row.expiresAt);
  if (!expiresAt) {
    // No parsed date. The raw string is what distinguishes THREE different
    // situations that would otherwise collapse into a useless "unknown":
    const raw = typeof row.expires_raw === 'string' ? row.expires_raw : row.expiresRaw;
    const text = typeof raw === 'string' ? raw.trim() : '';
    // 1. Perpetual — Palo Alto reports 'Never' for licences that never lapse.
    if (/^never$/i.test(text)) {
      return { status: 'perpetual', daysRemaining: null };
    }
    // 2. NOT LICENSED — FortiOS reports 'n/a' for a component this device has
    //    no entitlement for at all (live: OT Threat / IoT Detect definitions).
    //    That is a definite, device-asserted fact, NOT missing information, so
    //    it must not read as "unknown" (which implies someone should go look)
    //    and must never appear in a renewal table — there is nothing to renew.
    if (/^n\/?a$/i.test(text)) {
      return { status: 'not_licensed', daysRemaining: null };
    }
    // 3. Genuinely unreadable — the vendor gave a value we could not parse.
    return { status: 'unknown', daysRemaining: null };
  }

  const daysRemaining = daysBetween(at, expiresAt);
  if (daysRemaining < 0) return { status: 'expired', daysRemaining };
  if (daysRemaining <= warnDays) return { status: 'expiring', daysRemaining };
  return { status: 'ok', daysRemaining };
}

/**
 * Worst licence status across a device's entitlements, for a summary tile.
 * Ordered by severity so one expired licence is never hidden behind ten fine
 * ones. 'perpetual' collapses into 'ok' for summary purposes; 'unknown' ranks
 * above 'ok' because it needs a human to look.
 */
// not_licensed ranks with ok/perpetual: it needs no action, so it must never
// win the summary tile over a real renewal.
const LICENSE_SEVERITY = { expired: 4, expiring: 3, unknown: 2, ok: 1, perpetual: 1, not_licensed: 0 };

function worstLicenseStatus(rows, now, warnDays = DEFAULT_LICENSE_WARN_DAYS) {
  const list = Array.isArray(rows) ? rows : [];
  if (list.length === 0) return { status: 'unknown', daysRemaining: null, row: null };
  let worst = null;
  for (const row of list) {
    const s = licenseStatus(row, now, warnDays);
    const rank = LICENSE_SEVERITY[s.status] || 0;
    if (
      worst === null ||
      rank > worst.rank ||
      // Same severity: prefer the one expiring soonest, so the summary points
      // at the most urgent renewal rather than an arbitrary one.
      (rank === worst.rank &&
        typeof s.daysRemaining === 'number' &&
        typeof worst.daysRemaining === 'number' &&
        s.daysRemaining < worst.daysRemaining)
    ) {
      worst = { rank, status: s.status, daysRemaining: s.daysRemaining, row };
    }
  }
  return { status: worst.status, daysRemaining: worst.daysRemaining, row: worst.row };
}

/**
 * Staleness of one content/signature component.
 * @returns {{status:'stale'|'ok'|'unknown', ageDays:number|null}}
 */
function signatureStatus(row, now, staleDays = DEFAULT_SIGNATURE_STALE_DAYS) {
  const at = now instanceof Date ? now : new Date();
  if (!row || typeof row !== 'object') return { status: 'unknown', ageDays: null };
  const released = toDate(row.released_at !== undefined ? row.released_at : row.releasedAt);
  // No release date (e.g. PAN-OS reports none for url-filtering) → unknown.
  // Deliberately not inferred from a date-looking version string.
  if (!released) return { status: 'unknown', ageDays: null };
  const ageDays = daysBetween(released, at);
  return { status: ageDays > staleDays ? 'stale' : 'ok', ageDays };
}

/**
 * Oldest/worst signature across a device's components, for a summary tile.
 */
function worstSignatureStatus(rows, now, staleDays = DEFAULT_SIGNATURE_STALE_DAYS) {
  const list = Array.isArray(rows) ? rows : [];
  if (list.length === 0) return { status: 'unknown', ageDays: null, row: null };
  let worst = null;
  for (const row of list) {
    const s = signatureStatus(row, now, staleDays);
    if (s.status === 'unknown') continue; // a component with no date can't be the "oldest"
    if (worst === null || s.ageDays > worst.ageDays) worst = { ...s, row };
  }
  return worst || { status: 'unknown', ageDays: null, row: null };
}

/**
 * HA health for one device_ha_status row.
 * @returns {{status:'standalone'|'healthy'|'degraded'|'unknown', reasons:string[]}}
 *
 * `degraded` is reserved for conditions that indicate the pair is not currently
 * providing the redundancy it is supposed to. Note what deliberately does NOT
 * make a pair degraded: a `Last suspended state reason: User requested` — that
 * is a recorded admin action on an otherwise healthy pair, and the parser
 * already keeps it out of last_nonfunctional_reason for exactly this reason.
 */
function haStatus(row) {
  if (!row || typeof row !== 'object' || row.enabled === null || row.enabled === undefined) {
    return { status: 'unknown', reasons: [] };
  }
  if (row.enabled === false) return { status: 'standalone', reasons: [] };

  const reasons = [];
  const peerConn = typeof row.peer_connection_status === 'string' ? row.peer_connection_status : row.peerConnectionStatus;
  const sync = typeof row.config_sync_state === 'string' ? row.config_sync_state : row.configSyncState;
  const compatOk = row.version_compat_ok !== undefined ? row.version_compat_ok : row.versionCompatOk;
  const nonFunctional = row.last_nonfunctional_reason !== undefined ? row.last_nonfunctional_reason : row.lastNonfunctionalReason;
  const peerState = typeof row.peer_state === 'string' ? row.peer_state : row.peerState;

  if (peerConn && !/^up$/i.test(peerConn)) reasons.push(`Peer connection is "${peerConn}", not up.`);
  if (!peerState) reasons.push('No peer state reported.');
  if (sync && !/^synchronized$/i.test(sync)) reasons.push(`Running configuration is "${sync}", not synchronized.`);
  // false only — NULL means the device reported no compatibility block and must
  // not be read as a mismatch any more than as a match.
  if (compatOk === false) reasons.push('Software or content versions do not match across the pair.');
  if (nonFunctional) reasons.push(`Peer last went non-functional: ${nonFunctional}.`);

  return { status: reasons.length > 0 ? 'degraded' : 'healthy', reasons };
}

/**
 * Worst filesystem across a device's mounts.
 * @returns {{status:'critical'|'warning'|'ok'|'unknown', usePercent:number|null, row:object|null}}
 */
function diskStatus(rows) {
  const list = Array.isArray(rows) ? rows : [];
  let worst = null;
  for (const row of list) {
    const pct = row && (row.use_percent !== undefined ? row.use_percent : row.usePercent);
    const value = typeof pct === 'string' ? Number(pct) : pct;
    if (!Number.isFinite(value)) continue;
    if (worst === null || value > worst.usePercent) worst = { usePercent: value, row };
  }
  if (worst === null) return { status: 'unknown', usePercent: null, row: null };
  const status =
    worst.usePercent >= DISK_CRITICAL_PERCENT ? 'critical'
      : worst.usePercent >= DISK_WARNING_PERCENT ? 'warning'
        : 'ok';
  return { status, usePercent: worst.usePercent, row: worst.row };
}

module.exports = {
  licenseStatus,
  worstLicenseStatus,
  signatureStatus,
  worstSignatureStatus,
  haStatus,
  diskStatus,
  DEFAULT_LICENSE_WARN_DAYS,
  DEFAULT_SIGNATURE_STALE_DAYS,
  DISK_WARNING_PERCENT,
  DISK_CRITICAL_PERCENT,
};
