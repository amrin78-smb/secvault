// lib/productLicenseData.js
//
// The plumbing behind lib/productLicense.js: read the install date, the stored
// key and the monitored-firewall count out of the database, hand them to the
// pure decision functions, and cache the verdict.
//
// Split the same way `segmentation.js` / `segmentationData.js` and
// `workQueue.js` / `workQueueData.js` are split — the judgement is pure and
// testable, this file is the part that touches a pool.

'use strict';

const L = require('./productLicense');

const SETTING_KEY = 'product_license_key';
const SETTING_INSTALL = 'install_date';

// ⛔ CACHED, BECAUSE THIS IS ON THE WRITE PATH OF EVERY GATED ROUTE. Without it
// a licence check is three queries plus an AES decrypt per mutation. Five
// minutes matches the cadence the sibling apps already use.
//
// ⛔ AND ONLY A SUCCESSFUL READ IS CACHED. Caching a failed load would pin the
// install into an "unknown" verdict for five minutes after a momentary database
// blip — turning a one-second hiccup into a five-minute inability to add a
// firewall, with nothing on screen to explain it.
const CACHE_MS = 5 * 60 * 1000;
let _cache = null;
let _cachedAt = 0;

/** ⛔ MUST be called by anything that changes the key, or activation appears to do nothing for 5 minutes. */
function invalidate() {
  _cache = null;
  _cachedAt = 0;
}

/**
 * The install date, from settings — and if it is not there, from evidence.
 *
 * ⛔ A MISSING ROW MUST NOT GRANT A FRESH 30 DAYS. NetVault reports the full
 * trial length whenever `install_date` is absent, which makes `DELETE FROM
 * app_settings WHERE key='install_date'` an unlimited trial extension. Here the
 * date is instead DERIVED from the oldest thing in the database that could only
 * have been created at install time — the first user account — falling back to
 * the oldest device. Deleting the row therefore re-derives the real date rather
 * than resetting the clock, and the derived value is written back so the
 * derivation happens once.
 *
 * ⛔ The derived date is an UPPER BOUND on the true install date (the database
 * cannot contain a row older than itself), which is the safe direction: it can
 * only ever make the trial look YOUNGER than it is, never older. Erring the
 * other way would cut a genuine customer's evaluation short.
 *
 * @returns {Promise<{date: string|null, derived: boolean, error: string|null}>}
 */
async function resolveInstallDate(pool) {
  let stored = null;
  try {
    const { rows } = await pool.query('SELECT value FROM settings WHERE key = $1', [SETTING_INSTALL]);
    stored = rows.length ? rows[0].value : null;
  } catch (err) {
    return { date: null, derived: false, error: err.message || String(err) };
  }
  if (stored && String(stored).trim()) {
    return { date: String(stored).trim(), derived: false, error: null };
  }

  let derived = null;
  try {
    const { rows } = await pool.query(
      `SELECT LEAST(
                (SELECT MIN(created_at) FROM users),
                (SELECT MIN(created_at) FROM devices)
              ) AS first_seen`
    );
    derived = rows.length && rows[0].first_seen ? new Date(rows[0].first_seen).toISOString() : null;
  } catch (err) {
    return { date: null, derived: false, error: err.message || String(err) };
  }

  if (!derived) return { date: null, derived: false, error: null };

  // Write it back so the derivation is a one-off. Best effort: failing to
  // persist must not fail the licence check that prompted it.
  try {
    await pool.query(
      `INSERT INTO settings (key, value) VALUES ($1, $2)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
       WHERE settings.value IS NULL OR settings.value = ''`,
      [SETTING_INSTALL, derived]
    );
  } catch { /* best effort */ }

  return { date: derived, derived: true, error: null };
}

/**
 * How many firewalls this install monitors.
 *
 * ⛔ `active = true`, THE SAME DEFINITION THE PSIRT GATE USES. A firewall the
 * customer has deactivated is not being monitored, is not costing them a
 * licensed slot, and is not pulling a vendor advisory feed — one definition of
 * "monitored", used everywhere, or the invoice and the product disagree.
 *
 * ⛔ RETURNS null ON FAILURE, NEVER 0. `count` arrives from node-pg as a
 * STRING, and a failed read reported as zero would say the customer monitors no
 * firewalls — which reads as "plenty of room under the limit" and lets the
 * limit be walked straight past.
 *
 * @returns {Promise<{count: number|null, error: string|null}>}
 */
async function countMonitoredDevices(pool) {
  try {
    const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM devices WHERE active = true');
    const n = rows.length ? rows[0].n : null;
    return { count: Number.isInteger(n) ? n : null, error: null };
  } catch (err) {
    return { count: null, error: err.message || String(err) };
  }
}

async function readKey(pool) {
  try {
    const { rows } = await pool.query('SELECT value FROM settings WHERE key = $1', [SETTING_KEY]);
    return { key: rows.length && rows[0].value ? String(rows[0].value) : '', error: null };
  } catch (err) {
    return { key: '', error: err.message || String(err) };
  }
}

/**
 * The full verdict for this install.
 *
 * @param {object} pool
 * @param {{force?: boolean, now?: Date}} [opts]
 */
async function getLicenseVerdict(pool, opts = {}) {
  const now = opts.now || new Date();
  if (!opts.force && _cache && Date.now() - _cachedAt < CACHE_MS) return _cache;

  const id = L.getServerId();
  const [install, keyRead, devices] = await Promise.all([
    resolveInstallDate(pool),
    readKey(pool),
    countMonitoredDevices(pool),
  ]);

  const verdict = L.getLicenseStatus({
    installDate: install.date,
    licenseKey: keyRead.key,
    localHash: id.hash,
    deviceCount: devices.count,
    now,
  });

  const out = {
    ...verdict,
    serverId: id.serverId,
    serverIdWeak: id.weak,
    serverIdSource: id.source,
    installDate: install.date,
    installDateDerived: install.derived,
    // ⛔ The read errors travel WITH the verdict rather than being logged and
    // dropped. A verdict computed over a fleet count that failed to load is a
    // different thing from one computed over a real count, and the UI says so.
    readErrors: [install.error, keyRead.error, devices.error].filter(Boolean),
    sentence: L.licenceSentence(verdict),
  };

  // Only a clean read is cached (see the note on CACHE_MS).
  if (out.readErrors.length === 0) {
    _cache = out;
    _cachedAt = Date.now();
  }
  return out;
}

/**
 * Store a key, after checking it is one.
 *
 * ⛔ AN INVALID KEY IS NEVER STORED. Storing it would move the install from
 * `trial` to `invalid` — i.e. a typo during a trial would lock the customer out
 * of a trial they were entitled to for another three weeks.
 */
async function activateLicense(pool, key) {
  const id = L.getServerId();
  const res = L.validateLicenseKey(key, id.hash);
  if (!res.valid) {
    return { ok: false, code: res.code, error: res.error, serverId: id.serverId };
  }
  await pool.query(
    `INSERT INTO settings (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
    [SETTING_KEY, String(key).trim()]
  );
  invalidate();
  return { ok: true, payload: res.payload, serverId: id.serverId };
}

/**
 * Remove the stored key, returning the install to its trial/expired state.
 *
 * ⛔ Exists so a customer moving SecVault to new hardware is not stuck: the old
 * key names the old machine and would otherwise sit there reporting `invalid`
 * forever with no way to clear it from the UI.
 */
async function clearLicense(pool) {
  await pool.query('DELETE FROM settings WHERE key = $1', [SETTING_KEY]);
  invalidate();
}

// ─────────────────────────────────────────────────────────────────────────────
// Route guards
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Guard for administrative writes. Returns a body+status to send, or null.
 *
 * ⛔ FAILS OPEN ON AN UNREADABLE LICENCE STATE, deliberately, and this is the
 * opposite of how the RBAC guard behaves one line above it in every route that
 * uses both. RBAC answers "is this person allowed" and must fail closed.
 * Licensing answers "has the invoice been paid", and a database blip must never
 * be able to lock a paying customer out of their own firewall-management
 * platform. The authorisation boundary is still enforced; only the billing one
 * yields.
 */
async function licenceBlockForWrite(pool) {
  let verdict;
  try {
    verdict = await getLicenseVerdict(pool);
  } catch {
    return null;
  }
  if (L.writeAllowed(verdict)) return null;
  return {
    status: 403,
    body: {
      error: verdict.sentence.text,
      code: 'LICENSE_' + String(verdict.status).toUpperCase(),
      licenseStatus: verdict.status,
      serverId: verdict.serverId,
    },
  };
}

/**
 * Guard for adding a firewall — the licensed unit.
 *
 * ⛔ Checked at ADD time only. Nothing anywhere re-checks it against a device
 * that is already in the inventory; see `monitoringAllowed` in productLicense.js
 * for why that line matters more than any other in this feature.
 */
async function licenceBlockForNewDevice(pool) {
  let verdict;
  try {
    verdict = await getLicenseVerdict(pool, { force: true });
  } catch {
    return null;
  }
  const decision = L.canAddDevice(verdict);
  if (decision.allowed) return null;
  return {
    status: 403,
    body: {
      error: decision.reason,
      code: 'LICENSE_' + String(decision.code || 'blocked').toUpperCase(),
      licenseStatus: verdict.status,
      maxDevices: verdict.maxDevices,
      deviceCount: verdict.deviceCount,
      serverId: verdict.serverId,
    },
  };
}

module.exports = {
  SETTING_KEY,
  SETTING_INSTALL,
  CACHE_MS,
  invalidate,
  resolveInstallDate,
  countMonitoredDevices,
  getLicenseVerdict,
  activateLicense,
  clearLicense,
  licenceBlockForWrite,
  licenceBlockForNewDevice,
};
