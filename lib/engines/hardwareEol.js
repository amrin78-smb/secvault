// lib/engines/hardwareEol.js
//
// Hardware end-of-life for the firewalls themselves — "this chassis stops being
// supported on this date".
//
// ⛔ THIS IS NOT `/lifecycle`'s EXISTING LICENCE VIEW, AND THE TWO MUST NOT BE
// CONFLATED. `device_licenses` / `deviceHealth.licenseStatus()` answer "what
// support CONTRACTS does this device report about itself" (FortiGuard
// entitlements, PAN-OS support). This answers "when does the VENDOR stop
// supporting this hardware at all". A device can hold a perfectly valid support
// contract on a chassis whose end-of-support is next year.
//
// PURE. Takes the catalogue and the devices as arguments; no pool, no clock it
// is not given. `lib/feeds/eolFeed.js` is the plumbing that fills the catalogue.

'use strict';

const { normalizeForMatch, vendorLabelFor } = require('../eolNormalize');

/**
 * ⛔ THREE STATES, NOT TWO, AND THE THIRD IS THE WHOLE POINT.
 *
 * Measured against the live catalogue on 2026-09-17: 2 of 16 firewalls matched.
 * Every unmatched one is CURRENT-generation hardware (PA-440/460/3410, PA-VM,
 * FortiGate-60F/80F) which plausibly has no published EOL date yet.
 *
 * So "not in the catalogue" means EITHER "the vendor has published no date" OR
 * "nobody has curated this model yet", and the feed cannot presently tell them
 * apart. Rendering either one as "no EOL announced — you are fine" would be an
 * absence reported as an affirmative fact, on exactly the question this feature
 * exists to answer. It is `hit_count`'s old `DEFAULT 0` wearing a lifecycle hat.
 *
 * `no_date_published` is therefore built NOW even though the feed does not yet
 * emit it — when the hub starts recording "checked, vendor publishes no date as
 * of <date>", this engine and its UI already handle it and nothing is rewritten.
 */
const EOL_STATE = {
  /** The catalogue gave a real support-end date. */
  DATED: 'dated',
  /** The catalogue explicitly records that the vendor publishes no date. */
  NO_DATE_PUBLISHED: 'no_date_published',
  /** ⛔ Not in the catalogue. UNKNOWN — never "fine". */
  UNKNOWN: 'unknown',
  /** SecVault never collected a model for this device, so nothing can be asked. */
  NO_MODEL: 'no_model',
};

/** How close to end-of-support before it is worth saying so. */
const APPROACHING_DAYS = 365;

const MS_PER_DAY = 24 * 60 * 60 * 1000;

function parseDate(v) {
  if (!v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * The date as `YYYY-MM-DD`, whatever shape it arrived in.
 *
 * ⛔ node-pg RETURNS A `DATE` COLUMN AS A JavaScript Date, NOT A STRING, and
 * this engine's fixtures all used strings — so every test passed while the live
 * page rendered
 *   "Thu Aug 31 2028 00:00:00 GMT+0700 (Indochina Time)"
 * in a column headed "End of support". Caught only by running it against the
 * real database.
 *
 * ⛔ Formatted from the UTC parts, never `toISOString()` on a local-midnight
 * Date. A `DATE` of 2028-08-31 arrives as local midnight; at UTC+7 that is
 * 2028-08-30T17:00Z, and toISOString would render the day BEFORE. An
 * end-of-support date that is silently a day early is the kind of wrong nobody
 * notices until it matters.
 */
function toDateString(v) {
  if (!v) return null;
  if (typeof v === 'string') return v.slice(0, 10);
  const d = v instanceof Date ? v : new Date(v);
  if (Number.isNaN(d.getTime())) return null;
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/**
 * Build the lookup index from catalogue rows.
 *
 * ⛔ EVERY ALIAS IS INDEXED, not just the canonical model. The seed's `matches`
 * array is `[canonical, ...aliases]` precisely because one chassis is spelled
 * several ways across vendor tables, SKUs and legacy inventories — indexing only
 * `matches[0]` would silently drop the spellings the aliases exist to catch.
 *
 * ⛔ FIRST WRITER WINS on a duplicate key, matching the hub's own dedupe, so two
 * catalogue rows normalising to the same key cannot make the answer depend on
 * row order.
 */
function buildIndex(rows) {
  const index = new Map();
  for (const r of rows || []) {
    if (!r) continue;
    const spellings = [r.modelRaw, ...(Array.isArray(r.aliases) ? r.aliases : [])];
    for (const spelling of spellings) {
      const key = normalizeForMatch(r.vendor, spelling);
      if (key && !index.has(key)) index.set(key, r);
    }
  }
  return index;
}

/**
 * Resolve one device against the catalogue.
 *
 * @param {{vendor: string, model: string|null}} device
 * @param {Map} index  from buildIndex()
 * @param {Date} [now]
 */
function resolveDevice(device, index, now = new Date()) {
  const model = device && device.model ? String(device.model).trim() : '';

  if (!model) {
    // ⛔ Distinct from UNKNOWN. "We never collected a model" is a SecVault
    // coverage gap the operator can act on (fix collection); "not in the
    // catalogue" is a catalogue gap they cannot. Collapsing them would hide a
    // broken collector behind a data-coverage excuse.
    return {
      state: EOL_STATE.NO_MODEL,
      matchKey: null,
      supportEndDate: null,
      daysRemaining: null,
      approaching: false,
      pastEnd: false,
      reason: 'SecVault has not collected a hardware model for this firewall, so its '
        + 'end-of-support date cannot be looked up.',
    };
  }

  const label = vendorLabelFor(device.vendor);
  const key = normalizeForMatch(label || device.vendor, model);
  const row = index.get(key);

  if (!row) {
    return {
      state: EOL_STATE.UNKNOWN,
      matchKey: key,
      supportEndDate: null,
      daysRemaining: null,
      approaching: false,
      pastEnd: false,
      // ⛔ The wording is deliberate and must not become reassuring. It says what
      // we do NOT know, not that there is nothing to know.
      reason: `${model} is not in the lifecycle catalogue. That may mean the vendor has published `
        + 'no end-of-support date for it yet, or that the catalogue does not cover it — SecVault '
        + 'cannot tell which, so this is reported as unknown rather than as no end-of-support.',
    };
  }

  if (row.noDatePublished === true) {
    return {
      state: EOL_STATE.NO_DATE_PUBLISHED,
      matchKey: key,
      supportEndDate: null,
      daysRemaining: null,
      approaching: false,
      pastEnd: false,
      confidence: row.confidence || null,
      source: row.source || null,
      checkedAt: toDateString(row.checkedAt),
      reason: `${row.vendor} has published no end-of-support date for ${model}`
        + (row.checkedAt ? ` as of ${toDateString(row.checkedAt)}.` : '.'),
    };
  }

  const end = parseDate(row.supportEndDate);
  if (!end) {
    // A catalogue row with an unparseable date is NOT a date. Same rule as the
    // device-licence expiry: never treat an unreadable value as "fine".
    return {
      state: EOL_STATE.UNKNOWN,
      matchKey: key,
      supportEndDate: null,
      daysRemaining: null,
      approaching: false,
      pastEnd: false,
      confidence: row.confidence || null,
      reason: `${model} is in the catalogue but its end-of-support date could not be read.`,
    };
  }

  const daysRemaining = Math.ceil((end.getTime() - now.getTime()) / MS_PER_DAY);
  // ⛔ Normalised HERE, at the one place a date leaves this engine.
  const endStr = toDateString(row.supportEndDate);
  return {
    state: EOL_STATE.DATED,
    matchKey: key,
    supportEndDate: endStr,
    osEolDate: toDateString(row.osEolDate),
    daysRemaining,
    approaching: daysRemaining > 0 && daysRemaining <= APPROACHING_DAYS,
    pastEnd: daysRemaining <= 0,
    confidence: row.confidence || null,
    source: row.source || null,
    reason: daysRemaining <= 0
      ? `${model} passed end-of-support on ${endStr}.`
      : `${model} reaches end-of-support on ${endStr} (${daysRemaining} days).`,
  };
}

/**
 * Resolve a whole fleet, with coverage.
 *
 * ⛔ COVERAGE IS REPORTED ALONGSIDE THE ANSWER, ALWAYS. A fleet summary that
 * says "0 firewalls past end-of-support" over a catalogue that matched 2 of 16
 * is true and useless, and reads as an all-clear. `lib/evidence.js` already
 * forbids an all-clear while coverage is incomplete, and this returns what that
 * rule needs to enforce it.
 */
function resolveFleet(devices, catalogueRows, now = new Date()) {
  const index = buildIndex(catalogueRows);
  const results = (devices || []).map((d) => ({
    deviceId: d.id,
    name: d.name,
    vendor: d.vendor,
    model: d.model || null,
    ...resolveDevice(d, index, now),
  }));

  const counts = {
    dated: 0, no_date_published: 0, unknown: 0, no_model: 0,
  };
  for (const r of results) counts[r.state] = (counts[r.state] || 0) + 1;

  const pastEnd = results.filter((r) => r.pastEnd);
  const approaching = results.filter((r) => r.approaching);
  const answered = counts.dated + counts.no_date_published;

  return {
    results,
    counts,
    pastEnd: pastEnd.length,
    approaching: approaching.length,
    total: results.length,
    answered,
    // ⛔ null, not 0, on an empty fleet — a percentage over nothing is not 0%.
    coveragePct: results.length ? Math.round((answered / results.length) * 100) : null,
    // ⛔ THE FLAG THAT FORBIDS AN ALL-CLEAR. True whenever any firewall could not
    // be answered, whatever the headline count says.
    incomplete: counts.unknown > 0 || counts.no_model > 0,
  };
}

module.exports = {
  EOL_STATE,
  toDateString,
  APPROACHING_DAYS,
  buildIndex,
  resolveDevice,
  resolveFleet,
};
