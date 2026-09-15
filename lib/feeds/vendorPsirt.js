// lib/feeds/vendorPsirt.js
//
// Which vendor PSIRT feeds are worth running on THIS installation.
//
// ⛔ THE DISTINCTION THIS FILE ENCODES. A vendor's own PSIRT is a bespoke
// integration — its own transport, its own parser, its own auth or bot
// challenge, and its own way of breaking. It is worth carrying only for a
// vendor whose devices are actually in the inventory, because its advisories
// can only ever match those devices.
//
// The GENERAL databases are the opposite case and are deliberately NOT gated
// here: NVD and CIRCL are queried for every supported vendor whether or not one
// is deployed, so that a firewall added next month already has history behind
// it rather than starting from the day it was racked. Discovery breadth is
// cheap there and expensive in a PSIRT.
//
// ⛔ NOTHING HERE DELETES ANYTHING. Advisories already ingested for a vendor
// that has since left the inventory are history and stay. A device can come
// back, and a CVE does not stop having been true.

'use strict';

/**
 * The registry. A vendor appears here only when a MACHINE-READABLE source has
 * been verified reachable from a deployment — CLAUDE.md's "verify against live
 * responses before writing any parser" applies to feeds exactly as it does to
 * device parsers.
 *
 * ⛔ Probed from the reference deployment 2026-09-15, and the two obvious
 * additions did NOT qualify:
 *
 *   checkpoint  — no machine-readable feed found. `advisories.checkpoint.com`
 *                 and its /feed/ and /wp-json/ paths all answer **202 with
 *                 text/html**, which is a bot challenge rather than content.
 *                 Parsing that is the same ground `fortinet_psirt` is already
 *                 stuck on (232 of 460 runs succeeded, last clean run 27 days
 *                 before that probe), and adding a second feed with the same
 *                 failure mode buys nothing.
 *   cisco_asa   — a PSIRT RSS DOES exist and works (HTTP 200, 8 items, 19
 *                 distinct CVE ids), but it is a rolling recent-advisories
 *                 window with no history, and the real source (openVuln,
 *                 api.cisco.com/security/advisories/v2) answers **403** without
 *                 registered OAuth credentials. Viable but thin; it is left out
 *                 until either credentials exist or the rolling window is
 *                 judged worth having on its own. Registering it later is the
 *                 one-line addition this table exists to make cheap.
 *
 * @type {Object<string, {feedName: string, run: function}>}
 */
const VENDOR_PSIRTS = {};

/** Register a vendor PSIRT. Keyed by the `devices.vendor` slug, exactly. */
function registerVendorPsirt(vendorSlug, feedName, run) {
  VENDOR_PSIRTS[vendorSlug] = { feedName, run };
}

/**
 * The vendor slugs with at least one ACTIVE device.
 *
 * ⛔ ACTIVE ONLY. A decommissioned firewall's vendor should stop pulling a feed
 * — that is the whole point — and its existing advisories are untouched either
 * way.
 *
 * @returns {Promise<{ok: true, vendors: Set<string>} | {ok: false, error: string}>}
 *   ⛔ The failure is RETURNED, not thrown and not swallowed into an empty set.
 *   An empty set and an unreadable inventory are opposite instructions: the
 *   first says "skip every PSIRT", the second must say "we do not know".
 */
async function inventoryVendors(pool) {
  try {
    const { rows } = await pool.query(
      'SELECT DISTINCT vendor FROM devices WHERE active = true AND vendor IS NOT NULL'
    );
    return { ok: true, vendors: new Set(rows.map((r) => String(r.vendor))) };
  } catch (err) {
    return { ok: false, error: err.message || String(err) };
  }
}

/**
 * Decide, per registered PSIRT, whether this run should fetch it.
 *
 * ⛔ AN UNREADABLE INVENTORY FAILS OPEN — every feed runs. This is the one
 * place in this module where the safe direction is to do MORE work: a database
 * hiccup that silently switched off CVE discovery would leave the product
 * quietly not doing its main job, and the next sync would look identical to a
 * healthy one. Wasting a fetch is recoverable; missing a KEV-listed advisory
 * because a SELECT timed out is not.
 *
 * @returns {{vendor, feedName, run, shouldRun, reason}[]}
 */
function planVendorPsirts(inventory, registry = VENDOR_PSIRTS) {
  const entries = Object.entries(registry).map(([vendor, cfg]) => ({ vendor, ...cfg }));

  if (!inventory || inventory.ok !== true) {
    const why = inventory && inventory.error ? inventory.error : 'reason unknown';
    return entries.map((e) => ({
      ...e,
      shouldRun: true,
      reason: `The device inventory could not be read (${why}), so every vendor feed was fetched `
        + 'rather than risk skipping one that is needed.',
    }));
  }

  return entries.map((e) => {
    const present = inventory.vendors.has(e.vendor);
    return {
      ...e,
      shouldRun: present,
      reason: present
        ? null
        : `No active ${e.vendor} device is in the inventory, so this vendor's own advisory feed was `
          + 'not fetched. General sources (NVD, CIRCL) still cover this vendor, and advisories '
          + 'already collected for it are kept.',
    };
  });
}

// ⛔ 'skipped' IS NOT A FAILURE AND MUST NOT BE COLOURED LIKE ONE. It is
// recorded so the absence of a run is visible and explained — a feed that
// simply stops appearing is indistinguishable from one that silently broke —
// but the dashboard's badge maps anything unrecognised to amber, so this status
// is handled explicitly there. See syncBadgeColor in app/(dashboard)/page.js.
const SKIPPED = 'skipped';

module.exports = {
  VENDOR_PSIRTS,
  SKIPPED,
  registerVendorPsirt,
  inventoryVendors,
  planVendorPsirts,
};
