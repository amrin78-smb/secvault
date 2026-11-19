// lib/monitoringOnly.js
//
// ONE definition of "this firewall is in the inventory for its LOGS, and
// SecVault will never connect to it".
//
// ⛔ WHY THIS EXISTS. SecVault parses syslog from more vendors than it can
// manage — `juniper` and `sonicwall` have verified parsers and no adapter. Until
// now there was no way to ADD such a firewall at all: `POST /api/devices`
// rejects any vendor outside `VENDOR_META`, so its events were stored with
// `device_id NULL`, it appeared only on `/devices/discovered`, and it was
// excluded from the evidence window, the capacity forecast and change outcome
// by their deliberate `device_id IS NOT NULL` filters. A firewall the product
// could read and could not name.
//
// ⛔ THE DANGEROUS PART IS NOT ADDING IT — IT IS WHAT HAPPENS AFTERWARDS.
// `workQueueData.js` states it exactly: "a firewall that has not been collected
// from produces NO CVEs, NO compliance failures and NO rule findings — it is
// silently the cleanest device on the fleet." A monitoring-only device has that
// property BY CONSTRUCTION and for ever. So it is never hidden, never excluded
// from a coverage count, and never allowed to read as assessed. It gets its own
// work-queue item saying what it cannot answer and how to change that.
//
// ⛔ AND IT IS A DELIBERATE STATE, NOT A FAULT. "We cannot reach this firewall"
// and "we were never going to try" are different facts with different first
// steps — the same distinction `feedStatus.js` draws between a publisher
// refusing us (`blocked`) and our own decision not to run (`skipped`), and the
// same reason `skipped` renders muted rather than amber. The remedy is real and
// is stated: give it a management connection.
//
// ⛔ PURE, DEPENDENCY-FREE CommonJS, like lib/rbac.js — `services/engine-worker.js`
// requires the adapter registry under plain node, which cannot load ESM, while
// `components/devices/vendorMeta.js` is an ES module that client components
// import. Both sides need this constant and neither may own it.

'use strict';

/**
 * The `devices.mgmt_method` value that means "logs only".
 *
 * ⛔ IT IS A METHOD, NOT A VENDOR FLAG, and that is the load-bearing choice.
 * Modelling it as a vendor property would make it untrue the day somebody owns
 * a Fortinet they have no credentials for — which is the common case this
 * unlocks next, and is a strictly better state than leaving that firewall out
 * of the inventory so its syslog lands unattributed.
 */
const MONITORING_ONLY_METHOD = 'syslog';

/** True when SecVault will never open a management connection to this device. */
function isMonitoringOnly(device) {
  return Boolean(device) && device.mgmt_method === MONITORING_ONLY_METHOD;
}

// ⛔ The one sentence, so the work queue, the device page and any future
// surface cannot drift into describing this state three different ways.
const MONITORING_ONLY_CLAIM =
  'SecVault reads this firewall’s logs and does not connect to it, so it has no '
  + 'vulnerability assessment, no compliance result and no rule analysis — not because '
  + 'it passed them, but because they were never run.';

const MONITORING_ONLY_REMEDY =
  'Add a management connection (vendor, address and credentials) to assess this firewall. '
  + 'Its log collection is unaffected either way.';

module.exports = {
  MONITORING_ONLY_METHOD,
  MONITORING_ONLY_CLAIM,
  MONITORING_ONLY_REMEDY,
  isMonitoringOnly,
};
