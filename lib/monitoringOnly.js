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

/**
 * Should a PUT be refused for converting an already-collected firewall to
 * logs-only? Returns null to allow, or {error, code} to refuse with 409.
 *
 * ⛔ IT IS A FUNCTION SO IT CAN BE EXERCISED. The decision used to be an inline
 * `if` in `app/api/devices/[id]/route.js`, which `npm test` cannot reach — no
 * route harness exists here, and `npm run apisweep` refuses mutating verbs
 * because it runs against the production fleet. This repo has twice watched a
 * guard inside an unreachable module be asserted against its SOURCE TEXT and
 * pass over inverted logic, so the rule it follows (`lib/syslog/spoolFile.js`)
 * is to move the decision somewhere a test can call it.
 *
 * ⛔ WHY IT REFUSES. The PUT deletes credentials and NOTHING ELSE:
 * `device_versions`, `device_configs`, `firewall_rules`,
 * `device_cve_assessments`, `audit_findings`, `rule_analysis_results` and the
 * `last_*` stamps all survive, and `collectAndStore` then skips the device for
 * ever — so they are not stale, they are FROZEN, and `versionMatcher` re-matches
 * the frozen version on every feed sync and re-stamps `last_cve_assessed_at`,
 * while the work queue raises it as `act_now` and MAILS it. Measured on the
 * real `decorate()`: a converted FortiGate scores **97, band "excellent"**,
 * which is `lib/monitoringOnly.js`'s own "silently the cleanest device on the
 * fleet", live, on a page that sorts worst-first.
 *
 * ⛔ REFUSED RATHER THAN PURGED: a multi-table cascade delete does not belong
 * in a metadata PUT, and the collected history was TRUE when collected.
 * Deleting and re-adding is the honest path and already cascades — the
 * precedent the locked vendor dropdown in `DeviceForm` already sets.
 *
 * ⛔ THE REVERSE IS ALWAYS ALLOWED. logs-only → a real transport is
 * MONITORING_ONLY_REMEDY itself, and it strands nothing.
 */
function refuseMonitoringOnlyConversion(existingMethod, requestedMethod) {
  if (requestedMethod !== MONITORING_ONLY_METHOD) return null;
  if (existingMethod === MONITORING_ONLY_METHOD) return null;
  return {
    code: 'monitoring_only_conversion_refused',
    error:
      'This firewall has already been collected from, so it cannot be switched to '
      + 'logs-only here. SecVault would keep its stored version, ruleset, config, CVE '
      + 'assessment and compliance findings while never collecting from it again — so '
      + 'they would be reported as current for ever, including as urgent CVE work. '
      + 'Delete the firewall and add it again with Access Method "Syslog only" to keep '
      + 'only its logs.',
  };
}

module.exports = {
  MONITORING_ONLY_METHOD,
  MONITORING_ONLY_CLAIM,
  MONITORING_ONLY_REMEDY,
  isMonitoringOnly,
  refuseMonitoringOnlyConversion,
};
