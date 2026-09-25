'use strict';
//
// lib/deviceScopeCoverage.js — the register that stops a half-enforced
// boundary from looking like a whole one.
//
// ⛔ THIS FILE EXISTS BECAUSE THE DANGEROUS FAILURE IS SILENT COVERAGE.
// 104 non-test files read device data and there is no chokepoint they share,
// so per-device scoping cannot be retrofitted everywhere in one change. The
// failure mode that would create is not "too little access": it is an
// administrator restricting an account to two firewalls, watching the device
// list obey, and never learning that a report still shows the other fourteen.
// A boundary somebody believes in and that is not there is worse than no
// boundary at all.
//
// So every reachable surface carries one of three classifications, and
// tests/deviceScopeCoverage.test.js fails the build when a route or page
// exists that is on none of them. A new surface is therefore a DELIBERATE
// decision, never a default.
//
//   'aware'          — reads the session's scope and narrows what it returns.
//   'blocked'        — reads device data and does NOT scope it, so a SCOPED
//                      account is refused outright. Unscoped accounts (every
//                      account that exists today) are unaffected.
//   'no-device-data' — nothing here is per-firewall, so scoping does not apply.
//
// ⛔ THE LIST MAY ONLY MOVE ONE WAY. 'blocked' -> 'aware' is the work; the
// reverse is a regression and a test asserts the count never falls. Marking
// something 'aware' without actually narrowing its query is the one mistake
// this register cannot catch by itself, which is why each promotion needs its
// own test alongside.
//
// ⛔ 'blocked' IS A REAL PRODUCT STATE, NOT A TODO. A scoped user meeting one
// gets a clear refusal naming why. That is a smaller product, honestly
// described — the trade this design makes on purpose.

const COVERAGE = Object.freeze({
  'app/api/advisories/[cveId]/conditions/[conditionId]/route.js': 'no-device-data',
  'app/api/advisories/[cveId]/conditions/route.js': 'no-device-data',
  'app/api/advisories/[cveId]/conditions/test/route.js': 'blocked',
  'app/api/analysis/fleet/route.js': 'blocked',
  'app/api/analysis/run/route.js': 'blocked',
  'app/api/applications/[id]/flows/[flowId]/route.js': 'blocked',
  'app/api/applications/[id]/flows/route.js': 'blocked',
  'app/api/applications/[id]/retire/route.js': 'blocked',
  'app/api/applications/[id]/route.js': 'blocked',
  'app/api/applications/from-cloud/route.js': 'blocked',
  'app/api/applications/impact/route.js': 'blocked',
  'app/api/applications/route.js': 'blocked',
  'app/api/auth/[...nextauth]/route.js': 'no-device-data',
  'app/api/compliance/[deviceId]/exceptions/[exceptionId]/route.js': 'blocked',
  'app/api/compliance/[deviceId]/exceptions/route.js': 'blocked',
  'app/api/compliance/[deviceId]/route.js': 'blocked',
  'app/api/compliance/[deviceId]/run/route.js': 'blocked',
  'app/api/compliance/fleet/route.js': 'blocked',
  'app/api/compliance/report/generate/route.js': 'blocked',
  'app/api/compliance/report/pdf/route.js': 'blocked',
  'app/api/credential-profiles/[id]/route.js': 'blocked',
  'app/api/credential-profiles/route.js': 'blocked',
  'app/api/cve/assess/route.js': 'blocked',
  'app/api/cve/fleet/route.js': 'blocked',
  'app/api/devices/[id]/access-path/route.js': 'blocked',
  'app/api/devices/[id]/acknowledgements/route.js': 'blocked',
  'app/api/devices/[id]/analysis/route.js': 'blocked',
  'app/api/devices/[id]/backups/[backupId]/route.js': 'blocked',
  'app/api/devices/[id]/backups/route.js': 'blocked',
  'app/api/devices/[id]/collect/route.js': 'blocked',
  'app/api/devices/[id]/configs/[configId]/baseline/route.js': 'blocked',
  'app/api/devices/[id]/cve-acknowledgements/route.js': 'blocked',
  'app/api/devices/[id]/cve/route.js': 'blocked',
  'app/api/devices/[id]/diffs/[diffId]/route.js': 'blocked',
  'app/api/devices/[id]/diffs/route.js': 'blocked',
  'app/api/devices/[id]/reorder-recommendation/route.js': 'blocked',
  'app/api/devices/[id]/route.js': 'aware',
  'app/api/devices/[id]/rule-change-requests/route.js': 'blocked',
  'app/api/devices/[id]/rules/route.js': 'blocked',
  'app/api/devices/[id]/snmp/route.js': 'blocked',
  'app/api/devices/[id]/snmp/test/route.js': 'blocked',
  'app/api/devices/[id]/test/route.js': 'blocked',
  'app/api/devices/[id]/vpn/route.js': 'blocked',
  'app/api/devices/[id]/zone-classifications/route.js': 'blocked',
  'app/api/devices/route.js': 'aware',
  'app/api/devices/test-smc/route.js': 'blocked',
  'app/api/discovered-devices/[id]/ignore/route.js': 'no-device-data',
  'app/api/discovered-devices/[id]/link/route.js': 'blocked',
  'app/api/discovered-devices/route.js': 'blocked',
  'app/api/events/route.js': 'blocked',
  'app/api/feeds/status/route.js': 'no-device-data',
  'app/api/feeds/sync/route.js': 'no-device-data',
  'app/api/health/route.js': 'no-device-data',
  'app/api/jobs/[id]/route.js': 'blocked',
  'app/api/ldap-mappings/route.js': 'no-device-data',
  'app/api/license/route.js': 'no-device-data',
  // Same reading as its sibling: it reads syslog_events, which carries
  // device_id, so a scoped account must not reach it until the query is
  // scope-aware. ⛔ Blocking the page and leaving its export open is exactly
  // the hole this register exists to prevent.
  'app/api/logs/export/route.js': 'blocked',
  'app/api/logs/search/route.js': 'blocked',
  'app/api/mfa/route.js': 'no-device-data',
  'app/api/notification-channels/[id]/route.js': 'no-device-data',
  'app/api/notification-channels/[id]/test/route.js': 'no-device-data',
  'app/api/notification-channels/route.js': 'no-device-data',
  'app/api/notifications/summary/route.js': 'blocked',
  'app/api/reports/[id]/pdf/route.js': 'blocked',
  'app/api/rule-change-requests/[id]/export/route.js': 'blocked',
  'app/api/rule-change-requests/[id]/route.js': 'blocked',
  'app/api/saved-views/[id]/route.js': 'no-device-data',
  'app/api/saved-views/route.js': 'blocked',
  'app/api/search/route.js': 'blocked',
  'app/api/segmentation/route.js': 'blocked',
  'app/api/settings/route.js': 'no-device-data',
  'app/api/system/console-url/route.js': 'no-device-data',
  'app/api/system/session-policy/route.js': 'no-device-data',
  'app/api/system/tls/route.js': 'no-device-data',
  'app/api/system/update-available/route.js': 'no-device-data',
  'app/api/system/update-status/route.js': 'blocked',
  'app/api/system/update/route.js': 'blocked',
  'app/api/topology/graph/route.js': 'blocked',
  'app/api/topology/path-query/route.js': 'blocked',
  'app/api/users/[id]/mfa/route.js': 'no-device-data',
  // Reads `devices` only to validate that the ids being granted exist. Blocked
  // rather than aware: a SCOPED super_admin granting scopes outside their own
  // is an edge nobody has asked for, and guessing at it would be inventing a
  // policy rather than implementing one.
  'app/api/users/[id]/device-scope/route.js': 'blocked',
  'app/api/users/[id]/route.js': 'no-device-data',
  'app/api/users/route.js': 'no-device-data',
  'app/api/vpn/detections/export/route.js': 'blocked',
  'app/api/vpn/fleet/route.js': 'blocked',
  'app/(dashboard)/alerts/page.js': 'blocked',
  'app/(dashboard)/analysis/page.js': 'blocked',
  'app/(dashboard)/applications/page.js': 'blocked',
  'app/(dashboard)/compliance/[deviceId]/checks/[findingId]/page.js': 'blocked',
  'app/(dashboard)/compliance/[deviceId]/page.js': 'blocked',
  'app/(dashboard)/compliance/[deviceId]/print/page.js': 'blocked',
  'app/(dashboard)/compliance/[deviceId]/standards/page.js': 'blocked',
  'app/(dashboard)/compliance/page.js': 'blocked',
  // ⛔ AWARE. The register's whole subject is what is MISSING, so a fleet-wide
  // one shown to a scoped account would disclose both the existence and the
  // collection health of every firewall outside that scope. It narrows in
  // SQL via getCoverageRegister's `deviceIds`, and an UNKNOWN scope renders
  // an explicit refusal rather than an empty register -- on this page an
  // empty result would read as 'no blind spots'.
  'app/(dashboard)/coverage/page.js': 'aware',
  'app/(dashboard)/devices/[id]/analysis/page.js': 'blocked',
  'app/(dashboard)/devices/[id]/changes/page.js': 'blocked',
  'app/(dashboard)/devices/[id]/page.js': 'aware',
  'app/(dashboard)/devices/[id]/rules/page.js': 'blocked',
  'app/(dashboard)/devices/[id]/snmp/page.js': 'blocked',
  'app/(dashboard)/devices/[id]/vpn/page.js': 'blocked',
  'app/(dashboard)/devices/discovered/page.js': 'blocked',
  'app/(dashboard)/devices/new/page.js': 'blocked',
  'app/(dashboard)/devices/page.js': 'aware',
  'app/(dashboard)/exposure/page.js': 'blocked',
  'app/(dashboard)/lifecycle/page.js': 'blocked',
  'app/(dashboard)/logs/page.js': 'blocked',
  'app/(dashboard)/page.js': 'blocked',
  'app/(dashboard)/reports/page.js': 'blocked',
  'app/(dashboard)/segmentation/page.js': 'blocked',
  'app/(dashboard)/settings/page.js': 'no-device-data',
  'app/(dashboard)/topology/page.js': 'blocked',
  'app/(dashboard)/vpn/page.js': 'blocked',
  'app/(dashboard)/vulnerability/advisories/[cveId]/conditions/page.js': 'blocked',
  'app/(dashboard)/vulnerability/advisories/[cveId]/page.js': 'blocked',
  'app/(dashboard)/vulnerability/advisories/page.js': 'blocked',
  'app/(dashboard)/vulnerability/cve/[cveId]/page.js': 'blocked',
  'app/(dashboard)/vulnerability/page.js': 'blocked',
  'app/(dashboard)/work/page.js': 'blocked',
});

// ⛔ TEN SURFACES WERE RECLASSIFIED 'no-device-data' -> 'blocked' AFTER REVIEW.
// Each serves fleet-wide per-device data — names, UUIDs, management addresses —
// from an IMPORTED engine rather than from a query written in the surface file.
// The completeness test only ever grepped the surface file itself, so every one
// of them scored zero matches and passed while leaking. That is the
// guard-that-cannot-fire pattern aimed at the one test standing between a
// scoped account and the rest of the fleet, and it is why the test now follows
// imports.
const CLASSIFICATIONS = Object.freeze(['aware', 'blocked', 'no-device-data']);

/** Surfaces a SCOPED session may reach. Unscoped sessions reach everything. */
function isScopeAware(surface) {
  return COVERAGE[surface] === 'aware';
}

/** Does this surface deal in per-firewall data at all? */
// ⛔ SURFACES THAT REACH DEVICE DATA THROUGH AN IMPORT, AND ARE STILL
// CLASSIFIED 'no-device-data' — ON PURPOSE, WITH A REASON EACH.
//
// The register's own check reads only the surface FILE. A route whose device
// query lives one import away was invisible to it, and six were: every
// /api/applications route imported applicationViewData (which evaluates
// declared flows against each device's collected rulebase) while the PAGE those
// routes back was already `blocked`, and credential-profiles/[id] was open
// while its own collection route beside it was blocked. Blocking a page and
// leaving its API open is the exact shape of hole this register exists to
// prevent, and only a transitive check could see it.
//
// What remains is listed here rather than suppressed, because "the checker
// reports nothing" and "the checker was told to ignore these" must not look
// alike. Each entry states what the import actually carries.
const TRANSITIVE_ALLOWED = Object.freeze({
  // Writes an audit line that may name a device; returns none to the caller.
  'app/api/mfa/route.js': 'writes activity_log only',
  'app/api/system/tls/route.js': 'writes activity_log only',
  'app/api/users/[id]/mfa/route.js': 'writes activity_log only',
  // Reads a COUNT of active devices for the licence limit. ⛔ This is a real,
  // accepted residual: a scoped account learns how many firewalls exist beyond
  // its scope. GET /api/license is deliberately open to every signed-in user
  // (the subscription banner needs it, and an operator who cannot see "lapses
  // in nine days" is the one still using it on day ten). Blocking it would
  // remove that banner for scoped accounts to hide an integer.
  'app/api/license/route.js': 'device COUNT only, for the licence limit',
  'app/api/settings/route.js': 'device COUNT only, for the licence limit',
  'app/api/users/route.js': 'device COUNT only, for the licence limit',
  // Feed sync status. The cloud-catalogue engine it reaches can match rules to
  // providers, but these two routes return per-FEED status rows and no
  // per-firewall result.
  'app/api/feeds/status/route.js': 'feed sync status, no per-device rows',
  'app/api/feeds/sync/route.js': 'feed sync status, no per-device rows',
});

function touchesDeviceData(surface) {
  return COVERAGE[surface] === 'aware' || COVERAGE[surface] === 'blocked';
}

function countByClassification() {
  const out = { aware: 0, blocked: 0, 'no-device-data': 0 };
  for (const v of Object.values(COVERAGE)) out[v] += 1;
  return out;
}

module.exports = {
  COVERAGE,
  CLASSIFICATIONS,
  TRANSITIVE_ALLOWED,
  isScopeAware,
  touchesDeviceData,
  countByClassification,
};
