#!/usr/bin/env node
'use strict';
//
// scripts/apiSweep.js — does every API route actually HONOUR ITS CONTRACT?
//
// ⛔ THE GAP THIS FILLS, IN ONE INCIDENT. `npm test` has ~3,460 assertions and
// not one of them calls a route. A builder returned `[]` where its caller
// expected an object, and every per-firewall Traffic Activity report on a
// Fortinet answered HTTP 500. The engines were tested. The build was clean. The
// page smoke sweep was green, because /reports renders a list of links and the
// defect was behind one of them. Nothing in the suite could observe it, because
// nothing in the suite calls a route.
//
// Route handlers cannot be unit-tested here: they `import` next-auth and
// next/server, resolve a session, and are `dynamic = 'force-dynamic'`, so
// `next build` never evaluates one either. Reaching them without a mocking
// framework means going over HTTP — so this does exactly what scripts/smoke.js
// does one layer up, and deliberately mirrors its conventions: same cookie-jar
// login, same env vars, same insecure-TLS rule, same pure-and-exported verdict
// functions, same FAIL-LOUDLY stance, same "not part of npm test".
//
//   scripts/smoke.js       does every PAGE render?
//   scripts/apiSweep.js    does every ROUTE answer correctly?   (this file)
//
// ⛔ IT IS NOT PART OF `npm test` AND MUST NOT BE. It needs a built app, a
// running server and a populated database. A test that silently skips when it
// cannot reach one is the guard-that-cannot-fire pattern this codebase treats
// as worse than no guard, so this FAILS LOUDLY when it cannot connect and lives
// behind its own `npm run apisweep`.
//
// ⛔ NO PROBE ASKS THIS PRODUCT TO CHANGE ANYTHING AN OPERATOR CAN SEE — and
// that is a narrower claim than the one this header used to make, deliberately.
// Every probe is a GET, with exactly two exceptions — both POSTs that CLAUDE.md
// documents as pure computations over already-collected data that persist
// nothing (`/api/devices/[id]/access-path`, `/api/topology/path-query`). That
// rule is not a convention here, it is enforced: assertSafeChecks() THROWS on
// any other verb, so the table cannot be made dangerous by an edit. Even the
// unauthenticated probes use GET only — if middleware were broken (the very
// thing being tested) an unauthenticated POST would reach the handler and
// write.
//
// ⛔ BUT "GET" IS NOT "INERT", AND THE OLD CLAIM ("IT NEVER CALLS A MUTATING
// ROUTE") WAS ENFORCED ON THE HTTP VERB ALONE. Three GETs in this table do have
// a server-side effect, each named in SIDE_EFFECTING_GETS below and each
// requiring its check to say so:
//
//   /api/license                    resolveInstallDate() INSERTs settings.install_date
//                                   when that row is absent — the same function
//                                   scripts/dbCheck.js names as the canonical
//                                   read-named writer
//   /api/system/update-status       git ls-remote, and git fetch into the
//   /api/system/update-available    PRODUCTION checkout when a newer commit exists
//
// They are still probed, for one reason: each is reached by ordinary use of the
// product (the licence banner renders on every page; Settings → Updates runs the
// same git transport), and each effect is idempotent and invisible — a settings
// row that should already exist, and remote refs. None of them touches fleet
// data, device state, a score or a finding. What is NOT acceptable is a header
// asserting a property the code does not have, so the claim is now scoped and
// the exceptions are enforced rather than described.
//
// ─── WHAT THIS DOES NOT COVER, STATED UP FRONT ───────────────────────────────
//
// 1. ⛔ ROLE-SPECIFIC AUTHORISATION. There is ONE account available to the
//    harness and it is a super_admin, which holds all nine capabilities. So a
//    genuine 403 cannot be produced live, and this sweep does NOT fake a
//    session to manufacture one — a forged cookie would test the forgery, not
//    the boundary. What IS asserted live is the other direction and it is not
//    nothing: a route declaring a capability must NOT deny the session that
//    holds every one of them. That catches a mistyped capability constant,
//    which lib/rbac.js denies to EVERY role including super_admin. And any 403
//    that does come back must NAME the capability in its body. The denial
//    itself — operator refused `manage_users` — needs a second, lower-privilege
//    test account. Until one exists this is a real gap, not a covered case.
//    tests/apiSweepHarness.test.js drives the denial shapes synthetically.
// 2. RESPONSE BODY SEMANTICS. A 200 whose JSON parses is asserted; whether the
//    numbers in it are right is the engines' own tests' job.
// 3. MUTATION BEHAVIOUR. No POST/PUT/DELETE/PATCH contract is exercised, so
//    every 400-on-bad-body, 409-on-conflict and 202-job-enqueue path is
//    unverified here.
// 4. ⛔ WHAT THE 401 ASSERTION PROVES, PRECISELY. middleware.js gates by path
//    prefix BEFORE routing resolves, so a 401 proves the prefix is gated — it
//    does NOT prove the handler would refuse an unauthenticated call on its
//    own. It is still the highest-value assertion available: a matcher
//    exclusion added for a font or an image is exactly how a whole prefix goes
//    public, and that has already happened once in this file's history
//    (/_next/image, see middleware.js). A consequence worth knowing: a route
//    present in this checkout but not yet in the running build still answers
//    401, so this sweep cannot tell "gated" from "not deployed".
//
// Usage:
//   npm run apisweep                     (defaults to https://127.0.0.1:3010)
//   SMOKE_URL=https://192.168.7.69:3010 SMOKE_USER=admin SMOKE_PASS=… SMOKE_INSECURE=1 npm run apisweep
//
// ⛔ EXIT CODES, AND WHY "INCOMPLETE" HAS ITS OWN. A sweep whose fixtures did
// not resolve leaves whole classes of check UNRUN, and it used to print those
// after the totals where they touched nothing: an account scoped to no devices
// makes `/api/devices` answer `200 []`, every per-device check becomes unrun,
// and the banner read "0 failed", exit 0. A short sweep must never read as a
// clean one — the rule scripts/dbCheck.js already applies to `blocked`.
//
//   0  every assertion held AND every check ran
//   1  an assertion failed, or fixture discovery errored
//   2  could not reach the server / could not sign in — nothing was checked
//   3  harness error
//   4  every assertion that RAN held, but some checks could not run at all

const fs = require('node:fs');
const path = require('node:path');

// ⛔ THE CATALOGUE IS THE SOURCE OF TRUTH FOR REPORT CHECKS, NOT A COPY OF IT.
// Every report's happy path is DERIVED from lib/reports/catalogue.js, so a
// report added without a download test is impossible — the sweep grows with the
// registry. Requiring it is cheap: `builder` is a lazy `() => require(...)`, so
// pdfkit and the engine graph stay unloaded.
const { REPORTS } = require('../lib/reports/catalogue');
const { ALL_CAPABILITIES } = require('../lib/rbac');

const BASE = (process.env.SMOKE_URL || 'https://127.0.0.1:3010').replace(/\/+$/, '');
const USER = process.env.SMOKE_USER || 'admin';
const PASS = process.env.SMOKE_PASS || '';
// Longer than smoke.js's default because several checks build a real PDF over
// the live fleet; the VPN access review measured 12s on the reference server.
const TIMEOUT_MS = Number(process.env.SMOKE_TIMEOUT_MS || 60000);

// ⛔ SELF-SIGNED CERTIFICATES ARE ACCEPTED ONLY FOR A LOCAL TARGET, and only
// deliberately — the identical rule and reasoning as scripts/smoke.js. SecVault
// mints its own certificate at install, so a local sweep cannot verify it, but
// silently disabling verification for ANY url would make this script a
// convenient way to talk to an impostor. A remote host needs SMOKE_INSECURE=1
// typed by a human who meant it.
const isLocal = /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:|$|\/)/i.test(BASE);
if (BASE.startsWith('https://') && (isLocal || process.env.SMOKE_INSECURE === '1')) {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

// A uuid that is well-formed and cannot exist. Used for the "unknown id must be
// a 404, never a 500 and never a zero-byte artefact" checks, and as the filler
// for path parameters in the unauthenticated sweep, where the value is
// irrelevant because middleware answers before the handler runs.
const UNKNOWN_UUID = '00000000-0000-4000-8000-000000000000';

// ─── table 1: every route, and the auth contract ────────────────────────────
//
// One entry per `app/api/**/route.js`. `path` is the route's own parameter
// spelling with braces instead of brackets, so assertRouteTableComplete() can
// compare it MECHANICALLY against the filesystem — a new route with no entry
// throws rather than being quietly unswept. `capability` records what the
// handler declares (grepped from `can(session, X)`); `null` means it relies on
// middleware alone, or on isAdmin()'s legacy alias, which passes no capability
// name to forbiddenResponse().
//
// ⛔ EVERY ENTRY EXPECTS 401 UNAUTHENTICATED. `public: true` is the only escape
// and assertSafeChecks() throws on any other anonExpect, because the 401 rule
// is the whole point of this table: CLAUDE.md says API routes return 401 rather
// than redirecting, and middleware.js is the only thing enforcing it.
const API_ROUTES = [
  { path: '/api/advisories/{cveId}/conditions', methods: ['GET', 'POST'], capability: null },
  { path: '/api/advisories/{cveId}/conditions/test', methods: ['POST'], capability: null },
  { path: '/api/advisories/{cveId}/conditions/{conditionId}', methods: ['PUT', 'DELETE'], capability: null },
  { path: '/api/analysis/fleet', methods: ['GET'], capability: null },
  { path: '/api/analysis/run', methods: ['POST'], capability: 'operate' },
  { path: '/api/applications', methods: ['GET', 'POST'], capability: 'operate' },
  { path: '/api/applications/from-cloud', methods: ['POST'], capability: 'operate' },
  { path: '/api/applications/impact', methods: ['GET'], capability: null },
  { path: '/api/applications/{id}', methods: ['GET', 'PUT', 'DELETE'], capability: 'operate' },
  { path: '/api/applications/{id}/flows', methods: ['POST'], capability: 'operate' },
  { path: '/api/applications/{id}/flows/{flowId}', methods: ['PUT', 'DELETE'], capability: 'operate' },
  { path: '/api/applications/{id}/retire', methods: ['POST'], capability: 'operate' },
  // ⛔ THE ONE PUBLIC PREFIX, and it has to stay public: the login form fetches
  // /api/auth/csrf before it can post credentials. If this ever starts
  // answering 401 nobody can sign in at all — which is why it is asserted as a
  // 200 here rather than merely excluded from the 401 rule.
  {
    path: '/api/auth/{...nextauth}',
    methods: ['GET', 'POST'],
    capability: null,
    public: true,
    anonPath: '/api/auth/csrf',
    anonExpect: [200],
  },
  { path: '/api/compliance/fleet', methods: ['GET'], capability: null },
  { path: '/api/compliance/report/generate', methods: ['POST'], capability: 'operate' },
  { path: '/api/compliance/report/pdf', methods: ['GET'], capability: null },
  { path: '/api/compliance/{deviceId}', methods: ['GET'], capability: null },
  { path: '/api/compliance/{deviceId}/exceptions', methods: ['GET', 'POST'], capability: 'operate' },
  { path: '/api/compliance/{deviceId}/exceptions/{exceptionId}', methods: ['DELETE'], capability: 'operate' },
  { path: '/api/compliance/{deviceId}/run', methods: ['POST'], capability: 'operate' },
  { path: '/api/credential-profiles', methods: ['GET', 'POST'], capability: 'manage_credential_profiles' },
  { path: '/api/credential-profiles/{id}', methods: ['PUT', 'DELETE'], capability: 'manage_credential_profiles' },
  { path: '/api/cve/assess', methods: ['POST'], capability: 'operate' },
  { path: '/api/cve/fleet', methods: ['GET'], capability: null },
  { path: '/api/devices', methods: ['GET', 'POST'], capability: null },
  { path: '/api/devices/test-smc', methods: ['POST'], capability: null },
  { path: '/api/devices/{id}', methods: ['GET', 'PUT', 'DELETE'], capability: null },
  { path: '/api/devices/{id}/access-path', methods: ['POST'], capability: null },
  { path: '/api/devices/{id}/acknowledgements', methods: ['POST'], capability: 'operate' },
  { path: '/api/devices/{id}/analysis', methods: ['GET', 'POST'], capability: 'operate' },
  { path: '/api/devices/{id}/backups', methods: ['GET', 'POST'], capability: null },
  { path: '/api/devices/{id}/backups/{backupId}', methods: ['GET', 'DELETE'], capability: null },
  { path: '/api/devices/{id}/collect', methods: ['POST'], capability: 'operate' },
  { path: '/api/devices/{id}/configs/{configId}/baseline', methods: ['PUT'], capability: null },
  { path: '/api/devices/{id}/cve', methods: ['GET'], capability: null },
  { path: '/api/devices/{id}/cve-acknowledgements', methods: ['POST'], capability: 'operate' },
  { path: '/api/devices/{id}/diffs', methods: ['GET'], capability: null },
  { path: '/api/devices/{id}/diffs/{diffId}', methods: ['GET', 'PUT'], capability: 'operate' },
  { path: '/api/devices/{id}/reorder-recommendation', methods: ['GET'], capability: null },
  { path: '/api/devices/{id}/rule-change-requests', methods: ['GET', 'POST'], capability: 'operate' },
  { path: '/api/devices/{id}/rules', methods: ['GET'], capability: null },
  { path: '/api/devices/{id}/snmp', methods: ['GET', 'PUT'], capability: null },
  { path: '/api/devices/{id}/snmp/test', methods: ['POST'], capability: null },
  { path: '/api/devices/{id}/test', methods: ['POST'], capability: null },
  { path: '/api/devices/{id}/vpn', methods: ['GET'], capability: null },
  { path: '/api/devices/{id}/zone-classifications', methods: ['GET', 'PUT'], capability: null },
  { path: '/api/discovered-devices', methods: ['GET'], capability: null },
  { path: '/api/discovered-devices/{id}/ignore', methods: ['POST'], capability: null },
  { path: '/api/discovered-devices/{id}/link', methods: ['POST'], capability: null },
  { path: '/api/events', methods: ['GET'], capability: null },
  { path: '/api/feeds/status', methods: ['GET'], capability: null },
  { path: '/api/feeds/sync', methods: ['POST'], capability: 'operate' },
  { path: '/api/health', methods: ['GET'], capability: null },
  { path: '/api/jobs/{id}', methods: ['GET'], capability: null },
  { path: '/api/ldap-mappings', methods: ['GET', 'POST', 'DELETE'], capability: 'manage_users' },
  { path: '/api/license', methods: ['GET', 'POST', 'DELETE'], capability: 'manage_license' },
  { path: '/api/logs/export', methods: ['GET'], capability: 'view_log_search' },
  { path: '/api/logs/search', methods: ['GET'], capability: 'view_log_search' },
  { path: '/api/mfa', methods: ['GET', 'POST', 'PUT', 'DELETE'], capability: null },
  { path: '/api/notification-channels', methods: ['GET', 'POST'], capability: 'manage_settings' },
  { path: '/api/notification-channels/{id}', methods: ['PUT', 'DELETE'], capability: 'manage_settings' },
  { path: '/api/notification-channels/{id}/test', methods: ['POST'], capability: 'manage_settings' },
  { path: '/api/notifications/summary', methods: ['GET'], capability: null },
  { path: '/api/reports/{id}/pdf', methods: ['GET'], capability: 'operate' },
  { path: '/api/rule-change-requests/{id}', methods: ['GET', 'PATCH'], capability: 'operate' },
  { path: '/api/rule-change-requests/{id}/export', methods: ['GET'], capability: null },
  { path: '/api/saved-views', methods: ['GET', 'POST'], capability: null },
  { path: '/api/saved-views/{id}', methods: ['DELETE'], capability: null },
  { path: '/api/search', methods: ['GET'], capability: null },
  { path: '/api/segmentation', methods: ['GET', 'POST', 'DELETE'], capability: 'operate' },
  { path: '/api/settings', methods: ['GET', 'PUT'], capability: 'manage_settings' },
  { path: '/api/system/console-url', methods: ['GET', 'PUT'], capability: 'manage_settings' },
  { path: '/api/system/session-policy', methods: ['GET', 'PUT'], capability: 'manage_settings' },
  { path: '/api/system/tls', methods: ['GET', 'POST'], capability: 'manage_settings' },
  { path: '/api/system/update', methods: ['POST'], capability: 'run_update' },
  { path: '/api/system/update-available', methods: ['GET'], capability: null },
  { path: '/api/system/update-status', methods: ['GET'], capability: null },
  { path: '/api/topology/graph', methods: ['GET'], capability: null },
  { path: '/api/topology/path-query', methods: ['POST'], capability: null },
  { path: '/api/users', methods: ['GET', 'POST'], capability: 'manage_users' },
  { path: '/api/users/{id}', methods: ['PUT', 'DELETE'], capability: 'manage_users' },
  { path: '/api/users/{id}/mfa', methods: ['GET', 'PUT', 'DELETE'], capability: 'manage_users' },
  // ⛔ `manage_users`, not `manage_devices`. Whoever can widen an account's
  // device scope decides who sees which customer's firewalls.
  { path: '/api/users/{id}/device-scope', methods: ['GET', 'PUT'], capability: 'manage_users' },
  { path: '/api/vpn/detections/export', methods: ['GET'], capability: 'view_identity' },
  { path: '/api/vpn/fleet', methods: ['GET'], capability: null },
];

// ⛔ A HANDFUL OF PROBES AGAINST THE MATCHER ITSELF, not against a route. The
// exclusion list in middleware.js's matcher is a regex that has already been
// wrong once, and these are the two directions it can be wrong in: a prefix
// that must stay public going dark, and a prefix that must stay gated going
// public. A path that matches no route at all still has to answer 401, which is
// also the evidence for the caveat in this file's header — middleware runs
// before routing resolves.
const MATCHER_PROBES = [
  { path: '/api/auth/csrf', expect: [200], why: 'must stay public — the login form cannot post without it' },
  { path: '/api/auth/providers', expect: [200], why: 'must stay public — the login form reads it' },
  { path: '/api/HEALTH', expect: [401], why: 'a path matching no route is still gated, before routing' },
];

// ─── table 2: the authenticated contract ────────────────────────────────────
//
// `{token}` placeholders are resolved from fixtures DISCOVERED at run time —
// never hardcoded, the same rule scripts/smoke.js follows, because a pinned
// device id rots the moment that firewall is removed and the sweep then reports
// a route as broken because its fixture went away.
//
// `expect` is a list because more than one status can be correct: a log search
// stopped by its 10s statement timeout answers 504 and that is the documented,
// honest answer, not a failure.
//
// ⛔ NO ENTRY MAY EXPECT 500. assertSafeChecks() throws on one. A 500 is always
// a failure here, and its body is always printed, because in a production build
// that body is the only diagnostic Next gives.
const READ_CHECKS = [
  // fleet-level reads, no fixture needed
  { path: '/api/health', why: 'the liveness probe Update-SecVault.ps1 rolls back on' },
  { path: '/api/devices' },
  { path: '/api/discovered-devices', why: 'never [] on failure — "no unknown senders" is the dangerous wrong answer' },
  { path: '/api/events' },
  { path: '/api/analysis/fleet' },
  { path: '/api/applications', capability: 'operate' },
  { path: '/api/applications/impact' },
  { path: '/api/compliance/fleet' },
  { path: '/api/credential-profiles', capability: 'manage_credential_profiles' },
  { path: '/api/cve/fleet' },
  { path: '/api/feeds/status' },
  { path: '/api/ldap-mappings', capability: 'manage_users' },
  { path: '/api/license', sideEffect: true, why: 'open to every role — the banner needs it' },
  { path: '/api/logs/search?limit=5', capability: 'view_log_search', expect: [200, 504], why: '504 is the honest answer to a timed-out search, not an empty 200' },
  { path: '/api/mfa' },
  { path: '/api/notification-channels', capability: 'manage_settings' },
  { path: '/api/notifications/summary' },
  { path: '/api/saved-views?scope=devices' },
  { path: '/api/search?q=fw' },
  { path: '/api/segmentation' },
  { path: '/api/settings', capability: 'manage_settings' },
  { path: '/api/system/console-url', capability: 'manage_settings' },
  { path: '/api/system/session-policy' },
  { path: '/api/system/tls', capability: 'manage_settings' },
  { path: '/api/system/update-available', sideEffect: true },
  { path: '/api/system/update-status', sideEffect: true, why: 'degrades to up_to_date on any git failure; must never 500' },
  { path: '/api/topology/graph' },
  { path: '/api/users', capability: 'manage_users' },
  { path: '/api/vpn/fleet' },

  // per-device reads
  { path: '/api/devices/{device}' },
  { path: '/api/devices/{device}/analysis', capability: 'operate' },
  { path: '/api/devices/{device}/backups' },
  { path: '/api/devices/{device}/cve' },
  { path: '/api/devices/{device}/diffs' },
  { path: '/api/devices/{device}/reorder-recommendation' },
  { path: '/api/devices/{device}/rules?limit=5' },
  { path: '/api/devices/{device}/rule-change-requests', capability: 'operate' },
  { path: '/api/devices/{device}/snmp' },
  { path: '/api/devices/{device}/vpn' },
  { path: '/api/devices/{device}/zone-classifications' },
  { path: '/api/compliance/{device}' },
  // ⛔ THE VENDOR THAT BROKE. Yesterday's defect was Fortinet-only, because the
  // shape a builder got back differed by vendor. Every per-device read is run a
  // second time against a Fortinet for that reason.
  { path: '/api/devices/{fortinet}/analysis', capability: 'operate' },
  { path: '/api/devices/{fortinet}/rules?limit=5' },
  { path: '/api/devices/{fortinet}/vpn' },
  { path: '/api/compliance/{fortinet}' },

  // nested ids, discovered
  // ⛔ `type: 'text'` ASSERTS A DOCUMENT, not just a status code. This route
  // returns `config_backups.config_raw ?? ''`, so a NULL column is a 200
  // text/plain download of nothing — the exact artefact the PDF checks refuse
  // ("a zero-byte PDF someone would file"), in the one place an operator takes
  // the bytes away and treats them as the firewall's configuration.
  { path: '/api/devices/{deviceWithBackup}/backups/{backupId}', type: 'text', why: 'raw config download — must be a real config, not an empty or HTML body' },
  { path: '/api/devices/{deviceWithDiff}/diffs/{diffId}', capability: 'operate' },
  { path: '/api/applications/{application}', capability: 'operate' },
  { path: '/api/advisories/{cveId}/conditions' },

  // ⛔ AN UNKNOWN ID IS A 404, NEVER A 500 AND NEVER AN EMPTY 200. Each of these
  // is a documented behaviour; a 500 here is the shape of an id flowing
  // unvalidated into a query.
  { path: '/api/devices/{unknownUuid}', expect: [404] },
  { path: '/api/applications/{unknownUuid}', expect: [404], capability: 'operate' },
  { path: '/api/jobs/{unknownUuid}', expect: [404] },
  { path: '/api/rule-change-requests/{unknownUuid}', expect: [404], capability: 'operate' },
  { path: '/api/rule-change-requests/{unknownUuid}/export?format=csv', expect: [404] },

  // ⛔ THE ONLY TWO NON-GET PROBES IN THIS FILE, both documented in CLAUDE.md as
  // pure read-only computations that persist nothing. The allow-list below is
  // what keeps that true.
  {
    path: '/api/devices/{device}/access-path',
    method: 'POST',
    body: { srcIp: '10.0.0.1', dstIp: '8.8.8.8', protocol: 'tcp', port: 443 },
    why: 'a non-mutating POST — computes over collected data, writes nothing',
  },
  {
    path: '/api/topology/path-query',
    method: 'POST',
    body: { srcIp: '10.0.0.1', dstIp: '8.8.8.8', protocol: 'tcp', port: 443 },
    why: 'a non-mutating POST — fleet-wide path simulation, writes nothing',
  },

  // the fleet compliance PDF, which is its own route rather than a catalogue entry
  { path: '/api/compliance/report/pdf', type: 'pdf' },
];

// ⛔ THE ALLOW-LIST THAT MAKES THE MUTATION BAN REAL. Token form, path only.
// Anything else with a non-GET method throws in assertSafeChecks().
const NON_MUTATING_POSTS = new Set([
  '/api/devices/{device}/access-path',
  '/api/topology/path-query',
]);

// ⛔ THE GETs THAT ARE NOT INERT. See the header. Both directions are enforced
// in assertSafeChecks(): a check on one of these paths MUST carry
// `sideEffect: true`, and a check carrying it that is NOT on this list is
// refused — so neither the annotation nor the list can quietly drift away from
// the other, and adding one is a decision somebody has to write down.
const SIDE_EFFECTING_GETS = new Map([
  ['/api/license', 'INSERTs settings.install_date when that row is absent (resolveInstallDate)'],
  ['/api/system/update-status', 'runs git ls-remote, and git fetch into the production checkout when a newer commit exists (refs only, never the working tree)'],
  ['/api/system/update-available', 'the same git transport as update-status, behind a 6-hour in-process cache'],
]);

// ─── table 3: the report route's own parameter contract ─────────────────────
//
// Every one of these is a behaviour documented in app/api/reports/[id]/pdf/
// route.js, and every one of them is a refusal. They are listed explicitly
// rather than derived, because the POINT is that each refuses instead of
// silently widening — a request for the PCI document answered with the
// whole-fleet document under a filename saying PCI is a mislabelled audit
// artefact, which is worse than an error.
const REPORT_PARAM_CASES = [
  { path: '/api/reports/no-such-report-xyz/pdf', expect: [404], why: 'unknown report id — 404, never a zero-byte PDF someone would file' },
  { path: '/api/reports/rule-hygiene/pdf?deviceId=not-a-uuid', expect: [400], why: 'malformed deviceId is a bad request, not an empty fleet report' },
  { path: '/api/reports/compliance-fleet/pdf?deviceId={unknownUuid}', expect: [400], why: 'a report that cannot narrow refuses a deviceId rather than ignoring it' },
  { path: '/api/reports/compliance-fleet/pdf?standard=BOGUS', expect: [400], why: 'an out-of-allow-list param value is refused, never dropped' },
  { path: '/api/reports/traffic-activity/pdf?from=notadate', expect: [400], why: 'a range param is validated by shape' },
  { path: '/api/reports/traffic-activity/pdf?to=notadate', expect: [400], why: 'both ends of the range, not just the first' },
  { path: '/api/reports/change-audit/pdf?days=9999', expect: [400], why: 'a plausible-looking window outside the allow-list is still refused' },
];

// ─── plumbing (the same cookie jar as scripts/smoke.js) ─────────────────────

const jar = new Map();

function storeCookies(res) {
  const raw = typeof res.headers.getSetCookie === 'function'
    ? res.headers.getSetCookie()
    : [res.headers.get('set-cookie')].filter(Boolean);
  for (const line of raw) {
    const [pair] = String(line).split(';');
    const i = pair.indexOf('=');
    if (i > 0) jar.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
  }
}

const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');

async function req(p, opts = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(BASE + p, {
      redirect: 'manual',
      ...opts,
      signal: ctl.signal,
      // ⛔ `anon: true` sends NO cookie at all. Not an empty one — an empty
      // `cookie:` header is still a header, and the point of the
      // unauthenticated sweep is that nothing identifying travels with it.
      headers: opts.anon
        ? { ...(opts.headers || {}) }
        : { cookie: cookieHeader(), ...(opts.headers || {}) },
    });
    storeCookies(res);
    return res;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Read a response into the flat, serialisable shape the verdict functions take.
 * Binary bodies keep their length and their first bytes but not their content.
 *
 * ⛔ THE TEXT BODY IS KEPT WHOLE, AND THE FIRST DRAFT OF THIS FUNCTION DID NOT.
 * It sliced to 4 KB here, so every response larger than that arrived at
 * authedVerdict() as invalid JSON and eight healthy routes were reported
 * broken. Truncating the evidence and then judging it is this codebase's own
 * signature bug wearing a harness's clothes — the sweep was confidently wrong,
 * with a plausible message. Slicing for DISPLAY happens in the verdict, where
 * it cannot affect a decision.
 */
async function capture(res) {
  const contentType = res.headers.get('content-type') || '';
  const buf = Buffer.from(await res.arrayBuffer());
  const binary = /pdf|octet-stream|zip/i.test(contentType);
  return {
    status: res.status,
    contentType,
    location: res.headers.get('location'),
    bytes: buf.length,
    head: buf.subarray(0, 8).toString('latin1'),
    body: binary ? '' : buf.toString('utf8'),
  };
}

async function login() {
  const csrfRes = await req('/api/auth/csrf', { anon: true });
  if (!csrfRes.ok) throw new Error(`could not reach ${BASE} — /api/auth/csrf returned ${csrfRes.status}`);
  storeCookies(csrfRes);
  const { csrfToken } = await csrfRes.json();
  // ⛔ THE PROVIDER ID IS `local`, NOT `credentials`. SecVault registers two
  // credentials providers (`local` and `ldap`) with explicit ids, so NextAuth's
  // default /callback/credentials path does not exist here and answers 400.
  // `totp` is sent empty: the harness deliberately cannot supply a second
  // factor, and says so when a session does not come back.
  const body = new URLSearchParams({
    csrfToken, username: USER, password: PASS, totp: '', callbackUrl: `${BASE}/`, json: 'true',
  });
  const res = await req('/api/auth/callback/local', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const authed = [...jar.keys()].some((k) => /next-auth\.session-token|__Secure-next-auth\.session-token/.test(k));
  if (!authed) {
    // ⛔ ONE AUTH FAILURE, NOT SEVENTY ROUTE FAILURES.
    throw new Error(
      `sign-in as "${USER}" did not return a session cookie (HTTP ${res.status}). `
      + 'Set SMOKE_USER / SMOKE_PASS. If MFA is enabled on that account, use one without it — '
      + 'this harness deliberately cannot supply a second factor.'
    );
  }
}

// ─── the pure verdict logic ─────────────────────────────────────────────────
//
// ⛔ PURE, AND EXPORTED, SO THE HARNESS ITSELF CAN BE TESTED. A sweep that has
// only ever returned green proves nothing: the failing path is the one that
// matters and it is the one a healthy fleet never reaches.
// tests/apiSweepHarness.test.js feeds these synthetic responses — a 500, a 200
// that should have been a 401, a 403 naming no capability, a zero-byte PDF.

/** The empty-body 500 that Next serves when a handler throws uncaught. */
const UNCAUGHT_500_HINT =
  'an EMPTY 500 body is Next\'s uncaught-throw shape — the message is withheld in a '
  + 'production build, so the stack is only in logs/app-error.log on the server';

/**
 * The capability a 403 body names, or null.
 *
 * ⛔ IT MUST BE ONE lib/rbac.js RECOGNISES. `required: "adminish"` would satisfy
 * a "is the field present" check while naming an authority that does not exist
 * — and since can() denies an unrecognised capability string, that is exactly
 * the shape a mistyped constant produces. So the name is validated against
 * ALL_CAPABILITIES, not merely against being a non-empty string.
 */
function capabilityNamedIn(body, known) {
  const list = Array.isArray(known) ? known : ALL_CAPABILITIES;
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object') return null;
  if (typeof parsed.required === 'string' && list.includes(parsed.required)) return parsed.required;
  // The prose message names it too, and a client may only have the message.
  //
  // ⛔ MATCHED AS A WHOLE WORD, NOT AS A SUBSTRING. `'operator'.includes('operate')`
  // is true, so a body saying "the operator role may not do this" counted as
  // naming the `operate` CAPABILITY — defeating the one distinction the test
  // beside it exists to pin, that a ROLE is not a capability. Capabilities are
  // snake_case, so the boundary has to exclude `_` as well as letters and
  // digits: `manage_users_extra` must not match `manage_users` either.
  if (typeof parsed.error === 'string') {
    const hit = list.find((c) => new RegExp(`(^|[^a-z0-9_])${c}([^a-z0-9_]|$)`, 'i').test(parsed.error));
    if (hit) return hit;
  }
  return null;
}

/**
 * The unauthenticated contract for one route.
 *
 * ⛔ A REDIRECT IS ITS OWN FAILURE, NOT JUST A WRONG NUMBER. CLAUDE.md requires
 * API routes to answer 401; a 307 to /login is followed by `fetch` and the
 * caller then parses an HTML login page as JSON, so the symptom surfaces
 * nowhere near the cause.
 */
function anonVerdict(route, observed) {
  const expect = route.anonExpect || [401];
  const checks = ['no-redirect', 'status'];
  const fail = (reason) => ({ key: route.anonPath || route.path, ok: false, reason, status: observed.status, checks });

  if (observed.status === 301 || observed.status === 302 || observed.status === 307 || observed.status === 308) {
    return fail(
      `redirected to ${observed.location} — an API route must answer ${expect.join('/')} , not redirect; `
      + 'a fetch() follows this and parses the login page as JSON'
    );
  }
  if (!expect.includes(observed.status)) {
    if (observed.status === 200 && !route.public) {
      return fail('HTTP 200 with NO session cookie — this route is reachable unauthenticated');
    }
    return fail(`HTTP ${observed.status} unauthenticated, expected ${expect.join(' or ')}`);
  }
  return { key: route.anonPath || route.path, ok: true, status: observed.status, checks };
}

/**
 * The authenticated contract for one check.
 *
 * The session used here holds EVERY capability, which is what makes the 403
 * branch meaningful: a 403 can only mean the route asked for an authority
 * lib/rbac.js does not recognise.
 */
function authedVerdict(check, observed) {
  const expect = check.expect || [200];
  const type = check.type || 'json';
  const checks = ['status'];
  const fail = (reason) => ({ key: check.key || check.path, ok: false, reason, status: observed.status, checks });

  // ⛔ A 500 IS ALWAYS A FAILURE AND ITS BODY IS ALWAYS PRINTED.
  if (observed.status >= 500 && observed.status !== 504) {
    checks.push('no-server-error');
    const shown = observed.body ? `body: ${observed.body.slice(0, 300).replace(/\s+/g, ' ')}` : UNCAUGHT_500_HINT;
    return fail(`HTTP ${observed.status} — ${shown}`);
  }

  if (observed.status === 403) {
    checks.push('403-names-a-capability');
    const named = capabilityNamedIn(observed.body);
    if (!named) {
      return fail(
        '403 whose body does not name a capability lib/rbac.js recognises — forbiddenResponse() '
        + 'must carry `required`, or the operator is told only that they may not do something'
      );
    }
    // ⛔ `check.capability` IS READ HERE, and until v2.173.0 it was read
    // NOWHERE — set on sixteen checks, asserted by the harness test, and
    // never once compared against what a route actually answered. Dead
    // metadata that a test certifies is worse than none: it reads as coverage.
    // The live session holds every capability, so this can only fire when a
    // route gates on an authority the table (or lib/reports/catalogue.js)
    // does not think it gates on.
    if (check.capability && named !== check.capability) {
      checks.push('403-names-the-declared-capability');
      return fail(
        `403 requiring "${named}", but this check declares "${check.capability}" — the route and the `
        + 'sweep table disagree about which authority it gates on, so one of them is wrong'
      );
    }
    if (!expect.includes(403)) {
      return fail(
        `403 requiring "${named}" — this session holds every capability, so the route is gating on `
        + 'one it should not, or a constant is mistyped (can() denies an unrecognised string to every role)'
      );
    }
  }

  if (!expect.includes(observed.status)) {
    return fail(`HTTP ${observed.status}, expected ${expect.join(' or ')}`);
  }

  if (type === 'pdf' && observed.status === 200) {
    // ⛔ A ZERO-BYTE PDF IS THE ARTEFACT THIS ROUTE'S OWN COMMENTS FORBID —
    // someone would file it. Content type alone does not prove a document.
    checks.push('pdf-content-type', 'pdf-magic-bytes', 'pdf-not-empty');
    if (!/application\/pdf/i.test(observed.contentType)) {
      return fail(`200 but content-type is "${observed.contentType || '(none)'}", not application/pdf`);
    }
    if (!observed.head.startsWith('%PDF')) {
      return fail(`200 application/pdf whose first bytes are ${JSON.stringify(observed.head)}, not "%PDF"`);
    }
    if (observed.bytes < 1000) {
      return fail(`200 application/pdf of only ${observed.bytes} bytes — an empty document, not a report`);
    }
  } else if (type === 'text' && observed.status === 200) {
    // ⛔ A 200 IS NOT A DOCUMENT. This used to assert the status code and
    // nothing else, so a zero-byte body, an HTML error page served as 200, or
    // a JSON error envelope all passed — on the one route whose bytes an
    // operator saves to disk and reads as a firewall's configuration.
    checks.push('text-not-empty', 'text-not-html', 'text-not-an-error-envelope');
    if (observed.bytes === 0) {
      return fail('200 with a ZERO-BYTE body — an empty download, not a config. The stored config_raw is NULL or empty.');
    }
    if (/text\/html/i.test(observed.contentType) || /^\s*<(!doctype|html)\b/i.test(observed.body)) {
      return fail(`200 whose body is an HTML page (content-type "${observed.contentType || '(none)'}") — an error page served as a download`);
    }
    if (/json/i.test(observed.contentType)) {
      return fail(`200 served as "${observed.contentType}" where a text download was expected — an error envelope with a success status`);
    }
  } else if (type === 'json' || (type === 'any' && /json/i.test(observed.contentType))) {
    checks.push('json-parses');
    // ⛔ A 400/404 IS ALSO ASSERTED TO BE JSON. Every refusal in this product
    // carries a sentence saying what to do next; a bare status code with an
    // HTML body is a refusal the UI cannot render.
    try {
      const parsed = JSON.parse(observed.body);
      if (parsed === null || typeof parsed !== 'object') {
        return fail(`${observed.status} whose body parsed to ${typeof parsed}, not an object or array`);
      }
    } catch {
      return fail(
        `${observed.status} whose body is not parseable JSON (content-type "${observed.contentType || '(none)'}"): `
        + `${observed.body ? JSON.stringify(observed.body.slice(0, 160)) : '(empty)'}`
      );
    }
  }

  return { key: check.key || check.path, ok: true, status: observed.status, bytes: observed.bytes, checks };
}

// ─── the closing verdict ────────────────────────────────────────────────────

/** Exit codes, named so the reasons cannot be confused at the call site. */
const EXIT = { OK: 0, FAILED: 1, UNREACHABLE: 2, HARNESS: 3, INCOMPLETE: 4 };

/**
 * ⛔ A SHORT SWEEP MUST NEVER READ AS A CLEAN ONE — the rule scripts/dbCheck.js
 * applies to `blocked`, which this file did not have. `gaps` and `unresolved`
 * were printed AFTER the totals and touched neither the banner nor the exit
 * code, so the one state that matters most — a harness account scoped to no
 * devices, `/api/devices` answering `200 []`, every per-device check unrun —
 * printed "0 failed" and exited 0. Pure and exported, because a live run only
 * ever exercises the green path.
 *
 * ⛔ INCOMPLETE IS ITS OWN EXIT CODE, NOT A FAILURE AND NOT A PASS. Calling it
 * a failure would make a fleet that genuinely has no Fortinet red for ever and
 * train people to ignore the result; calling it a pass is what this fixes.
 */
function sweepVerdict({ failed = 0, fixtureErrors = 0, gaps = 0, unresolved = 0, ran = 0 } = {}) {
  const broken = failed + fixtureErrors;
  const unrun = gaps + unresolved;

  if (ran === 0) {
    return {
      tone: 'fail',
      exitCode: EXIT.FAILED,
      sentence: 'NOTHING RAN. No probe reached the server, so this sweep proves nothing about any route.',
    };
  }
  if (broken > 0) {
    return {
      tone: 'fail',
      exitCode: EXIT.FAILED,
      sentence: `${failed} assertion(s) failed${fixtureErrors ? ` and fixture discovery errored ${fixtureErrors} time(s)` : ''}`
        + `${unrun ? `, and ${unrun} check(s) could not run at all` : ''}.`,
    };
  }
  if (unrun > 0) {
    return {
      tone: 'unknown',
      exitCode: EXIT.INCOMPLETE,
      sentence: `Every assertion that RAN held, but ${unrun} check(s) never ran (${gaps} coverage gap(s), `
        + `${unresolved} unresolved fixture(s)) — this is NOT a clean sweep, and the routes behind them are unswept.`,
    };
  }
  return {
    tone: 'ok',
    exitCode: EXIT.OK,
    sentence: `All ${ran} probes ran and every assertion held.`,
  };
}

// ─── the guards on the tables themselves ────────────────────────────────────

/**
 * ⛔ THE TABLE CANNOT BE MADE DANGEROUS BY AN EDIT, AND IT THROWS RATHER THAN
 * WARNING. This runs against the production fleet; a warning would be printed
 * once above seventy lines of green and the sweep would still exit 0. The
 * analogue of scripts/smoke.js's assertUsableMarkers.
 */
function assertSafeChecks(checks, routes) {
  for (const c of checks || []) {
    const method = (c.method || 'GET').toUpperCase();
    const bare = String(c.path).split('?')[0];
    if (method !== 'GET' && method !== 'HEAD') {
      if (!NON_MUTATING_POSTS.has(bare)) {
        throw new Error(
          `${method} ${c.path} is not on the non-mutating allow-list. This sweep runs against the `
          + 'production fleet and may only call routes that persist nothing.'
        );
      }
      if (method !== 'POST') {
        throw new Error(`${method} ${c.path}: even an allow-listed compute route may only be POSTed.`);
      }
    }
    const expect = c.expect || [200];
    if (!Array.isArray(expect) || expect.length === 0) {
      throw new Error(`${c.path}: expect must be a non-empty list of statuses.`);
    }
    if (expect.some((s) => s >= 500 && s !== 504)) {
      throw new Error(`${c.path}: a 500 is never an acceptable answer, so it may not be expected.`);
    }
    if (!bare.startsWith('/api/')) {
      throw new Error(`${c.path}: this sweep covers /api only — pages belong to scripts/smoke.js.`);
    }
    // ⛔ BOTH DIRECTIONS, so the annotation and the list cannot drift apart.
    const effect = SIDE_EFFECTING_GETS.get(bare);
    if (effect && c.sideEffect !== true) {
      throw new Error(
        `${c.path} ${effect} — a GET is not automatically inert. Mark the check \`sideEffect: true\` `
        + 'so the header\'s claim stays true, or drop the check.'
      );
    }
    if (!effect && c.sideEffect) {
      throw new Error(
        `${c.path} declares a side effect that SIDE_EFFECTING_GETS does not describe. Add it there with `
        + 'what it actually does, or remove the flag — an undocumented one is the claim this sweep just stopped making.'
      );
    }
    // ⛔ `capability` IS VALIDATED, because it is now READ (see authedVerdict's
    // 403 branch). A mistyped one could otherwise never match a real 403 body
    // and would silently assert nothing — the state this field was in before.
    if (c.capability !== undefined && c.capability !== null && !ALL_CAPABILITIES.includes(c.capability)) {
      throw new Error(`${c.path}: "${c.capability}" is not a capability lib/rbac.js knows.`);
    }
  }
  for (const r of routes || []) {
    const expect = r.anonExpect || [401];
    if (!r.public && (expect.length !== 1 || expect[0] !== 401)) {
      throw new Error(
        `${r.path}: an unauthenticated API route must answer 401. Only an entry marked `
        + '`public: true` may expect anything else, and there is exactly one of those.'
      );
    }
    if (r.capability !== null && !ALL_CAPABILITIES.includes(r.capability)) {
      throw new Error(`${r.path}: "${r.capability}" is not a capability lib/rbac.js knows.`);
    }
  }
  return checks;
}

/** Every `app/api/**\/route.js`, as the route path the table uses. */
function listRouteFiles(rootDir) {
  const base = path.join(rootDir, 'app', 'api');
  const out = [];
  const walk = (dir, rel) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) walk(full, `${rel}/${ent.name}`);
      else if (ent.name === 'route.js') out.push(`/api${rel}`.replace(/\[/g, '{').replace(/\]/g, '}'));
    }
  };
  if (!fs.existsSync(base)) {
    throw new Error(`${base} does not exist — run this from a SecVault checkout.`);
  }
  walk(base, '');
  return out.sort();
}

/**
 * ⛔ DRIFT IS IMPOSSIBLE, NOT DISCOURAGED. A route added without a table entry
 * would otherwise get no auth assertion at all, and the sweep would report a
 * clean pass over an ungated route — a short list that looks complete, which
 * this codebase treats as the more insidious failure.
 */
function assertRouteTableComplete(files, routes) {
  const listed = new Set((routes || []).map((r) => r.path));
  const onDisk = new Set(files || []);
  const missing = [...onDisk].filter((f) => !listed.has(f)).sort();
  const stale = [...listed].filter((p) => !onDisk.has(p)).sort();
  if (missing.length || stale.length) {
    const parts = [];
    if (missing.length) parts.push(`not in API_ROUTES: ${missing.join(', ')}`);
    if (stale.length) parts.push(`in API_ROUTES but no route file: ${stale.join(', ')}`);
    throw new Error(`the route table has drifted from app/api — ${parts.join(' | ')}`);
  }
  return true;
}

// ─── fixtures ───────────────────────────────────────────────────────────────

/**
 * ⛔ FIXTURES ARE DISCOVERED, NEVER HARDCODED — the same rule scripts/smoke.js
 * follows for its per-device pages. A pinned device id rots the moment that
 * firewall is removed, and the sweep would then report a route as broken
 * because its fixture went away.
 *
 * ⛔ A DISCOVERY REQUEST THAT FAILS IS A FAILURE. A discovery request that
 * legitimately returns an EMPTY LIST is a COVERAGE GAP, reported as one and
 * counted. Those are different facts and collapsing them would let a broken
 * /api/devices silently reduce this sweep to the fleet-level checks while still
 * printing a pass.
 */
async function discoverFixtures() {
  const fixtures = { unknownUuid: UNKNOWN_UUID };
  const errors = [];
  const gaps = [];

  const getJson = async (p) => {
    const res = await req(p);
    const obs = await capture(res);
    if (obs.status !== 200) {
      errors.push(`${p} answered ${obs.status} during fixture discovery`);
      return null;
    }
    try {
      return JSON.parse(obs.body);
    } catch {
      errors.push(`${p} did not return JSON during fixture discovery`);
      return null;
    }
  };

  const devicesRaw = await getJson('/api/devices');
  const devices = Array.isArray(devicesRaw) ? devicesRaw : ((devicesRaw && devicesRaw.devices) || []);
  const active = devices.filter((d) => d && d.id);
  if (active.length === 0) gaps.push('no firewall in the inventory — every per-device check is unrun');
  else {
    fixtures.device = active[0].id;
    fixtures.deviceName = active[0].name;
    const fort = active.find((d) => d.vendor === 'fortinet');
    if (fort) {
      fixtures.fortinet = fort.id;
      fixtures.fortinetName = fort.name;
    } else {
      // ⛔ NOT silently substituted with another vendor. The Fortinet-scoped
      // checks exist BECAUSE yesterday's defect was vendor-specific; running
      // them against a Palo Alto would report a pass for a case never tried.
      gaps.push('no Fortinet in the inventory — the vendor-specific checks are unrun');
    }
  }

  // A backup and a diff, from whichever firewall has one.
  for (const d of active) {
    if (!fixtures.backupId) {
      const b = await getJson(`/api/devices/${d.id}/backups`);
      const first = b && Array.isArray(b.backups) ? b.backups[0] : null;
      if (first && first.id) { fixtures.backupId = first.id; fixtures.deviceWithBackup = d.id; }
    }
    if (!fixtures.diffId) {
      const f = await getJson(`/api/devices/${d.id}/diffs`);
      const first = f && Array.isArray(f.diffs) ? f.diffs[0] : null;
      if (first && first.id) { fixtures.diffId = first.id; fixtures.deviceWithDiff = d.id; }
    }
    if (fixtures.backupId && fixtures.diffId) break;
  }
  if (!fixtures.backupId) gaps.push('no config backup on any firewall — the backup download check is unrun');
  if (!fixtures.diffId) gaps.push('no config diff on any firewall — the diff detail check is unrun');

  const cve = await getJson('/api/cve/fleet');
  const firstCve = cve && Array.isArray(cve.cves) ? cve.cves.find((c) => c && c.cve_id) : null;
  if (firstCve) fixtures.cveId = firstCve.cve_id;
  else gaps.push('no advisory matched to any firewall — the advisory-conditions check is unrun');

  const apps = await getJson('/api/applications');
  const firstApp = apps && Array.isArray(apps.applications)
    ? apps.applications.map((a) => (a && a.application) || a).find((a) => a && a.id)
    : null;
  if (firstApp) fixtures.application = firstApp.id;
  else gaps.push('no declared application — the application detail check is unrun');

  const now = new Date();
  fixtures.windowTo = now.toISOString();
  fixtures.windowFrom = new Date(now.getTime() - 24 * 3600 * 1000).toISOString();

  return { fixtures, errors, gaps };
}

/**
 * The API_ROUTES entry a check's path targets, or null.
 *
 * ⛔ IT EXISTS TO CATCH A TYPO IN A CHECK THAT EXPECTS A 404. Every other
 * mistyped path fails loudly on its own — but `/api/jobsss/{id}` expecting 404
 * would PASS, for the wrong reason, for ever. A wrong assertion that reports
 * green is worse than no assertion. Tokens match any single segment; a `{...}`
 * catch-all matches the rest.
 */
function routeFor(checkPath, routes) {
  const segs = String(checkPath).split('?')[0].split('/').filter(Boolean);
  for (const r of routes || API_ROUTES) {
    const rs = r.path.split('/').filter(Boolean);
    const catchAll = rs.findIndex((s) => s.startsWith('{...'));
    if (catchAll === -1 && rs.length !== segs.length) continue;
    if (catchAll !== -1 && segs.length < catchAll) continue;
    let ok = true;
    for (let i = 0; i < rs.length; i += 1) {
      if (rs[i].startsWith('{...')) break;
      if (rs[i].startsWith('{')) continue;
      if (rs[i] !== segs[i]) { ok = false; break; }
    }
    if (ok) return r;
  }
  return null;
}

/** Substitute `{token}`s, or report which one could not be resolved. */
function resolvePath(p, fixtures) {
  const missing = [];
  const out = String(p).replace(/\{(\w+)\}/g, (_, name) => {
    const v = fixtures[name];
    if (v === undefined || v === null || v === '') { missing.push(name); return `{${name}}`; }
    return encodeURIComponent(String(v));
  });
  return { path: out, missing };
}

// ─── report checks, derived from the catalogue ───────────────────────────────

/**
 * ⛔ DERIVED, NOT LISTED. A report registered in lib/reports/catalogue.js
 * without a download check would otherwise be exactly the untested route this
 * file exists for — and /reports is where the defect that prompted it lived.
 */
function reportChecks(reports) {
  const out = [];
  for (const entry of reports || REPORTS) {
    const query = [];
    for (const p of entry.params || []) {
      if (p.kind === 'range') query.push('from={windowFrom}', 'to={windowTo}');
      else if (Array.isArray(p.choices) && p.choices.length) query.push(`${p.key}=${p.choices[0].value}`);
    }
    const qs = (extra) => {
      const all = extra ? [...extra, ...query] : query;
      return all.length ? `?${all.join('&')}` : '';
    };

    if (entry.scope === 'entity') {
      // ⛔ NO ENTITY IS CREATED TO TEST THIS. Creating a rule change request is a
      // mutation, and this sweep does not mutate. What is asserted instead are
      // the route's two documented refusals, which is the whole contract an
      // entity-scoped report has before its builder runs.
      out.push({
        key: `report:${entry.id}:no-id`,
        path: `/api/reports/${entry.id}/pdf`,
        expect: [400],
        capability: entry.capability,
        why: `${entry.name} is entity-scoped — no id is a 400, not a fleet document`,
      });
      out.push({
        key: `report:${entry.id}:unknown-id`,
        path: `/api/reports/${entry.id}/pdf?id={unknownUuid}`,
        expect: [404],
        capability: entry.capability,
        why: 'a well-formed id for a record that does not exist is a 404, never an empty PDF',
      });
      continue;
    }

    if (entry.scope === 'device') {
      out.push({
        key: `report:${entry.id}:device`,
        path: `/api/reports/${entry.id}/pdf${qs(['deviceId={device}'])}`,
        type: 'pdf',
        capability: entry.capability,
        why: `${entry.name}, scoped to one firewall`,
      });
      continue;
    }

    out.push({
      key: `report:${entry.id}`,
      path: `/api/reports/${entry.id}/pdf${qs()}`,
      type: 'pdf',
      capability: entry.capability,
      why: entry.name,
    });
    if (entry.optionalDevice) {
      // ⛔ AGAINST A FORTINET, DELIBERATELY. The defect this file was written
      // for answered 500 for Fortinet devices only, because the per-device
      // branch got a shape the fleet branch never produced.
      out.push({
        key: `report:${entry.id}:fortinet`,
        path: `/api/reports/${entry.id}/pdf${qs(['deviceId={fortinet}'])}`,
        type: 'pdf',
        capability: entry.capability,
        why: `${entry.name}, narrowed to a Fortinet — the per-device builder branch`,
      });
    }
  }
  return out;
}

// ─── the run ────────────────────────────────────────────────────────────────

/**
 * ⛔ "COULD NOT CONNECT" MUST BE A SENTENCE, NOT A STACK. The unauthenticated
 * phase runs before login, so a server that is down used to surface as a raw
 * ECONNREFUSED trace out of the first probe — loud, which is the rule, but not
 * diagnostic, which is the point of the rule. A reader has to be able to tell
 * "the sweep cannot reach the server" from "the product is broken" at a glance.
 */
async function preflight() {
  try {
    await req('/api/health', { anon: true });
  } catch (err) {
    // ⛔ NODE'S `fetch` SAYS ONLY "fetch failed" AND HIDES THE REASON IN
    // `err.cause`. Reporting the outer message alone gives a TLS refusal and a
    // dead service the identical sentence, which is the one distinction the
    // reader actually needs — the first is fixed with SMOKE_INSECURE=1, the
    // second with sc.exe.
    const cause = (err && err.cause) || {};
    const detail = cause.code || cause.message || (err && err.message) || String(err);
    const hint = /CERT|SELF_SIGNED|ALTNAME|certificate/i.test(String(detail))
      ? 'The certificate could not be verified — a remote host needs SMOKE_INSECURE=1 typed by a human who meant it.'
      : 'Is the SecVault-App service running, and is SMOKE_URL right (scheme and port)?';
    throw new Error(`could not reach ${BASE} (${detail}). ${hint}`);
  }
}

async function runAnon(routes) {
  const results = [];
  for (const r of routes) {
    const probe = r.anonPath || String(r.path).replace(/\{[^}]+\}/g, UNKNOWN_UUID);
    const res = await req(probe, { anon: true });
    results.push(anonVerdict(r, await capture(res)));
  }
  return results;
}

async function runMatcherProbes(probes) {
  const results = [];
  for (const p of probes) {
    const res = await req(p.path, { anon: true });
    const obs = await capture(res);
    results.push(anonVerdict({ path: p.path, anonExpect: p.expect, public: p.expect.includes(200) }, obs));
  }
  return results;
}

async function runAuthed(checks, fixtures) {
  const results = [];
  const unresolved = [];
  for (const c of checks) {
    const { path: p, missing } = resolvePath(c.path, fixtures);
    if (missing.length) {
      unresolved.push({ key: c.key || c.path, missing });
      continue;
    }
    const opts = { method: c.method || 'GET' };
    if (c.body) {
      opts.headers = { 'content-type': 'application/json' };
      opts.body = JSON.stringify(c.body);
    }
    const res = await req(p, opts);
    const verdict = authedVerdict(c, await capture(res));
    results.push({ ...verdict, key: c.key || p, why: c.why || null });
  }
  return { results, unresolved };
}

async function main() {
  const started = Date.now();
  console.log(`[apisweep] ${BASE} as "${USER}"`);

  const repoRoot = path.join(__dirname, '..');
  // ⛔ BOTH GUARDS BEFORE ANY REQUEST. A drifted or dangerous table must stop
  // the run, not be discovered halfway through it.
  assertRouteTableComplete(listRouteFiles(repoRoot), API_ROUTES);

  // ── phase 1: unauthenticated. Deliberately FIRST, and before login, so the
  // jar is genuinely empty rather than trusted to be.
  try {
    await preflight();
  } catch (err) {
    console.error(`[apisweep] FAILED before any check: ${err.message}`);
    process.exit(EXIT.UNREACHABLE);
  }
  const anonResults = [...await runAnon(API_ROUTES), ...await runMatcherProbes(MATCHER_PROBES)];
  const anonBad = anonResults.filter((r) => !r.ok);
  for (const r of anonBad) console.log(`  FAIL  401?  ${r.key}  ${r.reason}`);
  console.log(`[apisweep] auth gate: ${anonResults.length - anonBad.length}/${anonResults.length} routes refused an unauthenticated call`);

  try {
    await login();
  } catch (err) {
    console.error(`[apisweep] FAILED before any authenticated check: ${err.message}`);
    process.exit(EXIT.UNREACHABLE);
  }

  const { fixtures, errors: fixtureErrors, gaps } = await discoverFixtures();
  for (const e of fixtureErrors) console.log(`  FAIL  fixture  ${e}`);

  const checks = assertSafeChecks([...READ_CHECKS, ...reportChecks(REPORTS), ...REPORT_PARAM_CASES], API_ROUTES);
  const { results: authedResults, unresolved } = await runAuthed(checks, fixtures);

  for (const r of authedResults) {
    if (r.ok) console.log(`  ok    ${r.status}  ${r.key}${r.bytes ? `  (${r.bytes} bytes)` : ''}`);
    else console.log(`  FAIL  ${r.status}  ${r.key}\n          ${r.reason}${r.why ? `\n          contract: ${r.why}` : ''}`);
  }

  const assertions = [...anonResults, ...authedResults].reduce((n, r) => n + (r.checks ? r.checks.length : 1), 0);
  const bad = [...anonBad, ...authedResults.filter((r) => !r.ok)];
  const secs = ((Date.now() - started) / 1000).toFixed(1);

  console.log(
    `[apisweep] ${API_ROUTES.length} routes, ${anonResults.length + authedResults.length} probes, `
    + `${assertions} assertions, ${bad.length} failed, in ${secs}s`
  );

  // ⛔ A SHORT SWEEP MUST NEVER READ AS A CLEAN ONE. Anything that did not RUN
  // is listed here AND carried into the verdict below — the same rule the work
  // queue's `verify` band follows. A fixture that does not exist on this fleet
  // is a real coverage gap and the operator has to be told which checks it cost.
  for (const g of gaps) console.log(`  gap   ${g}`);
  for (const u of unresolved) console.log(`  unrun ${u.key} — no fixture for {${u.missing.join('}, {')}}`);
  console.log(
    '  note  role-specific denial (a 403 for a session that genuinely lacks a capability) is NOT '
    + 'covered — it needs a second, non-super_admin test account.'
  );
  for (const [p, effect] of SIDE_EFFECTING_GETS) {
    if (checks.some((c) => String(c.path).split('?')[0] === p)) {
      console.log(`  note  GET ${p} is not inert: it ${effect}.`);
    }
  }

  if (fixtureErrors.length) {
    console.error(`[apisweep] fixture discovery failed ${fixtureErrors.length} time(s) — the sweep above is incomplete`);
  }
  if (bad.length) {
    console.error(`[apisweep] ${bad.length} assertion(s) failed: ${bad.map((b) => b.key).join(', ')}`);
  }

  const verdict = sweepVerdict({
    failed: bad.length,
    fixtureErrors: fixtureErrors.length,
    gaps: gaps.length,
    unresolved: unresolved.length,
    ran: anonResults.length + authedResults.length,
  });
  console.log(`[apisweep] ${verdict.sentence}`);
  process.exit(verdict.exitCode);
}

// Only sweep when RUN; `require`d (by its test) this file must touch no network.
if (require.main === module) {
  main().catch((err) => {
    console.error(`[apisweep] harness error: ${err && err.stack ? err.stack : err}`);
    process.exit(EXIT.HARNESS);
  });
}

module.exports = {
  API_ROUTES,
  READ_CHECKS,
  REPORT_PARAM_CASES,
  MATCHER_PROBES,
  NON_MUTATING_POSTS,
  SIDE_EFFECTING_GETS,
  UNKNOWN_UUID,
  UNCAUGHT_500_HINT,
  EXIT,
  anonVerdict,
  authedVerdict,
  sweepVerdict,
  // ⛔ EXPORTED BECAUSE A MUTATION ESCAPED WITHOUT IT. The harness test built
  // its own `observed` objects, so re-introducing capture()'s 4 KB slice — the
  // one real defect this sweep has had — changed nothing and the suite stayed
  // green. That is the "asserted the line exists rather than that it runs"
  // pattern CLAUDE.md names over tests/cveHub.test.js. It is now driven by
  // behaviour, through a real Response.
  capture,
  capabilityNamedIn,
  assertSafeChecks,
  assertRouteTableComplete,
  listRouteFiles,
  reportChecks,
  resolvePath,
  routeFor,
};
