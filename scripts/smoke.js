#!/usr/bin/env node
'use strict';
//
// scripts/smoke.js — does every page actually RENDER?
//
// ⛔ THE GAP THIS FILLS, IN ONE INCIDENT. v2.120.0 shipped a blank /reports
// page. 2,399 tests passed. The build was clean. The deploy verified. The cause
// was a `builder` FUNCTION passed from a server component to a client one,
// which React refuses to serialise — and in a production build Next withholds
// the message "to avoid leaking sensitive details", so the browser shows a bare
// digest. Nothing in the suite could observe it, because nothing in the suite
// renders a page:
//
//   tests/jsxSyntax.test.js     parses every file — syntax only, never runs one
//   tests/moduleLoad.test.js    require()s lib/ and services/ — EXCLUDES app/
//   tests/importIntegrity.test.js  scans for a mentioned-but-unimported name
//   tests/reportRoute.test.js   regex-asserts clientSafe() — /reports ONLY
//
// Every dashboard page is `dynamic = 'force-dynamic'`, so `next build` never
// evaluates one. The same structural blindness produced the v2.86.1 outage (a
// wrong column name, digest 539791548) where "the only real gate was loading
// the page". This loads the pages.
//
// ⛔ IT IS NOT PART OF `npm test` AND MUST NOT BE. It needs a built app, a
// running server and a database. A test that silently skips when it cannot
// reach one is the guard-that-cannot-fire pattern this codebase treats as worse
// than no guard — so this FAILS LOUDLY when it cannot connect, and lives behind
// its own `npm run smoke`.
//
// Usage:
//   npm run smoke                       (defaults to https://127.0.0.1:3010)
//   SMOKE_URL=https://192.168.7.69:3010 SMOKE_USER=admin SMOKE_PASS=… npm run smoke
//
// Exit code 0 = every page rendered. Non-zero = at least one did not.

const BASE = (process.env.SMOKE_URL || 'https://127.0.0.1:3010').replace(/\/+$/, '');
const USER = process.env.SMOKE_USER || 'admin';
const PASS = process.env.SMOKE_PASS || '';
const TIMEOUT_MS = Number(process.env.SMOKE_TIMEOUT_MS || 30000);

// ⛔ SELF-SIGNED CERTIFICATES ARE ACCEPTED ONLY FOR A LOCAL TARGET, and only
// deliberately. SecVault mints its own certificate at install, so a local sweep
// cannot verify it — but silently disabling verification for ANY url would make
// this script a convenient way to talk to an impostor. A remote host needs
// SMOKE_INSECURE=1 typed by a human who meant it.
const isLocal = /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:|$|\/)/i.test(BASE);
if (BASE.startsWith('https://') && (isLocal || process.env.SMOKE_INSECURE === '1')) {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

// ─── the route table ────────────────────────────────────────────────────────
//
// ⛔ A MARKER MUST NOT BE A NAV LABEL. components/layout/Sidebar.js renders
// "Overview, Work queue, Alerts, Log search, Reports, Firewalls, Topology,
// Lifecycle, Vulnerabilities, Exposure, Segmentation, Applications, Rule
// hygiene, Compliance, VPN & identity, Settings" into EVERY dashboard page from
// the shared layout. A marker equal to any of those would be satisfied by a
// rendered shell around an empty page — which is precisely the failure being
// hunted. Page SUBTITLES are unique; titles frequently are not.
//
// `markers` is an OR: any one present counts. Several pages have more than one
// legitimate branch (an empty-state and a populated one) and both are a
// successful render.
//
// ⛔ NAV_LABELS IS NOT DECORATION -- tests/smokeHarness.test.js asserts that no
// marker in the table below equals one of these. The first draft of this file
// declared the list, wrote the warning above it, and then never used it, which
// would have let the next person add `markers: ['Compliance']` and get a green
// sweep from a blank page wrapped in a working sidebar.
const NAV_LABELS = [
  'Overview', 'Work queue', 'Alerts', 'Log search', 'Reports', 'Firewalls', 'Topology',
  'Lifecycle', 'Vulnerabilities', 'Exposure', 'Segmentation', 'Applications',
  'Rule hygiene', 'Compliance', 'VPN & identity', 'Settings',
];

const STATIC_ROUTES = [
  { path: '/login', anon: true, markers: ['Firewall security posture, in one place.'] },
  { path: '/', markers: ['Security Score', 'Overview sections'] },
  { path: '/work', markers: ['Everything outstanding across the product, in the order worth doing it.'] },
  { path: '/alerts', markers: ['Fleet-wide items needing attention'] },
  // ⛔ NOT a nav label: the sidebar renders 'Coverage' into every page from
  // the shared layout, so such a marker is satisfied by a working shell
  // around a dead page -- the exact failure this sweep exists to catch.
  { path: '/coverage', markers: ['Gaps by evidence source', 'Coverage could not be shown'] },
  // ⛔ Column headers from ConformanceBoard, not the nav label: the shell
  // renders 'Conformance' into every page, so such a marker is satisfied by a
  // working shell around a dead page.
  { path: '/conformance', markers: ['In the smaller group', 'Conformance could not be shown'] },
  { path: '/logs', markers: ['Search raw firewall logs', 'Log search is not available', 'received_at'] },
  { path: '/reports', markers: ['Point-in-time PDFs you can hand to an auditor'] },
  { path: '/devices', markers: ['Firewalls sending syslog from an address that is not in the inventory', 'Add firewall'] },
  { path: '/devices/discovered', markers: ['Discovered Senders'] },
  { path: '/devices/new', markers: ['Add firewall'] },
  { path: '/topology', markers: ['Multi-hop path simulation across your managed firewall fleet.'] },
  { path: '/lifecycle', markers: ['Support contracts, HA state and signature freshness across the fleet.'] },
  { path: '/vulnerability', markers: ['CVE Posture', 'Advisories'] },
  { path: '/vulnerability/advisories', markers: ['Advisory Applicability'] },
  { path: '/exposure', markers: ['What is reachable from the internet, through which rule, to which internal host'] },
  { path: '/segmentation', markers: ['What you say must not connect'] },
  { path: '/applications', markers: ['What each application needs from the network'] },
  { path: '/analysis', markers: ['Rule hygiene — Fleet', 'Rule hygiene &#x2014; Fleet'] },
  { path: '/compliance', markers: ['Compare PCI DSS', 'No active devices', 'PCI DSS'] },
  { path: '/settings', markers: ['Manage app configuration, users, and updates.'] },
  // ⛔ SWEPT SEPARATELY, because `/vulnerability` alone only loads the DEFAULT
  // tab (`posture`) — so `advisories` and `upgrade` were never rendered by any
  // gate. The marker is the recommendation heading, which only this tab
  // produces; a tab LABEL would be satisfied by the tab bar around a dead body.
  { path: '/vulnerability?tab=upgrade', markers: ['Recommended — patch within this branch', 'Firewalls with an upgrade to make'] },
  { path: '/vpn', markers: ['Fleet-wide VPN/remote-access exposure'] },
  // ⛔ THE DETECTIONS TAB IS SWEPT SEPARATELY, because `/vpn` alone only ever
  // loads the DEFAULT tab (`status`) — so the other six were never rendered by
  // any gate. This one is now the densest page in the product (a headline
  // strip, a client filter bar, six detection panels and six export buttons)
  // and it is IDENTITY-GATED, which the sweep only reaches because SMOKE_USER
  // is a super_admin; an operator account would 403 here and the marker would
  // fail for a reason that is not a bug. The marker is a headline tile label
  // that only this tab produces — never a detection title, which predates the
  // rebuild and would pass over the old page.
  { path: '/vpn?vtab=detections', markers: ['Firewalls reporting'] },
];

// ─── plumbing ───────────────────────────────────────────────────────────────

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

async function req(path, opts = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(BASE + path, {
      redirect: 'manual',
      ...opts,
      signal: ctl.signal,
      headers: { cookie: cookieHeader(), ...(opts.headers || {}) },
    });
    storeCookies(res);
    return res;
  } finally {
    clearTimeout(timer);
  }
}

async function login() {
  // NextAuth's credentials flow: a CSRF token bound to a cookie, then a form post.
  const csrfRes = await req('/api/auth/csrf');
  if (!csrfRes.ok) throw new Error(`could not reach ${BASE} — /api/auth/csrf returned ${csrfRes.status}`);
  const { csrfToken } = await csrfRes.json();
  // ⛔ THE PROVIDER ID IS `local`, NOT `credentials`. SecVault registers two
  // credentials providers (`local` and `ldap`) with explicit ids, so NextAuth's
  // default /callback/credentials path does not exist here and answers 400.
  // `totp` is sent empty: the harness deliberately cannot supply a second
  // factor, and says so when a session does not come back.
  const body = new URLSearchParams({
    csrfToken, username: USER, password: PASS, totp: '', callbackUrl: BASE + '/', json: 'true',
  });
  const res = await req('/api/auth/callback/local', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const authed = [...jar.keys()].some((k) => /next-auth\.session-token|__Secure-next-auth\.session-token/.test(k));
  if (!authed) {
    // ⛔ ONE AUTH FAILURE, NOT TWENTY PAGE FAILURES. Without a session every
    // page 307s to /login and the sweep would report the whole product broken.
    throw new Error(
      `sign-in as "${USER}" did not return a session cookie (HTTP ${res.status}). `
      + 'Set SMOKE_USER / SMOKE_PASS. If MFA is enabled on that account, use one without it — '
      + 'this harness deliberately cannot supply a second factor.'
    );
  }
}

// A page that errored server-side in a production build renders Next's digest
// shell. Catch it by name as well as by status, in case a future Next serves it
// with a 200.
const ERROR_SHAPES = [
  /Application error: a server-side exception has occurred/i,
  /digest:\s*['"]?\d{6,}/i,
  /Internal Server Error/i,
];

// ⛔ PURE, AND EXPORTED, SO THE HARNESS ITSELF CAN BE TESTED. A sweep that has
// only ever returned green proves nothing: the failing path is the one that
// matters and it is the one a live run never exercises. tests/smokeHarness.test.js
// feeds this synthetic responses, including the exact v2.120.0 shape.
// ⛔ THE GUARD RUNS ON DISCOVERED ROUTES TOO, NOT JUST THE STATIC TABLE.
// tests/smokeHarness.test.js asserted NAV_LABELS only over STATIC_ROUTES, so a
// marker added in discoverRoutes() escaped it entirely — and one had. A sweep
// that can be made green by a blank page is worse than no sweep, so this throws
// rather than warning: the update's own log would otherwise report a pass.
function assertUsableMarkers(routes) {
  for (const r of routes || []) {
    for (const m of r.markers || []) {
      if (NAV_LABELS.includes(m)) {
        throw new Error(
          `${r.path}: "${m}" is a navigation label, which the shared layout renders into every `
          + 'page — a blank body would pass. Use a string only this page produces.'
        );
      }
    }
  }
  return routes;
}

function pageVerdict(route, { status, location, body }) {
  const fail = (reason) => ({ path: route.path, ok: false, reason, status });

  if (route.anon !== true && (status === 307 || status === 302)) {
    return fail(`redirected to ${location} — the session was not accepted`);
  }
  if (status !== 200) return fail(`HTTP ${status}`);

  for (const shape of ERROR_SHAPES) {
    if (shape.test(body)) {
      return fail(`rendered Next's server-error shell (${shape.source.slice(0, 40)}…) — check logs/app-error.log for the digest`);
    }
  }
  // ⛔ A SHELL IS NOT A PAGE. The layout (sidebar, header) renders even when the
  // page body throws or returns nothing, so byte length alone proves nothing.
  const hit = route.markers.find((m) => body.includes(m));
  if (!hit) {
    return fail(
      `200 and ${body.length} bytes, but none of its content markers rendered `
      + `(${route.markers.map((m) => JSON.stringify(m.slice(0, 40))).join(', ')}) — `
      + 'this is the blank-page shape'
    );
  }
  return { path: route.path, ok: true, status: 200, bytes: body.length, marker: hit };
}

async function check(route) {
  const res = await req(route.path);
  return pageVerdict(route, {
    status: res.status,
    location: res.headers.get('location'),
    body: res.status === 200 ? await res.text() : '',
  });
}

// ⛔ THE PARAMETERISED ROUTES ARE DISCOVERED, NEVER HARDCODED. A pinned device
// id rots the moment that firewall is removed, and the sweep would then report
// a page as broken because its fixture went away.
async function discoverRoutes() {
  const out = [];
  try {
    const res = await req('/api/devices');
    if (res.ok) {
      const data = await res.json();
      const list = Array.isArray(data) ? data : (data.devices || []);
      const dev = list.find((d) => d && d.id);
      if (dev) {
        for (const suffix of ['', '/analysis', '/changes', '/rules', '/snmp', '/vpn']) {
          out.push({
            path: `/devices/${dev.id}${suffix}`,
            markers: suffix === '' ? ['← Back to firewalls', '&#x2190; Back to firewalls', dev.name]
              : suffix === '/changes' ? ['Configuration Changes']
                : [dev.name],
          });
        }
        // ⛔ NOT the bare word 'Compliance' — that is the SIDEBAR's label, which
        // the shared layout renders into every dashboard page, so it passed on a
        // blank body. This file's own NAV_LABELS comment predicted this exact
        // line. The page's own header is `Compliance — <device>`.
        out.push({ path: `/compliance/${dev.id}`, markers: [`Compliance — ${dev.name}`, dev.name] });
        out.push({ path: `/compliance/${dev.id}/standards`, markers: ['All Checks', dev.name] });
      }
    }
  } catch { /* reported below as a missing section, never silently */ }
  return out;
}

async function main() {
  const started = Date.now();
  console.log(`[smoke] ${BASE} as "${USER}"`);

  try {
    await login();
  } catch (err) {
    console.error(`[smoke] FAILED before any page was checked: ${err.message}`);
    process.exit(2);
  }

  const dynamic = await discoverRoutes();
  // ⛔ BOTH TABLES, EVERY RUN. The static one was guarded by a test; the
  // discovered one was not, and that is where a nav label had been sitting.
  const routes = assertUsableMarkers([...STATIC_ROUTES, ...dynamic]);
  if (dynamic.length === 0) {
    console.log('[smoke] NOTE: no device id could be discovered, so no per-device page was checked.');
  }

  const results = [];
  for (const r of routes) results.push(await check(r));

  const bad = results.filter((r) => !r.ok);
  for (const r of results) {
    console.log(r.ok
      ? `  ok    ${r.path}  (${r.bytes} bytes)`
      : `  FAIL  ${r.path}  ${r.reason}`);
  }
  const secs = ((Date.now() - started) / 1000).toFixed(1);
  console.log(`[smoke] ${results.length - bad.length}/${results.length} pages rendered in ${secs}s`);

  if (bad.length) {
    console.error(`[smoke] ${bad.length} page(s) did not render: ${bad.map((b) => b.path).join(', ')}`);
    process.exit(1);
  }
}

// Only sweep when RUN; `require`d (by its test) this file must touch no network.
if (require.main === module) {
  main().catch((err) => {
    console.error(`[smoke] harness error: ${err && err.stack ? err.stack : err}`);
    process.exit(3);
  });
}

module.exports = { pageVerdict, STATIC_ROUTES, NAV_LABELS, ERROR_SHAPES, assertUsableMarkers };
