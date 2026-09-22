'use strict';
//
// lib/deviceScopePaths.js — turns the coverage register into URL matchers, so
// middleware.js can enforce it.
//
// ⛔ THIS FILE IS WHY THE REGISTER IS A CONTROL AND NOT A COMMENT. When
// per-user scoping first shipped (v2.168.0) `lib/deviceScopeCoverage.js`
// classified every surface and a test failed the build on an unclassified one
// — and NOTHING CALLED IT AT RUNTIME. The default-deny property the whole
// design rests on was documented, tested for completeness, and not enforced:
// a scoped account would still have been served the entire fleet on
// /compliance. A guard that cannot fire is worse than no guard, because the
// code reads as handled.
//
// ⛔ EDGE-SAFE ON PURPOSE. middleware runs in the edge runtime, so this has no
// node imports, no database and no dynamic require — just the static register
// compiled into regexes once at module load.
//
// ⛔ IT DENIES `blocked` RATHER THAN ALLOWING `aware`. Those differ only for a
// surface that is on no list at all, and that cannot reach production: the
// build fails first. Denying the named set keeps /login, /api/auth/* and every
// page that carries no per-firewall data working, which an allow-list would
// have to re-enumerate and would eventually get wrong.

const { COVERAGE } = require('./deviceScopeCoverage');
const { SCOPE_STATES } = require('./deviceScope');

// The request header middleware uses to tell a server component which URL it is
// rendering. Next 14 hands a layout no pathname, and the authoritative
// (database-backed) scope check lives in app/(dashboard)/layout.js.
//
// ⛔ IT IS A HINT AND NEVER A PERMISSION. middleware SETS it on every forwarded
// request, overwriting any value a client sent, so it cannot be used to claim a
// path. A consumer that cannot read it must resolve nothing rather than assume
// the request is allowed.
const PATHNAME_HEADER = 'x-sv-pathname';

// app/api/devices/[id]/route.js      -> ^/api/devices/[^/]+$
// app/(dashboard)/devices/page.js    -> ^/devices$
// app/(dashboard)/page.js            -> ^/$
// ⛔ ROUTE GROUPS ARE STRIPPED GENERICALLY, not by naming the two that exist
// today. The original form tested for `app/api/` and `app/(dashboard)/` and
// returned null for anything else — so the day a surface lands in a NEW group
// (`app/(reports)/...`), it compiles to no pattern, is dropped from the list
// below, and is never blocked. The coverage test would still pass: it checks
// that every surface is CLASSIFIED, not that every classification is
// ENFORCEABLE. That is the guard-that-cannot-fire shape, pre-armed.
//
// A parenthesised segment is a Next route group and never appears in the URL.
function surfaceToPattern(file) {
  let p = file;
  if (!p.startsWith('app/')) return null;
  p = p.slice('app'.length);                                         // /api/... , /(dashboard)/...
  p = p.split('/').filter((seg) => !/^\(.+\)$/.test(seg)).join('/');
  if (!p.startsWith('/')) p = `/${p}`;
  p = p.replace(/\/route\.js$/, '').replace(/\/page\.js$/, '');
  if (p === '') p = '/';
  // A dynamic segment matches one path element and never a slash, so
  // /devices/[id] cannot swallow /devices/[id]/analysis — which is a SEPARATE
  // surface with its own classification.
  const body = p
    .split('/')
    .map((seg) => {
      if (/^\[\.\.\..+\]$/.test(seg)) return '.*';       // catch-all
      if (/^\[.+\]$/.test(seg)) return '[^/]+';
      return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('/');
  return new RegExp(`^${body === '' ? '/' : body}/?$`);
}

// ⛔ EVERY SURFACE IS MATCHED, NOT JUST THE BLOCKED ONES, AND THE MOST
// SPECIFIC MATCH WINS — the way a router resolves. A dynamic segment otherwise
// shadows its literal sibling: `/api/compliance/fleet` matches
// `app/api/compliance/[deviceId]/route.js`, and if the literal route were
// `aware` while the dynamic one was `blocked`, a scope-aware surface would be
// refused for a reason nobody could find. Specificity = fewest dynamic
// segments first, then the longer pattern.
const ALL_PATTERNS = Object.entries(COVERAGE)
  .map(([file, cls]) => ({
    file,
    cls,
    re: surfaceToPattern(file),
    dynamic: (file.match(/\[[^\]]+\]/g) || []).length,
  }))
  .filter((x) => x.re)
  .sort((a, b) => (a.dynamic - b.dynamic) || (b.file.length - a.file.length));

/**
 * Resolve a path against an ORDERED pattern list and say what blocks it.
 *
 * ⛔ TAKES ITS PATTERNS AS AN ARGUMENT SO THE FIRST-MATCH-WINS RULE CAN BE
 * TESTED BY BEHAVIOUR. On today's register no `blocked` pattern shadows an
 * `aware` one, so a version that kept scanning past an aware match would
 * behave identically — a guard that cannot fire, which this codebase treats
 * as a defect in its own right (see the jsonb comparison that could never be
 * true). A test feeds this a synthetic register where the shadowing DOES
 * happen, so the rule is pinned before the day a promotion relies on it.
 *
 * @returns {string|null} the blocking surface file, or null
 */
function resolveSurface(patterns, pathname) {
  if (typeof pathname !== 'string' || !pathname) return null;
  // Strip a trailing slash once so '/devices/' and '/devices' behave alike.
  const p = pathname.length > 1 && pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;
  for (const entry of patterns) {
    // ⛔ THE FIRST MATCH DECIDES, whatever its classification. Continuing
    // past an `aware` match to look for a `blocked` one would refuse a
    // scope-aware surface because a less specific neighbour is blocked.
    if (entry.re.test(p)) return entry.cls === 'blocked' ? entry.file : null;
  }
  // ⛔ A path matching NO surface is allowed. It is not a page or a route
  // this app serves (a static asset, a 404), and refusing it here would be
  // guessing at something the router has not resolved yet.
  return null;
}

// ⛔ A `blocked` SURFACE THAT COMPILED TO NO PATTERN IS AN UNENFORCEABLE
// REFUSAL, and it must not be discoverable only by someone reading this file.
// It is reported loudly at load rather than thrown: middleware runs this
// module, and throwing here would take the entire console down — an outage in
// place of a boundary, which is the trade lib/tlsConfig.js already refuses.
// The exported list is what a test asserts is empty.
const UNMAPPABLE_BLOCKED = Object.entries(COVERAGE)
  .filter(([file, cls]) => cls === 'blocked' && !surfaceToPattern(file))
  .map(([file]) => file);
if (UNMAPPABLE_BLOCKED.length > 0) {
  console.error('[deviceScope] these surfaces are classified `blocked` but compile to no URL '
    + `pattern, so they are NOT enforced: ${UNMAPPABLE_BLOCKED.join(', ')}`);
}

/**
 * Is this URL path a surface a device-scoped account must NOT reach?
 * @returns {string|null} the surface file that blocked it, or null
 */
function blockedSurfaceFor(pathname) {
  return resolveSurface(ALL_PATTERNS, pathname);
}

/**
 * The PAGE refusal decision, pure, so the layout that enforces it can be
 * tested without a request, a database or a React render.
 *
 * ⛔ THIS IS THE AUTHORITATIVE HALF. middleware decides the same question from
 * a claim in the session cookie, which `getToken()` only decrypts — it never
 * runs the jwt() callback — so that claim is as old as the last cookie
 * re-issue. A scope GRANTED since then would go unenforced there, which is the
 * direction that leaks. app/(dashboard)/layout.js calls this with a scope read
 * live from the database on every dashboard render.
 *
 * ⛔ AN UNRESOLVABLE PATHNAME REFUSES NOTHING, and that is not a fail-open: it
 * means middleware did not run, so the matcher is misconfigured, and refusing
 * every page — including /devices, the only place a scoped account can work —
 * would be a self-inflicted outage in place of a boundary. The caller logs it.
 *
 * ⛔ `unknown` (the scope read FAILED) refuses, exactly as canSeeDevice does.
 *
 * @param {string|null|undefined} pathname
 * @param {{state: string}|null|undefined} scope
 * @returns {{refused: boolean, surface: string|null, reason: string}}
 */
function pageRefusal(pathname, scope) {
  if (typeof pathname !== 'string' || !pathname.startsWith('/')) {
    return { refused: false, surface: null, reason: 'no-pathname' };
  }
  const surface = blockedSurfaceFor(pathname);
  if (!surface) return { refused: false, surface: null, reason: 'not-blocked' };
  const state = scope && scope.state;
  if (state === SCOPE_STATES.UNSCOPED) {
    return { refused: false, surface, reason: 'unscoped' };
  }
  if (state === SCOPE_STATES.SCOPED) {
    return { refused: true, surface, reason: 'scoped' };
  }
  // ⛔ Everything else — `unknown`, a missing scope, a state nobody recognises
  // — denies. An authorisation check that degrades to "probably fine" is not a
  // check, and an unrecognised state must not be a third flavour of allow.
  return { refused: true, surface, reason: 'unknown' };
}

const BLOCKED_PATTERNS = ALL_PATTERNS.filter((x) => x.cls === 'blocked');

module.exports = {
  PATHNAME_HEADER,
  pageRefusal,
  UNMAPPABLE_BLOCKED,
  surfaceToPattern,
  resolveSurface,
  blockedSurfaceFor,
  BLOCKED_PATTERNS,
  ALL_PATTERNS,
};
