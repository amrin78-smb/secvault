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

// app/api/devices/[id]/route.js      -> ^/api/devices/[^/]+$
// app/(dashboard)/devices/page.js    -> ^/devices$
// app/(dashboard)/page.js            -> ^/$
function surfaceToPattern(file) {
  let p = file;
  if (p.startsWith('app/api/')) p = p.slice('app'.length);           // /api/...
  else if (p.startsWith('app/(dashboard)/')) p = p.slice('app/(dashboard)'.length);
  else return null;
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

/**
 * Is this URL path a surface a device-scoped account must NOT reach?
 * @returns {string|null} the surface file that blocked it, or null
 */
function blockedSurfaceFor(pathname) {
  return resolveSurface(ALL_PATTERNS, pathname);
}

const BLOCKED_PATTERNS = ALL_PATTERNS.filter((x) => x.cls === 'blocked');

module.exports = { surfaceToPattern, resolveSurface, blockedSurfaceFor, BLOCKED_PATTERNS, ALL_PATTERNS };
