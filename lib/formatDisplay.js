// lib/formatDisplay.js
//
// Presentation helpers shared across pages. Pure, no DB, no React — so it is
// safe to import from a server component, a client component or a test.
//
// ── WHY THESE LIVE HERE ───────────────────────────────────────────────────
// Each of these existed already, correctly implemented, in exactly ONE file
// while a dozen other pages hand-rolled a worse version or none at all:
//
//   timeAgo()      lived in components/dashboard/DeviceStatusSummary.js and was
//                  used once, while 29 other sites rendered a bare
//                  "2026-09-09 06:11 UTC" and made the reader do timezone
//                  arithmetic against a UTC+7 wall clock.
//   vendor labels  lived in components/devices/vendorMeta.js and were applied
//                  by VendorDistribution.js but by none of the 11 other places
//                  that render a vendor, so the same dashboard showed both
//                  "Palo Alto PAN-OS" and "paloalto".
//
// ⛔ NONE of these may invent a value. A null timestamp returns null, not
// "never" or an epoch; an unrecognised key returns the key itself, not a
// prettified guess. Callers keep their own explicit "Never" / "—" branches,
// which are load-bearing wherever absence is a real state.

'use strict';

/**
 * Human-relative age: "just now" / "12m ago" / "3h ago" / "2d ago".
 *
 * ⛔ Returns null (never a placeholder) when the input is absent or
 * unparseable, so the caller decides how absence reads. Render this as the
 * VALUE and keep the absolute UTC string as the `title` — the absolute time is
 * still the evidence, it just should not be the thing a reader has to decode
 * to answer "is this stale?".
 */
function timeAgo(timestamp) {
  if (!timestamp) return null;
  const then = new Date(timestamp).getTime();
  if (Number.isNaN(then)) return null;

  const diffMs = Date.now() - then;
  // A clock skew or a future timestamp is not "0 minutes ago" — say so rather
  // than rendering a confident, wrong age.
  if (diffMs < 0) return 'in the future';
  if (diffMs < 60000) return 'just now';

  const minutes = Math.floor(diffMs / 60000);
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

/** Absolute UTC, the app's existing convention. Kept for the `title`. */
function absoluteUtc(timestamp) {
  if (!timestamp) return null;
  const d = new Date(timestamp);
  if (Number.isNaN(d.getTime())) return null;
  return `${d.toISOString().replace('T', ' ').slice(0, 16)} UTC`;
}

/** `snake_case` / `kebab-case` enum -> "Snake Case". Used for vendor action
 *  words and status enums that have no curated label. */
function titleCase(v) {
  if (typeof v !== 'string' || v === '') return v;
  return v
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

// Feed slugs are internal identifiers; these are the product names.
const FEED_LABELS = {
  nvd: 'NVD',
  kev: 'CISA KEV',
  paloalto_psirt: 'Palo Alto PSIRT',
  fortinet_psirt: 'Fortinet PSIRT',
  circl: 'CIRCL',
};

// Worst first. A partial NVD sync qualifies every CVE number on the page and
// must not sort below a healthy KEV one.
const FEED_STATUS_ORDER = { failed: 0, error: 0, partial: 1, running: 2, success: 3 };

function feedStatusRank(status) {
  const r = FEED_STATUS_ORDER[String(status || '').toLowerCase()];
  // ⛔ An unrecognised status sorts with the problems, not with the successes.
  // A status this app has never seen is not evidence that things are fine.
  return r === undefined ? 1 : r;
}

/** Newest completion across a set of feed rows, for a single "last synced" note. */
function newestFeedAt(rows) {
  let newest = null;
  for (const r of Array.isArray(rows) ? rows : []) {
    const t = r.finished_at || r.started_at;
    if (!t) continue;
    const d = new Date(t);
    if (Number.isNaN(d.getTime())) continue;
    if (newest === null || d > newest) newest = d;
  }
  return newest;
}

module.exports = {
  timeAgo,
  absoluteUtc,
  titleCase,
  FEED_LABELS,
  feedStatusRank,
  newestFeedAt,
};
