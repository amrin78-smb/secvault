'use strict';
// lib/vpnDetectionLinks.js
//
// Turns one VPN detection finding into a /logs query that shows the RAW EVENTS
// the finding was computed from. Pure: no pool, no clock it is not handed.
//
// The detections in lib/engines/vpnDetections.js are read out of
// `syslog_vpn_auth_hourly` — an hourly ROLLUP. It carries counts, not events.
// So every question an operator asks next ("which usernames, exactly?", "what
// did the successful one look like?", "is this the same client each time?") is
// answerable only in `syslog_events`, and until now the only route there was
// to retype the address into /logs by hand.
//
// ── ⛔ THE FILTERS ARE THE ROLLUP'S OWN PREDICATE, NOT AN APPROXIMATION ────
// lib/syslog/rollups.js builds that rollup with
//     WHERE log_class = 'vpn' AND auth_outcome IS NOT NULL
// grouping on `src_ip`, `src_country`, `device_id` and aggregating `src_user`.
// Every link below is built from those same columns, so the events it lands on
// are BY CONSTRUCTION the population the finding was counted from. A link
// assembled from some other notion of "VPN login" would drift from the number
// printed beside it, and the operator would be left holding two figures with
// no way to tell which was wrong.
//
// ── ⛔ THE WINDOW ALWAYS TRAVELS WITH THE LINK ────────────────────────────
// /logs defaults to THE LAST HOUR when it is given no window (see
// resolveWindow in lib/syslog/logSearch.js, and the reason it may never be
// unbounded). A spray finding reading "2,106 failures over 18 hours" that
// opens onto the last hour's handful of events does not look like a narrower
// view — it looks like the detection was WRONG. That is this codebase's
// failed-read-as-a-fact rule wearing a hyperlink: a partial answer, presented
// as the whole one, with nothing on screen saying so.
//
// ── ⛔ A FILTER IS NEVER INVENTED TO MAKE A LINK LOOK PRECISE ─────────────
// `country_change` names TWO addresses and `account_targeted` names dozens;
// picking one would quietly drop the rest of the evidence while the link still
// read as "this finding". Those link on the username alone — the same call
// notificationDispatch's `fetchOpenIngestDrop` makes when an item spans
// several firewalls and it therefore names none. Each link states what it
// filtered on, so a narrower-than-expected result is never a surprise.
//
// ⛔ AND AN UNFILTERABLE FINDING GETS NO LINK AT ALL, rather than one carrying
// only a time window: that would dump every VPN authentication on the fleet
// and present it as this finding's evidence.

// The rollup's own class predicate. Kept as a constant so the two files can be
// grepped together if the vendor parsers ever classify VPN differently.
const VPN_LOG_CLASS = 'vpn';

// ⛔ LOGINS ONLY, BUT BOTH OUTCOMES — and both halves were measured, not
// assumed. On the live fleet over two hours, only 4,871 of 19,600
// `log_class='vpn'` rows are authentications; the rest are portal-prelogin,
// HIP checks and tunnel latency. Without `authOutcome=any` a link lands on a
// page that is ~70% noise, and since /logs orders by time and pages at 50
// rows, the first screen can contain NO authentication at all — from which the
// only available reading is that the finding has nothing behind it.
//
// ⛔ AND IT IS NOT NARROWED TO `failure`. The question every one of these
// findings raises is the success question — "and none of them succeeded" is
// exactly the half `successClaimVerified` marks as measured or not. Filtering
// the successes out would hide the single piece of evidence that could
// overturn the finding.
const AUTH_OUTCOME_ANY = 'any';
const SHOWS_BOTH_OUTCOMES =
  'Successful and failed logins both, so a success that contradicts this finding is visible rather than filtered away.';

function isNonEmpty(v) {
  return typeof v === 'string' && v.trim() !== '';
}

/**
 * Format an instant the way /logs' own `datetime-local` inputs expect:
 * `YYYY-MM-DDTHH:mm`, in the SERVER'S LOCAL ZONE.
 *
 * ⛔ NOT AN ISO `Z` STRING, and the reason is visible rather than theoretical.
 * `searchEvents` would parse either one correctly — but `<input
 * type="datetime-local">` rejects a value carrying a zone and renders BLANK.
 * The operator would then see results covering 24 hours above two empty window
 * boxes, and one re-submit would silently narrow the search to the default
 * hour while looking like the same query.
 *
 * ⛔ Local, not UTC, because `new Date('2026-09-24T09:10')` parses a
 * zone-less string as LOCAL — so formatting local and re-parsing local
 * round-trips to the same instant. Emitting UTC digits here would shift the
 * window by the server's offset (+07:00 on the reference deployment) on the
 * way back in. This is the same server-local convention the fixed-HH:MM cron
 * jobs already run on.
 */
function toLocalInputValue(value) {
  // ⛔ `new Date(null)` IS EPOCH 0, NOT AN INVALID DATE. A missing
  // windowStart would otherwise produce `1970-01-01T07:00` -- a perfectly
  // well-formed link that /logs clamps to eight days ending in 1970 and
  // reports as an ordinary empty result. A caller reading that concludes the
  // finding has no events behind it. The absent value has to be rejected
  // BEFORE the Date constructor gets a chance to make it look real, which is
  // the same reason lib/consoleUrl.js catches a missing scheme before
  // `new URL()`.
  if (value === null || value === undefined || value === '') return null;
  if (!(value instanceof Date) && typeof value !== 'string' && typeof value !== 'number') return null;
  const d = value instanceof Date ? value : new Date(value);
  if (!(d instanceof Date) || Number.isNaN(d.getTime())) return null;
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
    + `T${p(d.getHours())}:${p(d.getMinutes())}`;
}

/**
 * Which columns a given finding can honestly be narrowed by.
 *
 * Returns `{}` when the finding carries nothing identifying — the caller then
 * renders no link rather than a window-only one.
 */
function filtersFor(finding) {
  const f = finding && typeof finding === 'object' ? finding : {};
  const out = {};
  switch (f.kind) {
    // One address, many usernames. The address is the subject.
    case 'credential_spray':
      if (isNonEmpty(f.srcIp)) out.srcIp = f.srcIp.trim();
      break;

    // One address against one username — the only finding precise in both.
    case 'brute_force':
      if (isNonEmpty(f.srcIp)) out.srcIp = f.srcIp.trim();
      if (isNonEmpty(f.username)) out.srcUser = f.username.trim();
      break;

    // One username, MANY addresses. ⛔ No address filter: naming one of dozens
    // would hide the distribution that IS the finding.
    case 'account_targeted':
      if (isNonEmpty(f.username)) out.srcUser = f.username.trim();
      break;

    // A username seen from a country absent from its own history.
    //
    // ⛔ THE COUNTRY IS DELIBERATELY *NOT* FILTERED, AND THAT IS A FIX.
    // The finding's `country` is normalizeCountry()'s output -- an ISO code
    // rewritten to a full English name, which lib/engines/vpnDetections.js does
    // precisely because vendors disagree: Palo Alto writes `US`, FortiOS writes
    // `United States`. `logSearch.js` matches `src_country` with EXACT EQUALITY
    // against the raw column, so a link carrying the normalised name matches the
    // raw rows only by luck.
    //
    // Measured on the live fleet (48h): `CH` 195 rows vs `Switzerland` 5;
    // `RU` 1,149 vs 5; `TH` 1,050 vs 8. An EXPLAIN of
    // `src_country = 'Switzerland'` over a 2h window returned 0 rows having
    // filtered out 18,626 -- so the link for a new-country finding would open
    // an EMPTY results table on the one page whose job is to show the evidence
    // behind it. An empty forensics result reads as "this did not happen".
    //
    // The honest link is the username alone: WIDER than the finding, and
    // correct. The raw spelling is not retained on the finding, so it cannot be
    // filtered without re-reading the rollup -- and guessing one of the two
    // spellings would reintroduce the same bug for the other vendor.
    case 'new_country_for_user':
      if (isNonEmpty(f.username)) out.srcUser = f.username.trim();
      break;

    // ⛔ TWO addresses and TWO countries, and the pair is the whole point.
    // Filtering to either end would show half an impossible-travel finding
    // while looking like all of it.
    case 'country_change':
      if (isNonEmpty(f.username)) out.srcUser = f.username.trim();
      break;

    // ⛔ THE HOUR IS NOT EXPRESSIBLE. /logs filters a CONTIGUOUS window, and
    // this finding is about one hour-of-day repeated across the window. The
    // link therefore covers the whole window and says so; silently returning a
    // single hour's worth would drop every other occurrence the count is made
    // of.
    case 'off_hours_success':
      if (isNonEmpty(f.username)) out.srcUser = f.username.trim();
      break;

    default:
      break;
  }
  return out;
}

// What each filter means, in the operator's words, for the link's own title.
// ⛔ `srcCountry` is intentionally absent: no link emits it any more (see
// the new_country_for_user case above).
const FILTER_WORDS = {
  srcIp: (v) => `from ${v}`,
  srcUser: (v) => `as "${v}"`,
};

/**
 * Build the /logs href for one finding.
 *
 * @param {object} finding    one entry from a detection's `findings` or
 *                            `unverifiable` array.
 * @param {object} window     `{ windowStart, windowEnd }` — the detection
 *                            window, exactly as the engine reports it.
 * @returns {{href: string, title: string, filters: object}|null}
 *          `null` when nothing identifying is available, which the caller
 *          MUST render as no link rather than as a bare time window.
 */
function buildDetectionLogHref(finding, window) {
  const filters = filtersFor(finding);
  if (Object.keys(filters).length === 0) return null;

  const w = window && typeof window === 'object' ? window : {};
  const from = toLocalInputValue(w.windowStart);
  const to = toLocalInputValue(w.windowEnd);
  // ⛔ NO WINDOW, NO LINK. See the header: a link that silently falls back to
  // /logs' one-hour default makes an 18-hour finding look overstated. Refusing
  // is the honest failure; the caller shows the row without a link.
  if (!from || !to) return null;

  const params = new URLSearchParams();
  params.set('from', from);
  params.set('to', to);
  params.set('logClass', VPN_LOG_CLASS);
  params.set('authOutcome', AUTH_OUTCOME_ANY);
  for (const [k, v] of Object.entries(filters)) params.set(k, v);

  const words = Object.entries(filters)
    .map(([k, v]) => (FILTER_WORDS[k] ? FILTER_WORDS[k](v) : `${k}=${v}`))
    .join(' ');

  return {
    href: `/logs?${params.toString()}`,
    filters,
    title:
      `Open the raw VPN authentication events ${words} over this detection's own `
      + `window. ${SHOWS_BOTH_OUTCOMES}`,
  };
}

module.exports = {
  buildDetectionLogHref,
  filtersFor,
  toLocalInputValue,
  VPN_LOG_CLASS,
  AUTH_OUTCOME_ANY,
  SHOWS_BOTH_OUTCOMES,
};
