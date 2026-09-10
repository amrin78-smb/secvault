// lib/engines/vpnDetections.js
//
// Named VPN authentication detections, computed at READ time over
// `syslog_vpn_auth_hourly`. No table, no cron job, no persistence — the same
// precedent as lib/engines/deviceHealth.js and baseline config drift: the raw
// facts are already stored, and a detection is a function of those facts plus
// the current time. Persisting a verdict would mean a stored severity that
// stops matching the evidence the moment either the thresholds or the rollup
// change, and there is nothing here a page load cannot recompute in one round
// of small queries.
//
// ⛔ NEVER `syslog_events`. Every query in this file reads the hourly VPN auth
// rollup. The equivalent question against the raw table was measured at 85.6
// SECONDS over a 24h window (see lib/syslog/vpnAuthStats.js) and the table
// takes ~28M rows/day.
//
// ── ⛔ THE FOUR THINGS THIS FILE IS NOT ALLOWED TO DO ─────────────────────
//
// 1. TREAT A THIN BASELINE AS A CLEAN ONE. VPN auth history on this fleet
//    begins 2026-09-09 — twenty-six hours at the time of writing. "This user
//    has never authenticated from India before" and "we have never seen this
//    user before at all" are DIFFERENT STATEMENTS, and a detection that cannot
//    tell them apart must say `insufficient_baseline`, never return an empty
//    findings list that reads as "nothing anomalous". Every detection carries
//    a `baseline` object stating what it needed and what it had.
//
// 2. FORGET THAT `usernames_truncated` BOUNDS THE CLAIM. The rollup caps each
//    bucket's username array at 50 (see lib/syslog/rollups.js). A count taken
//    from a capped array is a FLOOR, and a user's ABSENCE from a capped array
//    is not evidence of absence. Counts derived here are named `*Floor` and
//    rendered "at least N"; baselines exclude capped rows and say how many
//    they excluded.
//
// 3. CLAIM A DISTANCE IT CANNOT COMPUTE. There is NO city and NO latitude/
//    longitude anywhere in this schema — `src_country` is the only geography,
//    it is the VENDOR'S OWN word, and the time resolution is one hour. So
//    there is no "impossible travel" detection here. There is
//    `country_change`, which reports exactly what it measured: two successful
//    authentications for one user, from two different countries, N hours
//    apart. Inventing coordinates for a country to get a velocity would be a
//    fabricated measurement of precisely the class CLAUDE.md keeps fixing.
//
// 4. READ A REPORTING GAP AS A FACT ABOUT A DEVICE. Measured live: TSR-TL
//    (Fortinet) reported 1,860 VPN authentication FAILURES and ZERO successes
//    in 26 hours. That device does not have a 100% failure rate; SecVault
//    cannot see its successes, which is a device-side logging setting. Any
//    detection whose claim contains the words "and none succeeded" is
//    UNVERIFIED for a source whose failures were reported by such a device,
//    and is filed under `unverifiable` with the device named — never asserted.
//
// ── Reuse, not re-derivation ─────────────────────────────────────────────
// The credential-spray candidate set is `findUsernameSprayers()` from
// lib/syslog/vpnAuthStats.js, called unchanged. That rule (one address, >= 5
// distinct usernames, no observed success) already exists, is already tested,
// and already carries the country-normalisation the ranking depends on. This
// file NAMES it, attaches its evidence and its success-baseline caveat, and
// adds the detections that file does not cover — all of which are per-USER
// and therefore need their own reads.

'use strict';

const {
  getVpnLoginLocations,
  findUsernameSprayers,
  MIN_USERNAMES_FOR_SPRAY, normalizeCountry } = require('../syslog/vpnAuthStats');

// ── Window / baseline sizing ─────────────────────────────────────────────

const DEFAULT_WINDOW_HOURS = 24;
const MAX_WINDOW_HOURS = 24 * 8; // matches getVpnLoginLocations' own clamp
const DEFAULT_BASELINE_DAYS = 30;
const MAX_BASELINE_DAYS = 90;

// ── Thresholds ───────────────────────────────────────────────────────────
//
// ⛔ Each of these was chosen against LIVE fleet data and the count it
// produces is recorded beside it. A threshold with no measured firing rate is
// a guess, and a detection that fires on the fleet's own normal traffic gets
// switched off, which costs more than the coverage it buys.

// Credential spray: MIN_USERNAMES_FOR_SPRAY (5), owned by vpnAuthStats.js.
// Live: 249 of 1,840 source addresses, 0 of them Thai (where the real users
// are). The worst is one Bulgarian address at 1,821 failures / 908 usernames.

// Brute force: attributable failures from ONE address against ONE username.
// Live at 10: exactly 3 pairs, none of them a fleet account.
const MIN_BRUTE_FORCE_ATTEMPTS = 10;

// Targeted account: one username attacked from many distinct addresses — the
// distributed counterpart of brute force. Live at 10: 52 usernames; at 5 it is
// 326, which is a list nobody reads.
const MIN_TARGETED_SOURCES = 10;

// ⛔ BASELINE REQUIREMENTS. These are the honesty gates, not tuning knobs.
// A "this user has never done X" claim needs enough history for "never" to
// mean something.
const NEW_COUNTRY_MIN_BASELINE_DAYS = 7;   // fleet-wide history required
const NEW_COUNTRY_MIN_USER_DAYS = 3;       // per-user history required
// Hourly buckets, so the smallest measurable gap is 0 (same bucket). Beyond
// half a day a country change is unremarkable for anyone who flies.
const COUNTRY_CHANGE_MAX_GAP_HOURS = 12;
// A per-hour-of-day profile needs at least two weeks before "unusual hour"
// is a measurement rather than an assumption about office hours.
const OFF_HOURS_MIN_BASELINE_DAYS = 14;
// A quiet hour is one whose mean daily successful-auth volume is at or below
// this share of the busiest hour's.
const OFF_HOURS_QUIET_SHARE = 0.1;

const DETECTION_IDS = [
  'credential_spray',
  'brute_force',
  'account_targeted',
  'new_country_for_user',
  'country_change',
  'off_hours_success',
];

// Detection `status`, and what each licenses the UI to say.
//   'measured'              findings are real claims backed by the evidence attached
//   'insufficient_baseline' the question needs history SecVault does not hold yet
//   'no_data'               no VPN authentication evidence at all in scope
const STATUS = {
  MEASURED: 'measured',
  INSUFFICIENT: 'insufficient_baseline',
  NO_DATA: 'no_data',
};

// ⛔ HOW MANY `unverifiable` ITEMS ARE LISTED, never how many EXIST. Every
// detection also returns `unverifiableTotal`, and the UI must render the TOTAL
// rather than the length of the array — an insufficient-baseline state on a
// one-day-old fleet produces hundreds of these (393 for off-hours, measured
// live), and a silently shortened list is the same class of lie as a silently
// shortened findings list. The COUNT is the claim; the sample is illustration.
const MAX_UNVERIFIABLE_LISTED = 25;

const MS_PER_HOUR = 3600000;
const MS_PER_DAY = 86400000;

function clampInt(value, def, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return def;
  return Math.min(Math.max(Math.trunc(n), min), max);
}

function toDate(v) {
  if (v instanceof Date) return v;
  if (typeof v === 'string' || typeof v === 'number') {
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  return null;
}

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

/** Floor `now` to the top of its hour, then step back `hours - 1` hours. */
function windowStartFrom(now, hours) {
  const ref = toDate(now) || new Date();
  const topOfHour = new Date(Math.floor(ref.getTime() / MS_PER_HOUR) * MS_PER_HOUR);
  return new Date(topOfHour.getTime() - (hours - 1) * MS_PER_HOUR);
}

// ── Success-baseline classification, per device ──────────────────────────
//
// ⛔ THE QUESTION IS "WOULD WE HAVE SEEN A SUCCESS IF ONE HAPPENED", NOT
// "IS THIS DEVICE HEALTHY". A device that reported failures and no successes
// at all cannot support any claim of the form "and nobody got in": that is the
// failed-read-as-a-fact bug in its most dangerous form, because the wrong
// answer is reassuring.
//
// The gate is >= 1 successful authentication in the window — deliberately the
// same bar findFailureOnlyCountries() uses, so the two files cannot disagree
// about which vendors are measurable. `successShare` is carried alongside so a
// device that logs successes but barely (TSR_EKM: 12 successes against 1,899
// failures, 0.6%) is VISIBLY weak on screen rather than silently promoted to
// "measured" or silently demoted to "gap" by a second, unjustified threshold.
function classifyDeviceSuccessBaseline(row) {
  const successEvents = num(row.success_events);
  const successHours = num(row.success_hours);
  const failureEvents = num(row.failure_events);
  const total = successEvents + failureEvents;
  const status =
    successEvents > 0 ? 'measured' : failureEvents > 0 ? 'none' : 'no_vpn_data';
  return {
    deviceId: row.device_id || null,
    deviceName: row.device_name || null,
    vendor: row.vendor || null,
    successEvents,
    successHours,
    failureEvents,
    hours: num(row.hours),
    // null, not 0, when there is no denominator — an undefined ratio is not a
    // ratio of zero.
    successShare: total > 0 ? successEvents / total : null,
    successBaseline: status,
  };
}

/**
 * Does every device that reported this source's failures also report successes?
 *
 * ⛔ EVERY, not SOME — the same reasoning findFailureOnlyCountries() documents.
 * 1,183 of ~1,840 source addresses on this fleet were seen by MORE THAN ONE
 * device. If a Palo Alto (which logs successes) and TSR-TL (which does not)
 * both saw an address fail, "and it never succeeded" is still not assertable:
 * TSR-TL could have let a login through and never told us.
 *
 * @returns {{verified: boolean, blindDevices: Array<{deviceId, deviceName, vendor}>}}
 */
function successClaimSupport(deviceIds, baselineByDevice, unattributed) {
  const ids = Array.isArray(deviceIds) ? deviceIds.filter(Boolean) : [];
  const blind = [];
  for (const id of ids) {
    const b = baselineByDevice.get(id);
    // A device we have no coverage row for is not a device we can vouch for.
    if (!b || b.successBaseline !== 'measured') {
      blind.push({
        deviceId: id,
        deviceName: b ? b.deviceName : null,
        vendor: b ? b.vendor : null,
      });
    }
  }
  // Failures that were never attributed to a managed device at all: we do not
  // know which firewall saw them, so we cannot know whether it logs successes.
  const verified = ids.length > 0 && blind.length === 0 && !unattributed;
  return { verified, blindDevices: blind };
}

// ── Severity ─────────────────────────────────────────────────────────────
//
// ⛔ These return the SEVERITY RAMP's own values (critical/high/medium/low/
// info) so the component can hand them straight to components/analysis/
// severityRamp.js. No seventh local colour map — see that file's own warning.
//
// ⛔ An UNVERIFIED success claim is never a reason to LOWER a severity. Not
// knowing whether the attacker got in is not better news than knowing they did
// not; it is less news. The unverified flag rides alongside the severity.

function spraySeverity(usernames) {
  const n = num(usernames);
  if (n >= 100) return 'critical';
  if (n >= 25) return 'high';
  return 'medium';
}

function bruteForceSeverity(attemptsFloor) {
  const n = num(attemptsFloor);
  if (n >= 50) return 'high';
  if (n >= 20) return 'medium';
  return 'low';
}

function targetedSeverity(sources) {
  const n = num(sources);
  if (n >= 30) return 'high';
  if (n >= 20) return 'medium';
  return 'low';
}

function countryChangeSeverity(gapHours) {
  const n = num(gapHours);
  // Same hourly bucket: one account authenticated successfully from two
  // countries inside the same hour. That is the strongest statement available
  // without coordinates, and it does not depend on distance.
  if (n <= 0) return 'high';
  if (n <= 3) return 'medium';
  return 'low';
}

// ── Baseline summary ─────────────────────────────────────────────────────

/**
 * How much VPN auth history exists at all, and therefore what any "never
 * before" claim is allowed to rest on.
 */
function summariseBaseline(row, now) {
  const first = toDate(row && row.first_bucket_at);
  const last = toDate(row && row.last_bucket_at);
  const historyHours = num(row && row.history_hours);
  const historyDays = num(row && row.history_days);
  const ref = toDate(now) || new Date();
  // Elapsed span, not the count of populated buckets — an hour with no VPN
  // login is still an hour we were listening.
  const spanDays = first ? Math.max(0, (ref.getTime() - first.getTime()) / MS_PER_DAY) : 0;
  return {
    firstBucketAt: first,
    lastBucketAt: last,
    historyHours,
    historyDays,
    spanDays: Math.round(spanDays * 100) / 100,
    truncatedRows: num(row && row.truncated_rows),
    hasHistory: historyHours > 0,
  };
}

/** The per-detection baseline verdict, in one shape the UI can render generically. */
function baselineVerdict(baseline, requiredDays, unit = 'days of VPN authentication history') {
  const have = baseline.spanDays;
  return {
    required: requiredDays,
    have: Math.round(have * 100) / 100,
    unit,
    satisfied: baseline.hasHistory && have >= requiredDays,
    firstBucketAt: baseline.firstBucketAt,
  };
}

/**
 * Cap an `unverifiable` list for display while keeping its true size.
 *
 * ⛔ Returns BOTH, always, so a caller cannot accidentally read the array's
 * length as the number of affected items.
 */
function capUnverifiable(list) {
  const all = Array.isArray(list) ? list : [];
  return { unverifiable: all.slice(0, MAX_UNVERIFIABLE_LISTED), unverifiableTotal: all.length };
}

// ── Detection builders (pure — no pool, no clock beyond what is passed) ───

/**
 * Credential spray. Candidate set is findUsernameSprayers()'s output, UNCHANGED.
 *
 * What this adds: the evidence each finding must carry (which address, which
 * country, how many distinct usernames, how many failures, which devices saw
 * it, when it was last seen) and the success-baseline verdict that decides
 * whether "and none of them succeeded" is a measurement or a guess.
 */
function buildSprayDetection({ sources, attributionBySource, baselineByDevice, windowHours }) {
  const candidates = findUsernameSprayers(Array.isArray(sources) ? sources : []);
  const findings = [];
  const unverifiable = [];

  for (const s of candidates) {
    const attr = attributionBySource.get(s.srcIp) || {};
    const support = successClaimSupport(attr.deviceIds, baselineByDevice, attr.unattributed);
    const base = {
      kind: 'credential_spray',
      srcIp: s.srcIp,
      country: s.country || null,
      located: Boolean(s.country),
      vendors: Array.isArray(attr.vendors) ? attr.vendors : [],
      devices: Array.isArray(attr.deviceNames) ? attr.deviceNames : [],
      // ⛔ A FLOOR when the bucket's username array was capped at 50.
      usernames: num(s.usernames),
      usernamesIsFloor: Boolean(s.usernamesTruncated),
      failures: num(s.failure),
      hours: num(attr.hours),
      lastSeenAt: s.lastSeenAt || null,
      severity: spraySeverity(s.usernames),
      successClaimVerified: support.verified,
      blindDevices: support.blindDevices,
      evidence:
        `${num(s.failure)} failed VPN authentications from ${s.srcIp}`
        + ` against ${s.usernamesTruncated ? 'at least ' : ''}${num(s.usernames)} distinct usernames`
        + ` in the last ${windowHours}h`,
    };
    if (support.verified) findings.push(base);
    else unverifiable.push({ ...base, reason: 'no-success-baseline' });
  }

  const sortByFailures = (a, b) => b.failures - a.failures || b.usernames - a.usernames;
  findings.sort(sortByFailures);
  unverifiable.sort(sortByFailures);

  return {
    id: 'credential_spray',
    title: 'Credential spray',
    question: 'Is one address trying many different usernames?',
    method:
      `One source address, ${MIN_USERNAMES_FOR_SPRAY} or more distinct usernames failing, and no `
      + 'observed successful login from it. Shared with the Login Locations tab — the same rule, '
      + 'named and evidenced here.',
    // ⛔ ALWAYS `measured`, and that is not laziness. Spray is a statement
    // about ONE window — "this address tried N usernames in the last 24h" —
    // so a thin history does not weaken it and there is no baseline to gate
    // on. The uncertainty that DOES exist here is the success half, and it is
    // carried per finding in `successClaimVerified`, not smuggled into the
    // detection's status.
    status: STATUS.MEASURED,
    baseline: null,
    findings,
    ...capUnverifiable(unverifiable),
    caveats: unverifiable.length > 0
      ? [
        `${unverifiable.length} address(es) show the spray shape but were reported by a firewall `
        + 'that logs no successful VPN authentications at all, so "and none succeeded" is not '
        + 'measured for them. The username breadth still is.',
      ]
      : [],
  };
}

/**
 * Brute force — many attempts from ONE address against ONE username.
 *
 * ⛔ `attemptsFloor` IS A FLOOR AND CAN NEVER BE ANYTHING ELSE. One rollup row
 * carries a single `event_count` covering EVERY username in its array, with no
 * split — lib/syslog/vpnPresence.js documents the same limit ("a per-user
 * EVENT count is not derivable from this table at any price"). So the count
 * here attributes a bucket's full event_count to the user ONLY when that
 * bucket named exactly one username, and contributes 1 otherwise. Every label
 * built from it says "at least".
 */
function buildBruteForceDetection({ rows, baselineByDevice, windowHours }) {
  const findings = [];
  const unverifiable = [];

  for (const r of Array.isArray(rows) ? rows : []) {
    const support = successClaimSupport(r.device_ids, baselineByDevice, r.unattributed);
    const attemptsFloor = num(r.attempts_floor);
    const base = {
      kind: 'brute_force',
      username: r.username,
      srcIp: r.src_ip,
      country: r.src_country || null,
      devices: Array.isArray(r.device_names) ? r.device_names : [],
      attemptsFloor,
      // True when any contributing bucket named more than one username, i.e.
      // the count above is a genuine under-count rather than an exact total.
      attemptsIsFloor: Boolean(r.shared_buckets) || Boolean(r.usernames_truncated),
      hours: num(r.hours),
      firstSeenAt: r.first_seen_at || null,
      lastSeenAt: r.last_seen_at || null,
      // How many OTHER usernames this same address attacked. A source with a
      // broad username list is spraying and merely happened to hit this name
      // hardest; a source with one is genuinely focused. The operator needs
      // both numbers to disagree with the severity.
      sourceUsernameBreadth: num(r.source_username_breadth),
      severity: bruteForceSeverity(attemptsFloor),
      successClaimVerified: support.verified,
      blindDevices: support.blindDevices,
      evidence:
        `at least ${attemptsFloor} failed authentications for "${r.username}" from ${r.src_ip}`
        + ` across ${num(r.hours)} hourly buckets in the last ${windowHours}h`,
    };
    if (support.verified) findings.push(base);
    else unverifiable.push({ ...base, reason: 'no-success-baseline' });
  }

  const byAttempts = (a, b) => b.attemptsFloor - a.attemptsFloor;
  findings.sort(byAttempts);
  unverifiable.sort(byAttempts);

  return {
    id: 'brute_force',
    title: 'Brute force against one account',
    question: 'Is one address hammering a single username?',
    method:
      `At least ${MIN_BRUTE_FORCE_ATTEMPTS} attributable failed authentications from one source `
      + 'address against one username, with no observed success. Counts are FLOORS: an hourly '
      + 'bucket naming several usernames carries one undivided event count, so it contributes 1.',
    status: STATUS.MEASURED,
    baseline: null,
    findings,
    ...capUnverifiable(unverifiable),
    caveats: unverifiable.length > 0
      ? [
        `${unverifiable.length} case(s) were reported only by firewalls that log no successful VPN `
        + 'authentications, so whether any attempt succeeded is unmeasured.',
      ]
      : [],
  };
}

/**
 * Account targeted — one username, many distinct source addresses.
 *
 * The distributed counterpart of brute force, and the question an operator
 * actually acts on: WHICH accounts are they after.
 *
 * ⛔ THIS SAYS NOTHING ABOUT WHETHER THE ACCOUNT EXISTS. Live, all 52 targeted
 * usernames are absent from the successful-auth set — but that set covers ~1
 * day and 232 users, so their absence is a fact about the baseline, not about
 * the directory. Asserting "these accounts are not real" from it would be the
 * same error as reading a reporting gap as a device fact.
 */
function buildTargetedAccountDetection({ rows, windowHours }) {
  const findings = (Array.isArray(rows) ? rows : []).map((r) => ({
    kind: 'account_targeted',
    username: r.username,
    sources: num(r.sources),
    countries: num(r.countries),
    attemptsFloor: num(r.attempts_floor),
    attemptsIsFloor: true,
    hours: num(r.hours),
    lastSeenAt: r.last_seen_at || null,
    severity: targetedSeverity(r.sources),
    evidence:
      `"${r.username}" failed from ${num(r.sources)} distinct source addresses`
      + ` in ${num(r.countries)} countries over the last ${windowHours}h`,
  }));
  findings.sort((a, b) => b.sources - a.sources || b.attemptsFloor - a.attemptsFloor);

  return {
    id: 'account_targeted',
    title: 'Account targeted from many addresses',
    question: 'Which accounts is the fleet being attacked through?',
    method:
      `One username failing from ${MIN_TARGETED_SOURCES} or more distinct source addresses in the `
      + 'window. Attempt counts are floors, for the same undivided-event-count reason as brute force.',
    status: STATUS.MEASURED,
    baseline: null,
    findings,
    unverifiable: [],
    unverifiableTotal: 0,
    caveats: [
      'Whether these usernames correspond to real accounts is NOT answerable from authentication '
      + 'logs at this baseline depth, and is deliberately not claimed either way.',
    ],
  };
}

/**
 * New country for a user.
 *
 * ⛔ THE ENTIRE POINT OF THIS DETECTION IS THE BASELINE, so it is gated twice:
 * once on the fleet (is there enough history for "never" to mean anything at
 * all) and once per user (has THIS user been seen on enough separate days).
 * A user with no prior successful authentication is reported as
 * `no-user-baseline` under `unverifiable` — "we have never seen this user
 * before" is a different statement from "this user has never done this", and
 * they must not render the same way.
 *
 * ⛔ Capped buckets are EXCLUDED from the baseline and counted. A user absent
 * from a capped username array may simply have been cut from it, so treating
 * that absence as "never seen from there" would manufacture a finding.
 */
function buildNewCountryDetection({ successRows, baseline, windowStart }) {
  const verdict = baselineVerdict(baseline, NEW_COUNTRY_MIN_BASELINE_DAYS);
  const start = toDate(windowStart);

  // Per-user baseline: countries and distinct days seen STRICTLY BEFORE the
  // detection window, from non-capped buckets only.
  const prior = new Map();
  const inWindow = new Map();
  let truncatedBaselineRows = 0;

  for (const r of Array.isArray(successRows) ? successRows : []) {
    const at = toDate(r.bucket_hour);
    if (!at) continue;
    // ⛔ NORMALISE. Palo Alto emits ISO alpha-2 ("TH") and FortiOS emits the full
      // English name ("Thailand"), and vpnAuthStats.js exists partly to fold them
      // together — its own comment says a GROUP BY on the raw value "splits one
      // country in half". These builders were reading the raw column, which does the
      // opposite and far worse: it JOINS one country into two, so a single employee
      // authenticating through a FortiGate and a Palo Alto gateway produced a
      // high-severity "authenticated from both TH and Thailand in the same hour"
      // — same country, same source IP, same hour, naming a real person.
      // Latent only because no username currently appears in both vendors’ success
      // rows; one shared account is all it takes.
      const country = normalizeCountry(r.src_country) || null;
    const user = r.username;
    if (!user) continue;
    if (start && at.getTime() < start.getTime()) {
      if (r.usernames_truncated) { truncatedBaselineRows += 1; continue; }
      const p = prior.get(user) || { countries: new Set(), days: new Set() };
      if (country) p.countries.add(country);
      p.days.add(at.toISOString().slice(0, 10));
      prior.set(user, p);
    } else {
      if (!country) continue; // an unlocated login cannot be a new COUNTRY
      // NUL separator, not a space: country names contain spaces ("United
      // States") and a username may too, so a space-joined key can collide.
      const key = `${user}\u0000${country}`;
      const w = inWindow.get(key) || { username: user, country, hours: new Set(), sources: new Set(), devices: new Set() };
      w.hours.add(at.toISOString());
      if (r.src_ip) w.sources.add(r.src_ip);
      if (r.device_name) w.devices.add(r.device_name);
      inWindow.set(key, w);
    }
  }

  const findings = [];
  const unverifiable = [];

  for (const w of inWindow.values()) {
    const p = prior.get(w.username);
    const item = {
      kind: 'new_country_for_user',
      username: w.username,
      country: w.country,
      authHours: w.hours.size,
      sources: [...w.sources],
      devices: [...w.devices],
      knownCountries: p ? [...p.countries].sort() : [],
      baselineDays: p ? p.days.size : 0,
      severity: 'medium',
      evidence:
        `"${w.username}" authenticated successfully from ${w.country} in ${w.hours.size} hourly`
        + ` bucket(s) in this window`,
    };
    if (!verdict.satisfied) {
      unverifiable.push({ ...item, reason: 'fleet-baseline-too-short' });
      continue;
    }
    if (!p || p.days.size < NEW_COUNTRY_MIN_USER_DAYS) {
      unverifiable.push({ ...item, reason: 'no-user-baseline' });
      continue;
    }
    if (p.countries.has(w.country)) continue; // known — not a finding
    findings.push({
      ...item,
      caveat: truncatedBaselineRows > 0 ? 'baseline-contains-capped-buckets' : null,
    });
  }

  findings.sort((a, b) => b.authHours - a.authHours || a.username.localeCompare(b.username));
  unverifiable.sort((a, b) => b.authHours - a.authHours || a.username.localeCompare(b.username));

  const caveats = [];
  if (truncatedBaselineRows > 0) {
    caveats.push(
      `${truncatedBaselineRows} baseline bucket(s) had their username list capped at 50 and were `
      + 'excluded — a user cut from a capped list would look like a user who was never there.'
    );
  }
  if (!verdict.satisfied) {
    caveats.push(
      `Needs ${NEW_COUNTRY_MIN_BASELINE_DAYS} days of VPN authentication history; SecVault holds `
      + `${verdict.have}. Until then no country can be called new for anyone — this is NOT the `
      + 'same as finding nothing.'
    );
  }

  return {
    id: 'new_country_for_user',
    title: 'New country for a user',
    question: 'Did someone authenticate from a country they have no history in?',
    // ⛔ ONE template literal, deliberately — do NOT split this back into
    // `...` + `...`. Next’s SWC compressor DROPS the trailing static text of the
    // left-hand literal when both operands of + are template literals AND their
    // interpolations constant-fold. Both constants here are module-level literals,
    // so it folded, and the PRODUCTION page rendered:
    //
    //     "...where the user has at least 3least 7."
    //
    // 37 characters silently deleted, in the sentence that explains the rule to the
    // operator. ⛔ INVISIBLE to node --check, npm test, jsxSyntax.test.js and a
    // source read — only the built bundle shows it, which is why nothing caught it.
    // See .ai-codex/gotchas.md.
    // ⛔ PLAIN quoted strings, NOT template literals. Next’s SWC compressor DROPS
    // the trailing static text of a template literal when it is joined by + to
    // another template literal AND the interpolations constant-fold. Both constants
    // here are module-level literals, so it folded and the PRODUCTION page rendered
    // "...has at least 3least 7." — 37 characters silently deleted from the sentence
    // that explains the rule. Re-splitting the literals only MOVES which tail is
    // eaten (verified: it then rendered "3and the fleet has at least 7.").
    //
    // ⛔ INVISIBLE to node --check, npm test, jsxSyntax.test.js and a source read.
    // Only the built bundle shows it. See .ai-codex/gotchas.md.
    method: "A successful authentication from a country absent from that user's own prior "
      + 'history, where the user has at least ' + NEW_COUNTRY_MIN_USER_DAYS
      + ' days of history and the fleet has at least ' + NEW_COUNTRY_MIN_BASELINE_DAYS + '.',
    status: !baseline.hasHistory
      ? STATUS.NO_DATA
      : verdict.satisfied ? STATUS.MEASURED : STATUS.INSUFFICIENT,
    baseline: verdict,
    findings,
    ...capUnverifiable(unverifiable),
    caveats,
  };
}

/**
 * Country change — the HONEST form of "impossible travel".
 *
 * ⛔ THIS IS NOT A TRAVEL CALCULATION AND MUST NEVER BE LABELLED AS ONE.
 * SecVault holds no city and no coordinates for any address; `src_country` is
 * the firewall vendor's own word for the source's country and the time
 * resolution is one hour. So what is reported is exactly what was measured:
 * two SUCCESSFUL authentications for one user, from two named countries, N
 * hours apart. No distance, no velocity, no "impossible".
 *
 * Needs no historical baseline — both observations are inside the window and
 * the claim is about them, not about what is normal for the user.
 */
function buildCountryChangeDetection({ successRows, windowStart }) {
  const start = toDate(windowStart);
  const byUser = new Map();

  for (const r of Array.isArray(successRows) ? successRows : []) {
    const at = toDate(r.bucket_hour);
    // ⛔ NORMALISE. Palo Alto emits ISO alpha-2 ("TH") and FortiOS emits the full
      // English name ("Thailand"), and vpnAuthStats.js exists partly to fold them
      // together — its own comment says a GROUP BY on the raw value "splits one
      // country in half". These builders were reading the raw column, which does the
      // opposite and far worse: it JOINS one country into two, so a single employee
      // authenticating through a FortiGate and a Palo Alto gateway produced a
      // high-severity "authenticated from both TH and Thailand in the same hour"
      // — same country, same source IP, same hour, naming a real person.
      // Latent only because no username currently appears in both vendors’ success
      // rows; one shared account is all it takes.
      const country = normalizeCountry(r.src_country) || null;
    if (!at || !country || !r.username) continue;
    if (start && at.getTime() < start.getTime()) continue;
    const list = byUser.get(r.username) || [];
    list.push({ at, country, srcIp: r.src_ip || null, device: r.device_name || null });
    byUser.set(r.username, list);
  }

  const findings = [];
  for (const [username, list] of byUser) {
    list.sort((a, b) => a.at - b.at || a.country.localeCompare(b.country));
    let worst = null;
    for (let i = 1; i < list.length; i += 1) {
      const prev = list[i - 1];
      const cur = list[i];
      if (prev.country === cur.country) continue;
      const gapHours = Math.round((cur.at.getTime() - prev.at.getTime()) / MS_PER_HOUR);
      if (gapHours > COUNTRY_CHANGE_MAX_GAP_HOURS) continue;
      if (!worst || gapHours < worst.gapHours) {
        worst = { gapHours, from: prev, to: cur };
      }
    }
    if (!worst) continue;
    findings.push({
      kind: 'country_change',
      username,
      gapHours: worst.gapHours,
      fromCountry: worst.from.country,
      toCountry: worst.to.country,
      fromSrcIp: worst.from.srcIp,
      toSrcIp: worst.to.srcIp,
      fromAt: worst.from.at,
      toAt: worst.to.at,
      device: worst.to.device || worst.from.device || null,
      countries: [...new Set(list.map((x) => x.country))].sort(),
      // The whole in-window timeline, so an operator can disagree with the pair
      // that was picked.
      timeline: list.map((x) => ({ at: x.at, country: x.country, srcIp: x.srcIp })),
      severity: countryChangeSeverity(worst.gapHours),
      // ⛔ A zero gap means BOTH observations fell in the SAME hourly
      // bucket, so their order is unknown and the sentence must not imply
      // one. Saying "and then" about two timestamps that are equal is a
      // precision the rollup does not have.
      evidence:
        worst.gapHours === 0
          ? `"${username}" authenticated successfully from both ${worst.from.country} and `
            + `${worst.to.country} within the same hourly bucket`
          : `"${username}" authenticated successfully from ${worst.from.country} and then from `
            + `${worst.to.country} ${worst.gapHours}h later`,
    });
  }

  findings.sort((a, b) => a.gapHours - b.gapHours || a.username.localeCompare(b.username));

  return {
    id: 'country_change',
    title: 'Rapid country change',
    question: 'Did one account authenticate from two countries in quick succession?',
    method:
      `Two successful authentications for one username, from two different countries, at most `
      + `${COUNTRY_CHANGE_MAX_GAP_HOURS}h apart. Hourly buckets, so gaps are +/-1h.`,
    status: STATUS.MEASURED,
    baseline: null,
    findings,
    unverifiable: [],
    unverifiableTotal: 0,
    caveats: [
      'NOT an impossible-travel calculation. SecVault holds no city or coordinate data for any '
      + 'address, so no distance and no velocity is computed — only the country pair and the gap.',
      'The country is the firewall vendor\'s own geo-IP attribution. A commercial VPN, a proxy or a '
      + 'mobile carrier can legitimately change a user\'s apparent country without anyone travelling.',
    ],
  };
}

/**
 * Off-hours successful login.
 *
 * ⛔ "NORMAL HOURS" IS DERIVED FROM THE FLEET'S OWN OBSERVED DISTRIBUTION,
 * never from an assumption about office hours — which would be wrong for a
 * fleet spanning several countries and for anyone on shift work. That means it
 * needs a real profile: at least OFF_HOURS_MIN_BASELINE_DAYS days, so each
 * hour-of-day has been observed more than once or twice.
 *
 * ⛔ At the time of writing the fleet holds ~1 day, giving exactly ONE sample
 * per hour-of-day. This detection therefore reports `insufficient_baseline`
 * and NOT "no off-hours logins found". The second would be a fabricated
 * all-clear.
 */
function buildOffHoursDetection({ hourRows, successRows, baseline, windowStart }) {
  const verdict = baselineVerdict(baseline, OFF_HOURS_MIN_BASELINE_DAYS);
  // The REAL baseline length, not the number of days this hour happened to appear on.
  const spanDays = baseline && Number.isFinite(baseline.spanDays) ? baseline.spanDays : 0;
  const start = toDate(windowStart);

  // Mean successful-auth events per hour-of-day across the baseline.
  const perHour = new Map();
  for (const r of Array.isArray(hourRows) ? hourRows : []) {
    const h = Number(r.hour_utc);
    if (!Number.isInteger(h) || h < 0 || h > 23) continue;
    const at = toDate(r.bucket_hour);
    const slot = perHour.get(h) || { hour: h, events: 0, days: new Set() };
    slot.events += num(r.success_events);
    if (at) slot.days.add(at.toISOString().slice(0, 10));
    perHour.set(h, slot);
  }

  const profile = [...perHour.values()].map((s) => ({
    hour: s.hour,
    events: s.events,
    days: s.days.size,
    // ⛔ DIVIDE BY THE BASELINE LENGTH, NOT THE DAYS THIS HOUR HAPPENED TO APPEAR.
      // `s.days` only counts days on which this hour-of-day had a bucket row, so a
      // rare hour was divided by a tiny denominator and scored as BUSY — and an hour
      // with no successful login anywhere in the baseline has no row at all, so the
      // quietest hour possible could never be reported quiet. Both errors point the
      // same way: a false all-clear, which is what this detection exists to avoid.
      meanPerDay: spanDays > 0 ? s.events / spanDays : null,
      // Kept so a reader can see how much of the baseline this hour was present for.
      observedDays: s.days.size,
  }));
  const busiest = profile.reduce((m, p) => Math.max(m, p.meanPerDay || 0), 0);
  const quietHours = new Set(
    busiest > 0
      ? profile.filter((p) => p.meanPerDay !== null && p.meanPerDay <= busiest * OFF_HOURS_QUIET_SHARE).map((p) => p.hour)
      : []
  );

  const findings = [];
  const unverifiable = [];
  const byUserHour = new Map();
  for (const r of Array.isArray(successRows) ? successRows : []) {
    const at = toDate(r.bucket_hour);
    if (!at || !r.username) continue;
    if (start && at.getTime() < start.getTime()) continue;
    const hour = at.getUTCHours();
    const key = `${r.username}\u0000${hour}`;
    const e = byUserHour.get(key) || {
      kind: 'off_hours_success',
      username: r.username,
      hourUtc: hour,
      buckets: new Set(),
      countries: new Set(),
      devices: new Set(),
    };
    e.buckets.add(at.toISOString());
    if (r.src_country) e.countries.add(r.src_country);
    if (r.device_name) e.devices.add(r.device_name);
    byUserHour.set(key, e);
  }

  for (const e of byUserHour.values()) {
    const item = {
      kind: e.kind,
      username: e.username,
      hourUtc: e.hourUtc,
      authHours: e.buckets.size,
      countries: [...e.countries],
      devices: [...e.devices],
      severity: 'low',
      evidence: `"${e.username}" authenticated successfully at ${String(e.hourUtc).padStart(2, '0')}:00 UTC`,
    };
    if (!verdict.satisfied) {
      // ⛔ Not a finding and not silence: the fleet has no hour-of-day profile,
      // so no hour can be called unusual for anybody.
      unverifiable.push({ ...item, reason: 'no-hour-profile' });
      continue;
    }
    if (!quietHours.has(e.hourUtc)) continue;
    findings.push(item);
  }

  findings.sort((a, b) => b.authHours - a.authHours || a.username.localeCompare(b.username));
  // Nothing useful to show one-by-one when the whole detection is ungrounded —
  // the COUNT is the honest statement, so the list is capped by the caller.
  unverifiable.sort((a, b) => b.authHours - a.authHours || a.username.localeCompare(b.username));

  const caveats = [];
  if (!verdict.satisfied) {
    caveats.push(
      `"Normal hours" is measured from the fleet's own successful-login distribution and needs at `
      + `least ${OFF_HOURS_MIN_BASELINE_DAYS} days; SecVault holds ${verdict.have}. No hour is `
      + 'called unusual until then — assuming office hours would be an invented baseline.'
    );
  }
  caveats.push('Hour of day is UTC, matching every other timestamp this app renders.');

  return {
    id: 'off_hours_success',
    title: 'Successful login at an unusual hour',
    question: 'Did anyone log in successfully at an hour this fleet is normally quiet?',
    method:
      `An hour-of-day whose mean successful-login volume is at or below ${Math.round(OFF_HOURS_QUIET_SHARE * 100)}% `
      + 'of the busiest hour, measured over the baseline. Never an assumed office-hours window.',
    status: !baseline.hasHistory
      ? STATUS.NO_DATA
      : verdict.satisfied ? STATUS.MEASURED : STATUS.INSUFFICIENT,
    baseline: verdict,
    profile: verdict.satisfied ? profile.sort((a, b) => a.hour - b.hour) : [],
    quietHours: [...quietHours].sort((a, b) => a - b),
    findings,
    ...capUnverifiable(unverifiable),
    caveats,
  };
}

// ── SQL ──────────────────────────────────────────────────────────────────
//
// ⛔ Every one of these reads the ROLLUP, is parameterised, and casts its
// timestamp parameter explicitly (`$1::timestamptz`) — without the cast
// PostgreSQL raises "could not determine data type of parameter $N".

// How much VPN auth evidence exists AT ALL. Deliberately unwindowed: the whole
// question "is the baseline thin" cannot be answered from inside the window.
const HISTORY_SQL = `
  SELECT min(bucket_hour)                                   AS first_bucket_at,
         max(bucket_hour)                                   AS last_bucket_at,
         count(DISTINCT bucket_hour)::int                   AS history_hours,
         count(DISTINCT date_trunc('day', bucket_hour))::int AS history_days,
         count(*) FILTER (WHERE usernames_truncated)::int    AS truncated_rows
    FROM syslog_vpn_auth_hourly`;

// Per-device success/failure coverage in the window — the input to rule 4 at
// the top of this file. NOTHING is unnested here, so event_count is summed
// exactly once per rollup row (the 8.2x failure-inflation bug vpnAuthStats.js
// documents came from summing under an unnest).
const COVERAGE_SQL = `
  SELECT a.device_id,
         d.name                                                    AS device_name,
         a.vendor                                                  AS vendor,
         coalesce(sum(a.event_count) FILTER (WHERE a.auth_outcome = 'success'), 0)::bigint AS success_events,
         count(DISTINCT a.bucket_hour) FILTER (WHERE a.auth_outcome = 'success')::int      AS success_hours,
         coalesce(sum(a.event_count) FILTER (WHERE a.auth_outcome = 'failure'), 0)::bigint AS failure_events,
         count(DISTINCT a.bucket_hour)::int                        AS hours
    FROM syslog_vpn_auth_hourly a
    LEFT JOIN devices d ON d.id = a.device_id
   WHERE a.bucket_hour >= $1::timestamptz
   GROUP BY a.device_id, d.name, a.vendor`;

// Which devices reported each failing source, so a per-source success claim
// can be gated on ALL of them. 1,183 of ~1,840 addresses on this fleet were
// seen by more than one device, which is why this cannot be read off the
// single `vendor` field getVpnLoginLocations() carries per source.
const SOURCE_ATTRIBUTION_SQL = `
  SELECT host(a.src_ip)                                                   AS src_ip,
         array_agg(DISTINCT a.device_id) FILTER (WHERE a.device_id IS NOT NULL) AS device_ids,
         array_agg(DISTINCT d.name)      FILTER (WHERE d.name IS NOT NULL)      AS device_names,
         array_agg(DISTINCT a.vendor)    FILTER (WHERE a.vendor IS NOT NULL)    AS vendors,
         bool_or(a.device_id IS NULL)                                     AS unattributed,
         count(DISTINCT a.bucket_hour)::int                               AS hours
    FROM syslog_vpn_auth_hourly a
    LEFT JOIN devices d ON d.id = a.device_id
   WHERE a.bucket_hour >= $1::timestamptz
     AND a.auth_outcome = 'failure'
     AND a.src_ip IS NOT NULL
   GROUP BY host(a.src_ip)`;

// ⛔ THE UNNEST IS ALLOWED HERE ONLY BECAUSE OF THE CASE EXPRESSION.
// `event_count` covers every username in its bucket with no split, so
// attributing it to each unnested username would multiply the fleet's failure
// volume by the username breadth — the exact 8.2x bug vpnAuthStats.js
// documents. A bucket naming exactly ONE username can be attributed in full;
// any other bucket contributes 1, making the result a FLOOR by construction.
const BRUTE_FORCE_SQL = `
  SELECT u                                                          AS username,
         host(a.src_ip)                                             AS src_ip,
         min(a.src_country)                                         AS src_country,
         sum(CASE WHEN array_length(a.usernames, 1) = 1 THEN a.event_count ELSE 1 END)::bigint AS attempts_floor,
         bool_or(array_length(a.usernames, 1) > 1)                  AS shared_buckets,
         bool_or(a.usernames_truncated)                             AS usernames_truncated,
         bool_or(a.device_id IS NULL)                               AS unattributed,
         count(DISTINCT a.bucket_hour)::int                         AS hours,
         min(a.bucket_hour)                                         AS first_seen_at,
         max(a.bucket_hour)                                         AS last_seen_at,
         array_agg(DISTINCT a.device_id) FILTER (WHERE a.device_id IS NOT NULL) AS device_ids,
         array_agg(DISTINCT d.name)      FILTER (WHERE d.name IS NOT NULL)      AS device_names
    FROM syslog_vpn_auth_hourly a
    LEFT JOIN devices d ON d.id = a.device_id
    CROSS JOIN LATERAL unnest(coalesce(a.usernames, ARRAY[]::text[])) AS u
   WHERE a.bucket_hour >= $1::timestamptz
     AND a.auth_outcome = 'failure'
     AND a.src_ip IS NOT NULL
   GROUP BY u, host(a.src_ip)
  HAVING sum(CASE WHEN array_length(a.usernames, 1) = 1 THEN a.event_count ELSE 1 END) >= $2::bigint`;

// How many DISTINCT usernames each source attacked — context for a brute-force
// finding, so a focused attacker can be told from a sprayer that happened to
// hit one name hardest.
const SOURCE_BREADTH_SQL = `
  SELECT host(a.src_ip)          AS src_ip,
         count(DISTINCT u)::int  AS source_username_breadth
    FROM syslog_vpn_auth_hourly a
    CROSS JOIN LATERAL unnest(coalesce(a.usernames, ARRAY[]::text[])) AS u
   WHERE a.bucket_hour >= $1::timestamptz
     AND a.auth_outcome = 'failure'
     AND a.src_ip IS NOT NULL
   GROUP BY host(a.src_ip)`;

// Same floor construction as BRUTE_FORCE_SQL, aggregated the other way round.
const TARGETED_SQL = `
  SELECT u                                     AS username,
         count(DISTINCT a.src_ip)::int         AS sources,
         count(DISTINCT a.src_country)::int    AS countries,
         sum(CASE WHEN array_length(a.usernames, 1) = 1 THEN a.event_count ELSE 1 END)::bigint AS attempts_floor,
         bool_or(a.usernames_truncated)        AS usernames_truncated,
         count(DISTINCT a.bucket_hour)::int    AS hours,
         max(a.last_seen_at)                   AS last_seen_at
    FROM syslog_vpn_auth_hourly a
    CROSS JOIN LATERAL unnest(coalesce(a.usernames, ARRAY[]::text[])) AS u
   WHERE a.bucket_hour >= $1::timestamptz
     AND a.auth_outcome = 'failure'
   GROUP BY u
  HAVING count(DISTINCT a.src_ip) >= $2::int`;

// Every SUCCESSFUL authentication over the baseline, one row per username.
// ⛔ Nothing is SUMMED under this unnest, only listed — the fan-out is
// harmless for a set and fatal for a count.
const SUCCESS_ROWS_SQL = `
  SELECT u                    AS username,
         a.bucket_hour        AS bucket_hour,
         a.src_country        AS src_country,
         host(a.src_ip)       AS src_ip,
         a.device_id          AS device_id,
         d.name               AS device_name,
         a.usernames_truncated AS usernames_truncated
    FROM syslog_vpn_auth_hourly a
    LEFT JOIN devices d ON d.id = a.device_id
    CROSS JOIN LATERAL unnest(coalesce(a.usernames, ARRAY[]::text[])) AS u
   WHERE a.bucket_hour >= $1::timestamptz
     AND a.auth_outcome = 'success'`;

// Successful-auth volume per hour bucket, UN-fanned, for the hour-of-day
// profile. This is the one place a real event SUM is wanted, so no unnest.
const HOUR_PROFILE_SQL = `
  SELECT a.bucket_hour                                                AS bucket_hour,
         extract(hour FROM a.bucket_hour AT TIME ZONE 'UTC')::int      AS hour_utc,
         sum(a.event_count)::bigint                                   AS success_events
    FROM syslog_vpn_auth_hourly a
   WHERE a.bucket_hour >= $1::timestamptz
     AND a.auth_outcome = 'success'
   GROUP BY a.bucket_hour`;

// ── Orchestrator ─────────────────────────────────────────────────────────

/**
 * Every VPN detection, with its evidence and its baseline verdict.
 *
 * @param {import('pg').Pool} pool
 * @param {{hours?: number, baselineDays?: number, now?: Date}} [opts]
 * @returns {Promise<object>} see the shape assembled at the bottom of this fn
 */
async function getVpnDetections(pool, opts = {}) {
  const hours = clampInt(opts.hours, DEFAULT_WINDOW_HOURS, 1, MAX_WINDOW_HOURS);
  const baselineDays = clampInt(opts.baselineDays, DEFAULT_BASELINE_DAYS, 1, MAX_BASELINE_DAYS);
  const now = toDate(opts.now) || new Date();
  const windowStart = windowStartFrom(now, hours);
  const baselineStart = new Date(now.getTime() - baselineDays * MS_PER_DAY);
  const ws = windowStart.toISOString();
  const bs = baselineStart.toISOString();

  const [history, coverage, attribution, breadth, brute, targeted, successRows, hourRows, locations] =
    await Promise.all([
      pool.query(HISTORY_SQL),
      pool.query(COVERAGE_SQL, [ws]),
      pool.query(SOURCE_ATTRIBUTION_SQL, [ws]),
      pool.query(SOURCE_BREADTH_SQL, [ws]),
      pool.query(BRUTE_FORCE_SQL, [ws, MIN_BRUTE_FORCE_ATTEMPTS]),
      pool.query(TARGETED_SQL, [ws, MIN_TARGETED_SOURCES]),
      pool.query(SUCCESS_ROWS_SQL, [bs]),
      pool.query(HOUR_PROFILE_SQL, [bs]),
      // ⛔ REUSED, not reimplemented. This is the same read the Login Locations
      // tab performs, and findUsernameSprayers() below is its rule unchanged.
      getVpnLoginLocations(pool, hours),
    ]);

  const baseline = summariseBaseline(history.rows[0], now);

  const devices = coverage.rows.map(classifyDeviceSuccessBaseline);
  const baselineByDevice = new Map();
  for (const d of devices) if (d.deviceId) baselineByDevice.set(d.deviceId, d);
  // ⛔ `deviceId` required: a coverage row with no device_id is an UNMATCHED
  // SENDER (syslog from an address SecVault does not manage), not a firewall
  // with a logging gap. Listing it as a device with a reporting problem would
  // name a device that does not exist. Its failures are still counted, and the
  // per-source `unattributed` flag is what stops a claim resting on them.
  const reportingGapDevices = devices.filter(
    (d) => d.deviceId && d.successBaseline === 'none'
  );
  const unattributedCoverage = devices.filter((d) => !d.deviceId);

  const attributionBySource = new Map();
  for (const r of attribution.rows) {
    attributionBySource.set(r.src_ip, {
      deviceIds: r.device_ids || [],
      deviceNames: r.device_names || [],
      vendors: r.vendors || [],
      unattributed: Boolean(r.unattributed),
      hours: num(r.hours),
    });
  }

  const breadthBySource = new Map();
  for (const r of breadth.rows) breadthBySource.set(r.src_ip, num(r.source_username_breadth));
  const bruteRows = brute.rows.map((r) => ({
    ...r,
    source_username_breadth: breadthBySource.has(r.src_ip) ? breadthBySource.get(r.src_ip) : null,
  }));

  const detections = [
    buildSprayDetection({
      sources: locations.sources,
      attributionBySource,
      baselineByDevice,
      windowHours: hours,
    }),
    buildBruteForceDetection({ rows: bruteRows, baselineByDevice, windowHours: hours }),
    buildTargetedAccountDetection({ rows: targeted.rows, windowHours: hours }),
    buildNewCountryDetection({ successRows: successRows.rows, baseline, windowStart }),
    buildCountryChangeDetection({ successRows: successRows.rows, windowStart }),
    buildOffHoursDetection({ hourRows: hourRows.rows, successRows: successRows.rows, baseline, windowStart }),
  ];

  return {
    windowHours: hours,
    baselineDays,
    windowStart,
    generatedAt: now,
    baseline,
    coverage: {
      devices: devices.sort((a, b) =>
        String(a.deviceName || '').localeCompare(String(b.deviceName || ''))),
      // ⛔ Named, not counted. "FortiGate cannot tell us" beats an anonymous
      // shrug: the operator then knows exactly which device-side logging
      // setting would close the gap.
      reportingGapDevices,
      // Syslog whose sender matched no device. Never folded into the fleet
      // above and never presented as a firewall.
      unattributedCoverage,
      totalFailures: num(locations.totals && locations.totals.failure),
      totalSuccesses: num(locations.totals && locations.totals.success),
      sourcesSeen: Array.isArray(locations.sources) ? locations.sources.length : 0,
    },
    detections,
  };
}

module.exports = {
  getVpnDetections,
  // Pure builders + helpers, exported for tests/vpnDetections.test.js.
  buildSprayDetection,
  buildBruteForceDetection,
  buildTargetedAccountDetection,
  buildNewCountryDetection,
  buildCountryChangeDetection,
  buildOffHoursDetection,
  classifyDeviceSuccessBaseline,
  successClaimSupport,
  summariseBaseline,
  baselineVerdict,
  spraySeverity,
  bruteForceSeverity,
  targetedSeverity,
  countryChangeSeverity,
  windowStartFrom,
  DETECTION_IDS,
  STATUS,
  DEFAULT_WINDOW_HOURS,
  MAX_WINDOW_HOURS,
  DEFAULT_BASELINE_DAYS,
  MIN_BRUTE_FORCE_ATTEMPTS,
  MIN_TARGETED_SOURCES,
  NEW_COUNTRY_MIN_BASELINE_DAYS,
  NEW_COUNTRY_MIN_USER_DAYS,
  COUNTRY_CHANGE_MAX_GAP_HOURS,
  OFF_HOURS_MIN_BASELINE_DAYS,
  OFF_HOURS_QUIET_SHARE,
};
