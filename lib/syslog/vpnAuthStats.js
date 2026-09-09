// lib/syslog/vpnAuthStats.js
//
// Reads the VPN login-locations view off `syslog_vpn_auth_hourly`.
//
// ⛔ NEVER the raw table. The equivalent question against `syslog_events` was
// measured at 85.6 SECONDS over a 24h window: the log_class index finds the
// rows, but they are ~84k needles scattered across a 26 GB daily partition, so
// it costs 38,502 cold random reads. The index does not save you.

'use strict';

// PAN-OS writes RFC1918 RANGE STRINGS into the country field
// ("172.16.0.0-172.31.255.255"), and FortiOS writes "Reserved". Both are the
// VENDOR'S OWN answer and are stored verbatim on purpose — but neither is a
// country, and letting one top a "top countries" ranking would be nonsense.
const PRIVATE_COUNTRY_RE = /^\d{1,3}(\.\d{1,3}){3}\s*-/;

function isPrivateCountry(c) {
  if (typeof c !== 'string') return false;
  const v = c.trim().toLowerCase();
  return v === 'reserved' || v === 'private' || PRIVATE_COUNTRY_RE.test(c.trim());
}

// ⛔ THE TWO VENDORS NAME THE SAME COUNTRY DIFFERENTLY, and the first live run
// proved it: the ranked table showed
//     US            | failure | 22 | 18 sources
//     United States | failure | 22 | 14 sources
// as two separate countries. Palo Alto emits ISO-3166-1 alpha-2 ("US"),
// FortiOS emits the full English name ("United States"), so a GROUP BY on the
// raw value splits one country in half and under-states both.
//
// Normalised at READ time rather than with a stored column: this is a
// presentation concern, it needs no ALTER on a 28M-row/day table, and it
// applies retroactively to rows already collected.
//
// ⛔ An UNRECOGNISED code is returned VERBATIM, never dropped and never
// guessed at. A country missing from this map still ranks — it just keeps the
// vendor's own spelling, which is a visible prompt to extend the map rather
// than a silent omission.
const ISO_TO_NAME = {
  AU: 'Australia', BD: 'Bangladesh', BG: 'Bulgaria', BR: 'Brazil', CA: 'Canada',
  CH: 'Switzerland', CN: 'China', CZ: 'Czechia', DE: 'Germany', DK: 'Denmark',
  EE: 'Estonia', ES: 'Spain', FI: 'Finland', FR: 'France', GB: 'United Kingdom',
  HK: 'Hong Kong', ID: 'Indonesia', IE: 'Ireland', IN: 'India', IT: 'Italy',
  JP: 'Japan', KH: 'Cambodia', KR: 'South Korea', LA: 'Laos', MM: 'Myanmar',
  MY: 'Malaysia', NL: 'Netherlands', NO: 'Norway', NZ: 'New Zealand',
  PA: 'Panama', PH: 'Philippines', PL: 'Poland', PT: 'Portugal',
  RO: 'Romania', RU: 'Russian Federation', SE: 'Sweden', SG: 'Singapore',
  TH: 'Thailand', TR: 'Turkey', TW: 'Taiwan', UA: 'Ukraine',
  US: 'United States', VN: 'Vietnam', ZA: 'South Africa',
};

function normalizeCountry(c) {
  if (typeof c !== 'string') return null;
  const v = c.trim();
  if (v === '') return null;
  // Only a bare two-letter code is treated as ISO; anything longer is already
  // a name and is left exactly as the vendor wrote it.
  if (/^[A-Za-z]{2}$/.test(v)) return ISO_TO_NAME[v.toUpperCase()] || v.toUpperCase();
  return v;
}

function clampHours(h, def, max) {
  const n = Number(h);
  if (!Number.isFinite(n)) return def;
  return Math.min(Math.max(Math.trunc(n), 1), max);
}

/**
 * Per-country success/failure, plus the per-source detail the attack rules need.
 *
 * @returns {{countries, sources, totals, vendors, windowHours}}
 */
async function getVpnLoginLocations(pool, hours = 24) {
  const h = clampHours(hours, 24, 24 * 8);

  // ⛔ THE COUNTS AND THE USERNAME SET ARE AGGREGATED SEPARATELY, OVER THE SAME
  // FILTERED SET, AND THAT SEPARATION IS THE WHOLE CORRECTNESS STORY HERE.
  //
  // This used to be one query with `LEFT JOIN LATERAL unnest(usernames)` sitting
  // directly under `sum(event_count)`. The unnest fans each rollup row out to
  // one row PER USERNAME before the sum runs, so every bucket was counted once
  // for each distinct username it had seen. Measured on the live fleet over 24h:
  // the truth is 3,891 failures / 509 successes; the fanned-out query returned
  // 31,754 / 538 — failures inflated 8.2x, successes only 1.06x, because a
  // failure bucket carries many usernames and a success bucket carries one. The
  // worst single key carried 414 distinct usernames.
  //
  // The distortion is therefore NOT a uniform scaling that cancels out in a
  // ratio: it lands almost entirely on the FAILURE side, i.e. in the alarming
  // direction, and it reached the failed-logins tile, `totals`, every
  // per-country and per-source count, the mix bars and the spray ranking. A
  // security product inventing a brute-force volume that does not exist is the
  // most expensive thing this file can do.
  //
  // ⛔ The USERNAME side was always correct — it comes from the array union, and
  // a set does not care how many times it saw a member. Verified against
  // production after the fix: all 1,095 grouping keys returned identical
  // username sets, identical truncation flags and identical last-seen
  // timestamps; only the event sums moved. Do not "simplify" this back into one
  // GROUP BY.
  const { rows } = await pool.query(
    `WITH auth_rows AS (
        SELECT vendor,
               src_country,
               host(src_ip)  AS src_ip,
               auth_outcome,
               event_count,
               usernames,
               usernames_truncated,
               last_seen_at
          FROM syslog_vpn_auth_hourly
         WHERE bucket_hour >= date_trunc('hour', now()) - (($1::int - 1) * interval '1 hour')
     ),
     -- One row per grouping key. Nothing is fanned out here, so event_count is
     -- summed exactly once per rollup row.
     auth_counts AS (
        SELECT vendor, src_country, src_ip, auth_outcome,
               sum(event_count)::bigint     AS events,
               bool_or(usernames_truncated) AS usernames_truncated,
               max(last_seen_at)            AS last_seen_at
          FROM auth_rows
         GROUP BY vendor, src_country, src_ip, auth_outcome
     ),
     -- ⛔ The usernames SET, unioned across hours. A per-hour COUNT(DISTINCT)
     -- is NOT additive — summing 24 of them to answer "how many usernames did
     -- this address try today" over-counts badly, which is exactly what the
     -- spray rule turns on. This is the only place the unnest is allowed, and
     -- no count is computed inside it.
     auth_users AS (
        SELECT r.vendor, r.src_country, r.src_ip, r.auth_outcome,
               array_agg(DISTINCT u) AS usernames
          FROM auth_rows r
          CROSS JOIN LATERAL unnest(coalesce(r.usernames, ARRAY[]::text[])) AS u
         GROUP BY r.vendor, r.src_country, r.src_ip, r.auth_outcome
     )
     SELECT c.vendor, c.src_country, c.src_ip, c.auth_outcome, c.events,
            u.usernames, c.usernames_truncated, c.last_seen_at
       FROM auth_counts c
       -- ⛔ IS NOT DISTINCT FROM, not plain equality. vendor, src_country and
       -- src_ip are all honestly nullable (the rollup's own UNIQUE is NULLS NOT
       -- DISTINCT for the same reason), and an = join would drop an
       -- unattributed key's username set on the floor while keeping its counts.
       LEFT JOIN auth_users u
              ON u.vendor       IS NOT DISTINCT FROM c.vendor
             AND u.src_country  IS NOT DISTINCT FROM c.src_country
             AND u.src_ip       IS NOT DISTINCT FROM c.src_ip
             AND u.auth_outcome IS NOT DISTINCT FROM c.auth_outcome`,
    [h]
  );

  const byCountry = new Map();
  const bySource = new Map();
  const byVendor = new Map();
  const totals = { success: 0, failure: 0, privateSuccess: 0, privateFailure: 0 };

  for (const r of rows) {
    const events = Number(r.events);
    const outcome = r.auth_outcome;
    const users = Array.isArray(r.usernames) ? r.usernames : [];

    const vend = byVendor.get(r.vendor) || { vendor: r.vendor, success: 0, failure: 0 };
    vend[outcome] += events;
    byVendor.set(r.vendor, vend);

    // ⛔ Private-range pseudo-countries are bucketed separately and never
    // ranked. They are not a location.
    if (isPrivateCountry(r.src_country)) {
      totals[outcome === 'success' ? 'privateSuccess' : 'privateFailure'] += events;
    } else {
      const key = normalizeCountry(r.src_country) || '(not reported)';
      const c = byCountry.get(key) || {
        country: key,
        located: Boolean(r.src_country),
        success: 0,
        failure: 0,
        sources: new Set(),
        usernames: new Set(),
        // ⛔ WHICH VENDOR SAW WHAT, PER COUNTRY. Without this the "no successful
        // login from here" rule cannot be evaluated per vendor at all, because a
        // country row pre-aggregated across vendors has already lost the one
        // fact the rule turns on: whether the vendor that reported THESE
        // failures is a vendor whose successes we would have seen.
        vendorStats: new Map(),
      };
      c[outcome] += events;
      if (r.src_ip) c.sources.add(r.src_ip);
      for (const u of users) c.usernames.add(u);
      const cv = c.vendorStats.get(r.vendor) || { vendor: r.vendor, success: 0, failure: 0 };
      cv[outcome] += events;
      c.vendorStats.set(r.vendor, cv);
      byCountry.set(key, c);
      totals[outcome] += events;
    }

    if (r.src_ip) {
      const s = bySource.get(r.src_ip) || {
        srcIp: r.src_ip,
        country: normalizeCountry(r.src_country),
        vendor: r.vendor,
        success: 0,
        failure: 0,
        usernames: new Set(),
        usernamesTruncated: false,
        lastSeenAt: r.last_seen_at,
      };
      s[outcome] += events;
      for (const u of users) s.usernames.add(u);
      if (r.usernames_truncated) s.usernamesTruncated = true;
      bySource.set(r.src_ip, s);
    }
  }

  const countries = [...byCountry.values()]
    .map(({ vendorStats, ...c }) => ({
      ...c,
      sources: c.sources.size,
      usernames: c.usernames.size,
      total: c.success + c.failure,
      // The per-vendor split THIS country's numbers were built from — the input
      // findFailureOnlyCountries() gates on.
      vendors: [...vendorStats.values()],
    }))
    .sort((a, b) => b.total - a.total);

  const sources = [...bySource.values()]
    .map((s) => ({
      ...s,
      usernames: s.usernames.size,
      total: s.success + s.failure,
    }))
    .sort((a, b) => b.failure - a.failure || b.total - a.total);

  return {
    countries,
    sources,
    totals,
    vendors: [...byVendor.values()],
    windowHours: h,
  };
}

// ── The two attack rules ──────────────────────────────────────────────────
//
// ⛔ NO SCORE, NO SEVERITY BAND. Each rule is arithmetic the operator can read
// in one sentence, with the triggering numbers shown. CLAUDE.md bans exactly
// the kind of confident-but-unfounded escalation a composite score would be
// (see its rejected definition of `log_hit`).

const MIN_USERNAMES_FOR_SPRAY = 5;

/**
 * Rule A — one address, many usernames, no success.
 *
 * A legitimate user who mistypes a password generates many failures against
 * ONE username. The discriminator is the DISTINCT USERNAME count.
 */
function findUsernameSprayers(sources) {
  return sources.filter(
    (s) => s.failure > 0 && s.success === 0 && s.usernames >= MIN_USERNAMES_FOR_SPRAY
  );
}

/**
 * Rule B — a country from which no login has ever succeeded.
 *
 * ⛔ EVALUATED PER VENDOR, and ONLY for a vendor that has produced at least one
 * success in the window. "Zero successes from country X" is only a MEASUREMENT
 * if the vendor reports successes at all — and on this fleet Fortinet reports
 * essentially none (2,037 failures against ~4 successes over 12h, a device-side
 * logging setting). Applied naively to Fortinet data this rule would flag EVERY
 * country including Thailand, where the real users are. That is the
 * failed-read-as-a-fact error in its most dangerous form.
 *
 * ⛔ THAT PER-VENDOR GATE USED TO BE COMPUTED AND THEN NEVER READ. `vendorsWithSuccess`
 * was built, checked only for emptiness, and discarded — so ONE Palo Alto success
 * anywhere on the fleet switched the rule on for FORTINET's countries too, which is
 * precisely the case the paragraph above exists to forbid. It is now applied per
 * country, against the per-vendor split `getVpnLoginLocations()` carries on each
 * country row.
 *
 * The question asked of each country is: for every vendor that reported a FAILURE
 * from here, would that vendor's success have been visible to us? Only then does
 * "and it reported none" mean anything. If any one of them has no success baseline
 * at all, the country is NOT asserted — it goes to `caveated`, to be rendered as
 * an unmeasured absence rather than as the claim "no successful login has been
 * observed from here".
 *
 * ⛔ EVERY, not SOME. If Palo Alto (which reports successes) and Fortinet (which
 * does not) both report failures from one country, the country is still not
 * assertable: Fortinet could have let a login through and never told us.
 *
 * @returns {{rows, caveated, evaluable}}
 *   rows      — countries where the claim is a real measurement
 *   caveated  — countries that LOOK failure-only but have no success baseline
 *   evaluable — did ANY vendor report a success in the window (fleet-wide; this
 *               is the `successMeasurable` question, unchanged)
 */
function findFailureOnlyCountries(countries, vendors) {
  const vendorsWithSuccess = new Set(
    (vendors || []).filter((v) => v.success > 0).map((v) => v.vendor)
  );
  const evaluable = vendorsWithSuccess.size > 0;

  const rows = [];
  const caveated = [];
  for (const c of (countries || [])) {
    if (!c.located || !(c.failure > 0) || c.success !== 0) continue;
    // A caller that does not attribute a country's failures to a vendor at all
    // (no `vendors` array) can only be judged by the fleet-wide gate — the
    // pre-2026-09-09 behaviour, kept so an unattributed input is never treated
    // as MORE assertable than it used to be. Every production caller attributes.
    const attributed = Array.isArray(c.vendors) ? c.vendors.filter((v) => v.failure > 0) : null;
    const gated =
      attributed === null
        ? evaluable
        : attributed.length > 0 && attributed.every((v) => vendorsWithSuccess.has(v.vendor));
    if (gated) {
      rows.push(c);
      continue;
    }
    // WHICH vendors leave this country unmeasurable, named — so the UI can say
    // "FortiGate cannot tell us" instead of an anonymous shrug, and so the
    // operator knows exactly which device-side logging setting would fix it.
    caveated.push({
      ...c,
      unmeasuredVendors: (attributed || [])
        .filter((v) => !vendorsWithSuccess.has(v.vendor))
        .map((v) => v.vendor),
    });
  }
  return { rows, caveated, evaluable };
}

module.exports = {
  getVpnLoginLocations,
  normalizeCountry,
  findUsernameSprayers,
  findFailureOnlyCountries,
  isPrivateCountry,
  MIN_USERNAMES_FOR_SPRAY,
};
