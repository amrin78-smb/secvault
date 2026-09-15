// lib/engines/cloudApps.js
//
// Names an address or hostname against the published cloud catalogue: "this is
// Microsoft Teams", "this is inside AWS". Pure — takes catalogue rows in and
// returns a verdict. The fetching lives in lib/feeds/cloudApps.js.
//
// ⛔ WHY THIS EXISTS. Measured on the reference fleet: 510 distinct FQDN
// address objects sit in the rulebase, and 102 rules reference them. Today they
// are opaque strings, which is why flows touching them come back unverified and
// why the unaccounted-rule list is a wall rather than something readable. The
// catalogue turns a third of them into names.
//
// ⛔ THE THREE RULES THAT MAKE THIS HONEST RATHER THAN DECORATIVE:
//
// 1. AN EMPTY CATALOGUE IS "UNKNOWN", NEVER "NOT A CLOUD APP". This product
//    installs on segmented and air-gapped networks — that is its target
//    customer, not an edge case — where these feeds cannot be fetched at all.
//    A lookup with nothing to look in must say it could not answer. Reporting
//    "not a cloud app" there is the failed-read-as-a-fact bug in its most
//    plausible form, because the output looks like a real negative.
//
// 2. A PROVIDER IS NOT AN APPLICATION. An address inside AWS's ranges is AWS.
//    It is NOT Salesforce, or any other thing a customer happens to run on AWS.
//    Where a feed publishes no service breakdown, `service` stays null and the
//    label says only what was published.
//
// 3. THE FEED'S GRANULARITY IS OUR GRANULARITY. Microsoft publishes four
//    service areas, and 131 of the 152 live matches land in its catch-all
//    "Microsoft 365 Common and Office Online". We can say Teams. We cannot say
//    Word, and must not imply it.

'use strict';

// ⛔ The CIDR parser is BORROWED from applicationView.js, not rewritten. Two
// implementations of IPv4 range arithmetic in one codebase is how they drift,
// and the one that drifts is the one making a claim about a firewall rule.
const { parseCidr } = require('./applicationView');

const STATES = {
  MATCHED: 'matched',
  NO_MATCH: 'no_match',
  UNAVAILABLE: 'unavailable',
};

// How old the catalogue may be before a reader should be told. Not an expiry:
// ⛔ a stale catalogue is STALE, not WRONG. Published ranges change slowly, and
// refusing to answer from a two-week-old copy would be worse than answering
// with its age attached.
const STALE_AFTER_DAYS = 14;

const PROVIDER_LABEL = {
  microsoft_365: 'Microsoft 365',
  aws: 'AWS',
  google_cloud: 'Google Cloud',
  cloudflare: 'Cloudflare',
};

function providerLabel(provider) {
  // ⛔ An unknown provider prints its own raw key rather than a friendly guess.
  // A feed added later must show up as itself, not as blank or as "Other".
  return PROVIDER_LABEL[provider] || provider || 'Unknown provider';
}

// ── Hostnames ──────────────────────────────────────────────────────────────

function normaliseHost(h) {
  if (typeof h !== 'string') return null;
  const s = h.trim().toLowerCase().replace(/\.$/, '');
  return s || null;
}

/**
 * Does a catalogue pattern cover this host?
 *
 * ⛔ A WILDCARD MATCHES SUBDOMAINS ONLY, NEVER THE APEX. `*.office.com` does
 * not name `office.com` here. That is how firewalls themselves generally treat
 * the form, and it is the safe direction for a NAMING feature: under-claiming
 * leaves something unlabelled, which is visible and harmless, while
 * over-claiming puts a confident wrong name on a rule. Microsoft lists an apex
 * separately when it means it.
 */
function hostMatches(pattern, host) {
  const p = normaliseHost(pattern);
  const h = normaliseHost(host);
  if (!p || !h) return false;
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // '.office.com'
    return h.endsWith(suffix) && h.length > suffix.length;
  }
  return h === p;
}

/**
 * How specific a host pattern is, for choosing between two matches.
 * An exact name always beats a wildcard; among wildcards, more labels wins.
 */
function hostSpecificity(pattern) {
  const p = normaliseHost(pattern) || '';
  const labels = p.split('.').filter(Boolean).length;
  return p.startsWith('*.') ? labels : labels + 100;
}

// ── Addresses ──────────────────────────────────────────────────────────────

function ipToUint32(ip) {
  const r = parseCidr(ip);
  // parseCidr treats a bare address as a /32. Anything wider is not a single
  // address and is refused rather than silently taking the network address.
  if (!r || r.start !== r.end) return null;
  return r.start;
}

/** A catalogue CIDR to inclusive bounds. Returns null for anything unparseable. */
function cidrBounds(cidr) {
  const r = parseCidr(cidr);
  if (!r) return null;
  return { start: r.start, end: r.end };
}

// ── Matching ───────────────────────────────────────────────────────────────

function unavailable(reason) {
  return {
    state: STATES.UNAVAILABLE,
    reason,
    provider: null,
    service: null,
    label: null,
    // ⛔ Present and explicitly null so a caller destructuring this cannot
    // accidentally read a missing key as false.
    ambiguous: null,
  };
}

function noMatch() {
  return {
    state: STATES.NO_MATCH, reason: null, provider: null, service: null, label: null, ambiguous: false,
  };
}

function matched(entry, alternatives) {
  const service = entry.service_display || entry.service || null;
  return {
    state: STATES.MATCHED,
    provider: entry.provider,
    providerLabel: providerLabel(entry.provider),
    service,
    // ⛔ The label says exactly what was published and no more. With no service
    // breakdown it is the provider alone, which is the honest answer.
    label: service ? `${providerLabel(entry.provider)} — ${service}` : providerLabel(entry.provider),
    value: entry.value,
    category: entry.category || null,
    sourceVersion: entry.source_version || null,
    // ⛔ AMBIGUITY IS REPORTED, NOT RESOLVED SILENTLY. Two providers can
    // legitimately publish overlapping space (a SaaS fronted by Cloudflare, a
    // service inside a hyperscaler range). Picking one and hiding the other
    // would make a coincidence look like a fact.
    ambiguous: alternatives.length > 0,
    alternatives: alternatives.map((a) => ({
      provider: a.provider,
      providerLabel: providerLabel(a.provider),
      service: a.service_display || a.service || null,
      value: a.value,
    })),
    reason: null,
  };
}

/**
 * @param {string} host
 * @param {object[]|null} entries catalogue rows with kind='host'
 * @param {{count?:number}} [meta] total catalogue size, to tell "empty" from "no match"
 */
function matchHost(host, entries, meta = {}) {
  if (!Array.isArray(entries) || entries.length === 0) {
    return unavailable(
      Number(meta.count) > 0
        ? 'No hostname entries in the catalogue.'
        : 'The cloud catalogue is empty — the published feeds have not been fetched on this install.'
    );
  }
  const h = normaliseHost(host);
  if (!h) return noMatch();

  let best = null;
  let bestScore = -1;
  const ties = [];
  for (const e of entries) {
    if (!hostMatches(e.value, h)) continue;
    const score = hostSpecificity(e.value);
    if (score > bestScore) { bestScore = score; best = e; ties.length = 0; }
    else if (score === bestScore && best && e.provider !== best.provider) ties.push(e);
  }
  if (!best) return noMatch();
  return matched(best, ties);
}

/**
 * @param {string} ip a single IPv4 address
 * @param {object[]|null} entries catalogue rows with kind='ip' and numeric bounds
 */
function matchIp(ip, entries, meta = {}) {
  if (!Array.isArray(entries) || entries.length === 0) {
    return unavailable(
      Number(meta.count) > 0
        ? 'No address entries in the catalogue.'
        : 'The cloud catalogue is empty — the published feeds have not been fetched on this install.'
    );
  }
  const n = ipToUint32(ip);
  if (n === null) return noMatch();

  let best = null;
  let bestSize = Infinity;
  const ties = [];
  for (const e of entries) {
    // ⛔ Number() IS DELIBERATE, NOT DEFENSIVE NOISE. node-pg returns BIGINT as
    // a STRING ('50596868'), verified against the live database — comparing it
    // to a numeric address with < or > would compare lexically and silently
    // match the wrong ranges. An IPv4 address fits in a double exactly, so the
    // coercion is lossless here.
    const start = Number(e.range_start);
    const end = Number(e.range_end);
    if (!Number.isFinite(start) || !Number.isFinite(end)) continue;
    if (n < start || n > end) continue;
    const size = end - start;
    // ⛔ SMALLEST RANGE WINS. A /32 published for Teams beats the /8 the same
    // address also sits inside; the specific statement is the informative one.
    if (size < bestSize) { bestSize = size; best = e; ties.length = 0; }
    else if (size === bestSize && best && e.provider !== best.provider) ties.push(e);
  }
  if (!best) return noMatch();
  return matched(best, ties);
}

// ── Catalogue health ───────────────────────────────────────────────────────

/**
 * Is the catalogue usable, and how old is it?
 *
 * ⛔ THREE STATES, NOT TWO. `empty` is not a kind of `stale` and neither is a
 * kind of `ok`: an install that has never fetched is a different situation from
 * one whose copy is a month behind, and only the second can answer anything at
 * all. Collapsing them would tell an air-gapped operator their fleet uses no
 * cloud services.
 */
function catalogueStatus(summary, now = new Date()) {
  const count = Number(summary && summary.count) || 0;
  if (count === 0) {
    return {
      state: 'empty',
      count: 0,
      ageDays: null,
      usable: false,
      message: 'No cloud catalogue has been fetched on this install, so nothing can be named. '
        + 'That is expected on a network with no outbound access.',
    };
  }
  const last = summary && summary.lastSeenAt ? new Date(summary.lastSeenAt) : null;
  const ageDays = last && !Number.isNaN(last.getTime())
    ? Math.floor((now.getTime() - last.getTime()) / 86400000)
    : null;
  if (ageDays === null) {
    return {
      state: 'unknown_age',
      count,
      ageDays: null,
      usable: true,
      message: `${count.toLocaleString('en-US')} catalogue entries, but when they were last refreshed could not be read.`,
    };
  }
  if (ageDays > STALE_AFTER_DAYS) {
    return {
      state: 'stale',
      count,
      ageDays,
      // ⛔ STILL USABLE. Published ranges change slowly; refusing to name
      // anything from a copy two weeks old would be worse than saying its age.
      usable: true,
      message: `${count.toLocaleString('en-US')} catalogue entries, last refreshed ${ageDays} days ago. `
        + 'Names below may lag recent changes by the publishers.',
    };
  }
  return {
    state: 'ok',
    count,
    ageDays,
    usable: true,
    message: `${count.toLocaleString('en-US')} catalogue entries, refreshed ${ageDays === 0 ? 'today' : `${ageDays} day${ageDays === 1 ? '' : 's'} ago`}.`,
  };
}

/**
 * Group a set of matched hostnames into candidate applications, for the
 * "declare this?" suggestion.
 *
 * ⛔ A SUGGESTION IS A HYPOTHESIS AND MUST BE LABELLED ONE. This never creates
 * a declaration. An auto-created application is a declaration with nobody
 * behind it, which is worse than the stale-but-owned map the competing products
 * ship — at least someone once meant theirs. The operator accepts, or does not.
 */
function suggestApplications(matches) {
  const byKey = new Map();
  for (const m of matches || []) {
    if (!m || m.match.state !== STATES.MATCHED) continue;
    const key = `${m.match.provider}::${m.match.service || ''}`;
    if (!byKey.has(key)) {
      byKey.set(key, {
        provider: m.match.provider,
        providerLabel: m.match.providerLabel,
        service: m.match.service,
        label: m.match.label,
        hosts: [],
        deviceIds: new Set(),
      });
    }
    const g = byKey.get(key);
    g.hosts.push(m.host);
    if (m.deviceId) g.deviceIds.add(m.deviceId);
  }
  return [...byKey.values()]
    .map((g) => ({
      provider: g.provider,
      providerLabel: g.providerLabel,
      service: g.service,
      label: g.label,
      hostCount: new Set(g.hosts).size,
      hosts: [...new Set(g.hosts)].sort(),
      deviceCount: g.deviceIds.size,
      isSuggestion: true,
    }))
    .sort((a, b) => b.hostCount - a.hostCount);
}

module.exports = {
  STATES,
  STALE_AFTER_DAYS,
  PROVIDER_LABEL,
  providerLabel,
  normaliseHost,
  hostMatches,
  hostSpecificity,
  ipToUint32,
  cidrBounds,
  matchHost,
  matchIp,
  catalogueStatus,
  suggestApplications,
};
