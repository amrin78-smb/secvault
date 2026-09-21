'use strict';
//
// lib/syslog/applications.js
//
// THE single source of truth for "what does this application string and this
// URL-category string actually MEAN", as firewalls spell them.
//
// ⛔ IT SITS BESIDE actions.js FOR THE SAME REASON THAT FILE EXISTS. Its own
// header records what four private copies of a deny list cost: the narrowest
// under-counted blocks by 6.8% fleet-wide and by 24% on URL-category rows. The
// judgements below are the same KIND of thing - a claim about vendor vocabulary
// read off captured logs - and the first draft of them was written inside a PDF
// report, where the dashboard could never have shared it and the two would have
// drifted the first time either was corrected.
//
// ⛔ EVERY ENTRY WAS READ OFF LIVE ROLLUPS ON THE REFERENCE FLEET, not from
// vendor documentation, per CLAUDE.md's "documentation lies" rule.

// ⛔ THESE ARE NOT CATEGORIES. Each one is the firewall reporting that it did
// NOT classify the destination, and letting them rank in a "top categories"
// chart would put "we didn't look" at the top of a list of what staff browse.
// `license-expired` is the sharpest case: it is a LAPSED SUBSCRIPTION, an
// operational finding worth acting on, and filing it as a browsing category
// would hide a firewall that has stopped classifying anything at all.
const UNCLASSIFIED_URL_CATEGORIES = new Map([
  ['any', 'the matching rule applied no URL category'],
  ['unscanned', 'the web filter did not inspect these sessions'],
  ['license-expired', 'the URL-filtering subscription on this firewall has lapsed'],
  ['not-resolved', 'the firewall could not resolve a category in time'],
  ['unknown', 'the firewall returned no category'],
]);
const isUnclassifiedCategory = (c) => UNCLASSIFIED_URL_CATEGORIES.has(String(c || '').toLowerCase());

// ⛔ THESE ARE NOT APPLICATIONS EITHER, AND THE SAME SPLIT APPLIES FOR THE
// SAME REASON. Every value here is the firewall naming a TRANSPORT or declaring
// that it could NOT identify what was inside. Measured on this fleet over 24h,
// they are the top of the table by volume by an order of magnitude - `ssl` alone
// is 869 GB against YouTube's 4.2 GB - so a single ranked chart answers "which
// applications use the most bandwidth" with "encrypted traffic we did not
// identify", three times, before naming anything a person would recognise.
//
// ⛔ THE CRITERION IS THE VENDOR'S OWN MEANING, NOT OUR INTEREST. Each entry
// is a value whose definition is "not identified" (`unknown-tcp`, `incomplete`,
// `insufficient-data`) or a bare transport (`ssl`, `quic-base`, `HTTPS`,
// `tcp/8443`). A real application is NEVER moved here because it looked dull -
// that would be a report editing its own evidence. And nothing is dropped: the
// bucket is returned with its total and its members, and the caller prints
// both, exactly as the URL categories above do.
const UNATTRIBUTED_APPLICATIONS = new Set([
  'ssl', 'quic-base', 'quic', 'web-browsing', 'unknown-tcp', 'unknown-udp',
  'unknown-p2p', 'incomplete', 'insufficient-data', 'not-applicable', 'unknown',
  'https', 'http', 'tcp', 'udp', 'ip', 'ipv6', 'icmp',
]);
// FortiOS reports an unidentified session as the service it matched: `tcp/8443`,
// `udp/29810`, `icmp6/131/0`. That is a port, not an application.
// ⛔ ONE LIST, TWO CONSUMERS. The regex below and the SQL predicate at the
// bottom of this file are both built from this array, so a prefix added here
// reaches both. Transcribing it twice is how the dashboard and the report would
// come to disagree about what counts as an application.
const TRANSPORT_PREFIXES = ['tcp', 'udp', 'icmp', 'icmp6', 'ip', 'sctp'];
const TRANSPORT_SHAPED = new RegExp(`^(${TRANSPORT_PREFIXES.join('|')})[/\\d]`, 'i');
function isUnattributedApplication(a) {
  const v = String(a || '').trim().toLowerCase();
  if (v === '') return true;
  return UNATTRIBUTED_APPLICATIONS.has(v) || TRANSPORT_SHAPED.test(v);
}

// ⛔ THE SAME VOCABULARY, AS A SQL PREDICATE, BUILT FROM THE SAME CONSTANTS.
// A coverage query that counted `application IS NOT NULL` as "named" disagreed
// with the byte ranking that used isUnattributedApplication(): live on SMT the
// panel printed "44% was attributed to a named application" and, sixteen pixels
// below, "This firewall names 100% of its sessions". Both were computed
// honestly; they simply meant different things by the same word.
//
// ⛔ IT IS GENERATED, NOT TRANSCRIBED. The alternation below is the SAME array
// the JS regex is built from, so the two cannot drift into disagreeing about
// what a transport looks like — which is the whole reason this file exists.
function unattributedSqlPredicate(column, paramIndex) {
  return {
    sql: `(lower(${column}) = ANY($${paramIndex}::text[]) `
      + `OR ${column} ~* '^(${TRANSPORT_PREFIXES.join('|')})[/0-9]')`,
    params: [...UNATTRIBUTED_APPLICATIONS],
  };
}

module.exports = {
  unattributedSqlPredicate,
  TRANSPORT_PREFIXES,
  UNCLASSIFIED_URL_CATEGORIES,
  isUnclassifiedCategory,
  UNATTRIBUTED_APPLICATIONS,
  TRANSPORT_SHAPED,
  isUnattributedApplication,
};
