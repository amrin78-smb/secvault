// lib/syslog/actions.js
//
// THE single source of truth for "was this traffic allowed or blocked", as
// firewalls actually spell it.
//
// ── WHY THIS FILE EXISTS ──────────────────────────────────────────────────
// There were FOUR different deny lists in this codebase, and the narrowest one
// was driving every dashboard number:
//
//   rollups.js        4 verbs   deny drop reset-both block          <- the UI
//   eventShape.js     7 verbs   + block-url reset-client reset-server
//   threatStats.js    5 verbs   (exported, imported by nothing)
//   logHit.js        13 verbs
//
// Measured live on this fleet, the 4-verb list under-counted blocks by 6.8%
// fleet-wide and by 24% on URL-category rows — because `block-url`, the ONLY
// URL-filtering block verb PAN-OS emits, was missing from the list that feeds
// the "how much of each category was blocked" widget. `'block'` itself never
// appears on this fleet at all. `syslog_blocked_dst_hourly` did not merely
// under-count those rows, it DROPPED them (a WHERE, not a FILTER), so they
// were unrecoverable from the rollup.
//
// ⛔ Every verb below was read off REAL captured logs, not vendor docs, per
// CLAUDE.md's "documentation lies" rule.
//
// ⛔ THREE-STATE, always. A verb in neither set is UNKNOWN and must never be
// folded into either one. `close`/`client-rst`/`server-rst` are Fortinet
// SESSION-END actions — the session existed, so the service was reached —
// while Palo Alto's `reset-both` looks like that family but is a block.

'use strict';

// A session that was permitted. Includes Fortinet's session-teardown verbs:
// live proof they matter is FortiGate SSL-VPN on 10443, which is reached from
// public sources and logged `close`/`client-rst`, never `allow`.
//
// ⛔ `timeout` BELONGS HERE AND WAS IN THE DENY LIST UNTIL 2026-09-09. It is a
// FortiOS session-TEARDOWN verb of exactly the close/client-rst family — the
// session was removed from the session table because it went idle — not a
// refusal. The captured line that settles it (see
// tests/actionClassification.test.js, which uses it as its fixture):
//
//   type="traffic" subtype="forward" action="timeout" policyid=7
//   policytype="policy" policyname="chotruycap" trandisp="snat"
//   transip=123.25.240.15 duration=25 sentbyte=260 rcvdbyte=0 sentpkt=5
//
// An ALLOW policy matched, a session was created, SNAT was applied and packets
// were forwarded. Measured live on this fleet twice, and the two populations
// are not the same shape at all:
//
//   action='timeout'  every sampled row has bytes_sent > 0 and a matched
//                     rule_id; ~1,300-3,400 B sent, ~3,500-5,000 B received
//   action='deny'     ~37-44 B sent on the minority of rows that carry any
//                     bytes at all, and ZERO bytes received, ever
//
// Timeout rows carry real bidirectional payload; deny rows carry a SYN. It is
// also Fortinet-only on this fleet (100% of a live sample, log_class
// 'traffic'), so it cannot be confused with a Palo Alto verb.
//
// Cost of the old classification: ~213,000 sessions/day — 5.2% of every
// "denied" figure the fleet reported — counted as blocks, and, worse,
// `syslog_device_inbound_hourly.allowed` set FALSE for a service that WAS
// reached and then went idle, which suppressed logHit.js entirely.
const ALLOWED_ACTIONS = new Set([
  'allow',
  'accept',
  'permit',
  'start',
  'close',
  'client-rst',
  'server-rst',
  'timeout',
]);

// A session that was refused. `reset-both` is Palo Alto's IPS resetting BOTH
// ends — a block, despite resembling the teardown verbs above.
//
// ⛔ Do not add a verb here (or above) because it LOOKS like one of these.
// `timeout` sat in this list for exactly that reason and cost 5.2% of the
// fleet's denied total. Every entry is a verb read off captured logs, and a
// verb whose meaning is not established from live traffic must be left out of
// BOTH sets so classifyAction() answers 'unknown'.
const DENIED_ACTIONS = new Set([
  'deny',
  'drop',
  'drop-packet',
  'block',
  'blocked',
  'denied',
  'block-url',
  'block-ip',
  'block-continue',
  'block-override',
  'reset-both',
  'reset-client',
  'reset-server',
]);

/**
 * @returns {'allowed'|'blocked'|'unknown'}
 *
 * ⛔ `unknown` is a real third answer. Callers must not fold it into either
 * side — a vendor verb this codebase has never seen must not be able to
 * manufacture an escalation or a confident zero.
 */
function classifyAction(action) {
  if (typeof action !== 'string') return 'unknown';
  const a = action.trim().toLowerCase();
  if (a === '') return 'unknown';
  if (ALLOWED_ACTIONS.has(a)) return 'allowed';
  if (DENIED_ACTIONS.has(a)) return 'blocked';
  return 'unknown';
}

/**
 * Render a set as a complete, PARENTHESISED SQL IN-list: `('deny','drop',...)`.
 *
 * ⛔ The parentheses are part of this function's contract, not the caller's.
 * Returning a bare comma list produced `lower(action) IN 'deny','drop'` at the
 * call sites — a syntax error that would abort the whole nine-rollup sweep
 * transaction on the first run. Emitting a directly substitutable fragment is
 * what makes that impossible.
 *
 * ⛔ Safe by construction: these are module constants, never user input, and
 * no code path puts an external value into either set. Generating the SQL from
 * the same constant the JS uses is the entire point — it is what stops the
 * lists drifting apart again.
 */
function sqlList(set) {
  return (
    '(' +
    Array.from(set)
      .map((a) => `'${a}'`)
      .join(',') +
    ')'
  );
}

const ALLOWED_SQL = sqlList(ALLOWED_ACTIONS);
const DENIED_SQL = sqlList(DENIED_ACTIONS);

module.exports = {
  ALLOWED_ACTIONS,
  DENIED_ACTIONS,
  classifyAction,
  sqlList,
  ALLOWED_SQL,
  DENIED_SQL,
};
