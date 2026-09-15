// app/api/applications/from-cloud/derive.js
//
// Turns a PUBLISHED cloud catalogue entry into a candidate application
// declaration. Pure apart from one catalogue read, and CommonJS so the POST
// handler, the server-rendered section on /applications and the test suite all
// read the SAME derivation - a preview that disagrees with what the button
// actually creates is worse than no preview at all.
//
// This is NOT a route module. app/api/applications/from-cloud/route.js may only
// export HTTP handlers (Next rejects anything else), so the logic it shares
// with the UI lives here beside it rather than in lib/.
//
// ⛔ A FLOW MAY ONLY BE BUILT FROM WHAT THE PUBLISHER ACTUALLY PUBLISHED.
// The operator's name goes on a declaration. Every later verdict on that page -
// "this application is broken", "this rule is unclaimed" - is measured against
// it. A guessed port or a guessed destination is therefore not a convenience,
// it is a fabricated declaration that somebody will be judged against. Measured
// live: Microsoft publishes tcpPorts on 62 of 63 endpoint sets but IP ranges on
// only 10, and BOTH on just 9; AWS, Google and Cloudflare publish no ports at
// all. So most of the time the honest derivation is a partial one, and saying
// so is the feature.
//
// ⛔ NOTHING HERE INVENTS 443. A prefix whose publisher stated no ports becomes
// a flow with NULL/NULL ports, which schema.sql defines as "every port of this
// protocol" - a wider claim than the truth, but a STATED one, where 443 would
// be a narrower claim that is simply made up.

'use strict';

const { providerLabel } = require('../../../../lib/engines/cloudApps');
const { loadCatalogue } = require('../../../../lib/feeds/cloudApps');

// ⛔ THE CAP EXISTS BECAUSE AN UNUSABLE DECLARATION IS NOT A DECLARATION.
// Measured on the live catalogue: AWS's 'AMAZON' service area alone carries
// 5,969 IPv4 prefixes, and Microsoft's Exchange Online 16 prefixes whose
// published port strings expand to roughly 32 flows. Nobody reviews five
// thousand rows, and an application nobody reviews is exactly the stale,
// unowned map this feature exists to beat.
//
// 50 is the same figure workQueueData.js uses for its own per-source cap, for
// the same reason: it is about as much as a person will actually read, and this
// product already treats 50 as "a list, not a dump". It is deliberately NOT
// configurable - an operator raising it to 6,000 would be choosing an
// unreviewable declaration without being told that is the choice.
//
// ⛔ AND WHEN IT BITES IT IS DISCLOSED, always, with the number omitted. A
// truncated list that looks complete is the more insidious failure: the
// operator works to the bottom and believes they are finished.
const MAX_FLOWS = 50;

// ⛔ `src: 'any'` IS A PLACEHOLDER AND IS LABELLED ONE, ON EVERY SINGLE FLOW.
// Only the operator knows which of their networks reaches this service.
// SecVault knows the destination because a publisher stated it; it knows
// nothing whatsoever about the source, and a bare `any` sitting in a table
// reads as a decision somebody made. This exact string is written to every
// created flow's note AND returned to the UI, so the caveat cannot be shown in
// one place and lost in the other.
const SRC_PLACEHOLDER_NOTE =
  'Source is a placeholder. SecVault set it to "any" because only you know which of your '
  + 'networks reaches this service - the publisher states the destination and the ports, never '
  + 'the source. Narrow it before this flow is read as a declaration.';

const PORT_MIN = 1;
const PORT_MAX = 65535;

// -- The published port string ---------------------------------------------

/**
 * Parse a publisher's port string into ranges.
 *
 * ⛔ PARSED, NEVER ASSUMED. The live shapes are '80,443' and
 * '143, 587, 993, 995' - note the spaces, which an obvious split(',') plus
 * Number() survives and a stricter regex does not. Anything else is a shape
 * this code has not seen, and the answer to an unrecognised shape is NO FLOW
 * plus a count, never a guess at what it probably meant.
 *
 * ⛔ `published` IS NOT `ranges.length > 0`. "The publisher gave no ports" and
 * "the publisher gave ports we could not read" are different facts with
 * different fixes, and only the first may become an every-port flow. Collapsing
 * them would turn an unreadable value into a confident wide-open declaration -
 * this codebase's failed-read-as-a-fact bug, in the one field where the wrong
 * answer is an extra hole rather than a missing one.
 *
 * @returns {{published:boolean, ranges:{start:number,end:number}[], unreadable:string[]}}
 */
function parsePortList(raw) {
  if (raw === null || raw === undefined) return { published: false, ranges: [], unreadable: [] };
  const s = String(raw).trim();
  if (s === '') return { published: false, ranges: [], unreadable: [] };

  const ranges = [];
  const unreadable = [];
  const seen = new Set();

  for (const token of s.split(',')) {
    const t = token.trim();
    // A trailing or doubled comma carries no claim at all - there is nothing to
    // fail to understand, so it is skipped rather than counted as unreadable.
    if (t === '') continue;

    let start = null;
    let end = null;
    if (/^\d{1,5}$/.test(t)) {
      start = Number(t);
      end = start;
    } else {
      // Not seen live from any of the four publishers, but a hyphenated range
      // is the one other form these feeds plausibly use, and reading it is
      // strictly better than filing a real published range as unreadable.
      const m = /^(\d{1,5})\s*-\s*(\d{1,5})$/.exec(t);
      if (m) { start = Number(m[1]); end = Number(m[2]); }
    }

    if (start === null || start < PORT_MIN || end > PORT_MAX || start > end) {
      unreadable.push(t);
      continue;
    }
    const key = `${start}-${end}`;
    if (seen.has(key)) continue;
    seen.add(key);
    ranges.push({ start, end });
  }

  return { published: true, ranges, unreadable };
}

// -- Catalogue lookup -------------------------------------------------------

const norm = (v) => (v === null || v === undefined ? '' : String(v).trim().toLowerCase());

/** The display name this row is presented under, matching cloudApps.matched(). */
function rowServiceDisplay(row) {
  return row.service_display || row.service || null;
}

/**
 * The label the rest of the product already shows for this row.
 *
 * ⛔ CHARACTER-FOR-CHARACTER what cloudApps.matched() builds, em dash included.
 * This string becomes the APPLICATION NAME, and applications.name is UNIQUE, so
 * a label that drifts by one character would silently create a second
 * "Microsoft 365 - Exchange Online" beside the first instead of reporting the
 * 409 the operator needs to see.
 */
function labelFor(provider, serviceDisplay) {
  return serviceDisplay ? `${providerLabel(provider)} — ${serviceDisplay}` : providerLabel(provider);
}

/**
 * Rows for one (provider, service) pair.
 *
 * ⛔ THE PAIR IS VALIDATED AGAINST THE CATALOGUE, NEVER TRUSTED FROM THE BODY.
 * An unrecognised pair must be refused, not declared: creating an application
 * named after a service no publisher lists would put a name on the board that
 * nothing can ever match, and the operator would have no way to tell that from
 * a service whose rules are simply missing.
 *
 * The service is accepted as EITHER the publisher's display name ('Exchange
 * Online') or its raw key ('Exchange'), because both are live in this codebase
 * - cloudApps.matched() shows the display, the feed stores both - and refusing
 * one of them would be an arbitrary trap. An empty/absent service matches only
 * rows that genuinely have none (Cloudflare publishes no breakdown at all).
 */
function findServiceRows(catalogue, provider, service) {
  const p = norm(provider);
  if (p === '') return null;
  const s = norm(service);
  const all = [...((catalogue && catalogue.hosts) || []), ...((catalogue && catalogue.ips) || [])];

  const matches = all.filter((r) => {
    if (norm(r.provider) !== p) return false;
    const display = norm(rowServiceDisplay(r));
    if (s === '') return display === '';
    return display === s || norm(r.service) === s;
  });

  if (matches.length === 0) return null;

  const ipRows = matches.filter((r) => r.kind === 'ip');
  const hostRows = matches.filter((r) => r.kind === 'host');
  const serviceDisplay = rowServiceDisplay(matches[0]);
  const sourceVersion = (matches.find((r) => r.source_version) || {}).source_version || null;

  return {
    provider: matches[0].provider,
    service: serviceDisplay,
    label: labelFor(matches[0].provider, serviceDisplay),
    ipRows,
    hostRows,
    sourceVersion,
  };
}

// -- Derivation -------------------------------------------------------------

const CASES = {
  // The publisher stated ranges AND ports. The only case that produces a
  // narrow, fully-published flow.
  PORTS: 'ranges_and_ports',
  // Ranges, no ports. NULL/NULL ports: every port of this protocol.
  RANGES_ONLY: 'ranges_only',
  // Ranges, and port strings none of which could be read. NO flows from those
  // prefixes - an unreadable value is not licence to widen.
  PORTS_UNREADABLE: 'ranges_with_unreadable_ports',
  // ⛔ NOT AN ERROR. The publisher lists this service by hostname only, which is
  // a correct and common outcome - Microsoft publishes urls on 62 of 63
  // endpoint sets and ips on 10 - and the application is still worth declaring
  // so its flows can be added by hand.
  NO_RANGES: 'no_ranges',
};

function flowKey(f) {
  const a = f.port_start === null ? '*' : f.port_start;
  const b = f.port_end === null ? '*' : f.port_end;
  return `${f.dst}|${f.protocol}|${a}|${b}`;
}

/**
 * Candidate flows for a set of catalogue IP rows.
 *
 * @returns {{flows:object[], derivation:object}}
 */
function deriveFlows(ipRows, options = {}) {
  const cap = Number.isInteger(options.cap) && options.cap > 0 ? options.cap : MAX_FLOWS;
  const rows = Array.isArray(ipRows) ? ipRows : [];

  const candidates = [];
  const seen = new Set();
  const unreadablePorts = [];
  let prefixesWithPorts = 0;
  let prefixesWithoutPorts = 0;
  let prefixesUnreadable = 0;

  const push = (row, protocol, portStart, portEnd) => {
    const flow = {
      src: 'any',
      dst: String(row.value),
      protocol,
      port_start: portStart,
      port_end: portEnd,
      expectation: 'allow',
      note: SRC_PLACEHOLDER_NOTE,
    };
    const key = flowKey(flow);
    if (seen.has(key)) return;
    seen.add(key);
    // Sorted so a truncated declaration is at least DETERMINISTIC: the same
    // click twice produces the same 50 flows, and a reader comparing two
    // declarations is comparing like with like.
    flow.sortKey = [
      Number(row.range_start) || 0,
      String(row.value),
      protocol,
      portStart === null ? -1 : portStart,
    ];
    candidates.push(flow);
  };

  for (const row of rows) {
    if (!row || !row.value) continue;
    const tcp = parsePortList(row.tcp_ports);
    const udp = parsePortList(row.udp_ports);

    for (const pair of [['tcp', tcp], ['udp', udp]]) {
      const protocol = pair[0];
      const parsed = pair[1];
      for (const r of parsed.ranges) push(row, protocol, r.start, r.end);
      for (const token of parsed.unreadable) {
        unreadablePorts.push({
          prefix: String(row.value),
          protocol,
          token,
          published: protocol === 'tcp' ? row.tcp_ports : row.udp_ports,
        });
      }
    }

    if (!tcp.published && !udp.published) {
      // ⛔ NULL/NULL, NOT 443. "Every port of this protocol" is wider than the
      // truth but it is what the published data supports; a guessed 443 would
      // be narrower and invented, and an operator reviewing the row would have
      // no way to tell which of the two it was.
      //
      // ⛔ Protocol 'any' for the same reason - a publisher that stated no port
      // stated no protocol either, and writing 'tcp' here would be the same
      // invention one field to the left. applicationView.js already treats
      // 'any' as matching every protocol, so this evaluates correctly rather
      // than being a special case.
      push(row, 'any', null, null);
      prefixesWithoutPorts += 1;
    } else if (tcp.ranges.length === 0 && udp.ranges.length === 0) {
      // Ports WERE published and none of them could be read. No flow, counted.
      prefixesUnreadable += 1;
    } else {
      prefixesWithPorts += 1;
    }
  }

  candidates.sort((a, b) => {
    for (let i = 0; i < a.sortKey.length; i += 1) {
      if (a.sortKey[i] < b.sortKey[i]) return -1;
      if (a.sortKey[i] > b.sortKey[i]) return 1;
    }
    return 0;
  });

  const kept = candidates.slice(0, cap).map((f) => ({
    src: f.src,
    dst: f.dst,
    protocol: f.protocol,
    port_start: f.port_start,
    port_end: f.port_end,
    expectation: f.expectation,
    note: f.note,
  }));

  let derivationCase;
  if (rows.length === 0) derivationCase = CASES.NO_RANGES;
  else if (prefixesWithPorts > 0) derivationCase = CASES.PORTS;
  else if (prefixesWithoutPorts > 0) derivationCase = CASES.RANGES_ONLY;
  else derivationCase = CASES.PORTS_UNREADABLE;

  return {
    flows: kept,
    derivation: {
      case: derivationCase,
      prefixCount: rows.length,
      prefixesWithPublishedPorts: prefixesWithPorts,
      prefixesWithoutPublishedPorts: prefixesWithoutPorts,
      prefixesWithUnreadablePorts: prefixesUnreadable,
      // ⛔ Counted and reported, never silently dropped: an unreadable published
      // value is a gap in what SecVault can read, and hiding it would make the
      // declaration look more complete than the data behind it.
      unreadablePorts,
      unreadablePortCount: unreadablePorts.length,
      candidateFlowCount: candidates.length,
      plannedFlowCount: kept.length,
      cap,
      capped: candidates.length > kept.length,
      omittedByCap: candidates.length - kept.length,
      srcCaveat: SRC_PLACEHOLDER_NOTE,
    },
  };
}

// -- Saying it in words -----------------------------------------------------

/**
 * ⛔ THE REASON IS PART OF THE ANSWER, NOT DECORATION. "Zero flows" on its own
 * reads as a failure; "zero flows because this publisher lists this service by
 * hostname only" reads as the correct outcome it is.
 */
const n = (v) => Number(v).toLocaleString('en-US');

function describeDerivation(d, label) {
  const name = label || 'this service';
  if (d.case === CASES.NO_RANGES) {
    return `The publisher lists ${name} by hostname only - it publishes no IP ranges for it, so `
      + 'no flow could be derived from published data. That is a correct outcome, not a failure: '
      + 'the application is created with no flows, ready for the ones only you can state.';
  }
  if (d.case === CASES.PORTS_UNREADABLE) {
    return `The publisher states ${n(d.prefixCount)} IP range${d.prefixCount === 1 ? '' : 's'} for `
      + `${name}, but none of its published port values could be read `
      + `(${n(d.unreadablePortCount)} value${d.unreadablePortCount === 1 ? '' : 's'}), so no flow was `
      + 'derived rather than a guessed one.';
  }

  const parts = [];
  parts.push(`${n(d.plannedFlowCount)} flow${d.plannedFlowCount === 1 ? '' : 's'} from the `
    + `${n(d.prefixCount)} IP range${d.prefixCount === 1 ? '' : 's'} the publisher states for ${name}`);
  if (d.case === CASES.RANGES_ONLY) {
    parts.push('it publishes no ports, so each flow covers every port of its protocol - SecVault '
      + 'did not invent one');
  } else if (d.prefixesWithoutPublishedPorts > 0) {
    parts.push(`${n(d.prefixesWithoutPublishedPorts)} of those range`
      + `${d.prefixesWithoutPublishedPorts === 1 ? ' has' : 's have'} no published ports and `
      + 'cover every port of their protocol');
  }
  if (d.unreadablePortCount > 0) {
    parts.push(`${n(d.unreadablePortCount)} published port value`
      + `${d.unreadablePortCount === 1 ? '' : 's'} could not be read and produced no flow`);
  }
  if (d.capped) {
    parts.push(`${n(d.omittedByCap)} further flow${d.omittedByCap === 1 ? ' was' : 's were'} not `
      + `created - this action stops at ${d.cap}, because a declaration nobody can review is not `
      + 'a declaration');
  }
  return `${parts.join('; ')}.`;
}

/** The one-line promise the button makes BEFORE it is clicked. */
function describePlan(d) {
  if (d.plannedFlowCount === 0) return 'Declare (no flows can be derived)';
  const n = d.plannedFlowCount;
  return `Declare with ${n} flow${n === 1 ? '' : 's'}`;
}

// -- Entry points -----------------------------------------------------------

/** One pair, fully planned. `null` when the catalogue does not carry it. */
function planFor(catalogue, provider, service, options = {}) {
  const found = findServiceRows(catalogue || {}, provider, service);
  if (!found) return null;
  const derived = deriveFlows(found.ipRows, options);
  return {
    provider: found.provider,
    service: found.service,
    label: found.label,
    sourceVersion: found.sourceVersion,
    hostCount: found.hostRows.length,
    flows: derived.flows,
    derivation: {
      ...derived.derivation,
      label: found.label,
      sourceVersion: found.sourceVersion,
      reason: describeDerivation(derived.derivation, found.label),
      buttonLabel: describePlan(derived.derivation),
    },
  };
}

/**
 * Every (provider, service) pair the catalogue carries, planned once.
 *
 * Used by the server-rendered section so each Declare control can state its
 * effect on first paint - a one-click action whose result is a surprise is
 * worse than two clicks.
 */
function buildPlans(catalogue, options = {}) {
  const rows = [...((catalogue && catalogue.hosts) || []), ...((catalogue && catalogue.ips) || [])];
  const pairs = new Map();
  for (const r of rows) {
    const display = rowServiceDisplay(r);
    const key = `${norm(r.provider)}::${norm(display)}`;
    if (!pairs.has(key)) pairs.set(key, { provider: r.provider, service: display });
  }
  const out = [];
  for (const pair of pairs.values()) {
    const plan = planFor(catalogue, pair.provider, pair.service, options);
    if (plan) out.push(plan);
  }
  return out;
}

/** The catalogue, in the one shape both callers need. */
async function loadDeclarationCatalogue(pool) {
  return loadCatalogue(pool);
}

module.exports = {
  MAX_FLOWS,
  SRC_PLACEHOLDER_NOTE,
  CASES,
  parsePortList,
  findServiceRows,
  labelFor,
  deriveFlows,
  describeDerivation,
  describePlan,
  planFor,
  buildPlans,
  loadDeclarationCatalogue,
};
