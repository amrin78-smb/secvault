// lib/engines/applicationView.js
//
// The application-centric view's PURE half: given a declared flow and one
// device's rules + objects, decide what the rulebase actually says about it.
// No pool, no I/O — everything here takes data in and returns data out, which
// is what makes the judgement testable. The plumbing lives in
// applicationViewData.js.
//
// ⛔ WHY A RANGE MODEL AND NOT objectResolver.queryAccessPath().
//
// queryAccessPath() is this codebase's existing flow evaluator and it is reused
// UNCHANGED by topology.js and exposure.js. It could not be reused here, and
// the reason is worth stating so nobody "simplifies" this file back onto it:
// it requires srcIp and dstIp to be SINGLE /32 ADDRESSES and throws otherwise.
//
// A declared application flow is almost never a point. It is "the app subnet
// reaches the database subnet on 1521". Answering that by picking one address
// out of each /24 and reporting the result for the whole range is the
// fabricated-measurement bug this codebase keeps finding — the sample might be
// the one address a rule covers, or the one it misses, and nothing in the
// output would show which.
//
// So this module resolves rule fields with objectResolver's OWN
// resolveAddressField/resolveServiceField (the hard part — group expansion,
// FQDNs, vendor service grammars — is NOT reimplemented) and then does the
// comparison at RANGE granularity, which those helpers deliberately do not do.
//
// ⛔ WHY EXACT DECOMPOSITION AND NOT "WEAKEST DIMENSION".
//
// The cheap version compares each dimension separately and reports the worst.
// It is wrong in a way that matters. Take a flow 10.1.0.0/24 -> any:443 with
//     rule 1  deny   10.1.0.5  -> any:443
//     rule 2  allow  10.1.0.0/24 -> any:443
// Per-dimension, rule 1 is "relevant" and denies, so the flow reads BLOCKED —
// when 254 of its 255 addresses are permitted. On a `deny` expectation that is
// a hole reported as closed, i.e. a false assurance, which segmentation.js
// already names as the dangerous direction on this kind of report.
//
// This module therefore walks the rules in order carrying a set of UNDECIDED
// boxes (src range x dst range x port range), splitting each box as rules claim
// parts of it, and reports the exact permitted / blocked / unspecified volumes.
//
// ⛔ WHAT "PERMITTED" CLAIMS, PRECISELY: at least one enabled allow rule
// matches. It does NOT claim a packet would pass — rule order across DIFFERENT
// devices, routing, NAT and profiles are not modelled here. Same wording
// discipline as segmentation.js, and for the same reason: an operator who
// trusts "reachable" and finds it was a guess stops trusting the honest
// answers too.

'use strict';

// ⛔ The action vocabulary is BORROWED, never redefined. Two files deciding
// "is this an allow" independently would eventually disagree, and the one
// that was wrong would be recommending rule changes.
const {
  isAllowAction,
  isDenyAction,
  isUnrecognisedAction,
} = require('./segmentation');

const {
  buildObjectMap,
  resolveAddressField,
  resolveServiceField,
} = require('./objectResolver');

const PORT_MIN = 0;
const PORT_MAX = 65535;
const IP_MIN = 0;
const IP_MAX = 4294967295; // 2^32 - 1

// ⛔ A BOUND, DISCLOSED WHEN IT BITES — never a silent truncation. Splitting a
// box can fragment it, and a pathological rulebase could fragment it without
// end. Hitting this makes the flow `unverified` and sets `truncated`, so the
// answer is incomplete rather than a partial answer dressed as a whole one.
// ⛔ What it does NOT do is overwrite what was already proven — see the note
// above the verdict ladder in evaluateFlowOnDevice.
const MAX_UNDECIDED_BOXES = 4000;

const VERDICTS = {
  PERMITTED: 'permitted',
  PARTIAL: 'partially_permitted',
  BLOCKED: 'blocked',
  UNSPECIFIED: 'unspecified',
};

const USED = {
  ACTIVE: 'rule-active',
  IDLE: 'rule-idle',
  UNKNOWN: 'unknown',
};

// ── Address parsing ────────────────────────────────────────────────────────
//
// ⛔ This parses the DECLARED flow's own literal CIDR, which is a different
// input from a rule field: a flow never carries an object name, a group or an
// FQDN (schema.sql says why). objectResolver's parser is not exported, and
// duplicating twenty lines of CIDR arithmetic is the lesser evil against
// exporting a private helper purely to avoid it. The RESOLUTION logic — the
// part that is actually hard and actually drifts — is imported, not copied.

/** @returns {{start:number,end:number}|null} null when unparseable. */
function parseCidr(value) {
  if (typeof value !== 'string') return null;
  const raw = value.trim();
  if (!raw) return null;
  // 'any' is a legitimate declaration: "anything reaches the DMZ on 443".
  if (raw.toLowerCase() === 'any') return { start: IP_MIN, end: IP_MAX };

  const slash = raw.indexOf('/');
  const ipPart = slash === -1 ? raw : raw.slice(0, slash);
  const prefixPart = slash === -1 ? '32' : raw.slice(slash + 1);

  const octets = ipPart.split('.');
  if (octets.length !== 4) return null;
  let addr = 0;
  for (const o of octets) {
    if (!/^\d{1,3}$/.test(o)) return null;
    const n = Number(o);
    if (n > 255) return null;
    addr = addr * 256 + n;
  }
  if (!/^\d{1,2}$/.test(prefixPart)) return null;
  const prefix = Number(prefixPart);
  if (prefix < 0 || prefix > 32) return null;

  const size = prefix === 0 ? IP_MAX + 1 : 2 ** (32 - prefix);
  const network = prefix === 0 ? 0 : Math.floor(addr / size) * size;
  return { start: network, end: network + size - 1 };
}

function ipToString(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/** A range back to the tersest human form — a single IP, or start-end. */
function rangeToString(r) {
  if (r.start === r.end) return ipToString(r.start);
  if (r.start === IP_MIN && r.end === IP_MAX) return 'any';
  return `${ipToString(r.start)}-${ipToString(r.end)}`;
}

// ── Boxes ──────────────────────────────────────────────────────────────────
// A box is a closed interval in each of three dimensions: source address,
// destination address, destination port. Protocol is NOT a dimension — the
// flow declares one, and rule service entries are filtered to it up front,
// which keeps this 3-D instead of ragged.

function makeBox(s0, s1, d0, d1, p0, p1) {
  return { s0, s1, d0, d1, p0, p1 };
}

function boxVolume(b) {
  return BigInt(b.s1 - b.s0 + 1) * BigInt(b.d1 - b.d0 + 1) * BigInt(b.p1 - b.p0 + 1);
}

function totalVolume(boxes) {
  let v = 0n;
  for (const b of boxes) v += boxVolume(b);
  return v;
}

function intersectBox(a, b) {
  const s0 = Math.max(a.s0, b.s0);
  const s1 = Math.min(a.s1, b.s1);
  if (s0 > s1) return null;
  const d0 = Math.max(a.d0, b.d0);
  const d1 = Math.min(a.d1, b.d1);
  if (d0 > d1) return null;
  const p0 = Math.max(a.p0, b.p0);
  const p1 = Math.min(a.p1, b.p1);
  if (p0 > p1) return null;
  return makeBox(s0, s1, d0, d1, p0, p1);
}

/**
 * box minus cut, where cut is assumed to be contained in box (it always is
 * here — cut comes from intersectBox). Yields up to six disjoint boxes whose
 * union is exactly the remainder, so no volume is invented or lost.
 */
function subtractBox(box, cut) {
  const out = [];
  if (cut.s0 > box.s0) out.push(makeBox(box.s0, cut.s0 - 1, box.d0, box.d1, box.p0, box.p1));
  if (cut.s1 < box.s1) out.push(makeBox(cut.s1 + 1, box.s1, box.d0, box.d1, box.p0, box.p1));
  if (cut.d0 > box.d0) out.push(makeBox(cut.s0, cut.s1, box.d0, cut.d0 - 1, box.p0, box.p1));
  if (cut.d1 < box.d1) out.push(makeBox(cut.s0, cut.s1, cut.d1 + 1, box.d1, box.p0, box.p1));
  if (cut.p0 > box.p0) out.push(makeBox(cut.s0, cut.s1, cut.d0, cut.d1, box.p0, cut.p0 - 1));
  if (cut.p1 < box.p1) out.push(makeBox(cut.s0, cut.s1, cut.d0, cut.d1, cut.p1 + 1, box.p1));
  return out;
}

// ── Flow normalisation ─────────────────────────────────────────────────────

/**
 * Turns a stored application_flows row into the box the evaluator works on.
 * @returns {{ok:true, box:object, protocol:string, src:object, dst:object}
 *         | {ok:false, reason:string}}
 *
 * ⛔ Returns a REASON rather than throwing, and the caller surfaces it. A flow
 * an operator typed wrongly is a data problem they can fix; a 500 tells them
 * the feature is broken.
 */
function normaliseFlow(flow) {
  const src = parseCidr(flow && flow.src);
  if (!src) return { ok: false, reason: `Source "${flow && flow.src}" is not a valid address or CIDR.` };
  const dst = parseCidr(flow && flow.dst);
  if (!dst) return { ok: false, reason: `Destination "${flow && flow.dst}" is not a valid address or CIDR.` };

  const protocol = String((flow && flow.protocol) || 'tcp').trim().toLowerCase();

  // NULL/NULL means every port of this protocol — which is what a
  // protocol-only flow ("icmp from here to there") means too.
  let p0 = flow && flow.port_start !== null && flow.port_start !== undefined
    ? Number(flow.port_start) : PORT_MIN;
  let p1 = flow && flow.port_end !== null && flow.port_end !== undefined
    ? Number(flow.port_end) : (flow && flow.port_start !== null && flow.port_start !== undefined
      ? Number(flow.port_start) : PORT_MAX);

  if (!Number.isInteger(p0) || !Number.isInteger(p1)) {
    return { ok: false, reason: 'Ports must be whole numbers.' };
  }
  if (p0 > p1) return { ok: false, reason: `Port range ${p0}-${p1} starts after it ends.` };
  if (p0 < PORT_MIN || p1 > PORT_MAX) {
    return { ok: false, reason: `Ports must be between ${PORT_MIN} and ${PORT_MAX}.` };
  }

  return {
    ok: true,
    protocol,
    src,
    dst,
    box: makeBox(src.start, src.end, dst.start, dst.end, p0, p1),
  };
}

// ── Rule extent ────────────────────────────────────────────────────────────

/**
 * The port ranges a resolved service field covers FOR ONE PROTOCOL.
 * @returns {{ranges:{start:number,end:number}[], unresolved:boolean}}
 */
function servicePortRanges(resolvedService, protocol) {
  if (resolvedService.isAny) {
    return { ranges: [{ start: PORT_MIN, end: PORT_MAX }], unresolved: false };
  }
  const ranges = [];
  for (const p of resolvedService.protocols) {
    const proto = String(p.proto || '').toLowerCase();
    // 'ip'/'any'/'all' are the vendors' own any-protocol spellings, already
    // normalised by objectResolver's service parser.
    const protoMatches =
      protocol === 'any' || proto === 'ip' || proto === 'any' || proto === 'all' || proto === protocol;
    if (!protoMatches) continue;
    if (p.portStart === null || p.portStart === undefined) {
      // A protocol-only entry (e.g. "icmp") covers the whole port dimension,
      // because there is no port to constrain.
      ranges.push({ start: PORT_MIN, end: PORT_MAX });
      continue;
    }
    ranges.push({ start: p.portStart, end: p.portEnd });
  }
  return {
    ranges,
    unresolved: Array.isArray(resolvedService.unresolvedNames) && resolvedService.unresolvedNames.length > 0,
  };
}

function addressRanges(resolvedAddr) {
  if (resolvedAddr.isAny) return { ranges: [{ start: IP_MIN, end: IP_MAX }], unresolved: false };
  return {
    ranges: resolvedAddr.ranges || [],
    unresolved:
      (resolvedAddr.unresolvedFqdns || []).length > 0 || (resolvedAddr.unresolvedNames || []).length > 0,
  };
}

/** Only the ranges that could possibly touch the flow — prunes the cross product. */
function overlapping(ranges, lo, hi) {
  return ranges.filter((r) => r.end >= lo && r.start <= hi);
}

// ── The walk ───────────────────────────────────────────────────────────────

/**
 * Evaluate one declared flow against ONE device's rulebase.
 *
 * @param {object} normalised - from normaliseFlow(), ok:true
 * @param {object[]} rules   - firewall_rules rows for this device
 * @param {object[]} objects - network_objects rows for the SAME device
 * @returns {{
 *   verdict: string, allowVolume: bigint, denyVolume: bigint,
 *   unspecifiedVolume: bigint, total: bigint,
 *   permittingRules: object[], denyingRules: object[],
 *   unverified: boolean, unverifiedReasons: string[],
 *   unresolvedRuleCount: number, unrecognisedActionCount: number, truncated: boolean,
 * }}
 */
function evaluateFlowOnDevice(normalised, rules, objects, opts = {}) {
  const flowBox = normalised.box;
  const total = boxVolume(flowBox);

  // ⛔ THE OBJECT MAPS ARE HOISTABLE, AND ON A REAL FLEET THEY MUST BE HOISTED.
  // buildObjectMap walks every network_objects row for the device — 10,044 rows
  // across the live fleet — and rebuilding that per flow per device was most of
  // the measured cost. A caller evaluating many flows passes them in once
  // (loadFleet precomputes them); a caller with a single flow can omit them and
  // still get the same answer. The MAPS are a cache; no verdict is cached.
  const addressObjects = opts.addressObjects
    || buildObjectMap(objects || [], ['address', 'address_group']);
  const serviceObjects = opts.serviceObjects
    || buildObjectMap(objects || [], ['service', 'service_group']);

  const enabled = (Array.isArray(rules) ? rules : [])
    .filter((r) => r.enabled !== false)
    .slice()
    .sort((a, b) => {
      // ⛔ Same ordering convention as queryAccessPath: a NULL sequence sorts
      // LAST. A rule whose position we do not know must not be assumed to sit
      // at the top of the policy, where it would shadow everything below it.
      const as = a.sequence_number;
      const bs = b.sequence_number;
      if (as === null || as === undefined) return bs === null || bs === undefined ? 0 : 1;
      if (bs === null || bs === undefined) return -1;
      return as - bs;
    });

  let undecided = [flowBox];
  let allowVolume = 0n;
  let denyVolume = 0n;
  const permittingRules = [];
  const denyingRules = [];
  const unverifiedReasons = [];
  let unresolvedRuleCount = 0;
  let unrecognisedActionCount = 0;
  let truncated = false;

  for (const rule of enabled) {
    if (undecided.length === 0) break;
    if (undecided.length > MAX_UNDECIDED_BOXES) {
      truncated = true;
      break;
    }

    const action = rule.action;
    const allow = isAllowAction(action);
    const deny = isDenyAction(action);
    if (!allow && !deny) {
      // ⛔ AN UNRECOGNISED ACTION DECIDES NOTHING. It is counted and reported,
      // never guessed into allow or deny — the same rule log_hit follows, where
      // an unknown vendor verb must not be able to manufacture a verdict.
      if (isUnrecognisedAction(action)) unrecognisedActionCount += 1;
      continue;
    }

    const srcR = addressRanges(resolveAddressField(rule.src_addresses, addressObjects));
    const dstR = addressRanges(resolveAddressField(rule.dst_addresses, addressObjects));
    const svcR = servicePortRanges(resolveServiceField(rule.services, serviceObjects), normalised.protocol);

    const partiallyUnknown = srcR.unresolved || dstR.unresolved || svcR.unresolved;

    const srcRanges = overlapping(srcR.ranges, flowBox.s0, flowBox.s1);
    const dstRanges = overlapping(dstR.ranges, flowBox.d0, flowBox.d1);
    const svcRanges = overlapping(svcR.ranges, flowBox.p0, flowBox.p1);

    if (partiallyUnknown && (srcRanges.length || dstRanges.length || svcRanges.length
      || srcR.ranges.length === 0 || dstR.ranges.length === 0 || svcR.ranges.length === 0)) {
      // ⛔ THE RULE'S TRUE EXTENT IS NOT KNOWABLE. An FQDN or an object this
      // device never reported could cover any part of the flow. We apply only
      // its RESOLVED portion below — deliberately the conservative direction,
      // since understating an allow reports a working app as broken and
      // understating a deny reports a violation that may not exist, and both
      // are safer than the reverse — but the flow is marked unverified so no
      // caller can read the result as settled.
      unresolvedRuleCount += 1;
    }

    if (srcRanges.length === 0 || dstRanges.length === 0 || svcRanges.length === 0) continue;

    // The rule's extent, as boxes. Pruned to what can touch the flow, so this
    // cross product is small in practice even for a rule with many objects.
    const nextUndecided = [];
    let claimed = 0n;
    for (const box of undecided) {
      let remainder = [box];
      for (const s of srcRanges) {
        for (const d of dstRanges) {
          for (const p of svcRanges) {
            const ruleBox = makeBox(s.start, s.end, d.start, d.end, p.start, p.end);
            const stillOpen = [];
            for (const rem of remainder) {
              const hit = intersectBox(rem, ruleBox);
              if (!hit) { stillOpen.push(rem); continue; }
              claimed += boxVolume(hit);
              for (const piece of subtractBox(rem, hit)) stillOpen.push(piece);
            }
            remainder = stillOpen;
            if (remainder.length === 0) break;
          }
          if (remainder.length === 0) break;
        }
        if (remainder.length === 0) break;
      }
      for (const rem of remainder) nextUndecided.push(rem);
    }

    if (claimed > 0n) {
      // ⛔ The real firewall_rules column names are `rule_id_vendor` and
      // `rule_name`; the short forms are accepted only so a hand-built test
      // fixture stays readable. ⛔ `rule.applications` is deliberately NOT read
      // here — that column is the VENDOR L7 APP-ID list ('ssl', 'dns-base'),
      // which is a protocol fingerprint and not a business application. The two
      // must never be joined on, or conflated in any label.
      const summary = {
        deviceRuleId: rule.id,
        ruleId: rule.rule_id_vendor !== undefined ? rule.rule_id_vendor : rule.rule_id,
        name: rule.rule_name !== undefined ? rule.rule_name : (rule.name || null),
        action: rule.action,
        sequence: rule.sequence_number,
        // ⛔ TRI-STATE, preserved. undefined means the caller did not supply it;
        // null means the device genuinely cannot report a count. Neither is 0.
        effectiveHitCount: rule.effectiveHitCount === undefined
          ? (rule.hit_count === undefined ? null : rule.hit_count)
          : rule.effectiveHitCount,
        logEvidence: rule.logEvidence || null,
        volume: claimed.toString(),
        hasUnresolved: partiallyUnknown,
      };
      if (allow) { allowVolume += claimed; permittingRules.push(summary); }
      else { denyVolume += claimed; denyingRules.push(summary); }
    }
    undecided = nextUndecided;
  }

  const unspecifiedVolume = totalVolume(undecided);

  if (truncated) {
    unverifiedReasons.push(
      'This rulebase fragmented the flow into more pieces than the evaluator will follow, '
      + 'so the result is incomplete rather than approximate.'
    );
  }
  if (unresolvedRuleCount > 0) {
    unverifiedReasons.push(
      `${unresolvedRuleCount} rule${unresolvedRuleCount === 1 ? ' references' : 's reference'} an address `
      + 'or service this device did not report (an FQDN, or an object missing from the collected set), '
      + 'so how much of the flow they really cover is unknown.'
    );
  }

  // ⛔ TRUNCATION MUST NOT MANUFACTURE "NOTHING PERMITS THIS".
  //
  // This used to force `UNSPECIFIED` whenever the cap bit, on the reasoning
  // that a truncated walk is a refusal to answer. But `UNSPECIFIED` is not a
  // neutral "unknown" in this model — flowFinding() renders it as the POSITIVE
  // claims "Nothing permits this" / "Nothing permits it, and nothing denies
  // it". Measured on a device that really does hit the cap, the result was a
  // named permitting rule, an allowVolume of exactly half the flow and a
  // permittedPct of 50, printed under the headline "Nothing permits this" —
  // and on a `deny` expectation a demonstrated VIOLATION was downgraded to
  // "nothing permits it", i.e. a hole reported as closed, which this file's own
  // header names as the dangerous direction.
  //
  // Volume that was CLAIMED was claimed by rules that really matched, in order,
  // before the walk stopped; it is proven regardless of where the walk ended.
  // So the verdict states what was proven, and the refusal is carried by
  // `truncated` / `unverified` / the reason text, which is where a caller can
  // see it is incomplete rather than reading an answer that is simply wrong.
  //
  // ⛔ A truncated walk can never reach PERMITTED or BLOCKED: the cap only
  // fires while `undecided` is non-empty, so unspecifiedVolume > 0 and neither
  // allowVolume nor denyVolume can reach `total`. The incomplete result
  // therefore cannot be dressed as a whole one — pinned by a test.
  let verdict;
  if (allowVolume >= total) verdict = VERDICTS.PERMITTED;
  else if (allowVolume > 0n) verdict = VERDICTS.PARTIAL;
  else if (denyVolume >= total) verdict = VERDICTS.BLOCKED;
  else verdict = VERDICTS.UNSPECIFIED;

  return {
    verdict,
    allowVolume,
    denyVolume,
    unspecifiedVolume,
    total,
    permittingRules,
    denyingRules,
    unverified: truncated || unresolvedRuleCount > 0,
    unverifiedReasons,
    unresolvedRuleCount,
    unrecognisedActionCount,
    truncated,
  };
}

// ── Fleet aggregation ──────────────────────────────────────────────────────

/**
 * Combine per-device results into the flow's fleet answer.
 *
 * @param {{device:object, result:object}[]} perDevice
 * @param {{devicesWithoutRules:number}} [coverage]
 *
 * ⛔ VOLUMES ARE NEVER UNIONED ACROSS DEVICES. Two firewalls each permitting
 * half of a flow does not add up to a permitted flow — they are different
 * firewalls on (probably) different paths, and summing them would invent a
 * reachability that exists on neither. The fleet answer is the BEST SINGLE
 * DEVICE's answer, which is what "at least one enabled allow rule permits
 * this" means.
 */
function aggregateFlow(perDevice, coverage = {}) {
  const evaluated = (perDevice || []).filter((x) => x && x.result);

  let best = null;
  for (const entry of evaluated) {
    if (!best) { best = entry; continue; }
    const a = entry.result;
    const b = best.result;
    if (a.allowVolume > b.allowVolume) best = entry;
    else if (a.allowVolume === b.allowVolume && a.denyVolume > b.denyVolume) best = entry;
  }

  const permittedBy = evaluated
    .filter((e) => e.result.allowVolume > 0n)
    .map((e) => ({
      deviceId: e.device.id,
      deviceName: e.device.name,
      verdict: e.result.verdict,
      rules: e.result.permittingRules,
    }));

  const blockedBy = evaluated
    .filter((e) => e.result.denyVolume > 0n && e.result.allowVolume === 0n)
    .map((e) => ({ deviceId: e.device.id, deviceName: e.device.name, rules: e.result.denyingRules }));

  const devicesWithoutRules = Number(coverage.devicesWithoutRules || 0);
  const anyUnverified = evaluated.some((e) => e.result.unverified);

  // ⛔ A DEVICE WITH NO COLLECTED RULES MAKES THE ANSWER UNVERIFIED, NEVER
  // "BLOCKED". A fleet whose rulesets were never pulled would otherwise report
  // every flow as safely unreachable — a perfect result computed entirely from
  // missing data. Same rule segmentation.js applies to its own matrix.
  //
  // ⛔ AND NO DEVICE EVALUATED AT ALL IS THE SAME CLAIM WITH NOTHING BEHIND IT.
  // With an empty fleet (a fresh install, or every active device filtered out
  // upstream) `devicesWithoutRules` is 0 and nothing reports itself unverified,
  // so the verdict fell out as a SETTLED `unspecified` — "Nothing permits this"
  // asserted over zero evidence. Absence of a measurement is not a measurement.
  const unverified = anyUnverified || devicesWithoutRules > 0 || evaluated.length === 0;

  const reasons = [];
  for (const e of evaluated) {
    for (const r of e.result.unverifiedReasons) reasons.push(`${e.device.name}: ${r}`);
  }
  if (devicesWithoutRules > 0) {
    reasons.push(
      `${devicesWithoutRules} active firewall${devicesWithoutRules === 1 ? ' has' : 's have'} no `
      + 'collected ruleset, so what they permit is unknown.'
    );
  }
  if (evaluated.length === 0) {
    // ⛔ An unverified answer must always say why — a flag with no reason beside
    // it reads as a rendering glitch and gets ignored.
    reasons.push('No firewall was evaluated for this flow, so nothing has been measured about it.');
  }

  let verdict;
  if (!best) verdict = VERDICTS.UNSPECIFIED;
  else verdict = best.result.verdict;

  const total = best ? best.result.total : 0n;
  const allow = best ? best.result.allowVolume : 0n;

  return {
    verdict,
    permittedBy,
    blockedBy,
    unverified,
    unverifiedReasons: reasons,
    // Exact, as a percentage of the declared flow, from the single best device.
    permittedPct: total > 0n ? Number((allow * 10000n) / total) / 100 : null,
    evaluatedDeviceCount: evaluated.length,
  };
}

// ── The USED axis ──────────────────────────────────────────────────────────

/**
 * What the traffic says about a flow — AT RULE GRAIN ONLY.
 *
 * ⛔ THIS DOES NOT SAY THE FLOW WAS USED, AND NO CALLER MAY PRESENT IT AS IF
 * IT DID. No syslog rollup in this product carries both ends of a flow (every
 * one is source-keyed or destination-keyed), so "did this exact src -> dst:port
 * carry traffic" is not answerable from stored data at all. What IS answerable
 * is whether the RULE permitting it has seen traffic, which is a strictly
 * weaker statement and must be worded as one.
 *
 * ⛔ IT CONSUMES ruleHitCorrelation's OWN TRI-STATE — `effectiveHitCount`,
 * which is a real count, a genuine measured 0, or NULL meaning not measurable —
 * rather than defining a second vocabulary for the same three states. Two
 * engines each deciding "is this rule used" would eventually disagree, and the
 * wrong one would be the one justifying a deletion.
 *
 * @param {{effectiveHitCount:number|null}[]} evidences
 *   one per permitting rule, exactly as enrichRulesWithLogEvidence returns them.
 */
function usedVerdict(evidences) {
  const list = Array.isArray(evidences) ? evidences : [];
  if (list.length === 0) return USED.UNKNOWN;

  // ⛔ ONE SILENT RULE POISONS THE WHOLE ANSWER, deliberately. If any permitting
  // rule cannot report usage, that rule might be the one carrying the traffic,
  // so "idle" cannot be claimed. Fortinet over SSH reports no hit counts at
  // all, which makes this the COMMON case on this fleet rather than a corner —
  // the same finding that leaves segmentation's DID column mostly null.
  if (list.some((e) => !e || e.effectiveHitCount === null || e.effectiveHitCount === undefined)) {
    return USED.UNKNOWN;
  }
  if (list.some((e) => Number(e.effectiveHitCount) > 0)) return USED.ACTIVE;
  return USED.IDLE;
}

// ── Expectation → finding ──────────────────────────────────────────────────

/**
 * Turn a verdict into what it means for the operator, given what they declared.
 *
 * ⛔ BOTH DIRECTIONS PRODUCE FINDINGS. An `allow` flow nothing permits is a
 * broken application; a `deny` flow something permits is a violation. A model
 * carrying only one of them could express half the question.
 *
 * ⛔ `unspecified` IS NEVER REPORTED AS DENIED. No default/implicit-policy data
 * exists anywhere in this codebase, for any vendor, so "no rule decides this"
 * is genuinely not the same statement as "this is blocked".
 */
function flowFinding(expectation, agg) {
  const exp = expectation === 'deny' ? 'deny' : 'allow';
  const v = agg.verdict;

  if (exp === 'allow') {
    if (v === VERDICTS.PERMITTED) {
      return agg.unverified
        ? { state: 'ok_unverified', label: 'Permitted, not fully verified' }
        : { state: 'ok', label: 'Permitted' };
    }
    if (v === VERDICTS.PARTIAL) return { state: 'partial', label: 'Only partly permitted' };
    if (v === VERDICTS.BLOCKED) return { state: 'broken', label: 'Blocked — application cannot work' };
    return { state: 'unspecified', label: 'Nothing permits this' };
  }

  if (v === VERDICTS.PERMITTED || v === VERDICTS.PARTIAL) {
    return { state: 'violation', label: 'A rule permits what should be denied' };
  }
  if (v === VERDICTS.BLOCKED) {
    return agg.unverified
      ? { state: 'ok_unverified', label: 'Blocked, not fully verified' }
      : { state: 'ok', label: 'Blocked' };
  }
  // ⛔ Nothing permits it AND nothing denies it. For a deny expectation that is
  // NOT a pass: it holds only for as long as no rule is added, and this product
  // has no implicit-policy data to say what happens to unmatched traffic.
  return { state: 'unspecified', label: 'Nothing permits it, and nothing denies it' };
}

module.exports = {
  VERDICTS,
  USED,
  MAX_UNDECIDED_BOXES,
  PORT_MIN,
  PORT_MAX,
  IP_MIN,
  IP_MAX,
  parseCidr,
  ipToString,
  rangeToString,
  makeBox,
  boxVolume,
  intersectBox,
  subtractBox,
  normaliseFlow,
  servicePortRanges,
  addressRanges,
  evaluateFlowOnDevice,
  aggregateFlow,
  usedVerdict,
  flowFinding,
};
