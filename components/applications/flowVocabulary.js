// components/applications/flowVocabulary.js
//
// The WORDS and the COLOURS for the application view, in one pure place so a
// verdict cannot acquire a colour in one component and a different meaning in
// another.
//
// ⛔ THE TWO AXES ARE SEPARATE AND MUST STAY SEPARATE. `verdict` answers "does
// any rule permit this"; `used` answers "have the rules that permit it seen
// traffic". Collapsing them into a single status is exactly what this feature
// exists to avoid: a flow nothing has used and a flow whose usage cannot be
// measured are different answers, and the second must never be read as the
// first.
//
// ⛔ `used` NEVER SPEAKS ABOUT THE FLOW. No stored rollup in this product
// carries both ends of a flow, so "this flow carried traffic" is not answerable
// from anything SecVault holds. Every string below therefore says "a rule that
// permits this", never "this flow". If a future edit shortens one of these to
// "in use", it has quietly claimed a measurement nobody made.
//
// ⛔ `unspecified` IS NOT "BLOCKED". Nothing in this codebase knows any
// vendor's default policy, so "no rule decides this" and "this is denied" are
// different statements. The wording below keeps them different, and the chip
// carries no severity hue because "no rule matched" is neither good news nor
// bad.
//
// ⛔ COLOUR MEANS RISK — the palette rule this product is built on. So the two
// FACT columns (permitted / used) are deliberately hueless or muted, and the
// hue lives only on the column that makes a judgement (what it means for the
// application you declared). A green "Permitted" chip would paint a violation
// green on the deny-expectation rows.

// The visual grammar. `hatched` is the hueless "not measured" treatment —
// texture rather than a reassuring grey, because a flat grey reads as a real
// category that happens to be muted.
const NEUTRAL = { bg: 'var(--surface-subtle)', fg: 'var(--text-secondary)', border: 'var(--border)' };
const UNMEASURED = { bg: 'var(--surface-subtle)', fg: 'var(--unmeasured)', border: 'var(--border)', hatched: true };

/** CAN — what the rulebase says. Muted: this is a fact, not a judgement. */
export const PERMITTED_CHIP = {
  permitted: {
    ...NEUTRAL,
    text: 'A rule permits it',
    title:
      'At least one enabled allow rule matches every address and port of this declared flow. '
      + 'That is a statement about the rulebase, not a promise that a packet would arrive — '
      + 'routing, NAT, rule order across different firewalls and security profiles are not modelled.',
  },
  partially_permitted: {
    ...NEUTRAL,
    text: 'Partly permitted',
    title:
      'Some of the declared address/port range is permitted and some of it is not, so the '
      + 'application may work for part of its range and fail for the rest.',
  },
  blocked: {
    ...NEUTRAL,
    text: 'A rule denies it',
    title:
      'Every part of this flow is matched by an enabled deny rule before any allow rule reaches it.',
  },
  // ⛔ NO HUE AND NO "BLOCKED". Nothing matched — which is not the same as a
  // denial, because this product holds no implicit-policy data for any vendor.
  unspecified: {
    ...UNMEASURED,
    hatched: false,
    text: 'No rule decides it',
    title:
      'No enabled rule permits this flow, and none denies it either. SecVault holds no '
      + 'default-policy information for any vendor, so what actually happens to traffic no rule '
      + 'matches is not something this page can tell you.',
  },
  // The flow could not be parsed, so it was never put to the rulebase at all.
  none: {
    ...UNMEASURED,
    text: 'Not evaluated',
    title: 'This flow could not be read as written, so it was never put to the rulebase.',
  },
};

/**
 * DID — and only ever at RULE grain.
 *
 * ⛔ On the reference fleet `unknown` is the COMMON case, not an edge case:
 * Fortinet over SSH reports no hit counts at all, and one permitting rule with
 * no usage data makes the whole answer unknown (that rule might be the one
 * carrying the traffic). This styling is the normal path.
 */
export const USED_CHIP = {
  'rule-active': {
    ...NEUTRAL,
    text: 'A permitting rule is in use',
    title:
      'At least one of the rules that permits this flow has recorded traffic. Where the count is '
      + "the firewall's own counter it is cumulative since that counter was last reset, so the "
      + 'traffic is not necessarily recent — but it did happen. This says nothing about whether '
      + 'the traffic was this flow: no stored log carries both ends of a flow.',
  },
  'rule-idle': {
    ...NEUTRAL,
    text: 'No traffic on any permitting rule',
    title:
      'Every rule that permits this flow can report usage, and all of them report none. A '
      + 'measured zero, not an absence of data.',
  },
  // ⛔ Hueless and hatched. Not measurable is not good news and not bad news,
  // and it must never be drawn the same way as the measured zero above.
  unknown: {
    ...UNMEASURED,
    text: 'Not measurable',
    title:
      'At least one rule permitting this flow cannot report usage — several vendors and '
      + 'transports report no hit counts at all — so whether anything used it cannot be '
      + 'determined. Assume it is live.',
  },
  none: {
    ...UNMEASURED,
    text: 'Not evaluated',
    title: 'This flow could not be read as written, so no usage question was asked.',
  },
};

/**
 * What it MEANS for the application that was declared — the only hued column.
 *
 * ⛔ An all-clear is forbidden while anything is unverified, so `ok_unverified`
 * is hueless and hatched rather than green. A clean result over partial
 * coverage is the most dangerous thing this page could print.
 */
export const FINDING_CHIP = {
  ok: {
    bg: 'var(--tint-success)', fg: 'var(--tint-success-fg)', border: 'var(--sev-ok)',
    title: 'The rulebase matches what you declared, and everything it depends on was measured.',
  },
  ok_unverified: {
    ...UNMEASURED,
    title:
      'The rulebase matches what you declared, but not everything this answer rests on could be '
      + 'measured — so it is shown without a colour rather than as an all-clear.',
  },
  broken: {
    bg: 'var(--tint-danger)', fg: 'var(--tint-danger-fg)', border: 'var(--sev-crit)',
    title: 'You declared that this must work, and a rule denies it.',
  },
  violation: {
    bg: 'var(--tint-danger)', fg: 'var(--tint-danger-fg)', border: 'var(--sev-crit)',
    title: 'You declared that this must not be possible, and a rule permits it.',
  },
  partial: {
    bg: 'var(--tint-warn)', fg: 'var(--tint-warn-fg)', border: 'var(--sev-med)',
    title: 'Only part of the declared range is permitted, so this will work for some addresses and not others.',
  },
  unspecified: {
    ...UNMEASURED,
    hatched: false,
    title:
      'Nothing in the collected rulebase decides this flow either way, and SecVault has no '
      + 'default-policy data for any vendor.',
  },
  invalid: {
    ...UNMEASURED,
    title: 'This flow could not be read as written, so it has never been evaluated against anything.',
  },
};

/** Application-level roll-up, straight from the engine's summary.state. */
export const APP_STATE_CHIP = {
  ok: {
    bg: 'var(--tint-success)', fg: 'var(--tint-success-fg)', border: 'var(--sev-ok)',
    text: 'Matches the rulebase',
    title: 'Every declared flow matches what the rules permit, and everything it rests on was measured.',
  },
  problem: {
    bg: 'var(--tint-danger)', fg: 'var(--tint-danger-fg)', border: 'var(--sev-crit)',
    text: 'Needs attention',
    title: 'At least one declared flow does not match what the rules permit.',
  },
  unverified: {
    ...UNMEASURED,
    text: 'Not fully verified',
    title:
      'Nothing is outstanding, but at least one flow could not be fully verified — so this is not '
      + 'shown as an all-clear.',
  },
  undeclared: {
    ...UNMEASURED,
    hatched: false,
    text: 'No flows declared',
    title: 'This application exists but has no declared flows, so nothing about it has been checked.',
  },
};

/** Fallback for a state this file has not been taught. Never a hue. */
export const UNKNOWN_CHIP = { ...UNMEASURED, text: 'Unknown', title: 'SecVault does not recognise this state.' };

export function permittedChip(evaluated) {
  if (!evaluated || evaluated.invalid || !evaluated.verdict) return PERMITTED_CHIP.none;
  return PERMITTED_CHIP[evaluated.verdict] || UNKNOWN_CHIP;
}

export function usedChip(evaluated) {
  if (!evaluated || evaluated.invalid || !evaluated.used) return USED_CHIP.none;
  return USED_CHIP[evaluated.used] || UNKNOWN_CHIP;
}

export function findingChip(evaluated) {
  const state = evaluated && evaluated.finding ? evaluated.finding.state : null;
  return (state && FINDING_CHIP[state]) || UNKNOWN_CHIP;
}

export function appStateChip(summary) {
  const state = summary && summary.state;
  return (state && APP_STATE_CHIP[state]) || UNKNOWN_CHIP;
}

// ── flow formatting ────────────────────────────────────────────────────────

/**
 * ⛔ A NULL PORT RANGE MEANS EVERY PORT OF THE PROTOCOL, and the schema says so.
 * Printing an empty cell there would read as "no ports", which is the opposite
 * of what was declared and the opposite of what was evaluated.
 */
export function portLabel(flow) {
  const start = flow && flow.port_start;
  const end = flow && flow.port_end;
  if (start === null || start === undefined) return 'all ports';
  if (end === null || end === undefined || Number(end) === Number(start)) return String(start);
  return `${start}-${end}`;
}

export function serviceLabel(flow) {
  const proto = String((flow && flow.protocol) || 'tcp').toLowerCase();
  return `${proto}/${portLabel(flow)}`;
}

export function endpointsLabel(flow) {
  return `${(flow && flow.src) || '?'} → ${(flow && flow.dst) || '?'}`;
}

export function expectationLabel(flow) {
  return flow && flow.expectation === 'deny' ? 'must NOT connect' : 'must connect';
}

/** Percentage of the declared range that is permitted, when it is meaningful. */
export function permittedPctLabel(evaluated) {
  const pct = evaluated && evaluated.permittedPct;
  if (pct === null || pct === undefined || !Number.isFinite(Number(pct))) return null;
  if (Number(pct) >= 100 || Number(pct) <= 0) return null;
  return `${Number(pct)}% of the declared range`;
}
