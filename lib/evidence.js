// lib/evidence.js
//
// ⛔ THE POINT OF THIS FILE: every headline number in SecVault must be able to
// answer "how do you know that?" — including, and especially, "what could you
// NOT measure?"
//
// This is CLAUDE.md's most-repeated rule (a failed read is not a measurement)
// promoted from an engine-side discipline to a USER-FACING one. The engines are
// already careful: hit_count is tri-state, `na` is dropped from the compliance
// denominator, an unmeasurable security-score component leaves the denominator
// rather than scoring 0. None of that care was visible on screen. An operator
// saw "51" and had no way to learn that seven checks were unanswerable, or that
// three firewalls contributed nothing to it.
//
// A builder here takes data a caller ALREADY HAS and returns a plain,
// serializable descriptor. It runs no queries, imports no pool and touches no
// database — which is what lets a React SERVER component build one and hand it
// straight to the client drawer as a prop.
//
// ⛔ RULES FOR ADDING A BUILDER, in order of how badly each one bites:
//
//   1. NEVER fabricate an input. If the caller does not have the number, the
//      row does not appear. A plausible-looking "0" in an evidence drawer is
//      strictly worse than the same 0 on a tile, because the drawer is where
//      the operator goes specifically to check.
//   2. `unmeasured` is the reason this file exists. An empty array is a REAL
//      CLAIM — "everything this number depends on was measured" — and the
//      drawer renders it as exactly that sentence. Never leave it empty to
//      mean "I didn't look".
//   3. The formula must be the formula that actually ran. If the engine
//      changes its weights, this string is wrong until someone fixes it, and a
//      confidently-wrong explanation is worse than none. The security-score
//      builder therefore DERIVES its formula from the components the engine
//      returned rather than restating 40/30/30 from memory.
//
// Pure, dependency-free CommonJS — same shape as lib/rbac.js, so tests/ can
// require it with no stubbing and the engine worker could use it if it ever
// needed to.

'use strict';

/**
 * The descriptor a builder returns and `components/ui/Evidence.js` renders.
 *
 * @typedef {Object} Evidence
 * @property {string} title       What the drawer is about, e.g. "Security score 49 / 100".
 * @property {string} claim       One sentence restating what the number ASSERTS.
 * @property {string} formula     The computation, verbatim, as displayed text.
 * @property {{label:string, value:string, note?:string}[]} inputs
 * @property {{label:string, reason:string}[]} unmeasured  [] = everything measured.
 * @property {string} source      The file that computed it — where to go to check.
 * @property {string} [rule]      The CLAUDE.md section that governs it.
 */

/**
 * ⛔ The guard that stops an empty drawer from ever opening.
 *
 * A mark that opens onto nothing is worse than no mark: it promises an
 * explanation and delivers a shrug, which teaches the operator that the
 * affordance is decorative. Call sites render the mark ONLY if this passes.
 */
function isRenderableEvidence(ev) {
  return !!(
    ev &&
    typeof ev.title === 'string' && ev.title.length > 0 &&
    typeof ev.formula === 'string' && ev.formula.length > 0 &&
    Array.isArray(ev.inputs) && ev.inputs.length > 0 &&
    Array.isArray(ev.unmeasured)
  );
}

// ── small shared helpers ────────────────────────────────────────────────────

/** A count that may be absent. Never renders a guessed 0. */
function num(n) {
  return n === null || n === undefined || !Number.isFinite(Number(n))
    ? null
    : Number(n);
}

/** Formats a number for display, or the em-dash that means "not measured". */
function show(n) {
  const v = num(n);
  return v === null ? '—' : v.toLocaleString();
}

function plural(n, one, many) {
  return Number(n) === 1 ? one : (many || `${one}s`);
}

/**
 * The coverage caveat shared by every fleet-wide number: some devices were
 * never assessed, so the figure describes a smaller fleet than the one on
 * screen.
 *
 * ⛔ Returns null when there IS no gap — the caller then reports "everything
 * measured", which is a different and stronger statement than silence.
 */
function cveCoverageGap(headline) {
  const total = num(headline && headline.deviceCount);
  const assessed = num(headline && headline.devicesCveAssessed);
  if (total === null || assessed === null || assessed >= total) return null;
  const missing = total - assessed;
  return {
    label: `${missing} of ${total} ${plural(missing, 'firewall')} never assessed`,
    reason:
      'No CVE assessment has run for these devices, so they contribute nothing to this figure. ' +
      'They are excluded from the denominator rather than counted as clean — a never-assessed ' +
      'device is not a device with no findings.',
  };
}

// ── builders ────────────────────────────────────────────────────────────────

/**
 * Device count. The deliberately BORING one — and it earns its place precisely
 * because it demonstrates the honest positive case: a count of rows really is
 * fully measured, and the drawer says so in as many words.
 */
function deviceCountEvidence(headline) {
  const total = num(headline && headline.deviceCount);
  if (total === null) return null;
  const online = num(headline.devicesOnline);

  const inputs = [{ label: 'Active firewalls', value: show(total) }];
  if (online !== null) {
    inputs.push({ label: 'Reachable at last check', value: show(online) });
    inputs.push({
      label: 'Not reachable',
      value: show(total - online),
      note: 'Still counted — an unreachable firewall is still part of the fleet.',
    });
  }

  return {
    title: `${show(total)} ${plural(total, 'firewall')} under management`,
    claim: 'Every firewall marked active in SecVault, whether or not it answered at the last poll.',
    formula: 'COUNT(*) FROM devices WHERE active = true',
    inputs,
    // ⛔ Genuinely empty, and that is a claim rather than an omission: a row
    // count is a complete measurement of its own question.
    unmeasured: [],
    source: 'lib/engines/fleetHeadline.js',
  };
}

/**
 * Fleet security score. The most composite number in the product and therefore
 * the one most worth decomposing.
 *
 * ⛔ The formula is DERIVED from the components the engine handed back, never
 * restated as a literal "40/30/30". If someone changes the weights in
 * securityScore.js and forgets this file, the drawer still shows the truth.
 */
function securityScoreEvidence(headline) {
  const score = num(headline && headline.securityScore);
  const components = (headline && headline.securityComponents) || [];
  if (!Array.isArray(components) || components.length === 0) return null;

  const measured = components.filter((c) => num(c.score) !== null);
  const dropped = components.filter((c) => num(c.score) === null);
  const measuredWeight = measured.reduce((s, c) => s + (num(c.weight) || 0), 0);
  const totalWeight = components.reduce((s, c) => s + (num(c.weight) || 0), 0);

  const lines = components.map((c) => {
    const s = num(c.score);
    const left = c.label.padEnd(24, ' ');
    return s === null
      ? `  ${left}  not measurable — dropped`
      : `  ${left}  ${String(s).padStart(3, ' ')} × ${c.weight}`;
  });

  const formula = [
    'score = Σ(component × weight) ÷ Σ(weight of MEASURED components)',
    '',
    ...lines,
    '  ' + '─'.repeat(46),
    `  measured weight ${measuredWeight} of ${totalWeight}`,
    '',
    score === null
      ? '  → null. Nothing measurable, so no score is claimed.'
      : `  → ${score} / 100   (higher is better)`,
  ].join('\n');

  const inputs = components.map((c) => ({
    label: c.label,
    value: num(c.score) === null ? '—' : `${c.score} / 100`,
    note: `weight ${c.weight}`,
  }));

  const unmeasured = dropped.map((c) => ({
    label: `${c.label} — not measurable`,
    reason:
      'Dropped from the denominator rather than scored 0. Scoring an unmeasurable component ' +
      'as zero would report a data gap as a security problem, which is how a fresh install ' +
      'ends up looking like a compromised one.',
  }));

  const gap = cveCoverageGap(headline);
  if (gap) unmeasured.push(gap);

  return {
    title: score === null ? 'Security score — not measurable' : `Security score ${score} / 100`,
    claim:
      'A weighted blend of vulnerability posture, rule hygiene and compliance across the ' +
      'fleet. Higher is better.',
    formula,
    inputs,
    unmeasured,
    source: 'lib/engines/securityScore.js',
    rule: 'CLAUDE.md § Fleet & per-device Security Score',
  };
}

/**
 * "Patch now" CVE count.
 *
 * ⛔ The formula shown is the top of the priority decision tree, because that
 * tree — not a CVSS threshold — is what actually put these advisories in this
 * band. Showing "CVSS ≥ 9" would be a plausible lie: rule 1 fires on KEV
 * listing at any CVSS, and rule 2 on observed reachability.
 */
function patchNowEvidence(headline) {
  const count = num(headline && headline.patchNowCount);
  if (count === null) return null;

  const formula = [
    'A device-CVE assessment lands in patch_now when ANY of:',
    '',
    '  1. kev_listed = true   AND version_affected  AND config_applies ≠ no',
    '  2. log_hit    = true   AND version_affected  AND config_applies ≠ no',
    '  3. cvss ≥ 9.0          AND version_affected  AND config_applies = yes',
    '',
    '  + asset_criticality = critical promotes one band',
    '',
    '⛔ config_applies is tri-state. "unknown" never collapses to "no",',
    '   so an uncertain advisory is not silently downgraded.',
  ].join('\n');

  // ⛔ AN ASSESSMENT IS NOT A VULNERABILITY. Each row is a (device, advisory)
  // pair, so one advisory affecting three firewalls is three rows. Measured
  // live: 3 assessments / 3 devices / 1 distinct advisory. Both numbers are
  // shown, each labelled as what it counts, because conflating them is how a
  // single CVE gets reported as a fleet-wide outbreak.
  const devices = num(headline.devicesWithPatchNow);
  const inputs = [
    { label: 'Assessments in patch_now', value: show(count), note: 'one row per device + advisory' },
  ];
  if (devices !== null) {
    inputs.push({ label: 'Firewalls affected', value: show(devices) });
  }
  inputs.push({
    label: 'Firewalls assessed',
    value: show(headline.devicesCveAssessed),
    note: `of ${show(headline.deviceCount)} active`,
  });

  const unmeasured = [];
  const gap = cveCoverageGap(headline);
  if (gap) unmeasured.push(gap);

  return {
    title: devices !== null
      ? `${show(devices)} ${plural(devices, 'firewall')} needing action now`
      : `${show(count)} patch_now ${plural(count, 'assessment')}`,
    claim:
      'These are known-exploited, observed-reachable, or critical-and-applicable on a device ' +
      'running an affected version.',
    formula,
    inputs,
    unmeasured,
    source: 'lib/engines/cveMatcher.js',
    rule: 'CLAUDE.md § Priority Decision Tree',
  };
}

/** Critical + high rule-analysis findings across the fleet. */
function highRiskEvidence(headline) {
  const count = num(headline && headline.highRiskCount);
  if (count === null) return null;

  return {
    title: `${show(count)} high-risk ${plural(count, 'finding')}`,
    claim:
      'Rule-analysis findings at critical or high severity, across every firewall whose ruleset ' +
      'SecVault has collected.',
    formula: [
      "COUNT(*) FROM rule_analysis_results",
      " WHERE severity IN ('critical', 'high')",
      '   AND the device is active',
    ].join('\n'),
    inputs: [
      { label: 'Critical + high findings', value: show(count) },
      { label: 'Rules analysed', value: show(headline.rulesTotal) },
    ],
    unmeasured: [
      {
        label: 'Rules with no usage evidence',
        reason:
          'A rule whose hit_count is NULL was never measured — the vendor or transport cannot ' +
          'report hit counts. Those rules can never produce an "unused" finding, so this count ' +
          'is a floor, not a total. NULL is never coerced to 0.',
      },
    ],
    source: 'lib/engines/ruleAnalysis.js',
    rule: 'CLAUDE.md § A failed read is NOT a measurement',
  };
}

/** Total / enabled rule counts. */
function rulesEvidence(headline) {
  const total = num(headline && headline.rulesTotal);
  if (total === null) return null;
  const enabled = num(headline.rulesEnabled);

  const inputs = [{ label: 'Rules collected', value: show(total) }];
  if (enabled !== null) {
    inputs.push({ label: 'Enabled', value: show(enabled) });
    inputs.push({ label: 'Disabled', value: show(total - enabled) });
  }

  return {
    title: `${show(total)} firewall ${plural(total, 'rule')} collected`,
    claim: 'Every rule SecVault holds for every active firewall, as of the last successful pull.',
    formula: 'COUNT(*) FROM firewall_rules JOIN devices ON active = true',
    inputs,
    unmeasured: [
      {
        label: 'Firewalls whose rule pull failed',
        reason:
          'A failed pull THROWS and leaves the previous ruleset in place rather than writing an ' +
          'empty one, so this total may describe an older snapshot for some devices. It is never ' +
          'reduced to 0 by a collection failure.',
      },
    ],
    source: 'lib/adapters/index.js (collectAndStore)',
    rule: 'CLAUDE.md § Adapter contract',
  };
}

/**
 * Fleet compliance score.
 *
 * ⛔ This is the builder that most justifies the whole feature. The number is
 * computed over pass/fail/warning ONLY — `na` is excluded from the denominator,
 * because an `na` is a limitation of SecVault rather than a fact about the
 * device. That exclusion moved the live fleet from 46% to 51%, and until now
 * there was nowhere on screen an operator could have discovered it.
 */
function complianceScoreEvidence(headline) {
  const score = num(headline && headline.complianceScore);
  const counts = (headline && headline.complianceCounts) || null;

  // Sum the per-standard breakdown the engine already computed. A check
  // counted under two standards is counted twice here, exactly as it is in the
  // score itself — so the arithmetic in the drawer matches the arithmetic that
  // produced the number, rather than being a tidier-looking parallel version.
  let pass = null, fail = null, warning = null;
  if (counts && typeof counts === 'object') {
    pass = 0; fail = 0; warning = 0;
    for (const key of Object.keys(counts)) {
      const c = counts[key] || {};
      pass += num(c.pass) || 0;
      fail += num(c.fail) || 0;
      warning += num(c.warning) || 0;
    }
  }
  const measurable = pass === null ? null : pass + fail + warning;

  if (score === null && measurable === null) return null;

  const formula = [
    'score = round(100 × pass ÷ (pass + fail + warning))',
    '',
    measurable === null
      ? '  counts unavailable at this level'
      : [
          `  pass     ${String(pass).padStart(5, ' ')}`,
          `  fail     ${String(fail).padStart(5, ' ')}`,
          `  warning  ${String(warning).padStart(5, ' ')}`,
          `  ${'─'.repeat(16)}`,
          `  measurable ${String(measurable).padStart(3, ' ')}`,
        ].join('\n'),
    '',
    '⛔ `na` is EXCLUDED from the denominator entirely.',
    '   na = SecVault cannot ask the question of this device.',
    '   warning = we asked, and the answer was indeterminate.',
    '   Only the second is the device\'s problem, so only it counts.',
    '',
    score === null
      ? '  → null, rendered "—". Never 0.'
      : `  → ${score}%`,
  ].join('\n');

  const inputs = [];
  if (measurable !== null) {
    inputs.push({ label: 'Passing', value: show(pass) });
    inputs.push({ label: 'Failing', value: show(fail) });
    inputs.push({ label: 'Warning', value: show(warning), note: 'counts against the score' });
    inputs.push({ label: 'Measurable total', value: show(measurable) });
  }
  inputs.push({ label: 'Score', value: score === null ? '—' : `${score}%` });

  return {
    title: score === null ? 'Compliance — nothing measurable yet' : `Compliance ${score}%`,
    claim:
      'The share of answerable compliance checks that pass, across every firewall with a ' +
      'collected config.',
    formula,
    inputs,
    unmeasured: [
      {
        label: 'Checks marked `na`',
        reason:
          'Excluded from the score, never scored as failures. An `na` means the question cannot ' +
          'be asked of this device at all — nothing the operator changes on the firewall would ' +
          'make it answerable. The findings are still written and still listed, with reasons.',
      },
      {
        label: 'Firewalls with no usable config',
        reason:
          'A device SecVault could not retrieve a parseable config from has no measurable checks ' +
          'and contributes nothing in either direction.',
      },
    ],
    source: 'lib/engines/dashboardSnapshot.js (computeFleetComplianceScores)',
    rule: 'CLAUDE.md § `warning` vs `na` — whose limitation is it?',
  };
}

module.exports = {
  isRenderableEvidence,
  deviceCountEvidence,
  securityScoreEvidence,
  patchNowEvidence,
  highRiskEvidence,
  rulesEvidence,
  complianceScoreEvidence,
  // exported for tests and for future builders
  cveCoverageGap,
};
