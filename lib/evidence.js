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
//   3. ⛔ `source` AND `rule` ARE CUSTOMER-FACING PROSE, NOT DEVELOPER NOTES.
//      They render verbatim in the drawer footer, which a buyer reads. Use the
//      PRODUCT name of the engine ('CVE prioritisation engine') and a SecVault
//      POLICY name ('SecVault vulnerability policy — Priority Decision Tree').
//      Never a source path and never CLAUDE.md: one tells a customer how the
//      sausage is made, the other advertises that an AI assistant's instruction
//      file governs their security tooling. Pinned by tests/noInternalRefs.test.js.
//   4. The formula must be the formula that actually ran. If the engine
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
    source: 'Fleet inventory',
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
    source: 'Security scoring engine',
    rule: 'SecVault scoring policy — Fleet Security Score',
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
    source: 'CVE prioritisation engine',
    rule: 'SecVault vulnerability policy — Priority Decision Tree',
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
    source: 'Rule analysis engine',
    rule: 'SecVault measurement policy — a failed read is never a measurement',
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
    source: 'Rule collection pipeline',
    rule: 'SecVault collection policy — a failed pull never overwrites a ruleset',
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
  //
  // ⛔ AN EMPTY COUNTS OBJECT IS NOT THREE ZEROS. This read
  // `if (counts && typeof counts === 'object') { pass = 0; fail = 0; warning = 0; … }`
  // — and `{}` is truthy, so the accumulators were initialised, the loop body
  // never ran, and three fabricated zeros survived into `measurable`. The
  // drawer then rendered "Passing 0 · Failing 0 · Warning 0 · Measurable total
  // 0" beside a Score of "—": four confident numbers manufactured from an
  // object that carried none, in the one place an operator opens SPECIFICALLY
  // to check where a figure came from. That is this file's own Rule 1 violated
  // by the builder for the number Rule 1 was written about.
  //
  // The accumulators therefore stay null until a standard actually contributes
  // a finite count. A standard present but carrying no numbers contributes
  // nothing and cannot, by itself, promote the totals from "not measured" to
  // "measured as zero".
  let pass = null, fail = null, warning = null;
  if (counts && typeof counts === 'object') {
    for (const key of Object.keys(counts)) {
      const c = counts[key] || {};
      const p = num(c.pass), f = num(c.fail), w = num(c.warning);
      if (p === null && f === null && w === null) continue;
      pass = (pass || 0) + (p || 0);
      fail = (fail || 0) + (f || 0);
      warning = (warning || 0) + (w || 0);
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
    source: 'Compliance scoring engine',
    rule: 'SecVault compliance policy — not-applicable checks are excluded from scoring',
  };
}

/**
 * CVE posture (the /vulnerability tiles).
 *
 * ⛔ TWO UNITS, AND THE PAGE ALREADY KNOWS THE DIFFERENCE — this builder must
 * not undo that. `*_cves` counts DISTINCT advisories; `*_count` counts
 * device-CVE PAIRS. Live on 2026-09-09 the tiles briefly read
 * "Unique CVEs 26 · Patch Now 3 · Scheduled 163" — three numbers summing to 166
 * under a headline of 26. Both units appear here, each labelled, because the
 * second is genuinely useful ("163 pairs across 25 CVEs") and only dangerous
 * when unlabelled.
 */
function cvePostureEvidence(summary, coverage) {
  const s = summary || {};
  const c = coverage || {};
  const distinct = num(s.total_cves);
  if (distinct === null) return null;

  const active = num(c.active_devices);
  const assessed = num(c.devices_assessed);
  const versioned = num(c.devices_with_version);

  const band = (label, cves, pairs) =>
    '  ' + label.padEnd(12, ' ') + String(show(cves)).padStart(5, ' ') + ' CVEs   '
    + show(pairs) + ' device-CVE pairs';

  const formula = [
    'Each band is COUNT(DISTINCT advisory_id) over device_cve_assessments,',
    'so a tile and the table it filters agree on one number.',
    '',
    band('patch_now', s.patch_now_cves, s.patch_now_count),
    band('scheduled', s.scheduled_cves, s.scheduled_count),
    band('monitor', s.monitor_cves, s.monitor_count),
    '',
    '⛔ The two columns measure different things and never sum together.',
  ].join('\n');

  const inputs = [
    { label: 'Distinct CVEs assessed', value: show(distinct) },
    {
      label: 'Firewalls with a completed assessment',
      value: show(assessed),
      note: 'of ' + show(active) + ' active',
    },
    {
      label: 'Firewalls with a collected firmware version',
      value: show(versioned),
      note: 'a precondition, not proof of assessment',
    },
  ];

  const unmeasured = [];
  if (active !== null && assessed !== null && assessed < active) {
    unmeasured.push({
      label: (active - assessed) + ' of ' + active + ' firewalls carry no completed assessment',
      reason:
        'No assessment run is stamped for these devices, so they contribute nothing to any band. ' +
        'Their absence is why these tiles are a floor, not a total — an unassessed firewall is ' +
        'not a firewall with no CVEs.',
    });
  }
  if (versioned !== null && active !== null && versioned < active) {
    unmeasured.push({
      label: (active - versioned) + ' firewalls have no collected firmware version',
      reason:
        'Version matching cannot run without one, so no advisory can be judged applicable or not ' +
        'for these devices. ⛔ A version row is a PRECONDITION for assessment and never evidence ' +
        'that one happened.',
    });
  }

  return {
    title: show(distinct) + ' distinct ' + plural(distinct, 'CVE') + ' assessed across the fleet',
    claim:
      'Advisories matched to a device by firmware version and config applicability, then banded ' +
      'by the priority decision tree.',
    formula,
    inputs,
    unmeasured,
    source: 'CVE assessment store',
    rule: 'SecVault vulnerability policy — Priority Decision Tree',
  };
}

/**
 * One firewall's compliance posture.
 *
 * ⛔ The `na` row is the whole point. See complianceScoreEvidence for the fleet
 * form of the same argument: `warning` is a fact about the DEVICE, `na` is a
 * fact about SECVAULT, and only the first may count against a score.
 */
function deviceComplianceEvidence(counts, deviceName) {
  const c = counts || {};
  const pass = num(c.pass);
  const fail = num(c.fail);
  const warning = num(c.warning);
  const na = num(c.na);
  if (pass === null || fail === null || warning === null) return null;

  const measurable = pass + fail + warning;
  const score = measurable > 0 ? Math.round((pass / measurable) * 100) : null;
  // ⛔ `na` HAS ITS OWN ABSENT STATE and it used to be flattened to 0 here, so
  // a caller that did not supply the bucket got a drawer stating "Not
  // applicable 0" and a formula line reading "na 0 EXCLUDED" — an explicit,
  // itemised claim that nothing was unanswerable on this firewall, made from a
  // field nobody read. `na` is the row this whole builder exists to show; it is
  // the last one that may be invented. Displayed through show(), so an absent
  // bucket is an em-dash. The `> 0` tests below are unaffected: null > 0 is
  // false, so a missing bucket adds no unmeasured entry either.
  const naCount = na;
  const who = deviceName || 'This firewall';

  const formula = [
    'score = round(100 × pass ÷ (pass + fail + warning))',
    '',
    '  pass     ' + String(pass).padStart(5, ' '),
    '  fail     ' + String(fail).padStart(5, ' '),
    '  warning  ' + String(warning).padStart(5, ' '),
    '  ' + '─'.repeat(16),
    '  measurable ' + String(measurable).padStart(3, ' '),
    '  na         ' + String(show(naCount)).padStart(3, ' ') + '  EXCLUDED',
    '',
    score === null
      ? '  → null, rendered "—". Never 0: nothing was answerable.'
      : '  → ' + score + '%',
  ].join('\n');

  const inputs = [
    { label: 'Passing', value: show(pass) },
    { label: 'Failing', value: show(fail) },
    { label: 'Warning', value: show(warning), note: 'indeterminate on a config we DID collect' },
    { label: 'Not applicable', value: show(naCount), note: 'excluded from the score' },
    { label: 'Score', value: score === null ? '—' : score + '%' },
  ];

  const unmeasured = naCount > 0
    ? [{
        label: naCount + ' ' + plural(naCount, 'check') + ' cannot be asked of this firewall',
        reason:
          'Either the check needs telemetry a static config never contains, or it is inherently ' +
          'per-rule while the predicate engine evaluates one fixed path. Nothing the operator ' +
          'could change on the firewall would make these answerable, so scoring them down would ' +
          'record SecVault\'s limitation as the device\'s problem. They are still listed, with ' +
          'reasons.',
      }]
    : [];

  return {
    title: score === null
      ? who + ' — nothing measurable'
      : who + ' — ' + score + '% compliant',
    claim: 'The share of answerable compliance checks this firewall passes.',
    formula,
    inputs,
    unmeasured,
    source: 'Compliance audit engine',
    rule: 'SecVault compliance policy — not-applicable checks are excluded from scoring',
  };
}

/**
 * Fleet rule hygiene.
 *
 * ⛔ THE CANONICAL TRI-STATE, and the clearest demonstration of what this
 * product does that its competitors do not. hit_count is a real count, a
 * MEASURED zero, or NULL meaning never measured. Only a measured zero can
 * produce an `unused` finding. Every competing tool renders the NULLs as 0 and
 * recommends deleting those rules.
 */
function ruleHygieneEvidence(totals, hitCoverage) {
  const t = totals || {};
  const h = hitCoverage || {};
  const findings = num(t.total);
  if (findings === null) return null;

  const rules = num(h.total);
  const notMeasured = num(h.not_measured);
  const measuredZero = num(h.measured_zero);
  const withHits = num(h.with_hits);

  const lines = [
    'Findings by severity:',
    '  critical ' + String(show(t.critical)).padStart(6, ' '),
    '  high     ' + String(show(t.high)).padStart(6, ' '),
    '  medium   ' + String(show(t.medium)).padStart(6, ' '),
    '  info     ' + String(show(t.info)).padStart(6, ' '),
  ];

  if (rules !== null && notMeasured !== null) {
    lines.push(
      '',
      'Rule usage evidence (hit_count is TRI-STATE):',
      '  with hits      ' + String(show(withHits)).padStart(6, ' ') + '  measured, non-zero',
      '  measured zero  ' + String(show(measuredZero)).padStart(6, ' ') + '  a real, earned zero',
      '  NOT MEASURED   ' + String(show(notMeasured)).padStart(6, ' ') + '  vendor cannot report it',
      '',
      '⛔ Only a MEASURED zero can produce an `unused` finding.',
      '   NULL is never coerced to 0, in a query, a renderer or an engine.'
    );
  }

  // ⛔ A SUM OF TWO ABSENT NUMBERS IS NOT ZERO. Both of these were written as
  // `(a || 0) + (b || 0)`, which renders a confident "0" when NEITHER input was
  // supplied — and on this page the two fabrications say the worst possible
  // things: "Critical + high 0" is an all-clear, and "Rules with usage evidence
  // 0" would have an operator believe the fleet reports no hit counts at all.
  // A sum is only a measurement if at least one addend was measured.
  const sumOrNull = (a, b) => (num(a) === null && num(b) === null ? null : (num(a) || 0) + (num(b) || 0));

  const inputs = [
    { label: 'Total findings', value: show(findings) },
    { label: 'Critical + high', value: show(sumOrNull(t.critical, t.high)) },
  ];
  if (rules !== null) {
    inputs.push({ label: 'Rules analysed', value: show(rules) });
    inputs.push({
      label: 'Rules with usage evidence',
      value: show(sumOrNull(withHits, measuredZero)),
    });
    inputs.push({ label: 'Rules with NO usage evidence', value: show(notMeasured) });
  }

  const unmeasured = [];
  if (notMeasured !== null && notMeasured > 0) {
    const pct = rules ? Math.round((notMeasured / rules) * 100) : null;
    unmeasured.push({
      label:
        notMeasured + ' ' + plural(notMeasured, 'rule') + ' have no usage data'
        + (pct === null ? '' : ' (' + pct + '% of the ruleset)'),
      reason:
        'Their hit_count is NULL — the vendor or transport cannot report hit counts at all ' +
        '(Fortinet over SSH, Palo Alto over SSH, Sangfor). These rules can never produce an ' +
        '"unused" finding and are REFUSED from cleanup requests server-side rather than merely ' +
        'flagged: "we cannot tell whether this rule is used" is not a reason to delete it.',
    });
  }

  return {
    title: show(findings) + ' rule ' + plural(findings, 'finding') + ' across the fleet',
    claim:
      'Findings from the rule-analysis engine over every firewall whose ruleset has been ' +
      'collected. Usage-based findings rest on measured hit counts only.',
    formula: lines.join('\n'),
    inputs,
    unmeasured,
    source: 'Rule analysis engine',
    rule: 'SecVault measurement policy — a failed read is never a measurement',
  };
}

/**
 * Licence / support lifecycle.
 *
 * ⛔ EXPIRY IS TRI-STATE and the third state is the dangerous one. A NULL
 * expires_at means PERPETUAL when expires_raw says 'Never', and UNKNOWN
 * otherwise. Treating an unparsed expiry as "fine" is how a support contract
 * lapses while the dashboard stays green — so the unknown bucket is counted and
 * reported, never folded into either neighbour.
 */
function lifecycleEvidence(counts) {
  const c = counts || {};
  const expired = num(c.expired);
  const expiring = num(c.expiring);
  if (expired === null || expiring === null) return null;

  // ⛔ NOT `|| 0`. Each of these four is DISPLAYED, in the formula block and in
  // the inputs, so an absent bucket coerced to zero becomes an itemised claim:
  // "unknown 0 — no parseable expiry date" asserts that every expiry on the
  // fleet parsed, which is the exact reassurance this builder's own header
  // comment says must never be manufactured. show() renders a null as the
  // em-dash that means not measured; the `> 0` tests below are unaffected.
  const unknown = num(c.unknown);
  const perpetual = num(c.perpetual);
  const noLicenceData = num(c.devicesWithoutLicenceData);
  const activeDevices = num(c.activeDevices);
  const haWithData = num(c.devicesWithHaData);

  const formula = [
    'Each renewal event is grouped per (device, expiry date) and ranked:',
    '',
    '  expired    ' + String(expired).padStart(5, ' '),
    '  expiring   ' + String(expiring).padStart(5, ' ') + '  within 60 days',
    '  unknown    ' + String(show(unknown)).padStart(5, ' ') + '  no parseable expiry date',
    '  perpetual  ' + String(show(perpetual)).padStart(5, ' ') + "  reported as 'Never'",
    '',
    '⛔ A NULL expiry is PERPETUAL only when the device said so verbatim.',
    '   Any other NULL is UNKNOWN and is never read as healthy.',
  ].join('\n');

  const inputs = [
    { label: 'Expired entitlements', value: show(expired) },
    { label: 'Expiring within 60 days', value: show(expiring) },
    { label: 'Expiry not parseable', value: show(unknown), note: 'never treated as fine' },
    { label: 'Perpetual', value: show(perpetual) },
  ];
  if (activeDevices !== null) {
    inputs.push({
      label: 'Firewalls with licence data',
      // ⛔ A SUBTRACTION IS ONLY A MEASUREMENT IF BOTH TERMS WERE MEASURED. With
      // the no-data count absent this read `activeDevices - 0` and reported the
      // ENTIRE fleet as licence-covered — the strongest possible statement about
      // coverage, produced by the absence of the coverage number.
      value: noLicenceData === null ? '—' : show(activeDevices - noLicenceData),
      note: 'of ' + show(activeDevices) + ' active',
    });
  }
  if (haWithData !== null) {
    inputs.push({ label: 'Firewalls reporting HA state', value: show(haWithData) });
  }

  const unmeasured = [];
  if (unknown > 0) {
    unmeasured.push({
      label: unknown + ' ' + plural(unknown, 'entitlement') + ' with no parseable expiry',
      reason:
        'The device reported an expiry SecVault could not turn into a date, and did not report ' +
        "it as 'Never'. These are shown as unknown rather than assumed current — an unparsed " +
        'expiry read as healthy is how a contract lapses with nothing on screen to warn you.',
    });
  }
  if (noLicenceData > 0) {
    unmeasured.push({
      label: noLicenceData + ' ' + plural(noLicenceData, 'firewall') + ' report no licence data at all',
      reason:
        'Licence and support-contract collection is implemented for Palo Alto (both transports) ' +
        'and Fortinet over SSH. Other vendors and transports supply nothing, so these firewalls ' +
        'contribute no renewal events in either direction — their contracts are not known to be ' +
        'current, they are simply not known.',
    });
  }

  return {
    title: expired > 0
      ? show(expired) + ' expired ' + plural(expired, 'entitlement')
      : 'Support and licence lifecycle',
    claim:
      'Support contracts and feature entitlements collected from each firewall, grouped into ' +
      'renewal events.',
    formula,
    inputs,
    unmeasured,
    source: 'Lifecycle collection',
    rule: 'SecVault lifecycle policy — an unparsed expiry is unknown, never current',
  };
}

/**
 * Fleet device inventory (the /devices tiles).
 *
 * ⛔ THE TWO CVE TILES ARE FLEET SUMS, so a never-assessed device contributes
 * 0 to each — identically to a device assessed and found clean. That is the
 * whole reason cveNotAssessed exists on the tiles object, and this builder's
 * job is to put it in front of the reader.
 */
function deviceInventoryEvidence(tiles) {
  const t = tiles || {};
  const total = num(t.total);
  if (total === null) return null;

  const online = num(t.online);
  // ⛔ `neverChecked` is DISPLAYED (a formula line and an input row), so it may
  // not be defaulted: "never probed 0" states that every firewall has a
  // connectivity result on record, which is a coverage claim rather than a
  // count. The other two are only `> 0` triggers for unmeasured entries and
  // keep their coercion — an absent gap counter must not invent a gap either.
  const neverChecked = num(t.neverChecked);
  const notAssessed = num(t.cveNotAssessed) || 0;
  const noVersion = num(t.cveNoVersion) || 0;

  const formula = [
    'Every tile counts ACTIVE firewalls; the two CVE tiles are fleet SUMS.',
    '',
    '  firewalls          ' + String(show(total)).padStart(6, ' '),
    '  reachable          ' + String(show(online)).padStart(6, ' '),
    '  never probed       ' + String(show(neverChecked)).padStart(6, ' '),
    '  patch_now findings ' + String(show(t.patchNow)).padStart(6, ' ')
      + '  on ' + show(t.patchNowDevices) + ' firewalls',
    '',
    '⛔ A never-assessed firewall adds 0 to the CVE sums, exactly like a',
    '   firewall assessed and found clean. The two are not the same fact.',
  ].join('\n');

  const inputs = [
    { label: 'Active firewalls', value: show(total) },
    { label: 'Reachable at last check', value: show(online) },
    { label: 'Never probed', value: show(neverChecked), note: 'no connectivity result on record' },
    { label: 'Critical CVE findings', value: show(t.criticalCves), note: 'on ' + show(t.criticalCveDevices) + ' firewalls' },
    { label: 'Patch-now findings', value: show(t.patchNow), note: 'on ' + show(t.patchNowDevices) + ' firewalls' },
  ];

  const unmeasured = [];
  if (notAssessed > 0) {
    unmeasured.push({
      label: notAssessed + ' ' + plural(notAssessed, 'firewall') + ' never CVE-assessed',
      reason:
        'SecVault holds no evidence of a completed match for these devices, so they add 0 to ' +
        'both CVE tiles — the same contribution as a firewall that was assessed and found clean. ' +
        'The two are different facts and only one of them is good news.',
    });
  }
  if (noVersion > 0) {
    unmeasured.push({
      label: noVersion + ' ' + plural(noVersion, 'firewall') + ' have no firmware version collected',
      reason:
        'Version matching cannot begin without one, so these devices are skipped by the matcher ' +
        'outright. This is the nameable subset of the gap above: "we could not ask" rather than ' +
        '"we have not asked yet", and it needs a collection, not a re-run.',
    });
  }
  if (neverChecked > 0) {
    unmeasured.push({
      label: neverChecked + ' ' + plural(neverChecked, 'firewall') + ' have never been probed',
      reason:
        'No connectivity result is on record, so these are neither online nor offline. They are ' +
        'counted in the fleet total but not in the reachable count.',
    });
  }

  return {
    title: show(total) + ' ' + plural(total, 'firewall') + ' under management',
    claim: 'Every active firewall, with its collection and vulnerability-assessment coverage.',
    formula,
    inputs,
    unmeasured,
    source: 'Device inventory',
    rule: 'SecVault measurement policy — a failed read is never a measurement',
  };
}

/**
 * Internet exposure paths.
 *
 * ⛔ 'NOT SEEN' AND 'NOT MEASURED' ARE DIFFERENT and the page already draws
 * them differently. A path with no observed traffic is still OPEN; a path on a
 * device sending no syslog was never watched at all. Collapsing them would turn
 * a monitoring gap into a clean bill of health.
 */
function exposureEvidence(totals, errorCount) {
  const t = totals || {};
  const paths = num(t.paths);
  if (paths === null) return null;

  // ⛔ NOT `|| 0` for the three PATH buckets. They are printed as a three-line
  // breakdown that sums to `paths`, so a defaulted zero does not read as a gap
  // — it reads as an arithmetic fact. "reached 0" in particular is the single
  // most reassuring line this drawer can print, and defaulting it would print
  // it for a caller that supplied no traffic evidence at all. The device-level
  // counters below keep their `|| 0`: each is used only as a `> 0` trigger for
  // an unmeasured entry, never displayed as a figure.
  const observed = num(t.observed);
  const notObserved = num(t.notObserved);
  const unmeasuredPaths = num(t.unmeasured);
  const noSyslog = num(t.devicesWithoutSyslog) || 0;
  const noInbound = num(t.devicesWithoutInboundCoverage) || 0;
  const failed = num(errorCount) || 0;

  const formula = [
    'Each exposure path is a public source reaching a device service.',
    '',
    '  reached       ' + String(show(observed)).padStart(6, ' ') + '  traffic observed arriving',
    '  not seen      ' + String(show(notObserved)).padStart(6, ' ') + '  watched, no traffic — still OPEN',
    '  NOT MEASURED  ' + String(show(unmeasuredPaths)).padStart(6, ' ') + '  never watched',
    '  ' + '─'.repeat(30),
    '  paths         ' + String(paths).padStart(6, ' '),
    '',
    "⛔ 'not seen' is not 'closed'. An open path with no traffic in the",
    '   window is still an open path.',
  ].join('\n');

  const inputs = [
    { label: 'Exposure paths', value: show(paths), note: 'across ' + show(t.devicesWithExposure) + ' firewalls' },
    { label: 'Reached from a public source', value: show(observed) },
    { label: 'Watched, no traffic seen', value: show(notObserved), note: 'still open' },
    { label: 'Never watched', value: show(unmeasuredPaths) },
    { label: 'Public addresses on interfaces', value: show(t.publicIps) },
  ];

  const unmeasured = [];
  if (unmeasuredPaths > 0 || noSyslog > 0) {
    unmeasured.push({
      label: unmeasuredPaths > 0
        ? unmeasuredPaths + ' ' + plural(unmeasuredPaths, 'path') + ' were never watched'
        : noSyslog + ' ' + plural(noSyslog, 'firewall') + ' send no syslog',
      reason:
        'Without syslog from the device there is no traffic evidence either way, so these paths ' +
        'cannot be called reached OR unreached. They are open paths with no observation behind ' +
        'them — the absence of evidence, not evidence of absence.',
    });
  }
  if (noInbound > 0) {
    unmeasured.push({
      label: noInbound + ' ' + plural(noInbound, 'firewall') + ' have no inbound-traffic coverage',
      reason:
        'The device sends syslog, but nothing in the window recorded traffic arriving at its own ' +
        'interfaces — so traffic TO the device cannot be distinguished from traffic THROUGH it.',
    });
  }
  if (failed > 0) {
    unmeasured.push({
      label: failed + ' ' + plural(failed, 'firewall') + ' could not be analysed',
      reason:
        'These devices errored during analysis and are NOT represented in any total above. The ' +
        'figures describe a smaller fleet than the one on screen.',
    });
  }

  return {
    title: show(paths) + ' internet exposure ' + plural(paths, 'path'),
    claim:
      'Paths by which a public source can reach a service on a managed firewall, with whatever ' +
      'traffic evidence exists for each.',
    formula,
    inputs,
    unmeasured,
    source: 'Exposure analysis',
    rule: 'SecVault measurement policy — a failed read is never a measurement',
  };
}

/**
 * Segmentation intent.
 *
 * ⛔ THE FORMULA SPELLS OUT WHAT 'CAN' ACTUALLY CLAIMS. It means an enabled
 * allow rule matches the zone pair — NOT that a packet would pass. Addresses,
 * services, profiles and rule order all still apply and are deliberately not
 * modelled. On a security product, an operator who trusts 'reachable' and later
 * finds it was a guess stops trusting the honest answers too.
 */
function segmentationEvidence(result) {
  if (!result || !Array.isArray(result.intents)) return null;
  const s = result.summary || {};
  const total = num(s.total) || 0;
  if (total === 0) return null;

  const formula = [
    'Each declared pair is tested TWICE:',
    '',
    "  CAN  an enabled rule whose action is allow/accept/permit",
    "       matches (source zone, destination zone). 'any' counts",
    '       as a wildcard on either side.',
    "  DID  any of those permitting rules has a measured hit count",
    // ⛔ An absent windowDays printed the literal string "over the last
    // undefined days" — a formula this drawer promises is "the formula that
    // actually ran". Name the window as unstated rather than printing a
    // placeholder as if it were the measurement.
    // ⛔ AND THE WINDOW IS NOT THE WHOLE TRUTH EITHER. This read "above zero,
    // over the last N days", which is only accurate for the rules whose usage
    // came from LOGS. Where a firewall reports its own hit counter, that
    // counter is cumulative since it was last reset — so on the live fleet,
    // 1,524 of 1,757 rules, "over the last 30 days" describes a number that may
    // date from years ago. The drawer's whole promise is that it shows the
    // formula that actually ran, which makes a tightened-up window the one
    // detail it cannot afford to invent.
    //
    // The error direction is the tolerable one — it overstates a violation and
    // suppresses a removal candidate, rather than recommending a deletion — but
    // overclaiming precision here is what teaches an operator to discount the
    // honest parts of the same panel.
    result.windowDays === null || result.windowDays === undefined
      ? '       above zero. Log-derived usage covers the evidence window'
        + ' (length not reported); a firewall’s own hit counter is'
        + ' cumulative since it was last reset.'
      : '       above zero. Log-derived usage covers the last '
        + result.windowDays + ' days; a firewall’s own hit counter is'
        + ' cumulative since it was last reset, so it may predate that.',
    '',
    '⛔ CAN does NOT mean a packet would pass. Addresses, services,',
    '   profiles and rule order still apply and are not modelled here.',
    '',
    '⛔ DID is TRI-STATE. If even ONE permitting rule cannot report',
    '   usage, the pair is UNKNOWN — never "never used". That one rule',
    '   might be the one carrying the traffic.',
  ].join('\n');

  const inputs = [
    { label: 'Declared paths', value: show(total) },
    { label: 'Violations', value: show(s.violations), note: show(s.activeViolations) + ' with observed traffic' },
    { label: 'Permitted but unused', value: show(s.unusedPermissions), note: 'removal candidates' },
    { label: 'Rules evaluated', value: show(result.ruleCount), note: 'across ' + show(result.deviceCount) + ' firewalls' },
  ];

  const unmeasured = [];
  if (num(s.unmeasurable) > 0) {
    unmeasured.push({
      label: num(s.unmeasurable) + ' of ' + total + ' paths could not be fully measured',
      reason:
        'At least one rule permitting each of these paths cannot report whether it was used, so ' +
        'the path is reported as unknown rather than unused. Calling it unused would recommend ' +
        'removing a rule that may be carrying production traffic.',
    });
  }
  if (num(result.rulesWithoutHitData) > 0) {
    const n = num(result.rulesWithoutHitData);
    unmeasured.push({
      // 'rules' was hardcoded plural, so a single one read "1 rules cannot
      // report usage at all" — the nearly-clean-fleet misreading again.
      label: Number(n).toLocaleString() + ' ' + plural(n, 'rule') + ' cannot report usage at all',
      reason:
        'The vendor or transport supplies no hit counts (Fortinet over SSH, Palo Alto over SSH, ' +
        'Sangfor). Their silence measures SecVault\'s reach, not the traffic.',
    });
  }
  if (result.rulesCollected === false) {
    unmeasured.push({
      label: 'No rulesets have been collected',
      reason:
        'Every path is unknown. Without a ruleset the matrix would otherwise report every ' +
        'deny-intent as satisfied — a perfect score computed entirely from missing data.',
    });
  }

  return {
    title: total + ' declared segmentation ' + plural(total, 'boundary', 'boundaries'),
    claim: 'What you declared must not connect, checked against the rules and the traffic.',
    formula,
    inputs,
    unmeasured,
    source: 'Segmentation engine',
    rule: 'SecVault measurement policy — a failed read is never a measurement',
  };
}


// ── Applications (v2.124.0) ───────────────────────────────────────────────
// ⛔ rollUp is IMPORTED from lib/answers.js, not re-derived. The drawer must
// count a problem exactly the way the sentence above it does, or the page
// contradicts itself in two places a reader sees at once.
const { rollUpApplications: rollUp } = require('./answers');

function applicationsEvidence(result) {
  const r = rollUp(result);
  if (!r || r.readFailed) return null;
  // ⛔ NO DRAWER OVER NOTHING. With no flows evaluated the descriptor would read
  // "0 of 0 match the rules" — a confident-looking ratio computed from a
  // measurement that never happened. The headline sentence already says nothing
  // has been declared; a drawer restating it as a figure is worse than absent.
  if (r.flows === 0 || r.fleetFailed) return null;

  const cov = (result && result.coverage) || null;
  const orphans = (result && result.orphans) || null;

  const inputs = [
    { label: 'Applications declared', value: String(r.apps) },
    { label: 'Flows declared', value: String(r.flows) },
    {
      label: 'Flows matching what was declared',
      value: `${r.ok} of ${r.flows}`,
      note: 'Permitted where an allow was declared; denied where a denial was declared.',
    },
  ];
  if (cov) {
    inputs.push({
      label: 'Firewalls with a collected ruleset',
      value: `${cov.devicesWithRules} of ${cov.activeDeviceCount}`,
      note: 'Every declared flow is evaluated against each of them independently.',
    });
  }
  // ⛔ `Number.isFinite(Number(x))` IS NOT A MEASURED-AT-ALL TEST. Number(null)
  // is 0 and 0 is finite, so a null window walks straight through it and the
  // row renders "null days" — a stated measurement with no measurement behind
  // it. evaluateAllApplications() really does return `windowDays: null` on both
  // of its early-error paths, and segmentationEvidence() 100 lines above
  // already carries the explicit check plus a comment recording that this
  // exact defect shipped once. Same guard here, for the same reason.
  const windowDays = result === null || result === undefined ? null : result.windowDays;
  if (windowDays !== null && windowDays !== undefined && Number.isFinite(Number(windowDays))) {
    inputs.push({
      label: 'Traffic window',
      value: `${windowDays} days`,
      note: "Where a firewall reports its own hit counter, that count is cumulative since the counter was last reset, so it can span longer than this window.",
    });
  }
  if (orphans && Number(orphans.allowRules) > 0) {
    inputs.push({
      label: 'Allow rules accounted for by a declared flow',
      value: `${Number(orphans.claimedRules).toLocaleString()} of ${Number(orphans.allowRules).toLocaleString()}`,
      note: 'Reach of the declaration map. An unaccounted rule is not an unused rule.',
    });
  }

  const unmeasured = [];
  if (cov && Array.isArray(cov.devicesWithoutRules) && cov.devicesWithoutRules.length > 0) {
    unmeasured.push({
      label: `${cov.devicesWithoutRules.length} firewalls with no collected ruleset`,
      reason:
        `${cov.devicesWithoutRules.slice(0, 5).join(', ')}`
        + `${cov.devicesWithoutRules.length > 5 ? `, +${cov.devicesWithoutRules.length - 5} more` : ''}`
        + ' — what they permit is unknown, so no flow can be confirmed blocked.',
    });
  }
  if (r.usedUnknown > 0) {
    unmeasured.push({
      label: `${r.usedUnknown} flows whose usage cannot be determined`,
      reason:
        'At least one rule permitting each of them cannot report a hit count — several vendors and '
        + 'transports report none at all — and one silent rule makes the whole answer unknown, '
        + 'because that rule might be the one carrying the traffic.',
    });
  }
  if (r.unspecified > 0) {
    unmeasured.push({
      label: `${r.unspecified} flows no rule decides`,
      reason:
        'No enabled rule permits or denies them. SecVault holds no default-policy data for any '
        + 'vendor, so what happens to unmatched traffic is not knowable from here.',
    });
  }
  if (r.invalid > 0) {
    unmeasured.push({
      label: `${r.invalid} flows that could not be read`,
      reason: 'The declared source, destination or port range could not be parsed, so they were never evaluated.',
    });
  }
  if (r.appsWithoutFlows > 0) {
    unmeasured.push({
      label: `${r.appsWithoutFlows} applications with no declared flows`,
      reason: 'They ask no question of the rulebase, so they contribute nothing to this figure.',
    });
  }
  if (r.fleetFailed) {
    unmeasured.push({
      label: 'The fleet rulebase could not be loaded',
      reason: 'No declared flow was evaluated against anything on this run.',
    });
  }

  return {
    title: `Declared application flows: ${r.ok} of ${r.flows} match the rules`,
    claim:
      'Each declared flow was tested against every active firewall that has a collected ruleset, '
      + 'and separately asked whether the rules permitting it have seen traffic.',
    formula:
      'permitted = at least one enabled allow rule covers the whole declared range · '
      + 'used = every rule permitting the flow can report a hit count, and at least one is above zero · '
      + 'a flow matches when the verdict agrees with the expectation that was declared for it',
    inputs,
    unmeasured,
    source: 'Application view engine',
    rule: 'SecVault application policy — permitted and used are measured separately, and neither implies the other',
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
  cvePostureEvidence,
  deviceComplianceEvidence,
  ruleHygieneEvidence,
  lifecycleEvidence,
  deviceInventoryEvidence,
  exposureEvidence,
  segmentationEvidence,
  applicationsEvidence,
  // exported for tests and for future builders
  cveCoverageGap,
};
