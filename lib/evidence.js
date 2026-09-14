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
  const naCount = na === null ? 0 : na;
  const who = deviceName || 'This firewall';

  const formula = [
    'score = round(100 × pass ÷ (pass + fail + warning))',
    '',
    '  pass     ' + String(pass).padStart(5, ' '),
    '  fail     ' + String(fail).padStart(5, ' '),
    '  warning  ' + String(warning).padStart(5, ' '),
    '  ' + '─'.repeat(16),
    '  measurable ' + String(measurable).padStart(3, ' '),
    '  na         ' + String(naCount).padStart(3, ' ') + '  EXCLUDED',
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

  const inputs = [
    { label: 'Total findings', value: show(findings) },
    { label: 'Critical + high', value: show((num(t.critical) || 0) + (num(t.high) || 0)) },
  ];
  if (rules !== null) {
    inputs.push({ label: 'Rules analysed', value: show(rules) });
    inputs.push({
      label: 'Rules with usage evidence',
      value: show((withHits || 0) + (measuredZero || 0)),
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

  const unknown = num(c.unknown) || 0;
  const perpetual = num(c.perpetual) || 0;
  const noLicenceData = num(c.devicesWithoutLicenceData) || 0;
  const activeDevices = num(c.activeDevices);
  const haWithData = num(c.devicesWithHaData);

  const formula = [
    'Each renewal event is grouped per (device, expiry date) and ranked:',
    '',
    '  expired    ' + String(expired).padStart(5, ' '),
    '  expiring   ' + String(expiring).padStart(5, ' ') + '  within 60 days',
    '  unknown    ' + String(unknown).padStart(5, ' ') + '  no parseable expiry date',
    '  perpetual  ' + String(perpetual).padStart(5, ' ') + "  reported as 'Never'",
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
      value: show(activeDevices - noLicenceData),
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
  const neverChecked = num(t.neverChecked) || 0;
  const notAssessed = num(t.cveNotAssessed) || 0;
  const noVersion = num(t.cveNoVersion) || 0;

  const formula = [
    'Every tile counts ACTIVE firewalls; the two CVE tiles are fleet SUMS.',
    '',
    '  firewalls          ' + String(show(total)).padStart(6, ' '),
    '  reachable          ' + String(show(online)).padStart(6, ' '),
    '  never probed       ' + String(neverChecked).padStart(6, ' '),
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

  const observed = num(t.observed) || 0;
  const notObserved = num(t.notObserved) || 0;
  const unmeasuredPaths = num(t.unmeasured) || 0;
  const noSyslog = num(t.devicesWithoutSyslog) || 0;
  const noInbound = num(t.devicesWithoutInboundCoverage) || 0;
  const failed = num(errorCount) || 0;

  const formula = [
    'Each exposure path is a public source reaching a device service.',
    '',
    '  reached       ' + String(observed).padStart(6, ' ') + '  traffic observed arriving',
    '  not seen      ' + String(notObserved).padStart(6, ' ') + '  watched, no traffic — still OPEN',
    '  NOT MEASURED  ' + String(unmeasuredPaths).padStart(6, ' ') + '  never watched',
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
  // exported for tests and for future builders
  cveCoverageGap,
};
