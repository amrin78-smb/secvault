// lib/engines/riskScore.js
//
// Pure, no-DB risk scoring over a device's current rule_analysis_results.
// Deliberately separate from ruleAnalysis.js: that engine DECIDES findings;
// this one just WEIGHTS the findings already decided into one glanceable
// number + band for the dashboard (Rule Analysis Dashboard plan, Phase 1).
// No new schema, no new job -- computed on read from rows the caller already
// queried.
//
// CommonJS -- consumed by Next.js API routes today; a future phase may add a
// scheduled risk-trend snapshot via services/engine-worker.js (plain node).

'use strict';

// Same severity vocabulary as rule_analysis_results.severity / SeverityBadge.js.
// Weights are deliberately coarse (10/5/2/0), not tuned CVSS-style math --
// this is a triage signal ("does this device need attention today"), not a
// precise risk model.
const SEVERITY_WEIGHTS = {
  critical: 10,
  high: 5,
  medium: 2,
  info: 0,
};

// Raw weighted sum is unbounded (a large ruleset could tally hundreds) --
// clamped to 100 so the number is a stable, comparable scale regardless of
// ruleset size. Ten critical findings (any_any is the only critical
// finding_type today) already saturates the scale: a handful of critical
// findings should read as "as bad as it gets," not need dozens before the
// dashboard visually maxes out.
const MAX_SCORE = 100;

// Band cut points, applied to the CLAMPED 0-100 score. `low` requires a score
// of exactly 0 (no critical/high/medium findings at all -- info-only or
// clean devices) -- deliberately strict, so a single medium or worse finding
// always reads as at least 'medium', never masked as 'low'. A single critical
// finding (score 10) lands in 'medium', not 'high' -- three or more is what
// escalates a device to 'high'.
const BANDS = [
  { max: 0, band: 'low' },
  { max: 24, band: 'medium' },
  { max: 59, band: 'high' },
  { max: MAX_SCORE, band: 'critical' },
];

function bandFor(score) {
  for (const b of BANDS) {
    if (score <= b.max) return b.band;
  }
  return 'critical';
}

/**
 * @param {{critical?: number, high?: number, medium?: number, info?: number}} counts
 * @returns {{score: number, band: 'low'|'medium'|'high'|'critical', raw: number}}
 */
function computeRiskScoreFromCounts(counts = {}) {
  const raw =
    (Number(counts.critical) || 0) * SEVERITY_WEIGHTS.critical +
    (Number(counts.high) || 0) * SEVERITY_WEIGHTS.high +
    (Number(counts.medium) || 0) * SEVERITY_WEIGHTS.medium +
    (Number(counts.info) || 0) * SEVERITY_WEIGHTS.info;

  const score = Math.min(MAX_SCORE, raw);
  return { score, band: bandFor(score), raw };
}

/**
 * Convenience wrapper over a raw findings array (e.g. rule_analysis_results
 * rows, or the `findings` array the analysis API route already queries) --
 * tallies severity counts itself so callers don't have to.
 * @param {Array<{severity: string}>} findings
 * @returns {{score: number, band: 'low'|'medium'|'high'|'critical', raw: number}}
 */
function computeRiskScore(findings) {
  const counts = { critical: 0, high: 0, medium: 0, info: 0 };
  for (const f of Array.isArray(findings) ? findings : []) {
    const sev = f && f.severity;
    if (sev && Object.prototype.hasOwnProperty.call(counts, sev)) {
      counts[sev] += 1;
    }
  }
  return computeRiskScoreFromCounts(counts);
}

// Per-RULE risk banding — a different granularity from computeRiskScore()
// above (which weighs a whole DEVICE's finding counts into one number).
// ManageEngine Firewall Analyzer's "Risk" tab scores every individual rule
// ("43 Risky Rules of Total: 60"), not just a device aggregate; this is the
// same building block reused at rule granularity. Deliberately simpler than
// the device score: a rule either carries a given severity's finding or it
// doesn't (no weighted sum, no clamping) — the band is just "the worst
// severity among this rule's own findings," since a single rule can only
// meaningfully be as risky as its worst individual finding, not a sum of
// several (unlike a whole device, where MANY medium findings across
// different rules genuinely do add up to more overall exposure).
//
// 'attention' is a 5th band, distinct from the 4 severity-derived bands
// below — see computeRuleRiskBand()'s own comment for why it exists.
const RULE_BAND_BY_SEVERITY = { critical: 'critical', high: 'high', medium: 'medium', info: 'low' };
const RULE_BAND_RANK = { critical: 4, high: 3, medium: 2, low: 1, attention: 0 };

/**
 * Band one rule from the list of its OWN rule_analysis_results findings
 * (i.e. rows where rule_id === this rule's id — NOT affected_rule_ids,
 * which names OTHER rules involved in a shadow/redundant/correlation
 * relationship; see ruleAnalysis.js for that distinction).
 *
 * A rule with zero findings of its own is 'attention' when it is ENABLED —
 * not 'low' — mirroring Firewall Analyzer's own 5th "Attention" bucket
 * (see the Risk tab screenshot: Critical/High/Medium/Low/Attention, not
 * just 4 severity bands). An enabled rule with no Phase 5 finding at all
 * hasn't been flagged as risky by any specific check, but it also hasn't
 * been reviewed/cleared by one either — 'attention' communicates "nothing
 * wrong found, but also nothing confirming this one's fine" rather than
 * implying a false-confidence 'low'. A DISABLED rule with no findings is
 * 'low' — Phase 5 findings only ever key off enabled rules' live behavior
 * (an inactive rule can't itself be any_any-exposed right now), so "no
 * findings + disabled" really is the unambiguous low-risk case.
 *
 * @param {Array<{severity: string}>} ruleFindings - this rule's OWN findings only
 * @param {boolean} enabled
 * @returns {'low'|'medium'|'high'|'critical'|'attention'}
 */
function computeRuleRiskBand(ruleFindings, enabled) {
  const findings = Array.isArray(ruleFindings) ? ruleFindings : [];
  let worst = null;
  for (const f of findings) {
    const band = RULE_BAND_BY_SEVERITY[f && f.severity];
    if (!band) continue;
    if (worst === null || RULE_BAND_RANK[band] > RULE_BAND_RANK[worst]) {
      worst = band;
    }
  }
  if (worst) return worst;
  return enabled ? 'attention' : 'low';
}

module.exports = {
  computeRiskScore,
  computeRiskScoreFromCounts,
  computeRuleRiskBand,
  SEVERITY_WEIGHTS,
  MAX_SCORE,
};
