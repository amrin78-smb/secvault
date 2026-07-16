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

module.exports = { computeRiskScore, computeRiskScoreFromCounts, SEVERITY_WEIGHTS, MAX_SCORE };
