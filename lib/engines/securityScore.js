// lib/engines/securityScore.js
//
// Fleet Security Score — ONE 0-100 headline number for the dashboard, composed
// from the three postures SecVault already measures. Pure, no DB, no I/O: the
// caller queries the counts and passes them in (same shape as riskScore.js).
//
// CommonJS — consumed by the dashboard server component today, and by
// services/engine-worker.js's daily snapshot job (plain node) so the score can
// be trended and compared day-over-day.
//
// ─────────────────────────────────────────────────────────────────────────────
// ⛔ POLARITY. This score is 0-100 where HIGHER IS BETTER, matching the
// compliance score. That is the OPPOSITE of riskScore.js, which is 0-100 where
// higher is WORSE. Both feed this file. Getting the direction wrong here would
// not throw, would not fail a build, and would render a plausible-looking
// number that says the fleet is healthiest exactly when it is worst — so the
// inversion is done in exactly one place (hygieneSubscore) and asserted by the
// comments there. Do not "simplify" it away.
// ─────────────────────────────────────────────────────────────────────────────
//
// WHY THESE THREE COMPONENTS
// The question the tile answers is "is this fleet in good shape today". The
// three things SecVault actually knows about that are:
//   1. Vulnerability posture — are devices running software with CVEs that this
//      app has judged actionable? (device_cve_assessments)
//   2. Rule hygiene — are the rulesets themselves sound? (rule_analysis_results,
//      already weighted and band-tuned by riskScore.js)
//   3. Compliance — do the configs meet the audit checks? (audit_findings)
// Nothing else in the DB measures "security posture" without overlapping one of
// these. Deliberately NOT included: device count, feed freshness, uptime — those
// are operational health, not security posture, and mixing them makes a moving
// number nobody can explain.
//
// WEIGHTS. 40 / 30 / 30, vulnerability weighted highest because an unpatched
// KEV-listed CVE is the only one of the three that maps to a live, externally
// driven exploit path. Coarse on purpose — this is a triage signal, not a risk
// model, same stance as riskScore.js's own weight comment.

'use strict';

const WEIGHTS = {
  vulnerability: 40,
  hygiene: 30,
  compliance: 30,
};

// A device carrying a patch_now assessment is treated as fully exposed; a
// scheduled one as partially (0.4). 'monitor' contributes nothing — by the
// priority decision tree in CLAUDE.md it is explicitly the "no action needed
// today" band, so counting it would make a healthy fleet look permanently
// mediocre (the same failure mode riskScore.js's medium-severity saturation
// bug had).
const SCHEDULED_EXPOSURE_FACTOR = 0.4;

// "Is this a real measurement?" -- the single strictness rule every input to
// this engine goes through. Returns the number, or null meaning NOT MEASURED.
//
// ⛔ Deliberately stricter than `Number()`, which maps '', false, [] and null
// all to 0. In an engine where 0 is the WORST measurable score, that turns an
// unreadable input into a confident claim about the fleet. A numeric STRING is
// accepted because node-postgres hands back bigint/COUNT(*) as text, and a
// real 0 is accepted because a genuine zero is a measurement.
function finiteOrNull(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'boolean') return null;
  if (typeof value !== 'number' && typeof value !== 'string') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function clampScore(n) {
  if (!Number.isFinite(n)) return null;
  return Math.max(0, Math.min(100, Math.round(n)));
}

/**
 * Vulnerability sub-score.
 * @param {{activeDevices:number, devicesWithPatchNow:number, devicesWithScheduled:number}} counts
 *   devicesWithScheduled MUST exclude devices already counted in
 *   devicesWithPatchNow, or a device gets penalized twice.
 * @returns {number|null} 0-100 (higher = better), or null when not measurable.
 */
function vulnerabilitySubscore({ activeDevices, devicesWithPatchNow, devicesWithScheduled }) {
  // ⛔ All three counts use the SAME strictness on purpose. They used to
  // disagree: activeDevices demanded Number.isFinite (so an uncast pg
  // COUNT(*) string like "10" failed safe to null), while the exposure
  // counts used `Number(x) || 0` -- which turns an UNREADABLE value into
  // "no exposed devices", i.e. good news invented from a failed read. A
  // string that cleanly parses is now accepted everywhere (pg returns
  // bigint/count as text), and anything that does not parse yields null
  // for the whole sub-score rather than a flattering zero.
  const active = finiteOrNull(activeDevices);
  if (active === null || active <= 0) return null;
  const patchNowRaw = finiteOrNull(devicesWithPatchNow);
  const scheduledRaw = finiteOrNull(devicesWithScheduled);
  if (patchNowRaw === null || scheduledRaw === null) return null;
  const patchNow = Math.max(0, patchNowRaw);
  const scheduled = Math.max(0, scheduledRaw);
  const activeDevicesCount = active;
  const exposure = (patchNow + scheduled * SCHEDULED_EXPOSURE_FACTOR) / activeDevicesCount;
  return clampScore(100 * (1 - exposure));
}

/**
 * Rule-hygiene sub-score.
 *
 * ⛔ THE INVERSION LIVES HERE AND NOWHERE ELSE. riskScore.js returns 0-100
 * where HIGHER IS WORSE (100 = "critical"). This score is higher-is-better, so
 * the mean risk is subtracted from 100. A device with a clean ruleset (risk 0)
 * contributes 100; a saturated one (risk 100) contributes 0.
 *
 * @param {number[]} deviceRiskScores riskScore.js output, one per device.
 * @returns {number|null} 0-100 (higher = better), or null when no device has
 *   been analysed yet — NOT 0, which would read as "every ruleset is terrible"
 *   when the truth is "no analysis has run".
 */
function hygieneSubscore(deviceRiskScores) {
  if (!Array.isArray(deviceRiskScores)) return null;
  const usable = deviceRiskScores.filter((n) => Number.isFinite(n));
  if (usable.length === 0) return null;
  const meanRisk = usable.reduce((a, b) => a + b, 0) / usable.length;
  return clampScore(100 - meanRisk);
}

/**
 * Compliance sub-score — the fleet compliance percentage, used as-is. Already
 * 0-100 higher-is-better and already excludes `na` from its own denominator,
 * so there is nothing to convert.
 * @returns {number|null} null when nothing is measurable (never 0 — see
 *   scorePctFromCounts's own null-vs-0 distinction).
 */
function complianceSubscore(fleetCompliancePct) {
  // ⛔ Strict, because `Number()` is not. The old guard only rejected null
  // and undefined, so `''`, `false` and `[]` all coerced to 0 -- i.e. an
  // unreadable input became the affirmative claim "this fleet is 0%
  // compliant", the worst measurable value. That is CLAUDE.md's
  // failed-read-as-a-measurement class, the same one that produced 1,278
  // fabricated unused-rule findings. A real 0 is still honoured: it arrives
  // as the NUMBER 0 (or the string "0"), both of which parse finite.
  const pct = finiteOrNull(fleetCompliancePct);
  if (pct === null) return null;
  return clampScore(pct);
}

/**
 * Compose the fleet Security Score.
 *
 * ⛔ A component that is not measurable is DROPPED FROM THE DENOMINATOR, not
 * treated as 0 — exactly how the compliance score excludes `na`. Scoring a
 * brand-new install at 30/100 because no analysis has run yet would report a
 * data gap as a security problem. If nothing at all is measurable the result is
 * `null`, rendered "—", never 0.
 *
 * @returns {{score:number|null, components:{key:string,label:string,score:number|null,weight:number}[], measuredWeight:number}}
 *   `components` is returned alongside the score so the UI can show WHY it is
 *   what it is — a single opaque number nobody can decompose gets ignored.
 */
function computeSecurityScore({
  activeDevices,
  devicesWithPatchNow,
  devicesWithScheduled,
  deviceRiskScores,
  fleetCompliancePct,
}) {
  const components = [
    {
      key: 'vulnerability',
      label: 'Vulnerability posture',
      score: vulnerabilitySubscore({ activeDevices, devicesWithPatchNow, devicesWithScheduled }),
      weight: WEIGHTS.vulnerability,
    },
    {
      key: 'hygiene',
      label: 'Rule hygiene',
      score: hygieneSubscore(deviceRiskScores),
      weight: WEIGHTS.hygiene,
    },
    {
      key: 'compliance',
      label: 'Compliance',
      score: complianceSubscore(fleetCompliancePct),
      weight: WEIGHTS.compliance,
    },
  ];

  const measured = components.filter((c) => c.score !== null);
  const measuredWeight = measured.reduce((sum, c) => sum + c.weight, 0);
  if (measuredWeight === 0) return { score: null, components, measuredWeight: 0 };

  const weighted = measured.reduce((sum, c) => sum + c.score * c.weight, 0);
  return { score: clampScore(weighted / measuredWeight), components, measuredWeight };
}

// Bands match the compliance score's own vocabulary so two 0-100
// higher-is-better numbers sitting side by side on the dashboard never disagree
// about what "84" means.
function securityScoreBand(score) {
  if (score === null || score === undefined) return null;
  if (score >= 90) return 'excellent';
  if (score >= 75) return 'good';
  if (score >= 50) return 'fair';
  return 'poor';
}

module.exports = {
  computeSecurityScore,
  securityScoreBand,
  vulnerabilitySubscore,
  hygieneSubscore,
  complianceSubscore,
  WEIGHTS,
  SCHEDULED_EXPOSURE_FACTOR,
};
