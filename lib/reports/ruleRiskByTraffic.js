'use strict';
//
// lib/reports/ruleRiskByTraffic.js — which rules carry the traffic, and what is
// wrong with those rules.
//
// ⛔ THIS IS THE REPORT A LOG ANALYSER STRUCTURALLY CANNOT PRODUCE, and it is
// the reason CLAUDE.md gives for syslog belonging in SecVault at all: "the log
// storage itself is not the point; the fusion is." A traffic tool can rank
// rules by volume but has never read the rulebase, so it cannot say which of
// them are overly permissive, shadowed, logging-disabled or exposed. A policy
// tool knows all of that and has never seen a packet, so it ranks a rule that
// carries nothing beside one carrying a quarter of the estate's traffic and
// calls them equally important. Only something holding both can say which of
// your busiest rules is also your worst.
//
// ⛔ THE UNIT IS LOGGED HITS IN THE WINDOW, AND THAT DECISION IS THE WHOLE
// CORRECTNESS OF THE RANKING. An earlier draft of this file ranked on
// `effectiveHitCount`, which `ruleHitCorrelation.js` defines as the DEVICE'S
// OWN counter where one exists and log-derived hits otherwise. That is the
// right choice for `unused` — a device-reported zero is the strongest evidence
// available — and it is the WRONG choice here, for two independent reasons
// measured on the live fleet 2026-09-21:
//
//   1. A PAN-OS counter is CUMULATIVE SINCE ITS LAST RESET, not windowed.
//      Against the same rule's 30-day logged hits it ran between 33x and
//      1,076x (`Allow-M365-MDE-Intune`: 4,183,915,499 on the device against
//      3,886,420 in 30 days). Summing those into a "traffic in this window"
//      total mixes two different measurements and states the result as one.
//   2. Every device's counter has a DIFFERENT reset date, so the ratio between
//      two rules on two firewalls means nothing at all. `IDC FW`'s
//      `PRIVATE TO DMZ1` shows 4.0 billion lifetime hits and ZERO logged hits
//      in 30 days — under the old measure it was the fleet's 4th busiest rule
//      on evidence that says nothing about the last month.
//
// So the ranking uses `loggedHits` ONLY: one unit, one window, comparable
// across devices. The device counter is kept and SHOWN, clearly labelled as
// lifetime context, and is never summed and never ranked on.
//
// ⛔ EVERY CLAIM HERE IS BOUNDED BY ruleHitCorrelation.js, UNCHANGED. That file
// already owns the one genuinely hard question — when is "no logged hits" a
// MEASURED zero — and answers it with three conditions that must all hold
// (device logging throughout, rule logging enabled, window long enough). A
// second implementation would eventually disagree, and the wrong one would be
// recommending rule deletions.
//
// ⛔ AN UNMEASURED RULE APPEARS IN NEITHER LIST AND IS COUNTED IN ITS OWN.
// Letting it fall into "carries no traffic" would manufacture deletion
// candidates out of a collector gap — this codebase's signature bug, pointed at
// the one output where acting on it would cause an outage.

const {
  getDeviceLogCoverage,
  getLoggedRuleHits,
  enrichRulesWithLogEvidence,
} = require('../engines/ruleHitCorrelation');

// The share of observed traffic the "busiest rules" section accounts for. 80%
// is the conventional Pareto cut and is stated in the document rather than
// implied, so a reader can see why the list stops where it does.
const CONCENTRATION_TARGET = 0.8;
// However concentrated the traffic is, never print an unbounded table.
// ⛔ WHEN THIS BITES IT IS DISCLOSED. Live on this fleet the cap is reached at
// 65%, BEFORE the 80% target — so a reader told "25 rules carry 65%" without
// being told the list was truncated would read 25 as where the data stopped
// mattering. Same failure as the work queue's PER_SOURCE_CAP: a truncated list
// looks complete.
const MAX_BUSIEST = 25;

// ⛔ WHY THESE COUNT AS "RISK" AND THE OTHER THREE TYPES DO NOT. Every type
// here describes something DANGEROUS about a rule that is carrying traffic —
// too much permission, exposure, or a blind spot. The three excluded types are
// excluded deliberately, not by oversight:
//   `unused`            — the opposite claim, and self-contradictory in a table
//                         of the busiest rules. It belongs in the cleanup list
//                         below, computed from measured zeros only.
//   `correlation`       — a suggestion to MERGE two rules into one address
//                         group. Ruleset complexity, not risk.
//   `reorder_candidate` — a performance suggestion. Being busy is the whole
//                         argument for it, so pairing it with traffic would
//                         read as a risk finding when it is an optimisation.
const RISK_FINDINGS = new Set([
  'any_any', 'overly_permissive', 'risky_service', 'external_exposure',
  'log_disabled', 'shadow', 'redundant', 'generalization', 'expiring_soon',
]);

// ⛔ `log_disabled` CAN NEVER APPEAR IN THE BUSIEST LIST, BY CONSTRUCTION, and
// that is worth stating rather than quietly leaving a dead entry in the set. A
// rule with logging switched off cannot produce a log line, so
// ruleHitCorrelation marks it `rule-logging-disabled` — UNMEASURED — and it
// lands in the unmeasured count instead. It stays in the set because the set
// describes what is dangerous, not what this window happened to observe, and
// the report says in words that these rules are invisible to it.
const NEVER_MEASURABLE_FINDING = 'log_disabled';

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, info: 3 };
const rankOf = (s) => (SEVERITY_RANK[String(s || '').toLowerCase()] ?? SEVERITY_RANK.info);

// Why a rule's traffic could not be established, in the operator's words. The
// keys are ruleHitCorrelation's own vocabulary — not restated, mapped.
const UNMEASURED_REASON = {
  'no-coverage': 'the firewall was not logging to SecVault throughout the window',
  'window-too-short': 'there is not yet enough log history to judge',
  'rule-logging-disabled': 'logging is switched off on the rule, so it can never appear in a log',
};

async function loadFindings(pool, deviceId) {
  const { rows } = await pool.query(
    `SELECT rule_id, finding_type, severity, detail
       FROM rule_analysis_results
      WHERE device_id = $1::uuid`,
    [deviceId]
  );
  const byRule = new Map();
  for (const r of rows) {
    if (!byRule.has(r.rule_id)) byRule.set(r.rule_id, []);
    byRule.get(r.rule_id).push({
      type: r.finding_type,
      severity: r.severity,
      detail: r.detail,
    });
  }
  return byRule;
}

const worstFinding = (findings) => findings
  .filter((f) => RISK_FINDINGS.has(f.type))
  .sort((a, b) => rankOf(a.severity) - rankOf(b.severity))[0] || null;

/**
 * @param {object} pool
 * @param {{deviceId?:string|null, days?:number|string}} options
 */
async function buildRuleRiskData(pool, options = {}) {
  const deviceId = options.deviceId || null;
  // ⛔ THE DEFAULT IS 7, AND IT IS NOT AN ARBITRARY PREFERENCE. A rule's
  // traffic can only be called MEASURED when its firewall logged throughout the
  // window (ruleHitCorrelation's MIN_COVERAGE_RATIO, 0.9). Measured on this
  // fleet 2026-09-21: the collector holds ~313 hours of history, so a 30-day
  // window sits at 0.43 coverage and NOT ONE of the 15 devices passes - 278 of
  // 1,283 enabled rules measurable and ZERO cleanup candidates. At 7 days all
  // 15 pass, 1,235 rules are measurable and 566 candidates appear. The engine
  // is right in both cases; the window was wrong.
  const days = [7, 30].includes(Number(options.days)) ? Number(options.days) : 7;
  const now = new Date();

  const { rows: devices } = await pool.query(
    deviceId
      ? 'SELECT id, name, vendor, mgmt_method FROM devices WHERE id = $1::uuid AND active = true'
      : 'SELECT id, name, vendor, mgmt_method FROM devices WHERE active = true ORDER BY name',
    deviceId ? [deviceId] : []
  );
  // A report scoped to a device that is gone or inactive is a mistake, not an
  // empty document — the route turns null into a 404.
  if (deviceId && devices.length === 0) return null;

  // ⛔ HOISTED. getDeviceLogCoverage returns a map for the WHOLE fleet in one
  // query; calling correlateDeviceRules per device would re-run it once per
  // firewall. The lower-level functions are exported for exactly this.
  const coverageMap = await getDeviceLogCoverage(pool, days, now);

  const failures = [];
  const perDevice = [];

  for (const dev of devices) {
    try {
      const { rows: rules } = await pool.query(
        `SELECT id, rule_name, rule_id_vendor, action, enabled, log_enabled, hit_count,
                src_zones, dst_zones
           FROM firewall_rules WHERE device_id = $1::uuid`,
        [dev.id]
      );
      const hitMaps = await getLoggedRuleHits(pool, dev.id, days, now);
      const enriched = enrichRulesWithLogEvidence(
        rules, coverageMap.get(dev.id) || null, hitMaps
      );
      const findings = await loadFindings(pool, dev.id);

      perDevice.push({
        device: dev,
        rules: enriched.map((r) => ({
          id: r.id,
          name: r.rule_name || r.rule_id_vendor || '(unnamed)',
          action: r.action,
          enabled: r.enabled !== false,
          // ⛔ THE RANKED QUANTITY. Logged hits inside the window, or null when
          // the window could not answer. Never the device counter.
          windowHits: r.loggedHits,
          // ⛔ CONTEXT ONLY — cumulative since the device's counter last reset,
          // on an unknown date that differs per firewall. Shown beside the
          // windowed figure, never summed with it and never ranked on.
          lifetimeHits: r.hit_count === null || r.hit_count === undefined
            ? null
            : Number(r.hit_count),
          evidence: r.logEvidence,
          findings: findings.get(r.id) || [],
        })),
      });
    } catch (err) {
      // ⛔ One firewall that cannot be read is a NAMED gap. Dropping it silently
      // would shrink every denominator below without changing a word of the
      // heading above them.
      failures.push({ device: dev.name, message: err && err.message ? err.message : String(err) });
    }
  }

  const all = perDevice.flatMap((d) => d.rules.map((r) => ({ ...r, deviceName: d.device.name })));

  // Only ENABLED rules can carry traffic; a disabled rule with findings is a
  // different conversation and belongs to the rule-hygiene report.
  const active = all.filter((r) => r.enabled);
  const measured = active.filter((r) => r.windowHits !== null);
  const unmeasured = active.filter((r) => r.windowHits === null);
  const totalTraffic = measured.reduce((n, r) => n + r.windowHits, 0);

  // ── the headline: concentration, and what is wrong inside it ──────────────
  const ranked = [...measured].filter((r) => r.windowHits > 0).sort((a, b) => b.windowHits - a.windowHits);
  const busiest = [];
  let running = 0;
  let cappedBeforeTarget = false;
  for (const r of ranked) {
    busiest.push({ ...r, share: totalTraffic > 0 ? r.windowHits / totalTraffic : null });
    running += r.windowHits;
    if (totalTraffic > 0 && running / totalTraffic >= CONCENTRATION_TARGET) break;
    if (busiest.length >= MAX_BUSIEST) {
      // ⛔ The cap bit BEFORE the Pareto target was reached, so the list stops
      // for our reason and not the data's. That distinction is printed.
      cappedBeforeTarget = ranked.length > busiest.length;
      break;
    }
  }
  const busiestWithRisk = busiest
    .map((r) => ({ ...r, worst: worstFinding(r.findings) }))
    .filter((r) => r.worst !== null)
    .sort((a, b) => rankOf(a.worst.severity) - rankOf(b.worst.severity) || b.windowHits - a.windowHits);

  // ── the inverse: findings on rules with a MEASURED zero ───────────────────
  // ⛔ `measured-zero` ONLY. A rule whose traffic is unknown must never appear
  // here: this list is read as "safe to remove".
  const cleanupCandidates = active
    .filter((r) => r.windowHits === 0 && r.evidence === 'measured-zero'
      // ⛔ A RISK finding, not merely any finding — see `worst` below.
      && worstFinding(r.findings) !== null)
    .map((r) => ({
      ...r,
      // ⛔ THE SAME FILTER THE BUSIEST LIST USES. This used to sort ALL
      // findings, so a rule was nominated for deletion under a justification
      // that was not a risk at all: live, 160 of 565 candidates carried no
      // risk-type finding, and 10 printed `reorder_candidate (high)` — a
      // PERFORMANCE hint — as their stated reason, outranking genuine findings
      // because its severity is `high`. This file's own RISK_FINDINGS comment
      // says pairing reorder_candidate with traffic "would read as a risk
      // finding when it is an optimisation"; the cleanup list was doing exactly
      // that, on the page whose next step is deleting a firewall rule.
      worst: worstFinding(r.findings),
      // ⛔ A SECOND, STRONGER CLAIM WHEN THE DEVICE AGREES. A logged zero means
      // "nothing in this window"; a device counter of 0 means "nothing since
      // that counter was reset", which is a longer and independent statement.
      // They are labelled separately because they are different claims — the
      // report must never present the weaker one in the stronger one's words.
      deviceAgreesZero: r.lifetimeHits === 0,
    }))
    .sort((a, b) => rankOf(a.worst.severity) - rankOf(b.worst.severity)
      || Number(b.deviceAgreesZero) - Number(a.deviceAgreesZero));

  // ⛔ DID THE WINDOW HAVE ANYTHING TO MEASURE WITH? This is computed and
  // printed BEFORE any ranking, because the most dangerous output this report
  // can produce is an EMPTY CLEANUP LIST over an unmeasurable window: it reads
  // as "nothing to clean up" and means "we could not look". Same shape as a
  // compliance score computed from missing data, on a page whose next step is
  // deleting firewall rules.
  // ⛔ SCOPED. This used to read the WHOLE fleet's coverage map even for a
  // device-scoped report, so a report on a firewall that forwards no syslog at
  // all reported `devicesCovered: 15, sufficient: true` — and the coverage-
  // failure headline, the one guard that stops an empty cleanup list being read
  // as an all-clear, could not fire for that device while any OTHER firewall
  // was covered.
  // ⛔ AND A DEVICE ABSENT FROM THE MAP IS PRESENT-AND-UNCOVERED, not missing.
  // getDeviceLogCoverage only returns rows for devices that logged something,
  // so a silent firewall vanished from the denominator instead of counting
  // against it.
  const covRows = devices.map((d) => coverageMap.get(d.id) || null);
  const devicesCovered = covRows.filter((c) => c && c.covered).length;
  const devicesWithLogs = covRows.filter(Boolean).length;
  const historyHours = covRows.reduce(
    (n, c) => Math.max(n, (c && Number(c.hoursWithEvents)) || 0), 0
  );
  const windowHours = days * 24;
  const windowCoverage = {
    devicesCovered,
    devicesWithLogs,
    devicesInScope: devices.length,
    historyHours,
    windowHours,
    sufficient: devicesCovered > 0,
    // ⛔ SUGGESTED, NEVER APPLIED. Silently retrying on a shorter window would
    // mean this report picks whichever span produces the nicer answer, which is
    // the one thing it must never do. It states the shorter window and lets a
    // person ask for it.
    shorterWindowSuggested:
      devicesCovered === 0 && days > 7 && historyHours >= 7 * 24 ? 7 : null,
  };

  const unmeasuredByReason = {};
  for (const r of unmeasured) {
    const k = r.evidence || 'unknown';
    unmeasuredByReason[k] = (unmeasuredByReason[k] || 0) + 1;
  }

  // Per-firewall coverage, so the reader can see whose rules are in the ranking
  // at all. ⛔ A device with zero measured rules is NOT absent from this list.
  const coverage = perDevice.map((d) => {
    const act = d.rules.filter((r) => r.enabled);
    const meas = act.filter((r) => r.windowHits !== null);
    return {
      name: d.device.name,
      vendor: d.device.vendor,
      enabled: act.length,
      measured: meas.length,
      // Tri-state: a device with no enabled rules collected has an UNKNOWN
      // ratio, not a ratio of zero.
      ratio: act.length > 0 ? meas.length / act.length : null,
      traffic: meas.reduce((n, r) => n + r.windowHits, 0),
    };
  }).sort((a, b) => b.traffic - a.traffic);

  return {
    generatedAt: now,
    windowDays: days,
    device: deviceId ? devices[0] : null,
    scope: deviceId ? devices[0].name : 'All firewalls',
    totals: {
      devices: devices.length,
      devicesRead: perDevice.length,
      rules: all.length,
      enabled: active.length,
      measured: measured.length,
      unmeasured: unmeasured.length,
      traffic: totalTraffic,
      // The share of enabled rules SecVault could say anything about at all.
      // ⛔ Printed beside every percentage below, because a percentage of a
      // measured subset presented as a percentage of the rulebase is the whole
      // failure mode this report is guarding against.
      measuredRatio: active.length > 0 ? measured.length / active.length : null,
    },
    busiest,
    busiestWithRisk,
    concentration: {
      rules: busiest.length,
      share: totalTraffic > 0 ? running / totalTraffic : null,
      target: CONCENTRATION_TARGET,
      capped: cappedBeforeTarget,
      rankedTotal: ranked.length,
    },
    cleanupCandidates,
    // ⛔ THE DENOMINATOR FOR AN EMPTY CLEANUP LIST. Zero candidates out of
    // zero answerable rules is a coverage gap; zero out of 1,235 is good news.
    // The two must never render the same way.
    cleanupMeasurable: active.filter((r) => r.evidence === 'measured-zero').length,
    windowCoverage,
    unmeasuredByReason,
    unmeasuredReasonText: UNMEASURED_REASON,
    coverage,
    failures,
  };
}

/**
 * The single sentence this report exists to be able to say.
 *
 * ⛔ IT NAMES ITS OWN DENOMINATOR. "65% of traffic" over a rulebase where a
 * tenth of the rules could not be measured is not a fact about the rulebase,
 * and a reader who is not told cannot know which they were handed.
 *
 * ⛔ AND IT NAMES THE CAP. When the list stopped at MAX_BUSIEST rather than at
 * the concentration target, the sentence says so — otherwise the reader takes
 * the number of rules shown as the number that matter.
 */
function headlineSentence(d) {
  const t = d.totals;
  if (t.enabled === 0) return 'No enabled rules were collected, so there is nothing to weigh.';
  // ⛔ THE COVERAGE FAILURE OUTRANKS EVERY OTHER SENTENCE. If no firewall
  // logged throughout the window, nothing below is a statement about the
  // rulebase, and saying so first is the only way an empty cleanup list is not
  // read as an all-clear.
  // ⛔ FAILS CLOSED ON A MISSING DESCRIPTOR. `wc && !wc.sufficient` treated an
  // ABSENT windowCoverage as "coverage was fine" and printed the confident
  // concentration sentence — the wrong direction for the one branch that stops
  // an empty cleanup list reading as an all-clear.
  const wc = d.windowCoverage || { sufficient: false, historyHours: 0, shorterWindowSuggested: null };
  if (!wc.sufficient) {
    const days = Math.floor(wc.historyHours / 24);
    return `No firewall logged to SecVault throughout the last ${d.windowDays} days, so no rule `
      + 'can be shown to carry no traffic and nothing here may be read as a cleanup list. '
      + `SecVault holds about ${days} day${days === 1 ? '' : 's'} of log history`
      + `${wc.shorterWindowSuggested ? `; ask for a ${wc.shorterWindowSuggested}-day window instead` : ''}. `
      + 'The busiest-rule ranking below still holds for the rules that were seen, but it covers '
      + `only ${t.measured} of ${t.enabled} enabled rules.`;
  }
  if (t.measured === 0) {
    return `None of the ${t.enabled} enabled rules could be measured for traffic in this window, `
      + 'so no rule can be ranked. That is a gap in evidence, not a quiet rulebase.';
  }
  const c = d.concentration;
  const sharePct = c.share === null ? null : Math.round(c.share * 100);
  // ⛔ NOTHING RANKED IS NOT A CLEAN RANKING. With no rule carrying measurable
  // traffic the old wording produced "0 rules carry an unknown share of the
  // traffic … and none of them carries a hygiene finding" — an all-clear
  // assembled entirely out of an absence of evidence.
  if (c.rules === 0) {
    return `No rule carried measurable traffic in this window, so none can be ranked and nothing `
      + `here is evidence that the rulebase is healthy. ${t.measured} of ${t.enabled} enabled `
      + 'rules could be measured at all.';
  }
  const ruleWord = c.rules === 1 ? 'rule carries' : 'rules carry';
  const parts = [
    `${c.rules} ${ruleWord} `
    + `${sharePct === null ? 'an unknown share of' : `${sharePct}% of`} the traffic SecVault `
    + `observed in ${d.windowDays} days`,
  ];
  parts.push(
    d.busiestWithRisk.length > 0
      ? `${d.busiestWithRisk.length} of them ${d.busiestWithRisk.length === 1 ? 'carries' : 'carry'} a hygiene finding`
      : 'none of them carries a hygiene finding'
  );
  if (t.unmeasured > 0) {
    parts.push(
      `${t.unmeasured} of ${t.enabled} enabled rules could not be measured at all and are in neither list`
    );
  }
  let s = `${parts.join(', and ')}.`;
  if (c.capped) {
    s += ` The list stops at ${c.rules} because that is this report's limit, not because the `
      + `traffic ran out — ${c.rankedTotal} rules carried traffic in this window.`;
  }
  return s;
}

module.exports = {
  buildRuleRiskData,
  headlineSentence,
  worstFinding,
  RISK_FINDINGS,
  NEVER_MEASURABLE_FINDING,
  UNMEASURED_REASON,
  CONCENTRATION_TARGET,
  MAX_BUSIEST,
};
