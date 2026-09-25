'use strict';

// lib/engines/coverageRegister.js
//
// WHERE SECVAULT CANNOT SEE, AND WHAT THAT COSTS. Pure — takes already-fetched
// per-device counts, returns a register. No pool, no queries; the plumbing is
// `coverageRegisterData.js`.
//
// ── ⛔ WHY THIS EXISTS ────────────────────────────────────────────────────
//
// A firewall nothing can be collected from contributes no CVEs, no failing
// checks and no rule findings — which makes it look like the HEALTHIEST DEVICE
// ON THE FLEET everywhere else in this product. That inversion is this
// codebase's most-repeated bug, and every page inherits it.
//
// Measured on the live fleet 2026-09-25, all three live today:
//
//   PAKFood   0 syslog buckets, yet 17 CVE assessments, 24 audit findings and
//             25 rule findings — it renders as fully assessed. No log_hit, no
//             traffic verdict, no rule-hit evidence, and 77 of 77 object
//             references unresolvable.
//   5 Fortinets  100% unmeasured hit counts (38/38, 27/27, 30/30, 78/78, 8/8),
//             so `unused` can never fire on them — while they are the
//             HIGHEST-LOGGING devices on the fleet.
//   TSR_EKC   rule analysis last ran 2026-08-07, `last_rules_collected_at` is
//             NULL, and its 22 `unused` findings PREDATE the hit_count
//             tri-state fix — artefacts of a bug corrected a month ago, still
//             rendering as ordinary current findings.
//
// ── ⛔ THE THREE RULES THAT MAKE IT USEFUL RATHER THAN A CHECKLIST ────────
//
// 1. RANK BY CONSEQUENCE, NOT BY GAP COUNT. Every one of the 16 devices has at
//    least one gap, so a list of devices-with-gaps is a list of the fleet. What
//    distinguishes them is how many ANSWERS each gap withholds: a device
//    missing one source that gates five engines outranks one missing three that
//    gate nothing.
//
// 2. STALE IS WORSE THAN ABSENT, AND IS ITS OWN STATE. Absent evidence renders
//    as a gap. Stale evidence renders as an ANSWER — TSR_EKC's 49-day-old
//    findings sit beside today's with nothing distinguishing them. A reader
//    cannot tell, so the register must.
//
// 3. NO GAPS IS NOT AN ALL-CLEAR. It means "we can see this firewall", and
//    nothing whatever about whether it is secure. `fullyCovered` is deliberately
//    named for visibility, and no caller may render it as a security verdict.

// What each evidence source gates. ⛔ THE COST IS THE POINT — "no hit counts"
// is a fact nobody acts on; "`unused` cannot fire here, and rule cleanup will
// refuse every rule on this device" is.
const SOURCES = Object.freeze({
  ruleset: {
    label: 'Firewall rules',
    gates: ['rule hygiene findings', 'segmentation verdicts', 'application intent', 'rule-based compliance checks'],
  },
  ruleUsage: {
    label: 'Rule usage (hit counts)',
    gates: ['unused-rule findings', 'rule cleanup requests', 'segmentation "did it happen"'],
  },
  syslog: {
    label: 'Syslog',
    gates: ['log_hit (CVE priority rule 2)', 'traffic evidence', 'rule-hit correlation', 'VPN detections'],
  },
  interfaces: {
    label: 'Interfaces',
    gates: ['log_hit (traffic TO the device vs THROUGH it)', 'topology adjacency'],
  },
  objects: {
    label: 'Object resolution',
    gates: ['application impact', 'rule retirement', 'access-path queries'],
  },
  config: {
    label: 'Configuration',
    gates: ['compliance scoring', 'CVE applicability', 'configuration drift'],
  },
  version: {
    label: 'Version',
    gates: ['CVE matching', 'upgrade plan'],
  },
});

const STATE = Object.freeze({
  MEASURED: 'measured',
  PARTIAL: 'partial',
  ABSENT: 'absent',
  STALE: 'stale',
});

// ⛔ A GAP IS WEIGHTED BY HOW MUCH IT WITHHOLDS. `absent` blocks every gated
// answer; `partial` degrades them; `stale` is weighted as heavily as absent
// because a stale answer is acted on, where a missing one is not.
const STATE_WEIGHT = Object.freeze({
  [STATE.MEASURED]: 0,
  [STATE.PARTIAL]: 0.5,
  [STATE.ABSENT]: 1,
  [STATE.STALE]: 1,
});

// Days after which collected evidence is called stale. ⛔ Not an env var: this
// is an honesty threshold, not a tuning knob, and CONFIG_PULL_INTERVAL_HOURS
// defaults to 24 — so a week is seven missed pulls, not a slow afternoon.
const STALE_AFTER_DAYS = 7;

// ⛔ `Number(null)` IS 0 AND 0 IS FINITE. A bare `Number.isFinite(Number(v))`
// turns "we could not read this count" into a measured zero — the precise bug
// this engine exists to surface, and it was live here until the unreadable-count
// test caught it. `null`/`undefined`/`''`/`[]`/`false` all coerce to 0; only a
// real number or a non-empty numeric string is a measurement.
const num = (v) => {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'string' && v.trim() !== '') {
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }
  return null;
};

/**
 * One evidence cell.
 * ⛔ `null` inputs mean WE DID NOT MEASURE THE MEASUREMENT — distinct from a
 * measured zero, and it must not be rounded into one. A cell built from a
 * failed count is `absent` with `certain: false`, so the register can say "we
 * could not even check" rather than asserting a gap.
 */
function cell(key, state, detail, opts = {}) {
  const src = SOURCES[key] || { label: key, gates: [] };
  return {
    key,
    label: src.label,
    state,
    detail,
    gates: state === STATE.MEASURED ? [] : src.gates,
    weight: (STATE_WEIGHT[state] || 0) * src.gates.length,
    certain: opts.certain !== false,
    ageDays: opts.ageDays === undefined ? null : opts.ageDays,
  };
}

/**
 * The `ruleUsage` cell.
 *
 * ── ⛔ WHY THIS ONE CELL HAS ITS OWN FUNCTION (A3, 2026-09-25) ────────────
 *
 * It used to read the gap straight off `hit_count IS NULL`, and that OVERSTATED
 * it by 84 rules fleet-wide. A device that cannot report a hit count is not a
 * device whose rule usage is unknown — its own logs may answer instead, and
 * measured live they answer 84 of 235: 54 by the vendor's rule ID, 30 by NAME.
 *
 * ⛔ IT SHRINKS THE GAP TO `partial`. NEVER TO `measured`. A log-derived answer
 * is a bounded-window OBSERVATION, not the device's own lifetime counter, so a
 * firewall answered entirely from logs is better off than one answered not at
 * all and is still not a firewall SecVault can measure.
 *
 * ⛔ AND THE TWO GRADES ARE NOT INTERCHANGEABLE — this is the whole reason the
 * second count exists. `log-id` matches the vendor's own rule ID and is exact.
 * `log-name` matches a NAME, which is neither unique nor stable across a config
 * change: a rule RENAMED during the window reads as having had no traffic while
 * it is busily passing some. So a name-grade answer INFORMS an operator and may
 * NEVER authorise removing a rule from a firewall, and the detail text has to
 * say so — an operator who reads "the logs answer these" and deletes one has
 * been misled by this cell.
 *
 * ⛔ AN UNREADABLE LOG-EVIDENCE COUNT LEAVES THE CELL EXACTLY WHERE IT WAS,
 * marked `certain: false`. It may never improve the picture: "we could not
 * check whether the logs answer these" is not "the logs answer these".
 */
function ruleUsageCell(rules, unmeasured, r) {
  if (unmeasured === 0) {
    return cell('ruleUsage', STATE.MEASURED, `Hit counts available for all ${rules} rules.`);
  }

  // Where the cell sits on the device's evidence alone — the state it must fall
  // back to whenever log evidence cannot be read.
  const total = unmeasured >= rules;
  const baseState = total ? STATE.ABSENT : STATE.PARTIAL;
  const baseDetail = total
    ? `No hit counts at all (${unmeasured} of ${rules} rules). "Unused" cannot fire here, `
      + 'and rule cleanup will refuse every rule on this firewall.'
    : `${unmeasured} of ${rules} rules report no hit count.`;

  const answered = num(r.rulesLogAnswered);
  const idGrade = num(r.rulesLogAnsweredDeletionGrade);

  // ⛔ EITHER count unreadable holds the WHOLE cell back. Knowing that 40 rules
  // are log-answered without knowing how many of those are ID-grade would let
  // the detail below imply a deletion authority it cannot establish.
  // ⛔ A NEGATIVE IS A BROKEN READ, NOT A SMALLER GAP. `num()` rightly passes it
  // through as a finite number, and `answered <= 0` would then quietly render
  // it as "we checked; the logs answer none" — a failed read recorded as a
  // fact, in the one cell where the failure direction is flattering.
  if (answered === null || idGrade === null || answered < 0 || idGrade < 0) {
    return cell('ruleUsage', baseState,
      `${baseDetail} Whether the firewall's own logs answer any of them could not be read, so `
      + 'this may overstate the gap.',
      { certain: false });
  }

  if (answered <= 0) return cell('ruleUsage', baseState, baseDetail);

  // ⛔ Clamped to what was actually asked about. A log-evidence count larger
  // than the unmeasured count is a disagreement between two reads, and the
  // honest response is to claim the smaller of them rather than to report more
  // answers than there were questions.
  const covered = Math.min(answered, unmeasured);
  const id = Math.min(idGrade, covered);
  const byName = covered - id;
  const remaining = unmeasured - covered;
  // Rule cleanup accepts ID-grade evidence and nothing else here.
  const refused = unmeasured - id;

  const parts = [remaining === 0
    ? `${unmeasured} of ${rules} rules report no hit count, and the firewall's own logs answer `
      + `all ${covered} of them.`
    : `${unmeasured} of ${rules} rules report no hit count; the firewall's own logs answer `
      + `${covered}, leaving ${remaining} with no usage evidence at all.`];

  if (id > 0 && byName > 0) {
    parts.push(`${id} are matched by the vendor's own rule ID, which is exact, and ${byName} by `
      + 'rule NAME only — a name answer informs an operator but may never authorise removing a '
      + 'rule, because a renamed rule reads as unused.');
  } else if (id > 0) {
    parts.push(`All ${id} are matched by the vendor's own rule ID, which is exact.`);
  } else {
    parts.push(`All ${byName} are matched by rule NAME only, which informs an operator but may `
      + 'never authorise removing a rule, because a renamed rule reads as unused.');
  }

  parts.push(id === 0
    ? `"Unused" cannot fire on any of them, and rule cleanup will refuse all ${refused}.`
    : (refused === 0
      ? `"Unused" can fire on all ${id}, and rule cleanup will accept them.`
      : `"Unused" can fire on the ${id} matched by ID; rule cleanup will still refuse the other `
        + `${refused}.`));

  // ⛔ PARTIAL, not MEASURED, even when every unmeasured rule is log-answered.
  return cell('ruleUsage', STATE.PARTIAL, parts.join(' '));
}

/**
 * Assess one device's evidence coverage.
 *
 * @param {object} d per-device counts from coverageRegisterData.js
 * @returns {object} the device's register entry
 */
function assessDevice(d) {
  const r = d && typeof d === 'object' ? d : {};
  const cells = [];

  // ── rules collected at all
  const rules = num(r.rules);
  cells.push(rules === null
    ? cell('ruleset', STATE.ABSENT, 'Rule count could not be read.', { certain: false })
    : rules === 0
      ? cell('ruleset', STATE.ABSENT, 'No firewall rules have been collected.')
      : cell('ruleset', STATE.MEASURED, `${rules} rules collected.`));

  // ── rule usage. ⛔ The tri-state: unmeasured is NOT a measured zero — and
  // "the device cannot measure it" is not "SecVault cannot measure it", because
  // the firewall's own logs may answer instead. See ruleUsageCell.
  const unmeasured = num(r.rulesUnmeasured);
  if (rules && unmeasured !== null) {
    cells.push(ruleUsageCell(rules, unmeasured, r));
  }

  // ── syslog
  const buckets = num(r.logBuckets);
  cells.push(buckets === null
    ? cell('syslog', STATE.ABSENT, 'Syslog coverage could not be read.', { certain: false })
    : buckets === 0
      ? cell('syslog', STATE.ABSENT,
        'This firewall sends no syslog to SecVault. Every traffic-based answer about it is '
        + 'unmeasured, including whether a vulnerable service was reached.')
      : cell('syslog', STATE.MEASURED, `${buckets} hourly buckets received.`));

  // ── interfaces
  const ifaces = num(r.interfaces);
  if (ifaces !== null) {
    cells.push(ifaces === 0
      ? cell('interfaces', STATE.ABSENT,
        'No interface addresses collected, so traffic arriving AT this firewall cannot be told '
        + 'from traffic passing THROUGH it.')
      : cell('interfaces', STATE.MEASURED, `${ifaces} interfaces collected.`));
  }

  // ── object resolution
  const refs = num(r.objectRefs);
  const unres = num(r.objectUnresolvable);
  if (refs && unres !== null) {
    const pct = Math.round((unres / refs) * 100);
    cells.push(unres === 0
      ? cell('objects', STATE.MEASURED, `All ${refs} object references resolve.`)
      : cell('objects', unres >= refs ? STATE.ABSENT : STATE.PARTIAL,
        `${unres} of ${refs} rule object references (${pct}%) name something this firewall never `
        + 'reported, so application impact and retirement cannot conclude.'));
  }

  // ── configuration freshness
  const cfgAge = num(r.configAgeDays);
  cells.push(cfgAge === null
    ? cell('config', STATE.ABSENT, 'No configuration has been collected.')
    : cfgAge > STALE_AFTER_DAYS
      ? cell('config', STATE.STALE,
        `Configuration is ${cfgAge} days old, so compliance and CVE applicability here are scored `
        + 'on evidence that age.', { ageDays: cfgAge })
      : cell('config', STATE.MEASURED, `Configuration collected ${cfgAge} day(s) ago.`, { ageDays: cfgAge }));

  // ── version
  const versions = num(r.versionRows);
  cells.push(versions === null || versions === 0
    ? cell('version', STATE.ABSENT, 'No firmware version collected, so CVE matching cannot run.')
    : cell('version', STATE.MEASURED, 'Firmware version known.'));

  // ⛔ STALE FINDINGS ARE THEIR OWN FINDING, and the most dangerous state here.
  // An analysis that ran before a rule was fixed still renders as a current
  // answer. Live: TSR_EKC's 22 `unused` findings are from 2026-08-07, PREDATING
  // the hit_count tri-state fix, on a device whose rule collection has not
  // succeeded since.
  const analysisAge = num(r.analysisAgeDays);
  const staleFindings = analysisAge !== null && analysisAge > STALE_AFTER_DAYS
    ? {
      ageDays: analysisAge,
      findingCount: num(r.ruleFindings) || 0,
      neverCollected: !r.rulesCollectedAt,
      detail: `Rule analysis last ran ${analysisAge} days ago`
        + (r.rulesCollectedAt ? '.' : ', and rule collection has never succeeded.')
        + ` Its ${num(r.ruleFindings) || 0} findings are shown elsewhere with nothing marking them as that old.`,
    }
    : null;

  const gaps = cells.filter((c) => c.state !== STATE.MEASURED);
  const uncertain = cells.filter((c) => !c.certain);

  return {
    deviceId: r.deviceId,
    deviceName: r.deviceName,
    vendor: r.vendor,
    cells,
    gaps,
    gapCount: gaps.length,
    // ⛔ THE RANKING NUMBER: answers withheld, not gaps counted.
    answersWithheld: Math.round(gaps.reduce((n, c) => n + c.weight, 0) * 10) / 10,
    blockedEngines: [...new Set(gaps.flatMap((c) => c.gates))],
    staleFindings,
    uncertainCount: uncertain.length,
    // ⛔ VISIBILITY, NOT SAFETY. Named so it cannot be read as an all-clear.
    fullyCovered: gaps.length === 0 && !staleFindings,
  };
}

/** Rank by consequence. ⛔ Stale findings outrank a pure gap of equal weight. */
function rankRegister(entries) {
  return [...(Array.isArray(entries) ? entries : [])].sort((a, b) => {
    const aS = a.staleFindings ? 1 : 0;
    const bS = b.staleFindings ? 1 : 0;
    if (aS !== bS) return bS - aS;
    if (a.answersWithheld !== b.answersWithheld) return b.answersWithheld - a.answersWithheld;
    if (a.blockedEngines.length !== b.blockedEngines.length) {
      return b.blockedEngines.length - a.blockedEngines.length;
    }
    return String(a.deviceName || '').localeCompare(String(b.deviceName || ''));
  });
}

/** Fleet totals. */
function summariseRegister(entries) {
  const list = Array.isArray(entries) ? entries : [];
  const byGap = {};
  for (const e of list) for (const g of e.gaps) byGap[g.key] = (byGap[g.key] || 0) + 1;
  return {
    devices: list.length,
    devicesFullyCovered: list.filter((e) => e.fullyCovered).length,
    devicesWithGaps: list.filter((e) => !e.fullyCovered).length,
    devicesWithStaleFindings: list.filter((e) => e.staleFindings).length,
    // ⛔ A distinct count, because "we could not even check" is not a gap.
    devicesWithUnreadableChecks: list.filter((e) => e.uncertainCount > 0).length,
    gapsBySource: byGap,
    blockedEngines: [...new Set(list.flatMap((e) => e.blockedEngines))].sort(),
  };
}

module.exports = {
  assessDevice, rankRegister, summariseRegister,
  SOURCES, STATE, STALE_AFTER_DAYS,
};
