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
//
// ── ⛔ AND THE THREE RULES ADDED BY THE 2026-09-27 REVIEW ─────────────────
//
// 4. EVERY SOURCE ALWAYS PRODUCES A CELL. `cell()`'s own docblock has always
//    promised that a cell built from a failed count is `absent` with
//    `certain: false` — and four of the seven sources instead DROPPED the cell
//    when their count could not be read (`ruleUsage`, `interfaces` and both
//    halves of `objects`), which took its gap out of `gaps`, its weight out of
//    `answersWithheld` and its uncertainty out of `uncertainCount`. Executed
//    with one field nulled and everything else healthy, that produced
//    `fullyCovered: true` with `uncertainCount: 0` — "Fully visible", on the
//    one page whose subject is unreadable measurements. A missing count now
//    always yields a cell, and `assessDevice` pushes exactly seven of them.
//
// 5. THE GAP AND ITS MITIGATION ARE SEPARATE CERTAINTIES. `certain: false` means
//    WE COULD NOT ESTABLISH THIS GAP. The `ruleUsage` cell used it for something
//    else: `hit_count IS NULL` for 38 of 38 rules is read straight off
//    `firewall_rules` and is CERTAIN, while the log-evidence enrichment that may
//    SHRINK it is a second, independent read. Marking the whole cell uncertain
//    when only the enrichment failed reported an established blind spot as an
//    unanswered question — and downstream (`workQueueData.gatherCoverageGaps`)
//    it deleted a real work-queue item, reporting `ok: true` with no banner. So
//    the gap keeps `certain: true` and the unread mitigation travels separately
//    as `mitigationUnknown`. A state reached that way is a FLOOR: the gap is at
//    least this large.
//
// 6. A `partial` GAP IS WEIGHTED BY THE SHARE IT AFFECTS. `STATE_WEIGHT.partial`
//    was a flat 0.5, so "rank by consequence" collapsed: nine of sixteen live
//    firewalls sat on exactly 1.5 with the same blocked-engine count, and order
//    fell through to the device NAME — putting HRIS (74 of 90 object references
//    unresolvable) level with TUM (6 of 263). Worse, ONE log-answered rule in a
//    hundred HALVED the score. The share is now proportional, floored so a tiny
//    gap still counts and capped so a partial can never weigh as much as an
//    absence.

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
//
// ⛔ THE `partial` ENTRY IS A DEFAULT, NOT THE WEIGHT. It applies only to a
// partial cell that supplies no `share` — see partialShare below, and rule 6 in
// the header for the collapse a flat 0.5 produced on the live fleet.
const STATE_WEIGHT = Object.freeze({
  [STATE.MEASURED]: 0,
  [STATE.PARTIAL]: 0.5,
  [STATE.ABSENT]: 1,
  [STATE.STALE]: 1,
});

// ⛔ THE BOUNDS ON A PARTIAL SHARE, AND BOTH ARE LOAD-BEARING.
//
// The FLOOR stops a genuinely small gap weighing nothing at all: 6 unresolvable
// object references out of 263 is a real gap on a real firewall, and rounding it
// to zero would make the cell a gap that costs nothing, which reads as an answer.
//
// The CAP stops a partial ever weighing as much as an absence. They are
// different claims — "some of this is answered" versus "none of it is" — and a
// share of 0.995 rounding up to parity would erase the distinction the whole
// `partial` state exists to carry.
const PARTIAL_MIN_SHARE = 0.01;
const PARTIAL_MAX_SHARE = 0.95;

// ⛔ WHAT A LOG-ANSWERED RULE STILL WITHHOLDS. A log-derived answer is a
// bounded-window OBSERVATION, never the device's own lifetime counter, so it
// never zeroes the share:
//   * ID grade   answers the same question the counter would, over a window —
//                half the gap remains.
//   * NAME grade informs an operator and may NEVER authorise removing a rule
//                (a renamed rule reads as unused), so it leaves the gated
//                answer that matters most — rule cleanup — entirely blocked.
// Not tuning knobs: they encode the grade ORDER this file documents at length,
// and `tests/coverageRegister.test.js` pins the order rather than the numbers.
const LOG_ID_RESIDUAL = 0.5;
const LOG_NAME_RESIDUAL = 0.75;

const round2 = (n) => Math.round(n * 100) / 100;

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
 * The share of a source a `partial` cell withholds, clamped.
 * ⛔ A share that cannot be read falls back to the flat default rather than to
 * 0 — an unreadable proportion is not a small one.
 */
function partialShare(v) {
  const n = num(v);
  if (n === null) return STATE_WEIGHT[STATE.PARTIAL];
  if (!(n > 0)) return PARTIAL_MIN_SHARE;
  return Math.min(PARTIAL_MAX_SHARE, Math.max(PARTIAL_MIN_SHARE, n));
}

/**
 * A share as a percentage, as WORDS.
 *
 * ⛔ NEVER "0%" FOR A NON-ZERO COUNT. `Math.round` printed 1 of 878 as "(0%)" —
 * on the one page in this product that exists to stop a zero meaning nothing.
 * The same rule runs the other way: a gap that is not TOTAL may not round up to
 * "100%", because 100% and "all of them" are read as the same statement and one
 * of them would be false.
 */
function sharePct(part, whole) {
  if (!(whole > 0)) return null;
  const r = Math.round((part / whole) * 100);
  if (part > 0 && r === 0) return '<1%';
  if (part < whole && r >= 100) return '>99%';
  return `${r}%`;
}

/**
 * One evidence cell.
 *
 * ⛔ `null` inputs mean WE DID NOT MEASURE THE MEASUREMENT — distinct from a
 * measured zero, and it must not be rounded into one. A cell built from a
 * failed count is `absent` with `certain: false`, so the register can say "we
 * could not even check" rather than asserting a gap. ⛔ THAT IS A PROMISE ABOUT
 * A CELL THAT EXISTS: four sources used to drop theirs instead, which is how an
 * unreadable count produced "Fully visible" (header rule 4). Every source in
 * `assessDevice` now emits a cell unconditionally.
 *
 * @param {object} [opts]
 * @param {boolean} [opts.certain] false when the GAP ITSELF could not be
 *   established. Never used for an unread mitigation — see below.
 * @param {boolean} [opts.mitigationUnknown] true when the gap is established but
 *   a SECOND read that could have shrunk it failed. The state is then a FLOOR.
 *   ⛔ A separate axis on purpose: collapsing the two reported an established
 *   blind spot as an unanswered question, and deleted a work-queue item.
 * @param {number} [opts.share] for `partial` only: the fraction of this source
 *   the gap affects. Drives the weight; see PARTIAL_MIN_SHARE.
 * @param {number|null} [opts.ageDays]
 */
function cell(key, state, detail, opts = {}) {
  const src = SOURCES[key] || { label: key, gates: [] };
  const factor = state === STATE.PARTIAL
    ? partialShare(opts.share)
    : (STATE_WEIGHT[state] || 0);
  return {
    key,
    label: src.label,
    state,
    detail,
    gates: state === STATE.MEASURED ? [] : src.gates,
    weight: round2(factor * src.gates.length),
    // ⛔ Carried so the weight is auditable rather than a bare number: a reader
    // checking why HRIS outranks TUM can see 0.82 against 0.02.
    share: state === STATE.PARTIAL ? round2(partialShare(opts.share)) : null,
    certain: opts.certain !== false,
    mitigationUnknown: opts.mitigationUnknown === true,
    ageDays: opts.ageDays === undefined ? null : opts.ageDays,
  };
}

/** The cell every source falls back to when its own count could not be read. */
function unreadableCell(key, detail) {
  return cell(key, STATE.ABSENT, detail, { certain: false });
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
 * ⛔ AN UNREADABLE LOG-EVIDENCE COUNT LEAVES THE CELL EXACTLY WHERE IT WAS. It
 * may never improve the picture: "we could not check whether the logs answer
 * these" is not "the logs answer these".
 *
 * ⛔ BUT IT DOES **NOT** MAKE THE CELL UNCERTAIN, AND THAT WAS THE MODELLING
 * ERROR (found by review 2026-09-27). `hit_count IS NULL` for 38 of 38 rules is
 * read off `firewall_rules` and is a CERTAIN fact about the device; the
 * enrichment that might shrink it is a SECOND, independent read. Marking the
 * whole cell `certain: false` when only that second read failed reported an
 * established gap as an unanswered question — and `gatherCoverageGaps` drops
 * unconfirmed gaps, so on the live fleet a single failing log-evidence query
 * DELETED OKF(F2)'s work-queue item while the queue still reported `ok: true`
 * with no banner. The gap is certain; the MITIGATION is unknown, and they now
 * travel as two fields. The state reached that way is a FLOOR.
 */
function ruleUsageCell(rules, unmeasured, r) {
  if (unmeasured === 0) {
    return cell('ruleUsage', STATE.MEASURED, `Hit counts available for all ${rules} rules.`);
  }

  // Where the cell sits on the device's evidence alone — the state it must fall
  // back to whenever log evidence cannot be read.
  const total = unmeasured >= rules;
  const baseState = total ? STATE.ABSENT : STATE.PARTIAL;
  const baseShare = unmeasured / rules;
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
      // ⛔ `certain: true`. The gap was measured on the device; only the thing
      // that could have SHRUNK it was not. See the docblock.
      { mitigationUnknown: true, share: baseShare });
  }

  if (answered <= 0) return cell('ruleUsage', baseState, baseDetail, { share: baseShare });

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

  // ⛔ PARTIAL, not MEASURED, even when every unmeasured rule is log-answered —
  // and weighted by what the log answers still WITHHOLD, never by a flat half.
  // An unanswered rule counts in full; an ID-grade answer and a NAME-grade one
  // count at their own residuals, because the second cannot authorise a removal.
  const share = (remaining + (id * LOG_ID_RESIDUAL) + (byName * LOG_NAME_RESIDUAL)) / rules;
  return cell('ruleUsage', STATE.PARTIAL, parts.join(' '), { share });
}

/**
 * Assess one device's evidence coverage.
 *
 * ⛔ SEVEN CELLS, ALWAYS, ONE PER SOURCE. A source whose count could not be read
 * produces an `absent` + `certain: false` cell, never no cell at all — see
 * header rule 4 for the "Fully visible" a dropped cell produced.
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
    ? unreadableCell('ruleset', 'Rule count could not be read.')
    : rules === 0
      ? cell('ruleset', STATE.ABSENT, 'No firewall rules have been collected.')
      : cell('ruleset', STATE.MEASURED, `${rules} rules collected.`));

  // ── rule usage. ⛔ The tri-state: unmeasured is NOT a measured zero — and
  // "the device cannot measure it" is not "SecVault cannot measure it", because
  // the firewall's own logs may answer instead. See ruleUsageCell.
  //
  // ⛔ NO RULESET MEANS NO RULE USAGE, AND THAT IS A GAP OF ITS OWN. This used
  // to be pushed only `if (rules)`, so a firewall nothing had ever been
  // collected from withheld FEWER answers than one collected and blind — the
  // exact inversion this engine exists to correct, reproduced in its own
  // ranking. With no rules there is no hit count for anything, so every answer
  // `ruleUsage` gates is unavailable, and saying so is not double-counting the
  // `ruleset` cell: they gate different engines.
  const unmeasured = num(r.rulesUnmeasured);
  if (rules === null) {
    cells.push(unreadableCell('ruleUsage',
      'The rule count could not be read, so how much of this firewall’s rule usage is '
      + 'measured cannot be established either.'));
  } else if (rules === 0) {
    cells.push(cell('ruleUsage', STATE.ABSENT,
      'No rules have been collected, so no rule on this firewall has a hit count. '
      + '"Unused" cannot fire here and rule cleanup has nothing to work from.'));
  } else if (unmeasured === null) {
    cells.push(unreadableCell('ruleUsage',
      `How many of this firewall’s ${rules} rules report a hit count could not be read.`));
  } else {
    cells.push(ruleUsageCell(rules, unmeasured, r));
  }

  // ── syslog
  const buckets = num(r.logBuckets);
  cells.push(buckets === null
    ? unreadableCell('syslog', 'Syslog coverage could not be read.')
    : buckets === 0
      ? cell('syslog', STATE.ABSENT,
        'This firewall sends no syslog to SecVault. Every traffic-based answer about it is '
        + 'unmeasured, including whether a vulnerable service was reached.')
      : cell('syslog', STATE.MEASURED, `${buckets} hourly buckets received.`));

  // ── interfaces
  const ifaces = num(r.interfaces);
  cells.push(ifaces === null
    ? unreadableCell('interfaces', 'The interface count could not be read.')
    : ifaces === 0
      ? cell('interfaces', STATE.ABSENT,
        'No interface addresses collected, so traffic arriving AT this firewall cannot be told '
        + 'from traffic passing THROUGH it.')
      : cell('interfaces', STATE.MEASURED, `${ifaces} interfaces collected.`));

  // ── object resolution
  const refs = num(r.objectRefs);
  const unres = num(r.objectUnresolvable);
  if (refs === null || unres === null) {
    cells.push(unreadableCell('objects',
      'How many of this firewall’s rule object references resolve could not be read.'));
  } else if (refs === 0) {
    // ⛔ NO REFERENCES AND NO RULESET ARE NOT THE SAME FACT. With rules
    // collected, zero references is a measured zero — there is nothing to
    // resolve. With no ruleset (or an unreadable one) the references could not
    // have been counted in the first place, and the answers object resolution
    // gates stay unavailable.
    if (rules === null) {
      cells.push(unreadableCell('objects',
        'No rule object references were counted and the rule count could not be read, so '
        + 'whether this firewall has objects to resolve is unknown.'));
    } else if (rules === 0) {
      cells.push(cell('objects', STATE.ABSENT,
        'No rules have been collected, so there are no object references to resolve — '
        + 'application impact, rule retirement and access-path queries have nothing to run on.'));
    } else {
      cells.push(cell('objects', STATE.MEASURED,
        'No rule on this firewall references a named object, so there is nothing to resolve.'));
    }
  } else if (unres === 0) {
    cells.push(cell('objects', STATE.MEASURED, `All ${refs} object references resolve.`));
  } else {
    cells.push(cell('objects', unres >= refs ? STATE.ABSENT : STATE.PARTIAL,
      `${unres} of ${refs} rule object references (${sharePct(unres, refs)}) name something this `
      + 'firewall never reported, so application impact and retirement cannot conclude.',
      { share: unres / refs }));
  }

  // ── configuration freshness
  //
  // ⛔ THE ROW COUNT IS WHAT SEPARATES "NO CONFIG" FROM "UNREADABLE AGE". The
  // age is an EXTRACT over max(collected_at), which is SQL NULL both when there
  // is no snapshot at all and when the value did not travel — and the cell
  // asserted the first of those as a certain fact either way. The AGE is still
  // the measurement: when it reads, the row count adds nothing and is ignored.
  const cfgRows = num(r.configRows);
  const cfgAge = num(r.configAgeDays);
  if (cfgAge === null && cfgRows === 0) {
    cells.push(cell('config', STATE.ABSENT, 'No configuration has been collected.'));
  } else if (cfgAge === null && cfgRows === null) {
    cells.push(unreadableCell('config',
      'Whether any configuration has been collected from this firewall could not be read.'));
  } else if (cfgAge === null) {
    cells.push(unreadableCell('config',
      'A configuration has been collected, but its age could not be read, so whether '
      + 'compliance and CVE applicability here are scored on current evidence is unknown.'));
  } else if (cfgAge > STALE_AFTER_DAYS) {
    cells.push(cell('config', STATE.STALE,
      `Configuration is ${cfgAge} days old, so compliance and CVE applicability here are scored `
      + 'on evidence that age.', { ageDays: cfgAge }));
  } else {
    cells.push(cell('config', STATE.MEASURED,
      `Configuration collected ${cfgAge} day(s) ago.`, { ageDays: cfgAge }));
  }

  // ── version
  // ⛔ `count(*)` IS NEVER SQL NULL, so a null here is a value that did not
  // travel — which is not the same statement as "no version was collected", and
  // was reported as one.
  const versions = num(r.versionRows);
  cells.push(versions === null
    ? unreadableCell('version', 'Whether a firmware version has been collected could not be read.')
    : versions === 0
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
  // ⛔ COUNTED APART FROM `uncertain`. "This gap is established and something
  // that might have shrunk it could not be read" and "we could not establish
  // this gap at all" send a reader to different places, and only the second may
  // be withheld from the work queue.
  const unreadMitigation = cells.filter((c) => c.mitigationUnknown);

  return {
    deviceId: r.deviceId,
    deviceName: r.deviceName,
    vendor: r.vendor,
    cells,
    gaps,
    gapCount: gaps.length,
    // ⛔ THE RANKING NUMBER: answers withheld, not gaps counted. Rounded for
    // DISPLAY only.
    answersWithheld: Math.round(gaps.reduce((n, c) => n + c.weight, 0) * 10) / 10,
    // ⛔ AND THE RANKING USES THE UNROUNDED SUM. Now that a partial gap is
    // weighted by its share, two firewalls differing by 0.02 both display as
    // "3.1" — and ranking on the displayed figure would hand the order back to
    // `localeCompare(deviceName)`, which is the collapse the share was
    // introduced to fix, re-created by a display rounding.
    answersWithheldExact: gaps.reduce((n, c) => n + c.weight, 0),
    blockedEngines: [...new Set(gaps.flatMap((c) => c.gates))],
    staleFindings,
    uncertainCount: uncertain.length,
    mitigationUnknownCount: unreadMitigation.length,
    // ⛔ VISIBILITY, NOT SAFETY. Named so it cannot be read as an all-clear.
    fullyCovered: gaps.length === 0 && !staleFindings,
  };
}

/**
 * Rank by consequence. ⛔ Stale findings outrank a pure gap of equal weight.
 * ⛔ On the UNROUNDED weight, falling back to the displayed one for an entry that
 * carries no exact figure — ranking on a rounded number reintroduces ties that
 * fall through to the device NAME.
 */
function rankRegister(entries) {
  const withheldOf = (e) => (typeof e.answersWithheldExact === 'number'
    ? e.answersWithheldExact
    : e.answersWithheld);
  return [...(Array.isArray(entries) ? entries : [])].sort((a, b) => {
    const aS = a.staleFindings ? 1 : 0;
    const bS = b.staleFindings ? 1 : 0;
    if (aS !== bS) return bS - aS;
    if (withheldOf(a) !== withheldOf(b)) return withheldOf(b) - withheldOf(a);
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
    // ⛔ AND A THIRD COUNT, because an established gap whose MITIGATION could
    // not be read is neither of the other two.
    devicesWithUnreadMitigations: list.filter((e) => e.mitigationUnknownCount > 0).length,
    gapsBySource: byGap,
    blockedEngines: [...new Set(list.flatMap((e) => e.blockedEngines))].sort(),
  };
}

module.exports = {
  assessDevice, rankRegister, summariseRegister,
  SOURCES, STATE, STALE_AFTER_DAYS,
};
