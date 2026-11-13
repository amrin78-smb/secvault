// lib/engines/complianceControls.js
//
// The check library turned the other way up: one row per CONTROL, across the
// whole fleet, instead of one row per FIREWALL across the library.
//
// Every compliance surface in this product is device-first — pick a firewall,
// read its 74 answers. Nothing could answer the question an auditor opens
// with: "which control is failing on the most firewalls?" The data was always
// there (`audit_findings` is a (device, check) pair); no view aggregated it on
// the check axis.
//
// ⛔ A CONTROL HAS NO SINGLE FLEET-WIDE STATUS, AND THAT IS THE WHOLE REASON
// THIS FILE IS CAREFUL. `audit_findings` rows are (device, check) PAIRS:
// `rule-no-any-any-allow` is failing on four firewalls and passing on eleven
// AT THE SAME TIME. A headline reading "74 checks: 45 passed, 29 failed"
// silently picks one of those answers per check and throws the rest away —
// and the two units do not even reconcile, because 45+29+6 counts pairs while
// 74 counts checks. CLAUDE.md states the rule for the per-standard grain
// ("TWO UNITS, KEPT APART"); this is the same rule on the check grain. So
// every number here is a COUNT OF FIREWALLS, named as one.
//
// ⛔ AND A CONTROL WITH NO FAILURES IS NOT AUTOMATICALLY CLEAN. Seven states,
// not two, because the ways a control can fail to produce a failure are not
// interchangeable and send an operator to four different places:
//
//   failing        at least one firewall answered `fail`. A MEASUREMENT.
//   warning        none failed; at least one answered `warning` — the
//                  predicate ran against a collected config and came back
//                  indeterminate, which is a fact about the DEVICE.
//   not_measured   applicable to firewalls, and not one of them has an
//                  answer. Zero findings has two causes and this is the
//                  honest name for both. CLEARABLE.
//   partial        passing everywhere it was asked, and it was not asked
//                  everywhere. ⛔ THE STATE THIS PAGE EXISTS TO MAKE VISIBLE:
//                  a control passing on 3 of 16 applicable firewalls is not a
//                  green tick, and rendering it as one is this codebase's
//                  signature bug with a reassuring colour on it.
//   clean          passing on every firewall it applies to, with no gap.
//   not_evaluable  declared unanswerable BY CONSTRUCTION
//                  (`predicate_type: 'not_evaluable_from_config'`). PERMANENT
//                  — nothing an operator changes on a firewall makes this
//                  answerable, so it must never sit in the same bucket as
//                  `not_measured`, which clears itself on the next pull. Same
//                  distinction `capacityForecast.js` draws between
//                  `bytes_not_summable` and `no_log_coverage`.
//   not_applicable no active firewall is of this check's vendor.
//
// ⛔ A MEASUREMENT OUTRANKS A DECLARATION. `fail` and `warning` are tested
// BEFORE `not_evaluable_from_config`, so a check that somehow produced a real
// finding is reported as failing whatever its predicate claims about itself —
// the rule v2.226.0's rule-scan guard already follows ("a present finding is a
// MEASUREMENT and still fails, whatever the run state says").
//
// ⛔ NO PER-CONTROL PERCENTAGE, EVER. `scorePct` is the headline compliance
// figure and there is exactly one of it. "C-102: 69% compliant" would be a
// second percentage, computed over a different denominator, sitting beside the
// first and disagreeing with it — the artefact `compliance_exceptions` is
// forbidden from creating for the same reason ("COUNTS AND A HUELESS GRADE,
// NEVER A RIVAL PERCENTAGE"). Counts of firewalls, and a state. Nothing else.
//
// PURE — no pool, no clock it is not handed. `complianceControlsData.js` is
// the plumbing.

'use strict';

const FAILING = 'failing';
const WARNING = 'warning';
const NOT_MEASURED = 'not_measured';
const PARTIAL = 'partial';
const CLEAN = 'clean';
const NOT_EVALUABLE = 'not_evaluable';
const NOT_APPLICABLE = 'not_applicable';

const CONTROL_STATES = [
  FAILING,
  WARNING,
  NOT_MEASURED,
  PARTIAL,
  CLEAN,
  NOT_EVALUABLE,
  NOT_APPLICABLE,
];

// ⛔ THE ORDER IS THE DEFAULT SORT AND IT IS NOT ALPHABETICAL OR AESTHETIC.
// It ranks by what the operator should look at next, and the two non-obvious
// placements are deliberate: `not_measured` sits ABOVE `clean` because a
// control nobody has answered is a coverage gap worth closing, and `partial`
// sits above `clean` because it IS a clean answer with a hole in it.
const STATE_RANK = {
  [FAILING]: 0,
  [WARNING]: 1,
  [NOT_MEASURED]: 2,
  [PARTIAL]: 3,
  [CLEAN]: 4,
  [NOT_EVALUABLE]: 5,
  [NOT_APPLICABLE]: 6,
};

const STATE_LABELS = {
  [FAILING]: 'Failing',
  [WARNING]: 'Indeterminate',
  [NOT_MEASURED]: 'Never measured',
  [PARTIAL]: 'Passing where measured',
  [CLEAN]: 'Passing',
  [NOT_EVALUABLE]: 'Not evaluable from config',
  [NOT_APPLICABLE]: 'No firewall of this vendor',
};

// ⛔ FOUR OF THE SEVEN CARRY NO HUE, AND THAT IS THE POINT. `not_measured`,
// `partial`, `not_evaluable` and `not_applicable` are all statements about
// SECVAULT's reach, not about the customer's security posture — CLAUDE.md's
// own rule that a gap in OUR evidence is never ranked on the severity ramp.
// Rendering `partial` green would be the defect this state exists to expose.
const STATE_TONES = {
  [FAILING]: 'danger',
  [WARNING]: 'warning',
  [NOT_MEASURED]: 'unmeasured',
  [PARTIAL]: 'unmeasured',
  [CLEAN]: 'success',
  [NOT_EVALUABLE]: 'unmeasured',
  [NOT_APPLICABLE]: 'unmeasured',
};

// One sentence, exported so a test can pin it, in the shape `IMPACT_CLAIM` and
// `COVERAGE_CLAIM` already use. It names the unit, because the unit is what
// every mock of this page gets wrong.
const CONTROL_CLAIM =
  'Every count on this page is a number of FIREWALLS. A control has no single '
  + 'fleet-wide verdict: the same control can be failing on one firewall and '
  + 'passing on another, and both are true.';

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const KNOWN_SEVERITIES = Object.keys(SEVERITY_RANK);

// `audit_findings.status` has no CHECK constraint (lib/schema.sql), so a value
// outside these four is reachable. It is counted as `unreadable` rather than
// dropped — a row we cannot interpret is not a row that said "pass".
const KNOWN_STATUSES = ['pass', 'fail', 'warning', 'na'];

function intOrNull(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function text(v) {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

/**
 * Collapse this check's finding rows to one answer per device.
 *
 * ⛔ THE WORST STATUS WINS ON A DUPLICATE. `audit_findings` is DELETE+
 * reinserted per run and carries no UNIQUE(device_id, check_id), so two rows
 * for one pair is reachable — mid-run, or after a partial write. Picking the
 * first would make a failure disappear behind a stale pass; picking the worst
 * is the direction `exposure.js` names ("under-reporting is the more dangerous
 * error"). An unreadable status outranks `pass` for the same reason.
 */
const STATUS_SEVERITY = { fail: 0, warning: 1, unreadable: 2, na: 3, pass: 4 };

function collapseByDevice(findings) {
  const byDevice = new Map();
  for (const f of Array.isArray(findings) ? findings : []) {
    if (!f || typeof f !== 'object') continue;
    const deviceId = text(f.deviceId);
    if (!deviceId) continue;
    const raw = text(f.status);
    const status = raw && KNOWN_STATUSES.includes(raw) ? raw : 'unreadable';
    const prev = byDevice.get(deviceId);
    if (prev && STATUS_SEVERITY[prev.status] <= STATUS_SEVERITY[status]) continue;
    byDevice.set(deviceId, {
      deviceId,
      deviceName: text(f.deviceName),
      status,
      detectedAt: text(f.detectedAt),
    });
  }
  return [...byDevice.values()];
}

/**
 * One control's fleet-wide picture. PURE.
 *
 * @param {object} input
 * @param {string} input.slug          audit_checks.check_id (the text slug)
 * @param {object[]} input.findings    [{deviceId, deviceName, status, detectedAt}]
 * @param {number|null} input.applicableDeviceCount  active firewalls this
 *        check's vendor scope admits. ⛔ `null` means UNREADABLE, never zero —
 *        zero is a real answer ("no firewall of this vendor") with a different
 *        state attached.
 * @param {object[]} input.liveExceptions [{deviceId}] already filtered to the
 *        states that actually cover a failure. Never recomputed here.
 */
function buildControl(input) {
  const src = input && typeof input === 'object' ? input : {};
  const slug = text(src.slug) || null;
  const devices = collapseByDevice(src.findings);

  const counts = { fail: 0, warning: 0, pass: 0, na: 0, unreadable: 0 };
  let lastEvaluated = null;
  for (const d of devices) {
    counts[d.status] += 1;
    if (d.detectedAt && (lastEvaluated === null || d.detectedAt > lastEvaluated)) {
      lastEvaluated = d.detectedAt;
    }
  }

  const applicable = intOrNull(src.applicableDeviceCount);
  const answered = devices.length;
  // ⛔ NEVER NEGATIVE AND NEVER GUESSED. An unreadable `applicable` leaves this
  // null, which propagates into `partial` below — we cannot prove the control
  // was asked everywhere, so we do not claim it.
  const notEvaluated = applicable === null ? null : Math.max(0, applicable - answered);

  const predicateType = text(src.predicateType);
  const declaredUnanswerable = predicateType === 'not_evaluable_from_config';

  let status;
  if (counts.fail > 0) status = FAILING;
  else if (counts.warning > 0) status = WARNING;
  else if (declaredUnanswerable) status = NOT_EVALUABLE;
  else if (applicable === 0) status = NOT_APPLICABLE;
  else if (counts.pass > 0 && notEvaluated === 0 && counts.unreadable === 0) status = CLEAN;
  else if (counts.pass > 0) status = PARTIAL;
  else status = NOT_MEASURED;

  const failingDevices = devices
    .filter((d) => d.status === 'fail')
    .sort((a, b) => String(a.deviceName || '').localeCompare(String(b.deviceName || '')));

  const severity = text(src.severity);
  const exceptions = Array.isArray(src.liveExceptions) ? src.liveExceptions : null;

  return {
    slug,
    name: text(src.name) || slug,
    description: text(src.description),
    // ⛔ An unrecognised severity stays as the raw string rather than being
    // mapped to a default. `medium` is the column's DEFAULT, so silently
    // showing it for a value we did not understand would invent a grading.
    severity,
    severityKnown: severity !== null && KNOWN_SEVERITIES.includes(severity),
    standards: Array.isArray(src.standards) ? src.standards.filter((s) => typeof s === 'string') : [],
    vendor: text(src.vendor),
    predicateType,
    status,
    counts,
    answeredDeviceCount: answered,
    applicableDeviceCount: applicable,
    notEvaluatedDeviceCount: notEvaluated,
    failingDevices,
    // ⛔ null, not 0, when the exceptions table could not be read. "No
    // exception covers this failure" and "we do not know whether one does"
    // send an operator to different places.
    exceptionDeviceCount: exceptions === null ? null : exceptions.length,
    lastEvaluated,
  };
}

function buildControls(rows) {
  return (Array.isArray(rows) ? rows : []).map(buildControl);
}

function severityRank(control) {
  if (!control || !control.severityKnown) return KNOWN_SEVERITIES.length;
  return SEVERITY_RANK[control.severity];
}

/**
 * Default order: what to look at next.
 *
 * Within `failing`, the control failing on the MOST firewalls comes first —
 * that is the whole question this page was built to answer. Severity breaks
 * the tie, then the name, so the order is total and does not depend on the
 * order rows came back from Postgres.
 */
function sortControls(controls) {
  return [...(Array.isArray(controls) ? controls : [])].sort((a, b) => {
    const rank = (STATE_RANK[a.status] ?? 99) - (STATE_RANK[b.status] ?? 99);
    if (rank !== 0) return rank;
    const byFailing = (b.counts.fail || 0) - (a.counts.fail || 0);
    if (byFailing !== 0) return byFailing;
    const bySeverity = severityRank(a) - severityRank(b);
    if (bySeverity !== 0) return bySeverity;
    return String(a.name || '').localeCompare(String(b.name || ''));
  });
}

/**
 * Validate the URL's filter values.
 *
 * ⛔ AN UNRECOGNISED VALUE IS KEPT AND MATCHES NOTHING — never dropped, and
 * never widened to "everything". `/work` learned this the expensive way: a
 * dropped filter returns the whole list, which an operator reads as "the
 * filter applied and everything matched". The raw value travels back in
 * `unknown` so the page can show it rather than leaving a filter that silently
 * does nothing.
 */
function parseControlFilters(params, knownStandards) {
  const p = params && typeof params === 'object' ? params : {};
  const standards = Array.isArray(knownStandards) ? knownStandards : [];
  const one = (v) => (typeof v === 'string' && v.length > 0 ? v : null);

  const filters = {
    status: one(p.status),
    standard: one(p.standard),
    severity: one(p.severity),
    q: one(p.q),
  };
  const unknown = [];
  if (filters.status !== null && !CONTROL_STATES.includes(filters.status)) {
    unknown.push({ key: 'status', value: filters.status });
  }
  if (filters.standard !== null && !standards.includes(filters.standard)) {
    unknown.push({ key: 'standard', value: filters.standard });
  }
  if (filters.severity !== null && !KNOWN_SEVERITIES.includes(filters.severity)) {
    unknown.push({ key: 'severity', value: filters.severity });
  }
  const active = Object.keys(filters).filter((k) => filters[k] !== null);
  return { filters, unknown, active };
}

function filterControls(controls, filters) {
  const f = filters && typeof filters === 'object' ? filters : {};
  const needle = typeof f.q === 'string' ? f.q.trim().toLowerCase() : '';
  return (Array.isArray(controls) ? controls : []).filter((c) => {
    if (f.status !== null && f.status !== undefined && c.status !== f.status) return false;
    if (f.standard !== null && f.standard !== undefined && !c.standards.includes(f.standard)) return false;
    if (f.severity !== null && f.severity !== undefined && c.severity !== f.severity) return false;
    if (needle) {
      const hay = `${c.slug || ''} ${c.name || ''} ${c.description || ''}`.toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    return true;
  });
}

/**
 * The headline figures — ALWAYS computed on the UNFILTERED list.
 *
 * ⛔ THE SUMMARY MUST NOT FOLLOW THE FILTER. `?status=failing` with no matches
 * would otherwise render this page's own headline as "nothing is failing" over
 * a fleet with twenty-nine failing controls — a filter silently becoming an
 * all-clear, on the one screen whose job is to say what is failing. Same rule,
 * and the same reason, as `/work`'s `summarise()`.
 */
function summariseControls(controls) {
  const list = Array.isArray(controls) ? controls : [];
  const byStatus = {};
  for (const s of CONTROL_STATES) byStatus[s] = 0;

  const failingFirewalls = new Set();
  let failingPairs = 0;
  let withLiveException = 0;
  let exceptionsReadable = true;

  for (const c of list) {
    if (Object.prototype.hasOwnProperty.call(byStatus, c.status)) byStatus[c.status] += 1;
    failingPairs += c.counts.fail || 0;
    for (const d of c.failingDevices) failingFirewalls.add(d.deviceId);
    if (c.exceptionDeviceCount === null) exceptionsReadable = false;
    else if (c.exceptionDeviceCount > 0) withLiveException += 1;
  }

  return {
    total: list.length,
    byStatus,
    failingControls: byStatus[FAILING],
    // ⛔ TWO UNITS, NAMED APART. `failingControls` counts CHECKS;
    // `failingPairs` counts (firewall, check) answers. They are different
    // numbers and neither may be printed as the other.
    failingPairs,
    firewallsAffected: failingFirewalls.size,
    notMeasured: byStatus[NOT_MEASURED],
    partial: byStatus[PARTIAL],
    notEvaluable: byStatus[NOT_EVALUABLE],
    notApplicable: byStatus[NOT_APPLICABLE],
    controlsWithLiveException: exceptionsReadable ? withLiveException : null,
  };
}

/**
 * The filter options, DERIVED from the controls actually present.
 *
 * ⛔ NEVER A HARDCODED LIST. An option that can only ever return nothing is
 * indistinguishable from a filter that is broken, and a static list goes stale
 * the moment the seed library gains a severity or a standard — the rule
 * `WorkQueueFilters` already follows. The ORDER is the canonical one, not the
 * order rows arrived, so the dropdown does not reshuffle itself between loads.
 */
function controlFilterOptions(controls) {
  const list = Array.isArray(controls) ? controls : [];
  const seenStatus = new Set();
  const seenStandard = new Set();
  const seenSeverity = new Set();
  for (const c of list) {
    if (c.status) seenStatus.add(c.status);
    for (const st of c.standards) seenStandard.add(st);
    // ⛔ An unrecognised severity is still offered, because it is genuinely
    // present in the library and hiding it would leave rows no filter can
    // reach. It simply sorts last.
    if (c.severity) seenSeverity.add(c.severity);
  }
  const severities = [...seenSeverity].sort(
    (a, b) => (SEVERITY_RANK[a] ?? 99) - (SEVERITY_RANK[b] ?? 99) || a.localeCompare(b)
  );
  return {
    statuses: CONTROL_STATES.filter((s) => seenStatus.has(s)),
    standards: [...seenStandard].sort(),
    severities,
  };
}

module.exports = {
  // states
  FAILING,
  WARNING,
  NOT_MEASURED,
  PARTIAL,
  CLEAN,
  NOT_EVALUABLE,
  NOT_APPLICABLE,
  CONTROL_STATES,
  STATE_LABELS,
  STATE_TONES,
  STATE_RANK,
  KNOWN_SEVERITIES,
  CONTROL_CLAIM,
  // pure
  buildControl,
  buildControls,
  sortControls,
  parseControlFilters,
  filterControls,
  summariseControls,
  controlFilterOptions,
};
