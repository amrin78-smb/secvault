// lib/engines/applicationViewData.js
//
// The application view's PLUMBING. Loads declared applications and the fleet's
// rulebase, hands both to the pure evaluator in applicationView.js, and returns
// what the page and the routes render. The split is what makes the judgement
// testable: everything that decides anything lives in the pure half.
//
// ⛔ NOTHING IS CACHED AND NO VERDICT IS STORED. A verdict is a function of the
// current rulebase and the current traffic window; a stored one goes stale and
// is then read as fact — which is precisely the defect this feature exists to
// beat the competition on. schema.sql says the same thing beside the tables.
//
// ⛔ TRAFFIC EVIDENCE IS NOT RE-DERIVED HERE. It comes from
// ruleHitCorrelation.js unchanged, the same way segmentationData.js takes it.
// Two implementations of "has this rule seen traffic" would eventually
// disagree, and the wrong one would be the one justifying a deletion.

'use strict';

const { buildObjectMap } = require('./objectResolver');

const {
  normaliseFlow,
  evaluateFlowOnDevice,
  aggregateFlow,
  usedVerdict,
  flowFinding,
  VERDICTS,
  USED,
} = require('./applicationView');

const { isAllowAction } = require('./segmentation');

const {
  getDeviceLogCoverage,
  getLoggedRuleHits,
  enrichRulesWithLogEvidence,
} = require('./ruleHitCorrelation');

const DEFAULT_WINDOW_DAYS = 30;

// ⛔ THE WINDOW IS RESOLVED ONCE, AND THE RESOLVED VALUE IS WHAT IS REPORTED.
//
// This is the same defect segmentationData.js already documents having fixed,
// and it was still live here. `loadFleet` resolved with
// `Number.isFinite(Number(x)) ? Math.max(1, trunc(x)) : 30`, while the evidence
// it then loads is bounded by ruleHitCorrelation's own clampDays (floor 7, cap
// 400). Measured against the live fleet, every one of these reported a span the
// evidence did not cover:
//   windowDays: null  -> reported 1    (Number(null) === 0, which IS finite —
//                        the exact trap; a missing value read as a real one)
//   windowDays: ''    -> reported 1
//   windowDays: -5    -> reported 1    measured 7
//   windowDays: 3     -> reported 3    measured 7
//   windowDays: 1000  -> reported 1000 measured 400
// The last is the worst direction: the page states the traffic evidence spans
// 1,000 days when it spans at most 400 (and at most SYSLOG_RETENTION_DAYS of
// real logs). A window that is misreported is worse than one that is wrong —
// every number on the page is a measurement, and the stated span is how the
// reader decides what the measurement is worth.
//
// ⛔ THE FLOOR OF 7 AND CAP OF 400 MIRROR ruleHitCorrelation.clampDays, which is
// not exported. The floor is not a style choice: below it a single day of logs
// satisfies both coverage tests and can certify a rule as a MEASURED zero. If
// those bounds move, this must follow — a test pins the window this function
// reports against the window getDeviceLogCoverage was actually handed.
const MIN_WINDOW_DAYS = 7;
const MAX_WINDOW_DAYS = 400;

function resolveWindowDays(days) {
  // ⛔ Absent is absent. null/undefined/'' mean "the caller said nothing", not
  // "the caller said zero" — and Number(null) is 0, which passes every finiteness
  // check there is.
  if (days === null || days === undefined || days === '') return DEFAULT_WINDOW_DAYS;
  const n = Number(days);
  if (!Number.isFinite(n)) return DEFAULT_WINDOW_DAYS;
  return Math.min(Math.max(Math.trunc(n), MIN_WINDOW_DAYS), MAX_WINDOW_DAYS);
}

// ── CRUD ───────────────────────────────────────────────────────────────────

async function listApplications(pool) {
  const { rows } = await pool.query(
    `SELECT a.id, a.name, a.owner, a.criticality, a.status, a.note,
            a.created_by, a.created_at, a.updated_at,
            count(f.id)::int AS flow_count
       FROM applications a
       LEFT JOIN application_flows f ON f.application_id = a.id
      GROUP BY a.id
      ORDER BY a.name ASC`
  );
  return rows;
}

async function getApplication(pool, id) {
  const { rows } = await pool.query(
    `SELECT id, name, owner, criticality, status, note, created_by, created_at, updated_at
       FROM applications WHERE id = $1::uuid`,
    [id]
  );
  if (rows.length === 0) return null;
  const { rows: flows } = await pool.query(
    `SELECT id, application_id, src, dst, protocol, port_start, port_end,
            expectation, note, created_at, updated_at
       FROM application_flows
      WHERE application_id = $1::uuid
      ORDER BY created_at ASC`,
    [id]
  );
  return { ...rows[0], flows };
}

async function createApplication(pool, input, createdBy) {
  const { rows } = await pool.query(
    `INSERT INTO applications (name, owner, criticality, status, note, created_by)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id, name, owner, criticality, status, note, created_by, created_at, updated_at`,
    [
      input.name,
      input.owner || null,
      input.criticality === 'critical' ? 'critical' : 'normal',
      ['active', 'retiring', 'retired'].includes(input.status) ? input.status : 'active',
      input.note || null,
      createdBy || null,
    ]
  );
  return rows[0];
}

async function updateApplication(pool, id, input) {
  const { rows } = await pool.query(
    `UPDATE applications
        SET name = COALESCE($2, name),
            owner = $3,
            criticality = COALESCE($4, criticality),
            status = COALESCE($5, status),
            note = $6,
            updated_at = now()
      WHERE id = $1::uuid
      RETURNING id, name, owner, criticality, status, note, created_by, created_at, updated_at`,
    [
      id,
      input.name || null,
      input.owner === undefined ? null : input.owner,
      input.criticality === 'critical' || input.criticality === 'normal' ? input.criticality : null,
      ['active', 'retiring', 'retired'].includes(input.status) ? input.status : null,
      input.note === undefined ? null : input.note,
    ]
  );
  return rows[0] || null;
}

async function deleteApplication(pool, id) {
  const { rowCount } = await pool.query('DELETE FROM applications WHERE id = $1::uuid', [id]);
  return rowCount > 0;
}

/**
 * ⛔ VALIDATED BEFORE IT IS STORED, by the same parser that will evaluate it.
 * A flow whose src does not parse can never produce a verdict, so accepting it
 * would put a permanently unanswerable row in the operator's list and leave
 * them to work out which field was wrong.
 */
async function addFlow(pool, applicationId, input) {
  const check = normaliseFlow(input);
  if (!check.ok) return { ok: false, reason: check.reason };
  const { rows } = await pool.query(
    `INSERT INTO application_flows
       (application_id, src, dst, protocol, port_start, port_end, expectation, note)
     VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)
     RETURNING id, application_id, src, dst, protocol, port_start, port_end,
               expectation, note, created_at, updated_at`,
    [
      applicationId,
      String(input.src).trim(),
      String(input.dst).trim(),
      String(input.protocol || 'tcp').trim().toLowerCase(),
      input.port_start === undefined || input.port_start === null || input.port_start === ''
        ? null : Number(input.port_start),
      input.port_end === undefined || input.port_end === null || input.port_end === ''
        ? null : Number(input.port_end),
      input.expectation === 'deny' ? 'deny' : 'allow',
      input.note || null,
    ]
  );
  return { ok: true, flow: rows[0] };
}

async function updateFlow(pool, flowId, input) {
  const check = normaliseFlow(input);
  if (!check.ok) return { ok: false, reason: check.reason };
  const { rows } = await pool.query(
    `UPDATE application_flows
        SET src = $2, dst = $3, protocol = $4, port_start = $5, port_end = $6,
            expectation = $7, note = $8, updated_at = now()
      WHERE id = $1::uuid
      RETURNING id, application_id, src, dst, protocol, port_start, port_end,
                expectation, note, created_at, updated_at`,
    [
      flowId,
      String(input.src).trim(),
      String(input.dst).trim(),
      String(input.protocol || 'tcp').trim().toLowerCase(),
      input.port_start === undefined || input.port_start === null || input.port_start === ''
        ? null : Number(input.port_start),
      input.port_end === undefined || input.port_end === null || input.port_end === ''
        ? null : Number(input.port_end),
      input.expectation === 'deny' ? 'deny' : 'allow',
      input.note || null,
    ]
  );
  return rows[0] ? { ok: true, flow: rows[0] } : { ok: false, reason: 'No such flow.' };
}

async function deleteFlow(pool, flowId) {
  const { rowCount } = await pool.query('DELETE FROM application_flows WHERE id = $1::uuid', [flowId]);
  return rowCount > 0;
}

// ── The fleet rulebase ─────────────────────────────────────────────────────

/**
 * Every active device's rules and objects, with traffic evidence attached.
 *
 * ⛔ A DEVICE WITH NO COLLECTED RULES IS NAMED, NOT OMITTED. A device with no
 * rows is indistinguishable from a device that does not exist unless the active
 * list is loaded separately — and "we could not read this firewall" must never
 * be silently equivalent to "this firewall permits nothing".
 */
async function loadFleet(pool, options = {}) {
  const windowDays = resolveWindowDays(options.windowDays);
  const at = options.now instanceof Date ? options.now : new Date();

  const [{ rows: ruleRows }, { rows: activeRows }, { rows: objectRows }] = await Promise.all([
    pool.query(
      `SELECT fr.id, fr.device_id, fr.rule_name, fr.rule_id_vendor, fr.sequence_number,
              fr.enabled, fr.action, fr.src_addresses, fr.dst_addresses, fr.services,
              fr.hit_count, fr.log_enabled, fr.vdom
         FROM firewall_rules fr
         JOIN devices d ON d.id = fr.device_id
        WHERE d.active = true
        ORDER BY fr.device_id, fr.sequence_number NULLS LAST`
    ),
    pool.query('SELECT id, name, vendor FROM devices WHERE active = true ORDER BY name'),
    pool.query(
      `SELECT no.device_id, no.object_type, no.name, no.value, no.members
         FROM network_objects no
         JOIN devices d ON d.id = no.device_id
        WHERE d.active = true`
    ),
  ]);

  const rulesByDevice = new Map();
  for (const r of ruleRows) {
    if (!rulesByDevice.has(r.device_id)) rulesByDevice.set(r.device_id, []);
    rulesByDevice.get(r.device_id).push(r);
  }
  const objectsByDevice = new Map();
  for (const o of objectRows) {
    if (!objectsByDevice.has(o.device_id)) objectsByDevice.set(o.device_id, []);
    objectsByDevice.get(o.device_id).push(o);
  }

  // ⛔ ONE getLoggedRuleHits PER DEVICE, an N+1 kept on purpose — the same
  // decision segmentationData.js documents. Collapsing it would mean
  // reimplementing that function's handling of Fortinet's implicit-deny
  // pseudo-rule and of vendor-id-vs-name matching.
  const coverageMap = await getDeviceLogCoverage(pool, windowDays, at);
  const devices = [];
  for (const d of activeRows) {
    const deviceRules = rulesByDevice.get(d.id) || [];
    let enriched = deviceRules;
    if (deviceRules.length > 0) {
      // eslint-disable-next-line no-await-in-loop
      const hitMaps = await getLoggedRuleHits(pool, d.id, windowDays, at);
      const coverage = coverageMap instanceof Map ? coverageMap.get(d.id) : null;
      enriched = enrichRulesWithLogEvidence(deviceRules, coverage, hitMaps);
    }
    const objects = objectsByDevice.get(d.id) || [];
    devices.push({
      id: d.id,
      name: d.name,
      vendor: d.vendor,
      rules: enriched,
      objects,
      // Built ONCE per device here and reused for every flow — see the note in
      // evaluateFlowOnDevice. Rebuilding these per flow was the dominant cost.
      addressObjects: buildObjectMap(objects, ['address', 'address_group']),
      serviceObjects: buildObjectMap(objects, ['service', 'service_group']),
      hasRules: deviceRules.length > 0,
    });
  }

  return {
    devices,
    windowDays,
    activeDeviceCount: activeRows.length,
    devicesWithRules: devices.filter((d) => d.hasRules).length,
    devicesWithoutRules: devices.filter((d) => !d.hasRules).map((d) => d.name || d.id),
  };
}

// ── Evaluation ─────────────────────────────────────────────────────────────

/** One declared flow against the whole loaded fleet. */
function evaluateFlow(flowRow, fleet) {
  const normalised = normaliseFlow(flowRow);
  if (!normalised.ok) {
    // ⛔ An undeclarable flow is reported as such and counted, never dropped and
    // never silently treated as satisfied.
    return {
      flow: flowRow,
      invalid: true,
      reason: normalised.reason,
      verdict: null,
      used: null,
      finding: { state: 'invalid', label: 'This flow could not be read' },
      unverified: true,
      unverifiedReasons: [normalised.reason],
      permittedBy: [],
      blockedBy: [],
    };
  }

  const perDevice = [];
  for (const device of fleet.devices) {
    if (!device.hasRules) continue; // counted via devicesWithoutRules, not evaluated
    perDevice.push({
      device,
      result: evaluateFlowOnDevice(normalised, device.rules, device.objects, {
        addressObjects: device.addressObjects,
        serviceObjects: device.serviceObjects,
      }),
    });
  }

  const agg = aggregateFlow(perDevice, {
    devicesWithoutRules: fleet.devicesWithoutRules.length,
  });

  // ⛔ The USED axis is computed from the PERMITTING rules only, and it speaks
  // about those rules, not about the flow. No rollup in this product carries
  // both ends of a flow, so per-flow usage is not answerable at all — see the
  // note in applicationView.usedVerdict().
  const permittingRules = agg.permittedBy.flatMap((p) => p.rules);
  const used = usedVerdict(permittingRules);

  return {
    flow: flowRow,
    invalid: false,
    verdict: agg.verdict,
    permittedPct: agg.permittedPct,
    used,
    finding: flowFinding(flowRow.expectation, agg),
    unverified: agg.unverified,
    unverifiedReasons: agg.unverifiedReasons,
    permittedBy: agg.permittedBy,
    blockedBy: agg.blockedBy,
    evaluatedDeviceCount: agg.evaluatedDeviceCount,
  };
}

/**
 * Roll a set of evaluated flows up to an application-level state.
 *
 * ⛔ AN APPLICATION IS AS UNVERIFIED AS ITS LEAST-VERIFIED FLOW, and an
 * all-clear is forbidden while anything is unverified — the rule lib/evidence.js
 * already enforces across this product. A clean result over partial coverage is
 * the most dangerous output this page could produce.
 */
function summariseFlows(evaluated) {
  const counts = {
    total: evaluated.length,
    ok: 0, broken: 0, partial: 0, violation: 0, unspecified: 0, invalid: 0, unverified: 0,
  };
  for (const e of evaluated) {
    const s = e.finding.state;
    if (s === 'ok') counts.ok += 1;
    else if (s === 'ok_unverified') { counts.ok += 1; counts.unverified += 1; }
    else if (s === 'broken') counts.broken += 1;
    else if (s === 'partial') counts.partial += 1;
    else if (s === 'violation') counts.violation += 1;
    else if (s === 'invalid') counts.invalid += 1;
    else counts.unspecified += 1;
    if (e.unverified && s !== 'ok_unverified') counts.unverified += 1;
  }

  const problems = counts.broken + counts.partial + counts.violation;
  let state;
  if (counts.total === 0) state = 'undeclared';
  else if (problems > 0) state = 'problem';
  else if (counts.unverified > 0 || counts.unspecified > 0 || counts.invalid > 0) state = 'unverified';
  else state = 'ok';

  return { ...counts, state };
}

/** Everything the per-application page needs. */
async function evaluateApplication(pool, id, options = {}) {
  const app = await getApplication(pool, id);
  if (!app) return null;
  const fleet = await loadFleet(pool, options);
  const flows = app.flows.map((f) => evaluateFlow(f, fleet));
  return {
    application: app,
    flows,
    summary: summariseFlows(flows),
    coverage: {
      windowDays: fleet.windowDays,
      activeDeviceCount: fleet.activeDeviceCount,
      devicesWithRules: fleet.devicesWithRules,
      devicesWithoutRules: fleet.devicesWithoutRules,
    },
  };
}

// ── Orphan-rule COVERAGE (not a finding) ───────────────────────────────────

/**
 * How much of the fleet's allow rulebase is claimed by a declared application.
 *
 * ⛔ THIS IS A COVERAGE FIGURE, NOT A FINDING, AND THE DISTINCTION IS THE WHOLE
 * REASON IT IS SHAPED THIS WAY. With nothing declared, a fleet of 1,757 rules
 * reports every one of its ~1,095 allow rules as unclaimed — which is accurate
 * and completely useless, and as a "finding" it would be an alarming number
 * that means nothing on the feature's first screenshot.
 *
 * ⛔ AND "UNCLAIMED" IS NEVER "UNUSED". `unused` is ruleAnalysis.js's word and
 * it requires a MEASURED zero. A rule no one has declared an application for is
 * a gap in the DECLARATION, not evidence about the rule. Conflating them would
 * manufacture deletion candidates out of an incomplete map — this codebase's
 * signature bug wearing a new hat.
 */
function orphanCoverage(fleet, allEvaluatedFlows) {
  const claimed = new Set();
  for (const e of allEvaluatedFlows) {
    for (const p of e.permittedBy || []) {
      for (const r of p.rules || []) claimed.add(r.deviceRuleId);
    }
  }

  let allowRules = 0;
  const unclaimedByDevice = new Map();
  for (const device of fleet.devices) {
    for (const r of device.rules) {
      if (r.enabled === false) continue;
      if (!isAllowAction(r.action)) continue;
      allowRules += 1;
      if (!claimed.has(r.id)) {
        if (!unclaimedByDevice.has(device.id)) {
          unclaimedByDevice.set(device.id, { deviceId: device.id, deviceName: device.name, count: 0 });
        }
        unclaimedByDevice.get(device.id).count += 1;
      }
    }
  }

  const unclaimed = allowRules - claimed.size;
  return {
    allowRules,
    claimedRules: claimed.size,
    unclaimedRules: unclaimed < 0 ? 0 : unclaimed,
    claimedPct: allowRules > 0 ? Math.round((claimed.size / allowRules) * 1000) / 10 : null,
    byDevice: Array.from(unclaimedByDevice.values()).sort((a, b) => b.count - a.count),
    // ⛔ Stated so no caller can render the figure as a to-do list.
    isCoverageNotFinding: true,
  };
}

// ── The page's one call ────────────────────────────────────────────────────

/**
 * Every application evaluated, plus fleet coverage.
 *
 * ⛔ PER-SOURCE ISOLATION, as workQueueData.js does it: a throw is reported as
 * `{ok:false, error}` and banner'd, never allowed to contribute zero items
 * silently. A page that looks cleanest when it is least trustworthy is the
 * failure mode this product exists to remove.
 */
async function evaluateAllApplications(pool, options = {}) {
  const errors = [];
  let apps = [];
  try {
    apps = await listApplications(pool);
  } catch (err) {
    errors.push({ source: 'applications', error: err.message });
    return {
      applications: [], summary: null, coverage: null, orphans: null, errors, windowDays: null,
    };
  }

  let fleet = null;
  try {
    fleet = await loadFleet(pool, options);
  } catch (err) {
    errors.push({ source: 'fleet_rules', error: err.message });
    // ⛔ The declarations are still listed — the operator's own data is not
    // hidden because the evaluation half failed — but nothing is scored.
    return {
      applications: apps.map((a) => ({ application: a, summary: null, unevaluated: true })),
      summary: null, coverage: null, orphans: null, errors, windowDays: null,
    };
  }

  let flowRows = [];
  try {
    const { rows } = await pool.query(
      `SELECT id, application_id, src, dst, protocol, port_start, port_end,
              expectation, note
         FROM application_flows`
    );
    flowRows = rows;
  } catch (err) {
    errors.push({ source: 'application_flows', error: err.message });
  }

  const byApp = new Map();
  for (const f of flowRows) {
    if (!byApp.has(f.application_id)) byApp.set(f.application_id, []);
    byApp.get(f.application_id).push(f);
  }

  const allEvaluated = [];
  const applications = apps.map((a) => {
    const flows = (byApp.get(a.id) || []).map((f) => evaluateFlow(f, fleet));
    for (const e of flows) allEvaluated.push(e);
    return { application: a, flows, summary: summariseFlows(flows) };
  });

  return {
    applications,
    orphans: orphanCoverage(fleet, allEvaluated),
    coverage: {
      windowDays: fleet.windowDays,
      activeDeviceCount: fleet.activeDeviceCount,
      devicesWithRules: fleet.devicesWithRules,
      devicesWithoutRules: fleet.devicesWithoutRules,
    },
    windowDays: fleet.windowDays,
    errors,
  };
}

module.exports = {
  DEFAULT_WINDOW_DAYS,
  MIN_WINDOW_DAYS,
  MAX_WINDOW_DAYS,
  resolveWindowDays,
  VERDICTS,
  USED,
  listApplications,
  getApplication,
  createApplication,
  updateApplication,
  deleteApplication,
  addFlow,
  updateFlow,
  deleteFlow,
  loadFleet,
  evaluateFlow,
  summariseFlows,
  evaluateApplication,
  orphanCoverage,
  evaluateAllApplications,
};
