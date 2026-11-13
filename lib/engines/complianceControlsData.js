// lib/engines/complianceControlsData.js
//
// The plumbing behind /compliance/controls. `complianceControls.js` holds the
// judgement and is pure; this file holds the four reads and nothing else, the
// same split `segmentation`/`segmentationData` and `applicationView`/
// `applicationViewData` already use.
//
// ⛔ A FAILED READ THROWS; IT NEVER RETURNS AN EMPTY LIBRARY. Both of the
// first two reads are load-bearing, and `[]` from either one renders as "no
// control is failing" in green — a clean bill of health computed from a
// database error. That is this codebase's signature bug, and the work queue's
// own gather states the rule: silence for one cycle is recoverable, a false
// all-clear is not. The EXCEPTIONS read is the one exception to that (below),
// because it is an annotation rather than the measurement.
//
// ⛔ NO `active = true` FILTER ON THE LIBRARY, AND A HARD ONE ON THE DEVICES.
// Every count on this page is "firewalls in the fleet", so a deactivated
// firewall must contribute neither a finding nor a denominator — otherwise a
// control reads as failing on a firewall nobody manages any more, and the
// applicable count it is measured against includes machines that will never
// be collected from again.

'use strict';

const {
  exceptionState,
  ACCEPTED,
  EXPIRING,
  // ⛔ REUSED WHOLE, NOT RE-QUERIED. `listFleetExceptions` is the ONE query
  // that knows the LEFT-ness of the two joins an exception needs (a withdrawn
  // check and a never-audited device must both still show an operator's
  // recorded decision). A second copy here filtered by slug would drift from
  // it, and the first thing to diverge would be exactly that LEFT-ness.
  listFleetExceptions,
  describeExceptions,
} = require('./complianceExceptions');
const { buildControl, buildControls, sortControls, summariseControls } = require('./complianceControls');

/**
 * Every check in the curated library, with the fields the table renders.
 *
 * `predicate_config->>'predicate_type'` is pulled out here rather than in JS
 * so the engine never has to know the shape of a predicate — it only needs to
 * recognise the one value that declares a check unanswerable.
 */
const LIBRARY_SQL = `
  SELECT check_id   AS slug,
         name,
         description,
         severity,
         standards,
         vendor,
         predicate_config->>'predicate_type' AS predicate_type
  FROM audit_checks
`;

// ⛔ ONE ROW PER (FIREWALL, CHECK), NOT A PRE-AGGREGATED COUNT. The engine
// needs the device NAMES to answer "which firewalls", and collapsing in SQL
// would also hide the duplicate-pair case its `collapseByDevice` handles.
// Bounded by library x fleet — 74 x 16 today, and still trivial at 100
// firewalls.
const FINDINGS_SQL = `
  SELECT ac.check_id AS slug,
         af.status,
         af.device_id,
         d.name      AS device_name,
         af.detected_at
  FROM audit_findings af
  JOIN audit_checks ac ON ac.id = af.check_id
  JOIN devices d       ON d.id = af.device_id
  WHERE d.active = true
`;

const VENDOR_SCOPE_SQL = `
  SELECT vendor, count(*)::int AS devices
  FROM devices
  WHERE active = true
  GROUP BY vendor
`;

// ⛔ EVERY ROW, CLASSIFIED IN JS BY `exceptionState`. The obvious
// `WHERE revoked_at IS NULL AND expires_at > now()` would be a SECOND
// definition of "is this exception live", in SQL, drifting from the one in
// complianceExceptions.js that the device panel and the summary already use —
// and the two would disagree first at exactly the 30-day boundary that
// decides whether a lapse is visible. One definition, not a second opinion.
const EXCEPTIONS_SQL = `
  SELECT ce.check_slug, ce.device_id, ce.expires_at, ce.revoked_at
  FROM compliance_exceptions ce
  JOIN devices d ON d.id = ce.device_id
  WHERE d.active = true
`;

function groupBySlug(rows, map) {
  const out = new Map();
  for (const r of rows) {
    const slug = r && typeof r.slug === 'string' ? r.slug : null;
    if (!slug) continue;
    if (!out.has(slug)) out.set(slug, []);
    out.get(slug).push(map(r));
  }
  return out;
}

/**
 * Build the fleet-wide control view.
 *
 * @param {import('pg').Pool} pool
 * @param {{now?: Date}} [opts]
 * @returns {Promise<{controls: object[], summary: object, scope: object, errors: string[]}>}
 */
async function gatherControls(pool, opts = {}) {
  const now = opts.now instanceof Date ? opts.now : new Date();
  const errors = [];

  // ⛔ Sequential rather than Promise.all: these run on an interactive page
  // load against a database that is also taking ~1,000 syslog inserts a
  // second, and four concurrent sequential scans buy nothing a reader notices.
  const library = await pool.query(LIBRARY_SQL);
  const findings = await pool.query(FINDINGS_SQL);
  const vendorScope = await pool.query(VENDOR_SCOPE_SQL);

  // ⛔ THE ONE READ THAT IS ALLOWED TO FAIL SOFT, and it degrades to `null`
  // rather than to `0`. An exception is an annotation on a failure, not the
  // failure itself, so losing it must not blank the page — but "no exception
  // covers this" and "we could not tell" send an operator to different places,
  // and only the first may ever be printed.
  let exceptionsBySlug = null;
  try {
    const { rows } = await pool.query(EXCEPTIONS_SQL);
    const live = rows.filter((r) => {
      const state = exceptionState(r, now);
      return state === ACCEPTED || state === EXPIRING;
    });
    exceptionsBySlug = new Map();
    for (const r of live) {
      const slug = typeof r.check_slug === 'string' ? r.check_slug : null;
      if (!slug) continue;
      if (!exceptionsBySlug.has(slug)) exceptionsBySlug.set(slug, []);
      exceptionsBySlug.get(slug).push({ deviceId: r.device_id });
    }
  } catch (err) {
    errors.push(`recorded exceptions could not be read (${err.message}) — the exception column reports as unknown rather than as none`);
  }

  const findingsBySlug = groupBySlug(findings.rows, (r) => ({
    deviceId: r.device_id,
    deviceName: r.device_name,
    status: r.status,
    detectedAt: r.detected_at instanceof Date ? r.detected_at.toISOString() : r.detected_at,
  }));

  const vendorCounts = {};
  let activeDevices = 0;
  for (const r of vendorScope.rows) {
    const n = Number(r.devices);
    if (!Number.isFinite(n)) continue;
    activeDevices += n;
    // A device row with a NULL vendor is counted in the fleet total but can
    // never satisfy a vendor-scoped check, which is correct: nothing knows
    // what it is.
    if (typeof r.vendor === 'string' && r.vendor.length > 0) vendorCounts[r.vendor] = n;
  }

  const controls = sortControls(buildControls(library.rows.map((r) => ({
    slug: r.slug,
    name: r.name,
    description: r.description,
    severity: r.severity,
    standards: r.standards,
    vendor: r.vendor,
    predicateType: r.predicate_type,
    findings: findingsBySlug.get(r.slug) || [],
    // ⛔ A vendor-scoped check whose vendor is absent from the fleet gets 0,
    // which is a real answer (`not_applicable`). A check with NO vendor
    // applies to the whole fleet. Neither is ever null here — the reads above
    // threw if they could not answer.
    applicableDeviceCount: r.vendor ? (vendorCounts[r.vendor] || 0) : activeDevices,
    liveExceptions: exceptionsBySlug === null ? null : (exceptionsBySlug.get(r.slug) || []),
  }))));

  return {
    controls,
    summary: summariseControls(controls),
    scope: { activeDevices, vendorCounts },
    errors,
  };
}



// ── ONE control, across the whole fleet ─────────────────────────────────────
//
// /compliance/controls answers "which control is failing on the most
// firewalls?" and stops there: it can name the FAILING firewalls and nothing
// else. `audit_checks.remediation_guidance` — the only plain-English statement
// of how to fix a control — was reachable only by opening a device, then a
// finding, and then only for the one firewall you happened to pick. So "what
// is this control, how do I fix it, and which firewalls fail it" could not be
// read in one place for a control, which is the shape an auditor's question
// actually has.

// ⛔ `remediation_guidance` IS THE REASON THIS QUERY IS NOT `LIBRARY_SQL`.
// Everything else here is the same column list; the fleet table deliberately
// does not select the guidance (74 rows x up to 342 chars it never renders),
// and the detail page cannot do its job without it.
const CONTROL_SQL = `
  SELECT check_id   AS slug,
         name,
         description,
         severity,
         standards,
         vendor,
         remediation_guidance,
         predicate_config->>'predicate_type' AS predicate_type
  FROM audit_checks
  WHERE check_id = $1
`;

// ⛔ NO VENDOR FILTER, DELIBERATELY, AND IT MIRRORS `FINDINGS_SQL` EXACTLY.
// The roll-up on this page must be byte-identical to the one in the table, and
// the table counts every finding on an ACTIVE firewall whatever that
// firewall's vendor is. Filtering here to the check's vendor scope would make
// the detail page quietly disagree with the row that linked to it — the two
// surfaces would report different failure counts for the same control, and a
// reader has no way to tell which one lied.
//
// `af.detail` is the addition: the sentence the audit run wrote about THIS
// firewall, which is the whole reason a per-firewall row is worth rendering
// rather than a count.
const CONTROL_FINDINGS_SQL = `
  SELECT af.status,
         af.detail,
         af.device_id,
         d.name      AS device_name,
         d.vendor    AS device_vendor,
         af.detected_at
  FROM audit_findings af
  JOIN audit_checks ac ON ac.id = af.check_id
  JOIN devices d       ON d.id = af.device_id
  WHERE d.active = true
    AND ac.check_id = $1
`;

// ⛔ THE DEVICE LIST, NOT A COUNT. `VENDOR_SCOPE_SQL` gives the table the
// denominator it needs; this page has to NAME the firewalls that never
// answered, which is the entire point of it. The same `active = true` filter
// and therefore the same population — a deactivated firewall contributes
// neither a row nor a denominator on either surface.
const CONTROL_DEVICES_SQL = `
  SELECT id, name, vendor
  FROM devices
  WHERE active = true
  ORDER BY name ASC
`;

// ⛔ THIS LIST DECIDES NOTHING ABOUT A STATUS. `audit_findings.status` has no
// CHECK constraint (lib/schema.sql documents the domain in a comment and the
// column accepts anything), and the ENGINE is what classifies an unrecognised
// value as `unreadable` — see `collapseByDevice`. This copy of the domain is
// used for ONE thing: locating which of several duplicate rows carries the
// detail TEXT for the answer the engine already picked. If it ever drifts from
// the engine the worst outcome is a detail sentence from the wrong duplicate
// row, never a wrong status.
const KNOWN_FINDING_STATUSES = ['pass', 'fail', 'warning', 'na'];

/**
 * The collapsed answer ONE firewall gave, read back out of the ENGINE's own
 * collapse rather than re-ranked here.
 *
 * ⛔ `audit_findings` carries no `UNIQUE(device_id, check_id)` and is
 * DELETE+reinserted on every run, so two rows for one pair is reachable — and
 * `buildControl` already owns the rule for that case (worst status wins, so a
 * failure cannot hide behind a stale pass). Re-expressing that ranking here
 * would be a second opinion on the one question this page must agree with the
 * table about. Feeding the engine one device's rows and reading which count it
 * incremented asks the same code the same question.
 *
 * Exactly one count can be non-zero by construction: `collapseByDevice` keys
 * on `deviceId`, so one device yields at most one collapsed answer.
 *
 * @returns {string|null} 'fail'|'warning'|'pass'|'na'|'unreadable', or null
 *          when this firewall has NO finding row at all — NEVER 'pass'.
 */
function collapsedAnswer(deviceFindings, predicateType) {
  const one = buildControl({
    findings: deviceFindings,
    applicableDeviceCount: 1,
    predicateType,
  });
  for (const key of Object.keys(one.counts)) {
    if (one.counts[key] > 0) return key;
  }
  return null;
}

/**
 * Which of a device's duplicate rows carries the detail text for the answer
 * the engine chose. Never decides the answer — see KNOWN_FINDING_STATUSES.
 */
function rowForAnswer(rows, answer) {
  if (!Array.isArray(rows) || rows.length === 0) return null;
  if (answer === 'unreadable') {
    return rows.find((r) => !KNOWN_FINDING_STATUSES.includes(r.status)) || rows[0];
  }
  return rows.find((r) => r.status === answer) || rows[0];
}

const iso = (v) => (v instanceof Date ? v.toISOString() : (v || null));

/**
 * One control, every firewall's answer to it, and the exceptions over it.
 *
 * @param {import('pg').Pool} pool
 * @param {string} slug  audit_checks.check_id — the TEXT slug, never a UUID.
 * @param {{now?: Date}} [opts]
 * @returns {Promise<object>} `{found:false, slug}` for a slug that is not in
 *          the library — a RESULT, not an error. A check can leave the seed
 *          library (`compliance_exceptions` declines a FK for exactly that
 *          reason), so a link that was correct last month can land here, and
 *          crashing on it would make a retired control indistinguishable from
 *          a broken page.
 */
async function gatherControlDetail(pool, slug, opts = {}) {
  const now = opts.now instanceof Date ? opts.now : new Date();
  const errors = [];
  const wanted = typeof slug === 'string' ? slug : '';

  // ⛔ NO try/catch ON THE LIBRARY READ. An unreadable `audit_checks` must
  // reach the error boundary; returning `{found:false}` for it would tell the
  // operator this control does not exist, which is a confident wrong answer
  // built from a read that failed.
  const library = await pool.query(CONTROL_SQL, [wanted]);
  const row = library.rows[0];
  if (!row) return { found: false, slug: wanted, errors };

  const findings = await pool.query(CONTROL_FINDINGS_SQL, [wanted]);
  const deviceRows = await pool.query(CONTROL_DEVICES_SQL);

  // ⛔ THE ONE READ ALLOWED TO FAIL SOFT, degrading to `null` and never to an
  // empty list — the same call `gatherControls` makes. "No exception covers
  // this control" and "we could not read the record" send an operator to
  // different places, and only the first may be printed.
  let described = null;
  try {
    const all = await listFleetExceptions(pool);
    described = describeExceptions(
      all.filter((r) => r && r.check_slug === wanted),
      now
    );
  } catch (err) {
    errors.push(
      `recorded exceptions could not be read (${err.message}) — this control reports its acceptances as unknown rather than as none`
    );
  }

  // ⛔ CLASSIFIED BY `exceptionState` (inside `describeException`), NEVER by a
  // `WHERE revoked_at IS NULL AND expires_at > now()`. A second definition of
  // "is this live" in SQL would drift from the device panel's answer, and the
  // two would disagree first at exactly the 30-day `expiring` boundary that
  // decides whether a lapse is visible at all.
  const liveExceptions =
    described === null
      ? null
      : described
        .filter((d) => d.state === ACCEPTED || d.state === EXPIRING)
        .map((d) => ({ deviceId: d.deviceId }));

  const scopedVendor = typeof row.vendor === 'string' && row.vendor.length > 0 ? row.vendor : null;
  // ⛔ A VENDOR-SCOPED CHECK APPLIES TO ITS OWN VENDOR'S FIREWALLS AND NOTHING
  // ELSE. Listing a Palo Alto as "never answered" for a FortiOS-only check
  // would manufacture a coverage gap that cannot exist — SecVault is not
  // failing to ask the question, the question does not apply. A device with a
  // NULL vendor can satisfy no vendor-scoped check: nothing knows what it is.
  const applicable = deviceRows.rows.filter(
    (d) => scopedVendor === null || d.vendor === scopedVendor
  );

  const control = buildControl({
    slug: row.slug,
    name: row.name,
    description: row.description,
    severity: row.severity,
    standards: row.standards,
    vendor: row.vendor,
    predicateType: row.predicate_type,
    findings: findings.rows.map((r) => ({
      deviceId: r.device_id,
      deviceName: r.device_name,
      status: r.status,
      detectedAt: iso(r.detected_at),
    })),
    applicableDeviceCount: applicable.length,
    liveExceptions,
  });

  const byDevice = new Map();
  for (const r of findings.rows) {
    if (!r || !r.device_id) continue;
    if (!byDevice.has(r.device_id)) byDevice.set(r.device_id, []);
    byDevice.get(r.device_id).push(r);
  }

  const rowFor = (device, inScope) => {
    const rows = byDevice.get(device.id) || [];
    const answer = collapsedAnswer(
      rows.map((r) => ({
        deviceId: r.device_id,
        deviceName: r.device_name,
        status: r.status,
        detectedAt: iso(r.detected_at),
      })),
      row.predicate_type
    );
    const chosen = rowForAnswer(rows, answer);
    return {
      deviceId: device.id,
      deviceName: device.name || null,
      vendor: device.vendor || null,
      // ⛔ null IS "NEVER ANSWERED" AND IS THE WHOLE POINT OF THIS PAGE. It is
      // not a pass, not an `na`, and not an empty cell: nobody put the
      // question to this firewall. It clears itself the next time a config is
      // collected and the audit runs, which is why it must be visible.
      status: answer,
      rawStatus: chosen ? (chosen.status || null) : null,
      detail: chosen && chosen.detail ? chosen.detail : null,
      detectedAt: chosen ? iso(chosen.detected_at) : null,
      // ⛔ MORE THAN ONE ANSWER IS SURFACED, NOT SWALLOWED. The engine picked
      // the worst; the operator is told there was more than one rather than
      // being shown a single row that quietly discarded the others.
      answerCount: rows.length,
      inScope,
    };
  };

  const devices = applicable.map((d) => rowFor(d, true));

  // ⛔ A FINDING ON A FIREWALL THE CHECK DOES NOT APPLY TO IS STILL SHOWN.
  // The roll-up above counts it (the table's query has no vendor filter
  // either), so omitting the row would leave the page saying "1 failing" with
  // no failing firewall anywhere in the list — a discrepancy with no visible
  // cause. It is a curated-data or engine fault rather than a fleet problem,
  // so it is flagged `inScope: false` and named as one.
  const deviceNames = {};
  for (const d of deviceRows.rows) deviceNames[d.id] = d.name || null;

  const scopedIds = new Set(applicable.map((d) => d.id));
  for (const [deviceId, rows] of byDevice) {
    if (scopedIds.has(deviceId)) continue;
    const first = rows[0] || {};
    devices.push(rowFor(
      { id: deviceId, name: first.device_name, vendor: first.device_vendor },
      false
    ));
  }

  return {
    found: true,
    slug: row.slug,
    control,
    remediationGuidance:
      typeof row.remediation_guidance === 'string' && row.remediation_guidance.length > 0
        ? row.remediation_guidance
        : null,
    devices,
    // ⛔ COUNTED SEPARATELY AND NAMED. `control.notEvaluatedDeviceCount` is the
    // same figure from the engine; this one is derived from the rows actually
    // rendered, so a page that silently dropped a never-answered firewall
    // would disagree with its own roll-up and a test can see it.
    neverAnsweredCount: devices.filter((d) => d.inScope && d.status === null).length,
    applicableDeviceCount: applicable.length,
    outOfScopeAnswers: devices.filter((d) => !d.inScope).length,
    exceptions: described,
    // ⛔ EVERY ACTIVE FIREWALL, NOT ONLY THE APPLICABLE ONES. An exception can
    // sit on a firewall this check does not apply to and that has no finding
    // row — an operator's recorded decision outliving a vendor change or a
    // check's scope being narrowed. Naming it from a map built off the
    // applicable list alone would render that acceptance against a bare UUID.
    deviceNames,
    errors,
  };
}

module.exports = {
  gatherControls,
  gatherControlDetail,
  LIBRARY_SQL,
  FINDINGS_SQL,
  VENDOR_SCOPE_SQL,
  EXCEPTIONS_SQL,
  CONTROL_SQL,
  CONTROL_FINDINGS_SQL,
  CONTROL_DEVICES_SQL,
};
