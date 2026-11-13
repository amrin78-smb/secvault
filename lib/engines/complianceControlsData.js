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

const { exceptionState, ACCEPTED, EXPIRING } = require('./complianceExceptions');
const { buildControls, sortControls, summariseControls } = require('./complianceControls');

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

module.exports = { gatherControls, LIBRARY_SQL, FINDINGS_SQL, VENDOR_SCOPE_SQL, EXCEPTIONS_SQL };
