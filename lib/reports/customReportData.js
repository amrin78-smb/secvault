'use strict';

// lib/reports/customReportData.js — custom reports, THE PLUMBING.
//
// Every function takes `pool` as its FIRST argument, per CLAUDE.md's pool rule.
// The judgement lives next door in the pure lib/reports/customReport.js; this
// file reads and writes `custom_reports` rows and runs the DATASET GATHERS that
// the selected sections need. Same split as
// reportSchedule.js/reportScheduleData.js.
//
// ⛔ NO SECOND REPORT ENGINE, AND NOTHING IS RECOMPUTED. Each dataset below is
// the SHIPPED report's own data builder, called with the same signature the
// download route calls it with. A copy of any of them would drift from the
// document it was copied from, and the drifting copy would be the one an
// auditor is holding.
//
// ⛔ ONE GATHER PER DATASET, NOT ONE PER SECTION. Four of the nine registered
// sections come from the Executive Security Posture report, and running its
// gather four times for one PDF would cost four passes over the work queue —
// which is by far the most expensive source in this product. The registry's
// `dataset` key is what makes the de-duplication structural rather than
// remembered.
//
// ⛔ A DATASET FAILURE IS ISOLATED AND NAMED, never swallowed. It comes back as
// {ok:false, error} and the renderer prints the section with a refusal inside
// it and lists it on the cover and in the closing gaps. A section that quietly
// disappeared would read as a section with nothing in it, i.e. "we could not
// look" presented as "there was nothing to find".

const {
  validateDefinition,
  resolveSelection,
  datasetsFor,
  renderCustomReportPdf,
  CUSTOM_REPORT_CAPABILITY,
} = require('./customReport');
const { PRODUCT_NAME } = require('../branding');

// ── the datasets ───────────────────────────────────────────────────────────
//
// ⛔ EVERY BUILDER IS REQUIRED LAZILY, inside its own gather. Each one pulls
// pdfkit and most of lib/engines in behind it, and this module is imported by
// the CRUD routes, which never draw a document. The same reason
// lib/reports/catalogue.js resolves its builders with `() => require(...)`.
const DATASETS = Object.freeze({
  executive: {
    label: 'Executive Security Posture data',
    gather: (pool, opts) => require('./executiveSummary').gatherExecutiveSummary(pool, opts),
  },
  ruleHygiene: {
    label: 'Rule hygiene analysis',
    gather: (pool, opts) => require('./ruleHygiene').buildRuleHygieneData(pool, opts),
  },
  vulnerability: {
    label: 'Vulnerability assessments',
    gather: (pool, opts) => require('./vulnerabilityPosture').buildVulnerabilityReportData(pool, opts),
  },
  segmentation: {
    label: 'Segmentation evaluation',
    gather: (pool, opts) => require('./segmentationPosture').buildSegmentationPostureData(pool, opts),
  },
  lifecycle: {
    label: 'Lifecycle and support data',
    gather: (pool, opts) => require('./fleetLifecycle').buildFleetLifecycleData(pool, opts),
  },
  changeAudit: {
    label: 'Configuration change history',
    gather: (pool, opts) => require('./changeAudit').buildChangeAuditData(pool, opts),
  },
});

// ── CRUD ───────────────────────────────────────────────────────────────────

const SELECT_COLUMNS =
  'id, name, subtitle, sections, created_by, created_at, updated_at';

/**
 * Every saved definition, oldest first so the list does not reorder itself
 * under an operator who is editing one.
 *
 * THROWS on a read failure. ⛔ Never `[]` — an empty list is a claim that
 * nothing has been defined, and a panel rendering it over a failed read would
 * invite somebody to create a duplicate of a report that already exists.
 */
async function listCustomReports(pool) {
  if (!pool) throw new Error('listCustomReports requires pool parameter');
  const { rows } = await pool.query(
    `SELECT ${SELECT_COLUMNS} FROM custom_reports ORDER BY created_at ASC`
  );
  return rows.map(decorate);
}

/** One definition, or null. ⛔ Never a partially-populated stub. */
async function getCustomReport(pool, id) {
  if (!pool) throw new Error('getCustomReport requires pool parameter');
  const { rows } = await pool.query(
    `SELECT ${SELECT_COLUMNS} FROM custom_reports WHERE id = $1::uuid`,
    [id]
  );
  return rows[0] ? decorate(rows[0]) : null;
}

/**
 * The row plus what the registry says about its sections TODAY.
 *
 * ⛔ THE WITHDRAWN IDS TRAVEL WITH THE ROW. A section id is code, so a saved
 * report can outlive a section, and every surface that lists these rows has to
 * be able to say so — the panel, the API response and the PDF cover all read
 * this one derivation rather than each re-deriving it.
 */
function decorate(row) {
  const selection = resolveSelection(row.sections);
  return {
    ...row,
    sections: Array.isArray(row.sections) ? [...row.sections] : [],
    section_names: selection.filter((s) => s.section).map((s) => s.section.name),
    sources: selection.reduce((acc, s) => {
      if (s.section && !acc.includes(s.section.source)) acc.push(s.section.source);
      return acc;
    }, []),
    withdrawn_sections: selection.filter((s) => !s.section).map((s) => s.id),
  };
}

/** PostgreSQL's unique-violation SQLSTATE. */
const UNIQUE_VIOLATION = '23505';

/**
 * Create a definition.
 *
 * ⛔ IT VALIDATES AGAIN, even though the route already did — two independent
 * gates, the same shape createSchedule uses, because this function is callable
 * from anywhere and a mislabelled audit document is the one output this product
 * must never produce.
 *
 * @returns {{ok: boolean, errors: string[], report: object|null}} — never
 *   throws for a bad input, so the route maps it straight to a 400. A genuine
 *   database failure still throws, because that is a 500.
 */
async function createCustomReport(pool, input, createdBy) {
  if (!pool) throw new Error('createCustomReport requires pool parameter');
  const checked = validateDefinition(input);
  if (!checked.ok) return { ok: false, errors: checked.errors, report: null };
  const v = checked.value;
  try {
    const { rows } = await pool.query(
      `INSERT INTO custom_reports (name, subtitle, sections, created_by)
       VALUES ($1, $2, $3::text[], $4)
       RETURNING id`,
      [
        v.name, v.subtitle, v.sections,
        typeof createdBy === 'string' && createdBy.trim() !== '' ? createdBy.trim() : null,
      ]
    );
    return { ok: true, errors: [], report: await getCustomReport(pool, rows[0].id) };
  } catch (err) {
    if (err && err.code === UNIQUE_VIOLATION) {
      // ⛔ NAMED, not a raw constraint violation. One name means one document:
      // two definitions called "Board Pack" and "board pack" would produce two
      // different PDFs under one spoken name.
      return {
        ok: false,
        errors: [`A custom report called "${v.name}" already exists. One name, one document — `
          + 'edit that one or choose a different name.'],
        report: null,
      };
    }
    throw err;
  }
}

/**
 * Patch a definition. Absent keys are left alone; the result is re-validated as
 * a WHOLE row.
 *
 * ⛔ THE WHOLE ROW, because the fields are not independent of the registry: a
 * patch that replaces `sections` has to be checked against the sections that
 * exist now, and a patch that touches only the name must not be allowed to
 * resurrect a selection that has since been withdrawn... which is exactly why
 * the merge below keeps the stored sections and validateDefinition then
 * REFUSES them if any has gone. That refusal is correct: editing the title of a
 * report whose section no longer exists should make the operator fix the
 * selection, and the error names which id to replace. Deleting is always
 * available as the way out.
 */
async function updateCustomReport(pool, id, patch) {
  if (!pool) throw new Error('updateCustomReport requires pool parameter');
  const existing = await getCustomReport(pool, id);
  if (!existing) return { ok: false, errors: ['That custom report no longer exists.'], report: null };

  const p = patch && typeof patch === 'object' ? patch : {};
  const merged = {
    name: p.name !== undefined ? p.name : existing.name,
    subtitle: p.subtitle !== undefined ? p.subtitle : existing.subtitle,
    sections: p.sections !== undefined ? p.sections : existing.sections,
  };
  const checked = validateDefinition(merged);
  if (!checked.ok) return { ok: false, errors: checked.errors, report: null };
  const v = checked.value;

  try {
    await pool.query(
      `UPDATE custom_reports
          SET name = $1, subtitle = $2, sections = $3::text[], updated_at = now()
        WHERE id = $4::uuid`,
      [v.name, v.subtitle, v.sections, id]
    );
  } catch (err) {
    if (err && err.code === UNIQUE_VIOLATION) {
      return {
        ok: false,
        errors: [`A custom report called "${v.name}" already exists.`],
        report: null,
      };
    }
    throw err;
  }
  return { ok: true, errors: [], report: await getCustomReport(pool, id) };
}

/**
 * Delete a definition.
 *
 * ⛔ DELETING ONE WIDENS NOTHING AND CHANGES NO OTHER ROW'S MEANING — this is
 * not the user_device_scopes trap, where an emptied table flips from
 * "restricted" to "the whole fleet". Zero custom_reports rows means "none are
 * defined" both before and after, so no guard is needed here. Nothing
 * references the table either: it cannot be scheduled (see the catalogue
 * entry's scope), so no delivery can be left pointing at a row that is gone.
 *
 * @returns {boolean} whether a row was actually removed.
 */
async function deleteCustomReport(pool, id) {
  if (!pool) throw new Error('deleteCustomReport requires pool parameter');
  const res = await pool.query('DELETE FROM custom_reports WHERE id = $1::uuid', [id]);
  return (res.rowCount || 0) > 0;
}

// ── gathering ──────────────────────────────────────────────────────────────

/**
 * Run every dataset a selection needs, each isolated.
 *
 * @returns {Promise<Record<string, {ok: boolean, value: any, error: string|null}>>}
 */
async function gatherDatasets(pool, sectionIds, opts = {}) {
  const keys = datasetsFor(sectionIds);
  const results = await Promise.all(keys.map(async (key) => {
    const ds = DATASETS[key];
    if (!ds) {
      // ⛔ A SECTION NAMING A DATASET THAT DOES NOT EXIST IS A NAMED FAILURE.
      // It can only happen through a code edit, and an unnamed one would render
      // as an empty section.
      return [key, { ok: false, value: null, error: `No dataset called "${key}" exists.` }];
    }
    try {
      const value = await ds.gather(pool, opts);
      if (value === null || value === undefined) {
        // Every builder returns null only when a NAMED DEVICE does not exist.
        // A custom report is fleet-scoped, so this should be unreachable — and
        // it is reported rather than rendered as an empty section.
        return [key, { ok: false, value: null, error: `${ds.label} returned nothing.` }];
      }
      return [key, { ok: true, value, error: null }];
    } catch (err) {
      return [key, {
        ok: false,
        value: null,
        error: `${ds.label}: ${(err && err.message) || String(err)}`,
      }];
    }
  }));
  return Object.fromEntries(results);
}

/**
 * Everything renderCustomReportPdf needs.
 *
 * @returns {Promise<object|null>} null when the definition does not exist —
 *   ⛔ never an empty document, which the download route turns into a 404.
 */
async function gatherCustomReport(pool, id, options = {}) {
  if (!pool) throw new Error('gatherCustomReport requires pool parameter');
  const row = await getCustomReport(pool, id);
  if (!row) return null;

  const selection = resolveSelection(row.sections);

  // ⛔ ONE CLOCK FOR THE WHOLE DOCUMENT. Each builder defaults to its own
  // `new Date()`, so without this the six datasets would be computed at six
  // slightly different instants and a cover stamp would speak for none of them.
  // It is also what the evidence-window resolver wants: an explicit `now` is
  // threaded into its own history read rather than being compared against a
  // cached value resolved at a different moment.
  const generatedAt = options.generatedAt instanceof Date ? options.generatedAt : new Date();
  const datasets = await gatherDatasets(pool, row.sections, {
    generatedAt,
    now: generatedAt,
  });

  return {
    report: {
      id: row.id,
      name: row.name,
      subtitle: row.subtitle,
      createdBy: row.created_by,
      createdAt: row.created_at,
    },
    generatedAt,
    company: options.company || PRODUCT_NAME,
    capabilityFloor: CUSTOM_REPORT_CAPABILITY,
    selection,
    datasets,
  };
}

/**
 * The catalogue entry's builder.
 *
 * ⛔ THE SIGNATURE IS THE ENTITY-SCOPED ONE app/api/reports/[id]/pdf/route.js
 * ALREADY CALLS: `build(pool, entityId, opts)`. There is deliberately no second
 * download route — the generic one resolves this report through the registry,
 * enforces the entry's own capability, validates the id as a UUID and refuses
 * an unknown one with a 404, which is every gate a custom report needs. A
 * parallel route would be a second copy of all of that.
 *
 * @returns {Promise<Buffer|null>} null when no such definition exists.
 */
async function generateCustomReportPdf(pool, id, options = {}) {
  const data = await gatherCustomReport(pool, id, options);
  if (!data) return null;
  return renderCustomReportPdf(data);
}

module.exports = {
  DATASETS,
  listCustomReports,
  getCustomReport,
  createCustomReport,
  updateCustomReport,
  deleteCustomReport,
  gatherDatasets,
  gatherCustomReport,
  generateCustomReportPdf,
  decorate,
};
