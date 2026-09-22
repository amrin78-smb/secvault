'use strict';
//
// lib/configDiffDisplay.js — turning one changed config object into table rows.
//
// ⛔ EXTRACTED FROM components/config/DiffViewer.js SO IT CAN BE TESTED.
// It lived inside a client component, which cannot be required from node, so
// the only way to check it was to load the page and look — the same blindness
// that let a blank /reports ship. The component now imports this.

// ⛔ BOUNDED, AND IT GIVES UP RATHER THAN TRUNCATING. Past either limit the
// whole value returns null and the caller falls back to the raw-JSON renderer,
// which shows everything. A table that silently dropped the remaining fields
// would look complete while hiding part of a configuration change — the
// truncation-looks-complete failure this codebase guards everywhere else.
const MAX_FLATTEN_DEPTH = 4;
const MAX_FLATTEN_ROWS = 40;

/**
 * Flatten a nested config object into `{path: string[], value}` rows.
 *
 * ⛔ ONE PAN-OS IDIOM DRIVES THE EMPTY-OBJECT RULE: `"override": {"no": ""}`
 * uses the KEY as the value, so `{}` and `{"no": ""}` are meaningful and are
 * kept as rows. Dropping them would delete a real setting from the display.
 *
 * @returns {{path: string[], value: *}[]|null} null = too deep or too wide
 */
function flattenForDisplay(value, prefix = [], out = [], depth = 0) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  for (const key of Object.keys(value)) {
    if (out.length >= MAX_FLATTEN_ROWS) return null;
    const v = value[key];
    const path = prefix.concat(key);
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      if (depth + 1 >= MAX_FLATTEN_DEPTH) return null;
      if (Object.keys(v).length === 0) { out.push({ path, value: '' }); continue; }
      if (flattenForDisplay(v, path, out, depth + 1) === null) return null;
      continue;
    }
    out.push({ path, value: v });
  }
  return out;
}

// ⛔ THE NAME IS DROPPED ONLY WHEN THE HEADING ALREADY SAYS IT. The row is now
// headed `Tag "BioStar" was added`, so a `Name | BioStar` row beneath repeats
// it and pushes the fields that actually changed down the table. When the
// heading FELL BACK to a raw config path it names nothing, so the row stays —
// dropping it there would remove the only place the name appears.
const NAME_KEYS_IN_HEADING = new Set(['@_name', '@name', 'name']);

/**
 * The rows a flat-object table should render.
 * @param {object} value
 * @param {boolean} nameInHeading  is the object already named above the table?
 * @returns {{path: string[], value: *}[]|null} null = render raw JSON instead
 */
function displayRowsFor(value, nameInHeading) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const flat = flattenForDisplay(value);
  if (flat === null) return null;
  const rows = flat.filter(
    (r) => !(nameInHeading && r.path.length === 1 && NAME_KEYS_IN_HEADING.has(r.path[0]))
  );
  // ⛔ An object whose ONLY field was the name still renders nothing rather
  // than an empty table — the heading has already said everything there is.
  return rows;
}

module.exports = {
  MAX_FLATTEN_DEPTH,
  MAX_FLATTEN_ROWS,
  NAME_KEYS_IN_HEADING,
  flattenForDisplay,
  displayRowsFor,
};
