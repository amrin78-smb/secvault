// lib/configChangeSummary.js
//
// Turns a stored config diff into something a non-technical reader can act on.
//
// ── THE PROBLEM THIS SOLVES ───────────────────────────────────────────────
// `config_diffs.change_summary` is a machine string, and it was rendered
// VERBATIM in the column literally headed "Description" on /alerts, plus the
// dashboard's config-changes widget and every device Overview card. Real rows
// from the live fleet:
//
//   3 added — e.g. shared.local-user-database.user.entry[375].disabled, …
//   2 modified — e.g. devices.entry.vsys.entry.rulebase.security.rules.entry[17].service.member, …
//
// Those cells are `white-space: nowrap` + ellipsis at ~36% width, so what the
// reader actually saw was `3 added — e.g. shared.local-user-datab…`. The
// USEFUL half ("3 added") survived and the meaningless half filled the space.
//
// ⛔ The fix is a RENDER change, not a data change. `change_summary` stays
// exactly as stored — it is the evidence, and it stays available in `title`
// and in the full DiffViewer. This only decides what is shown first.
//
// ── WHY IT REUSES classifyDiff() ──────────────────────────────────────────
// lib/engines/configDiff.js already knows how to turn those dot-paths into
// human section labels ("Security Rules", "Admin Accounts", "VPN
// Configuration"). Re-deriving that here would be a second classifier that
// drifts from the first — the exact shape of the four-deny-list problem this
// codebase just finished untangling.

'use strict';

const { classifyDiff } = require('./engines/configDiff');

/**
 * @param {object|null} diff  the stored `config_diffs.diff` JSONB
 * @returns {{added:number, removed:number, modified:number, sections:string[],
 *            total:number, hasDetail:boolean}}
 *
 * ⛔ Never throws. A malformed or absent diff yields zero counts and an EMPTY
 * section list, and `hasDetail:false` tells the caller to fall back to the raw
 * `change_summary` rather than render a confident-looking empty description.
 * Silently showing "0 changes" for a diff we failed to parse would be the
 * failed-read-as-a-fact rule in presentation form.
 */
function summarizeConfigChange(diff) {
  const empty = { added: 0, removed: 0, modified: 0, sections: [], total: 0, hasDetail: false };
  if (!diff || typeof diff !== 'object') return empty;

  const added = Array.isArray(diff.added) ? diff.added.length : 0;
  const removed = Array.isArray(diff.removed) ? diff.removed.length : 0;
  const modified = Array.isArray(diff.modified) ? diff.modified.length : 0;
  const total = added + removed + modified;

  let sections = [];
  try {
    const classified = classifyDiff(diff);
    sections = (classified.sections || [])
      .map((s) => s.label)
      .filter((l) => typeof l === 'string' && l !== '');
  } catch (_err) {
    // classifyDiff is defensive already; this is belt-and-braces. An
    // unclassifiable diff still reports its counts, which are the half the
    // reader could always use.
    sections = [];
  }

  return { added, removed, modified, sections, total, hasDetail: total > 0 };
}

/**
 * One-line human sentence: "Security Rules, Admin Accounts — 3 added, 2 modified".
 *
 * ⛔ Falls back to the raw `change_summary` when the diff carried nothing we
 * could classify. An empty string here would render a blank Description cell,
 * which reads as "nothing changed" rather than "we could not describe it".
 */
function describeConfigChange(diff, changeSummary) {
  const s = summarizeConfigChange(diff);
  if (!s.hasDetail) return changeSummary || null;

  const counts = [];
  if (s.added) counts.push(`${s.added} added`);
  if (s.removed) counts.push(`${s.removed} removed`);
  if (s.modified) counts.push(`${s.modified} modified`);

  // Cap the section list so one sprawling diff cannot push the counts — the
  // part that is always meaningful — off the end of the cell.
  const shown = s.sections.slice(0, 3);
  const more = s.sections.length - shown.length;
  const where = shown.length
    ? shown.join(', ') + (more > 0 ? ` +${more} more` : '')
    : null;

  return where ? `${where} — ${counts.join(', ')}` : counts.join(', ');
}

module.exports = { summarizeConfigChange, describeConfigChange };
