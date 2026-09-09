// components/ui/tableStyles.js
//
// Shared cell styles for tables that carry PROSE rather than identifiers.
//
// ── WHY ───────────────────────────────────────────────────────────────────
// app/globals.css applies `white-space: nowrap; overflow: hidden;
// text-overflow: ellipsis` to every `td`, which is right for identifiers and
// wrong for sentences. Measured in the live database:
//
//   rule_analysis_results.detail        avg 128 chars, max 296
//   rule_analysis_results.remediation   max 195
//   audit_findings.detail               max 355
//   audit_checks.remediation_guidance   max 342
//
// Those columns hold the only plain-English content in four tables — everything
// else is a badge or an ID — and each was clipped to a single line, readable
// only on hover, and not at all on a touch device. The effect was to reduce a
// findings table to "here are 216 problems, no descriptions".
//
// WRAP_CELL already existed, correct, in app/(dashboard)/devices/[id]/page.js
// and was used by exactly one table. This lifts it so the other four can share
// it rather than each re-deriving it (or not).
//
// ⛔ Safe under the mandatory `tableLayout: 'fixed'` + <colgroup>: the row
// grows TALLER within its allocated column width, it does not widen the column
// or disturb the layout.

'use strict';

const WRAP_CELL = {
  whiteSpace: 'normal',
  overflow: 'visible',
  textOverflow: 'clip',
  maxWidth: 'none',
  wordBreak: 'break-word',
  verticalAlign: 'top',
};

module.exports = { WRAP_CELL };
