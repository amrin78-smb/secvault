// The work queue's item-type labels — ONE map, shared.
//
// ⛔ THIS WAS TWO MAPS AND THEY HAD ALREADY DRIFTED. `WorkQueueBoard.js` and
// `WorkQueueFilters.js` each carried their own copy and each fell through to
// the RAW TYPE on a miss, so a missing entry rendered a snake_case identifier
// on screen instead of failing visibly. Measured 2026-11-16 against the
// sixteen types `workQueueData.js` actually emits: the board was missing three
// (`ingest_silent`, `tunnel_stale`, `tunnel_unknown`) and the filter dropdown
// was missing NINE while offering four options — `application`, `ingest`,
// `device`, `conformance` — that no source has ever produced. An option that
// can only ever return nothing is indistinguishable from a filter that is
// broken, which is the rule `WorkQueueFilters`' own header already states.
//
// ⛔ THE GUARD IS THE FIX, NOT THE SIXTEEN ENTRIES.
// `tests/workQueueTypeLabels.test.js` derives the emitted types from
// `lib/engines/workQueueData.js` and fails the build on a type with no label
// and on a label for a type nothing emits. Six edits would have been correct
// today and wrong again at the next source — this is how the drift ends.
//
// ⛔ A TYPE IS NOT A SOURCE. `source('tunnel', …)` emits `tunnel`,
// `tunnel_stale` AND `tunnel_unknown`; `source('ingest', …)` emits
// `ingest_drop` and `ingest_silent`. The twelve source keys are pinned
// separately in `tests/workQueue.test.js` — this file is about the other axis.

export const WORK_TYPE_LABEL = {
  cve: 'Vulnerability',
  compliance: 'Compliance',
  config_diff: 'Config change',
  licence: 'Licence',
  // ⛔ Same label, deliberately: to an operator both rows are about a licence.
  // They are separate TYPES because one is a date we read and one is a date we
  // could not, which is what puts them in different bands.
  licence_unknown: 'Licence',
  rule_cleanup: 'Rule hygiene',
  tunnel: 'VPN tunnel',
  tunnel_stale: 'VPN tunnel',
  tunnel_unknown: 'VPN tunnel',
  collection_gap: 'Collection',
  segmentation: 'Segmentation',
  ingest_drop: 'Log ingest',
  ingest_silent: 'Log ingest',
  application_flow: 'Application',
  coverage_gap: 'Coverage',
  os_lifecycle: 'OS lifecycle',
};

/**
 * The label, or the raw type when there is none.
 *
 * ⛔ IT STILL FALLS BACK, AND THAT IS NOT THE DEFECT. A renderer that threw on
 * an unlabelled type would take the whole queue down over a cosmetic gap — on
 * the page whose job is to say what is outstanding. The fallback keeps the
 * item visible; the BUILD is what refuses to let an unlabelled type ship.
 */
export function workTypeLabel(type) {
  return WORK_TYPE_LABEL[type] || type;
}
