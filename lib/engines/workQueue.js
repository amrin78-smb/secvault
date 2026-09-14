'use strict';

// THE WORK QUEUE — one ranked list of what to actually do, across every engine
// in the product (Phase 3).
//
// PURE. No pool, no queries. It takes items that workQueueData.js has already
// gathered and decides the order and the banding. The split is what makes the
// judgement testable, and the judgement is the entire value of the feature.
//
// ⛔ ═══ AN ITEM IS A DECISION, NOT A FACT ════════════════════════════════
// The fleet currently holds 1,132 rule-analysis findings, 345 of them
// unused/shadow/redundant across 14 firewalls. A queue that listed those as
// 345 rows would be a database dump wearing a to-do list's clothes — nobody
// works a 345-item list, and its length would grow with the size of the fleet
// rather than with the amount of work outstanding.
//
// So a source AGGREGATES to the grain at which a human makes one decision in
// one sitting: "clean up 31 never-used rules on TSR-EKM" is ONE item that links
// to the tab where that work is done. The count travels WITH the item so the
// aggregation is visible rather than hidden.
//
// ⛔ ═══ THREE BANDS, AND THE THIRD IS THE POINT ═════════════════════════
// CLAUDE.md already records what happens when everything is urgent — the
// rejected `log_hit` definition would have moved ~all 155 assessments to
// patch_now, and the file's own conclusion was that "a queue where everything
// is urgent has no prioritisation left, which is strictly worse than
// `log_hit` staying honestly false". The same trap is available here and is
// much easier to fall into, because every engine believes its own findings
// matter.
//
//   act_now   — MEASURED evidence that something is exposed or broken now.
//   scheduled — real, confirmed, not urgent.
//   verify    — SecVault CANNOT MEASURE THIS. A human has to look.
//
// ⛔ AN UNMEASURED ITEM MAY NEVER ENTER `act_now`. Not because it is unimportant
// — it may well be the most important thing on the list — but because
// `act_now` is a claim about evidence, and we do not have any. The 44 licences
// on this fleet whose expiry string could not be parsed are the live example:
// one of them may already have lapsed. Ranking them urgent would be a guess
// presented as a measurement; dropping them would be the failed-read-as-a-fact
// bug. They go to `verify`, which is a VISIBLE, COUNTED band — never a
// collapsed footer, never sorted to the bottom of `scheduled` where a long
// list buries it.
//
// ⛔ ═══ A SOURCE THAT FAILED IS NOT A SOURCE WITH NOTHING TO SAY ═════════
// This is the oldest bug in this codebase, applied to the queue itself. If the
// compliance query throws, the queue must NOT simply render 5 fewer items and
// look cleaner — it would look BEST exactly when it is least trustworthy.
// `summarise()` therefore reports failed sources, and the answer sentence is
// forbidden from claiming an empty queue while any source is down.

const WORK_BANDS = ['act_now', 'scheduled', 'verify'];

// Severity ordering inside a band. Not a score — just a stable rank.
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Evidence strength. ⛔ `unmeasured` is not the bottom of a scale that runs
// from good to bad; it is a different KIND of statement, which is why it
// changes the BAND rather than just the position.
const EVIDENCE = ['measured', 'reported', 'unmeasured'];

function severityRank(s) {
  const r = SEVERITY_RANK[String(s || '').toLowerCase()];
  return Number.isFinite(r) ? r : SEVERITY_RANK.medium;
}

/**
 * Which band an item belongs in.
 *
 * @param {{urgency:'now'|'soon', evidence:'measured'|'reported'|'unmeasured'}} item
 */
function bandFor(item) {
  const it = item || {};
  const evidence = EVIDENCE.includes(it.evidence) ? it.evidence : 'unmeasured';

  // ⛔ THE LOAD-BEARING LINE. Everything unmeasured goes to verify, whatever
  // the source thought its urgency was. A source cannot promote a guess into
  // `act_now` by declaring itself urgent.
  if (evidence === 'unmeasured') return 'verify';

  return it.urgency === 'now' ? 'act_now' : 'scheduled';
}

/**
 * How broad an item is, in the ONE unit every source can express: how many
 * firewalls it is about.
 *
 * ⛔ THIS IS NOT `count`, AND THE DIFFERENCE WAS A REAL MIS-RANKING. `count` is
 * a display figure whose unit is whatever the item is about — affected devices
 * for a CVE, entitlements for a licence, findings for a cleanup backlog,
 * permitting rules for a segmentation violation, and RAW DROPPED DATAGRAMS for
 * the syslog ingest item. Sorting on it compared those units to each other, so
 * the live incident that dropped 324,875 events sat permanently at the top of
 * its band above every genuine exposure, purely because syslog is counted in
 * bigger numbers than firewalls are.
 *
 * ⛔ THE FALLBACK IS 1, NEVER `count`. Falling back to the display count for an
 * item that did not supply a magnitude would reintroduce exactly the bug this
 * function exists to remove, and it would do it silently — the item would
 * simply start winning again.
 */
function magnitudeOf(item) {
  const it = item || {};
  const m = Number(it.magnitude);
  if (Number.isFinite(m) && m > 0) return m;
  const devices = Array.isArray(it.deviceIds)
    ? new Set(it.deviceIds.filter(Boolean)).size
    : 0;
  return devices > 0 ? devices : 1;
}

/**
 * Rank a gathered item list. Returns a NEW array; does not mutate.
 *
 * Order: band, then severity, then magnitude (an item spanning more firewalls
 * outranks one of the same kind on fewer), then title for stability across
 * renders — ⛔ an unstable sort makes a queue reorder itself between refreshes,
 * which destroys the one thing a queue is for.
 */
function rankItems(items) {
  const list = (Array.isArray(items) ? items : []).filter(Boolean).map((it) => ({
    ...it,
    band: bandFor(it),
  }));

  return list.sort((a, b) => {
    const ba = WORK_BANDS.indexOf(a.band) - WORK_BANDS.indexOf(b.band);
    if (ba !== 0) return ba;
    const sv = severityRank(a.severity) - severityRank(b.severity);
    if (sv !== 0) return sv;
    const mg = magnitudeOf(b) - magnitudeOf(a);
    if (mg !== 0) return mg;
    return String(a.title || '').localeCompare(String(b.title || ''));
  });
}

/**
 * Fleet-level counts, plus an honest account of which sources produced them.
 *
 * @param {Array} items    already ranked (or not — this re-bands defensively)
 * @param {Array<{key:string, ok:boolean, error?:string}>} sources
 */
function summarise(items, sources) {
  const list = Array.isArray(items) ? items : [];
  const counts = { act_now: 0, scheduled: 0, verify: 0 };
  const byType = {};
  let devices = new Set();

  for (const it of list) {
    const band = it.band || bandFor(it);
    if (counts[band] !== undefined) counts[band] += 1;
    byType[it.type] = (byType[it.type] || 0) + 1;
    for (const d of it.deviceIds || []) devices.add(d);
  }

  const src = Array.isArray(sources) ? sources : [];
  const failed = src.filter((s) => s && s.ok === false);
  // ⛔ A cap that bit is a second way the queue is shorter than the truth,
  // and it must travel with the summary for the same reason a failed source
  // does — the operator works the list to the bottom and believes they are
  // finished.
  const truncated = src.filter((s) => s && s.truncatedFrom);

  return {
    total: list.length,
    ...counts,
    byType,
    deviceCount: devices.size,
    sourcesTotal: src.length,
    // ⛔ Reported, never swallowed. An empty queue with a failed source is not
    // an empty queue — it is an unknown one.
    sourcesFailed: failed.length,
    failedSources: failed.map((s) => ({ key: s.key, error: s.error || 'unknown error' })),
    sourcesTruncated: truncated.length,
    truncatedSources: truncated.map((s) => ({ key: s.key, shown: s.count, of: s.truncatedFrom })),
  };
}

module.exports = {
  WORK_BANDS,
  EVIDENCE,
  bandFor,
  rankItems,
  summarise,
  severityRank,
  magnitudeOf,
};
