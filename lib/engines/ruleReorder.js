// lib/engines/ruleReorder.js
//
// Pure, no-DB companion to ruleAnalysis.js's `reorder_candidate` finding —
// same "pure engine, no I/O" pattern as riskScore.js. ruleAnalysis.js only
// ever flags INDIVIDUAL problem rules ("this deny is shadowed by that
// allow"); this file is the missing synthesis step: given a device's
// current rule order and its full set of reorder_candidate findings,
// compute ONE recommended new order that resolves as many of them as
// possible, the same concept as ManageEngine Firewall Analyzer's "Rule
// Reorder & Recommendation" tool (see the SecVault/ManageEngine research
// artifact this feature was scoped from).
//
// Each reorder_candidate finding means: rule `rule_id` (a deny/drop/reject)
// is unreachable because an earlier rule `affected_rule_ids[0]` (an allow)
// fully covers its traffic. The fix is a precedence CONSTRAINT: the deny
// must end up positioned before its shadowing allow. With many findings on
// one device, these constraints can interact -- moving one deny to satisfy
// one finding could reintroduce or resolve another. This is a topological
// ordering problem, solved with Kahn's algorithm rather than naive
// pairwise swapping, specifically because Kahn's algorithm has a clean,
// correct answer for the case naive swapping doesn't: a genuine CYCLE
// (rule A must precede rule B per one finding, and rule B must precede
// rule A per a different finding -- two conflicting requirements that no
// single order can satisfy). Silently guessing an order in that case would
// be exactly the "looks fine, isn't" failure this codebase's own tri-state
// honesty conventions exist to avoid -- cyclic rules are detected and
// reported as UNRESOLVED, left in their original position, rather than
// guessed at.
//
// 'use strict';

/**
 * @typedef {{id: string, sequence_number: number|null, rule_name: string|null, rule_id_vendor: string|null}} RuleRow
 * @typedef {{rule_id: string, affected_rule_ids: string[]}} ReorderFinding
 */

/**
 * Computes a recommended rule order that resolves as many reorder_candidate
 * findings as possible via topological sort (Kahn's algorithm), leaving any
 * rule involved in a genuine ordering conflict (a cycle) at its original
 * position and reporting it separately rather than guessing.
 *
 * Deliberately conservative in two ways, matching this codebase's existing
 * "no ruleset is safer than the wrong one" posture (CLAUDE.md, Fortinet/
 * Sangfor getRules()):
 *  - A finding referencing a rule id that no longer exists in `rules` (the
 *    finding is stale relative to this snapshot -- firewall_rules is fully
 *    DELETE+reinserted on every collect, same caveat ReorderTab.js's own
 *    header comment already documents) is silently skipped, never guessed.
 *  - Rules NOT referenced by any finding are never touched or reordered --
 *    only the minimal subset of rules actually involved in a flagged
 *    ordering problem moves; their new positions are the SLOTS the
 *    involved rules originally occupied (stable merge), so the recommended
 *    order is the smallest possible diff from the current one, not a full
 *    re-sort.
 *
 * @param {RuleRow[]} rules - device's current rules, in current order (by sequence_number)
 * @param {ReorderFinding[]} findings - this device's reorder_candidate findings
 * @returns {{
 *   recommendedOrder: RuleRow[],
 *   changedRuleIds: string[],
 *   unresolvedRuleIds: string[],
 *   resolvedFindingCount: number,
 *   unresolvedFindingCount: number,
 * }}
 */
function computeRecommendedOrder(rules, findings) {
  const ruleList = Array.isArray(rules) ? rules : [];
  const findingList = Array.isArray(findings) ? findings : [];

  const orderedIds = ruleList.map((r) => r.id);
  const idSet = new Set(orderedIds);
  const originalIndex = new Map(orderedIds.map((id, i) => [id, i]));

  // Build precedence edges (before -> after) from findings that are still
  // valid against this exact rule snapshot. Deduplicate identical edges
  // (two findings can independently name the same deny/allow pair) so
  // in-degree counting below isn't inflated by duplicates -- but keep a
  // per-edge count of how many original findings contributed to it, so the
  // resolved/unresolved tally below (which must reflect one count per
  // FINDING, not per unique edge) doesn't silently drop duplicates.
  const edgeKeys = new Set();
  const edgeFindingCounts = new Map();
  const edges = [];
  let resolvedFindingCount = 0;
  let unresolvedFindingCount = 0;

  for (const f of findingList) {
    const denyId = f && f.rule_id;
    const allowId = f && Array.isArray(f.affected_rule_ids) ? f.affected_rule_ids[0] : null;
    if (!denyId || !allowId || !idSet.has(denyId) || !idSet.has(allowId) || denyId === allowId) {
      unresolvedFindingCount += 1;
      continue;
    }
    const key = `${denyId}->${allowId}`;
    edgeFindingCounts.set(key, (edgeFindingCounts.get(key) || 0) + 1);
    if (!edgeKeys.has(key)) {
      edgeKeys.add(key);
      edges.push({ before: denyId, after: allowId });
    }
  }

  const involvedIds = new Set();
  for (const e of edges) {
    involvedIds.add(e.before);
    involvedIds.add(e.after);
  }

  // Kahn's algorithm, scoped to only the involved subgraph.
  const adj = new Map();
  const indegree = new Map();
  for (const id of involvedIds) {
    adj.set(id, new Set());
    indegree.set(id, 0);
  }
  for (const e of edges) {
    const neighbors = adj.get(e.before);
    if (!neighbors.has(e.after)) {
      neighbors.add(e.after);
      indegree.set(e.after, indegree.get(e.after) + 1);
    }
  }

  // Ties broken by original position, so the algorithm's output is
  // deterministic and stays as close to the current order as the
  // constraints allow, not an arbitrary/unstable ordering.
  const byOriginalIndex = (a, b) => originalIndex.get(a) - originalIndex.get(b);

  let queue = [...involvedIds].filter((id) => indegree.get(id) === 0).sort(byOriginalIndex);
  const topoOrder = [];
  while (queue.length > 0) {
    const id = queue.shift();
    topoOrder.push(id);
    for (const next of adj.get(id)) {
      indegree.set(next, indegree.get(next) - 1);
      if (indegree.get(next) === 0) queue.push(next);
    }
    queue.sort(byOriginalIndex);
  }

  const resolvedSet = new Set(topoOrder);
  const unresolvedRuleIds = [...involvedIds].filter((id) => !resolvedSet.has(id));
  // A finding counts as resolved only if BOTH its rules made it into the
  // topological order (neither is part of a cycle). Tally per ORIGINAL
  // finding (edgeFindingCounts), not per deduplicated edge, so two findings
  // that collapse to the same edge are both accounted for.
  for (const e of edges) {
    const key = `${e.before}->${e.after}`;
    const count = edgeFindingCounts.get(key) || 0;
    if (resolvedSet.has(e.before) && resolvedSet.has(e.after)) resolvedFindingCount += count;
    else unresolvedFindingCount += count;
  }

  // Stable merge: the slots originally occupied by successfully-ordered
  // rules get filled, in order, by the topological result. Every other
  // position (untouched rules, and rules stuck in a cycle) keeps its
  // original occupant.
  const slots = [];
  orderedIds.forEach((id, i) => {
    if (resolvedSet.has(id)) slots.push(i);
  });

  const newOrderIds = [...orderedIds];
  slots.forEach((slotIndex, k) => {
    newOrderIds[slotIndex] = topoOrder[k];
  });

  const ruleById = new Map(ruleList.map((r) => [r.id, r]));
  const recommendedOrder = newOrderIds.map((id) => ruleById.get(id));
  const changedRuleIds = newOrderIds.filter((id, i) => id !== orderedIds[i]);

  return {
    recommendedOrder,
    changedRuleIds,
    unresolvedRuleIds,
    resolvedFindingCount,
    unresolvedFindingCount,
  };
}

module.exports = { computeRecommendedOrder };
