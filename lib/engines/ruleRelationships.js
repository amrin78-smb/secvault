// lib/engines/ruleRelationships.js
//
// Pure, no-DB clustering over the 5 rule_analysis_results finding types that
// each describe a RELATIONSHIP between two specific rules rather than a
// property of one rule alone: shadow / redundant / correlation /
// generalization / reorder_candidate. Same "pure engine, no I/O" pattern as
// riskScore.js/ruleReorder.js in this directory.
//
// Every row of these 5 types has rule_id (the rule the finding is attached
// to) and affected_rule_ids (a JSONB array -- currently always exactly one
// element for all 5 of these types, per ruleAnalysis.js -- naming the OTHER
// rule involved). Treating each finding as an undirected edge between
// rule_id and every id in affected_rule_ids (iterated as an array rather
// than assumed to hold exactly one, so this stays correct if that ever
// changes) and computing connected components turns the flat, hard-to-scan
// findings table into groups of rules that are actually related to each
// other -- "rule A shadows four other rules" becomes one 5-rule cluster
// instead of four separate, seemingly-unrelated table rows.
//
'use strict';

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, info: 3 };

// Standard union-find with path compression. Keyed on rule id (a UUID
// string) -- parent is a Map, not an array, since ids aren't small ints.
function findRoot(parent, x) {
  if (!parent.has(x)) parent.set(x, x);
  let root = x;
  while (parent.get(root) !== root) root = parent.get(root);
  let cur = x;
  while (parent.get(cur) !== root) {
    const next = parent.get(cur);
    parent.set(cur, root);
    cur = next;
  }
  return root;
}

function union(parent, a, b) {
  const ra = findRoot(parent, a);
  const rb = findRoot(parent, b);
  if (ra !== rb) parent.set(ra, rb);
}

/**
 * Groups relationship findings into connected clusters via union-find over
 * the rule_id <-> affected_rule_ids edges each finding represents.
 *
 * A cluster with only 2 rules and 1 finding (e.g. a single shadow pair) is
 * still a valid, common result -- never filtered out. Findings with a
 * missing/falsy rule_id are skipped (defensive only; rule_id is NOT NULL in
 * the schema). An affected id equal to its own finding's rule_id (should
 * never happen, but not assumed impossible) is treated as a no-op self-edge,
 * not a crash.
 *
 * Clusters are sorted worst-first: by the highest severity present in the
 * cluster (critical > high > medium > info, matching the ordering already
 * used across this app -- see SeverityBadge.js/the Findings tab's ORDER BY),
 * then by rule count descending as a tiebreaker so bigger clusters surface
 * before smaller ones of the same severity.
 *
 * @param {Array<{finding_id: string, finding_type: string, severity: string, detail?: string, remediation?: string, rule_id: string, affected_rule_ids: string[]}>} findings
 * @returns {Array<{ruleIds: string[], findings: Array, worstSeverity: string}>}
 */
function clusterRelationshipFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  const parent = new Map();

  for (const f of list) {
    if (!f || !f.rule_id) continue;
    findRoot(parent, f.rule_id); // register the node even if affected_rule_ids ends up empty
    const affected = Array.isArray(f.affected_rule_ids) ? f.affected_rule_ids : [];
    for (const otherId of affected) {
      if (!otherId || otherId === f.rule_id) continue;
      union(parent, f.rule_id, otherId);
    }
  }

  const clustersByRoot = new Map();
  for (const f of list) {
    if (!f || !f.rule_id) continue;
    const root = findRoot(parent, f.rule_id);
    let cluster = clustersByRoot.get(root);
    if (!cluster) {
      cluster = { ruleIdSet: new Set(), findings: [] };
      clustersByRoot.set(root, cluster);
    }
    cluster.ruleIdSet.add(f.rule_id);
    const affected = Array.isArray(f.affected_rule_ids) ? f.affected_rule_ids : [];
    for (const otherId of affected) {
      if (otherId) cluster.ruleIdSet.add(otherId);
    }
    cluster.findings.push(f);
  }

  const clusters = [...clustersByRoot.values()].map((c) => {
    let worstSeverity = 'info';
    for (const f of c.findings) {
      const rank = SEVERITY_RANK[f.severity];
      if (rank !== undefined && rank < SEVERITY_RANK[worstSeverity]) {
        worstSeverity = f.severity;
      }
    }
    return {
      ruleIds: [...c.ruleIdSet],
      findings: c.findings,
      worstSeverity,
    };
  });

  clusters.sort((a, b) => {
    const sevDiff = SEVERITY_RANK[a.worstSeverity] - SEVERITY_RANK[b.worstSeverity];
    if (sevDiff !== 0) return sevDiff;
    return b.ruleIds.length - a.ruleIds.length;
  });

  return clusters;
}

module.exports = { clusterRelationshipFindings, SEVERITY_RANK };
