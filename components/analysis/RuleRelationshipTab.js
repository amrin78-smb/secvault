import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import EmptyState from '../ui/EmptyState';
import SeverityBadge from './SeverityBadge';
import FindingTypeBadge from './FindingTypeBadge';
import { clusterRelationshipFindings } from '../../lib/engines/ruleRelationships';

// Rule Analysis Dashboard -- "Relationships" tab. 5 of the engine's finding
// types (shadow / redundant / correlation / generalization /
// reorder_candidate -- see lib/engines/ruleAnalysis.js) each describe a
// RELATIONSHIP between two specific rules, not a property of one rule alone.
// Until this tab, the only place to see them was the flat Findings table,
// one rule + one detail sentence per row, with no way to tell at a glance
// that (say) one rule is the hub shadowing four others, or that three rules
// form one connected cleanup cluster. This tab groups the SAME
// already-computed rule_analysis_results rows into connected clusters
// (lib/engines/ruleRelationships.js's clusterRelationshipFindings(), a plain
// union-find over the rule_id <-> affected_rule_ids edges) and renders one
// card per cluster instead of one row per finding.
//
// Deliberately NOT a force-directed graph / new charting dependency -- see
// this feature's own scoping discussion. A hand-rolled clustered list (rule
// chips + a stacked edge list per cluster) is the actual deliverable; it
// stays readable at any cluster size, unlike an SVG node-link diagram, which
// only reads cleanly for a handful of nodes and turns into an unreadable
// hairball past that.
//
// Async server component, does its own pool.query -- same "server component
// queries the DB directly" convention as ReorderTab.js/RiskyRulesTab.js/
// ObjectsTab.js in this same directory. Do not add 'use client'.
//
// affected_rule_ids is resolved against a same-request snapshot of the
// device's rules (getDeviceRules below), same discipline ReorderTab.js's own
// header comment documents: firewall_rules is fully DELETE+reinserted on
// every collect, so these ids are not stable across pulls -- never persist
// or cache a resolved name anywhere, only render it once per request.

const RELATIONSHIP_FINDING_TYPES = ['shadow', 'redundant', 'correlation', 'generalization', 'reorder_candidate'];

async function getRelationshipFindings(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT
       rar.id AS finding_id,
       rar.finding_type,
       rar.severity,
       rar.detail,
       rar.remediation,
       rar.rule_id,
       rar.affected_rule_ids
     FROM rule_analysis_results rar
     WHERE rar.device_id = $1 AND rar.finding_type = ANY($2::text[])
     ORDER BY rar.id`,
    [deviceId, RELATIONSHIP_FINDING_TYPES]
  );
  return result.rows;
}

// All rules for this device, used to build the id -> {rule_name,
// sequence_number} lookup map for resolving rule_id/affected_rule_ids into
// display labels -- same query ReorderTab.js's getDeviceRules() runs.
async function getDeviceRules(dbPool, deviceId) {
  const result = await dbPool.query(
    'SELECT id, rule_name, sequence_number FROM firewall_rules WHERE device_id = $1',
    [deviceId]
  );
  return result.rows;
}

// Same "#<seq> <name>" convention as ReorderTab.js's/RiskyRulesTab.js's own
// ruleLabel() helpers, duplicated per this app's established
// per-file-duplication convention for small render helpers rather than a
// shared import (see CLAUDE.md's Alerts/Compliance sections for other
// examples of this same tradeoff).
function ruleLabel(ruleId, ruleMap) {
  const match = ruleMap.get(ruleId);
  if (!match) return '(rule no longer present)';
  const seq = match.sequence_number != null ? `#${match.sequence_number}` : '#—';
  return `${seq} ${match.rule_name || '(unnamed rule)'}`;
}

function sortRuleIds(ruleIds, ruleMap) {
  return [...ruleIds].sort((a, b) => {
    const ra = ruleMap.get(a);
    const rb = ruleMap.get(b);
    const sa = ra && ra.sequence_number != null ? ra.sequence_number : Number.MAX_SAFE_INTEGER;
    const sb = rb && rb.sequence_number != null ? rb.sequence_number : Number.MAX_SAFE_INTEGER;
    return sa - sb;
  });
}

// A small chip rendering one rule's label -- module-top-level component
// (not defined inside another component, per CLAUDE.md's React rule), reused
// both in a cluster's "rules involved" summary row and in each individual
// edge row below.
function RuleChip({ ruleId, ruleMap }) {
  const label = ruleLabel(ruleId, ruleMap);
  return (
    <span
      title={label}
      style={{
        display: 'inline-block',
        padding: '3px 8px',
        borderRadius: 'var(--radius-sm)',
        border: '1px solid var(--border)',
        background: 'var(--bg-card)',
        fontSize: 'var(--text-sm)',
        color: 'var(--text-primary)',
        whiteSpace: 'nowrap',
        maxWidth: 240,
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        verticalAlign: 'middle',
      }}
    >
      {label}
    </span>
  );
}

// One cluster = one Card. For a 2-rule cluster (the common case -- a single
// shadow/redundant/correlation/generalization pair, or one reorder_candidate
// pair) the "rules involved" summary chip row is deliberately SKIPPED: the
// single edge row rendered below it already shows exactly those same two
// rules as a chip -> chip chain, so repeating them above would be pure
// redundancy. For a 3+ rule cluster (e.g. one hub rule shadowing several
// others, or a chain of generalizations), the summary row gives a genuine
// at-a-glance overview before the operator reads through the individual
// edges underneath it.
function ClusterCard({ cluster, ruleMap }) {
  const orderedRuleIds = sortRuleIds(cluster.ruleIds, ruleMap);
  const findingTypesPresent = [...new Set(cluster.findings.map((f) => f.finding_type))];

  return (
    <Card>
      <CardBody>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 8,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <SeverityBadge severity={cluster.worstSeverity} />
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
              {orderedRuleIds.length} rule{orderedRuleIds.length === 1 ? '' : 's'} in this cluster
              {' · '}
              {cluster.findings.length} relationship{cluster.findings.length === 1 ? '' : 's'}
            </span>
          </div>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {findingTypesPresent.map((t) => (
              <FindingTypeBadge key={t} type={t} />
            ))}
          </div>
        </div>

        {orderedRuleIds.length > 2 && (
          <div style={{ marginTop: 12, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {orderedRuleIds.map((id) => (
              <RuleChip key={id} ruleId={id} ruleMap={ruleMap} />
            ))}
          </div>
        )}

        <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 10 }}>
          {cluster.findings.map((f) => {
            const affected = Array.isArray(f.affected_rule_ids) ? f.affected_rule_ids : [];
            return (
              <div
                key={f.finding_id}
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 4,
                  padding: '8px 10px',
                  borderLeft: '3px solid var(--border)',
                  background: 'var(--bg-primary)',
                  borderRadius: 'var(--radius-sm)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                  <RuleChip ruleId={f.rule_id} ruleMap={ruleMap} />
                  {affected.length > 0 && <span style={{ color: 'var(--text-muted)' }}>→</span>}
                  {affected.map((otherId) => (
                    <RuleChip key={otherId} ruleId={otherId} ruleMap={ruleMap} />
                  ))}
                  <FindingTypeBadge type={f.finding_type} />
                  <SeverityBadge severity={f.severity} />
                </div>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }} title={f.detail || ''}>
                  {f.detail || '—'}
                </div>
                {f.remediation && (
                  <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                    Suggested fix: {f.remediation}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </CardBody>
    </Card>
  );
}

export default async function RuleRelationshipTab({ deviceId }) {
  const [findings, deviceRules] = await Promise.all([
    getRelationshipFindings(pool, deviceId),
    getDeviceRules(pool, deviceId),
  ]);

  if (findings.length === 0) {
    return (
      <EmptyState message="No shadow, redundant, correlated, generalized, or reorder-candidate rule relationships found for this device." />
    );
  }

  const ruleMap = new Map(deviceRules.map((r) => [r.id, r]));
  const clusters = clusterRelationshipFindings(findings);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
        {clusters.length} cluster{clusters.length === 1 ? '' : 's'} of related rules, grouped from{' '}
        {findings.length} relationship finding{findings.length === 1 ? '' : 's'} (shadow, redundant, correlation,
        generalization, reorder-candidate) — sorted worst severity and largest cluster first.
      </p>
      {clusters.map((cluster, i) => (
        <ClusterCard key={cluster.ruleIds[0] || i} cluster={cluster} ruleMap={ruleMap} />
      ))}
    </div>
  );
}
