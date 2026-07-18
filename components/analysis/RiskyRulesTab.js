import { pool } from '../../lib/db';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import StatCard from '../ui/StatCard';
import EmptyState from '../ui/EmptyState';
import { computeRuleRiskBand } from '../../lib/engines/riskScore';

// Rule Analysis Dashboard -- "Risky Rules" tab (sibling of the existing
// device-level "Risk" tab / RiskTab.js, which trends ONE score for the whole
// device). This tab is the per-RULE breakdown ManageEngine Firewall
// Analyzer's own Risk area shows alongside its device gauge: 5 stat tiles
// (Critical/High/Medium/Low/Attention counts of RULES, not findings) plus a
// full rule-by-rule risk table. Async server component, does its own
// pool.query -- same convention as RiskTab.js/CleanupTab.js/ReorderTab.js.
// Do not add 'use client'.

// Same color convention as app/(dashboard)/devices/[id]/analysis/page.js's
// RISK_BAND_COLOR/RISK_BAND_LABEL (device-level bands) and RiskTab.js's copy
// of the same, extended with a 5th 'attention' band -- see
// computeRuleRiskBand()'s own comment in lib/engines/riskScore.js for why
// 'attention' exists and must not be collapsed into 'low' or relabeled.
const RULE_BAND_COLOR = { low: 'success', medium: 'info', high: 'warning', critical: 'danger', attention: 'muted' };
const RULE_BAND_LABEL = { low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical', attention: 'Attention' };

// StatCard takes a raw CSS color (its left-border accent), not a Badge color
// name -- same var(--red)/var(--yellow)/var(--blue)/var(--text-muted)
// convention already used for the severity tiles on the Summary tab in
// devices/[id]/analysis/page.js, extended with var(--green) for 'low'
// (success/green is the "no issues" meaning used everywhere else in this
// app -- StatusDot, etc.).
const STAT_TILE_COLOR = {
  critical: 'var(--red)',
  high: 'var(--yellow)',
  medium: 'var(--blue)',
  low: 'var(--green)',
  attention: 'var(--text-muted)',
};

// Display/sort order requested for this tab specifically: worst band first,
// but with 'attention' placed between 'medium' and 'low' -- distinct from
// RULE_BAND_RANK inside riskScore.js (which ranks 'attention' as the LOWEST
// concern, for "is this worse than that" comparisons elsewhere). Both are
// correct for their own purpose; this is purely a display-order concern.
const SORT_RANK = { critical: 0, high: 1, medium: 2, attention: 3, low: 4 };
const BAND_ORDER = ['critical', 'high', 'medium', 'low', 'attention'];

// Same array-to-readable-string cell convention as
// devices/[id]/rules/page.js's joinArray() -- mirrored here rather than
// imported, matching this app's established per-file-duplication convention
// for small render helpers (see CLAUDE.md's Alerts/Compliance sections for
// other examples of this same tradeoff).
function joinArray(value) {
  if (!Array.isArray(value) || value.length === 0) return '—';
  return value.join(', ');
}

function ruleLabel(row) {
  const seq = row.sequence_number != null ? `#${row.sequence_number}` : '#—';
  return `${seq} ${row.rule_name || '(unnamed rule)'}`;
}

// One rule per row, LEFT JOINed against rule_analysis_results and aggregated
// to that rule's OWN findings only (rar.rule_id = fr.id -- never
// affected_rule_ids, which names OTHER rules in a shadow/redundant/
// correlation relationship, a different concept -- see ReorderTab.js for
// where affected_rule_ids IS the right thing to resolve). A rule with zero
// findings still appears, with severities = '{}' via the FILTER-based
// array_agg, so computeRuleRiskBand() can correctly band it 'attention' or
// 'low' rather than being silently dropped by an inner join.
async function getRulesWithFindings(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT
       fr.id,
       fr.rule_name,
       fr.sequence_number,
       fr.action,
       fr.enabled,
       fr.src_addresses,
       fr.dst_addresses,
       fr.services,
       COALESCE(array_agg(rar.severity) FILTER (WHERE rar.severity IS NOT NULL), '{}') AS severities
     FROM firewall_rules fr
     LEFT JOIN rule_analysis_results rar ON rar.rule_id = fr.id
     WHERE fr.device_id = $1
     GROUP BY fr.id
     ORDER BY fr.sequence_number ASC NULLS LAST`,
    [deviceId]
  );
  return result.rows;
}

export default async function RiskyRulesTab({ deviceId }) {
  const rules = await getRulesWithFindings(pool, deviceId);

  if (rules.length === 0) {
    return (
      <EmptyState message="No rules collected yet — per-rule risk banding will appear here once rules are collected and analysis has run." />
    );
  }

  const banded = rules.map((rule) => {
    const findings = (Array.isArray(rule.severities) ? rule.severities : []).map((severity) => ({ severity }));
    const band = computeRuleRiskBand(findings, rule.enabled);
    return { ...rule, band, findingCount: findings.length };
  });

  banded.sort((a, b) => SORT_RANK[a.band] - SORT_RANK[b.band]);

  const bandCounts = { critical: 0, high: 0, medium: 0, low: 0, attention: 0 };
  for (const rule of banded) bandCounts[rule.band] += 1;

  const totalRules = banded.length;
  const riskyCount = totalRules - bandCounts.low;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 16 }}>
        {BAND_ORDER.map((band) => (
          <StatCard
            key={band}
            label={RULE_BAND_LABEL[band]}
            value={bandCounts[band]}
            color={STAT_TILE_COLOR[band]}
          />
        ))}
      </div>

      <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
        {riskyCount} Risky Rule{riskyCount === 1 ? '' : 's'} of Total: {totalRules}
      </p>

      <Table>
        <colgroup>
          <col style={{ width: '22%' }} />
          <col style={{ width: '10%' }} />
          <col style={{ width: '18%' }} />
          <col style={{ width: '18%' }} />
          <col style={{ width: '14%' }} />
          <col style={{ width: '10%' }} />
          <col style={{ width: '8%' }} />
        </colgroup>
        <thead>
          <tr>
            <th>Rule Name</th>
            <th>Action</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Service</th>
            <th>Risk Band</th>
            <th># Findings</th>
          </tr>
        </thead>
        <tbody>
          {banded.map((rule) => (
            <tr key={rule.id}>
              <td title={ruleLabel(rule)}>{ruleLabel(rule)}</td>
              <td>{rule.action || '—'}</td>
              <td title={joinArray(rule.src_addresses)}>{joinArray(rule.src_addresses)}</td>
              <td title={joinArray(rule.dst_addresses)}>{joinArray(rule.dst_addresses)}</td>
              <td title={joinArray(rule.services)}>{joinArray(rule.services)}</td>
              <td>
                <Badge color={RULE_BAND_COLOR[rule.band]}>{RULE_BAND_LABEL[rule.band]}</Badge>
              </td>
              <td>{rule.findingCount}</td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}
