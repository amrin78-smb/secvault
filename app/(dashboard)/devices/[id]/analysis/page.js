import Link from 'next/link';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../../api/auth/[...nextauth]/route';
import { isAdmin } from '../../../../../lib/rbac';
import { pool } from '../../../../../lib/db';
import Table from '../../../../../components/ui/Table';
import Badge from '../../../../../components/ui/Badge';
import EmptyState from '../../../../../components/ui/EmptyState';
import StatCard from '../../../../../components/ui/StatCard';
import PageHeader from '../../../../../components/ui/PageHeader';
import Card, { CardBody } from '../../../../../components/ui/Card';
import SeverityBadge from '../../../../../components/analysis/SeverityBadge';
import FindingTypeBadge from '../../../../../components/analysis/FindingTypeBadge';
import RunAnalysisButton from '../../../../../components/analysis/RunAnalysisButton';
import FindingsBarChart from '../../../../../components/analysis/FindingsBarChart';
import RuleStatsBarChart from '../../../../../components/analysis/RuleStatsBarChart';
import CleanupTab from '../../../../../components/analysis/CleanupTab';
import OptimizationTab from '../../../../../components/analysis/OptimizationTab';
import ReorderTab from '../../../../../components/analysis/ReorderTab';
import RiskTab from '../../../../../components/analysis/RiskTab';
import RiskyRulesTab from '../../../../../components/analysis/RiskyRulesTab';
import ObjectsTab from '../../../../../components/analysis/ObjectsTab';
import TrackingTab from '../../../../../components/analysis/TrackingTab';
import ReachabilityTab from '../../../../../components/analysis/ReachabilityTab';
import RuleRelationshipTab from '../../../../../components/analysis/RuleRelationshipTab';
import { computeRiskScoreFromCounts } from '../../../../../lib/engines/riskScore';

export const dynamic = 'force-dynamic';

// The 11 finding types in the fixed severity order CLAUDE.md documents for
// the rule analysis engine, used both for the findings-tab filter dropdown
// and for the summary-tab bar chart (so the bar order never depends on
// whatever happens to be present in a given device's results). 'correlation'
// (medium — mergeable rules, added alongside the Risky Rules view) sits
// next to 'redundant'/'overly_permissive', the other ruleset-simplification
// (not security-exposure) finding types. 'generalization' (added in the
// "Path A" rule-analysis intelligence round) is the mirror direction of
// shadow/redundant — an earlier, narrower same-action rule made pointless
// by a later, broader one — and sits in that same ruleset-simplification
// group, not the security-exposure group.
const FINDING_TYPES = [
  'any_any',
  'risky_service',
  'shadow',
  'reorder_candidate',
  'redundant',
  'correlation',
  'generalization',
  'overly_permissive',
  'unused',
  'expiring_soon',
  'log_disabled',
];

const SEVERITIES = ['critical', 'high', 'medium', 'info'];

// Same color convention as SeverityBadge.js (critical->danger, high->warning,
// medium->info) extended with 'low'->success, matching the green/success
// meaning used everywhere else in the app (StatusDot, etc.) for "no issues".
const RISK_BAND_COLOR = { low: 'success', medium: 'info', high: 'warning', critical: 'danger' };
const RISK_BAND_LABEL = { low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' };

function formatDateTime(value) {
  if (!value) return 'Never';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'Never';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

async function getDevice(dbPool, id) {
  const result = await dbPool.query('SELECT id, name FROM devices WHERE id = $1', [id]);
  return result.rows[0] || null;
}

// Severity counts + last-analyzed timestamp from rule_analysis_results.
async function getSeveritySummary(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT
       COUNT(*)::int AS total,
       COUNT(*) FILTER (WHERE severity = 'critical')::int AS critical,
       COUNT(*) FILTER (WHERE severity = 'high')::int AS high,
       COUNT(*) FILTER (WHERE severity = 'medium')::int AS medium,
       COUNT(*) FILTER (WHERE severity = 'info')::int AS info,
       MAX(analyzed_at) AS last_analyzed_at
     FROM rule_analysis_results
     WHERE device_id = $1`,
    [deviceId]
  );
  return (
    result.rows[0] || { total: 0, critical: 0, high: 0, medium: 0, info: 0, last_analyzed_at: null }
  );
}

// Per-finding_type counts, for the summary-tab bar chart. Zero-filled for
// every known type (not just the ones present) so the chart's bars are
// always in the same fixed order/width scale run to run.
async function getFindingTypeCounts(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT finding_type, COUNT(*)::int AS count
     FROM rule_analysis_results
     WHERE device_id = $1
     GROUP BY finding_type`,
    [deviceId]
  );
  const counts = {};
  for (const type of FINDING_TYPES) counts[type] = 0;
  for (const row of result.rows) counts[row.finding_type] = row.count;
  return counts;
}

// Rule-level stats direct from firewall_rules -- ManageEngine-style
// Allowed/Denied/Inactive/Total, computed independently of the findings
// engine (a device can have rules with zero findings).
//
// nat_count added 2026-07-19 for RuleStatsBarChart / the NAT StatCard tile --
// firewall_rules.nat_enabled already existed in the schema (used by no UI
// until now).
async function getRuleStats(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT
       COUNT(*)::int AS total_rules,
       COUNT(*) FILTER (WHERE action IN ('allow', 'permit', 'accept'))::int AS allowed_count,
       COUNT(*) FILTER (WHERE action IN ('deny', 'drop', 'reject', 'block'))::int AS denied_count,
       COUNT(*) FILTER (WHERE enabled = false)::int AS inactive_count,
       COUNT(*) FILTER (WHERE nat_enabled = true)::int AS nat_count
     FROM firewall_rules
     WHERE device_id = $1`,
    [deviceId]
  );
  return (
    result.rows[0] || {
      total_rules: 0,
      allowed_count: 0,
      denied_count: 0,
      inactive_count: 0,
      nat_count: 0,
    }
  );
}

async function getFindings(dbPool, deviceId, { severity, findingType } = {}) {
  const conditions = ['rar.device_id = $1'];
  const params = [deviceId];

  if (severity && SEVERITIES.includes(severity)) {
    params.push(severity);
    conditions.push(`rar.severity = $${params.length}`);
  }
  if (findingType && FINDING_TYPES.includes(findingType)) {
    params.push(findingType);
    conditions.push(`rar.finding_type = $${params.length}`);
  }

  const result = await dbPool.query(
    `SELECT
       rar.id,
       rar.finding_type,
       rar.severity,
       rar.detail,
       rar.remediation,
       fr.rule_name,
       fr.sequence_number
     FROM rule_analysis_results rar
     JOIN firewall_rules fr ON fr.id = rar.rule_id
     WHERE ${conditions.join(' AND ')}
     ORDER BY
       CASE rar.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
       rar.finding_type ASC,
       fr.sequence_number ASC NULLS LAST`,
    params
  );
  return result.rows;
}

function ruleLabel(row) {
  const seq = row.sequence_number != null ? `#${row.sequence_number}` : '#—';
  return `${seq} ${row.rule_name || '(unnamed rule)'}`;
}

// Module-top-level so a future refactor toward client-side interactive tabs
// can't accidentally turn this into a component defined inside a component
// (see CLAUDE.md's "NEVER define a React component inside another React
// component" rule). Currently invoked as a plain function call ({tabLink(...)}),
// not a JSX tag, so it isn't a component today -- but this keeps it that way
// even if a later change starts rendering it as <TabLink/>. Takes the
// previously-closed-over `deviceId`/`activeTab` explicitly instead of relying
// on closure.
function tabLink(deviceId, activeTab, key, label) {
  const active = activeTab === key;
  return (
    <Link
      key={key}
      href={`/devices/${deviceId}/analysis?tab=${key}`}
      style={{
        padding: '8px 12px',
        fontSize: 'var(--text-base)',
        color: active ? 'var(--primary)' : 'var(--text-secondary)',
        borderBottom: active ? '2px solid var(--primary)' : '2px solid transparent',
        textDecoration: 'none',
      }}
    >
      {label}
    </Link>
  );
}

export default async function DeviceAnalysisPage({ params, searchParams }) {
  // Defense in depth only -- POST devices/[id]/analysis (Run Analysis) is
  // already server-side admin-only (lib/rbac.js). Hiding the button here
  // just avoids a viewer clicking it and getting a 403.
  const session = await getServerSession(authOptions);
  const canWrite = isAdmin(session);

  const device = await getDevice(pool, params.id);

  if (!device) {
    return (
      <div>
        <Link href="/devices" style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
          ← Back to devices
        </Link>
        <p style={{ marginTop: 16, color: 'var(--text-secondary)' }}>Device not found.</p>
      </div>
    );
  }

  const tab = [
    'summary',
    'rules',
    'findings',
    'cleanup',
    'optimization',
    'reorder',
    'risk',
    'risky-rules',
    'objects',
    'tracking',
    'reachability',
    'relationships',
  ].includes(searchParams?.tab)
    ? searchParams.tab
    : 'summary';
  const severityFilter = searchParams?.severity || '';
  const findingTypeFilter = searchParams?.finding_type || '';

  const [severitySummary, findingTypeCounts, ruleStats, findings] = await Promise.all([
    getSeveritySummary(pool, device.id),
    tab === 'summary' ? getFindingTypeCounts(pool, device.id) : Promise.resolve(null),
    getRuleStats(pool, device.id),
    tab === 'findings'
      ? getFindings(pool, device.id, { severity: severityFilter, findingType: findingTypeFilter })
      : Promise.resolve([]),
  ]);

  const riskScore = computeRiskScoreFromCounts(severitySummary);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <Link href={`/devices/${device.id}`} style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
          ← Back to {device.name}
        </Link>
      </div>

      <PageHeader
        title={`Rule Analysis — ${device.name}`}
        actions={
          <>
            <Badge color={RISK_BAND_COLOR[riskScore.band]}>
              Risk: {RISK_BAND_LABEL[riskScore.band]} ({riskScore.score})
            </Badge>
            <a href={`/api/devices/${device.id}/analysis?format=csv`} className="btn btn-secondary">
              Export CSV
            </a>
            {canWrite && <RunAnalysisButton deviceId={device.id} />}
          </>
        }
      />

      <div style={{ display: 'flex', alignItems: 'center', gap: 4, borderBottom: '1px solid var(--border)' }}>
        {tabLink(device.id, tab, 'summary', 'Summary')}
        {tabLink(device.id, tab, 'rules', `Security Rules ${ruleStats.total_rules}`)}
        {tabLink(device.id, tab, 'findings', `Findings ${severitySummary.total}`)}
        {tabLink(device.id, tab, 'cleanup', 'Cleanup')}
        {tabLink(device.id, tab, 'optimization', 'Optimization')}
        {tabLink(device.id, tab, 'reorder', 'Reorder')}
        {tabLink(device.id, tab, 'risk', 'Risk')}
        {tabLink(device.id, tab, 'risky-rules', 'Risky Rules')}
        {tabLink(device.id, tab, 'objects', 'Objects')}
        {tabLink(device.id, tab, 'tracking', 'Tracking')}
        {tabLink(device.id, tab, 'reachability', 'Reachability')}
        {tabLink(device.id, tab, 'relationships', 'Relationships')}
      </div>

      {tab === 'summary' && (
        <>
          {/* ⛔ 2026-07-19: every tile below that has a real filtered
              destination is now a link -- "Denied Rules" links to
              action=deny,drop,reject,block (buildFilters() in both
              devices/[id]/rules/page.js and the sibling API route now accept
              a comma-separated action list via `= ANY(...)`, added
              specifically for this so the link's result set actually matches
              what this tile counted), "Any-to-Any"/"Logging Disabled" link
              into the Findings tab pre-filtered by finding_type (already
              supported), "NAT Enabled" is a new tile (ruleStats.nat_count,
              from firewall_rules.nat_enabled -- collected but never surfaced
              in any UI until now). "Total Rules" links to the unfiltered
              rule list. */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 16 }}>
            <Link href={`/devices/${device.id}/rules`} style={{ textDecoration: 'none' }}>
              <StatCard label="Total Rules" value={ruleStats.total_rules} />
            </Link>
            <Link href={`/devices/${device.id}/rules?action=allow`} style={{ textDecoration: 'none' }}>
              <StatCard label="Allowed Rules" value={ruleStats.allowed_count} color="var(--green)" />
            </Link>
            <Link
              href={`/devices/${device.id}/rules?action=deny,drop,reject,block`}
              style={{ textDecoration: 'none' }}
            >
              <StatCard label="Denied Rules" value={ruleStats.denied_count} color="var(--red)" />
            </Link>
            <Link href={`/devices/${device.id}/rules?enabled=false`} style={{ textDecoration: 'none' }}>
              <StatCard label="Inactive Rules" value={ruleStats.inactive_count} />
            </Link>
            <Link href={`/devices/${device.id}/rules?nat=true`} style={{ textDecoration: 'none' }}>
              <StatCard label="NAT Enabled" value={ruleStats.nat_count || 0} color="var(--blue)" />
            </Link>
            <Link
              href={`/devices/${device.id}/analysis?tab=findings&finding_type=any_any`}
              style={{ textDecoration: 'none' }}
            >
              <StatCard label="Allowed Any-to-Any" value={findingTypeCounts.any_any} color="var(--red)" />
            </Link>
            <Link
              href={`/devices/${device.id}/analysis?tab=findings&finding_type=log_disabled`}
              style={{ textDecoration: 'none' }}
            >
              <StatCard label="Logging Disabled" value={findingTypeCounts.log_disabled} color="var(--text-muted)" />
            </Link>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 16 }}>
            <StatCard label="Critical" value={severitySummary.critical} color="var(--red)" />
            <StatCard label="High" value={severitySummary.high} color="var(--yellow)" />
            <StatCard label="Medium" value={severitySummary.medium} color="var(--blue)" />
            <StatCard label="Info" value={severitySummary.info} color="var(--text-muted)" />
            <StatCard label="Total Findings" value={severitySummary.total} />
            {/* A datetime string, not a KPI number -- kept at the smaller
                text-base size (as the original text-sm/font-medium styling
                did) rather than StatCard's large stat-value size, which would
                make a long timestamp string look out of place next to the
                numeric tiles around it. */}
            <div className="kpi-card" style={{ borderLeftColor: 'var(--border)' }}>
              <div style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--text-primary)' }}>
                {formatDateTime(severitySummary.last_analyzed_at)}
              </div>
              <div className="stat-label">Last Analyzed</div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: 16 }}>
            <RuleStatsBarChart ruleStats={ruleStats} findingTypeCounts={findingTypeCounts} />
            <FindingsBarChart counts={findingTypeCounts} />
          </div>
        </>
      )}

      {tab === 'rules' && (
        <Card>
          <CardBody>
            <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
              {ruleStats.total_rules} rule{ruleStats.total_rules === 1 ? '' : 's'} collected —{' '}
              {ruleStats.allowed_count} allowed, {ruleStats.denied_count} denied,{' '}
              {ruleStats.inactive_count} inactive.
            </p>
            <Link
              href={`/devices/${device.id}/rules`}
              style={{ marginTop: 8, display: 'inline-block', fontSize: 'var(--text-base)', color: 'var(--primary)' }}
            >
              View full rule list →
            </Link>
          </CardBody>
        </Card>
      )}

      {tab === 'cleanup' && <CleanupTab deviceId={device.id} canWrite={canWrite} />}

      {tab === 'optimization' && <OptimizationTab deviceId={device.id} canWrite={canWrite} />}

      {tab === 'reorder' && <ReorderTab deviceId={device.id} canWrite={canWrite} />}

      {tab === 'risk' && <RiskTab deviceId={device.id} />}

      {tab === 'risky-rules' && <RiskyRulesTab deviceId={device.id} />}
      {tab === 'objects' && <ObjectsTab deviceId={device.id} />}

      {tab === 'tracking' && <TrackingTab deviceId={device.id} />}

      {tab === 'reachability' && <ReachabilityTab deviceId={device.id} />}
      {tab === 'relationships' && <RuleRelationshipTab deviceId={device.id} />}

      {tab === 'findings' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <form method="GET" className="filter-row">
            <input type="hidden" name="tab" value="findings" />
            <div className="form-field">
              <label htmlFor="severity">Severity</label>
              <select id="severity" name="severity" defaultValue={severityFilter} className="select">
                <option value="">All severities</option>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s[0].toUpperCase() + s.slice(1)}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-field">
              <label htmlFor="finding_type">Finding Type</label>
              <select id="finding_type" name="finding_type" defaultValue={findingTypeFilter} className="select">
                <option value="">All types</option>
                {FINDING_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>
            <button type="submit" className="btn btn-secondary">
              Filter
            </button>
          </form>

          {findings.length === 0 ? (
            <EmptyState message="No findings — run analysis or collect rules first." />
          ) : (
            <Table>
              <colgroup>
                <col style={{ width: '9%' }} />
                <col style={{ width: '13%' }} />
                <col style={{ width: '20%' }} />
                <col style={{ width: '31%' }} />
                <col style={{ width: '27%' }} />
              </colgroup>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Type</th>
                  <th>Rule</th>
                  <th>Detail</th>
                  <th>Remediation</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id}>
                    <td>
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td>
                      <FindingTypeBadge type={f.finding_type} />
                    </td>
                    <td title={ruleLabel(f)}>
                      <Link href={`/devices/${device.id}/rules`} style={{ color: 'var(--primary)' }}>
                        {ruleLabel(f)}
                      </Link>
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }} title={f.detail || ''}>
                      {f.detail || '—'}
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }} title={f.remediation || ''}>
                      {f.remediation || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </div>
      )}
    </div>
  );
}
