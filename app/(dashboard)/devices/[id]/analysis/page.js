import Link from 'next/link';
import { pool } from '../../../../../lib/db';
import Table from '../../../../../components/ui/Table';
import Badge from '../../../../../components/ui/Badge';
import EmptyState from '../../../../../components/ui/EmptyState';
import SeverityBadge from '../../../../../components/analysis/SeverityBadge';
import FindingTypeBadge from '../../../../../components/analysis/FindingTypeBadge';
import RunAnalysisButton from '../../../../../components/analysis/RunAnalysisButton';
import { computeRiskScoreFromCounts } from '../../../../../lib/engines/riskScore';

export const dynamic = 'force-dynamic';

// The 9 finding types in the fixed severity order CLAUDE.md documents for the
// rule analysis engine, used both for the findings-tab filter dropdown and
// for the summary-tab bar chart (so the bar order never depends on whatever
// happens to be present in a given device's results).
const FINDING_TYPES = [
  'any_any',
  'risky_service',
  'shadow',
  'reorder_candidate',
  'redundant',
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
async function getRuleStats(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT
       COUNT(*)::int AS total_rules,
       COUNT(*) FILTER (WHERE action IN ('allow', 'permit', 'accept'))::int AS allowed_count,
       COUNT(*) FILTER (WHERE action IN ('deny', 'drop', 'reject', 'block'))::int AS denied_count,
       COUNT(*) FILTER (WHERE enabled = false)::int AS inactive_count
     FROM firewall_rules
     WHERE device_id = $1`,
    [deviceId]
  );
  return (
    result.rows[0] || { total_rules: 0, allowed_count: 0, denied_count: 0, inactive_count: 0 }
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

// Hand-built bar chart -- no charting library in this repo (see CLAUDE.md).
// Bar height is a CSS % of a fixed-height container, driven by count / max
// count; colored via the same Tailwind utility classes SeverityBadge already
// maps finding severity to, so a critical-severity type's bar is red, etc.
const FINDING_TYPE_SEVERITY = {
  any_any: 'critical',
  risky_service: 'high',
  shadow: 'high',
  reorder_candidate: 'high',
  redundant: 'medium',
  overly_permissive: 'medium',
  unused: 'medium',
  expiring_soon: 'medium',
  log_disabled: 'info',
};

const BAR_COLOR_CLASS = {
  critical: 'bg-danger',
  high: 'bg-warning',
  medium: 'bg-info',
  info: 'bg-text-muted',
};

function FindingTypeBarChart({ counts }) {
  const maxCount = Math.max(1, ...FINDING_TYPES.map((t) => counts[t] || 0));
  return (
    <div className="rounded-lg border border-border bg-bg-surface p-4">
      <div className="mb-3 text-xs uppercase tracking-wide text-text-muted">Findings by Type</div>
      <div className="flex h-40 items-end gap-3">
        {FINDING_TYPES.map((type) => {
          const count = counts[type] || 0;
          const heightPct = count === 0 ? 0 : Math.max(4, Math.round((count / maxCount) * 100));
          const colorClass = BAR_COLOR_CLASS[FINDING_TYPE_SEVERITY[type]] || 'bg-text-muted';
          return (
            <div key={type} className="flex flex-1 flex-col items-center gap-1">
              <div className="flex h-32 w-full items-end justify-center">
                <div
                  className={`w-full max-w-[28px] rounded-t ${colorClass}`}
                  style={{ height: `${heightPct}%` }}
                  title={`${count}`}
                />
              </div>
              <div className="text-xs font-medium text-text-primary">{count}</div>
            </div>
          );
        })}
      </div>
      <div className="mt-2 flex gap-3 text-[10px] text-text-muted">
        {FINDING_TYPES.map((type) => (
          <div key={type} className="flex-1 truncate text-center" title={type}>
            <FindingTypeBadge type={type} />
          </div>
        ))}
      </div>
    </div>
  );
}

function StatCard({ label, value, colorClass = 'text-text-primary' }) {
  return (
    <div className="rounded-lg border border-border bg-bg-surface p-4">
      <div className="text-xs uppercase tracking-wide text-text-muted">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${colorClass}`}>{value}</div>
    </div>
  );
}

export default async function DeviceAnalysisPage({ params, searchParams }) {
  const device = await getDevice(pool, params.id);

  if (!device) {
    return (
      <div>
        <Link href="/devices" className="text-sm text-accent hover:underline">
          ← Back to devices
        </Link>
        <p className="mt-4 text-text-secondary">Device not found.</p>
      </div>
    );
  }

  const tab = ['summary', 'rules', 'findings'].includes(searchParams?.tab)
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

  function tabLink(key, label) {
    return (
      <Link
        href={`/devices/${device.id}/analysis?tab=${key}`}
        className={`px-3 py-2 text-sm ${
          tab === key
            ? 'border-b-2 border-accent text-text-primary'
            : 'text-text-secondary hover:text-text-primary'
        }`}
      >
        {label}
      </Link>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <Link href={`/devices/${device.id}`} className="text-sm text-accent hover:underline">
          ← Back to {device.name}
        </Link>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <h1 className="text-lg font-semibold text-text-primary">Rule Analysis — {device.name}</h1>
          <Badge color={RISK_BAND_COLOR[riskScore.band]}>
            Risk: {RISK_BAND_LABEL[riskScore.band]} ({riskScore.score})
          </Badge>
        </div>
        <RunAnalysisButton deviceId={device.id} />
      </div>

      <div className="flex items-center gap-1 border-b border-border">
        {tabLink('summary', 'Summary')}
        {tabLink('rules', `Security Rules ${ruleStats.total_rules}`)}
        {tabLink('findings', `Findings ${severitySummary.total}`)}
      </div>

      {tab === 'summary' && (
        <>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
            <StatCard label="Total Rules" value={ruleStats.total_rules} />
            <StatCard label="Allowed Rules" value={ruleStats.allowed_count} colorClass="text-success" />
            <StatCard label="Denied Rules" value={ruleStats.denied_count} colorClass="text-danger" />
            <StatCard label="Inactive Rules" value={ruleStats.inactive_count} />
            <StatCard
              label="Allowed Any-to-Any"
              value={findingTypeCounts.any_any}
              colorClass="text-danger"
            />
            <StatCard
              label="Logging Disabled"
              value={findingTypeCounts.log_disabled}
              colorClass="text-text-muted"
            />
          </div>

          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
            <StatCard label="Critical" value={severitySummary.critical} colorClass="text-danger" />
            <StatCard label="High" value={severitySummary.high} colorClass="text-warning" />
            <StatCard label="Medium" value={severitySummary.medium} colorClass="text-info" />
            <StatCard label="Info" value={severitySummary.info} colorClass="text-text-muted" />
            <StatCard label="Total Findings" value={severitySummary.total} />
            <StatCard
              label="Last Analyzed"
              value={formatDateTime(severitySummary.last_analyzed_at)}
              colorClass="text-sm font-medium text-text-primary"
            />
          </div>

          <FindingTypeBarChart counts={findingTypeCounts} />
        </>
      )}

      {tab === 'rules' && (
        <div className="rounded border border-border bg-bg-surface p-4">
          <p className="text-sm text-text-secondary">
            {ruleStats.total_rules} rule{ruleStats.total_rules === 1 ? '' : 's'} collected —{' '}
            {ruleStats.allowed_count} allowed, {ruleStats.denied_count} denied,{' '}
            {ruleStats.inactive_count} inactive.
          </p>
          <Link
            href={`/devices/${device.id}/rules`}
            className="mt-2 inline-block text-sm text-accent hover:underline"
          >
            View full rule list →
          </Link>
        </div>
      )}

      {tab === 'findings' && (
        <div className="space-y-3">
          <form method="GET" className="flex flex-wrap items-end gap-3">
            <input type="hidden" name="tab" value="findings" />
            <div className="flex flex-col gap-1">
              <label htmlFor="severity" className="text-xs text-text-secondary">
                Severity
              </label>
              <select
                id="severity"
                name="severity"
                defaultValue={severityFilter}
                className="rounded border border-border bg-bg-base px-2 py-1 text-sm text-text-primary"
              >
                <option value="">All severities</option>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s[0].toUpperCase() + s.slice(1)}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex flex-col gap-1">
              <label htmlFor="finding_type" className="text-xs text-text-secondary">
                Finding Type
              </label>
              <select
                id="finding_type"
                name="finding_type"
                defaultValue={findingTypeFilter}
                className="rounded border border-border bg-bg-base px-2 py-1 text-sm text-text-primary"
              >
                <option value="">All types</option>
                {FINDING_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>
            <button
              type="submit"
              className="rounded border border-border bg-bg-surface px-3 py-1.5 text-sm text-text-primary hover:bg-bg-elevated"
            >
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
                <tr className="border-b border-border bg-bg-surface text-left text-text-secondary">
                  <th className="px-2 py-2">Severity</th>
                  <th className="px-2 py-2">Type</th>
                  <th className="px-2 py-2">Rule</th>
                  <th className="px-2 py-2">Detail</th>
                  <th className="px-2 py-2">Remediation</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id} className="border-b border-border">
                    <td className="px-2 py-2">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="px-2 py-2">
                      <FindingTypeBadge type={f.finding_type} />
                    </td>
                    <td className="truncate px-2 py-2" title={ruleLabel(f)}>
                      <Link href={`/devices/${device.id}/rules`} className="text-accent hover:underline">
                        {ruleLabel(f)}
                      </Link>
                    </td>
                    <td className="px-2 py-2 text-text-secondary" title={f.detail || ''}>
                      {f.detail || '—'}
                    </td>
                    <td className="px-2 py-2 text-text-secondary" title={f.remediation || ''}>
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
