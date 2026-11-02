import Link from 'next/link';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../../api/auth/[...nextauth]/route';
import { can, OPERATE } from '../../../../../lib/rbac';
import { pool } from '../../../../../lib/db';
import Table from '../../../../../components/ui/Table';
import Badge from '../../../../../components/ui/Badge';
import EmptyState from '../../../../../components/ui/EmptyState';
import StatCard from '../../../../../components/ui/StatCard';
import DeviceContextHeader from '../../../../../components/devices/DeviceContextHeader';
import TabRows from '../../../../../components/ui/TabRows';
import { loadDeviceContext } from '../../../../../lib/deviceContext';
import { visibleDeviceNav } from '../../../../../lib/deviceNav';
import { resolveAnalysisTab, analysisTabRows } from '../../../../../lib/analysisTabs';
import PageHeader from '../../../../../components/ui/PageHeader';
import Card, { CardBody } from '../../../../../components/ui/Card';
import SeverityBadge from '../../../../../components/analysis/SeverityBadge';
import FindingTypeBadge, { TYPE_LABELS } from '../../../../../components/analysis/FindingTypeBadge';
import RunAnalysisButton from '../../../../../components/analysis/RunAnalysisButton';
import FindingsBarChart from '../../../../../components/analysis/FindingsBarChart';
import RuleStatsBarChart from '../../../../../components/analysis/RuleStatsBarChart';
import CleanupTab from '../../../../../components/analysis/CleanupTab';
import OptimizationTab from '../../../../../components/analysis/OptimizationTab';
import ReorderTab from '../../../../../components/analysis/ReorderTab';
import ConsolidationTab from '../../../../../components/analysis/ConsolidationTab';
import RiskTab from '../../../../../components/analysis/RiskTab';
import RiskyRulesTab from '../../../../../components/analysis/RiskyRulesTab';
import ObjectsTab from '../../../../../components/analysis/ObjectsTab';
import TrackingTab from '../../../../../components/analysis/TrackingTab';
import ReachabilityTab from '../../../../../components/analysis/ReachabilityTab';
import AccessPathTab from '../../../../../components/analysis/AccessPathTab';
import RuleRelationshipTab from '../../../../../components/analysis/RuleRelationshipTab';
import { computeRiskScoreFromCounts } from '../../../../../lib/engines/riskScore';
import {
  BAND_BADGE_COLOR,
  BAND_LABEL,
  SEVERITY_FILL,
} from '../../../../../components/analysis/severityRamp';

export const dynamic = 'force-dynamic';

// The 12 finding types in the fixed severity order CLAUDE.md documents for
// the rule analysis engine, used both for the findings-tab filter dropdown
// and for the summary-tab bar chart (so the bar order never depends on
// whatever happens to be present in a given device's results). 'correlation'
// (medium — mergeable rules, added alongside the Risky Rules view) sits
// next to 'redundant'/'overly_permissive', the other ruleset-simplification
// (not security-exposure) finding types. 'generalization' (added in the
// "Path A" rule-analysis intelligence round) is the mirror direction of
// shadow/redundant — an earlier, narrower same-action rule made pointless
// by a later, broader one — and sits in that same ruleset-simplification
// group, not the security-exposure group. 'external_exposure' (added
// alongside operator-supplied Zone Classification — Settings > Zones) is a
// security-exposure finding, same class as risky_service/any_any/
// overly_permissive, not ruleset-simplification.
const FINDING_TYPES = [
  'any_any',
  'risky_service',
  'external_exposure',
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

// ⛔ Band colours and labels come from components/analysis/severityRamp.js
// and are NOT redeclared here. The private copy this file used to hold still
// described the PRE-v2.87.0 ramp in its own comment ("high->warning,
// medium->info") and rendered it: `medium` as BLUE, one step from --primary
// teal, which the palette rewrite forbade on any severity. The tiles below sit
// directly above <FindingsBarChart>, which was already colouring the same
// values orange and yellow — the chart and the tiles above it disagreed about
// what "High" looks like, on one screen.

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

export default async function DeviceAnalysisPage({ params, searchParams }) {
  // Defense in depth only -- POST devices/[id]/analysis (Run Analysis) is
  // already server-side admin-only (lib/rbac.js). Hiding the button here
  // just avoids a viewer clicking it and getting a 403.
  const session = await getServerSession(authOptions);
  // ⛔ OPERATE, not isAdmin(). The button this gates calls a route that now
  // accepts the Operator role, and a UI gate STRICTER than its API is its own
  // kind of bug: the action is permitted, the control is invisible, and the
  // operator concludes the product is broken rather than that they lack access.
  const canWrite = can(session, OPERATE);

  const device = await getDevice(pool, params.id);

  if (!device) {
    return (
      <div>
        <Link href="/devices" style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
          ← Back to firewalls
        </Link>
        <p style={{ marginTop: 16, color: 'var(--text-secondary)' }}>Device not found.</p>
      </div>
    );
  }

  // ⛔ THE FOURTEEN-ELEMENT LITERAL THAT USED TO LIVE HERE IS GONE. It was a
  // second copy of the tab list, maintained beside the fourteen <Link>s below,
  // so adding a view meant editing two places and forgetting the second fell
  // through to `summary` silently. lib/analysisTabs.js is the one source and
  // the rows are derived from it.
  const tab = resolveAnalysisTab(searchParams?.tab);
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

  const tabRows = analysisTabRows(device.id, tab);

  // ⛔ THE SHARED PER-DEVICE HEADER. This page used to open with a "← Back to
  // <name>" link, a second "← Back to firewalls" link on its not-found path,
  // and a PageHeader titled "Rule hygiene — <name>" — three different ways of
  // saying which firewall, and no way to reach any of its other pages.
  const deviceContext = await loadDeviceContext(pool, device.id);
  const deviceNav = visibleDeviceNav({
    deviceId: device.id,
    pathname: `/devices/${device.id}/analysis`,
    // ⛔ `canWrite` here is OPERATE (run an analysis), NOT manage_devices
    // (change the device). The Manage tab needs the latter, so it is hidden
    // rather than offered on the strength of a different capability — a UI
    // looser than the route behind it is the one direction this product
    // refuses.
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <DeviceContextHeader
        context={deviceContext}
        nav={deviceNav}
        fallback={device}
      />

      <PageHeader
        title="Rule hygiene"
        actions={
          <>
            <Badge color={BAND_BADGE_COLOR[riskScore.band] || 'muted'}>
              Risk: {BAND_LABEL[riskScore.band] || riskScore.band} ({riskScore.score})
            </Badge>
            <a href={`/api/devices/${device.id}/analysis?format=csv`} className="btn btn-secondary">
              Export CSV
            </a>
            {canWrite && <RunAnalysisButton deviceId={device.id} />}
          </>
        }
      />

      {/* ⛔ FOUR TASKS OVER FOURTEEN VIEWS. Every one of the fourteen is still
          here and every `?tab=` value still resolves — the group is DERIVED
          from the leaf rather than stored in the URL, so no bookmark, ticket
          link or internal href needed rewriting. See lib/analysisTabs.js.

          ⛔ THE TWO COUNTS THE OLD ROW CARRIED ("Security Rules 706",
          "Findings 31") MOVED RATHER THAN DISAPPEARING: a count on a tab is
          only readable while the tab is visible, and under a disclosure it
          would vanish for anyone not already in that group. They are stated on
          the leaf labels' own views and in the device context strip above,
          which is on screen on every one of these pages. */}
      <TabRows groups={tabRows.groups} leaves={tabRows.leaves} ariaLabel="Rule hygiene" />

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
            {/* ⛔ NO HUE ON ANY OF THESE THREE (v2.213.x), and the v2.202.0
                decoration sweep skipped this page INCLUDING ITS OWN CITED
                EXAMPLE — v2.200.0's commit message named the problem as "red
                permanently on 'Denied Rules'". The 4px border was removed; the
                hue was not, and since `color` now routes to the headline NUMBER
                through StatCard's TEXT_SAFE_VALUE map, the red moved somewhere
                MORE prominent than the edge it was taken off.

                ⛔ ALL THREE ENCODE NO RISK, and two of them encode it
                BACKWARDS. A deny rule is the GOOD direction on a firewall, so
                permanent red on "Denied Rules" taught the operator to read this
                product's most urgent signal as decoration — the exact dilution
                "Colour means RISK" exists to prevent. "Allowed Rules" wore
                --green with the inverse semantics beside it. "NAT Enabled" is a
                plain count wearing --blue, a status token v2.87.0 pulled out of
                the severity vocabulary precisely because it sits one step from
                the brand teal. Omitting `color` falls to StatCard's
                var(--border) sentinel, which renders the number as
                --text-primary. The genuine risk tile on this row ("Allowed
                Any-to-Any") keeps its red AND is already gated on the count
                being non-zero, which is the pattern. */}
            <Link href={`/devices/${device.id}/rules?action=allow`} style={{ textDecoration: 'none' }}>
              <StatCard label="Allowed Rules" value={ruleStats.allowed_count} />
            </Link>
            <Link
              href={`/devices/${device.id}/rules?action=deny,drop,reject,block`}
              style={{ textDecoration: 'none' }}
            >
              <StatCard label="Denied Rules" value={ruleStats.denied_count} />
            </Link>
            <Link href={`/devices/${device.id}/rules?enabled=false`} style={{ textDecoration: 'none' }}>
              <StatCard label="Inactive Rules" value={ruleStats.inactive_count} />
            </Link>
            <Link href={`/devices/${device.id}/rules?nat=true`} style={{ textDecoration: 'none' }}>
              <StatCard label="NAT Enabled" value={ruleStats.nat_count || 0} />
            </Link>
            <Link
              href={`/devices/${device.id}/analysis?tab=findings&finding_type=any_any`}
              style={{ textDecoration: 'none' }}
            >
              <StatCard
                label="Allowed Any-to-Any"
                value={findingTypeCounts.any_any}
                color={findingTypeCounts.any_any > 0 ? 'var(--red)' : 'var(--text-muted)'}
              />
            </Link>
            <Link
              href={`/devices/${device.id}/analysis?tab=findings&finding_type=log_disabled`}
              style={{ textDecoration: 'none' }}
            >
              <StatCard label="Logging Disabled" value={findingTypeCounts.log_disabled} color="var(--text-muted)" />
            </Link>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 16 }}>
            <StatCard
              label="Critical"
              value={severitySummary.critical}
              color={severitySummary.critical > 0 ? SEVERITY_FILL.critical : 'var(--text-muted)'}
            />
            <StatCard
              label="High"
              value={severitySummary.high}
              color={severitySummary.high > 0 ? SEVERITY_FILL.high : 'var(--text-muted)'}
            />
            <StatCard
              label="Medium"
              value={severitySummary.medium}
              color={severitySummary.medium > 0 ? SEVERITY_FILL.medium : 'var(--text-muted)'}
            />
            <StatCard
              label="Info"
              value={severitySummary.info}
              color={severitySummary.info > 0 ? SEVERITY_FILL.info : 'var(--text-muted)'}
            />
            <StatCard label="Total Findings" value={severitySummary.total} />
            {/* A datetime string, not a KPI number -- kept at the smaller
                text-base size (as the original text-sm/font-medium styling
                did) rather than StatCard's large stat-value size, which would
                make a long timestamp string look out of place next to the
                numeric tiles around it. */}
            {/* ⛔ The inline borderLeftColor was dropped in v2.200.0 with the
                accent edge itself. It was harmless here (it named --border),
                but it was a THIRD site setting that property outside
                StatCard, and an inline style beats the stylesheet — left in
                place it would have pinned this one tile's left edge while
                the five StatCards beside it went neutral. */}
            <div className="kpi-card">
              <div style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--text-primary)' }}>
                {formatDateTime(severitySummary.last_analyzed_at)}
              </div>
              <div className="stat-label">Last Analyzed</div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: 16 }}>
            <RuleStatsBarChart ruleStats={ruleStats} findingTypeCounts={findingTypeCounts} />
            <FindingsBarChart counts={findingTypeCounts} lastAnalyzedAt={severitySummary.last_analyzed_at} />
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

      {tab === 'cleanup' && (
        <CleanupTab deviceId={device.id} canWrite={canWrite} searchParams={searchParams} />
      )}

      {tab === 'optimization' && (
        <OptimizationTab deviceId={device.id} canWrite={canWrite} searchParams={searchParams} />
      )}

      {/* ⛔ searchParams is REQUIRED by every paginated tab below. Without it
          they read page 1 forever while still rendering a "Page 1 of 8"
          control whose Next link silently does nothing -- a visibly broken
          control is worse than no control. Each tab re-asserts its own
          tab value into the params it hands to Pagination, so a page link
          can never navigate away from the tab it belongs to. */}
      {tab === 'reorder' && <ReorderTab deviceId={device.id} canWrite={canWrite} searchParams={searchParams} />}

      {/* ⛔ No canWrite. This tab has no write path at all — a consolidation
          group is a proposal for a human, never a change SecVault makes — so
          there is no control for a capability to gate. */}
      {tab === 'consolidation' && (
        <ConsolidationTab deviceId={device.id} searchParams={searchParams} />
      )}

      {tab === 'risk' && <RiskTab deviceId={device.id} />}

      {tab === 'risky-rules' && <RiskyRulesTab deviceId={device.id} searchParams={searchParams} />}
      {tab === 'objects' && <ObjectsTab deviceId={device.id} searchParams={searchParams} />}

      {tab === 'tracking' && <TrackingTab deviceId={device.id} />}

      {tab === 'reachability' && <ReachabilityTab deviceId={device.id} />}
      {tab === 'access-path' && <AccessPathTab deviceId={device.id} />}
      {tab === 'relationships' && <RuleRelationshipTab deviceId={device.id} searchParams={searchParams} />}

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
                    {/* ⛔ The same words the badges use. This listed raw slugs
                        (log_disabled) while the table two inches below labelled
                        the very same rows "Logging Off" — two controls
                        disagreeing about the name of one thing, in one
                        viewport. The VALUE stays the slug, so the URL contract
                        is untouched. */}
                    {TYPE_LABELS[t] || t}
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
                      <Link href={`/devices/${device.id}/rules`} className="link-quiet">
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
