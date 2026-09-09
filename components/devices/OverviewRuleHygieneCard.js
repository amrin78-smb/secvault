import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import StatCard from '../ui/StatCard';
import NotMeasured from '../ui/NotMeasured';
import RuleHygieneDonut from '../analysis/RuleHygieneDonut';

// Overview-tab card for the per-device page (app/(dashboard)/devices/[id]/page.js), which
// imports and renders this component on its Overview tab.
// Standalone async server component, same "queries its own DB directly" convention as
// components/dashboard/ConfigChangesWidget.js.
//
// The 6 donut categories below are 5 of the 10 real rule_analysis_results.finding_type
// values (unused/shadow/redundant/any_any/log_disabled -- see lib/engines/ruleAnalysis.js,
// confirmed directly against that file) plus a 6th "Other Issues" bucket summing the
// remaining finding types (correlation/risky_service/reorder_candidate/expiring_soon/
// overly_permissive/generalization) -- kept as one bucket rather than many slices so the
// donut/legend stays readable, mirroring CLAUDE.md's own "Cleanup/Optimization/Reorder" tab
// split philosophy of grouping finding types by what an operator actually acts on.
// generalization (an earlier, narrower rule made pointless by a later, broader same-action
// rule) is the same ruleset-simplification class as correlation -- belongs in this bucket
// alongside it, not one of the 5 headline categories. external_exposure (an explicitly
// classified External zone reaching an explicitly classified Internal one -- see
// lib/engines/zoneClassification.js) is a security-exposure finding, same class as
// risky_service/overly_permissive already in this bucket, not one of the 5 headline
// categories either.
const OTHER_FINDING_TYPES = [
  'correlation',
  'risky_service',
  'reorder_candidate',
  'expiring_soon',
  'overly_permissive',
  'generalization',
  'external_exposure',
];

const CATEGORY_DEFS = [
  { key: 'unused', label: 'Unused Rules', color: 'var(--red)' },
  { key: 'shadow', label: 'Shadow Rules', color: 'var(--orange)' },
  { key: 'redundant', label: 'Redundant Rules', color: 'var(--yellow)' },
  { key: 'any_any', label: 'Any-to-Any Rules', color: 'var(--purple)' },
  { key: 'log_disabled', label: 'Logging Disabled', color: 'var(--blue)' },
  { key: 'other', label: 'Other Issues', color: 'var(--teal)' },
];

async function getFindingTypeCounts(dbPool, deviceId) {
  const { rows } = await dbPool.query(
    `SELECT finding_type, COUNT(*)::int AS count
     FROM rule_analysis_results
     WHERE device_id = $1
     GROUP BY finding_type`,
    [deviceId]
  );
  return rows;
}

async function getRuleStats(dbPool, deviceId) {
  const { rows } = await dbPool.query(
    `SELECT
       COUNT(*)::int AS total,
       COUNT(*) FILTER (WHERE enabled)::int AS active,
       COUNT(*) FILTER (WHERE NOT enabled)::int AS disabled,
       COUNT(*) FILTER (WHERE expiry_date IS NOT NULL AND expiry_date < now())::int AS expired
     FROM firewall_rules
     WHERE device_id = $1`,
    [deviceId]
  );
  return rows[0] || { total: 0, active: 0, disabled: 0, expired: 0 };
}

export default async function OverviewRuleHygieneCard({ deviceId }) {
  const [findingRows, ruleStats] = await Promise.all([
    getFindingTypeCounts(pool, deviceId),
    getRuleStats(pool, deviceId),
  ]);

  // Loop over the FIXED category list (not findingRows directly) so a finding_type with
  // zero rows still appears in the legend at count 0, rather than being silently omitted
  // -- per this component's own spec, a missing row means "zero", not "unknown".
  const countByType = {};
  for (const r of findingRows) {
    countByType[r.finding_type] = Number(r.count) || 0;
  }

  const otherCount = OTHER_FINDING_TYPES.reduce((sum, t) => sum + (countByType[t] || 0), 0);

  const categories = CATEGORY_DEFS.map((def) => ({
    ...def,
    count: def.key === 'other' ? otherCount : countByType[def.key] || 0,
  }));

  const totalFindings = categories.reduce((sum, c) => sum + c.count, 0);

  // ⛔ NO RULESET COLLECTED IS NOT A CLEAN RULESET. rule_analysis_results is
  // written by ruleAnalysis.js from inside collectAndStore, over the rules it
  // just stored — so a device with zero firewall_rules necessarily has zero
  // findings, and the four tiles plus an empty donut rendered that as a
  // spotless firewall. A firewall with genuinely no rules does not exist in
  // practice; zero here means the pull has not succeeded (getRules() THROWS on
  // a retrieval failure precisely so a failure is never stored as an empty
  // ruleset, and nothing is stored at all in that case).
  //
  // ⛔ SecVault cannot currently prove which of the two it is: devices
  // .last_collected_at is stamped when ANY capability succeeded (version alone
  // counts), so it does not attest to a successful RULE pull. Per the tri-state
  // rule the uncertain bound is widened, not narrowed — this reports "not
  // measured" rather than claiming a measured zero. The clean fix is a
  // persisted per-device rule-pull outcome (collectAndStore already computes
  // `rulesCount`, null on failure, and simply does not store it).
  const rulesCollected = ruleStats.total > 0;
  const noRulesReason =
    'No ruleset has been collected from this device, so no hygiene finding can exist for it. An empty ruleset and a rule pull that has never succeeded look identical here — this is not a clean firewall.';

  return (
    <Card>
      <CardBody>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 16 }}>
          <span style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)' }}>
            Rule Hygiene Summary
          </span>
          <Link
            href={`/devices/${deviceId}/analysis`}
            style={{ fontSize: 'var(--text-base)', color: 'var(--primary)', textDecoration: 'underline', whiteSpace: 'nowrap' }}
          >
            View full analysis →
          </Link>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))',
            gap: 12,
            marginBottom: 20,
          }}
        >
          <StatCard
            label="Total Rules"
            value={rulesCollected ? ruleStats.total : <NotMeasured reason={noRulesReason} />}
            color={rulesCollected ? 'var(--text-muted)' : 'var(--unmeasured)'}
          />
          <StatCard
            label="Active"
            value={rulesCollected ? ruleStats.active : <NotMeasured reason={noRulesReason} />}
            color={rulesCollected ? 'var(--green)' : 'var(--unmeasured)'}
          />
          <StatCard
            label="Disabled"
            value={rulesCollected ? ruleStats.disabled : <NotMeasured reason={noRulesReason} />}
            color={rulesCollected ? 'var(--text-muted)' : 'var(--unmeasured)'}
          />
          <StatCard
            label="Expired"
            value={rulesCollected ? ruleStats.expired : <NotMeasured reason={noRulesReason} />}
            color={
              !rulesCollected ? 'var(--unmeasured)' : ruleStats.expired > 0 ? 'var(--red)' : 'var(--text-muted)'
            }
          />
        </div>

        {rulesCollected ? (
          <RuleHygieneDonut categories={categories} total={totalFindings} />
        ) : (
          // A donut drawn over six zeros is a picture of a perfect ruleset.
          // Say instead which question could not be answered, and why.
          <div
            style={{
              border: '1px dashed var(--border)',
              borderRadius: 'var(--radius)',
              padding: 'var(--s5) var(--s4)',
              fontSize: 'var(--text-base)',
              color: 'var(--text-muted)',
            }}
          >
            {noRulesReason} Run Collect Now on the Manage tab, then re-check this card.
          </div>
        )}
      </CardBody>
    </Card>
  );
}
