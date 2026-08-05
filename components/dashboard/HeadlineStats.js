import { pool } from '../../lib/db';
import StatCard from '../ui/StatCard';
import { getFleetHeadline, getPreviousHeadline } from '../../lib/engines/fleetHeadline';
import { securityScoreBand } from '../../lib/engines/securityScore';
import {
  IconDevices,
  IconShield,
  IconAlertTriangle,
  IconTrendingUp,
  IconActivity,
  IconChart,
} from '../icons';

export const dynamic = 'force-dynamic';

// ⛔ Direction of GOOD is per-metric, not universal. A compliance score rising
// is good; a critical-alert count rising is not. The mockup this layout came
// from coloured every arrow the same way, which would have shown "more urgent
// CVEs than yesterday" as a reassuring green tick.
const GOOD = { up: 'up', down: 'down' };

function DeltaBadge({ current, previous, goodDirection }) {
  // ⛔ No prior row, or a prior row from before these columns existed, means
  // the change is UNKNOWN — render nothing. A "0" here would read as
  // "unchanged", which is a different and unearned claim.
  if (previous === null || previous === undefined) return null;
  if (current === null || current === undefined) return null;
  const diff = Number(current) - Number(previous);
  if (!Number.isFinite(diff)) return null;
  if (diff === 0) {
    return <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>No change since yesterday</span>;
  }
  const rising = diff > 0;
  const isGood = (rising && goodDirection === GOOD.up) || (!rising && goodDirection === GOOD.down);
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 4,
        fontSize: 'var(--text-xs)',
        fontWeight: 600,
        color: isGood ? 'var(--green)' : 'var(--red)',
      }}
    >
      {rising ? '↑' : '↓'} {Math.abs(diff)}
      <span style={{ fontWeight: 400, color: 'var(--text-muted)' }}>from yesterday</span>
    </span>
  );
}

const BAND_COLOR = {
  excellent: 'var(--green)',
  good: 'var(--green)',
  fair: 'var(--yellow)',
  poor: 'var(--red)',
};

const BAND_LABEL = {
  excellent: 'Excellent',
  good: 'Good',
  fair: 'Fair',
  poor: 'Needs attention',
};

// A nullable 0-100 score renders as "—", never 0 — the app-wide null-vs-zero
// rule (a score of 0 means "measured, and terrible"; null means "nothing to
// measure yet", and they must not look alike).
function scoreValue(score) {
  return score === null || score === undefined ? '—' : `${score}`;
}

export default async function HeadlineStats() {
  const [h, prev] = await Promise.all([getFleetHeadline(pool), getPreviousHeadline(pool)]);

  const secBand = securityScoreBand(h.securityScore);
  const compBand = securityScoreBand(h.complianceScore);

  // Shown under the Security Score tile so the number is decomposable at a
  // glance — an opaque composite nobody can explain gets ignored.
  const secSub = h.securityComponents
    .map((c) => `${c.label.split(' ')[0]} ${c.score === null ? '—' : c.score}`)
    .join(' · ');

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: 10 }}>
      <StatCard
        compact
        label="Devices"
        value={h.deviceCount}
        sub={`Online ${h.devicesOnline}`}
        color="var(--accent-teal)"
        icon={IconDevices}
        iconColor="#60a5fa"
        iconBg="rgba(96,165,250,0.20)"
        delta={<DeltaBadge current={h.deviceCount} previous={prev?.device_count} goodDirection={GOOD.up} />}
      />
      <StatCard
        compact
        label="Security Score"
        value={<>{scoreValue(h.securityScore)}<span style={{ fontSize: '0.5em', color: 'var(--text-muted)' }}> / 100</span></>}
        sub={h.securityScore === null ? 'Not enough data yet' : `${BAND_LABEL[secBand]} — ${secSub}`}
        color={BAND_COLOR[secBand] || 'var(--border)'}
        icon={IconShield}
        iconColor="#4ade80"
        iconBg="rgba(74,222,128,0.20)"
        delta={<DeltaBadge current={h.securityScore} previous={prev?.security_score} goodDirection={GOOD.up} />}
      />
      <StatCard
        compact
        label="Critical Alerts"
        value={h.patchNowCount}
        sub="Patch now"
        color="var(--red)"
        icon={IconAlertTriangle}
        iconColor="#f87171"
        iconBg="rgba(248,113,113,0.22)"
        delta={<DeltaBadge current={h.patchNowCount} previous={prev?.patch_now_count} goodDirection={GOOD.down} />}
      />
      <StatCard
        compact
        label="High Risks"
        value={h.highRiskCount}
        sub="Critical + high findings"
        color="var(--yellow)"
        icon={IconTrendingUp}
        iconColor="#fbbf24"
        iconBg="rgba(251,191,36,0.20)"
        delta={<DeltaBadge current={h.highRiskCount} previous={prev?.high_risk_count} goodDirection={GOOD.down} />}
      />
      <StatCard
        compact
        label="Total Rules"
        value={h.rulesTotal.toLocaleString()}
        sub={`${h.rulesEnabled.toLocaleString()} enabled`}
        color="var(--blue)"
        icon={IconActivity}
        iconColor="#60a5fa"
        iconBg="rgba(96,165,250,0.20)"
        delta={<DeltaBadge current={h.rulesTotal} previous={prev?.rules_total} goodDirection={GOOD.down} />}
      />
      <StatCard
        compact
        label="Compliance Score"
        value={<>{scoreValue(h.complianceScore)}<span style={{ fontSize: '0.5em', color: 'var(--text-muted)' }}> / 100</span></>}
        sub={h.complianceScore === null ? 'Nothing measurable yet' : BAND_LABEL[compBand]}
        color={BAND_COLOR[compBand] || 'var(--border)'}
        icon={IconChart}
        iconColor="#4ade80"
        iconBg="rgba(74,222,128,0.20)"
        delta={
          <DeltaBadge
            current={h.complianceScore}
            previous={prev?.compliance_overall_score}
            goodDirection={GOOD.up}
          />
        }
      />
    </div>
  );
}
