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
// ⛔ A null band is NOT "no accent given" — it is "nothing was measurable".
// These two tiles used to fall through to StatCard's var(--border) SENTINEL,
// which that component reads as "the caller passed no colour" and answers by
// rendering the value in ordinary body text. So the em-dash looked exactly
// like any other unstyled number rather than like a gap. --unmeasured says
// the true thing, and colours the accent border and the value together.
const UNMEASURED = 'var(--unmeasured)';

function scoreValue(score) {
  return score === null || score === undefined ? '—' : `${score}`;
}

export default async function HeadlineStats() {
  const [h, prev] = await Promise.all([getFleetHeadline(pool), getPreviousHeadline(pool)]);

  const secBand = securityScoreBand(h.securityScore);
  const compBand = securityScoreBand(h.complianceScore);

  // Shown under the Security Score tile so the number is decomposable at a
  // glance — an opaque composite nobody can explain gets ignored.
  // ⛔ Short forms exist ONLY to fit one line at the tile width. Every component
  // still appears with its own score -- nothing is dropped or merged. If a new
  // component is added and its first word is long, add it here rather than
  // letting the tile wrap and re-inflate all six.
  const SEC_SHORT = { Vulnerability: 'Vuln' };
  const secSub = h.securityComponents
    .map((c) => {
      const word = c.label.split(' ')[0];
      return `${SEC_SHORT[word] || word} ${c.score === null ? '—' : c.score}`;
    })
    .join(' · ');

  // ⛔ SAY WHAT WAS LEFT OUT. The vulnerability component is scored only over
  // devices a CVE assessment has actually run for, because counting a
  // never-assessed device as assessed-and-clean is "never measured" recorded as
  // "nothing found". Dropping them from the denominator is the correct fix, but
  // a fleet number quietly averaged over fewer devices than the fleet the
  // operator can see is its own kind of dishonesty — so the gap is stated.
  const cveGap =
    typeof h.devicesCveAssessed === 'number' && h.devicesCveAssessed < h.deviceCount
      ? h.deviceCount - h.devicesCveAssessed
      : 0;
  const coverageNote = cveGap
    ? `${cveGap} firewall${cveGap === 1 ? '' : 's'} not yet assessed for vulnerabilities and left out of this score`
    : null;

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: 10 }}>
      <StatCard
        compact
        layout="row"
        label="Devices"
        value={h.deviceCount}
        sub={`Online ${h.devicesOnline}`}
        color="var(--accent-teal)"
        icon={IconDevices}
        iconColor="var(--tint-info-fg)"
        iconBg="var(--tint-info)"
        delta={<DeltaBadge current={h.deviceCount} previous={prev?.device_count} goodDirection={GOOD.up} />}
      />
      <StatCard
        compact
        layout="row"
        label="Security Score"
        value={<>{scoreValue(h.securityScore)}<span style={{ fontSize: '0.5em', color: 'var(--text-muted)' }}> / 100</span></>}
        sub={
          h.securityScore === null
            ? 'Not enough data yet'
            // ⛔ "Vuln" rather than "Vulnerability", and · rather than an em-dash,
            // purely so the COMMON case fits one line at this tile width. Measured:
            // the long form wrapped to 2 lines and, because the grid stretches every
            // tile to the tallest, that single wrap set the height of all six.
            // ⛔ Every fact is kept -- no score is dropped and nothing moves to a
            // tooltip. And when coverageNote IS present it is appended and the tile is
            // ALLOWED to wrap: a real caveat about unassessed firewalls outranks a
            // tidy row of equal heights.
            : `${BAND_LABEL[secBand]} · ${secSub}${coverageNote ? ` · ${coverageNote}` : ''}`
        }
        color={BAND_COLOR[secBand] || UNMEASURED}
        icon={IconShield}
        iconColor="var(--tint-success-fg)"
        iconBg="var(--tint-success)"
        delta={<DeltaBadge current={h.securityScore} previous={prev?.security_score} goodDirection={GOOD.up} />}
      />
      <StatCard
        compact
        layout="row"
        label="Critical Alerts"
        value={h.patchNowCount}
        sub="Patch now"
        color="var(--red)"
        icon={IconAlertTriangle}
        iconColor="var(--tint-danger-fg)"
        iconBg="var(--tint-danger)"
        delta={<DeltaBadge current={h.patchNowCount} previous={prev?.patch_now_count} goodDirection={GOOD.down} />}
      />
      <StatCard
        compact
        layout="row"
        label="High Risks"
        value={h.highRiskCount}
        sub="Critical + high findings"
        color="var(--yellow)"
        icon={IconTrendingUp}
        iconColor="var(--tint-warn-fg)"
        iconBg="var(--tint-warn)"
        delta={<DeltaBadge current={h.highRiskCount} previous={prev?.high_risk_count} goodDirection={GOOD.down} />}
      />
      <StatCard
        compact
        layout="row"
        label="Total Rules"
        value={h.rulesTotal.toLocaleString()}
        sub={`${h.rulesEnabled.toLocaleString()} enabled`}
        color="var(--blue)"
        icon={IconActivity}
        iconColor="var(--tint-info-fg)"
        iconBg="var(--tint-info)"
        delta={<DeltaBadge current={h.rulesTotal} previous={prev?.rules_total} goodDirection={GOOD.down} />}
      />
      <StatCard
        compact
        layout="row"
        label="Compliance Score"
        value={<>{scoreValue(h.complianceScore)}<span style={{ fontSize: '0.5em', color: 'var(--text-muted)' }}> / 100</span></>}
        sub={h.complianceScore === null ? 'Nothing measurable yet' : BAND_LABEL[compBand]}
        color={BAND_COLOR[compBand] || UNMEASURED}
        icon={IconChart}
        iconColor="var(--tint-success-fg)"
        iconBg="var(--tint-success)"
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
