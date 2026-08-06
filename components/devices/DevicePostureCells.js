import Badge from '../ui/Badge';

// Presentational cells shared by the Devices table. Server components (no
// interactivity), defined at module top level per CLAUDE.md.

// ⛔ ONE NUMBER, ONE MEANING. The mockup showed a Risk Level column AND a
// Security Score column side by side. They are both roughly 0-100 and they move
// in OPPOSITE directions (risk: higher is worse; security score: higher is
// better), which is a reliable way to get one read as the other. Per the user's
// decision, the security score is the only FIGURE and the risk band is carried
// as its COLOUR plus a text label underneath.
const RISK_COLOR = {
  critical: 'var(--red)',
  high: '#f97316',
  medium: 'var(--yellow)',
  low: 'var(--green)',
};

const RISK_LABEL = {
  critical: 'Critical risk',
  high: 'High risk',
  medium: 'Medium risk',
  low: 'Low risk',
};

export function SecurityScoreCell({ score, riskBand, components }) {
  // Null is "nothing measurable yet", NOT zero — the app-wide rule. A device
  // with no rules collected and no compliance run must not read as 0/100,
  // which would say "measured, and terrible".
  if (score === null || score === undefined) {
    return (
      <span style={{ color: 'var(--text-muted)' }} title="No measurable data yet">
        —
      </span>
    );
  }
  const color = RISK_COLOR[riskBand] || 'var(--text-muted)';
  // Hover shows the decomposition — an opaque composite nobody can explain
  // gets ignored.
  const breakdown = Array.isArray(components)
    ? components.map((c) => `${c.label}: ${c.score === null ? 'not measurable' : c.score}`).join(' · ')
    : undefined;

  return (
    <span style={{ display: 'flex', flexDirection: 'column', gap: 2 }} title={breakdown}>
      <span style={{ display: 'flex', alignItems: 'baseline', gap: 3 }}>
        <span style={{ fontWeight: 700, fontSize: 'var(--text-lg)', color }}>{score}</span>
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>/100</span>
      </span>
      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
        {riskBand ? RISK_LABEL[riskBand] : 'Not analysed'}
      </span>
      {/* Proportional bar, same hue as the figure. */}
      <span style={{ display: 'block', height: 3, background: 'var(--border)', borderRadius: 'var(--radius-pill)' }}>
        <span
          style={{
            display: 'block',
            height: '100%',
            width: `${Math.max(0, Math.min(100, score))}%`,
            background: color,
            borderRadius: 'var(--radius-pill)',
          }}
        />
      </span>
    </span>
  );
}

// Support-contract expiry. ⛔ This is NOT OS end-of-life — SecVault collects no
// vendor EOL dates. It is the licence/support contract state from
// device_licenses, and the three states are kept distinct because they call for
// different actions (renew now / plan a renewal / go and look).
export function SupportCell({ expiredCount, soonestFutureExpiry, unknownCount }) {
  if (expiredCount > 0) {
    return (
      <span style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
        <Badge color="danger">Lapsed</Badge>
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          {expiredCount} licence{expiredCount === 1 ? '' : 's'}
        </span>
      </span>
    );
  }
  if (soonestFutureExpiry) {
    const date = new Date(soonestFutureExpiry);
    const days = Math.round((date.getTime() - Date.now()) / 86400000);
    const soon = days <= 90;
    return (
      <span style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
        <span style={{ color: soon ? 'var(--yellow)' : 'var(--text-primary)' }}>
          {date.toISOString().slice(0, 10)}
        </span>
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          in {days}d
        </span>
      </span>
    );
  }
  if (unknownCount > 0) {
    // An unparsed vendor date is NOT "fine" — treating it as no-expiry is how a
    // contract lapses unnoticed.
    return (
      <span title={`${unknownCount} licence date(s) could not be parsed`}>
        <Badge color="warning">Unknown</Badge>
      </span>
    );
  }
  return <span style={{ color: 'var(--text-muted)' }}>—</span>;
}

// HA state from device_ha_status. A device whose adapter does not report HA at
// all is blank, NOT "standalone" — those are different facts (Fortinet HA is
// simply not collected yet).
export function HaCell({ enabled, mode, localState, peerStatus }) {
  if (enabled === null || enabled === undefined) {
    return <span style={{ color: 'var(--text-muted)' }} title="This vendor does not report HA state to SecVault">—</span>;
  }
  if (!enabled) return <span style={{ color: 'var(--text-muted)' }}>Standalone</span>;
  const peerDown = peerStatus && peerStatus !== 'up';
  return (
    <span style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
      <span style={{ color: peerDown ? 'var(--red)' : 'var(--text-primary)' }}>{mode || 'HA'}</span>
      <span style={{ fontSize: 'var(--text-xs)', color: peerDown ? 'var(--red)' : 'var(--text-muted)' }}>
        {localState || '?'}{peerDown ? ' · peer down' : ''}
      </span>
    </span>
  );
}

export function CveCell({ patchNow, scheduled }) {
  if (patchNow === 0 && scheduled === 0) return <span style={{ color: 'var(--text-muted)' }}>0</span>;
  return (
    <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
      {patchNow > 0 && <Badge color="danger">{patchNow} now</Badge>}
      {scheduled > 0 && <Badge color="warning">{scheduled}</Badge>}
    </span>
  );
}
