import Link from 'next/link';
import { ageLabel, freshnessNote, STATES } from '../../lib/engines/complianceFreshness';

// ⛔ ONE PANEL, TWO PAGES. /compliance (cards view, the DEFAULT) and
// /compliance/[deviceId] both have to say this, and a hand-copied second
// version would drift — this one carries a claim precise enough that a
// drifted copy would be a wrong claim, not just an inconsistent one.
//
// ⛔ THE ACTION IS RE-COLLECTION, NOT RE-RUNNING THE CHECKS.
// runComplianceAuditForDevice() reads getLatestConfigParsed() — the newest
// device_configs row WHATEVER ITS AGE — and stamps detected_at = now(). So a
// "run checks now" press on a firewall that has stopped being collectable puts
// a brand-new timestamp on month-old evidence. Measured live on TSR_EKC: its
// audit had already run 18 days after the last successful collection. This
// panel therefore links to the device page and says so in words.
export default function StaleConfigBanner({ freshness, device }) {
  if (!freshness) return null;
  if (freshness.state !== STATES.STALE && freshness.state !== STATES.AGEING) return null;
  return (
    <div style={{
      padding: '10px 12px',
      borderRadius: 'var(--radius-sm)',
      background: 'var(--tint-warn)',
      color: 'var(--tint-warn-fg)',
      fontSize: 'var(--text-sm)',
      lineHeight: 1.6,
    }}>
      <strong>These checks describe a configuration collected {ageLabel(freshness)}.</strong>{' '}
      {freshnessNote(freshness, device.name)}
      {freshness.evaluatedAgainstOldConfig && (
        <>
          {' '}The checks themselves were last re-run {ageLabel(freshness.evaluation)}, but against
          that same old configuration — which is why the two dates differ.
        </>
      )}
      {' '}
      <Link href={`/devices/${device.id}`} style={{ color: 'inherit', fontWeight: 600 }}>
        Collect from {device.name}
      </Link>{' '}to refresh the configuration these checks read.
    </div>
  );
}
