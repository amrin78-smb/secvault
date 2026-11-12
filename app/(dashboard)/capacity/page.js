import { getServerSession } from 'next-auth';
import { authOptions } from '../../api/auth/[...nextauth]/route';
import { pool } from '../../../lib/db';
import PageHeader from '../../../components/ui/PageHeader';
import Card, { CardBody } from '../../../components/ui/Card';
import BandwidthTrendBoard from '../../../components/capacity/BandwidthTrendBoard';
import { getCapacityForecasts } from '../../../lib/engines/capacityForecastData';
import {
  loadScopeForSession, isScoped, SCOPE_STATES, refusalMessage,
} from '../../../lib/deviceScope';

export const dynamic = 'force-dynamic';

// Bandwidth trend — how much traffic each firewall carries, and where the
// measured trend reaches.
//
// ⛔ PER FIREWALL, AND THERE IS NO FLEET FIGURE ANYWHERE ON THIS PAGE. Measured
// on the reference fleet, the ten firewalls that can be measured span 1,630
// GB/day down to 0.0024 GB/day — a factor of ~680,000 — so a fleet total is its
// two largest members wearing the estate's name, and it would move with them
// while reading as a property of everything.
//
// ⛔ SIX OF SIXTEEN FIREWALLS HAVE NO TREND, FOR TWO DIFFERENT REASONS, AND THE
// PAGE KEEPS THEM APART. Five Fortinets report no byte count that can be added
// up — FortiOS logs a long-lived session repeatedly with a running total, so
// summing double-counts, and the ingest flag excludes them deliberately
// (lib/schema.sql's `bytes_summable` note measured 55 Gbps implied on TSR_EKM
// from two hours of logs). That is PERMANENT. PAKFood sends no syslog at all,
// which is a COLLECTION GAP and can be closed. A combined "6 unavailable"
// would send an operator to the wrong one of those.
//
// ⛔ NO TABLE, NO CRON JOB, NO SCHEMA CHANGE. The history is already permanent
// in `syslog_rollup_hourly`, and a trend is a function of it plus the current
// clock — a stored projection goes stale and is then read as fact, the rule
// /segmentation, /applications and baseline config drift all follow.

export const metadata = { title: 'Bandwidth trend · SecVault' };

export default async function CapacityPage() {
  const session = await getServerSession(authOptions);

  // ⛔ SCOPE-AWARE. A restricted account measures only the firewalls it was
  // granted — and that is a pure filter here, unlike /conformance, because
  // every trend is computed per firewall from that firewall's own logs. No
  // cohort, no fleet denominator, so nothing a scoped account sees is changed
  // by what it cannot see.
  const scope = await loadScopeForSession(session, pool);

  if (scope.state === SCOPE_STATES.UNKNOWN) {
    return (
      <>
        <PageHeader
          title="Bandwidth trend"
          subtitle="How much traffic each firewall carries, and where the measured trend reaches."
        />
        <Card>
          <CardBody>
            <div style={{
              display: 'flex', flexDirection: 'column', gap: 'var(--s2)',
              padding: 'var(--s5)', textAlign: 'center',
            }}
            >
              <strong style={{ fontSize: 'var(--text-lg)', color: 'var(--text-primary)' }}>
                The bandwidth trend could not be shown
              </strong>
              <span style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>
                {refusalMessage(scope, 'the bandwidth trend')}
              </span>
              <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
                Nothing here has been measured — this is not a statement about the fleet.
              </span>
            </div>
          </CardBody>
        </Card>
      </>
    );
  }

  const data = await getCapacityForecasts(pool, {
    deviceIds: isScoped(scope) ? scope.deviceIds : null,
  });

  return (
    <>
      <PageHeader
        title="Bandwidth trend"
        subtitle={
          isScoped(scope)
            ? 'How much traffic the firewalls you can access carry, and where the measured '
              + 'trend reaches.'
            : 'How much traffic each firewall carries, and where the measured trend reaches.'
        }
      />
      <BandwidthTrendBoard
        devices={data.devices}
        summary={data.summary}
        failures={data.failures}
        horizonDays={data.horizonDays}
        lookbackDays={data.lookbackDays}
        claim={data.summary.claim}
      />
    </>
  );
}
