import { getServerSession } from 'next-auth';
import { authOptions } from '../../api/auth/[...nextauth]/route';
import { pool } from '../../../lib/db';
import PageHeader from '../../../components/ui/PageHeader';
import Card, { CardBody } from '../../../components/ui/Card';
import ConformanceBoard from '../../../components/analysis/ConformanceBoard';
import { getFleetConformance } from '../../../lib/engines/fleetConformanceData';
import {
  loadScopeForSession, isScoped, SCOPE_STATES, refusalMessage,
} from '../../../lib/deviceScope';

export const dynamic = 'force-dynamic';

// Conformance — which firewall is configured unlike its peers.
//
// ⛔ THE ONLY ANALYTIC IN THIS PRODUCT THAT DISCOVERS CHECKS RATHER THAN
// EVALUATING CURATED ONES. The 45-check compliance library is hand-written and
// finite; this finds deviations nobody thought to encode.
//
// ⛔ MAJORITY IS NOT CORRECTNESS, AND THAT RULE IS ABSOLUTE. This page says
// "1 of 5 differs" and never "misconfigured". The live fleet contains the proof:
// `global.admin-ssh-port` is 4x `22` against OKF(F2)'s `5022` — OKF is the only
// firewall NOT on the default SSH port, which is HARDENING, and the majority is
// the weaker configuration. `fleetConformance.js` exports CONFORMANCE_CLAIM for
// exactly this reason and a test rejects the verdict vocabulary from every
// string either file can emit.
//
// ⛔ THE COHORT IS (vendor, mgmt_method), NOT VENDOR. TUG is the only Palo Alto
// collected over SSH and its parser emits a different structure entirely, so
// grouped by vendor it would deviate on nearly every path and every one of
// those findings would be false. It is a cohort of one and correctly yields
// nothing.

export const metadata = { title: 'Conformance · SecVault' };

export default async function ConformancePage() {
  const session = await getServerSession(authOptions);

  // ⛔ SCOPE-AWARE (see lib/deviceScopeCoverage.js). A restricted account
  // compares only the firewalls it was granted — and that is not merely a
  // filter, it changes the COHORTS. An account granted 2 of the 5 Fortinets
  // gets a cohort of 2, which the engine reports as `insufficient_cohort` and
  // refuses to draw a majority from. That is the correct answer, not a
  // degraded one: you cannot say which firewall is the odd one out of a group
  // you cannot see.
  const scope = await loadScopeForSession(session, pool);

  if (scope.state === SCOPE_STATES.UNKNOWN) {
    return (
      <>
        <PageHeader
          title="Conformance"
          subtitle="Which firewall is configured unlike its peers."
        />
        <Card>
          <CardBody>
            <div style={{
              display: 'flex', flexDirection: 'column', gap: 'var(--s2)',
              padding: 'var(--s5)', textAlign: 'center',
            }}
            >
              <strong style={{ fontSize: 'var(--text-lg)', color: 'var(--text-primary)' }}>
                Conformance could not be shown
              </strong>
              <span style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>
                {refusalMessage(scope, 'conformance')}
              </span>
              <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
                Nothing here has been compared — this is not a statement about the fleet.
              </span>
            </div>
          </CardBody>
        </Card>
      </>
    );
  }

  const data = await getFleetConformance(pool, {
    deviceIds: isScoped(scope) ? scope.deviceIds : null,
  });

  return (
    <>
      <PageHeader
        title="Conformance"
        subtitle={
          isScoped(scope)
            ? 'How the firewalls you can access differ from one another. A difference is not a fault.'
            : 'Which firewall is configured unlike its peers. A difference is not a fault.'
        }
      />
      <ConformanceBoard
        cohorts={data.cohorts}
        summary={data.summary}
        failures={data.failures}
        generatedAt={data.generatedAt}
        claim={data.claim}
      />
    </>
  );
}
