import { getServerSession } from 'next-auth';
import { authOptions } from '../../api/auth/[...nextauth]/route';
import { pool } from '../../../lib/db';
import PageHeader from '../../../components/ui/PageHeader';
import Card, { CardBody } from '../../../components/ui/Card';
import CoverageRegister from '../../../components/devices/CoverageRegister';
import { getCoverageRegister } from '../../../lib/engines/coverageRegisterData';
import {
  loadScopeForSession, isScoped, SCOPE_STATES, refusalMessage,
} from '../../../lib/deviceScope';

export const dynamic = 'force-dynamic';

// Coverage — the blind-spot register.
//
// ⛔ WHAT THIS PAGE IS FOR. A firewall nothing can be collected from
// contributes no CVEs, no failing checks and no rule findings — so it renders
// as the HEALTHIEST DEVICE ON THE FLEET on every other page in this product.
// This is the one page whose subject is that inversion.
//
// ⛔ IT IS NOT A SECURITY VERDICT, AND MUST NEVER BE READ AS ONE. "Fully
// visible" means SecVault can see this firewall, and says nothing whatever
// about whether it is configured safely. The word is deliberately about
// VISIBILITY; `CoverageRegister.js` carries a test that rejects any all-clear
// vocabulary reaching the screen.
//
// ⛔ ON THE REFERENCE FLEET EVERY ONE OF THE 16 FIREWALLS HAS AT LEAST ONE
// GAP, which is exactly why the engine ranks by CONSEQUENCE — how many answers
// a gap withholds — rather than by gap count. A page listing devices-with-gaps
// would be a list of the fleet.

export const metadata = { title: 'Coverage · SecVault' };

export default async function CoveragePage() {
  const session = await getServerSession(authOptions);

  // ⛔ SCOPE-AWARE (see lib/deviceScopeCoverage.js). A restricted account sees
  // the coverage of the firewalls it was granted and no others — and because
  // this page's whole subject is what is MISSING, a fleet-wide register shown
  // to a scoped account would disclose both the existence and the collection
  // health of every firewall outside that scope.
  const scope = await loadScopeForSession(session, pool);

  // ⛔ AN UNKNOWN SCOPE DENIES, and says so rather than rendering an empty
  // register. On THIS page an empty result reads as "no blind spots" — the
  // most misleading thing this product could print — so the refusal has to be
  // explicit and must not be confused with a clean fleet.
  if (scope.state === SCOPE_STATES.UNKNOWN) {
    return (
      <>
        <PageHeader
          title="Coverage"
          subtitle="Where SecVault cannot see, and what that costs."
        />
        <Card>
          <CardBody>
            <div style={{
              display: 'flex', flexDirection: 'column', gap: 'var(--s2)',
              padding: 'var(--s5)', textAlign: 'center',
            }}
            >
              <strong style={{ fontSize: 'var(--text-lg)', color: 'var(--text-primary)' }}>
                Coverage could not be shown
              </strong>
              <span style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>
                {refusalMessage(scope, 'coverage')}
              </span>
              <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
                This is not a statement about the fleet — nothing here has been measured.
              </span>
            </div>
          </CardBody>
        </Card>
      </>
    );
  }

  // ⛔ NARROWED IN SQL, not after the fact. `getCoverageRegister` takes
  // `deviceIds` and parameterises them as `$1::uuid[]`; filtering the returned
  // entries instead would leave the fleet summary computed over devices the
  // operator cannot see.
  const register = await getCoverageRegister(pool, {
    deviceIds: isScoped(scope) ? scope.deviceIds : null,
  });

  return (
    <>
      <PageHeader
        title="Coverage"
        subtitle={
          isScoped(scope)
            ? 'Where SecVault cannot see across the firewalls you can access, and what that costs.'
            : 'Where SecVault cannot see across the fleet, and what that costs.'
        }
      />
      <CoverageRegister
        entries={register.entries}
        summary={register.summary}
        failures={register.failures}
        generatedAt={register.generatedAt}
      />
    </>
  );
}
