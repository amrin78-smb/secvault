import Link from 'next/link';
import { pool } from '../../../../lib/db';
import PageHeader from '../../../../components/ui/PageHeader';
import AnswerHeader from '../../../../components/ui/AnswerHeader';
import KpiRow from '../../../../components/ui/KpiRow';
import StatCard from '../../../../components/ui/StatCard';
import EmptyState from '../../../../components/ui/EmptyState';
import ComplianceTabs from '../../../../components/compliance/ComplianceTabs';
import FleetExceptionsTable from '../../../../components/compliance/FleetExceptionsTable';
import {
  listFleetExceptions,
  countFleetFailingChecks,
  describeExceptions,
  summariseExceptions,
  EXPIRING_WINDOW_DAYS,
} from '../../../../lib/engines/complianceExceptions';
import { buildExceptionsAnswer } from '../../../../lib/answers';

export const dynamic = 'force-dynamic';

// /compliance/exceptions — every recorded acceptance of risk, fleet-wide.
//
// ⛔ WHY THIS ROUTE EXISTS. `compliance_exceptions` has been complete since
// v2.163.0 — four states, a mandatory expiry evaluated at read time, an owner,
// a compensating control — and an exception was visible ONLY if you opened the
// device it sits on. So "two acceptances have lapsed somewhere on the fleet"
// was a real, dated, actionable fact that nobody could see without opening
// sixteen pages. The judgement is entirely `complianceExceptions.js`'s and is
// reused UNCHANGED; this page is the fleet-wide read of it.
//
// ⛔ NO PERCENTAGE, AND NO SECOND SCORE. The headline compliance figure is
// computed as if no exception existed, and this page states COUNTS beside it —
// the rule the engine's own header sets out, because a rival percentage
// differing from the headline by a set of typed labels is how a compliance
// score becomes a number people manage instead of a fact they act on.
//
// ⛔ THERE IS NO "CREATE EXCEPTION" BUTTON HERE, AND THAT IS A REFUSAL RATHER
// THAN AN OMISSION. An exception may only be recorded against a check that is
// ACTUALLY FAILING on a specific device — otherwise somebody could pre-accept
// a future failure — so the form belongs where that list exists, on the
// device's own assessment. A fleet-wide button would have to ask for a
// firewall first and would then be the device page with extra steps.

export default async function ComplianceExceptionsPage() {
  // ⛔ NO try/catch. An unreadable exceptions table must reach the error
  // boundary, never render as an empty register — "nobody has accepted any
  // risk" and "we could not read the record" are opposite statements and the
  // first one reads as tidy.
  const rows = await listFleetExceptions(pool);
  const failingChecks = await countFleetFailingChecks(pool);
  const { rows: deviceRows } = await pool.query(
    'SELECT id, name FROM devices WHERE active = true'
  );
  const deviceNames = {};
  for (const d of deviceRows) deviceNames[d.id] = d.name;

  const described = describeExceptions(rows);
  const summary = summariseExceptions(described, failingChecks);
  const answer = buildExceptionsAnswer(summary);

  const live = summary.accepted + summary.expiring;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <PageHeader
        eyebrow={<Link href="/compliance">Compliance</Link>}
        title="Exceptions"
        subtitle="Failing checks an operator has formally accepted, with the compensating control, the owner and the expiry. An exception never changes a finding's status and never moves the compliance score."
      />

      <ComplianceTabs active="exceptions" />

      <AnswerHeader answer={answer} />

      <KpiRow cols={4}>
        <StatCard
          label="Live acceptances"
          value={live}
          color={live > 0 ? 'var(--sev-med)' : 'var(--sev-ok)'}
          sub={`covering ${summary.covering} currently failing ${summary.covering === 1 ? 'check' : 'checks'}`}
        />
        <StatCard
          label={`Expiring within ${EXPIRING_WINDOW_DAYS} days`}
          value={summary.expiring}
          color={summary.expiring > 0 ? 'var(--sev-high)' : 'var(--sev-ok)'}
          sub="renew or withdraw before the next monthly report"
        />
        {/* ⛔ A LAPSE IS DANGER, NOT GREY. A failing check with nothing standing
            over it any more is a positive, actionable fact — the engine's own
            rule for this state. */}
        <StatCard
          label="Lapsed"
          value={summary.expired}
          color={summary.expired > 0 ? 'var(--sev-crit)' : 'var(--sev-ok)'}
          sub="no longer cover anything, and the check is still failing"
        />
        {/* ⛔ null, NEVER 0, when the failing count could not be read — the
            engine returns null for exactly that case and "0 failures are
            unaccepted" would be a claim nobody measured. */}
        <StatCard
          label="Failing, not accepted"
          value={summary.unaccepted === null ? '—' : summary.unaccepted}
          color={summary.unaccepted === null ? 'var(--unmeasured)' : summary.unaccepted > 0 ? 'var(--sev-high)' : 'var(--sev-ok)'}
          sub={
            summary.unaccepted === null
              ? 'the fleet-wide failing count could not be read'
              : `of ${summary.failingChecks} failing (firewall, check) answers`
          }
        />
      </KpiRow>

      {(summary.overCheckNoLongerFailing > 0 || summary.overCheckNotEvaluated > 0) && (
        // ⛔ STALE COVER IS SURFACED, NOT TIDIED AWAY. An exception over a check
        // that has started passing is covering nothing; one over a check nobody
        // evaluates here is not evidence of anything. Both still occupy the
        // register and both read as live risk management until somebody says
        // otherwise.
        <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
          {summary.overCheckNoLongerFailing > 0 && (
            <>
              <strong>{summary.overCheckNoLongerFailing}</strong>{' '}
              {summary.overCheckNoLongerFailing === 1 ? 'acceptance covers' : 'acceptances cover'} a check that is
              no longer failing — it can be withdrawn.{' '}
            </>
          )}
          {summary.overCheckNotEvaluated > 0 && (
            <>
              <strong>{summary.overCheckNotEvaluated}</strong>{' '}
              {summary.overCheckNotEvaluated === 1 ? 'sits' : 'sit'} over a check that is not being evaluated on
              that firewall at all, so {summary.overCheckNotEvaluated === 1 ? 'it covers' : 'they cover'} nothing
              measurable.
            </>
          )}
        </p>
      )}

      {described.length === 0 ? (
        // ⛔ WORDED SO AN EMPTY REGISTER CANNOT READ AS A CLEAN FLEET. Zero
        // exceptions means nobody has accepted anything — a statement about the
        // paperwork, not about the firewalls, and the failing count is put
        // beside it so the two are never confused.
        <EmptyState
          title="No risk has been formally accepted"
          message={
            summary.failingChecks
              ? `No exception is recorded on any active firewall, while ${summary.failingChecks} (firewall, check) answers are currently failing. Record an acceptance from a firewall's own assessment page, where the failing checks it may be recorded against are listed.`
              : 'No exception is recorded on any active firewall. An acceptance is recorded from a firewall’s own assessment page, against a check that is actually failing there.'
          }
        />
      ) : (
        <FleetExceptionsTable exceptions={described} deviceNames={deviceNames} />
      )}

      <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-muted)', maxWidth: '72ch' }}>
        An exception records a decision, not a measurement: the check is still failing and the
        firewall is still configured that way, so the compliance score on{' '}
        <Link href="/compliance?view=table">Compare firewalls</Link> is computed as though none of
        these existed. Expiry is evaluated every time this page is read, so a lapsed acceptance
        stops counting the moment it lapses — there is no job to wait for.
      </p>
    </div>
  );
}
