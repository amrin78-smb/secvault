import Link from 'next/link';
import { pool } from '../../../../lib/db';
import PageHeader from '../../../../components/ui/PageHeader';
import AnswerHeader from '../../../../components/ui/AnswerHeader';
import KpiRow from '../../../../components/ui/KpiRow';
import StatCard from '../../../../components/ui/StatCard';
import EmptyState from '../../../../components/ui/EmptyState';
import ComplianceTabs from '../../../../components/compliance/ComplianceTabs';
import ControlsFilters from '../../../../components/compliance/ControlsFilters';
import ControlsTable from '../../../../components/compliance/ControlsTable';
import { gatherControls } from '../../../../lib/engines/complianceControlsData';
import {
  CONTROL_CLAIM,
  parseControlFilters,
  filterControls,
  controlFilterOptions,
} from '../../../../lib/engines/complianceControls';
import { buildControlsAnswer } from '../../../../lib/answers';

export const dynamic = 'force-dynamic';

// /compliance/controls — the check library across the whole fleet.
//
// ⛔ WHY THIS ROUTE EXISTS. Every other compliance surface in this product is
// DEVICE-FIRST: pick a firewall, read its answers. Nothing could answer the
// question an auditor actually opens with — "which control is failing on the
// most firewalls?" — even though `audit_findings` has always held the data.
// This is the same table read on the other axis.
//
// ⛔ IT IS NOT A SECOND SCORE. There is no percentage anywhere on this page;
// `scorePct` lives on /compliance and there is exactly one of it. What this
// page adds is the CHECK-grain breakdown behind that number, in counts of
// firewalls.
//
// ⛔ THE SUMMARY IS COMPUTED BEFORE THE FILTER, ALWAYS. `gatherControls`
// returns the summary over the full library; the filter only ever narrows what
// the TABLE renders. `?status=failing` matching nothing must never make this
// page's own headline read as an all-clear — /work's rule, and the reason the
// two empty states below are worded apart rather than merely gated apart.

const STANDARD_KEYS = ['PCI_DSS', 'ISO_27001', 'CIS_V8', 'NIST', 'SANS'];

export default async function ComplianceControlsPage({ searchParams }) {
  // ⛔ NO try/catch AROUND THE GATHER. A failed read must reach the error
  // boundary rather than render an empty library, which is indistinguishable
  // on screen from a fleet with nothing failing — this codebase's signature
  // bug, on the page whose job is to list what is failing.
  const { controls, summary, scope, errors } = await gatherControls(pool);

  const { filters, unknown, active } = parseControlFilters(
    {
      status: searchParams?.status,
      standard: searchParams?.standard,
      severity: searchParams?.severity,
      q: searchParams?.q,
    },
    STANDARD_KEYS
  );
  const shown = filterControls(controls, filters);
  const options = controlFilterOptions(controls);
  const answer = buildControlsAnswer(summary);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* ⛔ THE BREADCRUMB USES PageHeader's EXISTING `eyebrow`, not a new
          component. It renders ABOVE the h1, which is where a breadcrumb
          belongs, and it keeps the "exactly one h1 per page" rule intact — a
          breadcrumb built out of headings would break the document outline it
          is meant to clarify. It earns its place on a narrow viewport, where
          the sidebar carrying the same hierarchy is behind a drawer. */}
      <PageHeader
        eyebrow={<Link href="/compliance">Compliance</Link>}
        title="Controls"
        subtitle="Every check in the library, measured across the whole fleet. A control is failing if any firewall fails it — the firewall counts beside each one are the split behind that."
      />

      <ComplianceTabs active="controls" />

      <AnswerHeader answer={answer} />

      {errors.length > 0 && (
        // ⛔ A PARTIAL READ IS BANNERED, NEVER SWALLOWED. A column quietly
        // reporting "0 exceptions" because the table could not be read is the
        // failed-read-as-a-fact rule in a cell.
        <div className="notice-row" style={{ color: 'var(--tint-warn-fg)' }}>
          {errors.join(' · ')}
        </div>
      )}

      <KpiRow cols={4}>
        <StatCard
          label="Controls failing"
          value={summary.failingControls}
          color={summary.failingControls > 0 ? 'var(--sev-crit)' : 'var(--sev-ok)'}
          sub={`of ${summary.total} in the library · ${summary.failingPairs} failing answers in total`}
        />
        <StatCard
          label="Firewalls affected"
          value={summary.firewallsAffected}
          color={summary.firewallsAffected > 0 ? 'var(--sev-high)' : 'var(--sev-ok)'}
          sub={`of ${scope.activeDevices} active`}
        />
        {/* ⛔ THE TWO GAP TILES ARE SEPARATE AND MUST STAY SO. One clears
            itself on the next collection; the other never clears at all, and
            a combined "N unmeasured" would send an operator looking for a fix
            that does not exist. Same call /capacity makes between
            `no_log_coverage` and `bytes_not_summable`. */}
        <StatCard
          label="Never measured"
          value={summary.notMeasured}
          color="var(--unmeasured)"
          sub="apply to firewalls here, and no firewall has answered them yet"
        />
        <StatCard
          label="Not evaluable from config"
          value={summary.notEvaluable}
          color="var(--unmeasured)"
          sub="cannot be answered from a config snapshot at all — excluded from the score, not counted against it"
        />
      </KpiRow>

      {summary.partial > 0 && (
        // ⛔ STATED ON THE PAGE, NOT ONLY IN A ROW. "Passing where measured" is
        // the finding this view exists to surface: a control passing on three
        // of sixteen firewalls is not a green tick, and it is invisible in
        // every other compliance surface in this product.
        <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
          <strong>{summary.partial}</strong>{' '}
          {summary.partial === 1 ? 'control is' : 'controls are'} passing only on the firewalls
          SecVault could ask — they are listed as “Passing where measured”, never as passing.
        </p>
      )}

      <ControlsFilters options={options} counts={summary.byStatus} shown={shown.length} total={controls.length} />

      {unknown.length > 0 && (
        // ⛔ AN UNRECOGNISED FILTER VALUE IS NAMED. It matches nothing by
        // design, and a table that is empty for a reason the operator cannot
        // see reads as a broken page.
        <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--tint-warn-fg)' }}>
          {unknown.map((u) => `“${u.value}” is not a known ${u.key}`).join('; ')} — nothing matches it.
        </p>
      )}

      {controls.length === 0 ? (
        <EmptyState
          title="No checks are seeded"
          message="The compliance check library is empty, so there is nothing to measure. This is a SecVault data gap, not a result about the fleet."
        />
      ) : shown.length === 0 ? (
        // ⛔ WORDED APART FROM THE ABOVE, DELIBERATELY. "No control matches
        // these filters" says nothing about the fleet; an all-clear says
        // everything about it, and a reader must never have to check the
        // filter chips to tell which one they are looking at.
        <EmptyState
          title="No control matches these filters"
          message={`${controls.length} controls are in the library. This says nothing about the fleet — clear the filters to see them.`}
        />
      ) : (
        <ControlsTable controls={shown} />
      )}

      <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-muted)', maxWidth: '72ch' }}>
        {CONTROL_CLAIM}{' '}
        <Link href="/compliance?view=table">Compare firewalls</Link> scores each firewall against
        each framework; this page is the same findings read by check.
        {active.length > 0 && ' The headline figures above are computed over the whole library and do not follow these filters.'}
      </p>
    </div>
  );
}
