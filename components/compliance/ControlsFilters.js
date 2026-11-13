'use client';

import { useSearchParams } from 'next/navigation';
import FilterBar, { FilterSelect, FilterSearch, useFilterNav } from '../ui/FilterBar';
import { STATE_LABELS } from '../../lib/engines/complianceControls';

// Narrowing controls for /compliance/controls.
//
// ⛔ EVERY OPTION IS DERIVED FROM THE CONTROLS ACTUALLY PRESENT
// (`controlFilterOptions`), never hardcoded — an option that can only ever
// return nothing is indistinguishable from a filter that is broken, and the
// seed library has changed size three times.
//
// ⛔ THE SUMMARY ABOVE THIS BAR IS NOT FILTERED, AND THAT IS THE SAFETY
// PROPERTY. `?status=failing` matching nothing must never make the page's own
// headline read "no control is failing" — see summariseControls().
//
// ⛔ NO "ASSIGN", "ACKNOWLEDGE" OR "MARK REMEDIATED" CONTROL HERE, AND THAT IS
// A REFUSAL RATHER THAN AN OMISSION. `audit_findings` is DELETE+reinserted on
// every compliance run and carries no workflow column, no owner and no
// history; a control stops failing when the FIREWALL changes and the next run
// says so. A remediation state backed by nothing would be a control that
// forgets what the operator typed — the same refusal WorkQueueFilters records.

const STANDARD_LABEL = {
  PCI_DSS: 'PCI DSS',
  ISO_27001: 'ISO 27001',
  CIS_V8: 'CIS v8',
  NIST: 'NIST',
  SANS: 'SANS',
};

const titleCase = (s) => s.charAt(0).toUpperCase() + s.slice(1);

export default function ControlsFilters({ options, shown, total }) {
  const nav = useFilterNav('/compliance/controls');
  const params = useSearchParams();
  // Every control is driven by the URL — the page is a server component that
  // re-renders from the query string, so a control holding its own copy would
  // disagree with the table beneath it.
  const cur = (k) => (params ? params.get(k) || '' : '');
  const set = (k, v) => nav.set({ [k]: v });

  const opt = (values, labels) => [
    { value: '', label: 'All' },
    ...values.map((v) => ({ value: v, label: (labels && labels[v]) || titleCase(v) })),
  ];

  const statusOpts = opt(options.statuses, STATE_LABELS);
  const standardOpts = opt(options.standards, STANDARD_LABEL);
  const sevOpts = opt(options.severities);

  const defs = [
    { key: 'q', label: 'Search' },
    { key: 'status', label: 'Status', options: statusOpts },
    { key: 'standard', label: 'Framework', options: standardOpts },
    { key: 'severity', label: 'Severity', options: sevOpts },
  ];

  return (
    <FilterBar
      basePath="/compliance/controls"
      defs={defs}
      count={{ shown, total, noun: 'controls' }}
    >
      <FilterSearch param="q" placeholder="Control id, name or description…" value={cur('q')} onChange={set} idPrefix="cc" />
      <FilterSelect label="Status" param="status" value={cur('status')} options={statusOpts} onChange={set} idPrefix="cc" />
      <FilterSelect label="Framework" param="standard" value={cur('standard')} options={standardOpts} onChange={set} idPrefix="cc" />
      <FilterSelect label="Severity" param="severity" value={cur('severity')} options={sevOpts} onChange={set} idPrefix="cc" />
    </FilterBar>
  );
}
