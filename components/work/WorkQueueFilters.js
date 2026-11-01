'use client';

import { useSearchParams } from 'next/navigation';
import FilterBar, { FilterSelect, FilterSearch, useFilterNav } from '../ui/FilterBar';

// The work queue's triage controls.
//
// ⛔ THE BANDS BECAME A FILTER AS WELL AS A GROUPING, NOT INSTEAD OF ONE.
// "Act now / Scheduled / Needs a human" are still rendered as three sections,
// because the three are a statement about EVIDENCE and an operator needs to
// see all three to understand the queue. What is new is being able to narrow
// to one — which is what makes a long queue workable without hiding the fact
// that the other two bands exist.
//
// ⛔ EVERY OPTION IS DERIVED FROM THE ITEMS ACTUALLY PRESENT
// (`workFilterOptions`), never hardcoded. A static list goes stale the moment
// a source is added, and an option that can only ever return nothing is
// indistinguishable from a filter that is broken.
//
// ⛔ THERE IS NO OWNER, STATUS, DUE DATE OR COMMENT CONTROL HERE, AND THAT IS
// A REFUSAL RATHER THAN AN OMISSION. None of those is persisted anywhere in
// this product — there is no assignment table, no workflow state and no
// per-item history. Rendering them backed by local component state would give
// an operator a control that forgets what they typed the moment they navigate,
// on the screen they are using to decide what to do next. When the backend
// exists, this is the file that gains them.

const BAND_LABEL = {
  act_now: 'Act now',
  scheduled: 'Scheduled',
  verify: 'Needs a human',
};

const EVIDENCE_LABEL = {
  measured: 'Measured',
  reported: 'Reported',
  unmeasured: 'Not measurable',
};

const TYPE_LABEL = {
  cve: 'Vulnerability',
  compliance: 'Compliance',
  config_diff: 'Config change',
  rule_cleanup: 'Rule hygiene',
  licence: 'Licence',
  segmentation: 'Segmentation',
  application: 'Application',
  ingest: 'Log ingest',
  device: 'Firewall',
  conformance: 'Conformance',
};

const titleCase = (s) => s.charAt(0).toUpperCase() + s.slice(1);

export default function WorkQueueFilters({ options, shown, total }) {
  const nav = useFilterNav('/work');
  const params = useSearchParams();
  // ⛔ EVERY CONTROL IS DRIVEN BY THE URL, not by local state. The page is a
  // server component that re-renders from the query string, so a control
  // holding its own copy would show one thing while the list below it showed
  // another — and the applied-filter chips, which read the URL, would agree
  // with the list and contradict the control.
  const cur = (k) => (params ? params.get(k) || '' : '');
  const set = (k, v) => nav.set({ [k]: v });

  const opt = (values, labels) => [
    { value: '', label: 'All' },
    ...values.map((v) => ({ value: v, label: (labels && labels[v]) || titleCase(v) })),
  ];

  const bandOpts = opt(options.bands, BAND_LABEL);
  const sevOpts = opt(options.severities);
  const typeOpts = opt(options.types, TYPE_LABEL);
  const evOpts = opt(options.evidences, EVIDENCE_LABEL);
  const devOpts = opt(options.devices);

  const defs = [
    { key: 'q', label: 'Search' },
    { key: 'band', label: 'Band', options: bandOpts },
    { key: 'severity', label: 'Severity', options: sevOpts },
    { key: 'type', label: 'Source', options: typeOpts },
    // ⛔ Evidence and firewall sit behind "More filters" because the first
    // three answer the question an operator opens this page with. The panel
    // OPENS ITSELF when either is applied, so an active filter can never hide
    // inside a collapsed section — see FilterBar.
    { key: 'evidence', label: 'Evidence', options: evOpts, advanced: true },
    { key: 'device', label: 'Firewall', options: devOpts, advanced: true },
  ];

  return (
    <FilterBar
      basePath="/work"
      defs={defs}
      count={{ shown, total, noun: 'items' }}
      advanced={(
        <>
          <FilterSelect label="Evidence" param="evidence" value={cur('evidence')} options={evOpts} onChange={set} idPrefix="wq" />
          <FilterSelect label="Firewall" param="device" value={cur('device')} options={devOpts} onChange={set} idPrefix="wq" />
        </>
      )}
    >
      <FilterSearch param="q" placeholder="Title or firewall…" value={cur('q')} onChange={set} idPrefix="wq" />
      <FilterSelect label="Band" param="band" value={cur('band')} options={bandOpts} onChange={set} idPrefix="wq" />
      <FilterSelect label="Severity" param="severity" value={cur('severity')} options={sevOpts} onChange={set} idPrefix="wq" />
      <FilterSelect label="Source" param="type" value={cur('type')} options={typeOpts} onChange={set} idPrefix="wq" />
    </FilterBar>
  );
}
