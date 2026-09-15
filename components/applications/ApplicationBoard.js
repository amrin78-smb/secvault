'use client';

// components/applications/ApplicationBoard.js
//
// The declared applications, what the rules say about each of their flows, and
// the forms for declaring more.
//
// ⛔ THE SERVER PAGE HANDS US ITS EVALUATION (`initial`) AND WE NEVER FETCH OUR
// OWN COPY. This is the mistake that was found and fixed on /segmentation: the
// page evaluated once, then the board mounted and immediately ran the whole
// evaluation AGAIN through the API. It is expensive — the fleet rulebase is
// loaded per evaluation — but the real cost is that the two copies are taken at
// different instants, so a rule pull landing between them puts the headline
// sentence and the table underneath it into disagreement, on a page whose whole
// job is to be trusted about what the rules permit.
//
// ⛔ AND AFTER A MUTATION WE REFRESH THE SERVER COMPONENT rather than re-fetching
// /api/applications into local state. Same reason, one step further: fetching
// the evaluation here would produce a SECOND copy that the server-rendered
// headline above us knows nothing about, so an operator who declared a flow
// would see it appear in the table while the sentence above kept describing the
// fleet as it was before. router.refresh() re-runs the one evaluation and both
// halves of the page move together. The only fetches this component makes are
// the mutations themselves.
//
// ⛔ AN EDIT IS A MUTATION LIKE ANY OTHER AND TAKES EXACTLY THAT PATH. It is the
// most tempting place in this file to introduce optimistic state — the operator
// typed the new name, we have it right here, we could paint it immediately —
// and it is the worst place to do it. A renamed application whose verdict,
// headline sentence and coverage summary still describe the old declaration is
// two copies disagreeing on the one page whose job is to be trusted about what
// the rules permit. The PUT lands, router.refresh() re-runs the evaluation, and
// the edited row is re-read from the server like every other row.
//
// ⛔ EVERY COMPONENT HERE IS DEFINED AT MODULE TOP LEVEL. A component declared
// inside another is a new type on every render, so React remounts its subtree
// and the declare form loses focus after one character.

import { useCallback, useState, useTransition } from 'react';
import { useRouter } from 'next/navigation';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Button from '../ui/Button';
import ApplicationCard from './ApplicationCard';
import CoverageSummary from './CoverageSummary';
import { DeclareApplicationForm, ErrorNote } from './ApplicationForms';

const SOURCE_LABEL = {
  applications: 'The declared applications',
  application_flows: 'The declared flows',
  fleet_rules: 'The fleet rulebase',
};

/**
 * ⛔ A SOURCE THAT FAILED IS BANNER'D, NEVER ALLOWED TO CONTRIBUTE NOTHING
 * SILENTLY. A page that looks cleanest when it is least trustworthy is the
 * failure mode this product exists to remove: with the banner suppressed, a
 * broken rulebase load renders as an application with no problems.
 */
function SourceErrors({ errors }) {
  if (!Array.isArray(errors) || errors.length === 0) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
      {errors.map((e, i) => (
        <ErrorNote key={i}>
          <strong>{SOURCE_LABEL[e.source] || e.source}</strong> could not be read: {e.error}. Anything
          that depends on it is missing from this page — not zero, and not an all-clear.
        </ErrorNote>
      ))}
    </div>
  );
}

/**
 * ⛔ THE EMPTY STATE CARRIES THE FEATURE. Most people will see this screen
 * first, and an empty table would tell them nothing about what an application is
 * here or why they would declare one. It is deliberately the longest piece of
 * prose on the page and it disappears the moment something is declared.
 */
function EmptyApplications() {
  return (
    <Card>
      <CardHeader><CardTitle>Declare your first application</CardTitle></CardHeader>
      <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)', maxWidth: '80ch' }}>
        <p style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
          An application here is a business system plus the connections it depends on — “the payroll
          servers on <code>10.1.0.0/24</code> reach the database at <code>10.2.0.10</code> on
          tcp/1521” — and, just as importantly, the connections it must never make.
        </p>
        <p style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
          Once a flow is declared, SecVault tests it two ways against every firewall it has
          collected: whether <strong>any rule permits it</strong>, and separately whether the
          <strong> rules that permit it have seen traffic</strong>. Those are different questions and
          they are kept in different columns — a rule that cannot report usage is shown as
          unmeasurable, never as unused.
        </p>
        <p style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
          Nothing is guessed. A flow no rule decides is reported as exactly that, not as blocked —
          this product holds no default-policy data for any vendor. A firewall whose ruleset has
          never been collected keeps the answer unverified rather than quietly making it look clean.
        </p>
        <p style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
          Start with the application you would most hate to find broken after a firewall change, or
          the one whose auditor asks about it.
        </p>
      </CardBody>
    </Card>
  );
}

export default function ApplicationBoard({ initial = null, initialError = '' }) {
  const router = useRouter();
  // ⛔ THE SERVER PROP IS READ DIRECTLY — there is deliberately NO local copy of
  // it in state. Mirroring it into useState would create a second version that
  // can lag the server render by a frame (or, if a sync effect were ever
  // dropped, for good), which is the same two-copies-disagreeing failure this
  // component was written to avoid, just moved inside one file. Nothing here
  // edits the evaluation optimistically, so there is nothing for state to hold.
  const data = initial;
  const [busy, setBusy] = useState(false);
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState('');
  // WHERE the failure belongs on screen. One shared string rendered in two
  // places prints every message twice; rendered only at the top, a validation
  // error raised by the declare form at the bottom of a long page can be
  // off-screen at the moment it is raised.
  //
  // ⛔ AN EDIT'S FAILURE BELONGS AT THE EDITOR, so the slot is an ADDRESS, not a
  // fixed set: 'board', 'form', `app:<id>` or `flow:<id>`. Reason enough on its
  // own — but the specific message these routes return is the engine's own parse
  // failure, naming the field that is wrong, and a message that names a field
  // printed hundreds of pixels away from that field is barely a message at all.
  const [errorAt, setErrorAt] = useState('board');

  const fail = useCallback((msg, at) => { setError(msg); setErrorAt(at || 'board'); }, []);

  const refresh = useCallback(() => {
    startTransition(() => { router.refresh(); });
  }, [router]);

  /**
   * One mutation, one place. ⛔ `res.ok` IS ALWAYS CHECKED: a 403 — exactly what
   * a role without the operate capability receives — would otherwise refresh the
   * page unchanged, so the button would look like it did nothing at all. An
   * operator who cannot tell a permission boundary from a broken button files
   * the second bug and stops trusting the first.
   */
  const mutate = useCallback(async (url, options, at, failureNoun) => {
    setBusy(true);
    setError('');
    try {
      const res = await fetch(url, options);
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        fail(body.error || `Could not ${failureNoun} (HTTP ${res.status}).`, at);
        return false;
      }
      refresh();
      return true;
    } catch (err) {
      // ⛔ try/finally with no catch turns a network failure into an unhandled
      // rejection: the form sits there, nothing was saved, and nothing on the
      // page says so. On a page that records what an application is allowed to
      // do, a silently dropped declaration is the worst available failure.
      fail(`Could not reach SecVault — nothing was ${failureNoun === 'save' ? 'saved' : 'changed'}.`, at);
      return false;
    } finally {
      setBusy(false);
    }
  }, [fail, refresh]);

  const addApplication = useCallback((body) => mutate(
    '/api/applications',
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
    'form',
    'save',
  ), [mutate]);

  /**
   * ⛔ THE ROUTE'S OWN MESSAGE IS WHAT REACHES THE OPERATOR. `mutate` already
   * prefers `body.error`, and on these two PUTs that string is the engine's
   * verbatim reason — `Source "10.0.0.300" is not a valid address or CIDR.`,
   * `Another application already has that name.`, or the 403 naming the missing
   * capability. Substituting a generic "invalid input" here would discard the
   * only part of the response that tells anyone what to change.
   */
  const updateApplicationById = useCallback((id, body) => mutate(
    `/api/applications/${encodeURIComponent(id)}`,
    { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
    `app:${id}`,
    'save that change',
  ), [mutate]);

  const updateFlowById = useCallback((appId, flowId, body) => mutate(
    `/api/applications/${encodeURIComponent(appId)}/flows/${encodeURIComponent(flowId)}`,
    { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
    `flow:${flowId}`,
    'save that change',
  ), [mutate]);

  const removeApplication = useCallback((id) => mutate(
    `/api/applications/${encodeURIComponent(id)}`,
    { method: 'DELETE' },
    'board',
    'delete that application',
  ), [mutate]);

  const addFlow = useCallback((appId, body) => mutate(
    `/api/applications/${encodeURIComponent(appId)}/flows`,
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) },
    'board',
    'save',
  ), [mutate]);

  const removeFlow = useCallback((appId, flowId) => mutate(
    `/api/applications/${encodeURIComponent(appId)}/flows/${encodeURIComponent(flowId)}`,
    { method: 'DELETE' },
    'board',
    'remove that flow',
  ), [mutate]);

  const working = busy || pending;

  // ⛔ NEVER `return null` HERE. The one case this state exists for — no data,
  // because the evaluation failed — would then render a page with a header and
  // nothing underneath it: no reason, no retry, and no way to tell "the engine
  // is broken" from "you have declared nothing yet".
  const errors = (data && Array.isArray(data.errors)) ? data.errors : [];
  const readFailed = errors.some((e) => e && e.source === 'applications');

  if (!data || readFailed) {
    const reason = initialError
      || (readFailed && errors.find((e) => e.source === 'applications').error)
      || 'The applications could not be evaluated.';
    return (
      <Card>
        <CardHeader><CardTitle>Applications could not be read</CardTitle></CardHeader>
        <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
          <ErrorNote>{reason}</ErrorNote>
          <p style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
            {/* ⛔ The distinction this sentence draws is the whole point. An
                empty list and a failed read look identical on screen unless
                something says which one happened. */}
            This is a failure to read the declared applications, not an empty list — nothing here
            says that no application is declared.
          </p>
          {error && <ErrorNote>{error}</ErrorNote>}
          <div>
            <Button variant="secondary" disabled={working} onClick={refresh}>Retry</Button>
          </div>
        </CardBody>
      </Card>
    );
  }

  const applications = Array.isArray(data.applications) ? data.applications : [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
      <SourceErrors errors={errors} />
      {error && errorAt === 'board' && <ErrorNote>{error}</ErrorNote>}

      <CoverageSummary
        orphans={data.orphans}
        coverage={data.coverage}
        windowDays={data.windowDays}
      />

      {applications.length === 0 ? (
        <EmptyApplications />
      ) : (
        applications.map((entry) => (
          <ApplicationCard
            key={entry.application.id}
            entry={entry}
            busy={working}
            // The card renders this only when errorAt addresses something
            // inside it, so the one shared string is still printed exactly once
            // on the page.
            error={error}
            errorAt={errorAt}
            onAddFlow={addFlow}
            onUpdateApp={updateApplicationById}
            onUpdateFlow={(flowId, body) => updateFlowById(entry.application.id, flowId, body)}
            onRemoveFlow={(flowId) => removeFlow(entry.application.id, flowId)}
            onRemoveApp={removeApplication}
          />
        ))
      )}

      <Card>
        <CardHeader>
          <CardTitle>{applications.length === 0 ? 'Declare an application' : 'Declare another application'}</CardTitle>
        </CardHeader>
        <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
          <DeclareApplicationForm busy={working} onSubmit={addApplication} />
          {error && errorAt === 'form' && <ErrorNote>{error}</ErrorNote>}
        </CardBody>
      </Card>
    </div>
  );
}
