import PageHeader from '../../../components/ui/PageHeader';
import AnswerHeader from '../../../components/ui/AnswerHeader';
import ApplicationBoard from '../../../components/applications/ApplicationBoard';
import CloudServices from '../../../components/applications/CloudServices';
import { pool } from '../../../lib/db';
import { evaluateAllApplications } from '../../../lib/engines/applicationViewData';
import { buildApplicationsAnswer } from '../../../lib/answers';
import { applicationsEvidence } from '../../../lib/evidence';
import { summariseCloudUsage } from '../../../lib/engines/cloudAppsData';

export const dynamic = 'force-dynamic';

// The application-centric view: what each business system needs from the
// network, and what the rulebase actually says about it.
//
// ⛔ THE EVALUATION RUNS ONCE, HERE, AND IS HANDED DOWN. The board does not
// fetch its own copy on mount. That exact mistake was found and fixed on
// /segmentation: two evaluations per page view, taken at different instants, so
// a rule pull landing between them put the headline sentence and the table
// beneath it into disagreement — on a page whose entire job is to be trusted
// about what the rules permit. After a mutation the board calls
// router.refresh(), which re-runs THIS function, so both halves of the page
// always describe the same instant.
//
// ⛔ NOTHING NON-SERIALISABLE CROSSES INTO THE CLIENT. The two props below are a
// plain object and a string. The engine's own output is built for this: rule
// match volumes are stringified BigInts, every verdict is a string, and the
// only class instances anywhere in it are the applications' Date columns, which
// the server/client boundary carries natively. A function passed across this
// boundary is what shipped a blank page once before — React refuses it, and the
// build does not notice.
export default async function ApplicationsPage() {
  // ⛔ The two reads are INDEPENDENT and neither gates the other. Naming a rule
  // against the cloud catalogue has nothing to do with evaluating a declared
  // flow, and one failing must not blank the other — the catalogue half is the
  // only useful thing on this page while nothing is declared yet.
  let cloud = null;
  let result = null;
  let initialError = '';
  try {
    result = await evaluateAllApplications(pool);
  } catch (err) {
    // ⛔ A failure here must neither blank the page nor be swallowed. The
    // sentence says nothing rather than claiming a clean fleet, and the REASON
    // is handed to the board, which renders it with a retry.
    result = null;
    initialError = err && err.message
      ? `Could not evaluate applications: ${err.message}`
      : 'Could not evaluate applications.';
  }

  try {
    cloud = await summariseCloudUsage(pool);
  } catch (_err) {
    // summariseCloudUsage reports its own failures in `status` rather than
    // throwing; reaching here means something outside it broke, and the section
    // is simply omitted rather than taking the page down.
    cloud = null;
  }

  const answer = buildApplicationsAnswer(result, initialError);
  const evidence = applicationsEvidence(result);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
      <PageHeader
        title="Applications"
        subtitle="What each application needs from the network, checked against what the rules permit — and, separately, against what the permitting rules have actually carried."
      />

      <AnswerHeader answer={answer} evidence={evidence} />

      {/* ⛔ ABOVE the declaration board on purpose. With nothing declared yet
          this is the only part of the page with anything to say, and it is what
          tells an operator what there is to declare. */}
      {/* ⛔ The declared names travel WITH the cloud summary. Without them the
          Declare control offers to create an application that already exists
          and the click comes back a 409 — the page knew before the operator
          pressed it. Taken from the SAME evaluation the cards below render, so
          the two halves of the page cannot disagree about what exists. */}
      <CloudServices
        summary={cloud}
        declaredNames={(result && result.applications ? result.applications : [])
          .map((a) => (a && a.application ? a.application.name : null))
          .filter(Boolean)}
      />

      <ApplicationBoard initial={result} initialError={initialError} />
    </div>
  );
}
