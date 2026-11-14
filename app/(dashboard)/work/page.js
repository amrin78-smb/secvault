import PageHeader from '../../../components/ui/PageHeader';
import Card, { CardBody } from '../../../components/ui/Card';
import EmptyState from '../../../components/ui/EmptyState';
import WorkQueueBoard from '../../../components/work/WorkQueueBoard';
import { pool } from '../../../lib/db';
import { gatherWorkQueue } from '../../../lib/engines/workQueueData';
import { rankItems, summarise, filterWorkItems, workFilterOptions } from '../../../lib/engines/workQueue';
import { evaluateSegmentation } from '../../../lib/engines/segmentationData';
import { evaluateAllApplications } from '../../../lib/engines/applicationViewData';
import { buildWorkQueueAnswer } from '../../../lib/answers';

export const dynamic = 'force-dynamic';

// THE WORK QUEUE — the single prioritised feed across every engine (Phase 3).
//
// ⛔ FULLY SERVER-RENDERED, no client fetch. Every other answer-first page in
// this product puts its headline on the server for the same reason: the
// sentence an operator acts on must not wait behind the slowest part of the
// page. Here it matters more than usual, because this page IS the headline —
// there is nothing else on it to read while a fetch resolves.
//
// ⛔ Segmentation is computed HERE and passed in, rather than being left to
// workQueueData.js, because evaluateSegmentation() loads the whole fleet's
// rules with traffic evidence — far and away the most expensive single source,
// measured against the reference deployment 2026-11-14 at 9.8s cold over 1,803
// rules, 16 firewalls and a 65-day window — and doing it only behind the
// queue's own abstraction would hide that cost from anyone reading the gather
// list. (That 9.8s is a COLD STANDALONE figure, i.e. roughly what this render
// pays. It is not what the background poll adds: inside gatherWorkQueue the
// eleven sources run under one Promise.all, where the measured marginal cost is
// ~112ms — see gatherSegmentation().)
//
// ⛔ IT IS NO LONGER THE ONLY WAY THAT SOURCE CAN RUN, AND THAT MATTERS HERE
// (v2.228.5). gatherSegmentation() now evaluates for itself when handed
// nothing, behind a COUNT on `segmentation_intents` — it had to, or the
// 15-minute dispatch poll would go on contributing a silent zero for a
// declared security boundary. Passing the result keeps the work happening
// exactly once on this render, and keeps the cost where a reader can see it.

export default async function WorkQueuePage({ searchParams }) {
  // ⛔ A FAILURE HERE IS LEFT TO THE GATHER TO REPORT, AND THE SECOND ERROR
  // CHANNEL THAT USED TO LIVE HERE IS NOW GONE. While gatherSegmentation() only
  // read what it was handed, recording the message was the only way the page
  // could say the band was missing. Now the gather RETRIES, so overriding its
  // verdict from here would mark the source failed on a page where the retry
  // actually succeeded — a worse lie than the cost of retrying, and precisely
  // the reasoning the application source below has carried all along.
  let segmentation = null;
  try {
    segmentation = await evaluateSegmentation(pool);
  } catch (_err) {
    // Left null on purpose: the gather re-attempts and runSource() banners it.
  }

  // ⛔ THE APPLICATION VIEW IS COMPUTED HERE FOR THE SAME REASON AS SEGMENTATION
  // ABOVE, and the reason is visibility of cost, not convenience. It loads the
  // whole fleet's rules AND every network object (measured: ~740ms, 1,757 rules
  // and 10,044 objects live), which makes it the second most expensive source in
  // this file. Doing that behind the queue's own gather list would hide it from
  // anyone reading what the queue costs.
  //
  // gatherApplications() can still reach it on its own — it has to, or a caller
  // that does not pass one would contribute a silent zero forever — but it puts
  // a cheap COUNT in front of the load and skips it entirely while nothing is
  // declared. Passing it here means the work that IS needed happens exactly once.
  //
  // ⛔ NO SECOND ERROR CHANNEL HERE EITHER, FOR THE REASON STATED ABOVE — and
  // as of v2.228.5 the two sources finally handle this the same way. This one
  // always did its own evaluation when handed nothing, and runSource() banners
  // whatever that throws, so recording the error here as well could mark the
  // source failed on a page where the retry actually succeeded.
  let applications = null;
  try {
    applications = await evaluateAllApplications(pool);
  } catch (_err) {
    // Left null on purpose: the gather re-attempts and reports it properly.
  }

  let gathered = null;
  let fatal = null;
  try {
    gathered = await gatherWorkQueue(pool, { segmentation, applications });
  } catch (err) {
    // gatherWorkQueue catches per source, so reaching here means something
    // structural failed. Say so — never render an empty, reassuring page.
    fatal = err.message;
  }

  if (fatal) {
    return (
      <div>
        <PageHeader
          title="Work queue"
          subtitle="Everything outstanding across the product, in the order worth doing it."
        />
        <Card>
          <CardBody>
            <EmptyState
              message={
                'The work queue could not be built, so this page is not a statement that nothing '
                + `is outstanding. The error was: ${fatal}`
              }
            />
          </CardBody>
        </Card>
      </div>
    );
  }

  const sources = gathered.sources;

  const items = rankItems(gathered.items);

  // ⛔ THE SUMMARY IS COMPUTED ON THE **UNFILTERED** LIST, AND THAT SEPARATION
  // IS THE WHOLE SAFETY PROPERTY OF ADDING FILTERS TO THIS PAGE.
  // `summarise()` carries the band counts, the failed-source list and the
  // truncation disclosure, and `buildWorkQueueAnswer` is forbidden from
  // claiming an empty queue while any of those is non-zero. Summarising the
  // filtered list instead would make "Severity: critical" with no matches
  // render the page's own headline as "nothing outstanding" — a filter
  // silently becoming an all-clear, on the one screen whose job is to say what
  // is outstanding. The banners above the list describe the REAL queue for the
  // same reason: a source that failed is still missing from a filtered view.
  const summary = summarise(items, sources);
  const answer = buildWorkQueueAnswer(summary);

  const filters = {
    band: searchParams?.band || '',
    severity: searchParams?.severity || '',
    type: searchParams?.type || '',
    evidence: searchParams?.evidence || '',
    device: searchParams?.device || '',
    q: searchParams?.q || '',
  };
  const shown = filterWorkItems(items, filters);
  // ⛔ Options come from the FULL list, so narrowing by one field never empties
  // the controls for the others — a filter set that collapses as you use it is
  // one you cannot back out of.
  const options = workFilterOptions(items);

  return (
    <div>
      <PageHeader
        title="Work queue"
        subtitle="Everything outstanding across the product, in the order worth doing it."
        eyebrow={`${items.length} item${items.length === 1 ? '' : 's'} across ${summary.sourcesTotal} engines`}
      />
      <WorkQueueBoard
        result={{ items: shown, summary, answer, sources }}
        totalItems={items.length}
        options={options}
      />
    </div>
  );
}
