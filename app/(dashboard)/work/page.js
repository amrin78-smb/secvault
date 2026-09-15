import PageHeader from '../../../components/ui/PageHeader';
import Card, { CardBody } from '../../../components/ui/Card';
import EmptyState from '../../../components/ui/EmptyState';
import WorkQueueBoard from '../../../components/work/WorkQueueBoard';
import { pool } from '../../../lib/db';
import { gatherWorkQueue } from '../../../lib/engines/workQueueData';
import { rankItems, summarise } from '../../../lib/engines/workQueue';
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
// ⛔ Segmentation is computed HERE and passed in, rather than being gathered
// inside workQueueData.js, because evaluateSegmentation() loads the whole
// fleet's rules with traffic evidence — far and away the most expensive source
// — and doing it behind the queue's own abstraction would hide that cost from
// anyone reading the gather list. Its failure is caught here and reported as a
// failed source, exactly like the eight query-backed ones.

export default async function WorkQueuePage() {
  let segmentation = null;
  let segmentationError = null;
  try {
    segmentation = await evaluateSegmentation(pool);
  } catch (err) {
    // ⛔ Recorded, not swallowed. It becomes a failed source below, so the page
    // says the queue is incomplete rather than quietly omitting the band.
    segmentationError = err.message;
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
  // ⛔ AND THERE IS DELIBERATELY NO SECOND ERROR CHANNEL HERE, unlike
  // segmentation above. gatherSegmentation() only ever reads what it is handed,
  // so a failure on this page would vanish without that variable. This source
  // does its own evaluation when handed nothing, and runSource() banners
  // whatever that throws — so recording the error here as well could mark the
  // source failed on a page where the retry actually succeeded, which is a
  // worse lie than the cost of retrying.
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

  const sources = gathered.sources.slice();
  if (segmentationError) {
    const i = sources.findIndex((s) => s.key === 'segmentation');
    const entry = { key: 'segmentation', ok: false, count: 0, error: segmentationError };
    if (i >= 0) sources[i] = entry;
    else sources.push(entry);
  }

  const items = rankItems(gathered.items);
  const summary = summarise(items, sources);
  const answer = buildWorkQueueAnswer(summary);

  return (
    <div>
      <PageHeader
        title="Work queue"
        subtitle="Everything outstanding across the product, in the order worth doing it."
      />
      <WorkQueueBoard result={{ items, summary, answer, sources }} />
    </div>
  );
}
