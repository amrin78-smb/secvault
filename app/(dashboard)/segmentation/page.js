import PageHeader from '../../../components/ui/PageHeader';
import AnswerHeader from '../../../components/ui/AnswerHeader';
import SegmentationBoard from '../../../components/segmentation/SegmentationBoard';
import { pool } from '../../../lib/db';
import { evaluateSegmentation, listFleetZones } from '../../../lib/engines/segmentationData';
import { buildSegmentationAnswer } from '../../../lib/answers';
import { segmentationEvidence } from '../../../lib/evidence';

export const dynamic = 'force-dynamic';

// Declared segmentation intent, tested two ways.
//
// ⛔ THE ANSWER SENTENCE IS SERVER-RENDERED and the board is a client component,
// deliberately. The headline is the thing an operator reads and acts on; making
// them wait for a client fetch to learn whether anything is broken would put the
// most important line on the page behind the slowest part of it.
//
// ⛔ THE BOARD IS HANDED THIS EVALUATION, IT DOES NOT FETCH ITS OWN COPY.
//
// It used to do both: this page ran evaluateSegmentation, then the board mounted
// and immediately GET /api/segmentation ran the whole thing AGAIN. Measured, each
// run is ~19 queries and ~700ms, so every page view cost ~40 queries and ~1.4s to
// compute the same answer twice. Worse than the waste: the two copies are taken at
// different instants, so a rule pull landing between them puts a headline sentence
// and the matrix underneath it into disagreement with each other, on a page whose
// entire job is to be trusted about what the rules permit.
//
// The board still owns `load()` and calls it after a mutation, which is the only
// moment the data can actually have changed while the operator is looking at it.
export default async function SegmentationPage() {
  let result = null;
  let zones = [];
  let initialError = '';
  try {
    // Zones come from here too, so the board has everything it needs to render
    // AND to populate the declare-an-intent selects without a round trip.
    [result, zones] = await Promise.all([
      evaluateSegmentation(pool),
      listFleetZones(pool),
    ]);
  } catch (err) {
    // ⛔ A failure here must not blank the page, and must not be swallowed
    // either. The sentence says nothing rather than claiming a clean fleet, and
    // the REASON is handed to the board, which renders it with a retry. Before
    // this, a 500 produced a header and then an entirely empty page: no matrix,
    // no form, no error, no way to try again.
    result = null;
    initialError = err && err.message
      ? `Could not evaluate segmentation: ${err.message}`
      : 'Could not evaluate segmentation.';
  }

  const answer = buildSegmentationAnswer(result);
  const evidence = segmentationEvidence(result);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <PageHeader
        title="Segmentation"
        subtitle="What you say must not connect, checked against what the rules permit and what the traffic actually did."
      />

      <AnswerHeader answer={answer} evidence={evidence} />

      <SegmentationBoard
        initial={result ? { ...result, zones } : null}
        initialError={initialError}
      />
    </div>
  );
}
