import PageHeader from '../../../components/ui/PageHeader';
import AnswerHeader from '../../../components/ui/AnswerHeader';
import SegmentationBoard from '../../../components/segmentation/SegmentationBoard';
import { pool } from '../../../lib/db';
import { evaluateSegmentation } from '../../../lib/engines/segmentationData';
import { buildSegmentationAnswer } from '../../../lib/answers';
import { segmentationEvidence } from '../../../lib/evidence';

export const dynamic = 'force-dynamic';

// Declared segmentation intent, tested two ways.
//
// ⛔ THE ANSWER SENTENCE IS SERVER-RENDERED and the board is a client component,
// deliberately. The headline is the thing an operator reads and acts on; making
// them wait for a client fetch to learn whether anything is broken would put the
// most important line on the page behind the slowest part of it.

export default async function SegmentationPage() {
  let result = null;
  try {
    result = await evaluateSegmentation(pool);
  } catch (err) {
    // ⛔ A failure here must not blank the page. The board below fetches its own
    // copy and will report its own error; the sentence simply says nothing
    // rather than claiming a clean fleet.
    result = null;
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

      <SegmentationBoard />
    </div>
  );
}
