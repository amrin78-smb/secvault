// components/ui/AnswerHeader.js
//
// The answer-first page header: one sentence of plain English that answers the
// question the operator arrived with, above the grid that proves it.
//
// ⛔ THE COVERAGE LINE IS NOT A FOOTNOTE. It sits in the same block as the
// headline, immediately under it, in the same reading motion. A fleet claim
// made over a partial fleet is the most dangerous thing this product can print,
// and burying the caveat at the bottom of the page — or behind a tooltip — is
// functionally the same as not printing it. CoverageNote (ui/NotMeasured.js)
// already established this rule for a single tile; this applies it to the
// sentence that summarises all of them.
//
// ⛔ TONE `unknown` CARRIES NO HUE. Three of the four tones map to the severity
// ramp; the fourth deliberately does not, because "nothing outstanding, but we
// could not see all of it" is neither good news nor bad news. Colouring it
// green would be the failed-read-as-a-fact bug in prose — see lib/answers.js,
// which is what decides that a clear result over incomplete coverage is
// `unknown` rather than `ok`.

import { EvidenceMark } from './Evidence';

// The dot beside the sentence. Hue is the ONLY thing that varies — the shape
// and size stay identical, so the row never reflows between states.
const TONE_DOT = {
  critical: 'var(--sev-crit)',
  warn: 'var(--sev-med)',
  ok: 'var(--sev-ok)',
  unknown: 'var(--unmeasured)',
};

// ⛔ The LEAD fragment is text, so it takes the text-safe counterpart of the
// ramp rather than the raw hue — the same split StatCard documents at length
// (a raw --yellow measured 3.64:1 as text, under WCAG 1.4.3's 4.5:1).
const TONE_TEXT = {
  critical: 'var(--tint-danger-fg)',
  warn: 'var(--tint-warn-fg)',
  ok: 'var(--tint-success-fg)',
  unknown: 'var(--unmeasured)',
};

/**
 * @param {{sentence:string, lead:string|null, tone:string, coverage:string|null}} answer
 *        From lib/answers.js — never assembled inline at a call site, so the
 *        rules about what may be claimed live in one testable place.
 * @param {Object}  [evidence]  Descriptor from lib/evidence.js for the headline figure.
 * @param {string}  [context]   Small muted line above the sentence (fleet size, freshness).
 * @param {React.ReactNode} [actions]  Right-hand slot.
 */
export default function AnswerHeader({ answer, evidence, context, actions }) {
  if (!answer || !answer.sentence) return null;
  const tone = answer.tone || 'unknown';

  return (
    <div className="answer-header">
      <div className="answer-main">
        {context && <div className="answer-context">{context}</div>}

        <p className="answer-sentence">
          <span
            className="answer-dot"
            style={{ background: TONE_DOT[tone] || TONE_DOT.unknown }}
            aria-hidden="true"
          />
          {answer.lead && (
            <strong style={{ color: TONE_TEXT[tone] || TONE_TEXT.unknown }}>{answer.lead} </strong>
          )}
          {answer.sentence}
          {evidence && <EvidenceMark evidence={evidence} subject={answer.lead || 'this figure'} />}
        </p>

        {/* Hatched, hueless, and in the same block as the claim it qualifies. */}
        {answer.coverage && (
          <div className="answer-coverage">
            <span className="answer-hatch" aria-hidden="true" />
            {answer.coverage}
          </div>
        )}
      </div>

      {actions && <div className="answer-actions">{actions}</div>}
    </div>
  );
}
