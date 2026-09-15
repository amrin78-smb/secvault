'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

// The one interactive control inside the otherwise server-rendered
// CloudServices section: declare a published cloud service as an application.
//
// ⛔ THE BUTTON STATES ITS EFFECT BEFORE IT IS CLICKED. `plan` is derived on the
// SERVER, by the same module the POST handler uses, so the count on the button
// is the count that will be created - not an estimate, and not a surprise. A
// one-click action whose result has to be discovered afterwards is worse than
// two clicks.
//
// ⛔ AND IT NEVER PROMISES FLOWS IT CANNOT DERIVE. Where the publisher lists a
// service by hostname only, the button says so in advance and the declaration
// is created empty - a correct outcome, and one the operator has agreed to
// before clicking rather than discovered after.

const ROW = {
  display: 'flex',
  flexDirection: 'column',
  gap: 'var(--s2)',
  alignItems: 'flex-start',
};

const HINT = {
  fontSize: 'var(--text-xs)',
  color: 'var(--text-muted)',
  lineHeight: 1.5,
  maxWidth: '46ch',
};

// ⛔ HUELESS, not green. A declaration built from a partial published list is
// not an all-clear, and the caveat below it is the point of the panel.
const RESULT = {
  marginTop: 'var(--s2)',
  padding: 'var(--s3)',
  border: '1px solid var(--border)',
  borderLeft: '3px solid var(--primary)',
  borderRadius: 'var(--radius)',
  fontSize: 'var(--text-xs)',
  lineHeight: 1.55,
  color: 'var(--text-secondary)',
  maxWidth: '52ch',
};

const CAVEAT = {
  marginTop: 'var(--s2)',
  padding: 'var(--s3)',
  backgroundImage: 'var(--hatch)',
  backgroundColor: 'var(--surface-subtle)',
  border: '1px dashed var(--border)',
  borderRadius: 'var(--radius)',
  fontSize: 'var(--text-xs)',
  lineHeight: 1.55,
  color: 'var(--unmeasured)',
};

const ERROR = {
  marginTop: 'var(--s2)',
  padding: 'var(--s3)',
  border: '1px solid var(--border)',
  borderLeft: '3px solid var(--sev-high)',
  borderRadius: 'var(--radius)',
  fontSize: 'var(--text-xs)',
  lineHeight: 1.55,
  color: 'var(--text-secondary)',
  maxWidth: '52ch',
};

export default function DeclareCloudApp({ provider, service, label, plan }) {
  const router = useRouter();
  const [state, setState] = useState('idle'); // idle | working | done | error
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  // No plan means the catalogue does not carry this pair - the control is
  // omitted rather than offering an action that would be refused with a 400.
  if (!plan) return null;

  async function declare() {
    setState('working');
    setError('');
    try {
      const res = await fetch('/api/applications/from-cloud', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, service }),
      });
      const payload = await res.json().catch(() => ({}));
      if (!res.ok) {
        // ⛔ The server's own sentence, verbatim. A 409 says the service is
        // already declared and a 400 says the catalogue does not carry it -
        // replacing either with "could not declare" throws away the only part
        // the operator can act on.
        setError(payload.error || `The declaration failed (HTTP ${res.status}).`);
        setState('error');
        return;
      }
      setResult(payload);
      setState('done');
      // The application board on this page is server-rendered from the same
      // request, so the new declaration only appears once the page re-runs.
      router.refresh();
    } catch (err) {
      setError(err && err.message ? err.message : 'The declaration could not be sent.');
      setState('error');
    }
  }

  if (state === 'done' && result) {
    const d = result.derivation || {};
    const created = d.createdFlowCount || 0;
    return (
      <div style={ROW}>
        <div style={RESULT}>
          <strong style={{ color: 'var(--text-primary)' }}>
            Declared &ldquo;{(result.application && result.application.name) || label}&rdquo;
            {' '}with {created} flow{created === 1 ? '' : 's'}.
          </strong>
          {d.reason ? <div style={{ marginTop: 'var(--s2)' }}>{d.reason}</div> : null}
          {d.failedFlowCount > 0 ? (
            // ⛔ A partial result says so. The application exists either way,
            // and an operator told "done" while rows were refused would be
            // working from a map that is quietly missing pieces.
            <div style={{ marginTop: 'var(--s2)', color: 'var(--unmeasured)' }}>
              {d.failedFlowCount} flow{d.failedFlowCount === 1 ? ' was' : 's were'} refused and not
              stored. The application was still created.
            </div>
          ) : null}
        </div>
        {/* ⛔ THE PLACEHOLDER CAVEAT, SURFACED. It is written on every created
            flow's note as well, so it survives this panel being dismissed. */}
        <div style={CAVEAT}>
          {d.srcCaveat || plan.srcCaveat}
        </div>
      </div>
    );
  }

  return (
    <div style={ROW}>
      <button
        type="button"
        className="btn btn-secondary"
        onClick={declare}
        disabled={state === 'working'}
        style={{ fontSize: 'var(--text-xs)' }}
        title={plan.reason}
      >
        {state === 'working' ? 'Declaring...' : plan.buttonLabel}
      </button>

      {/* ⛔ The full sentence, not just the count. It names what will be
          created, what will not, and why - before the click, where it can still
          change the decision. */}
      <div style={HINT}>{plan.reason}</div>

      {state === 'error' ? <div style={ERROR}>{error}</div> : null}
    </div>
  );
}
