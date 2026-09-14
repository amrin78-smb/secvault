// components/ui/Disclosure.js
//
// A collapsed block of explanatory text. Native <details>/<summary>, so it
// works in a SERVER component with no client JS, no state and no hydration —
// the same constraint that makes VpnTunnelHealth a server component in the
// first place.
//
// ⛔ WHAT MAY AND MAY NOT GO IN HERE. This is for the MECHANISM — why a vendor
// cannot answer a question, what command produces a field, what it would take
// to close a gap. It is NOT for a caveat that changes how the number above it
// should be read. Those belong in the answer sentence or the coverage line,
// where they cannot be missed.
//
// The test to apply before moving a sentence in here: if a reader who never
// opens this block would draw a WRONG CONCLUSION from the numbers on screen,
// the sentence is load-bearing and must stay outside it. If they would simply
// not know WHY, it belongs here.
//
// Collapsed by default, and deliberately not remembered across pages — a
// disclosure that stays open because of something the user did last week is a
// layout that changes for reasons they cannot see.

export default function Disclosure({ summary, children, defaultOpen = false }) {
  return (
    <details open={defaultOpen} className="sv-disclosure">
      <summary
        style={{
          cursor: 'pointer',
          fontSize: 'var(--text-sm)',
          fontWeight: 600,
          color: 'var(--text-secondary)',
          padding: 'var(--s2) 0',
          listStyle: 'revert',
        }}
      >
        {summary}
      </summary>
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: 'var(--s3)',
          paddingTop: 'var(--s2)',
          maxWidth: '95ch',
          fontSize: 'var(--text-sm)',
          color: 'var(--text-secondary)',
          lineHeight: 1.6,
        }}
      >
        {children}
      </div>
    </details>
  );
}
