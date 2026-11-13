// The "there is nothing here" panel.
//
// ⛔ IT SILENTLY SWALLOWED `title` FOR ITS WHOLE LIFE, AND FOUR CALL SITES
// WERE PASSING ONE (found 2026-11-13). The signature destructured `message`
// alone, so `<EmptyState title="..." message="..." />` dropped the title with
// no error, no warning and nothing in any test — React does not complain about
// a prop a component ignores, and `node --check` is a no-op on JSX. The four:
//
//   RemediationVelocity.js   "Remediation velocity could not be measured"
//   /compliance/exceptions   "No risk has been formally accepted"
//   /compliance/controls     "No checks are seeded"
//   /compliance/controls     "No control matches these filters"
//
// ⛔ THE WORST ONE IS THE FIRST. "Could not be measured" is a statement that
// SecVault failed to read something, and it vanished — leaving a bare grey
// paragraph that reads as "nothing to report". That is this codebase's
// signature bug (a failed read presenting as an affirmative answer) produced
// not by any engine but by a prop name nobody implemented.
//
// ⛔ AND IT IS INVISIBLE BY CONSTRUCTION, which is why a GUARD ships with the
// fix rather than four edited call sites. `tests/emptyState.test.js` scans
// every `<EmptyState>` in the repo and fails the build on a prop this
// component does not destructure — so the next `icon=` or `action=` somebody
// invents is a build failure instead of a silent omission. Four independent
// authors reached for `title`; the component was wrong, not the call sites.
//
// ⛔ THE TITLE IS NOT A HEADING ELEMENT, DELIBERATELY. This panel is mounted
// inside cards, inside tabs and directly under a page's own `<h1>`, so
// emitting an `<h2>` here would inject a document-outline entry whose LEVEL
// depends on where the panel happens to be used — and `tests/pageHeading.js`
// pins the outline at both ends. It is styled as a title and left out of the
// outline; the message beside it carries the meaning either way.
export default function EmptyState({ title, message = 'Nothing to show.' }) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 'var(--s2)',
        border: '1px dashed var(--border)',
        borderRadius: 'var(--radius)',
        padding: '48px 16px',
        textAlign: 'center',
        fontSize: 'var(--text-base)',
        color: 'var(--text-muted)',
      }}
    >
      {/* ⛔ `--text-secondary`, not `--text-primary`: this panel is a statement
          that there is nothing to act on, and a full-contrast heading in the
          middle of a page reads as a result. It must be legible and must not
          compete with the real content above it. */}
      {title && (
        <div style={{ fontSize: 'var(--text-lg)', fontWeight: 600, color: 'var(--text-secondary)' }}>
          {title}
        </div>
      )}
      {/* ⛔ `max-width` in CH, so a long explanation wraps to a readable
          measure instead of a single line across a 1440px page. Several of
          these messages are two sentences, because a gap that does not say
          WHY is only marginally better than a blank. */}
      <div style={{ maxWidth: '68ch' }}>{message}</div>
    </div>
  );
}
