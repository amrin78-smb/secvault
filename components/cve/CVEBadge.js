// KEV badge — per CLAUDE.md design system: solid danger background, white text, "KEV"
// label. Renders nothing when the advisory is not KEV-listed.
//
// Deliberately NOT built on <Badge> (components/ui/Badge.js): Badge's color="danger"
// resolves to the `.badge-red` class, which is a soft *tint* (background:
// var(--tint-danger), foreground: var(--tint-danger-fg)) — the same tinted treatment
// used for every other badge in the app, including PriorityBadge's "Patch Now". KEV
// specifically needs to stand out from that as a SOLID fill per CLAUDE.md's Design
// System section ("KEV badge -> solid --danger background, white text"), so this stays
// a hand-rolled solid-fill span instead.
export default function CVEBadge({ kevListed }) {
  if (!kevListed) return null;

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        borderRadius: 'var(--radius-sm)',
        padding: '3px 7px',
        fontSize: '10px',
        fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.04em',
        background: 'var(--red)',
        color: '#fff',
        whiteSpace: 'nowrap',
      }}
    >
      KEV
    </span>
  );
}
