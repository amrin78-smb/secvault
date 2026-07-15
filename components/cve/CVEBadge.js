// KEV badge — per CLAUDE.md design system: solid danger background, white text, "KEV"
// label. Renders nothing when the advisory is not KEV-listed.
export default function CVEBadge({ kevListed }) {
  if (!kevListed) return null;

  return (
    <span className="inline-flex items-center rounded bg-danger px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-white">
      KEV
    </span>
  );
}
