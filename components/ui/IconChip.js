// Small colored icon badge for card/section headers -- same visual
// language as the sidebar's per-route nav chips (components/layout/
// Sidebar.js's .sv-nav-chip), just always-colored since it sits on a
// light card background. `color`/`bg` are literal CSS color values (a
// hex + a matching low-opacity rgba()), same pairing convention
// Sidebar.js's NAV array already uses.
export default function IconChip({ icon: Icon, color, bg }) {
  return (
    <span className="widget-icon-chip" style={{ '--chip-color': color, '--chip-bg': bg }}>
      <Icon width={14} height={14} />
    </span>
  );
}
