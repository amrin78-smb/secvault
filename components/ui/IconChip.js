// Small colored icon badge for card/section headers -- same visual language as
// the sidebar's nav chip (components/layout/Sidebar.js's .sv-nav-chip), just
// always-colored since it sits on a card rather than the dark shell.
//
// `color`/`bg` are CSS color values, passed as a PAIR: a foreground and a
// matching low-opacity surface behind it. Every call site now passes design
// tokens — `color="var(--tint-danger-fg)" bg="var(--tint-danger)"` — rather
// than the original literal hex + rgba(). The values land on --chip-color /
// --chip-bg custom properties, and that nested var() indirection resolves
// correctly.
//
// ⛔ Pass a MATCHED tint pair, never a raw hue for `bg`. A raw status hue as a
// background does not adapt between themes, which is the one thing the tint
// pairs exist to guarantee.
export default function IconChip({ icon: Icon, color, bg }) {
  return (
    <span className="widget-icon-chip" style={{ '--chip-color': color, '--chip-bg': bg }}>
      <Icon width={14} height={14} />
    </span>
  );
}
