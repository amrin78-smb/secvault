// Suite `.badge` + color-variant classes (app/globals.css). `color` keeps the
// same prop values callers already use across the app (danger/warning/
// success/info/muted/purple/teal) — mapped here to the suite's badge-<hue>
// naming so call sites don't need to change.
const COLOR_CLASS = {
  danger: 'badge-red',
  warning: 'badge-yellow',
  success: 'badge-green',
  info: 'badge-blue',
  muted: 'badge-gray',
  purple: 'badge-purple',
  teal: 'badge-teal',
  orange: 'badge-orange',
};

export default function Badge({ color = 'muted', children, className = '' }) {
  const colorClass = COLOR_CLASS[color] || COLOR_CLASS.muted;
  return <span className={`badge ${colorClass} ${className}`}>{children}</span>;
}
