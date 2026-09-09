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

// `title` is forwarded because a badge is where this app puts a LABEL over a
// raw vendor value — "Login failed" for `ssl-login-fail`, "Synchronized" for
// `synchronized`. The raw string is the evidence and must stay reachable on
// hover; without this prop the attribute was silently dropped and the friendly
// word became the only thing the operator could ever see.
export default function Badge({ color = 'muted', children, className = '', title }) {
  const colorClass = COLOR_CLASS[color] || COLOR_CLASS.muted;
  return (
    <span className={`badge ${colorClass} ${className}`} title={title}>
      {children}
    </span>
  );
}
