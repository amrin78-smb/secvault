const COLOR_CLASSES = {
  danger: 'bg-danger/15 text-danger',
  warning: 'bg-warning/15 text-warning',
  success: 'bg-success/15 text-success',
  info: 'bg-info/15 text-info',
  muted: 'bg-bg-elevated text-text-muted',
};

export default function Badge({ color = 'muted', children, className = '' }) {
  const colorClasses = COLOR_CLASSES[color] || COLOR_CLASSES.muted;

  return (
    <span
      className={`inline-flex items-center whitespace-nowrap rounded px-2 py-0.5 text-xs font-medium ${colorClasses} ${className}`}
    >
      {children}
    </span>
  );
}
