const STATUS_CLASSES = {
  green: 'bg-success',
  amber: 'bg-warning',
  red: 'bg-danger',
  grey: 'bg-text-muted',
};

export default function StatusDot({ status = 'grey', className = '' }) {
  const statusClasses = STATUS_CLASSES[status] || STATUS_CLASSES.grey;

  return (
    <span
      className={`inline-block h-2.5 w-2.5 shrink-0 rounded-full ${statusClasses} ${className}`}
      title={status}
      aria-label={`status: ${status}`}
    />
  );
}
