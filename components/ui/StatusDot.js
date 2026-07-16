const STATUS_COLOR = {
  green: 'var(--green)',
  amber: 'var(--yellow)',
  red: 'var(--red)',
  grey: 'var(--text-muted)',
};

export default function StatusDot({ status = 'grey', className = '' }) {
  const color = STATUS_COLOR[status] || STATUS_COLOR.grey;
  return (
    <span
      className={className}
      title={status}
      aria-label={`status: ${status}`}
      style={{
        display: 'inline-block',
        width: 10,
        height: 10,
        flexShrink: 0,
        borderRadius: '50%',
        background: color,
      }}
    />
  );
}
