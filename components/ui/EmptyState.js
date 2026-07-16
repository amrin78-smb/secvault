export default function EmptyState({ message = 'Nothing to show.' }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        border: '1px dashed var(--border)',
        borderRadius: 'var(--radius)',
        padding: '48px 16px',
        textAlign: 'center',
        fontSize: 'var(--text-base)',
        color: 'var(--text-muted)',
      }}
    >
      {message}
    </div>
  );
}
