export default function EmptyState({ message = 'Nothing to show.' }) {
  return (
    <div className="flex items-center justify-center rounded border border-dashed border-border py-12 text-center text-sm text-text-muted">
      {message}
    </div>
  );
}
