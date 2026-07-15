export default function LoadingSpinner({ size = 20, className = '' }) {
  return (
    <span
      role="status"
      aria-label="Loading"
      className={`inline-block animate-spin rounded-full border-2 border-border border-t-accent align-middle ${className}`}
      style={{ width: size, height: size }}
    />
  );
}
