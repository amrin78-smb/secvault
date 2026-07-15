export default function Card({ className = '', children }) {
  return (
    <div className={`rounded-lg border border-border bg-bg-surface ${className}`}>
      {children}
    </div>
  );
}
