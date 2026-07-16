// Suite `.card` class (app/globals.css) — bg-card surface, border, radius,
// shadow-sm. Optional CardHeader/CardTitle/CardBody sub-components for pages
// that want the standard header/body split; plain Card still works as a bare
// container for callers that lay out their own padding.
export default function Card({ className = '', children, style }) {
  return (
    <div className={`card ${className}`} style={style}>
      {children}
    </div>
  );
}

export function CardHeader({ children, className = '' }) {
  return <div className={`card-header ${className}`}>{children}</div>;
}

export function CardTitle({ children, className = '' }) {
  return <div className={`card-title ${className}`}>{children}</div>;
}

export function CardBody({ children, className = '' }) {
  return <div className={`card-body ${className}`}>{children}</div>;
}
