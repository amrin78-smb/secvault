// Suite `.card` class (app/globals.css) — bg-card surface, border, radius,
// shadow-sm. Optional CardHeader/CardTitle/CardBody sub-components for pages
// that want the standard header/body split; plain Card still works as a bare
// container for callers that lay out their own padding.
//
// All four accept `style`. The sub-components did NOT until 2026-09-08, so the
// `display:flex` every syslog widget passed to CardTitle -- to sit an IconChip
// beside its text -- was silently dropped. React does not warn on an unused
// prop, so it rendered subtly wrong and looked deliberate.
export default function Card({ className = '', children, style }) {
  return (
    <div className={`card ${className}`} style={style}>
      {children}
    </div>
  );
}

export function CardHeader({ children, className = '', style }) {
  return <div className={`card-header ${className}`} style={style}>{children}</div>;
}

export function CardTitle({ children, className = '', style }) {
  return <div className={`card-title ${className}`} style={style}>{children}</div>;
}

export function CardBody({ children, className = '', style }) {
  return <div className={`card-body ${className}`} style={style}>{children}</div>;
}
