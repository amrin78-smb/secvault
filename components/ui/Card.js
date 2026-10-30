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

/**
 * ⛔ THE HEADING LAYER, AND IT WAS BEING BYPASSED (v2.215.0). Every dashboard
 * widget rolled its own `headingStyle` instead of using this: 12px, UPPERCASE,
 * .06em tracked, on --text-muted — a LABEL treatment applied to a HEADING, so
 * the card title rendered smaller and fainter than the body text beneath it.
 * With nothing on the page announcing itself as a title, structure had to be
 * read off the boxes, which is very likely why more boxes kept being added.
 *
 * `compact` selects .card-title-compact (14px / 600 / --text-primary, sentence
 * case) for widget-grid cards; the default .card-title (18px) stays for
 * page-level cards. Both already existed in app/globals.css and both are the
 * right treatment — only adoption was missing.
 */
export function CardTitle({ children, className = '', style, compact = false }) {
  const base = compact ? 'card-title-compact' : 'card-title';
  return <div className={`${base} ${className}`} style={style}>{children}</div>;
}

export function CardBody({ children, className = '', style }) {
  return <div className={`card-body ${className}`} style={style}>{children}</div>;
}
