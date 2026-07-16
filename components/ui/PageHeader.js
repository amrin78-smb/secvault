// Suite `.page-header`/`.page-title`/`.page-subtitle` classes — replaces the
// ad hoc <h1>/<p> pairs previously at the top of every page. `actions` is an
// optional right-side slot (buttons, filters) rendered flush with the title.
export default function PageHeader({ title, subtitle, actions }) {
  return (
    <div className="page-header">
      <div>
        <div className="page-title">{title}</div>
        {subtitle && <div className="page-subtitle">{subtitle}</div>}
      </div>
      {actions && <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>{actions}</div>}
    </div>
  );
}
