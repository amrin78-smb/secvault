import Card, { CardBody } from '../ui/Card';
import {
  LOG_SEARCH_FIELDS,
  ESSENTIAL_LOG_FIELDS,
  ADVANCED_LOG_FIELDS,
  HIDDEN_LOG_FIELDS,
  advancedIsApplied,
  logFilterChips,
  withoutLogFilter,
} from '../../lib/logSearchFields';

// A plain GET <form>. No client JS, no useState — the URL IS the query, which
// makes a search linkable, bookmarkable, pasteable into a ticket, and
// survivable across a refresh. Same server-driven convention as the
// dashboard's ?tab= and /topology's ?view=.
//
// Module top level, never nested inside another component — CLAUDE.md's React
// rule. This is a plain function returning JSX, called imperatively.

const LABEL = {
  display: 'block',
  fontSize: 11,
  fontWeight: 700,
  letterSpacing: '0.06em',
  textTransform: 'uppercase',
  color: 'var(--text-muted)',
  marginBottom: 4,
};

// ⛔ ONE HEIGHT FOR EVERY CONTROL ON THE ACTION ROW, stated once.
// The row is `align-items: flex-end`, so it lines up the BOTTOM of each
// control and lets the tops fall where they may. That is only invisible while
// the controls happen to be the same height, and they were not: the Search
// button was hand-rolled with `border: none` and the Reset link with
// `border: 1px`, which is a two-pixel difference on its own, and a <select>'s
// intrinsic height is a user-agent decision that differs again between
// browsers and platforms. Pinning the height is what makes the row square on
// every machine rather than only on the one it was eyeballed on.
const CONTROL_H = 34;

const FIELD = {
  width: '100%',
  height: CONTROL_H,
  boxSizing: 'border-box',
  padding: '7px 9px',
  fontSize: 'var(--text-sm)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)',
  background: 'var(--bg-card)',
  color: 'var(--text-primary)',
};

function Field({ name, label, value, placeholder, type }) {
  return (
    <div>
      <label style={LABEL} htmlFor={`f-${name}`}>{label}</label>
      <input
        id={`f-${name}`}
        name={name}
        type={type || 'text'}
        defaultValue={value || ''}
        placeholder={placeholder || ''}
        style={FIELD}
        autoComplete="off"
      />
    </div>
  );
}


// ⛔ ONE CONTROL RENDERER OVER THE REGISTRY, not nineteen hand-written ones.
// Module top level, never nested — CLAUDE.md's React rule.
function Control({ def, value, sources }) {
  if (def.control === 'select') {
    const opts = def.options
      || (sources[def.source] || []).map((o) => (
        typeof o === 'string' ? { value: o, label: o } : o
      ));
    return (
      <div>
        <label style={LABEL} htmlFor={`f-${def.name}`}>{def.label}</label>
        <select id={`f-${def.name}`} name={def.name} defaultValue={value || ''} style={FIELD}>
          <option value="">{def.emptyLabel || 'Any'}</option>
          {opts.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
      </div>
    );
  }
  return (
    <Field
      name={def.name}
      label={def.label}
      value={value}
      placeholder={def.placeholder}
      type={def.type}
    />
  );
}

export default function LogSearchForm({ params, devices, options }) {
  const p = params || {};
  const sources = {
    devices: (devices || []).map((d) => ({ value: d.id, label: d.name })),
    logClasses: options?.logClasses || [],
    actions: options?.actions || [],
  };
  const grid = {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(165px, 1fr))',
    gap: 12,
  };

  // ⛔ THE DISCLOSURE OPENS ITSELF WHEN SOMETHING INSIDE IT IS APPLIED, the
  // same rule FilterBar follows and the half of §8 that actually matters:
  // "do not hide active advanced filters without an indicator." Rendered as
  // <details open> on the SERVER, so it is correct on first paint with no
  // client JavaScript — which is the whole reason this form is a plain GET.
  const openAdvanced = advancedIsApplied(p);
  const chips = logFilterChips(p);
  const limit = LOG_SEARCH_FIELDS.find((f) => f.name === 'limit');

  return (
    <Card>
      <CardBody>
        <form method="get" action="/logs">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={grid}>
              {ESSENTIAL_LOG_FIELDS.map((def) => (
                <Control key={def.name} def={def} value={p[def.name]} sources={sources} />
              ))}
            </div>

            {/* ⛔ EVERY ACCEPTED PARAM THAT HAS NO CONTROL IS CARRIED HERE.
                vendor, logSubtype, protocol, sourceIp, urlCategory and
                srcPort are all accepted by the page and arrive on links from
                elsewhere in the product; none had a field, so pressing
                Search DELETED them and silently widened the search while the
                form looked unchanged. A hidden input preserves the value and
                the chip below makes it visible and removable. */}
            {HIDDEN_LOG_FIELDS.map((def) => (
              p[def.name]
                ? <input key={def.name} type="hidden" name={def.name} value={p[def.name]} />
                : null
            ))}

            <details className="log-advanced" open={openAdvanced || undefined}>
              <summary className="log-advanced-summary">
                More filters
                {/* ⛔ A COUNT ON THE TOGGLE, so a collapsed panel still says
                    it is doing something. The auto-open above handles the
                    first load; this handles the operator who collapses it
                    again and scrolls. */}
                {openAdvanced && (
                  <span className="log-advanced-count">
                    {[...ADVANCED_LOG_FIELDS, ...HIDDEN_LOG_FIELDS]
                      .filter((f) => p[f.name]).length} applied
                  </span>
                )}
              </summary>
              <div style={{ ...grid, marginTop: 12 }}>
                {ADVANCED_LOG_FIELDS.map((def) => (
                  <Control key={def.name} def={def} value={p[def.name]} sources={sources} />
                ))}
              </div>
            </details>

            <div style={{ display: 'flex', gap: 10, alignItems: 'flex-end' }}>
              <div style={{ width: 130 }}>
                {/* ⛔ "Max results" was a LIE ABOUT PAGING, and it is why log
                    search looked like it had none. The value is the PAGE SIZE:
                    the search fetches this many rows plus one, and the extra
                    row is what drives the Next control. Labelled "Max results",
                    an operator reads 100 rows as the complete answer, capped —
                    so they never look for pagination, and the "More matches
                    exist" banner below reads as a contradiction rather than an
                    invitation. Verified live: paging itself works, returning
                    distinct rows per page in 18-25ms. Only the word was wrong. */}
                <label style={LABEL} htmlFor="f-limit">{limit.label}</label>
                <select id="f-limit" name="limit" defaultValue={p.limit || '50'} style={FIELD}>
                  {/* 50 first and default, matching DEFAULT_LIMIT in
                      lib/syslog/logSearch.js: it fits on one screen together
                      with the pagination control below the table. */}
                  {limit.options.map((o) => (
                    <option key={o.value} value={o.value}>{o.label}</option>
                  ))}
                </select>
              </div>
              {/* ⛔ THE SHARED .btn CLASSES, not a hand-rolled pair. */}
              <button type="submit" className="btn btn-primary" style={{ height: CONTROL_H }}>
                Search
              </button>
              <a href="/logs" className="btn btn-secondary" style={{ height: CONTROL_H }}>
                Reset
              </a>
            </div>

            {/* ⛔ THE CHIPS ARE THE SECOND HALF OF THE DISCLOSURE RULE. The
                open panel says "there are advanced filters here"; the chips
                say WHICH, including the six that have no control at all. A
                chip removes exactly its own parameter and resets `page`,
                because a page number from a larger result set lands past the
                end of a smaller one. */}
            {chips.length > 0 && (
              <div className="filter-summary">
                <span className="filter-count">
                  {chips.length} filter{chips.length === 1 ? '' : 's'} applied
                </span>
                {chips.map((c) => (
                  <a
                    key={c.name}
                    className="filter-chip"
                    data-unknown={c.known ? undefined : ''}
                    href={withoutLogFilter(p, c.name)}
                    title={c.known ? `Remove ${c.label}` : `Remove ${c.name} — this filter has no control on this form`}
                  >
                    {c.label}: {c.value}
                    <span aria-hidden="true"> ×</span>
                    <span className="sr-only"> (remove)</span>
                  </a>
                ))}
                <a className="filter-clear" href="/logs">Clear filters</a>
              </div>
            )}
          </div>
        </form>
      </CardBody>
    </Card>
  );
}
