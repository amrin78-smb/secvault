import Card, { CardBody } from '../ui/Card';

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

const FIELD = {
  width: '100%',
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

function Select({ name, label, value, options }) {
  return (
    <div>
      <label style={LABEL} htmlFor={`f-${name}`}>{label}</label>
      <select id={`f-${name}`} name={name} defaultValue={value || ''} style={FIELD}>
        <option value="">Any</option>
        {options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </div>
  );
}

export default function LogSearchForm({ params, devices, options }) {
  const p = params || {};
  const grid = {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(165px, 1fr))',
    gap: 12,
  };

  return (
    <Card>
      <CardBody>
        <form method="get" action="/logs">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={grid}>
              {/* datetime-local so the operator picks a window rather than
                  typing an ISO string. A window is MANDATORY server-side —
                  blank here means the default last hour, never "everything". */}
              <Field name="from" label="From" value={p.from} type="datetime-local" />
              <Field name="to" label="To" value={p.to} type="datetime-local" />
              <Select
                name="deviceId"
                label="Device"
                value={p.deviceId}
                options={(devices || []).map((d) => ({ value: d.id, label: d.name }))}
              />
              <Select
                name="logClass"
                label="Log type"
                value={p.logClass}
                options={(options?.logClasses || []).map((v) => ({ value: v, label: v }))}
              />
              <Select
                name="action"
                label="Action"
                value={p.action}
                options={(options?.actions || []).map((v) => ({ value: v, label: v }))}
              />
            </div>
            <div style={grid}>
              <Field name="srcIp" label="Source IP" value={p.srcIp} placeholder="10.1.2.3 or 10.1.0.0/16" />
              <Field name="dstIp" label="Destination IP" value={p.dstIp} placeholder="8.8.8.8" />
              <Field name="dstPort" label="Dest port" value={p.dstPort} placeholder="443" />
              <Field name="srcUser" label="User" value={p.srcUser} placeholder="exact match" />
              <Field name="ruleName" label="Rule" value={p.ruleName} placeholder="exact match" />
            </div>
            <div style={grid}>
              <Field name="dstCountry" label="Dest country" value={p.dstCountry} placeholder="Singapore" />
              <Field name="application" label="Application" value={p.application} placeholder="ssl" />
              <Field name="threatName" label="Threat" value={p.threatName} placeholder="exact match" />
              <Field name="urlHostname" label="Website contains" value={p.urlHostname} placeholder="bing.com" />
              <Field name="q" label="Raw text contains" value={p.q} placeholder="slower — narrow the window" />
            </div>
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
                <label style={LABEL} htmlFor="f-limit">Rows per page</label>
                <select id="f-limit" name="limit" defaultValue={p.limit || '25'} style={FIELD}>
                  {/* 25 first and default: it fits on one screen together with
                      the pagination control below the table. The larger sizes
                      remain for deliberate wide scans. */}
                  {['25', '50', '100', '250', '500'].map((n) => (
                    <option key={n} value={n}>{n}</option>
                  ))}
                </select>
              </div>
              <button
                type="submit"
                style={{
                  padding: '8px 20px',
                  fontSize: 'var(--text-sm)',
                  fontWeight: 600,
                  color: '#fff',
                  background: 'var(--primary)',
                  border: 'none',
                  borderRadius: 'var(--radius-sm)',
                  cursor: 'pointer',
                }}
              >
                Search
              </button>
              <a
                href="/logs"
                style={{
                  padding: '8px 16px',
                  fontSize: 'var(--text-sm)',
                  color: 'var(--text-secondary)',
                  textDecoration: 'none',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                }}
              >
                Reset
              </a>
            </div>
          </div>
        </form>
      </CardBody>
    </Card>
  );
}
