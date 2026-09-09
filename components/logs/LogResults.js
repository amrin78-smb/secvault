import Link from 'next/link';
import Card, { CardBody } from '../ui/Card';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';
import Pagination from '../ui/Pagination';
import { classifyAction } from '../../lib/syslog/actions';

// Results for a raw log search. Server component — the rows arrive already
// queried by the page.
//
// ⛔ THE TRUNCATION NOTICE IS NOT DECORATION. Presenting the first 100 of
// 4,000,000 matches as if it were the whole answer is how an investigator
// concludes "that host made three connections" and is wrong. Both the cap and
// a clamped time window are stated in words above the table.

// ⛔ THREE-STATE, from the SHARED vocabulary. This was a private deny list —
// the fifth in the codebase — with two compounding faults:
//
//   1. Anything not in it rendered as a GREEN "success" badge. Measured live
//      over one window that meant ~78,000 genuinely BLOCKED events (`blocked`
//      14,843 and `timeout` 63,079) and ~290,000 unclassifiable ones
//      (`ssl-login-fail`, `alert`, `dns`, `negotiate`, ...) were all shown to
//      the reader as allowed. A failed VPN login looked like a permitted
//      session.
//   2. It listed `reset-client`/`reset-server`, which this fleet never emits —
//      the real Fortinet verbs are `client-rst`/`server-rst`. It was written
//      from documentation rather than captured logs.
//
// lib/syslog/actions.js exists precisely to end this: a verb in neither set is
// UNKNOWN and must never be folded into either one.
function actionTone(a) {
  const verdict = classifyAction(a);
  if (verdict === 'allowed') return 'success';
  if (verdict === 'blocked') return 'danger';
  return 'muted';
}

function actionTitle(a) {
  const verdict = classifyAction(a);
  if (verdict === 'allowed') return `${a} — session was permitted`;
  if (verdict === 'blocked') return `${a} — session was refused`;
  return `${a} — SecVault has not classified this vendor action as allowed or blocked`;
}

function fmtTime(v, tzAssumed) {
  if (!v) return '—';
  const d = v instanceof Date ? v : new Date(v);
  if (Number.isNaN(d.getTime())) return '—';
  const s = d.toISOString().replace('T', ' ').slice(0, 19);
  // The caveat travels with the value: the device gave no timezone, so the
  // collector's own zone was assumed. Investigations turn on timestamps.
  return tzAssumed ? `${s} ~` : s;
}

// Which compressed archive file holds this event's raw line. Mirrors
// lib/syslog/archive.js's fileNameFor() — UTC day, same key as the partition.
// Named rather than linked: the file is on the server's disk, not served over
// HTTP, and an operator reads it with `zgrep`.
function archiveFileFor(v) {
  if (!v) return 'the daily archive';
  const d = v instanceof Date ? v : new Date(v);
  if (Number.isNaN(d.getTime())) return 'the daily archive';
  return `syslog-${d.toISOString().slice(0, 10).replace(/-/g, '')}.log.gz`;
}

// ⛔ ONE ROW, ONE LINE. Each row used to stack up to FIVE blocks in the
// Detail column (threat, host, category, class/subtype, raw) and three in
// Source, which made a row ~105px tall — so a 100-row page was roughly nine
// screens of scrolling and the pagination at the bottom was effectively
// unreachable. A forensic log table is scanned, not read: the operator is
// looking for the row that matters, and every row that is four lines tall is
// three lines of noise between them and it.
//
// ⛔ NOTHING IS DROPPED. The stacked values are joined onto one line with
// middots and truncated with an ellipsis; the full text is on the title
// attribute, and the raw line keeps its own disclosure. Hiding a field
// outright would be a different and much worse change — this is the same
// rule as the density switch, which may compress a row but never remove a
// fact from it.
function Cell({ children, mono, muted, nowrap, maxWidth, title }) {
  return (
    <td
      title={title}
      style={{
        padding: 'var(--row-pad-y) var(--row-pad-x)',
        fontSize: 'var(--row-font)',
        fontFamily: mono ? 'var(--font-mono)' : undefined,
        color: muted ? 'var(--text-muted)' : 'var(--text-primary)',
        whiteSpace: nowrap === false ? undefined : 'nowrap',
        maxWidth,
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        verticalAlign: 'middle',
      }}
    >
      {children === null || children === undefined || children === '' ? (
        <span style={{ color: 'var(--text-muted)' }}>—</span>
      ) : children}
    </td>
  );
}

// Joins the parts of a former stack onto one line. Falsy parts drop out, so
// a row with no user and no country is just the address.
function inline(parts) {
  return parts.filter((p) => p !== null && p !== undefined && p !== '');
}

const DOT = <span style={{ color: 'var(--text-muted)' }}> · </span>;

export default function LogResults({ result, deviceNames, searchParams }) {
  if (!result) return null;

  if (result.error) {
    return (
      <Card>
        <CardBody>
          {/* ⛔ An error must never render as "no results". */}
          <div style={{ color: 'var(--red)', fontSize: 'var(--text-base)' }}>
            <strong>Search failed.</strong> {result.error}
          </div>
        </CardBody>
      </Card>
    );
  }

  const rows = result.rows || [];
  const windowText =
    `${fmtTime(result.from)} to ${fmtTime(result.to)} UTC`;

  return (
    <Card>
      <CardBody>
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 10,
            alignItems: 'baseline',
            marginBottom: 12,
            fontSize: 'var(--text-sm)',
            color: 'var(--text-muted)',
          }}
        >
          <strong style={{ color: 'var(--text-primary)', fontSize: 'var(--text-base)' }}>
            {rows.length.toLocaleString()}{result.truncated ? '+' : ''} event
            {rows.length === 1 ? '' : 's'}
          </strong>
          <span>{windowText}</span>
          <span>· {result.ms} ms</span>
        </div>

        {result.truncated ? (
          <div
            style={{
              marginBottom: 12,
              padding: '9px 12px',
              borderRadius: 'var(--radius-sm)',
              background: 'var(--tint-warn)',
              color: 'var(--tint-warn-fg)',
              fontSize: 'var(--text-sm)',
            }}
          >
            More matches exist beyond this page. Use <strong>Next</strong> below to page
            through them, or narrow the window to make the set smaller.
          </div>
        ) : null}

        {result.clamped ? (
          <div
            style={{
              marginBottom: 12,
              padding: '9px 12px',
              borderRadius: 'var(--radius-sm)',
              background: 'var(--tint-warn)',
              color: 'var(--tint-warn-fg)',
              fontSize: 'var(--text-sm)',
            }}
          >
            The requested range was wider than a single search may scan, so it
            was shortened to the window shown above. Narrow the window and
            search again to reach older events.
          </div>
        ) : null}

        {/* ⛔ The depth cap must be stated. At the last page the Next control
            pointed at a page that clamped straight back, so the same rows
            re-rendered with the label and the address bar disagreeing and no
            explanation — a silent truncation sitting next to two that are
            correctly surfaced. */}
        {result.pageCapped ? (
          <div
            style={{
              marginBottom: 12,
              padding: '9px 12px',
              borderRadius: 'var(--radius-sm)',
              background: 'var(--tint-warn)',
              color: 'var(--tint-warn-fg)',
              fontSize: 'var(--text-sm)',
            }}
          >
            Paging stops at page {result.maxPage}. Narrow the time window or add
            a filter to reach the events beyond it — deep paging over the raw
            log table is far slower than searching a smaller window.
          </div>
        ) : null}

        {Object.keys(result.rejected || {}).length > 0 ? (
          <div
            style={{
              marginBottom: 12,
              padding: '9px 12px',
              borderRadius: 'var(--radius-sm)',
              background: 'var(--tint-danger)',
              color: 'var(--tint-danger-fg)',
              fontSize: 'var(--text-sm)',
            }}
          >
            {/* ⛔ A dropped filter is surfaced, never silently ignored: a search
                that quietly discards "srcIp=10.1.1" returns everything and
                reads as a confident answer about that host. */}
            Ignored — not a valid value:{' '}
            {Object.entries(result.rejected).map(([k, v]) => `${k}="${v}"`).join(', ')}
          </div>
        ) : null}

        {rows.length === 0 ? (
          <EmptyState message="Nothing in this window matched. Widen the time range or remove a filter — note that raw events are only kept for a few days." />
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 1000 }}>
              <thead>
                <tr>
                  {['Time (UTC)', 'Device', 'Action', 'Source', 'Destination', 'App / Rule', 'Detail'].map((h) => (
                    <th
                      key={h}
                      style={{
                        textAlign: 'left',
                        padding: '8px 10px',
                        fontSize: 10,
                        letterSpacing: '0.07em',
                        textTransform: 'uppercase',
                        color: 'var(--text-muted)',
                        borderBottom: '1px solid var(--border)',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id} style={{ borderBottom: '1px solid var(--border-subtle, var(--border))' }}>
                    <Cell mono nowrap>{fmtTime(r.receivedAt, r.tzAssumed)}</Cell>
                    <Cell nowrap>
                      {r.deviceId && deviceNames?.[r.deviceId] ? (
                        <Link href={`/devices/${r.deviceId}`} style={{ color: 'var(--text-primary)' }}>
                          {deviceNames[r.deviceId]}
                        </Link>
                      ) : (
                        <>
                          <span style={{ fontFamily: 'ui-monospace, Consolas, monospace' }}>
                            {String(r.sourceIp || '').replace('/32', '')}
                          </span>{' '}
                          <Badge color="warning">unmanaged</Badge>
                        </>
                      )}
                    </Cell>
                    <Cell nowrap>
                      {r.action ? (
                        <Badge color={actionTone(r.action)} title={actionTitle(r.action)}>
                          {r.action}
                        </Badge>
                      ) : null}
                    </Cell>
                    <Cell
                      mono
                      maxWidth={230}
                      title={inline([String(r.srcIp || '').replace('/32', ''), r.srcUser, r.srcCountry]).join(' · ')}
                    >
                      {String(r.srcIp || '').replace('/32', '') || null}
                      {r.srcPort ? <span style={{ color: 'var(--text-muted)' }}>:{r.srcPort}</span> : null}
                      {r.srcUser ? <>{DOT}<span style={{ color: 'var(--accent-teal)' }}>{r.srcUser}</span></> : null}
                      {r.srcCountry ? <>{DOT}<span style={{ color: 'var(--text-muted)' }}>{r.srcCountry}</span></> : null}
                    </Cell>
                    <Cell
                      mono
                      maxWidth={210}
                      title={inline([String(r.dstIp || '').replace('/32', ''), r.dstCountry]).join(' · ')}
                    >
                      {String(r.dstIp || '').replace('/32', '') || null}
                      {r.dstPort ? <span style={{ color: 'var(--text-muted)' }}>:{r.dstPort}</span> : null}
                      {r.dstCountry ? <>{DOT}<span style={{ color: 'var(--text-muted)' }}>{r.dstCountry}</span></> : null}
                    </Cell>
                    <Cell
                      maxWidth={190}
                      title={inline([r.application, r.ruleName]).join(' · ')}
                    >
                      {r.application || null}
                      {r.ruleName ? <>{r.application ? DOT : null}<span style={{ color: 'var(--text-muted)' }}>{r.ruleName}</span></> : null}
                    </Cell>
                    {/* ⛔ FOUR STACKED BLOCKS BECAME ONE LINE. This cell alone
                        made a row ~105px tall, so a page of results was several
                        screens and the pagination underneath it was effectively
                        unreachable. Same rule as everywhere else in this pass:
                        NOTHING IS DROPPED — the values are joined with middots,
                        the full text is on the title attribute, and the raw line
                        keeps its own disclosure below. */}
                    <Cell
                      maxWidth={330}
                      title={inline([
                        r.threatName ? r.threatName + (r.threatSeverity ? ` (${r.threatSeverity})` : '') : null,
                        r.urlHostname,
                        r.urlCategory,
                        r.logClass ? `${r.logClass}${r.logSubtype ? '/' + r.logSubtype : ''}` : null,
                      ]).join(' · ')}
                    >
                      {r.threatName ? (
                        <span style={{ color: 'var(--red)' }}>
                          {r.threatName}
                          {r.threatSeverity ? ` (${r.threatSeverity})` : ''}
                        </span>
                      ) : null}
                      {r.urlHostname ? <>{r.threatName ? DOT : null}{r.urlHostname}</> : null}
                      {r.urlCategory ? (
                        <>{r.threatName || r.urlHostname ? DOT : null}<span style={{ color: 'var(--text-muted)' }}>{r.urlCategory}</span></>
                      ) : null}
                      {r.logClass ? (
                        <>
                          {r.threatName || r.urlHostname || r.urlCategory ? DOT : null}
                          <span style={{ color: 'var(--text-muted)' }}>
                            {r.logClass}{r.logSubtype ? `/${r.logSubtype}` : ''}
                          </span>
                        </>
                      ) : null}
                      {/* ⛔ A null raw line does NOT mean nothing was received.
                          Ordinary allowed traffic keeps its raw text in the
                          compressed archive rather than the database; the raw
                          line is ALWAYS kept in the DB for anything unparsed,
                          non-traffic or denied. Rendering an empty box here
                          would read as "no evidence", which is the opposite of
                          the truth — so this names the file it is in. */}
                      {r.message ? (
                        <details style={{ marginTop: 3 }}>
                          <summary style={{ cursor: 'pointer', color: 'var(--text-muted)', fontSize: 10 }}>
                            raw
                          </summary>
                          <pre
                            style={{
                              margin: '4px 0 0',
                              padding: 8,
                              background: 'var(--bg-primary)',
                              borderRadius: 'var(--radius-sm)',
                              fontSize: 10,
                              whiteSpace: 'pre-wrap',
                              wordBreak: 'break-all',
                              maxWidth: 620,
                            }}
                          >
                            {r.message}
                          </pre>
                        </details>
                      ) : (
                        <div style={{ marginTop: 3, fontSize: 10, color: 'var(--text-muted)' }}>
                          raw line in archive{' '}
                          <code style={{ fontSize: 10 }}>{archiveFileFor(r.receivedAt)}</code>
                        </div>
                      )}
                    </Cell>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* ⛔ hasMore, not total. An exact COUNT over even a one-hour window was
            measured at 43 seconds on this fleet, so this set is genuinely
            uncountable and the control says "Page 3" rather than inventing a
            "of 47" that nobody verified. */}
        {rows.length > 0 ? (
          <Pagination
            basePath="/logs"
            searchParams={searchParams}
            page={result.page}
            pageSize={result.limit}
            total={null}
            hasMore={result.hasMore}
            pageSizes={[50, 100, 200]}
            label="events"
          />
        ) : null}
      </CardBody>
    </Card>
  );
}
