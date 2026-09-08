import { pool } from '../../lib/db';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import StatCard from '../ui/StatCard';
import EmptyState from '../ui/EmptyState';
import Pagination from '../ui/Pagination';
import { resolvePage, paginateArray, DEFAULT_PAGE_SIZE } from '../../lib/pagination';

// Rule Analysis Dashboard -- "Objects" tab (address/service object catalog
// hygiene: Unused Objects + Duplicate Objects, the ManageEngine Firewall
// Analyzer "Rule Management > Cleanup/Optimization > Objects" concept this
// mirrors). See CLAUDE.md's "Network Object Catalog" section for the full
// design -- this is a thin presentational layer over
// lib/engines/objectUsage.js's already-computed object_analysis_results,
// same "server component queries the DB directly" convention as every
// other tab on this page. Async server component, does its own pool.query.

const TYPE_LABEL = {
  address: 'Address',
  address_group: 'Address Group',
  service: 'Service',
  service_group: 'Service Group',
};

function typeBadge(type) {
  return <Badge color="muted">{TYPE_LABEL[type] || type || 'Unknown'}</Badge>;
}

function valueOrMembers(row) {
  if (row.value) return row.value;
  if (Array.isArray(row.members) && row.members.length > 0) return row.members.join(', ');
  return '—';
}

// ⛔ BUG FIXED 2026-07-18, found in a bug-sweep pass: this used to select
// finding_type and detail as two INDEPENDENT array_agg() calls. An object
// CAN carry both an 'unused' and a 'duplicate' finding at once (nothing in
// analyzeObjectUsage() makes them mutually exclusive), and the component
// below matched them up with a blind `finding_details.find(d => d)` —
// grabbing whichever detail string happened to be first, with no actual
// pairing to the finding_type it was rendering next to. For a dual-finding
// object this could show the 'unused' explanation text in the "Duplicate
// Of" column, or vice versa. Postgres also doesn't guarantee two
// independent array_agg() calls in one GROUP BY produce arrays in
// correlated order without an explicit ORDER BY inside each. Fixed by
// aggregating (finding_type, detail) as a single paired JSON object per
// finding, so there is no separate-arrays alignment problem at all — the
// component below now finds the right detail by finding_type, directly.
async function getObjectsWithFindings(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT
       no.id, no.object_type, no.name, no.value, no.members, no.collected_at,
       COALESCE(
         json_agg(
           json_build_object('finding_type', oar.finding_type, 'detail', oar.detail)
         ) FILTER (WHERE oar.finding_type IS NOT NULL),
         '[]'
       ) AS findings
     FROM network_objects no
     LEFT JOIN object_analysis_results oar ON oar.object_id = no.id
     WHERE no.device_id = $1
     GROUP BY no.id
     ORDER BY no.object_type ASC, no.name ASC`,
    [deviceId]
  );
  return result.rows.map((row) => ({
    ...row,
    findings: Array.isArray(row.findings) ? row.findings : [],
  }));
}

function detailFor(row, findingType) {
  const match = row.findings.find((f) => f && f.finding_type === findingType);
  return (match && match.detail) || '—';
}

// ── TWO LISTS, ONE `page` PARAM: why only Unused Objects is paginated ──────
// This tab renders two independent lists (Unused, Duplicate). Real pagination
// needs one query param per list, but components/ui/Pagination.js hardcodes
// `page` as its buildPageHref override key, so only ONE list on a given
// screen can carry page links without a `paramName` prop being added to that
// shared control — which is not this file's to change.
//
// Unused Objects gets it, because that is the list that actually grows
// without bound: it is every catalogued object no rule references, so it
// scales with the whole object catalog. Duplicates are pairs the engine
// actually found, a far smaller and self-limiting set, and it keeps the
// existing <details> "Show all (N)" collapse below — which already bounds its
// height AND states its true full count, so the reader is never shown ten
// rows as though they were all of them.
//
// See RiskyRulesTab.js's "PAGINATION: why the plain `page` param" block for
// why `page` (not ?opage=) is safe across the tabs of this page.
//
// OBJECT_ROW_LIMIT now governs the Duplicate table only.
const OBJECT_ROW_LIMIT = 10;

// This tab is an async SERVER component (it does its own pool.query), so it
// can't hold React state / use hooks. The collapse is done with a native
// <details>/<summary> element instead of useState — independent per table
// (each <details> tracks its own open state), no client boundary needed,
// presentation-only. The tiny stylesheet below swaps the summary label
// between "Show all (N)" (collapsed) and "Show fewer" (expanded).
const COLLAPSE_CSS = `
.sv-obj-overflow > summary {
  list-style: none;
  cursor: pointer;
  user-select: none;
  display: inline-block;
  padding: 4px 0;
  color: var(--primary);
  font-size: var(--text-sm);
  font-weight: 600;
}
.sv-obj-overflow > summary::-webkit-details-marker { display: none; }
.sv-obj-overflow > summary:hover { text-decoration: underline; }
.sv-obj-overflow .sv-obj-less { display: none; }
.sv-obj-overflow[open] .sv-obj-more { display: none; }
.sv-obj-overflow[open] .sv-obj-less { display: inline; }
`;

function ObjectColgroup() {
  return (
    <colgroup>
      <col style={{ width: '25%' }} />
      <col style={{ width: '15%' }} />
      <col style={{ width: '25%' }} />
      <col style={{ width: '35%' }} />
    </colgroup>
  );
}

// valueMode: 'members' → value-or-joined-members (Unused table); 'value' →
// raw value (Duplicate table). Titles preserved exactly as the originals.
function objectCell(o, valueMode) {
  if (valueMode === 'members') {
    const v = valueOrMembers(o);
    return { display: v, title: v };
  }
  return { display: o.value || '—', title: o.value || '' };
}

function ObjectRows({ rows, valueMode, detailType }) {
  return rows.map((o) => {
    const cell = objectCell(o, valueMode);
    return (
      <tr key={o.id}>
        <td title={o.name}>{o.name}</td>
        <td>{typeBadge(o.object_type)}</td>
        <td title={cell.title}>{cell.display}</td>
        <td style={{ color: 'var(--text-secondary)' }}>{detailFor(o, detailType)}</td>
      </tr>
    );
  });
}

// Plain (non-collapsing) table, used by the paginated Unused Objects list.
// The page window already bounds its height, so layering a "Show all" toggle
// on top would be a second, contradictory bounding mechanism — and one that
// would let a "show all" expand back to the endless list pagination exists to
// end. Module top level, per CLAUDE.md's never-nest-a-component rule.
function ObjectTable({ rows, headers, valueMode, detailType }) {
  return (
    <Table>
      <ObjectColgroup />
      <thead>
        <tr>
          {headers.map((h) => (
            <th key={h}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        <ObjectRows rows={rows} valueMode={valueMode} detailType={detailType} />
      </tbody>
    </Table>
  );
}

// Renders the first OBJECT_ROW_LIMIT rows always; any remainder goes inside a
// <details> whose <summary> is the "Show all (N)" / "Show fewer" toggle. The
// overflow table reuses the same fixed-width colgroup so it lines up under
// the first table as one continuous list.
function CollapsibleObjectTable({ rows, headers, valueMode, detailType, limit = OBJECT_ROW_LIMIT }) {
  const head = rows.slice(0, limit);
  const rest = rows.slice(limit);
  return (
    <div>
      <Table>
        <ObjectColgroup />
        <thead>
          <tr>
            {headers.map((h) => (
              <th key={h}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          <ObjectRows rows={head} valueMode={valueMode} detailType={detailType} />
        </tbody>
      </Table>
      {rest.length > 0 && (
        <details className="sv-obj-overflow" style={{ marginTop: 8 }}>
          <summary>
            <span className="sv-obj-more">Show all ({rows.length})</span>
            <span className="sv-obj-less">Show fewer</span>
          </summary>
          <div style={{ marginTop: 8 }}>
            <Table>
              <ObjectColgroup />
              <tbody>
                <ObjectRows rows={rest} valueMode={valueMode} detailType={detailType} />
              </tbody>
            </Table>
          </div>
        </details>
      )}
    </div>
  );
}

export default async function ObjectsTab({ deviceId, searchParams }) {
  const objects = await getObjectsWithFindings(pool, deviceId);

  if (objects.length === 0) {
    return (
      <EmptyState message="No object catalog collected for this device yet — this vendor's adapter may not support object collection yet, or a collect hasn't run since it was added. See CLAUDE.md's Network Object Catalog section for per-vendor status." />
    );
  }

  const unused = objects.filter((o) => o.findings.some((f) => f.finding_type === 'unused'));
  const duplicates = objects.filter((o) => o.findings.some((f) => f.finding_type === 'duplicate'));
  const lastCollectedAt = objects.reduce((latest, o) => {
    if (!o.collected_at) return latest;
    return !latest || new Date(o.collected_at) > new Date(latest) ? o.collected_at : latest;
  }, null);

  // The three StatCards above stay whole-catalog counts, not page counts — a
  // paginated view must never restate its window as the total.
  const pagedUnused = paginateArray(unused, resolvePage(searchParams?.page), DEFAULT_PAGE_SIZE);
  const pageParams = { ...(searchParams || {}), tab: 'objects' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* ⛔ dangerouslySetInnerHTML, not a JSX child.
                    <style> is a RAW TEXT element, but React SSR HTML-escapes a string
                    child — so the `>` child combinator shipped to the browser as `&gt;`
                    while the RSC flight payload carried the real `>`. The server HTML
                    therefore contained INVALID CSS (measured: 3 of 6 rules parsed, so
                    the <summary> kept its default disclosure triangle and body colour),
                    and React saw the text mismatch and threw: 9x #425 then #418 then
                    #423 on every load, discarding the server render and re-rendering the
                    whole route on the client. dangerouslySetInnerHTML injects the CSS
                    verbatim, which is what a raw-text element needs. */}
          <style dangerouslySetInnerHTML={{ __html: COLLAPSE_CSS }} />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 16 }}>
        <StatCard label="Total Objects" value={objects.length} color="var(--text-muted)" />
        <StatCard label="Unused" value={unused.length} color="var(--yellow)" />
        <StatCard label="Duplicate" value={duplicates.length} color="var(--blue)" />
      </div>

      {lastCollectedAt && (
        <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
          Object catalog last collected {new Date(lastCollectedAt).toISOString().replace('T', ' ').slice(0, 16)} UTC
        </p>
      )}

      <div>
        <h3 style={{ fontSize: 'var(--text-md)', marginBottom: 8 }}>Unused Objects</h3>
        {unused.length === 0 ? (
          <EmptyState message="No unused objects found." />
        ) : (
          <>
            <ObjectTable
              rows={pagedUnused.rows}
              headers={['Name', 'Type', 'Value / Members', 'Detail']}
              valueMode="members"
              detailType="unused"
            />
            <Pagination
              basePath={`/devices/${deviceId}/analysis`}
              searchParams={pageParams}
              page={pagedUnused.page}
              pageSize={pagedUnused.pageSize}
              total={pagedUnused.total}
              label="unused objects"
            />
          </>
        )}
      </div>

      <div>
        <h3 style={{ fontSize: 'var(--text-md)', marginBottom: 8 }}>Duplicate Objects</h3>
        {duplicates.length === 0 ? (
          <EmptyState message="No duplicate objects found." />
        ) : (
          <>
            {/* Not page-linked (see the OBJECT_ROW_LIMIT block above), so the
                true total is stated in words here — the <details> toggle below
                repeats it, but the count must be visible while collapsed too,
                or ten rows read as the whole set. */}
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 0, marginBottom: 8 }}>
              {duplicates.length.toLocaleString()} duplicate object{duplicates.length === 1 ? '' : 's'}
              {duplicates.length > OBJECT_ROW_LIMIT ? ` — showing the first ${OBJECT_ROW_LIMIT}` : ''}
            </p>
            <CollapsibleObjectTable
              rows={duplicates}
              headers={['Name', 'Type', 'Value', 'Duplicate Of']}
              valueMode="value"
              detailType="duplicate"
            />
          </>
        )}
      </div>
    </div>
  );
}
