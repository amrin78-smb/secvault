import { pool } from '../../lib/db';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import StatCard from '../ui/StatCard';
import EmptyState from '../ui/EmptyState';

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

export default async function ObjectsTab({ deviceId }) {
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
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
          <Table>
            <colgroup>
              <col style={{ width: '25%' }} />
              <col style={{ width: '15%' }} />
              <col style={{ width: '25%' }} />
              <col style={{ width: '35%' }} />
            </colgroup>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Value / Members</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {unused.map((o) => (
                <tr key={o.id}>
                  <td title={o.name}>{o.name}</td>
                  <td>{typeBadge(o.object_type)}</td>
                  <td title={valueOrMembers(o)}>{valueOrMembers(o)}</td>
                  <td style={{ color: 'var(--text-secondary)' }}>{detailFor(o, 'unused')}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </div>

      <div>
        <h3 style={{ fontSize: 'var(--text-md)', marginBottom: 8 }}>Duplicate Objects</h3>
        {duplicates.length === 0 ? (
          <EmptyState message="No duplicate objects found." />
        ) : (
          <Table>
            <colgroup>
              <col style={{ width: '25%' }} />
              <col style={{ width: '15%' }} />
              <col style={{ width: '25%' }} />
              <col style={{ width: '35%' }} />
            </colgroup>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Value</th>
                <th>Duplicate Of</th>
              </tr>
            </thead>
            <tbody>
              {duplicates.map((o) => (
                <tr key={o.id}>
                  <td title={o.name}>{o.name}</td>
                  <td>{typeBadge(o.object_type)}</td>
                  <td title={o.value || ''}>{o.value || '—'}</td>
                  <td style={{ color: 'var(--text-secondary)' }}>{detailFor(o, 'duplicate')}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </div>
    </div>
  );
}
