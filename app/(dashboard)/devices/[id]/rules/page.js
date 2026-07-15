import Link from 'next/link';
import { pool } from '../../../../../lib/db';
import Table from '../../../../../components/ui/Table';
import EmptyState from '../../../../../components/ui/EmptyState';

export const dynamic = 'force-dynamic';

const PAGE_SIZE = 50;

const SORT_OPTIONS = {
  sequence: 'sequence_number ASC NULLS LAST',
  hits: 'hit_count DESC',
};

function actionBorderClass(action) {
  if (action === 'allow') return 'border-l-4 border-l-success';
  if (action === 'deny' || action === 'drop' || action === 'reject') return 'border-l-4 border-l-danger';
  return 'border-l-4 border-l-border';
}

function joinArray(value) {
  if (!Array.isArray(value) || value.length === 0) return '—';
  return value.join(', ');
}

// Builds a parameterized WHERE clause + params array — never interpolates raw query
// param values into SQL, only bound parameters.
function buildFilters(deviceId, searchParams) {
  const conditions = ['device_id = $1'];
  const params = [deviceId];

  const action = searchParams?.action;
  if (action) {
    params.push(action);
    conditions.push(`action = $${params.length}`);
  }

  const enabled = searchParams?.enabled;
  if (enabled === 'true' || enabled === 'false') {
    params.push(enabled === 'true');
    conditions.push(`enabled = $${params.length}`);
  }

  const zone = searchParams?.zone;
  if (zone) {
    params.push(JSON.stringify([zone]));
    const idx = params.length;
    conditions.push(`(src_zones @> $${idx}::jsonb OR dst_zones @> $${idx}::jsonb)`);
  }

  const search = searchParams?.search;
  if (search) {
    params.push(`%${search}%`);
    const idx = params.length;
    conditions.push(
      `(rule_name ILIKE $${idx} OR src_addresses::text ILIKE $${idx} OR dst_addresses::text ILIKE $${idx} OR services::text ILIKE $${idx})`
    );
  }

  return { where: `WHERE ${conditions.join(' AND ')}`, params };
}

async function getDevice(dbPool, id) {
  const result = await dbPool.query('SELECT id, name FROM devices WHERE id = $1', [id]);
  return result.rows[0] || null;
}

async function getRules(dbPool, deviceId, searchParams) {
  const { where, params } = buildFilters(deviceId, searchParams);
  const sortKey = SORT_OPTIONS[searchParams?.sort] ? searchParams.sort : 'sequence';
  const orderBy = SORT_OPTIONS[sortKey];

  const page = Math.max(1, parseInt(searchParams?.page || '1', 10) || 1);
  const offset = (page - 1) * PAGE_SIZE;

  const limitIdx = params.length + 1;
  const offsetIdx = params.length + 2;

  const [rowsResult, countResult] = await Promise.all([
    dbPool.query(
      `SELECT * FROM firewall_rules ${where} ORDER BY ${orderBy} LIMIT $${limitIdx} OFFSET $${offsetIdx}`,
      [...params, PAGE_SIZE, offset]
    ),
    dbPool.query(`SELECT COUNT(*)::int AS total FROM firewall_rules ${where}`, params),
  ]);

  return { rows: rowsResult.rows, total: countResult.rows[0]?.total ?? 0, page, sortKey };
}

function buildQueryString(searchParams, overrides) {
  const merged = { ...searchParams, ...overrides };
  const qs = new URLSearchParams();
  Object.entries(merged).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      qs.set(key, value);
    }
  });
  return qs.toString();
}

export default async function DeviceRulesPage({ params, searchParams }) {
  const device = await getDevice(pool, params.id);

  if (!device) {
    return (
      <div>
        <Link href="/devices" className="text-sm text-accent hover:underline">
          ← Back to devices
        </Link>
        <p className="mt-4 text-text-secondary">Device not found.</p>
      </div>
    );
  }

  const { rows, total, page, sortKey } = await getRules(pool, device.id, searchParams || {});
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const csvHref = `/api/devices/${device.id}/rules?format=csv&${buildQueryString(searchParams || {}, { page: undefined })}`;

  return (
    <div className="space-y-4">
      <div>
        <Link href={`/devices/${device.id}`} className="text-sm text-accent hover:underline">
          ← Back to {device.name}
        </Link>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-lg font-semibold text-text-primary">Firewall Rules — {device.name}</h1>
        <a
          href={csvHref}
          className="inline-flex items-center justify-center rounded border border-border bg-bg-surface px-3 py-1.5 text-sm text-text-primary hover:bg-bg-elevated"
        >
          Export CSV
        </a>
      </div>

      <form method="GET" className="flex flex-wrap items-end gap-3">
        <div className="flex flex-col gap-1">
          <label htmlFor="search" className="text-xs text-text-secondary">
            Search (name / IP / port)
          </label>
          <input
            id="search"
            type="text"
            name="search"
            defaultValue={searchParams?.search || ''}
            className="rounded border border-border bg-bg-base px-2 py-1 text-sm text-text-primary"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="action" className="text-xs text-text-secondary">
            Action
          </label>
          <select
            id="action"
            name="action"
            defaultValue={searchParams?.action || ''}
            className="rounded border border-border bg-bg-base px-2 py-1 text-sm text-text-primary"
          >
            <option value="">All actions</option>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
            <option value="drop">Drop</option>
            <option value="reject">Reject</option>
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="enabled" className="text-xs text-text-secondary">
            Enabled
          </label>
          <select
            id="enabled"
            name="enabled"
            defaultValue={searchParams?.enabled || ''}
            className="rounded border border-border bg-bg-base px-2 py-1 text-sm text-text-primary"
          >
            <option value="">All</option>
            <option value="true">Enabled</option>
            <option value="false">Disabled</option>
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="zone" className="text-xs text-text-secondary">
            Zone
          </label>
          <input
            id="zone"
            type="text"
            name="zone"
            defaultValue={searchParams?.zone || ''}
            className="rounded border border-border bg-bg-base px-2 py-1 text-sm text-text-primary"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="sort" className="text-xs text-text-secondary">
            Sort
          </label>
          <select
            id="sort"
            name="sort"
            defaultValue={sortKey}
            className="rounded border border-border bg-bg-base px-2 py-1 text-sm text-text-primary"
          >
            <option value="sequence">Sequence #</option>
            <option value="hits">Hit Count</option>
          </select>
        </div>
        <button
          type="submit"
          className="rounded border border-border bg-bg-surface px-3 py-1.5 text-sm text-text-primary hover:bg-bg-elevated"
        >
          Filter
        </button>
      </form>

      {rows.length === 0 ? (
        <EmptyState message="No rules match these filters." />
      ) : (
        <Table>
          <colgroup>
            <col style={{ width: '5%' }} />
            <col style={{ width: '14%' }} />
            <col style={{ width: '7%' }} />
            <col style={{ width: '7%' }} />
            <col style={{ width: '10%' }} />
            <col style={{ width: '10%' }} />
            <col style={{ width: '12%' }} />
            <col style={{ width: '12%' }} />
            <col style={{ width: '14%' }} />
            <col style={{ width: '7%' }} />
            <col style={{ width: '2%' }} />
          </colgroup>
          <thead>
            <tr className="border-b border-border bg-bg-surface text-left text-text-secondary">
              <th className="px-2 py-2">#</th>
              <th className="px-2 py-2">Name</th>
              <th className="px-2 py-2">Enabled</th>
              <th className="px-2 py-2">Action</th>
              <th className="px-2 py-2">Src Zone</th>
              <th className="px-2 py-2">Dst Zone</th>
              <th className="px-2 py-2">Src Address</th>
              <th className="px-2 py-2">Dst Address</th>
              <th className="px-2 py-2">Services</th>
              <th className="px-2 py-2">Log</th>
              <th className="px-2 py-2">Hits</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className={`border-b border-border ${actionBorderClass(r.action)}`}>
                <td className="px-2 py-2 text-text-secondary">{r.sequence_number ?? '—'}</td>
                <td className="truncate px-2 py-2 text-text-primary" title={r.rule_name || ''}>
                  {r.rule_name || '—'}
                </td>
                <td className="px-2 py-2 text-text-secondary">{r.enabled ? 'Yes' : 'No'}</td>
                <td className="px-2 py-2 text-text-secondary">{r.action || '—'}</td>
                <td className="truncate px-2 py-2 text-text-secondary" title={joinArray(r.src_zones)}>
                  {joinArray(r.src_zones)}
                </td>
                <td className="truncate px-2 py-2 text-text-secondary" title={joinArray(r.dst_zones)}>
                  {joinArray(r.dst_zones)}
                </td>
                <td className="truncate px-2 py-2 text-text-secondary" title={joinArray(r.src_addresses)}>
                  {joinArray(r.src_addresses)}
                </td>
                <td className="truncate px-2 py-2 text-text-secondary" title={joinArray(r.dst_addresses)}>
                  {joinArray(r.dst_addresses)}
                </td>
                <td className="truncate px-2 py-2 text-text-secondary" title={joinArray(r.services)}>
                  {joinArray(r.services)}
                </td>
                <td className="px-2 py-2 text-text-secondary">{r.log_enabled ? 'Yes' : 'No'}</td>
                <td className="px-2 py-2 text-text-secondary">{r.hit_count ?? 0}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <div className="flex items-center justify-between text-sm text-text-secondary">
        <span>
          Page {page} of {totalPages} ({total} rules)
        </span>
        <div className="flex items-center gap-3">
          {page > 1 && (
            <Link
              href={`/devices/${device.id}/rules?${buildQueryString(searchParams || {}, { page: page - 1 })}`}
              className="text-accent hover:underline"
            >
              ← Prev
            </Link>
          )}
          {page < totalPages && (
            <Link
              href={`/devices/${device.id}/rules?${buildQueryString(searchParams || {}, { page: page + 1 })}`}
              className="text-accent hover:underline"
            >
              Next →
            </Link>
          )}
        </div>
      </div>
    </div>
  );
}
