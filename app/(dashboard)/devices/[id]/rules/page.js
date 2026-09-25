import Link from 'next/link';
import { pool } from '../../../../../lib/db';
import { correlateDeviceRules } from '../../../../../lib/engines/ruleHitCorrelation';
import Table from '../../../../../components/ui/Table';
import EmptyState from '../../../../../components/ui/EmptyState';
import PageHeader from '../../../../../components/ui/PageHeader';
import RuleUsageCell, { USAGE_CLAIM } from '../../../../../components/analysis/UsageGrade';

export const dynamic = 'force-dynamic';

const PAGE_SIZE = 50;

const SORT_OPTIONS = {
  sequence: 'sequence_number ASC NULLS LAST',
  // NULLS LAST is required, not cosmetic: Postgres sorts NULLs FIRST in a
  // DESC ordering, so without it every UNMEASURED rule would head the
  // "most hits" list ahead of the genuinely busiest rules.
  //
  // ⛔ THIS SORTS THE DEVICE'S OWN COUNTER, NOT THE DISPLAYED FIGURE. The Usage
  // column below can also answer from the firewall's logs, and that answer
  // lives in syslog_rollup_hourly — it cannot be reached from this ORDER BY at
  // all. So a log-answered rule still sorts as a NULL, i.e. last. Stated in the
  // option label rather than left for someone to discover: a sort that quietly
  // means something narrower than the column it names is the same class of
  // mistake as a number whose window is smaller than its sentence claims.
  hits: 'hit_count DESC NULLS LAST',
};

function actionBorderColor(action) {
  if (action === 'allow') return 'var(--green)';
  if (action === 'deny' || action === 'drop' || action === 'reject' || action === 'block') return 'var(--red)';
  return 'var(--border)';
}

function joinArray(value) {
  if (!Array.isArray(value) || value.length === 0) return '—';
  return value.join(', ');
}

// Builds a parameterized WHERE clause + params array — never interpolates raw query
// param values into SQL, only bound parameters.
//
// ⛔ Extended 2026-07-19: `action` now accepts a comma-separated list (e.g.
// `action=deny,drop,reject`), matched via `= ANY($N::text[])` instead of
// plain `=` — added so the Rule hygiene Summary tab's "Denied Rules"
// StatCard (which counts action IN ('deny','drop','reject','block'), see
// getRuleStats() in devices/[id]/analysis/page.js) can link to a filtered
// view that actually matches what it counted, rather than only the single
// literal 'deny' action. A bare single value (no comma) still works exactly
// as before — ANY() over a 1-element array is equivalent to `=`. Also added
// `nat=true`, for the new "NAT Enabled" stat/chart bar.
function buildFilters(deviceId, searchParams) {
  const conditions = ['device_id = $1'];
  const params = [deviceId];

  const action = searchParams?.action;
  if (action) {
    const actions = action.split(',').map((a) => a.trim()).filter(Boolean);
    if (actions.length > 0) {
      params.push(actions);
      conditions.push(`action = ANY($${params.length}::text[])`);
    }
  }

  const enabled = searchParams?.enabled;
  if (enabled === 'true' || enabled === 'false') {
    params.push(enabled === 'true');
    conditions.push(`enabled = $${params.length}`);
  }

  const nat = searchParams?.nat;
  if (nat === 'true' || nat === 'false') {
    params.push(nat === 'true');
    conditions.push(`nat_enabled = $${params.length}`);
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
        <Link href="/devices" style={{ fontSize: 'var(--text-base)', color: 'var(--primary)', textDecoration: 'underline' }}>
          ← Back to firewalls
        </Link>
        <p style={{ marginTop: 16, color: 'var(--text-secondary)' }}>Device not found.</p>
      </div>
    );
  }

  const { rows, total, page, sortKey } = await getRules(pool, device.id, searchParams || {});
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  // ⛔ THE HIT COUNTER IS NOT THE ONLY SOURCE, AND THIS COLUMN USED TO PRETEND
  // IT WAS. `hit_count` is NULL for every vendor/transport that cannot report
  // one (Fortinet SSH, Palo Alto SSH, Sangfor), and this page drew every one of
  // those as a bare em-dash — while the firewall's own logs could answer 84 of
  // them on the live fleet. Correlating here is what lets the four grades
  // actually appear in the product.
  //
  // ⛔ AND IT MAY NOT TAKE THE PAGE DOWN. The correlation reads the syslog
  // rollups; on an installation with no collector, or one whose rollup read
  // fails, the honest outcome is the device counter alone — NOT a blank rule
  // list. A failure therefore falls back to the un-enriched rows, which render
  // exactly as they did before: a real count, or "not measured".
  //
  // ⛔ The fallback still has to produce the DEVICE-grade fields by hand. Left
  // as the raw rows, every rule with a perfectly good counter would render
  // "not measured" — a read failure of OURS shown as a gap in the FIREWALL,
  // which is the exact substitution this whole feature exists to refuse.
  const deviceGradeOnly = (r) => Object.assign({}, r, {
    effectiveHitCount: r.hit_count === null || r.hit_count === undefined ? null : Number(r.hit_count),
    usageGrade: r.hit_count === null || r.hit_count === undefined ? null : 'device',
    logEvidence: null,
  });
  let usageRows;
  try {
    usageRows = await correlateDeviceRules(pool, device.id, rows);
  } catch {
    usageRows = rows.map(deviceGradeOnly);
  }

  const csvHref = `/api/devices/${device.id}/rules?format=csv&${buildQueryString(searchParams || {}, { page: undefined })}`;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div>
        <Link
          href={`/devices/${device.id}`}
          style={{ fontSize: 'var(--text-base)', color: 'var(--primary)', textDecoration: 'underline' }}
        >
          ← Back to {device.name}
        </Link>
      </div>

      <PageHeader
        title={`Firewall Rules — ${device.name}`}
        actions={
          <a href={csvHref} className="btn btn-secondary">
            Export CSV
          </a>
        }
      />

      <form method="GET" className="filter-row" style={{ alignItems: 'flex-end' }}>
        <div className="form-field">
          <label htmlFor="search">Search (name / IP / port)</label>
          <input id="search" type="text" name="search" defaultValue={searchParams?.search || ''} className="input" />
        </div>
        <div className="form-field">
          <label htmlFor="action">Action</label>
          <select id="action" name="action" defaultValue={searchParams?.action || ''} className="input">
            <option value="">All actions</option>
            <option value="allow">Allow</option>
            <option value="deny,drop,reject,block">Denied (deny/drop/reject/block)</option>
            <option value="deny">Deny only</option>
            <option value="drop">Drop only</option>
            <option value="reject">Reject only</option>
          </select>
        </div>
        <div className="form-field">
          <label htmlFor="enabled">Enabled</label>
          <select id="enabled" name="enabled" defaultValue={searchParams?.enabled || ''} className="input">
            <option value="">All</option>
            <option value="true">Enabled</option>
            <option value="false">Disabled</option>
          </select>
        </div>
        <div className="form-field">
          <label htmlFor="nat">NAT</label>
          <select id="nat" name="nat" defaultValue={searchParams?.nat || ''} className="input">
            <option value="">All</option>
            <option value="true">NAT enabled</option>
            <option value="false">NAT disabled</option>
          </select>
        </div>
        <div className="form-field">
          <label htmlFor="zone">Zone</label>
          <input id="zone" type="text" name="zone" defaultValue={searchParams?.zone || ''} className="input" />
        </div>
        <div className="form-field">
          <label htmlFor="sort">Sort</label>
          <select id="sort" name="sort" defaultValue={sortKey} className="input">
            <option value="sequence">Sequence #</option>
            <option value="hits">Hit count (device counter only)</option>
          </select>
        </div>
        <button type="submit" className="btn btn-secondary">
          Filter
        </button>
      </form>

      {rows.length === 0 ? (
        <EmptyState message="No rules match these filters." />
      ) : (
        <Table>
          <colgroup>
            <col style={{ width: '4%' }} />
            <col style={{ width: '12%' }} />
            <col style={{ width: '5%' }} />
            <col style={{ width: '5%' }} />
            <col style={{ width: '8%' }} />
            <col style={{ width: '8%' }} />
            <col style={{ width: '8%' }} />
            <col style={{ width: '8%' }} />
            <col style={{ width: '10%' }} />
            {/* Comment and Applications each give up 2% so Usage can carry a
                grade chip and, where it needs one, a visible caveat. */}
            <col style={{ width: '6%' }} />
            <col style={{ width: '7%' }} />
            <col style={{ width: '6%' }} />
            <col style={{ width: '5%' }} />
            <col style={{ width: '8%' }} />
          </colgroup>
          <thead>
            <tr>
              <th>#</th>
              <th>Name</th>
              <th>Enabled</th>
              <th>Action</th>
              <th>Src Zone</th>
              <th>Dst Zone</th>
              <th>Src Address</th>
              <th>Dst Address</th>
              <th>Services</th>
              <th>Comment</th>
              <th>Applications</th>
              <th>Schedule</th>
              <th>Log</th>
              <th title={USAGE_CLAIM}>Usage</th>
            </tr>
          </thead>
          <tbody>
            {usageRows.map((r) => (
              <tr key={r.id} style={{ borderLeft: `4px solid ${actionBorderColor(r.action)}` }}>
                <td>{r.sequence_number ?? '—'}</td>
                <td title={r.rule_name || ''}>{r.rule_name || '—'}</td>
                <td>{r.enabled ? 'Yes' : 'No'}</td>
                <td>{r.action || '—'}</td>
                <td title={joinArray(r.src_zones)}>{joinArray(r.src_zones)}</td>
                <td title={joinArray(r.dst_zones)}>{joinArray(r.dst_zones)}</td>
                <td title={joinArray(r.src_addresses)}>{joinArray(r.src_addresses)}</td>
                <td title={joinArray(r.dst_addresses)}>{joinArray(r.dst_addresses)}</td>
                <td title={joinArray(r.services)}>{joinArray(r.services)}</td>
                <td title={r.comment || ''}>{r.comment || '—'}</td>
                <td title={joinArray(r.applications)}>{joinArray(r.applications)}</td>
                <td title={r.schedule || ''}>{r.schedule || '—'}</td>
                <td>{r.log_enabled ? 'Yes' : 'No'}</td>
                {/* ⛔ null = not measured, NOT zero hits — and the cell now also
                    says WHAT the figure rests on, because a log answer matched
                    by rule NAME is not the same kind of answer as the device's
                    own counter. See components/analysis/UsageGrade.js. */}
                <td><RuleUsageCell rule={r} /></td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
        <span>
          Page {page} of {totalPages} ({total} rules)
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {page > 1 && (
            <Link
              href={`/devices/${device.id}/rules?${buildQueryString(searchParams || {}, { page: page - 1 })}`}
              style={{ color: 'var(--primary)', textDecoration: 'underline' }}
            >
              ← Prev
            </Link>
          )}
          {page < totalPages && (
            <Link
              href={`/devices/${device.id}/rules?${buildQueryString(searchParams || {}, { page: page + 1 })}`}
              style={{ color: 'var(--primary)', textDecoration: 'underline' }}
            >
              Next →
            </Link>
          )}
        </div>
      </div>
    </div>
  );
}
