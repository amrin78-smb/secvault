import Link from 'next/link';
import { pool } from '../../../../lib/db';

export const dynamic = 'force-dynamic';

function formatDate(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().slice(0, 10);
}

function cvssTextClass(score) {
  if (score === null || score === undefined) return 'text-text-muted';
  const n = Number(score);
  if (Number.isNaN(n)) return 'text-text-muted';
  if (n >= 9) return 'text-danger font-semibold';
  if (n >= 7) return 'text-warning font-semibold';
  if (n >= 4) return 'text-text-primary';
  return 'text-text-muted';
}

async function getAdvisory(dbPool, cveId) {
  const result = await dbPool.query(`SELECT * FROM advisories WHERE cve_id = $1`, [cveId]);
  return result.rows[0] || null;
}

async function getConditionCount(dbPool, advisoryId) {
  const result = await dbPool.query(
    `SELECT COUNT(*)::int AS count FROM advisory_conditions WHERE advisory_id = $1`,
    [advisoryId]
  );
  return result.rows[0]?.count || 0;
}

async function getAffectedDevices(dbPool, cveId) {
  const result = await dbPool.query(
    `SELECT d.name, d.id
     FROM device_cve_assessments dca
     JOIN devices d ON d.id = dca.device_id
     JOIN advisories a ON a.id = dca.advisory_id
     WHERE a.cve_id = $1`,
    [cveId]
  );
  return result.rows;
}

export default async function AdvisoryDetailPage({ params }) {
  const cveId = decodeURIComponent(params.cveId);
  const advisory = await getAdvisory(pool, cveId);

  if (!advisory) {
    return (
      <div>
        <Link href="/advisories" className="text-sm text-accent hover:underline">
          ← Back to advisories
        </Link>
        <p className="mt-4 text-text-secondary">Advisory {cveId} not found.</p>
      </div>
    );
  }

  // These come back as a table this device may not have any assessments recorded for
  // yet, depending on integration order (matcher engine / SMC adapter may not have run
  // against every device) — handle zero rows gracefully rather than assuming data exists.
  const [devices, conditionCount] = await Promise.all([
    getAffectedDevices(pool, cveId),
    getConditionCount(pool, advisory.id),
  ]);

  const ranges = Array.isArray(advisory.affected_version_ranges) ? advisory.affected_version_ranges : [];
  const fixedIn = Array.isArray(advisory.fixed_in_versions) ? advisory.fixed_in_versions : [];

  return (
    <div className="space-y-6">
      <div>
        <Link href="/advisories" className="text-sm text-accent hover:underline">
          ← Back to advisories
        </Link>
      </div>

      <div className="rounded border border-border bg-bg-surface p-4">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-xl font-semibold text-text-primary">{advisory.cve_id}</h1>
          {advisory.kev_listed ? (
            <span className="rounded bg-danger px-2 py-0.5 text-xs font-semibold uppercase tracking-wide text-white">
              KEV
            </span>
          ) : (
            <span className="text-sm text-text-muted">Not KEV-listed</span>
          )}
          {advisory.kev_listed && advisory.kev_date && (
            <span className="text-sm text-text-secondary">Added to KEV {formatDate(advisory.kev_date)}</span>
          )}
        </div>
        <p className="mt-1 text-text-secondary">{advisory.title}</p>

        <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div>
            <div className="text-xs uppercase tracking-wide text-text-muted">Vendor</div>
            <div className="text-text-primary">{advisory.vendor}</div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-wide text-text-muted">CVSS Score</div>
            <div className={cvssTextClass(advisory.cvss_score)}>{advisory.cvss_score ?? '—'}</div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-wide text-text-muted">CVSS Vector</div>
            <div className="break-all text-text-secondary">{advisory.cvss_vector || '—'}</div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-wide text-text-muted">Published</div>
            <div className="text-text-primary">{formatDate(advisory.published_at)}</div>
          </div>
        </div>
      </div>

      <div className="rounded border border-border bg-bg-surface p-4">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-text-secondary">Description</h2>
        <p className="text-text-primary">{advisory.description || 'No description available.'}</p>
      </div>

      <div className="rounded border border-border bg-bg-surface p-4">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-text-secondary">
          Affected Version Ranges
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full table-fixed border-collapse text-sm" style={{ tableLayout: 'fixed' }}>
            <colgroup>
              <col style={{ width: '30%' }} />
              <col style={{ width: '30%' }} />
              <col style={{ width: '40%' }} />
            </colgroup>
            <thead>
              <tr className="border-b border-border text-left text-text-secondary">
                <th className="py-1 pr-2">Min Version</th>
                <th className="py-1 pr-2">Max Version</th>
                <th className="py-1 pr-2">Fix Version Excluded</th>
              </tr>
            </thead>
            <tbody>
              {ranges.map((r, i) => (
                <tr key={i} className="border-b border-border">
                  <td className="py-1 pr-2 text-text-primary">{r.min ?? '—'}</td>
                  <td className="py-1 pr-2 text-text-primary">{r.max ?? '—'}</td>
                  <td className="py-1 pr-2 text-text-secondary">{r.exclude_fixed ? 'Yes' : 'No'}</td>
                </tr>
              ))}
              {ranges.length === 0 && (
                <tr>
                  <td colSpan={3} className="py-2 text-text-muted">
                    No version range data.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="rounded border border-border bg-bg-surface p-4">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-text-secondary">Fixed In</h2>
        {fixedIn.length === 0 ? (
          <p className="text-sm text-text-muted">No fixed-in version data.</p>
        ) : (
          <ul className="flex flex-wrap gap-2">
            {fixedIn.map((v) => (
              <li
                key={v}
                className="rounded bg-bg-elevated px-2 py-1 text-sm text-success"
              >
                {v}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="rounded border border-border bg-bg-surface p-4">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-text-secondary">
          Applicability Conditions
        </h2>
        <p className="text-sm text-text-secondary">
          {conditionCount === 0
            ? 'No config predicates defined — config_applies resolves to "unknown" (treated conservatively).'
            : `${conditionCount} config predicate${conditionCount === 1 ? '' : 's'} gate whether this CVE applies per device.`}
        </p>
        <Link
          href={`/advisories/${encodeURIComponent(advisory.cve_id)}/conditions`}
          className="mt-2 inline-block text-sm text-accent hover:underline"
        >
          Manage conditions →
        </Link>
      </div>

      <div className="rounded border border-border bg-bg-surface p-4">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-text-secondary">Affected Devices</h2>
        {devices.length === 0 ? (
          <p className="text-sm text-text-muted">No devices affected yet.</p>
        ) : (
          <ul className="space-y-1 text-sm">
            {devices.map((d) => (
              <li key={d.id}>
                <Link href={`/devices/${d.id}`} className="text-accent hover:underline">
                  {d.name}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>

      {advisory.advisory_url && (
        <div>
          <a
            href={advisory.advisory_url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-accent hover:underline"
          >
            View on NVD →
          </a>
        </div>
      )}
    </div>
  );
}
