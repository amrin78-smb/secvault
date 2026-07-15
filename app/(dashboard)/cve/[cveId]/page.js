import Link from 'next/link';
import { pool } from '../../../../lib/db';
import CVEBadge from '../../../../components/cve/CVEBadge';
import PriorityBadge from '../../../../components/cve/PriorityBadge';
import Table from '../../../../components/ui/Table';
import EmptyState from '../../../../components/ui/EmptyState';

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
  const result = await dbPool.query('SELECT * FROM advisories WHERE cve_id = $1', [cveId]);
  return result.rows[0] || null;
}

async function getAffectedDevices(dbPool, cveId) {
  const result = await dbPool.query(
    `SELECT d.id, d.name, dca.fixed_in, dca.priority_band, dca.is_fixed_recommended, dv.version_string
     FROM device_cve_assessments dca
     JOIN devices d ON d.id = dca.device_id
     JOIN advisories a ON a.id = dca.advisory_id
     LEFT JOIN LATERAL (
       SELECT version_string
       FROM device_versions
       WHERE device_versions.device_id = d.id
       ORDER BY collected_at DESC
       LIMIT 1
     ) dv ON true
     WHERE a.cve_id = $1
     ORDER BY d.name ASC`,
    [cveId]
  );
  return result.rows;
}

export default async function CveDetailPage({ params }) {
  const cveId = decodeURIComponent(params.cveId);
  const advisory = await getAdvisory(pool, cveId);

  if (!advisory) {
    return (
      <div>
        <Link href="/cve" className="text-sm text-accent hover:underline">
          ← Back to fleet CVE posture
        </Link>
        <p className="mt-4 text-text-secondary">Advisory {cveId} not found.</p>
      </div>
    );
  }

  const devices = await getAffectedDevices(pool, cveId);

  return (
    <div className="space-y-6">
      <div>
        <Link href="/cve" className="text-sm text-accent hover:underline">
          ← Back to fleet CVE posture
        </Link>
      </div>

      <div className="rounded border border-border bg-bg-surface p-4">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-xl font-semibold text-text-primary">{advisory.cve_id}</h1>
          <CVEBadge kevListed={advisory.kev_listed} />
          {!advisory.kev_listed && <span className="text-sm text-text-muted">Not KEV-listed</span>}
        </div>
        {advisory.title && <p className="mt-1 text-text-secondary">{advisory.title}</p>}

        <div className="mt-4 grid grid-cols-1 gap-4 text-sm sm:grid-cols-3">
          <div>
            <div className="text-xs uppercase tracking-wide text-text-muted">CVSS Score</div>
            <div className={cvssTextClass(advisory.cvss_score)}>{advisory.cvss_score ?? '—'}</div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-wide text-text-muted">Published</div>
            <div className="text-text-primary">{formatDate(advisory.published_at)}</div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-wide text-text-muted">Vendor</div>
            <div className="text-text-primary">{advisory.vendor}</div>
          </div>
        </div>
      </div>

      <div className="rounded border border-border bg-bg-surface p-4">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-text-secondary">Description</h2>
        <p className="text-text-primary">{advisory.description || 'No description available.'}</p>
      </div>

      <div className="rounded border border-border bg-bg-surface p-4">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-text-secondary">Affected Devices</h2>
        {devices.length === 0 ? (
          <EmptyState message="No devices assessed against this CVE yet." />
        ) : (
          <Table>
            <colgroup>
              <col style={{ width: '30%' }} />
              <col style={{ width: '20%' }} />
              <col style={{ width: '20%' }} />
              <col style={{ width: '15%' }} />
              <col style={{ width: '15%' }} />
            </colgroup>
            <thead>
              <tr className="border-b border-border text-left text-text-secondary">
                <th className="py-2 pr-2">Device</th>
                <th className="py-2 pr-2">Current Version</th>
                <th className="py-2 pr-2">Fixed-In</th>
                <th className="py-2 pr-2">Priority Band</th>
                <th className="py-2 pr-2">Recommended</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.id} className="border-b border-border hover:bg-bg-elevated">
                  <td className="truncate py-2 pr-2">
                    <Link href={`/devices/${d.id}`} className="text-accent hover:underline">
                      {d.name}
                    </Link>
                  </td>
                  <td className="truncate py-2 pr-2 text-text-secondary">{d.version_string || '—'}</td>
                  <td className="truncate py-2 pr-2 text-text-secondary">{d.fixed_in || '—'}</td>
                  <td className="py-2 pr-2">
                    <PriorityBadge band={d.priority_band} />
                  </td>
                  <td className="py-2 pr-2">
                    {d.is_fixed_recommended ? (
                      <span className="text-success">Yes</span>
                    ) : (
                      <span className="text-text-muted">No</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
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
