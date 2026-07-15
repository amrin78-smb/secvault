import Link from 'next/link';
import { notFound } from 'next/navigation';
import { pool } from '../../../../../lib/db';
import ConditionsManager from '../../../../../components/config/ConditionsManager';

export const dynamic = 'force-dynamic';

async function getAdvisory(dbPool, cveId) {
  const result = await dbPool.query(
    `SELECT id, cve_id, title, vendor FROM advisories WHERE cve_id = $1`,
    [cveId]
  );
  return result.rows[0] || null;
}

async function getConditions(dbPool, advisoryId) {
  const result = await dbPool.query(
    `SELECT id, advisory_id, vendor, condition_description, predicate_type, predicate_config, created_at
     FROM advisory_conditions
     WHERE advisory_id = $1
     ORDER BY created_at ASC`,
    [advisoryId]
  );
  return result.rows;
}

async function getActiveDevices(dbPool) {
  const result = await dbPool.query(
    `SELECT id, name FROM devices WHERE active = true ORDER BY name ASC`
  );
  return result.rows;
}

export default async function AdvisoryConditionsPage({ params }) {
  const cveId = decodeURIComponent(params.cveId);
  const advisory = await getAdvisory(pool, cveId);

  if (!advisory) {
    notFound();
  }

  const [conditionRows, deviceRows] = await Promise.all([
    getConditions(pool, advisory.id),
    getActiveDevices(pool),
  ]);

  // Plain serializable props for the client component (timestamps → ISO strings).
  const initialConditions = conditionRows.map((c) => ({
    id: c.id,
    advisory_id: c.advisory_id,
    vendor: c.vendor,
    condition_description: c.condition_description,
    predicate_type: c.predicate_type,
    predicate_config: c.predicate_config,
    created_at: c.created_at ? new Date(c.created_at).toISOString() : null,
  }));

  const devices = deviceRows.map((d) => ({ id: d.id, name: d.name }));

  return (
    <div className="space-y-6">
      <div>
        <Link
          href={`/advisories/${encodeURIComponent(advisory.cve_id)}`}
          className="text-sm text-accent hover:underline"
        >
          ← Back to {advisory.cve_id}
        </Link>
      </div>

      <div className="rounded border border-border bg-bg-surface p-4">
        <h1 className="text-xl font-semibold text-text-primary">
          {advisory.cve_id} — Applicability Conditions
        </h1>
        <p className="mt-1 text-text-secondary">{advisory.title}</p>
        <p className="mt-3 text-sm text-text-muted">
          Conditions gate this advisory&apos;s <span className="font-mono">config_applies</span> result per
          device (tri-state: yes / no / unknown). All conditions are ANDed together; if no conditions are
          defined, <span className="font-mono">config_applies</span> stays{' '}
          <span className="font-mono">unknown</span> and is treated conservatively.
        </p>
      </div>

      <ConditionsManager cveId={params.cveId} initialConditions={initialConditions} devices={devices} />
    </div>
  );
}
