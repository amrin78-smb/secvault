import Link from 'next/link';
import { revalidatePath } from 'next/cache';
import { pool } from '../../../lib/db';
import { runFullSync } from '../../../lib/feeds';

export const dynamic = 'force-dynamic';

const CVSS_BAND_OPTIONS = [
  { value: '', label: 'All CVSS' },
  { value: 'critical', label: 'Critical (9.0+)' },
  { value: 'high', label: 'High (7.0-8.9)' },
  { value: 'medium', label: 'Medium (4.0-6.9)' },
  { value: 'low', label: 'Low (<4.0)' },
];

// ────────────────────────────────────────────────────────────────────────
// NOTE on the "Sync Now" control:
// The spec for this page called for a small 'use client' island component defined in
// this same file (not nested inside the server component) that POSTs to
// /api/feeds/sync and then calls router.refresh(). That is not achievable in a single
// file: Next.js's `'use client'` directive is file-scoped — placing it at the top of
// this file would turn the ENTIRE module (including the async Server Component default
// export below, which does direct `pool.query` data fetching) into a client bundle.
// `pg` cannot be bundled for the browser, so that would either fail the build or leak
// DB access into client code. Since only these seven files may be touched (no separate
// SyncNowButton.js is allowed), the equivalent, correct pattern is used instead: a
// Server Action (`syncNowAction`, marked with the `'use server'` directive inside the
// function body — NOT at the top of the file) triggered by a plain <form>. It runs the
// sync directly on the server (no self-fetch of our own API route, consistent with the
// same principle behind "don't fetch your own API routes from a server component") and
// calls `revalidatePath` — the server-side equivalent of `router.refresh()` — so the
// page re-renders with fresh data after the sync completes. Functionally this delivers
// the same UX (click "Sync Now" -> sync runs -> page shows fresh results) without
// violating Next.js's module boundaries.
// ────────────────────────────────────────────────────────────────────────
async function syncNowAction() {
  'use server';
  await runFullSync(pool);
  revalidatePath('/advisories');
}

function SyncNowButton() {
  return (
    <form action={syncNowAction}>
      <button
        type="submit"
        className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-hover"
      >
        Sync Now
      </button>
    </form>
  );
}

function formatDateTime(value) {
  if (!value) return 'never';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'never';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

function formatDate(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().slice(0, 10);
}

function formatFixedIn(fixedInVersions) {
  if (!Array.isArray(fixedInVersions) || fixedInVersions.length === 0) return '—';
  return fixedInVersions.join(', ');
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

function KevBadge({ kevListed }) {
  if (!kevListed) return null;
  return (
    <span className="rounded bg-danger px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-white">
      KEV
    </span>
  );
}

async function getLastSyncs(dbPool) {
  const result = await dbPool.query(
    `SELECT feed_name, status, started_at, finished_at
     FROM feed_sync_log
     ORDER BY started_at DESC
     LIMIT 10`
  );
  return result.rows;
}

async function getAdvisories(dbPool, searchParams) {
  const vendor = searchParams?.vendor || '';
  const cvssBand = searchParams?.cvssBand || '';
  const kevOnly = searchParams?.kevOnly === '1' || searchParams?.kevOnly === 'true';
  const q = searchParams?.q || '';

  const conditions = [];
  const params = [];

  if (vendor) {
    params.push(vendor);
    conditions.push(`vendor = $${params.length}`);
  }
  if (kevOnly) {
    conditions.push('kev_listed = true');
  }
  if (q) {
    params.push(`%${q}%`);
    const idx = params.length;
    conditions.push(`(cve_id ILIKE $${idx} OR title ILIKE $${idx})`);
  }
  // CVSS band thresholds are fixed literals (not user input), so it's safe to inline
  // them rather than parameterize.
  if (cvssBand === 'critical') conditions.push('cvss_score >= 9');
  else if (cvssBand === 'high') conditions.push('cvss_score >= 7 AND cvss_score < 9');
  else if (cvssBand === 'medium') conditions.push('cvss_score >= 4 AND cvss_score < 7');
  else if (cvssBand === 'low') conditions.push('cvss_score < 4');

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const sql = `
    SELECT cve_id, vendor, title, cvss_score, kev_listed, kev_date, fixed_in_versions, published_at
    FROM advisories
    ${where}
    ORDER BY published_at DESC NULLS LAST, cve_id DESC
    LIMIT 300
  `;
  const result = await dbPool.query(sql, params);
  return result.rows;
}

export default async function AdvisoriesPage({ searchParams }) {
  const [advisories, lastSyncs] = await Promise.all([
    getAdvisories(pool, searchParams),
    getLastSyncs(pool),
  ]);

  const lastNvd = lastSyncs.find((s) => s.feed_name === 'nvd');
  const lastKev = lastSyncs.find((s) => s.feed_name === 'kev');

  const vendorValue = searchParams?.vendor || '';
  const cvssBandValue = searchParams?.cvssBand || '';
  const kevOnlyChecked = searchParams?.kevOnly === '1' || searchParams?.kevOnly === 'true';
  const qValue = searchParams?.q || '';

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded border border-border bg-bg-surface px-4 py-3">
        <div className="text-sm text-text-secondary">
          <span>
            Last NVD sync: {formatDateTime(lastNvd?.finished_at)}{' '}
            {lastNvd ? `(${lastNvd.status})` : ''}
          </span>
          <span className="ml-4">
            Last KEV sync: {formatDateTime(lastKev?.finished_at)}{' '}
            {lastKev ? `(${lastKev.status})` : ''}
          </span>
        </div>
        <SyncNowButton />
      </div>

      <form method="GET" className="mb-4 flex flex-wrap items-end gap-3">
        <div className="flex flex-col gap-1">
          <label htmlFor="q" className="text-xs text-text-secondary">
            Search
          </label>
          <input
            id="q"
            type="text"
            name="q"
            defaultValue={qValue}
            placeholder="CVE ID or title"
            className="rounded border border-border bg-bg-base px-2 py-1 text-sm text-text-primary"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="vendor" className="text-xs text-text-secondary">
            Vendor
          </label>
          <select
            id="vendor"
            name="vendor"
            defaultValue={vendorValue}
            className="rounded border border-border bg-bg-base px-2 py-1 text-sm text-text-primary"
          >
            <option value="">All vendors</option>
            <option value="forcepoint">Forcepoint</option>
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="cvssBand" className="text-xs text-text-secondary">
            CVSS band
          </label>
          <select
            id="cvssBand"
            name="cvssBand"
            defaultValue={cvssBandValue}
            className="rounded border border-border bg-bg-base px-2 py-1 text-sm text-text-primary"
          >
            {CVSS_BAND_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
        <label className="flex items-center gap-1.5 pb-1.5 text-sm text-text-secondary">
          <input type="checkbox" name="kevOnly" value="1" defaultChecked={kevOnlyChecked} />
          KEV only
        </label>
        <button
          type="submit"
          className="rounded border border-border bg-bg-surface px-3 py-1.5 text-sm text-text-primary hover:bg-bg-elevated"
        >
          Filter
        </button>
      </form>

      <div className="overflow-x-auto rounded border border-border">
        <table className="w-full table-fixed border-collapse text-sm" style={{ tableLayout: 'fixed' }}>
          <colgroup>
            <col style={{ width: '14%' }} />
            <col style={{ width: '8%' }} />
            <col style={{ width: '8%' }} />
            <col style={{ width: '10%' }} />
            <col style={{ width: '32%' }} />
            <col style={{ width: '16%' }} />
            <col style={{ width: '12%' }} />
          </colgroup>
          <thead>
            <tr className="border-b border-border bg-bg-surface text-left text-text-secondary">
              <th className="px-2 py-2">CVE ID</th>
              <th className="px-2 py-2">CVSS</th>
              <th className="px-2 py-2">KEV</th>
              <th className="px-2 py-2">Vendor</th>
              <th className="px-2 py-2">Title</th>
              <th className="px-2 py-2">Fixed In</th>
              <th className="px-2 py-2">Published</th>
            </tr>
          </thead>
          <tbody>
            {advisories.map((a) => (
              <tr key={a.cve_id} className="border-b border-border hover:bg-bg-elevated">
                <td className="truncate p-0">
                  <Link
                    href={`/advisories/${encodeURIComponent(a.cve_id)}`}
                    className="block truncate px-2 py-2 font-medium text-accent hover:underline"
                  >
                    {a.cve_id}
                  </Link>
                </td>
                <td className="truncate p-0">
                  <Link
                    href={`/advisories/${encodeURIComponent(a.cve_id)}`}
                    className={`block truncate px-2 py-2 ${cvssTextClass(a.cvss_score)}`}
                  >
                    {a.cvss_score ?? '—'}
                  </Link>
                </td>
                <td className="truncate p-0">
                  <Link
                    href={`/advisories/${encodeURIComponent(a.cve_id)}`}
                    className="flex items-center px-2 py-2"
                  >
                    <KevBadge kevListed={a.kev_listed} />
                  </Link>
                </td>
                <td className="truncate p-0">
                  <Link
                    href={`/advisories/${encodeURIComponent(a.cve_id)}`}
                    className="block truncate px-2 py-2 text-text-secondary"
                  >
                    {a.vendor}
                  </Link>
                </td>
                <td className="truncate p-0">
                  <Link
                    href={`/advisories/${encodeURIComponent(a.cve_id)}`}
                    className="block truncate px-2 py-2 text-text-primary"
                    title={a.title || ''}
                  >
                    {a.title || '—'}
                  </Link>
                </td>
                <td className="truncate p-0">
                  <Link
                    href={`/advisories/${encodeURIComponent(a.cve_id)}`}
                    className="block truncate px-2 py-2 text-text-secondary"
                    title={formatFixedIn(a.fixed_in_versions)}
                  >
                    {formatFixedIn(a.fixed_in_versions)}
                  </Link>
                </td>
                <td className="truncate p-0">
                  <Link
                    href={`/advisories/${encodeURIComponent(a.cve_id)}`}
                    className="block truncate px-2 py-2 text-text-secondary"
                  >
                    {formatDate(a.published_at)}
                  </Link>
                </td>
              </tr>
            ))}
            {advisories.length === 0 && (
              <tr>
                <td colSpan={7} className="px-2 py-6 text-center text-text-muted">
                  No advisories found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
