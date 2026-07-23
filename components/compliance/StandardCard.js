import Link from 'next/link';
import Card, { CardBody } from '../ui/Card';
import Badge from '../ui/Badge';
import StandardDonut from './StandardDonut';

/**
 * @param {{key: string, label: string}} standard
 * @param {string} description
 * @param {string} [referenceUrl]
 * @param {{pass: number, fail: number, warning: number, na: number, total: number, scorePct: number|null}} stats
 * @param {{id: string, name: string, href: string}[]} [failedChecks] - already truncated by the caller (e.g. first 5)
 * @param {number} [failedChecksTotal] - the real total fail count (may exceed failedChecks.length)
 * @param {string} [viewMoreHref] - link to the full findings view for this standard
 * @param {string|null} [lastRunAt] - ISO date string or null
 */

// Same "d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC'" / "Never run"
// formatting already used by ComplianceMatrix.js's formatLastRun() and
// app/(dashboard)/compliance/[deviceId]/page.js's formatDateTime() -- inlined
// here (rather than imported) since neither of those files exports its
// formatter, and this component owns no other file it could add an export
// to; matching the exact string shape is what matters, not sharing the
// function object itself.
function formatLastRun(value) {
  if (!value) return 'Never run';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'Never run';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

// Plain function returning JSX, called imperatively from the main component
// body below -- same "helper, not a nested component" pattern already used
// by ComplianceMatrix.js's scoreChip() -- CLAUDE.md's critical React rule is
// about component definitions, not JSX-returning helper functions, but the
// distinction only matters if this stays a plain function and is never
// invoked as `<StatusPanel />`.
function statusPanel({ stats, failedChecks, failedChecksTotal, viewMoreHref }) {
  if (stats.scorePct === 100) {
    return <Badge color="success">Fully Compliant</Badge>;
  }

  if (stats.fail > 0) {
    const shown = failedChecks.slice(0, 5);
    const remaining = Math.max(0, (failedChecksTotal || 0) - shown.length);
    return (
      <div
        style={{
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-sm)',
          padding: '8px 10px',
        }}
      >
        <span
          style={{
            display: 'inline-block',
            background: 'var(--tint-danger)',
            color: 'var(--tint-danger-fg)',
            fontSize: 'var(--text-xs)',
            fontWeight: 600,
            padding: '2px 8px',
            borderRadius: 'var(--radius-sm)',
            marginBottom: 6,
          }}
        >
          Failed: {failedChecksTotal || stats.fail}
        </span>
        <ul style={{ margin: 0, paddingLeft: 18, fontSize: 'var(--text-sm)' }}>
          {shown.map((c) => (
            <li key={c.id}>
              <Link href={c.href} className="link-quiet">
                {c.name}
              </Link>
            </li>
          ))}
        </ul>
        {remaining > 0 && viewMoreHref && (
          <Link
            href={viewMoreHref}
            className="link-quiet"
            style={{ display: 'inline-block', marginTop: 6, fontSize: 'var(--text-sm)' }}
          >
            +{remaining} more
          </Link>
        )}
      </div>
    );
  }

  return (
    <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
      {stats.total === 0 ? 'Not yet audited.' : 'No failing checks.'}
    </span>
  );
}

// Server-renderable (no 'use client' -- renders StandardDonut, a client
// component, directly; Next.js allows a server component to import and
// render a client component as a normal child with no wrapper needed).
export default function StandardCard({
  standard,
  description,
  referenceUrl,
  stats,
  failedChecks = [],
  failedChecksTotal = 0,
  viewMoreHref,
  lastRunAt,
}) {
  return (
    <Card>
      <CardBody>
        <div
          style={{
            display: 'flex',
            alignItems: 'baseline',
            justifyContent: 'space-between',
            gap: 12,
            marginBottom: 4,
          }}
        >
          {referenceUrl ? (
            <a
              href={referenceUrl}
              target="_blank"
              rel="noopener noreferrer"
              style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--primary)' }}
            >
              {standard.label}
            </a>
          ) : (
            <span style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)' }}>
              {standard.label}
            </span>
          )}
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
            Last run: {formatLastRun(lastRunAt)}
          </span>
        </div>

        <p style={{ margin: '0 0 16px', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
          {description}
          {referenceUrl && (
            <>
              {' '}
              <a
                href={referenceUrl}
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: 'var(--primary)', whiteSpace: 'nowrap' }}
              >
                Learn more
              </a>
            </>
          )}
        </p>

        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 16 }}>
          <StandardDonut pct={stats.scorePct} />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, minWidth: 160, flex: '1 1 200px' }}>
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              {`${stats.pass} pass · ${stats.fail} fail · ${stats.warning} warning · ${stats.na} n/a`}
            </span>
            {statusPanel({ stats, failedChecks, failedChecksTotal, viewMoreHref })}
          </div>
        </div>
      </CardBody>
    </Card>
  );
}
