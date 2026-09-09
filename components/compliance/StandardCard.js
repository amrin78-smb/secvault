import Link from 'next/link';
import TimeAgo from '../ui/TimeAgo';
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

// Plain function returning JSX, called imperatively from the main component
// body below -- same "helper, not a nested component" pattern already used
// by ComplianceMatrix.js's scoreChip() -- CLAUDE.md's critical React rule is
// about component definitions, not JSX-returning helper functions, but the
// distinction only matters if this stays a plain function and is never
// invoked as `<StatusPanel />`.
// Composition bar for one standard.
//
// ⛔ Module top level, a plain function returning JSX called imperatively —
// never a component defined inside a component (CLAUDE.md's React rule).
//
// The donut beside this shows only the PASS PERCENTAGE. The fail/warning
// composition — the part that says what to go and fix — was four bare numbers
// in a sentence the reader had to add up and divide, ten times per compliance
// visit, and comparing two standards meant doing that arithmetic twice.
//
// ⛔ `na` is rendered HATCHED and set apart after a gap, NOT as a fourth
// coloured grade. It is excluded from the score's denominator entirely
// (CLAUDE.md's warning-vs-na rule: `na` is a fact about SecVault's inability to
// ask the question, not about the device), so drawing it flush with the graded
// segments would imply it counts against the score. The existing "n/a excluded
// from the score" caption then labels a visible thing rather than floating
// loose.
function complianceBar(stats) {
  const graded = stats.pass + stats.fail + stats.warning;
  // Nothing gradeable: the card's own "Not measurable" branch already handles
  // this case in words, and a bar of zero segments would read as an empty
  // result rather than an unmeasurable one.
  if (graded <= 0) return null;

  const pct = (n) => `${(n / graded) * 100}%`;
  const seg = (w, bg, label) => (
    <div
      key={label}
      title={label}
      style={{ width: w, background: bg, height: '100%' }}
      aria-label={label}
    />
  );

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <div
        style={{
          display: 'flex',
          height: 8,
          flex: '1 1 auto',
          borderRadius: 'var(--radius-pill)',
          overflow: 'hidden',
          background: 'var(--bg-primary)',
        }}
      >
        {stats.pass > 0 ? seg(pct(stats.pass), 'var(--green)', `${stats.pass} passing`) : null}
        {stats.fail > 0 ? seg(pct(stats.fail), 'var(--red)', `${stats.fail} failing`) : null}
        {stats.warning > 0
          ? seg(pct(stats.warning), 'var(--yellow)', `${stats.warning} warning`)
          : null}
      </div>
      {stats.na > 0 ? (
        <div
          title={`${stats.na} not applicable — excluded from the score`}
          aria-label={`${stats.na} not applicable`}
          style={{
            width: 22,
            height: 8,
            borderRadius: 'var(--radius-pill)',
            border: '1px solid var(--border)',
            background:
              'repeating-linear-gradient(45deg, var(--border) 0 3px, transparent 3px 6px)',
          }}
        />
      ) : null}
    </div>
  );
}

function statusPanel({ stats, failedChecks, failedChecksTotal, viewMoreHref }) {
  if (stats.scorePct === 100) {
    return <Badge color="success">Fully Compliant</Badge>;
  }

  // ⛔ scorePct === null with checks present means every check for this
  // standard resolved `na` — questions SecVault could not ask of this device
  // at all, excluded from the score denominator (CLAUDE.md's warning-vs-na
  // rule). This used to fall through to "No failing checks.", which reads as a
  // clean bill of health for a standard that was never actually evaluated:
  // our inability to measure, rendered as good news about the device. The
  // donut already shows "—" here; this line says why.
  if (stats.scorePct === null && stats.total > 0) {
    return (
      <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
        Not measurable — all {stats.total} check{stats.total === 1 ? '' : 's'} are N/A, so this standard has no
        score.
      </span>
    );
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
            Last run: <TimeAgo value={lastRunAt} empty="Never run" />
          </span>
        </div>

        <p style={{ margin: '0 0 16px', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
          {/* Clamp long standard blurbs to 2 lines to cut vertical bulk (this
              card renders ~5x). Full text stays reachable via the title tooltip
              and the "Learn more" link, which is kept outside the clamp so it is
              never truncated. A short description still shows in full. */}
          <span
            title={description}
            style={{
              display: '-webkit-box',
              WebkitLineClamp: 2,
              WebkitBoxOrient: 'vertical',
              overflow: 'hidden',
            }}
          >
            {description}
          </span>
          {referenceUrl && (
            <a
              href={referenceUrl}
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: 'var(--primary)', whiteSpace: 'nowrap' }}
            >
              Learn more
            </a>
          )}
        </p>

        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 16 }}>
          <StandardDonut pct={stats.scorePct} />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, minWidth: 160, flex: '1 1 200px' }}>
            {complianceBar(stats)}
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              {`${stats.pass} pass · ${stats.fail} fail · ${stats.warning} warning · ${stats.na} n/a`}
              {/* The four counts are not four equal parts of the score: `na`
                  is excluded from its denominator entirely (CLAUDE.md's
                  warning-vs-na rule), so the donut is pass / (pass+fail+
                  warning). Only said when there IS an n/a to misread. */}
              {stats.na > 0 && (
                <span style={{ display: 'block', fontSize: 'var(--text-xs)' }}>n/a excluded from the score</span>
              )}
            </span>
            {statusPanel({ stats, failedChecks, failedChecksTotal, viewMoreHref })}
          </div>
        </div>
      </CardBody>
    </Card>
  );
}
