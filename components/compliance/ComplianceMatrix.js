import Link from 'next/link';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';

// The 4 standards this UI scores against, in the fixed display order used by
// both the fleet matrix (this file) and the per-device tabs
// (StandardTabs.js) -- exported so both places (and
// app/(dashboard)/compliance/page.js's + [deviceId]/page.js's own
// aggregation, which each duplicate the sibling API's scorePct formula per
// this app's established "server components query the DB directly" pattern
// -- see app/(dashboard)/alerts/page.js) iterate the same 4 keys and never
// drift out of step.
export const STANDARDS = [
  { key: 'PCI_DSS', label: 'PCI DSS' },
  { key: 'ISO_27001', label: 'ISO 27001' },
  { key: 'CIS_V8', label: 'CIS v8' },
  { key: 'NIST', label: 'NIST' },
];

// Score -> visual severity banding, per the compliance spec: green >80%,
// amber 60-80%, red <60%, muted/gray for null (never audited, or every
// finding mapped to that standard is 'na') -- rendered as "-", not "0%",
// since null and 0% mean very different things (nothing measured vs.
// measured and failed everything). Exported so the per-device page can
// reuse the same bands for its StatCard tiles instead of re-deriving the
// cut points a second time.
export function scoreColor(pct) {
  if (pct == null) return 'muted';
  if (pct > 80) return 'success';
  if (pct >= 60) return 'warning';
  return 'danger';
}

// Badge's color names (success/warning/danger/muted) map directly to the
// suite's CSS var tokens for callers that need a raw color value instead of
// a Badge element -- e.g. StatCard's `color` prop, which takes a CSS color,
// not a Badge variant name.
export const SCORE_COLOR_VAR = {
  success: 'var(--green)',
  warning: 'var(--yellow)',
  danger: 'var(--red)',
  muted: 'var(--text-muted)',
};

// Plain function (not a JSX component tag) returning a colored score chip --
// same "helper that returns JSX, called imperatively" pattern already used
// by devices/[id]/analysis/page.js's tabLink(), not a component defined
// inside another component (CLAUDE.md's critical React rule).
function scoreChip(pct) {
  return <Badge color={scoreColor(pct)}>{pct == null ? '—' : `${pct}%`}</Badge>;
}

// The fleet query already computes lastRunAt per device (see
// app/(dashboard)/compliance/page.js and the sibling GET /api/compliance/fleet
// route) but this table never rendered it -- added so that data isn't fetched
// and silently dropped.
function formatLastRun(value) {
  if (!value) return 'Never run';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'Never run';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

// Fleet-wide compliance matrix: rows = devices, columns = the 4 standards,
// cells = a colored score chip linking into that device's compliance page.
// Purely presentational, no local state -- stays a plain server-renderable
// component, no 'use client' needed.
export default function ComplianceMatrix({ devices }) {
  if (!devices || devices.length === 0) {
    return <EmptyState message="No active devices to audit." />;
  }

  return (
    <Table>
      <colgroup>
        <col style={{ width: '22%' }} />
        <col style={{ width: '10%' }} />
        <col style={{ width: '12%' }} />
        <col style={{ width: '14%' }} />
        <col style={{ width: '14%' }} />
        <col style={{ width: '14%' }} />
        <col style={{ width: '14%' }} />
      </colgroup>
      <thead>
        <tr>
          <th>Device</th>
          <th>Vendor</th>
          <th>Last Run</th>
          {STANDARDS.map((s) => (
            <th key={s.key}>{s.label}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {devices.map((d) => (
          <tr key={d.deviceId}>
            <td title={d.deviceName}>
              <Link href={`/compliance/${d.deviceId}`} style={{ color: 'var(--primary)' }}>
                {d.deviceName}
              </Link>
            </td>
            <td>
              <Badge color="info">{d.vendor}</Badge>
            </td>
            <td style={{ color: 'var(--text-secondary)' }}>{formatLastRun(d.lastRunAt)}</td>
            {STANDARDS.map((s) => {
              const stat = d.standards ? d.standards[s.key] : null;
              const pct = stat ? stat.scorePct : null;
              return (
                <td key={s.key}>
                  <Link href={`/compliance/${d.deviceId}#${s.key}`} style={{ textDecoration: 'none' }}>
                    {scoreChip(pct)}
                  </Link>
                </td>
              );
            })}
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
