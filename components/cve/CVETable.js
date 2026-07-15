import Link from 'next/link';
import Table from '../ui/Table';
import PriorityBadge from './PriorityBadge';
import CVEBadge from './CVEBadge';

function cvssTextClass(score) {
  if (score === null || score === undefined) return 'text-text-muted';
  const n = Number(score);
  if (Number.isNaN(n)) return 'text-text-muted';
  if (n >= 9) return 'text-danger font-semibold';
  if (n >= 7) return 'text-warning font-semibold';
  if (n >= 4) return 'text-text-primary';
  return 'text-text-muted';
}

// Reusable CVE table used both on the device detail CVE Posture tab (single-device
// context, one row per advisory for that device) and the fleet CVE view (one row per
// advisory across the whole fleet). The optional column shows whichever of
// `device_name` (single device) or `affected_device_count` (fleet) the caller
// populates per row — this component never decides which mode it's in globally.
export default function CVETable({ rows = [], showDeviceColumn = false, deviceColumnLabel = 'Devices' }) {
  const colCount = showDeviceColumn ? 7 : 6;

  return (
    <Table>
      <colgroup>
        <col style={{ width: showDeviceColumn ? '16%' : '20%' }} />
        <col style={{ width: '8%' }} />
        <col style={{ width: '8%' }} />
        {showDeviceColumn && <col style={{ width: '16%' }} />}
        <col style={{ width: '16%' }} />
        <col style={{ width: showDeviceColumn ? '20%' : '28%' }} />
        <col style={{ width: '12%' }} />
      </colgroup>
      <thead>
        <tr className="border-b border-border bg-bg-surface text-left text-text-secondary">
          <th className="px-2 py-2">CVE ID</th>
          <th className="px-2 py-2">CVSS</th>
          <th className="px-2 py-2">KEV</th>
          {showDeviceColumn && <th className="px-2 py-2">{deviceColumnLabel}</th>}
          <th className="px-2 py-2">Priority Band</th>
          <th className="px-2 py-2">Fixed-In</th>
          <th className="px-2 py-2">Recommended</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row, i) => {
          let deviceCell = '—';
          if (showDeviceColumn) {
            if (row.device_name !== undefined && row.device_name !== null) {
              deviceCell = row.device_name;
            } else if (row.affected_device_count !== undefined && row.affected_device_count !== null) {
              deviceCell = row.affected_device_count;
            }
          }

          const href = `/cve/${encodeURIComponent(row.cve_id)}`;
          const rowKey = `${row.cve_id}-${row.device_name || ''}-${i}`;

          return (
            <tr key={rowKey} className="border-b border-border hover:bg-bg-elevated">
              <td className="truncate p-0">
                <Link href={href} className="block truncate px-2 py-2 font-medium text-accent hover:underline">
                  {row.cve_id}
                </Link>
              </td>
              <td className="truncate p-0">
                <Link href={href} className={`block truncate px-2 py-2 ${cvssTextClass(row.cvss_score)}`}>
                  {row.cvss_score ?? '—'}
                </Link>
              </td>
              <td className="truncate p-0">
                <Link href={href} className="flex items-center px-2 py-2">
                  <CVEBadge kevListed={row.kev_listed} />
                </Link>
              </td>
              {showDeviceColumn && (
                <td className="truncate p-0">
                  <Link href={href} className="block truncate px-2 py-2 text-text-secondary" title={String(deviceCell)}>
                    {deviceCell}
                  </Link>
                </td>
              )}
              <td className="truncate p-0">
                <Link href={href} className="flex items-center px-2 py-2">
                  <PriorityBadge band={row.priority_band} />
                </Link>
              </td>
              <td className="truncate p-0">
                <Link href={href} className="block truncate px-2 py-2 text-text-secondary" title={row.fixed_in || ''}>
                  {row.fixed_in || '—'}
                </Link>
              </td>
              <td className="truncate p-0">
                <Link href={href} className="block truncate px-2 py-2">
                  {row.is_fixed_recommended ? (
                    <span className="text-success">Yes</span>
                  ) : (
                    <span className="text-text-muted">No</span>
                  )}
                </Link>
              </td>
            </tr>
          );
        })}
        {rows.length === 0 && (
          <tr>
            <td colSpan={colCount} className="px-2 py-6 text-center text-text-muted">
              No CVEs found.
            </td>
          </tr>
        )}
      </tbody>
    </Table>
  );
}
