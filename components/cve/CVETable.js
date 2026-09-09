import Link from 'next/link';
import Table from '../ui/Table';
import PriorityBadge from './PriorityBadge';
import CVEBadge from './CVEBadge';

function cvssStyle(score) {
  if (score === null || score === undefined) return { color: 'var(--text-muted)' };
  const n = Number(score);
  if (Number.isNaN(n)) return { color: 'var(--text-muted)' };
  if (n >= 9) return { color: 'var(--red)', fontWeight: 600 };
  if (n >= 7) return { color: 'var(--yellow)', fontWeight: 600 };
  if (n >= 4) return { color: 'var(--text-primary)' };
  return { color: 'var(--text-muted)' };
}

// Every cell in a row is wrapped in a full-bleed <Link> (each <td> has padding
// stripped to 0, and the Link carries the padding instead) so the whole row acts as
// a click target to the CVE detail page — same behavior as the original Tailwind
// version's "block" links, just re-expressed with inline styles now that table
// cells get their padding from app/globals.css by default.
// ⛔ The padding here must be the DENSITY TOKENS, not fixed px. Because the
// <td> padding is stripped to 0 and this link carries it instead, a literal
// here would make this one table ignore the density switch entirely while
// every other table in the app changed height around it — which reads as a
// broken layout rather than a setting. Same failure mode as a hardcoded
// border-radius under the corners switch.
const linkCellStyle = {
  display: 'block',
  padding: 'var(--row-pad-y) var(--row-pad-x)',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
  color: 'inherit',
  textDecoration: 'none',
};

// Reusable CVE table used both on the device detail CVE Posture tab (single-device
// context, one row per advisory for that device) and the fleet CVE view (one row per
// advisory across the whole fleet). The optional column shows whichever of
// `device_name` (single device) or `affected_device_count` (fleet) the caller
// populates per row — this component never decides which mode it's in globally.
// ⛔ `emptyMessage` exists because "No CVEs found." is THREE different facts
// wearing one sentence: this device is genuinely clean, the current filters
// exclude everything, or nothing was ever assessed here. Only the caller
// knows which, and on a security product the difference between "clean" and
// "never looked" is the entire value of the answer. The default stays
// deliberately non-committal rather than reassuring.
export default function CVETable({
  rows = [],
  showDeviceColumn = false,
  deviceColumnLabel = 'Devices',
  emptyMessage = 'No CVEs to show for the current view.',
}) {
  const colCount = showDeviceColumn ? 7 : 6;

  return (
    // ⛔ stickyHeader and maxHeight are a PAIR — position:sticky resolves
    // against the nearest scrolling ancestor, so without a bounded height the
    // page scrolls and the header sticks to a container that is fully on
    // screen. This table renders up to 300 rows (~8 screens); viewport-
    // relative so it adapts to the window rather than guessing a pixel count.
    <Table stickyHeader maxHeight="70vh">
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
        <tr>
          <th>CVE ID</th>
          <th>CVSS</th>
          <th>KEV</th>
          {showDeviceColumn && <th>{deviceColumnLabel}</th>}
          <th>Priority Band</th>
          <th>Fixed-In</th>
          <th>Recommended</th>
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

          const href = `/vulnerability/cve/${encodeURIComponent(row.cve_id)}`;
          const rowKey = `${row.cve_id}-${row.device_name || ''}-${i}`;

          return (
            <tr key={rowKey}>
              <td style={{ padding: 0 }}>
                <Link
                  href={href}
                  className="link-quiet"
                  style={{
                    display: 'block',
                    padding: 'var(--row-pad-y) var(--row-pad-x)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {row.cve_id}
                </Link>
              </td>
              <td style={{ padding: 0 }}>
                <Link href={href} style={{ ...linkCellStyle, ...cvssStyle(row.cvss_score) }}>
                  {row.cvss_score ?? '—'}
                </Link>
              </td>
              <td style={{ padding: 0 }}>
                <Link href={href} style={{ ...linkCellStyle, display: 'flex', alignItems: 'center' }}>
                  <CVEBadge kevListed={row.kev_listed} />
                </Link>
              </td>
              {showDeviceColumn && (
                <td style={{ padding: 0 }}>
                  <Link
                    href={href}
                    style={{ ...linkCellStyle, color: 'var(--text-secondary)' }}
                    title={String(deviceCell)}
                  >
                    {deviceCell}
                  </Link>
                </td>
              )}
              <td style={{ padding: 0 }}>
                <Link href={href} style={{ ...linkCellStyle, display: 'flex', alignItems: 'center' }}>
                  <PriorityBadge band={row.priority_band} />
                </Link>
              </td>
              <td style={{ padding: 0 }}>
                <Link
                  href={href}
                  style={{ ...linkCellStyle, color: 'var(--text-secondary)' }}
                  title={row.fixed_in || ''}
                >
                  {row.fixed_in || '—'}
                </Link>
              </td>
              <td style={{ padding: 0 }}>
                <Link href={href} style={linkCellStyle}>
                  {row.is_fixed_recommended ? (
                    <span style={{ color: 'var(--green)' }}>Yes</span>
                  ) : (
                    <span style={{ color: 'var(--text-muted)' }}>No</span>
                  )}
                </Link>
              </td>
            </tr>
          );
        })}
        {rows.length === 0 && (
          <tr>
            <td colSpan={colCount} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 'var(--s5) var(--s4)' }}>
              {emptyMessage}
            </td>
          </tr>
        )}
      </tbody>
    </Table>
  );
}
