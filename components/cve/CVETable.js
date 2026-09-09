import Link from 'next/link';
import Table from '../ui/Table';
import PriorityBadge from './PriorityBadge';
import CVEBadge from './CVEBadge';
import NotMeasured from '../ui/NotMeasured';

function cvssStyle(score) {
  if (score === null || score === undefined) return { color: 'var(--text-muted)' };
  const n = Number(score);
  if (Number.isNaN(n)) return { color: 'var(--text-muted)' };
  if (n >= 9) return { color: 'var(--red)', fontWeight: 600 };
  if (n >= 7) return { color: 'var(--yellow)', fontWeight: 600 };
  if (n >= 4) return { color: 'var(--text-primary)' };
  return { color: 'var(--text-muted)' };
}

// ── CVSS provenance ───────────────────────────────────────────────────────
// ⛔ THIS IS A LABEL, NEVER A CONVERSION. Measured on the live fleet, a CVE
// carries exactly ONE metric version: 1 advisory of 1,001 has both a v3 and a
// v4 vector, and 110 of 159 live assessments are banded on v4 with NO v3
// available at all. The mix is therefore STRUCTURAL — it is whatever each CNA
// published — not a defect to be normalised away, and picking v3 as the
// authoritative scale would leave those 110 unscored, which the priority tree
// reads as "not scored". v3.x and v4.0 use different metrics and different
// formulas and there is no conversion between them, so naming the scale beside
// the number is the only honest fix available.
//
// ⛔ Never add a "normalised" or converted score here — that is exactly the
// fabricated-value bug this codebase exists to avoid — and never let the scale
// reach a band: the priority tree bands on cvss_score ALONE (CLAUDE.md rules 3
// and 4). Everything below is presentation.
function cvssScaleLabel(version) {
  if (version === null || version === undefined) return null;
  const v = String(version).trim().replace(/^v/i, '');
  return v ? `v${v}` : null;
}

const CVSS_SOURCE_LABELS = { nvd: 'NVD', circl: 'CIRCL', psirt: 'vendor PSIRT' };

function cvssSourceLabel(source) {
  if (!source) return null;
  return CVSS_SOURCE_LABELS[String(source).toLowerCase()] || String(source);
}

// The scale, shown beside the score. Deliberately small and muted — the number
// stays the prominent thing, and the scale is the footnote that stops two
// numbers measured differently from being read as one ranking.
//
// ⛔ THREE STATES, not two:
//   scale recorded        → "v4.0"
//   scale NULL            → NotMeasured. cvss_version is NULL on every advisory
//                           until each feed's next sync rewrites it, and stays
//                           NULL for the 255 advisories carrying no vector at
//                           all. NEVER assume v3.1.
//   column never SELECTed → nothing at all. That is a gap in what SecVault
//                           ASKED for, not a fact about the advisory, and
//                           printing "not recorded" about a column we never
//                           read would be its own fabricated answer. A caller
//                           that wants the scale adds advisories.cvss_version
//                           (and optionally cvss_source) to its own query.
function CvssScale({ row }) {
  if (row.cvss_score === null || row.cvss_score === undefined) return null;
  if (!Object.prototype.hasOwnProperty.call(row, 'cvss_version')) return null;
  const label = cvssScaleLabel(row.cvss_version);
  if (!label) {
    return (
      <span style={{ marginLeft: 5, fontSize: 'var(--text-xs)', fontWeight: 400 }}>
        <NotMeasured
          text="v—"
          reason="The CVSS scale this score was measured on was not recorded. It is not assumed to be v3.1 — the scale is filled in the next time the feed that supplied this score syncs, and stays empty for advisories that carry no vector at all."
        />
      </span>
    );
  }
  const source = cvssSourceLabel(row.cvss_source);
  return (
    <span
      title={`CVSS ${label} base score${source ? `, supplied by ${source}` : ''}. Scores measured on different CVSS versions are not directly comparable.`}
      style={{ marginLeft: 5, fontSize: 'var(--text-xs)', fontWeight: 400, color: 'var(--text-muted)' }}
    >
      {label}
    </span>
  );
}

// Does THIS list actually mix scales? The caveat is rendered only when it does.
// A permanent banner under every table is furniture people stop reading, and
// the note is supposed to disappear on its own once every row on screen shares
// one recorded scale.
function cvssScaleMix(rows) {
  const majors = new Set();
  let unrecorded = false;
  for (const r of rows) {
    if (r.cvss_score === null || r.cvss_score === undefined) continue;
    if (!Object.prototype.hasOwnProperty.call(r, 'cvss_version')) continue;
    const label = cvssScaleLabel(r.cvss_version);
    // Major version only: v3.0 vs v3.1 is the same formula family and is not
    // worth a warning; v3.x vs v4.0 is a different measurement entirely.
    if (label) majors.add(label.replace(/^v/, '').split('.')[0]);
    else unrecorded = true;
  }
  return { mixed: majors.size > 1, unrecorded };
}

function CvssScaleNote({ rows }) {
  const { mixed, unrecorded } = cvssScaleMix(rows);
  if (!mixed && !unrecorded) return null;
  return (
    <p style={{ marginTop: 'var(--s2)', fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
      {mixed
        ? 'These scores are not all on the same CVSS scale — v3.x and v4.0 use different formulas, so this ordering ranks the list but does not strictly compare the numbers.'
        : 'Some of these scores have no recorded CVSS scale, and v3.x and v4.0 use different formulas — so this ordering ranks the list but does not strictly compare the numbers.'}
    </p>
  );
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
    <div>
    <Table stickyHeader maxHeight="70vh">
      <colgroup>
        <col style={{ width: showDeviceColumn ? '16%' : '20%' }} />
        {/* ⛔ CVSS now carries a "9.8 v4.0" pair rather than a bare number, so
            this column was widened from 8%. ui/Table enforces
            tableLayout:'fixed', which means these percentages are the whole
            story — widening a cell's content without widening its <col> just
            ellipsises the new part away silently. */}
        <col style={{ width: '11%' }} />
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
                  {/* A missing CVSS is the SCORER's gap, not a low score. And
                      with no score there is no scale to name either, so the
                      suffix stays off rather than stacking a second absence
                      next to the first. */}
                  {row.cvss_score === null || row.cvss_score === undefined ? (
                    <NotMeasured reason="No CVSS base score has been published for this CVE yet. It is unscored, not low-severity." />
                  ) : (
                    <>
                      {row.cvss_score}
                      <CvssScale row={row} />
                    </>
                  )}
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
    {/* One sentence, under the ranked list, and only when the rows on screen
        genuinely mix scales (or hide one). See cvssScaleMix above. */}
    <CvssScaleNote rows={rows} />
    </div>
  );
}
