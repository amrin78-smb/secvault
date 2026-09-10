import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';
import { vendorLabel } from '../devices/vendorMeta';
import { getVpnUserPresence, INTENSITY_THRESHOLDS } from '../../lib/syslog/vpnPresence';

export const dynamic = 'force-dynamic';

// Per-user VPN activity heatmap — rows are users, columns are UTC days,
// intensity is how many distinct hours that user AUTHENTICATED in that day.
//
// ⛔ ═══ THE LABEL IS THE FEATURE. READ lib/syslog/vpnPresence.js FIRST. ═══
//
// The request was "how long they were connected". SecVault cannot answer that
// and this component must never look like it has: the only per-user VPN
// evidence is an hourly rollup of usernames that AUTHENTICATED, so a login held
// open for eight hours is ONE hour here. Every heading, the legend, the
// tooltips and the footer say "authenticated", and the gap is stated on screen
// in the operator's own words rather than buried in a tooltip — they asked for
// duration, so they are owed the reason they are not getting it.
//
// ── ⛔ WHY DAY COLUMNS AND NOT HOUR COLUMNS ───────────────────────────────
// 30 days x 24 hours is 720 columns: at any readable row height that is a
// barcode, not a table. A column is a day; the hour detail is preserved and
// surfaced on hover, so the drill-down costs a pointer move rather than a page.
//
// ── ⛔ WHY THE INTENSITY RAMP IS ONE HUE AND NEVER THE SEVERITY RAMP ──────
// A heavily-used VPN account is BUSY, not CRITICAL. Painting the busiest row
// red would spend the product's loudest signal on its most ordinary fact, and
// on a security console red has one job. Sequential tints of --primary only.

// ⛔ ROW GEOMETRY COMES FROM THE DENSITY TOKENS, never a hardcoded padding —
// otherwise this table alone ignores Settings -> Appearance -> Density while
// every other table on the page changes height.
const CELL = {
  padding: 'var(--row-pad-y) var(--row-pad-x)',
  fontSize: 'var(--row-font)',
  verticalAlign: 'middle',
};

const TH = {
  textAlign: 'left',
  padding: 'var(--row-pad-y) var(--row-pad-x)',
  fontSize: 'var(--text-xs)',
  letterSpacing: '0.07em',
  textTransform: 'uppercase',
  color: 'var(--text-muted)',
  fontWeight: 700,
  borderBottom: '1px solid var(--border)',
  whiteSpace: 'nowrap',
};

// A day column is far too narrow for the uppercase/letter-spaced header above.
const DAY_TH = {
  ...TH,
  textAlign: 'center',
  padding: 'var(--row-pad-y) 0',
  letterSpacing: 0,
  textTransform: 'none',
  fontWeight: 600,
};

const DAY_CELL = { padding: '2px 1px', verticalAlign: 'middle', textAlign: 'center' };

// Sequential ramp: one hue, five steps, tracking INTENSITY_THRESHOLDS.
//
// ⛔ Opacity over a token, not five hardcoded hexes. --primary is re-picked per
// theme (the teal that reads on white goes muddy on near-black), so a literal
// ramp would be correct in exactly one theme. Index 0 is never drawn — a zero
// is a different STATE, not the faintest shade of activity.
const LEVEL_OPACITY = [0, 0.22, 0.4, 0.58, 0.78, 1];

const WINDOW_OPTIONS = [7, 14, 30];
const TOP_OPTIONS = [10, 25, 50];

const LABEL = {
  display: 'block',
  fontSize: 11,
  fontWeight: 700,
  letterSpacing: '0.06em',
  textTransform: 'uppercase',
  color: 'var(--text-muted)',
  marginBottom: 4,
};

const FIELD = {
  width: '100%',
  padding: '7px 9px',
  fontSize: 'var(--text-sm)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)',
  background: 'var(--bg-card)',
  color: 'var(--text-primary)',
};

// ⛔ Plain functions returning JSX, defined at module top level and called
// imperatively. Never components nested inside a component — CLAUDE.md's React
// rule: a nested definition remounts on every render.

function swatch({ background, backgroundColor, border, opacity }) {
  return (
    <span
      aria-hidden="true"
      style={{
        display: 'inline-block',
        width: 14,
        height: 14,
        flex: 'none',
        borderRadius: 3,
        border: border || '1px solid var(--border-light)',
        background: background || 'transparent',
        backgroundColor: backgroundColor || 'transparent',
        opacity: opacity === undefined ? 1 : opacity,
      }}
    />
  );
}

function legendItem(node, text) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--s2)' }}>
      {node}
      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>{text}</span>
    </span>
  );
}

function rangeLabel(index) {
  const lo = INTENSITY_THRESHOLDS[index];
  const hi = index + 1 < INTENSITY_THRESHOLDS.length ? INTENSITY_THRESHOLDS[index + 1] - 1 : 24;
  return lo === hi ? `${lo} h` : `${lo}–${hi} h`;
}

function formatHourList(hours) {
  if (!Array.isArray(hours) || hours.length === 0) return '';
  return hours.map((h) => `${String(h).padStart(2, '0')}:00`).join(', ');
}

function formatDateTime(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return `${d.toISOString().replace('T', ' ').slice(0, 16)} UTC`;
}

/**
 * ⛔ THE WHOLE POINT OF THIS FUNCTION: a real zero and a not-measured cell must
 * not look the same. A zero is a flat empty square with a light border ("we
 * looked, they were not there"); every unmeasured state is HATCHED and has no
 * hue at all ("we could not look"). Rendering both as blank space is the
 * failed-read-as-a-fact bug drawn in a grid — and in this grid it would read as
 * a confident accusation that a user was inactive.
 */
function cellVisual(cell, dayMeta) {
  const base = {
    display: 'block',
    width: '100%',
    height: 16,
    borderRadius: 3,
  };

  if (cell.state === 'active') {
    const hourText = formatHourList(cell.hourList);
    const title =
      `${cell.day} — authenticated in ${cell.hours} distinct hour${cell.hours === 1 ? '' : 's'}`
      + (hourText ? ` (${hourText} UTC)` : '')
      + (cell.lowerBound ? ' — AT LEAST: a username list was capped this day, so this is a floor.' : '')
      + (dayMeta && dayMeta.partial ? ` — only ${dayMeta.hoursCovered} of 24 hours of this day have log coverage.` : '')
      + '\nHours in which a login was recorded, NOT hours connected.';
    return (
      <span
        title={title}
        aria-label={title}
        style={{
          ...base,
          backgroundColor: 'var(--primary)',
          opacity: LEVEL_OPACITY[cell.level] || LEVEL_OPACITY[1],
          // A capped day can only under-report, so the cell says "at least".
          outline: cell.lowerBound ? '1px dashed var(--unmeasured)' : 'none',
          outlineOffset: cell.lowerBound ? '-1px' : 0,
        }}
      />
    );
  }

  if (cell.state === 'zero') {
    const title = `${cell.day} — no login recorded for this user. ${cell.reason}`;
    return (
      <span
        title={title}
        aria-label={title}
        style={{
          ...base,
          backgroundColor: 'var(--surface-subtle)',
          border: '1px solid var(--border-light)',
        }}
      />
    );
  }

  // Every remaining state is NOT MEASURED: hatched, no hue, and the reason is
  // always available on hover. --hatch is a repeating-linear-gradient, so it
  // goes in `background` over a `backgroundColor` ground.
  const title = `${cell.day} — NOT MEASURED. ${cell.reason}`;
  return (
    <span
      title={title}
      aria-label={title}
      style={{
        ...base,
        background: 'var(--hatch)',
        backgroundColor: 'var(--surface-subtle)',
        border: '1px solid var(--border)',
      }}
    />
  );
}

function filterForm(devices, deviceId, days, topUsers) {
  return (
    <form method="get" action="/vpn">
      {/* Keeps the reader on this tab when the filter is applied. */}
      <input type="hidden" name="vtab" value="presence" />
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
          gap: 12,
          alignItems: 'end',
        }}
      >
        <div>
          <label style={LABEL} htmlFor="hm-device">Firewall</label>
          <select id="hm-device" name="hmDevice" defaultValue={deviceId || ''} style={FIELD}>
            <option value="">All firewalls</option>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name} ({vendorLabel(d.vendor, { short: true })})
              </option>
            ))}
          </select>
        </div>
        <div>
          <label style={LABEL} htmlFor="hm-days">Window</label>
          <select id="hm-days" name="hmDays" defaultValue={String(days)} style={FIELD}>
            {WINDOW_OPTIONS.map((n) => (
              <option key={n} value={n}>Last {n} days</option>
            ))}
          </select>
        </div>
        <div>
          <label style={LABEL} htmlFor="hm-top">Users shown</label>
          <select id="hm-top" name="hmTop" defaultValue={String(topUsers)} style={FIELD}>
            {TOP_OPTIONS.map((n) => (
              <option key={n} value={n}>Top {n}</option>
            ))}
          </select>
        </div>
        <div>
          <button type="submit" className="btn btn-primary" style={{ width: '100%' }}>Apply</button>
        </div>
      </div>
    </form>
  );
}

function coverageStrip(coverage, days) {
  const items = [];

  // ⛔ HOW MUCH HISTORY ACTUALLY EXISTS, first and unmissable. The collector's
  // first day is 2026-09-08, so a 30-day window is mostly empty today and fills
  // in over the coming month. Without this line, 27 hatched columns read as a
  // fault rather than as a product that has not been running long enough yet.
  if (!coverage.firstLogAt) {
    items.push(['No syslog history at all', 'SecVault holds no logs for this selection, so nothing in this grid is measured.']);
  } else if (coverage.requestedExceedsHistory) {
    items.push([
      `${coverage.historyDays} day${coverage.historyDays === 1 ? '' : 's'} of history, ${days}-day window`,
      `Log history for this selection begins ${formatDateTime(coverage.firstLogAt)}. Earlier columns are hatched because they predate collection — not because these users were idle.`,
    ]);
  } else {
    items.push([`${days} days of history available`, `Log history begins ${formatDateTime(coverage.firstLogAt)}.`]);
  }

  items.push([
    `${coverage.measuredDays} of ${days} days measured`,
    'A day counts as measured only if syslog arrived AND at least one successful VPN login was recorded in it. Any other day cannot support a zero for anybody, so it is hatched.',
  ]);

  items.push([
    `${coverage.rankedUsers} of ${coverage.totalUsers} users shown`,
    'Ranked by the number of distinct hours in which they authenticated.',
  ]);

  if (coverage.truncatedBuckets > 0) {
    items.push([
      `${coverage.truncatedBuckets} capped username lists`,
      'These hours stored a TRUNCATED user list, so a user missing from them may have been dropped rather than absent. Affected days are hatched for absent users and marked as a floor for present ones.',
    ]);
  }

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--s2) var(--s5)' }}>
      {items.map(([text, why]) => (
        <span
          key={text}
          title={why}
          style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', borderBottom: '1px dotted var(--border)' }}
        >
          {text}
        </span>
      ))}
    </div>
  );
}

function vendorGapNotice(gaps) {
  if (!gaps || gaps.length === 0) return null;
  // ⛔ Measured on this fleet: FortiOS logs SSL-VPN FAILURES in bulk and
  // successes essentially not at all (a device-side logging setting SecVault
  // cannot change). Without this line a Fortinet selection renders an empty
  // grid that reads "nobody uses this VPN", which is the opposite of true.
  return (
    <div
      style={{
        display: 'flex',
        gap: 'var(--s3)',
        alignItems: 'flex-start',
        padding: 'var(--s3) var(--s4)',
        borderRadius: 'var(--radius)',
        background: 'var(--tint-warn)',
        color: 'var(--tint-warn-fg)',
        fontSize: 'var(--text-sm)',
      }}
    >
      <span>
        <strong>Successful logins are not being reported</strong> by{' '}
        {gaps.map((g) => `${vendorLabel(g.vendor)} (${g.failureRows.toLocaleString()} failed logins recorded, 0 successful)`).join('; ')}.
        {' '}An empty row here is a gap in what the firewall sends, not evidence that nobody connected. Enable successful-VPN-login logging on the device to populate this grid.
      </span>
    </div>
  );
}

export default async function VpnUserHeatmap({ deviceId, days, topUsers }) {
  const { rows: devices } = await pool.query(
    `SELECT id, name, vendor FROM devices WHERE active = true ORDER BY name ASC`
  );

  // An unknown device id is dropped rather than passed through: it would
  // silently scope the grid to nothing and render as "no VPN users".
  const scopedDeviceId = devices.some((d) => d.id === deviceId) ? deviceId : null;

  const presence = await getVpnUserPresence(pool, {
    days,
    deviceId: scopedDeviceId,
    topUsers,
  });

  const { coverage, users, days: dayMeta, notes } = presence;
  const device = devices.find((d) => d.id === scopedDeviceId) || null;
  const dayColWidth = `${(74 / Math.max(1, dayMeta.length)).toFixed(3)}%`;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
      <Card>
        <CardBody>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
            <div>
              <h2 style={{ margin: 0, fontSize: 'var(--text-lg)', fontWeight: 600 }}>
                VPN user activity — hours authenticated
              </h2>
              {/* ⛔ THE UNIT, stated before the grid and not in a footnote. */}
              <p style={{ margin: '6px 0 0', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', maxWidth: '90ch' }}>
                Each square is one UTC day. Its shade is the number of distinct hours in which that
                user <strong>authenticated</strong> to the VPN — <strong>not</strong> how long they
                stayed connected. {notes.durationGap}
              </p>
            </div>
            {filterForm(devices, scopedDeviceId, presence.windowDays, topUsers)}
          </div>
        </CardBody>
      </Card>

      {vendorGapNotice(coverage.successReportingGaps)}

      <Card>
        <CardBody>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--s3)', alignItems: 'center' }}>
              <Badge color="info">{device ? device.name : 'All firewalls'}</Badge>
              <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                {presence.dayKeys[0]} → {presence.dayKeys[presence.dayKeys.length - 1]} (UTC)
              </span>
            </div>

            {coverageStrip(coverage, presence.windowDays)}

            {/* Legend. The three families must stay visually distinct: activity
                (one hue, five steps), a real zero (flat), and NOT MEASURED
                (hatched, no hue). */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--s2) var(--s4)', alignItems: 'center' }}>
              {legendItem(
                <span style={{ display: 'inline-flex', gap: 2 }}>
                  {INTENSITY_THRESHOLDS.map((t, i) => (
                    <span key={t} title={`${rangeLabel(i)} authenticated`}>
                      {swatch({ backgroundColor: 'var(--primary)', opacity: LEVEL_OPACITY[i + 1], border: '1px solid transparent' })}
                    </span>
                  ))}
                </span>,
                `${rangeLabel(0)} → ${rangeLabel(INTENSITY_THRESHOLDS.length - 1)} authenticated`
              )}
              {legendItem(
                swatch({ backgroundColor: 'var(--surface-subtle)' }),
                'No login this day (measured)'
              )}
              {legendItem(
                swatch({ background: 'var(--hatch)', backgroundColor: 'var(--surface-subtle)', border: '1px solid var(--border)' }),
                'Not measured — no coverage, no successful-login evidence, or a capped user list'
              )}
            </div>

            {users.length === 0 ? (
              <EmptyState
                message={
                  coverage.successReportingGaps.length > 0
                    ? 'No successful VPN logins have been recorded for this selection — see the note above. This is a device-side logging gap, not an absence of VPN use.'
                    : 'No successful VPN logins recorded for this selection in this window.'
                }
              />
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', minWidth: 720, borderCollapse: 'collapse', tableLayout: 'fixed' }}>
                  {/* ⛔ tableLayout:'fixed' is mandatory with percentage widths
                      — CLAUDE.md's rule; without it 30 narrow columns collapse
                      unpredictably the moment one username is long. */}
                  <colgroup>
                    <col style={{ width: '20%' }} />
                    <col style={{ width: '6%' }} />
                    {dayMeta.map((d) => <col key={d.key} style={{ width: dayColWidth }} />)}
                  </colgroup>
                  <thead>
                    <tr>
                      <th style={TH}>User</th>
                      <th style={{ ...TH, textAlign: 'right' }} title="Total distinct hours in which this user authenticated during the window. Not connected time.">
                        Hrs
                      </th>
                      {dayMeta.map((d) => (
                        <th
                          key={d.key}
                          style={{
                            ...DAY_TH,
                            // A day with no coverage is muted in the header too,
                            // so the reader can see the gap without reading a
                            // single cell.
                            color: d.covered ? 'var(--text-muted)' : 'var(--unmeasured)',
                          }}
                          title={
                            d.preHistory
                              ? `${d.key} — before log collection began. Not measured.`
                              : d.covered
                                ? `${d.key} — ${d.hoursCovered}/24 hours of log coverage from ${d.devicesReporting} firewall${d.devicesReporting === 1 ? '' : 's'}; ${d.successRows} successful and ${d.failureRows} failed VPN auth buckets.`
                                : `${d.key} — no syslog reached SecVault from this selection. Not measured.`
                          }
                        >
                          {d.key.slice(8)}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((u) => (
                      <tr key={u.username} style={{ borderTop: '1px solid var(--border-light)' }}>
                        <td style={{ ...CELL, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={
                          `${u.username} — authenticated in ${u.authHours} distinct hours across ${u.authDays} day(s) on ${u.devices} firewall(s). `
                          + `First ${formatDateTime(u.firstSeenAt)}, last ${formatDateTime(u.lastSeenAt)}.`
                        }>
                          {u.username}
                        </td>
                        <td style={{ ...CELL, textAlign: 'right', fontVariantNumeric: 'tabular-nums', color: 'var(--text-secondary)' }}>
                          {u.authHours}
                        </td>
                        {u.cells.map((c, i) => (
                          <td key={c.day} style={DAY_CELL}>{cellVisual(c, dayMeta[i])}</td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* ⛔ The duration gap, restated where a reader who scrolled past the
                header will still meet it, together with what would close it.
                This is a retention change, not a UI one. */}
            <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-muted)', maxWidth: '95ch' }}>
              <strong>Why not connected time?</strong> The only per-user VPN evidence SecVault holds
              is an hourly rollup of the usernames that authenticated, built from firewall syslog. It
              carries no session end and no duration.
              {/* ⛔ This paragraph used to end "...that is a schema and retention change, and it
                  is not what this grid does" — written before vpn_sessions existed. It went FALSE
                  on 2026-09-10 and then contradicted the note ~600px above it on the same card,
                  which already said duration IS measured separately. A reader who scrolled
                  concluded the product cannot answer a question it answers on the next tab. */}
              {' '}Connected duration is measured separately, from the
              <code style={{ fontFamily: 'var(--font-mono)' }}> vpn_sessions </code>
              history added on 2026-09-10 — see the VPN session views.
              <code style={{ fontFamily: 'var(--font-mono)' }}> vpn_active_sessions </code>
              itself is still deleted and reinserted on every poll, so it only ever holds "right
              now"; the history table is what retains it. This grid measures a different thing.
            </p>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
