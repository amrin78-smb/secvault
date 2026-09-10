import Card, { CardBody } from '../ui/Card';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';
import NotMeasured from '../ui/NotMeasured';
import { SEVERITY_FILL, SEVERITY_TEXT_COLOR, SEVERITY_LABEL } from '../analysis/severityRamp';
import { timeAgo, absoluteUtc } from '../../lib/formatDisplay';

// Named VPN threat detections — the render half of lib/engines/vpnDetections.js.
//
// ⛔ SERVER COMPONENT, NO CLIENT JS. Everything here is static markup plus two
// native <details> accordions. There is no state to hold: the data arrives
// already computed and every list is capped server-side with its true total
// alongside it.
//
// ── ⛔ THE THING THIS FILE MUST GET RIGHT ─────────────────────────────────
// A detection that found nothing and a detection that COULD NOT LOOK must not
// look the same on screen. The engine already keeps them apart
// (`status: 'measured'` vs `'insufficient_baseline'`), and the whole risk here
// is flattening that back out into one empty table.
//
// So:
//   * `measured` + no findings  -> a plain "nothing matched" line. An earned
//                                  all-clear, in ordinary text.
//   * `insufficient_baseline`   -> a HATCHED panel, --unmeasured text, the
//                                  required-vs-held numbers, and the count of
//                                  items that could not be judged. Never an
//                                  empty table, never a green tick, and never
//                                  the reassuring grey of a muted zero.
//   * `no_data`                 -> the same treatment, different sentence.
//
// ⛔ NO HUE ON THE NOT-MEASURED STATE. --unmeasured and --hatch only. Painting
// it anywhere on the severity ramp — in either direction — is a claim SecVault
// has not earned (see components/ui/NotMeasured.js and the /exposure bar that
// drew its unmeasured segment in --yellow).

export const dynamic = 'force-dynamic';

// ⛔ ROW GEOMETRY FROM THE DENSITY TOKENS, never a hardcoded padding. A cell
// that hardcodes `padding: 12px 16px` opts itself out of Settings ->
// Appearance -> Density silently and sits at one height while the table around
// it changes.
const CELL = {
  padding: 'var(--row-pad-y) var(--row-pad-x)',
  fontSize: 'var(--row-font)',
  verticalAlign: 'top',
};

const TH = {
  textAlign: 'left',
  padding: 'var(--row-pad-y) var(--row-pad-x)',
  fontSize: 'var(--text-xs)',
  letterSpacing: '0.07em',
  textTransform: 'uppercase',
  color: 'var(--text-muted)',
  borderBottom: '1px solid var(--border)',
  whiteSpace: 'nowrap',
};

const MONO = { fontFamily: 'var(--font-mono)' };
const NUM = { textAlign: 'right', fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap' };

// How many rows a detection lists before it says "showing N of M".
// ⛔ Never a silent cut — the total is printed beside every capped list.
const ROWS_SHOWN = 15;

// The reason codes lib/engines/vpnDetections.js attaches to an unverifiable
// item, in the operator's words. ⛔ Each says WHOSE limitation it is: a device
// logging setting, or a gap in SecVault's own history. An anonymous "unknown"
// would leave the reader unable to act.
const REASON_TEXT = {
  'no-success-baseline':
    'the firewall that saw this logs no successful VPN authentications at all, so whether anything '
    + 'succeeded is unmeasured',
  'fleet-baseline-too-short':
    'SecVault does not yet hold enough VPN authentication history for "never before" to mean anything',
  'no-user-baseline':
    'this account has no earlier successful authentication, so there is nothing to call this new against',
  'no-hour-profile':
    'no hour-of-day profile exists yet, so no hour can be called unusual',
};

const STATUS_BADGE = {
  measured: { color: 'success', label: 'Measured' },
  insufficient_baseline: { color: 'muted', label: 'Insufficient baseline' },
  no_data: { color: 'muted', label: 'No data' },
};

// ── Small formatters (module top level, plain functions) ─────────────────

function n(value) {
  const v = Number(value);
  return Number.isFinite(v) ? v.toLocaleString() : '—';
}

function atLeast(value, isFloor) {
  return isFloor ? `≥ ${n(value)}` : n(value);
}

function severityCell(severity) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--s2)', whiteSpace: 'nowrap' }}>
      <span
        aria-hidden="true"
        style={{
          width: 8, height: 8, flex: 'none', borderRadius: '50%',
          background: SEVERITY_FILL[severity] || 'var(--unmeasured)',
        }}
      />
      <span style={{ color: SEVERITY_TEXT_COLOR[severity] || 'var(--text-muted)' }}>
        {SEVERITY_LABEL[severity] || '—'}
      </span>
    </span>
  );
}

function whenCell(value) {
  if (!value) return <NotMeasured reason="No timestamp was recorded for this observation." />;
  return <span title={absoluteUtc(value)}>{timeAgo(value)}</span>;
}

function countryCell(country) {
  if (!country) {
    // ⛔ Not "Unknown" — a made-up country would sit in the table looking like
    // a place. The failures ARE measured; only the location is not.
    return <NotMeasured reason="The firewall did not report a country for this address." />;
  }
  return country;
}

function listCell(values, emptyReason) {
  const list = Array.isArray(values) ? values.filter(Boolean) : [];
  if (list.length === 0) return <NotMeasured reason={emptyReason} />;
  const shown = list.slice(0, 3).join(', ');
  return <span title={list.join(', ')}>{shown}{list.length > 3 ? ` +${list.length - 3}` : ''}</span>;
}

// ── Per-detection columns ────────────────────────────────────────────────
//
// ⛔ Every column here is EVIDENCE — the numbers the severity was computed
// from — so an operator can disagree with a finding rather than only accept or
// dismiss it. Do not trade one of these for a prettier row.

const COLUMNS = {
  credential_spray: [
    { label: 'Source', width: '16%', cell: (f) => <span style={MONO}>{f.srcIp}</span> },
    { label: 'Country', width: '14%', cell: (f) => countryCell(f.country) },
    // ⛔ 15%, not 12%: at 12 the HEADING itself truncated to "Usernames tr…".
    // A clipped header makes the reader guess what the number counts, which is
    // exactly the column whose meaning carries the "at least" caveat.
    { label: 'Usernames tried', width: '15%', style: NUM, cell: (f) => atLeast(f.usernames, f.usernamesIsFloor) },
    { label: 'Failures', width: '10%', style: NUM, cell: (f) => n(f.failures) },
    { label: 'Hours', width: '7%', style: NUM, cell: (f) => n(f.hours) },
    { label: 'Seen by', width: '17%', cell: (f) => listCell(f.devices, 'This sender matched no managed firewall.') },
    { label: 'Last seen', width: '11%', cell: (f) => whenCell(f.lastSeenAt) },
    { label: 'Severity', width: '10%', cell: (f) => severityCell(f.severity) },
  ],
  brute_force: [
    { label: 'Account', width: '20%', cell: (f) => <span style={MONO}>{f.username}</span> },
    { label: 'Source', width: '15%', cell: (f) => <span style={MONO}>{f.srcIp}</span> },
    { label: 'Country', width: '13%', cell: (f) => countryCell(f.country) },
    { label: 'Attempts', width: '10%', style: NUM, cell: (f) => atLeast(f.attemptsFloor, f.attemptsIsFloor) },
    { label: 'Hours', width: '7%', style: NUM, cell: (f) => n(f.hours) },
    {
      label: 'Names tried by source',
      width: '13%',
      style: NUM,
      // Context, not decoration: 1 means genuinely focused on this account; 13
      // means a sprayer that happened to hit this name hardest.
      cell: (f) => (f.sourceUsernameBreadth === null || f.sourceUsernameBreadth === undefined
        ? <NotMeasured reason="This source's full username list was not resolved." />
        : n(f.sourceUsernameBreadth)),
    },
    { label: 'Last seen', width: '12%', cell: (f) => whenCell(f.lastSeenAt) },
    { label: 'Severity', width: '10%', cell: (f) => severityCell(f.severity) },
  ],
  account_targeted: [
    { label: 'Account', width: '32%', cell: (f) => <span style={MONO}>{f.username}</span> },
    { label: 'Source addresses', width: '14%', style: NUM, cell: (f) => n(f.sources) },
    { label: 'Countries', width: '11%', style: NUM, cell: (f) => n(f.countries) },
    { label: 'Attempts', width: '11%', style: NUM, cell: (f) => atLeast(f.attemptsFloor, f.attemptsIsFloor) },
    { label: 'Hours', width: '8%', style: NUM, cell: (f) => n(f.hours) },
    { label: 'Last seen', width: '13%', cell: (f) => whenCell(f.lastSeenAt) },
    { label: 'Severity', width: '11%', cell: (f) => severityCell(f.severity) },
  ],
  new_country_for_user: [
    { label: 'Account', width: '28%', cell: (f) => <span style={MONO}>{f.username}</span> },
    { label: 'New country', width: '16%', cell: (f) => countryCell(f.country) },
    {
      label: 'Known countries',
      width: '20%',
      cell: (f) => listCell(f.knownCountries, 'This account has no earlier successful authentication.'),
    },
    { label: 'Auth hours', width: '11%', style: NUM, cell: (f) => n(f.authHours) },
    { label: 'Firewall', width: '15%', cell: (f) => listCell(f.devices, 'Not attributed to a managed firewall.') },
    { label: 'Severity', width: '10%', cell: (f) => severityCell(f.severity) },
  ],
  country_change: [
    { label: 'Account', width: '26%', cell: (f) => <span style={MONO}>{f.username}</span> },
    {
      label: 'Countries',
      width: '18%',
      cell: (f) => (f.gapHours === 0
        ? `${f.fromCountry} + ${f.toCountry}`
        : `${f.fromCountry} → ${f.toCountry}`),
    },
    {
      label: 'Gap',
      width: '12%',
      style: NUM,
      // ⛔ The rollup is hourly, so 0 means "the same bucket", not "zero
      // seconds". The label says so rather than printing a false precision.
      cell: (f) => (f.gapHours === 0 ? 'same hour' : `${n(f.gapHours)} h`),
    },
    { label: 'Addresses', width: '20%', cell: (f) => <span style={MONO}>{[f.fromSrcIp, f.toSrcIp].filter(Boolean).join(' / ') || '—'}</span> },
    { label: 'Firewall', width: '14%', cell: (f) => (f.device || <NotMeasured reason="Not attributed to a managed firewall." />) },
    { label: 'Severity', width: '10%', cell: (f) => severityCell(f.severity) },
  ],
  off_hours_success: [
    { label: 'Account', width: '32%', cell: (f) => <span style={MONO}>{f.username}</span> },
    { label: 'Hour (UTC)', width: '13%', style: NUM, cell: (f) => `${String(f.hourUtc).padStart(2, '0')}:00` },
    { label: 'Auth hours', width: '12%', style: NUM, cell: (f) => n(f.authHours) },
    { label: 'From', width: '18%', cell: (f) => listCell(f.countries, 'The firewall did not report a country.') },
    { label: 'Firewall', width: '15%', cell: (f) => listCell(f.devices, 'Not attributed to a managed firewall.') },
    { label: 'Severity', width: '10%', cell: (f) => severityCell(f.severity) },
  ],
};

// ── Table renderers ──────────────────────────────────────────────────────

function findingsTable(id, rows, extraColumn) {
  const cols = COLUMNS[id] || [];
  const shown = rows.slice(0, ROWS_SHOWN);
  return (
    <div style={{ overflowX: 'auto' }}>
      {/* ⛔ tableLayout:'fixed' is required with percentage widths — without it
          columns collapse unpredictably on overflow. */}
      <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
        <colgroup>
          {cols.map((c) => <col key={c.label} style={{ width: c.width }} />)}
          {extraColumn ? <col style={{ width: '22%' }} /> : null}
        </colgroup>
        <thead>
          <tr>
            {cols.map((c) => (
              <th key={c.label} style={{ ...TH, ...(c.style || {}) }}>{c.label}</th>
            ))}
            {extraColumn ? <th style={TH}>{extraColumn.label}</th> : null}
          </tr>
        </thead>
        <tbody>
          {shown.map((f, i) => (
            <tr key={`${id}-${i}`} style={{ borderBottom: '1px solid var(--border-light)' }}>
              {cols.map((c) => (
                <td key={c.label} style={{ ...CELL, ...(c.style || {}) }}>{c.cell(f)}</td>
              ))}
              {extraColumn ? <td style={CELL}>{extraColumn.cell(f)}</td> : null}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > shown.length ? (
        <div style={{ padding: 'var(--s2) var(--row-pad-x)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          Showing {shown.length} of {n(rows.length)}.
        </div>
      ) : null}
    </div>
  );
}

// ⛔ THE NOT-MEASURED PANEL. Hatched, hueless, and it states the arithmetic:
// what the detection needed and what SecVault holds. A reader must be able to
// tell "we looked and found nothing" from "we could not look" without hovering
// anything.
function baselinePanel(detection) {
  const b = detection.baseline;
  const total = detection.unverifiableTotal || 0;
  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        background: 'var(--hatch)',
        backgroundColor: 'var(--surface-subtle)',
        padding: 'var(--s4)',
      }}
    >
      <div style={{ fontWeight: 600, color: 'var(--unmeasured)', fontSize: 'var(--text-sm)' }}>
        {detection.status === 'no_data'
          ? 'No VPN authentication evidence in scope'
          : 'Not measured — the baseline is too short'}
      </div>
      {b ? (
        <div style={{ marginTop: 'var(--s2)', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
          Needs <strong>{b.required}</strong> {b.unit}; SecVault holds{' '}
          <strong style={{ fontVariantNumeric: 'tabular-nums' }}>{b.have}</strong>
          {b.firstBucketAt ? (
            <> (first VPN authentication log <span title={absoluteUtc(b.firstBucketAt)}>{timeAgo(b.firstBucketAt)}</span>).</>
          ) : '.'}
        </div>
      ) : null}
      {total > 0 ? (
        <div style={{ marginTop: 'var(--s2)', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
          {/* ⛔ The TOTAL, not the length of the sampled list. */}
          <strong style={{ fontVariantNumeric: 'tabular-nums' }}>{n(total)}</strong>{' '}
          observation(s) could not be judged either way. This is <em>not</em> a finding of zero.
        </div>
      ) : null}
    </div>
  );
}

function unverifiableBlock(detection) {
  const rows = detection.unverifiable || [];
  const total = detection.unverifiableTotal || 0;
  if (total === 0) return null;
  const reasons = [...new Set(rows.map((r) => r.reason))];
  return (
    <details style={{ marginTop: 'var(--s3)' }}>
      <summary
        style={{
          cursor: 'pointer', fontSize: 'var(--text-sm)', color: 'var(--unmeasured)',
          padding: 'var(--s2) 0',
        }}
      >
        {n(total)} could not be verified{rows.length < total ? ` (${rows.length} shown)` : ''} —{' '}
        {reasons.map((r) => REASON_TEXT[r] || r).join('; ')}
      </summary>
      <div style={{ marginTop: 'var(--s2)' }}>
        {findingsTable(detection.id, rows, {
          label: 'Why not verified',
          cell: (f) => (
            <span style={{ color: 'var(--unmeasured)', fontSize: 'var(--text-xs)' }}>
              {REASON_TEXT[f.reason] || f.reason}
              {Array.isArray(f.blindDevices) && f.blindDevices.length > 0
                ? ` (${f.blindDevices.map((d) => d.deviceName || d.vendor || 'unnamed device').join(', ')})`
                : ''}
            </span>
          ),
        })}
      </div>
    </details>
  );
}

function caveatList(caveats) {
  if (!Array.isArray(caveats) || caveats.length === 0) return null;
  return (
    <ul
      style={{
        margin: 'var(--s3) 0 0', paddingLeft: 'var(--s5)',
        fontSize: 'var(--text-xs)', color: 'var(--text-muted)', lineHeight: 1.6,
      }}
    >
      {caveats.map((c) => <li key={c}>{c}</li>)}
    </ul>
  );
}

function detectionCard(detection) {
  const badge = STATUS_BADGE[detection.status] || STATUS_BADGE.no_data;
  const findings = detection.findings || [];
  const measured = detection.status === 'measured';
  return (
    <Card key={detection.id}>
      <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--s3)', flexWrap: 'wrap' }}>
          <span style={{ fontSize: 'var(--text-lg)', fontWeight: 600, color: 'var(--text-primary)' }}>
            {detection.title}
          </span>
          <Badge color={badge.color}>{badge.label}</Badge>
          {measured && findings.length > 0 ? (
            <Badge color="danger">{n(findings.length)} finding{findings.length === 1 ? '' : 's'}</Badge>
          ) : null}
          <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            {detection.question}
          </span>
        </div>

        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', lineHeight: 1.6 }}>
          {detection.method}
        </div>

        {/* ⛔ The off-hours findings name an hour; without the profile behind
            it the reader cannot tell WHY that hour is unusual, and a severity
            nobody can check is unfalsifiable. Only rendered once the profile
            is real — an empty quietHours list prints nothing rather than an
            implied "no hour is quiet". */}
        {measured && Array.isArray(detection.quietHours) && detection.quietHours.length > 0 ? (
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            Quiet hours, measured from this fleet&apos;s own successful-login distribution:{' '}
            <span style={{ ...MONO, fontVariantNumeric: 'tabular-nums' }}>
              {detection.quietHours.map((h) => `${String(h).padStart(2, '0')}:00`).join(', ')}
            </span>{' '}
            UTC.
          </div>
        ) : null}

        {measured && findings.length > 0 ? findingsTable(detection.id, findings) : null}

        {measured && findings.length === 0 ? (
          // ⛔ An EARNED all-clear, in ordinary text. Reachable only when the
          // detection genuinely evaluated its question.
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            Nothing matched this detection in the last {detection.windowLabel || 'window'}.
          </div>
        ) : null}

        {!measured ? baselinePanel(detection) : null}

        {unverifiableBlock(detection)}
        {caveatList(detection.caveats)}
      </CardBody>
    </Card>
  );
}

// ── Fleet-level strips ───────────────────────────────────────────────────

function historyStrip(data) {
  const b = data.baseline;
  return (
    <Card>
      <CardBody style={{ display: 'flex', gap: 'var(--s6)', flexWrap: 'wrap', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>
            Detection window
          </div>
          <div style={{ fontSize: 'var(--text-xl)', fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>
            {data.windowHours} h
          </div>
        </div>
        <div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>
            VPN auth history held
          </div>
          {/* ⛔ THE HEADLINE FACT ON THIS PAGE. Everything below that says
              "never before" is bounded by this number, so it is stated once,
              large, at the top — not buried in a per-detection footnote. */}
          <div style={{ fontSize: 'var(--text-xl)', fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>
            {b.hasHistory
              ? `${b.spanDays} day${b.spanDays === 1 ? '' : 's'}`
              : <NotMeasured reason="No VPN authentication rollups exist yet." />}
          </div>
          {b.firstBucketAt ? (
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>
              since <span title={absoluteUtc(b.firstBucketAt)}>{absoluteUtc(b.firstBucketAt)}</span>
            </div>
          ) : null}
        </div>
        <div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>
            Failed / successful logins
          </div>
          <div style={{ fontSize: 'var(--text-xl)', fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>
            <span style={{ color: 'var(--sev-crit)' }}>{n(data.coverage.totalFailures)}</span>
            <span style={{ color: 'var(--text-muted)' }}> / </span>
            <span>{n(data.coverage.totalSuccesses)}</span>
          </div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 2 }}>
            across {n(data.coverage.sourcesSeen)} source addresses
          </div>
        </div>
      </CardBody>
    </Card>
  );
}

// ⛔ THE REPORTING-GAP BANNER. Live on this fleet, TSR-TL reports 1,791 VPN
// authentication failures and ZERO successes. That is a device-side logging
// setting, not a 100% failure rate, and every success-dependent detection above
// excludes it. Saying so — and naming the firewall — is what stops a reader
// concluding the device is under a successful siege, and tells them exactly
// which setting would close the gap.
function reportingGapBanner(data) {
  const gaps = data.coverage.reportingGapDevices || [];
  if (gaps.length === 0) return null;
  return (
    <Card>
      <CardBody>
        <div style={{ display: 'flex', gap: 'var(--s3)', alignItems: 'flex-start' }}>
          <span
            aria-hidden="true"
            style={{
              width: 14, height: 10, flex: 'none', marginTop: 4, borderRadius: 3,
              border: '1px solid var(--border)',
              background: 'var(--hatch)', backgroundColor: 'var(--surface-subtle)',
            }}
          />
          <div>
            <div style={{ fontWeight: 600, fontSize: 'var(--text-sm)' }}>
              {gaps.length} firewall{gaps.length === 1 ? '' : 's'} report VPN failures but no successes
            </div>
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginTop: 'var(--s2)' }}>
              This is a device-side logging gap, <strong>not</strong> a 100% failure rate. Any detection
              whose claim includes “and none succeeded” is filed as <em>not verified</em> for sources
              these firewalls saw, never asserted.
            </div>
            <ul style={{ margin: 'var(--s2) 0 0', paddingLeft: 'var(--s5)', fontSize: 'var(--text-sm)' }}>
              {gaps.map((d) => (
                <li key={d.deviceId}>
                  <strong>{d.deviceName || d.deviceId}</strong>
                  <span style={{ color: 'var(--text-muted)' }}>
                    {' '}({d.vendor || 'unknown vendor'}) — {n(d.failureEvents)} failures,{' '}
                  </span>
                  <NotMeasured reason="This firewall logged no successful VPN authentication in the window, so its success count is not a measured zero." text="no successes measured" />
                </li>
              ))}
            </ul>
          </div>
        </div>
      </CardBody>
    </Card>
  );
}

/**
 * @param {object}  props
 * @param {object}  props.data   the return value of
 *                               lib/engines/vpnDetections.js `getVpnDetections(pool, { hours })`
 *                               — passed straight through, unmodified.
 */
export default function VpnDetections({ data }) {
  if (!data || !Array.isArray(data.detections)) {
    return (
      // EmptyState takes `message` only — passing a `title` it does not accept
      // would be silently dropped, the same trap CardHeader had.
      <EmptyState message="No VPN detection data for this scope." />
    );
  }

  const windowLabel = `${data.windowHours} h`;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
      {historyStrip(data)}
      {reportingGapBanner(data)}
      {data.detections.map((d) => detectionCard({ ...d, windowLabel }))}
    </div>
  );
}
