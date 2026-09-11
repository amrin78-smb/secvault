import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';
import NotMeasured from '../ui/NotMeasured';
import {
  getVpnUserTraffic,
  DEFAULT_WINDOW_DAYS,
  DEFAULT_TOP_USERS,
} from '../../lib/engines/vpnTrafficAttribution';

// Per-user VPN TRAFFIC — what a named remote user actually did, joined from
// `vpn_sessions` (who held which assigned address, between which times) to
// `syslog_talker_hourly` (per-source-address hourly traffic totals).
//
// ⛔ SERVER component. No client JS: it fetches its own data exactly like
// VpnUserHeatmap, so it survives AutoRefresh's router.refresh() and every part
// of its state lives in the URL.
//
// ⛔ ═══ WHAT THIS SCREEN IS ALLOWED TO CLAIM ══════════════════════════════
// It puts a named employee's name over traffic. The engine refuses to attribute
// anything ambiguous — see lib/engines/vpnTrafficAttribution.js — and this
// component's job is to make sure the refusals are as visible as the answers.
// Concretely:
//
//   * the UNATTRIBUTED panel is not a footnote. Traffic SecVault declined to
//     name is rendered beside the traffic it named, with its reason, because a
//     table of users with no denominator invites the reader to assume it is
//     complete;
//   * an absent byte total renders through NotMeasured, never as 0 B — "we
//     could not measure this person's volume" must not read as "this person
//     moved no data";
//   * a zero-attribution result states WHY (too early, no traffic rows, no
//     history) instead of drawing an empty user list, which reads as "nobody
//     used the VPN";
//   * the Palo-Alto-only scope is stated on the panel, not implied.
//
// ⛔ Destinations and applications are deliberately ABSENT and the panel says
// so. Neither rollup that carries them is keyed by source address, so there is
// no honest way to narrow them to one user today. An approximation here would
// be a claim about where a named person went.
//
// ⛔ ═══ UNDER A FILTER, THE REFUSALS ARE SCOPED TOO ═══════════════════════
// This panel used to draw the engine's FLEET-wide `unattributed` and
// `collisions` verbatim, whatever the filter. So `?utUser=alice` rendered
// Alice's one row above 166,892 unnamed events and a collision table naming
// twenty other employees — the fleet's answer, printed under Alice's question.
// Two distinct faults: other people's names shown to someone who asked about
// one person, and a denominator ("27% of all traffic") that is not this
// filter's.
//
// Now: `data.scope` (engine-side, see vpnTrafficAttribution.js) carries the
// refusals that tie to the filtered subject, and this file renders
//   * the scoped table, whose row labels state the TIE for each reason — the
//     subject's own session for partial_hour and collision, the ADDRESS only
//     for gap, because a gap is by definition nobody's;
//   * collisions the subject was a PARTY to, and only those. Another
//     employee's name may appear here solely as the counterparty to the
//     subject's own missing hour, which is WHY it is missing;
//   * ONE fleet-wide line, labelled fleet-wide, so a bucket that ties to
//     nobody in this filter is still visible somewhere. ⛔ Scoping is a lens,
//     never a deletion: a coverage gap that vanishes when you filter is this
//     codebase's dominant bug wearing a filter.
//
// ⛔ And an unknown filter value is REFUSED, not applied. An id matching no
// active device used to scope the page to nothing and render confident zeros
// (VpnUserHeatmap already refused exactly this); a username matching no session
// rendered the fleet panel under a sentence claiming it was that user's.

const TH = {
  textAlign: 'left',
  fontSize: 'var(--text-xs)',
  textTransform: 'uppercase',
  letterSpacing: '0.04em',
  color: 'var(--text-muted)',
  fontWeight: 600,
};

const NUM = { textAlign: 'right', fontVariantNumeric: 'tabular-nums' };

const SUBTLE = { fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' };

// Why a bucket of traffic carries no name. Order is deliberate: the two that
// mean "SecVault refused to guess" come before the one that means "nobody we
// know of was there".
const REASON_LABEL = {
  partial_hour: 'Session held the address for only part of the hour',
  collision: 'Two or more sessions held the address in the same hour',
  gap: 'No known session held the address at that time',
};

// ⛔ THE SAME THREE REASONS, RE-WORDED FOR A FILTER — because the TIE to the
// filtered subject is different in each case and blurring them would overclaim.
// partial_hour and collision are tied by the subject's OWN session; a gap is
// tied by the address alone, and its label has to say that the traffic is
// nobody's rather than let a reader take it for the subject's.
const SCOPED_REASON_LABEL = {
  partial_hour: {
    label: 'One of their own sessions held the address for only part of the hour',
    why:
      'Their session entered or left the address mid-hour. The rest of that hour may have been '
      + 'somebody else’s, and the hourly rollup cannot separate the two halves — so the whole '
      + 'hour is unnamed.',
  },
  collision: {
    label: 'Another session held one of their addresses in the same hour',
    why:
      'Their own session was one of the parties. The other party is named below, because it is '
      + 'the reason this hour is missing from their total.',
  },
  gap: {
    label: 'No session at all held one of their addresses, at some hour in this window',
    why:
      'This traffic belongs to NOBODY SecVault can name — no session held the address then, so '
      + 'it is not this subject’s traffic. It is shown here only because the address is one they '
      + 'held at another time in this window.',
  },
};

function formatBytes(n) {
  if (n == null) return null;
  const b = Number(n);
  if (!Number.isFinite(b) || b < 0) return null;
  if (b < 1024) return `${b} B`;
  const units = ['KB', 'MB', 'GB', 'TB', 'PB'];
  let v = b / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v >= 10 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

function formatCount(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return '—';
  return v.toLocaleString('en-US');
}

function formatWhen(iso) {
  if (!iso) return '—';
  return String(iso).replace('T', ' ').replace(/\.\d+Z$/, 'Z').replace(/Z$/, ' UTC');
}

// ⛔ Tri-state volume in one cell. Three outcomes, three treatments:
// unmeasured (hueless em-dash + reason), a floor (prefixed >=, with the count
// of buckets that could not contribute), or a plain measured total.
function volumeCell(row) {
  const sent = formatBytes(row.bytesSent);
  const received = formatBytes(row.bytesReceived);
  if (sent == null && received == null) {
    return (
      <NotMeasured
        reason={
          'None of this user’s traffic hours carried summable byte counters, so their volume '
          + 'is unmeasured. This is not zero traffic — their event count is real.'
        }
      />
    );
  }
  const prefix = row.bytesArePartial ? '≥ ' : '';
  const title = row.bytesArePartial
    ? `A lower bound: ${row.unmeasuredByteBuckets} of ${row.byteBuckets + row.unmeasuredByteBuckets} `
      + 'attributed hours carried no summable byte counters and contribute nothing to this figure.'
    : `Measured across ${row.byteBuckets} attributed hour${row.byteBuckets === 1 ? '' : 's'}.`;
  return (
    <span title={title} style={{ fontVariantNumeric: 'tabular-nums' }}>
      {prefix}
      {sent || '0 B'}
      <span style={{ color: 'var(--text-muted)' }}> up</span>
      {' / '}
      {prefix}
      {received || '0 B'}
      <span style={{ color: 'var(--text-muted)' }}> down</span>
    </span>
  );
}

function statTile(label, value, hint) {
  return (
    <div
      style={{
        flex: '1 1 150px',
        minWidth: 150,
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: 'var(--s3)',
        background: 'var(--surface-subtle)',
      }}
    >
      <div style={{ fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-muted)' }}>
        {label}
      </div>
      <div style={{ fontSize: 'var(--text-xl)', fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>
        {value}
      </div>
      {hint ? <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{hint}</div> : null}
    </div>
  );
}

// ⛔ The coverage strip. Both bounds, always, whether or not either one bit —
// "session history starts here" and "the traffic rollup starts here" are the
// two sentences that stop this screen being read as a complete record.
function coverageStrip(coverage, windowMeta) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--s2) var(--s4)', alignItems: 'center' }}>
        <Badge color="info">
          {coverage.vendors.length > 0 ? coverage.vendors.join(', ') : 'Palo Alto'} gateways only
        </Badge>
        <span style={SUBTLE}>
          {formatWhen(windowMeta.from)} → {formatWhen(windowMeta.until)}
        </span>
        <span style={SUBTLE}>hourly grain</span>
      </div>
      <div style={{ ...SUBTLE, display: 'flex', flexWrap: 'wrap', gap: 'var(--s2) var(--s4)' }}>
        <span>
          Session history begins{' '}
          <strong>{coverage.sessionHistoryStart ? formatWhen(coverage.sessionHistoryStart) : 'never — none collected'}</strong>
        </span>
        <span>
          Traffic rollup retained from <strong>{formatWhen(coverage.trafficRollupStart)}</strong>
        </span>
        {coverage.trafficRollupEnd ? (
          <span>
            Traffic rollup current to <strong>{formatWhen(coverage.trafficRollupEnd)}</strong>
          </span>
        ) : null}
      </div>
      {coverage.boundNote ? (
        <div
          style={{
            ...SUBTLE,
            border: '1px solid var(--border)',
            borderLeft: '3px solid var(--unmeasured)',
            borderRadius: 'var(--radius-sm)',
            padding: 'var(--s2) var(--s3)',
            background: 'var(--surface-subtle)',
          }}
        >
          {coverage.boundNote}
        </div>
      ) : null}
      {coverage.sessionsUnjoinable > 0 ? (
        <div style={SUBTLE}>
          {coverage.sessionsUnjoinable} session
          {coverage.sessionsUnjoinable === 1 ? '' : 's'} in this window reported no assigned address
          and can never be joined to traffic. Anything they generated is counted below as
          unattributed.
        </div>
      ) : null}
      {coverage.sessionsClippedByDeviceCoverage > 0 ? (
        <div style={SUBTLE}>
          {coverage.sessionsClippedByDeviceCoverage} session
          {coverage.sessionsClippedByDeviceCoverage === 1 ? '' : 's'} began before their own gateway
          was first polled. Their earlier hours are not attributed — SecVault could not see who
          else held those addresses at the time.
        </div>
      ) : null}
      {coverage.truncatedSessions || coverage.truncatedBuckets ? (
        <div style={SUBTLE}>
          This window exceeded an internal row ceiling, so the figures below are a partial read of
          it. Narrow the window.
        </div>
      ) : null}
    </div>
  );
}

// A bordered aside. `tone` picks the tint PAIR — never a hardcoded hex, and
// never a tint background without its own -fg, or the text goes invisible in
// one of the two themes.
function noticeBox(tone, children) {
  const tinted = tone === 'warn';
  return (
    <div
      style={{
        ...SUBTLE,
        border: '1px solid var(--border)',
        borderLeft: '3px solid ' + (tinted ? 'var(--orange)' : 'var(--unmeasured)'),
        borderRadius: 'var(--radius-sm)',
        padding: 'var(--s2) var(--s3)',
        background: tinted ? 'var(--tint-warn)' : 'var(--surface-subtle)',
        color: tinted ? 'var(--tint-warn-fg)' : 'var(--text-secondary)',
        maxWidth: '95ch',
      }}
    >
      {children}
    </div>
  );
}

// What the filter actually selected, in words, for a heading.
function subjectLabel(scope) {
  const who = scope.username || scope.requestedUsername;
  const where = scope.deviceName || scope.deviceId;
  if (who && scope.deviceId) return `${who} on ${where}`;
  if (who) return who;
  if (where) return `gateway ${where}`;
  return 'this filter';
}

function collisionTable(collisions) {
  return (
    <Table>
      <colgroup>
        <col style={{ width: '22%' }} />
        <col style={{ width: '26%' }} />
        <col style={{ width: '32%' }} />
        <col style={{ width: '20%' }} />
      </colgroup>
      <thead>
        <tr>
          <th style={TH}>Assigned address</th>
          <th style={TH}>Hour (UTC)</th>
          <th style={TH}>Sessions in contention</th>
          <th style={{ ...TH, ...NUM }}>Events</th>
        </tr>
      </thead>
      <tbody>
        {collisions.map((c) => (
          <tr key={`${c.assignedIp}-${c.hourStart}`}>
            <td style={{ fontFamily: 'var(--font-mono)' }}>{c.assignedIp}</td>
            <td>{formatWhen(c.hourStart)}</td>
            <td>
              {c.usernames.join(', ')}
              {c.sameUser ? (
                <Badge color="muted" title="Both sessions belong to the same person, so the ambiguity is benign — but the traffic is still not attributed.">
                  same user
                </Badge>
              ) : null}
            </td>
            <td style={NUM}>{formatCount(c.events)}</td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function reasonRows(unattributed, labelFor) {
  return ['partial_hour', 'collision', 'gap'].map((key) => ({
    key,
    ...labelFor(key),
    ...unattributed[key],
  }));
}

function reasonTable(rows) {
  return (
    <Table>
      <colgroup>
        <col style={{ width: '58%' }} />
        <col style={{ width: '21%' }} />
        <col style={{ width: '21%' }} />
      </colgroup>
      <thead>
        <tr>
          <th style={TH}>Reason</th>
          <th style={{ ...TH, ...NUM }}>Hours</th>
          <th style={{ ...TH, ...NUM }}>Events</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.key}>
            <td title={r.why || undefined}>{r.label}</td>
            <td style={NUM}>{formatCount(r.buckets)}</td>
            <td style={NUM}>{formatCount(r.events)}</td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

// ⛔ THE ONE FLEET LINE, kept under every filter. Whatever could not be tied to
// the filtered subject is counted HERE and is never dropped — and it is
// labelled fleet-wide so it cannot be read as this filter's answer.
function fleetLine(unattributed, totals, collisionsTotal) {
  const buckets = ['partial_hour', 'collision', 'gap'].reduce((a, k) => a + unattributed[k].buckets, 0);
  const events = ['partial_hour', 'collision', 'gap'].reduce((a, k) => a + unattributed[k].events, 0);
  const share = totals.eventsConsidered > 0
    ? Math.round((events / totals.eventsConsidered) * 100)
    : null;
  return noticeBox('muted', (
    <span>
      <strong>Fleet-wide, not this filter:</strong> {formatCount(buckets)} address-hour
      {buckets === 1 ? '' : 's'} carrying {formatCount(events)} event{events === 1 ? '' : 's'} went
      unnamed across every VPN pool address in this window
      {share == null ? '' : ` — ${share}% of all traffic seen from those addresses`}, in{' '}
      {formatCount(collisionsTotal)} collision{collisionsTotal === 1 ? '' : 's'} and the two other
      reasons. Anything that could not be tied to this filter is counted in that figure, not
      dropped.
    </span>
  ));
}

// ⛔ The refusals, given the same weight as the answers. An operator who cannot
// see how much traffic went unnamed has no way to judge the names above it.
function fleetUnattributedPanel(data) {
  const { unattributed, totals, collisions, collisionsTotal } = data;
  const rows = reasonRows(unattributed, (k) => ({ label: REASON_LABEL[k] }));
  const unnamedEvents = rows.reduce((a, r) => a + r.events, 0);
  const share = totals.eventsConsidered > 0
    ? Math.round((unnamedEvents / totals.eventsConsidered) * 100)
    : null;
  const sameUser = collisions.filter((c) => c.sameUser).length;

  return (
    <Card>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 'var(--text-base)', fontWeight: 600 }}>
              Traffic SecVault would not put a name to
            </h3>
            <p style={{ margin: 'var(--s1) 0 0', ...SUBTLE, maxWidth: '90ch' }}>
              A VPN pool recycles addresses, so an hour that two sessions touched, or that a session
              held for only part of, cannot be assigned to a person without inventing the answer.
              These events are real and are counted here rather than dropped.
              {share == null
                ? ''
                : ` They are ${share}% of all traffic seen from these addresses in this window.`}
            </p>
          </div>
          {reasonTable(rows)}
          {collisionsTotal > 0 ? (
            <div style={SUBTLE}>
              {formatCount(collisionsTotal)} address-hour
              {collisionsTotal === 1 ? '' : 's'} were held by more than one session.
              {sameUser > 0
                ? ` ${sameUser} of the ${collisions.length} shown are one person reconnecting onto the same address — a benign ambiguity, and still an ambiguity.`
                : ''}
            </div>
          ) : null}
          {collisions.length > 0 ? collisionTable(collisions) : null}
        </div>
      </CardBody>
    </Card>
  );
}

// ⛔ THE SCOPED PANEL. Same buckets, tied to the filtered subject where a tie
// genuinely exists — and NOTHING here may name an employee other than the
// subject, except as the counterparty to a collision the subject was party to.
function scopedUnattributedPanel(data) {
  const scope = data.scope;
  const who = subjectLabel(scope);
  const rows = reasonRows(scope.unattributed, (k) => SCOPED_REASON_LABEL[k]);
  const share = scope.eventsConsidered > 0
    ? Math.round((scope.unattributedEvents / scope.eventsConsidered) * 100)
    : null;
  // Zeros are only drawable when traffic on the subject's own addresses was
  // actually measured. Otherwise they would be the failed-read-as-a-fact bug.
  const measurable = scope.bucketsConsidered > 0;
  const sameUser = scope.collisions.filter((c) => c.sameUser).length;
  const named = scope.collisions.filter((c) => !c.sameUser).length;

  return (
    <Card>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 'var(--text-base)', fontWeight: 600 }}>
              Traffic SecVault would not put a name to — {who}
            </h3>
            <p style={{ margin: 'var(--s1) 0 0', ...SUBTLE, maxWidth: '90ch' }}>
              Scoped to the {formatCount(scope.addresses)} address
              {scope.addresses === 1 ? '' : 'es'} this filter&rsquo;s{' '}
              {formatCount(scope.matchedSessions)} session
              {scope.matchedSessions === 1 ? '' : 's'} held during the window. Each row states what
              ties it to them — hover a row for the detail.
              {share == null || !measurable
                ? ''
                : ` These are ${share}% of the ${formatCount(scope.eventsConsidered)} events seen `
                  + 'from those addresses.'}
            </p>
          </div>

          {/* ⛔ WHICH ZERO IT IS, in the engine's own words. "Nothing unnamed",
              "nothing attributable", "no traffic on their addresses" and "this
              filter matched no session" are four different facts and only one
              of them is good news. */}
          {scope.reasonText ? noticeBox(measurable ? 'muted' : 'warn', scope.reasonText) : null}

          {measurable ? reasonTable(rows) : null}

          {scope.collisionsTotal > 0 ? (
            <div style={SUBTLE}>
              {formatCount(scope.collisionsTotal)} of these address-hours were held by more than one
              session at once, with one of this filter&rsquo;s own sessions as a party.
              {sameUser > 0
                ? ` ${sameUser} are this same person reconnecting onto the address they already held — a benign ambiguity, and still an ambiguity.`
                : ''}
              {named > 0
                ? ` ${named} involve a different account, named below because that is precisely why the hour is missing from this total.`
                : ''}
            </div>
          ) : null}
          {scope.collisions.length > 0 ? collisionTable(scope.collisions) : null}

          {fleetLine(data.unattributed, data.totals, data.collisionsTotal)}
        </div>
      </CardBody>
    </Card>
  );
}

function unattributedPanel(data) {
  return data.scope && data.scope.active
    ? scopedUnattributedPanel(data)
    : fleetUnattributedPanel(data);
}

function notMeasuredPanel(data) {
  const { coverage, notes, window: windowMeta, scope } = data;
  const scoped = scope && scope.active;
  // ⛔ ORDER MATTERS. Under a filter, the FILTER's reason is the answer to the
  // question the operator actually asked; the fleet-level coverage reason would
  // describe a window they did not ask about. The generic fallback below was
  // being printed for `?utUser=<nobody>` and claimed traffic HAD been seen from
  // "these addresses" — of which there were none. It can only ever be reached
  // unfiltered now.
  const message = (scoped && scope.reasonText)
    || coverage.reasonText
    || (scoped
      ? 'This filter matched nothing that could be measured. Nothing on this page is its answer.'
      : 'Traffic was seen from these addresses, but none of it fell in an hour a single '
        + 'session demonstrably held — so no name can be put to it. Every event is '
        + 'accounted for below.');
  return (
    <Card>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
          {coverageStrip(coverage, windowMeta)}
          {/* ⛔ NOT an empty table. An empty user list reads as "nobody used the
              VPN"; this says which measurement is missing and why. */}
          {/* ⛔ The fallback is not a shrug. If the engine measured the window
              and still named nobody, traffic WAS seen and every event of it is
              accounted for in the panel below — saying "no data" here would
              contradict the numbers on the same screen. */}
          <EmptyState message={message} />
          <div style={SUBTLE}>{notes.vendorScope}</div>
        </div>
      </CardBody>
    </Card>
  );
}

// ⛔ A FILTER VALUE THAT MATCHES NOTHING IS REFUSED, NOT APPLIED — the
// precedent is VpnUserHeatmap, which drops an unknown device id rather than let
// it scope the grid to nothing and render as "no VPN users". Dropping it
// silently is only half the job: the page then answers a question nobody asked,
// so the refusal is stated here, at the top, in the operator's terms.
function rejectedFilterNotice(kind, value) {
  if (kind === 'device') {
    return noticeBox('warn', (
      <span>
        <strong>That firewall filter was not applied.</strong> The id{' '}
        <code style={{ fontFamily: 'var(--font-mono)' }}>{value}</code> matches no active device in
        SecVault, so scoping to it would produce a page of confident zeros about a firewall that is
        not there. The unfiltered view is shown instead — everything below is the whole fleet, not
        that device.
      </span>
    ));
  }
  return null;
}

/**
 * @param {object}  props
 * @param {number} [props.days]      window size in days, 1..30 (default 7)
 * @param {string} [props.deviceId]  restrict to one VPN GATEWAY's sessions
 * @param {string} [props.username]  restrict to one user
 * @param {number} [props.topUsers]  rows to draw, 1..250 (default 50)
 */
export default async function VpnUserTraffic({
  days = DEFAULT_WINDOW_DAYS,
  deviceId = null,
  username = null,
  topUsers = DEFAULT_TOP_USERS,
}) {
  // ⛔ VALIDATE THE FILTER BEFORE SCOPING ANYTHING TO IT. An id that matches no
  // active device is dropped (VpnUserHeatmap's precedent) AND announced — see
  // rejectedFilterNotice. An unknown USERNAME cannot be checked here, because
  // "the set of usernames" is exactly what the engine computes; it is validated
  // there and comes back as scope.reason = 'filter_matched_no_sessions'.
  const requestedDeviceId = typeof deviceId === 'string' && deviceId.trim()
    ? deviceId.trim()
    : null;
  const { rows: devices } = await pool.query(
    `SELECT id, name FROM devices WHERE active = true ORDER BY name ASC`
  );
  const knownDevice = requestedDeviceId
    ? devices.find((d) => d.id === requestedDeviceId) || null
    : null;
  const rejectedDeviceId = requestedDeviceId && !knownDevice ? requestedDeviceId : null;

  const data = await getVpnUserTraffic(pool, {
    days,
    deviceId: knownDevice ? knownDevice.id : null,
    username,
    topUsers,
  });
  const { coverage, notes, totals, users } = data;
  const scope = data.scope;

  // What this page is currently answering, stated where it cannot be missed.
  const filterChips = scope && scope.active ? (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--s2)', alignItems: 'center' }}>
      <Badge color="info">Filtered: {subjectLabel(scope)}</Badge>
      <span style={SUBTLE}>
        {formatCount(scope.matchedSessions)} matching session
        {scope.matchedSessions === 1 ? '' : 's'} · {formatCount(scope.addresses)} address
        {scope.addresses === 1 ? '' : 'es'} held
      </span>
    </div>
  ) : null;

  const header = (
    <Card>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
          <div>
            <h2 style={{ margin: 0, fontSize: 'var(--text-lg)', fontWeight: 600 }}>
              VPN user traffic — attributed by assigned address
            </h2>
            <p style={{ margin: '6px 0 0', ...SUBTLE, maxWidth: '95ch' }}>
              A remote user&rsquo;s traffic is logged under the address the gateway{' '}
              <strong>assigned</strong> them, so it is joined to their name only for the hours a
              session demonstrably held that address. {notes.grain} {notes.vendorScope}
            </p>
          </div>
          {/* ⛔ Stated up front, not discovered by its absence: this screen
              answers volume, not where anybody went. */}
          <div
            style={{
              ...SUBTLE,
              border: '1px solid var(--border)',
              borderLeft: '3px solid var(--unmeasured)',
              borderRadius: 'var(--radius-sm)',
              padding: 'var(--s2) var(--s3)',
              background: 'var(--surface-subtle)',
            }}
          >
            {notes.destinations}
          </div>
          {filterChips}
        </div>
      </CardBody>
    </Card>
  );

  if (!data.measured || users.length === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
        {header}
        {rejectedFilterNotice('device', rejectedDeviceId)}
        {notMeasuredPanel(data)}
        {/* ⛔ Still shown, because every unnamed event has to be visible
            somewhere — but scoped when a filter is active, so a user who
            matched nothing is never handed the fleet's collision list. */}
        {data.measured ? unattributedPanel(data) : null}
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
      {header}
      {rejectedFilterNotice('device', rejectedDeviceId)}

      <Card>
        <CardBody>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
            {coverageStrip(coverage, data.window)}

            {/* ⛔ THE DENOMINATOR FOLLOWS THE FILTER. A one-user table above
                "of 4,025 address-hours seen" invites the reader to divide two
                numbers that are not about the same thing. Under a filter every
                tile counts only the subject's own addresses; the fleet figures
                are still on the page, in the fleet line of the panel below. */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--s3)' }}>
              {scope && scope.active ? (
                <>
                  {statTile('Users named', formatCount(data.usersTotal), `${formatCount(scope.matchedSessions)} matching sessions`)}
                  {statTile('Hours attributed', formatCount(scope.hoursAttributed), `of ${formatCount(scope.bucketsConsidered)} address-hours on their addresses`)}
                  {statTile('Events attributed', formatCount(scope.eventsAttributed), `of ${formatCount(scope.eventsConsidered)} on their addresses`)}
                  {statTile('Addresses held', formatCount(scope.addresses), `of ${formatCount(coverage.poolAddresses)} pool addresses fleet-wide`)}
                </>
              ) : (
                <>
                  {statTile('Users named', formatCount(data.usersTotal), `${formatCount(coverage.sessionsJoinable)} joinable sessions`)}
                  {statTile('Hours attributed', formatCount(totals.bucketsAttributed), `of ${formatCount(totals.bucketsConsidered)} address-hours seen`)}
                  {statTile('Events attributed', formatCount(totals.eventsAttributed), `of ${formatCount(totals.eventsConsidered)} seen`)}
                  {statTile('Pool addresses', formatCount(coverage.poolAddresses), 'observed being assigned')}
                </>
              )}
            </div>

            {data.usersTruncated ? (
              <div style={SUBTLE}>
                Showing the {users.length} busiest of {formatCount(data.usersTotal)} users with
                attributed traffic.
              </div>
            ) : null}

            <Table>
              <colgroup>
                <col style={{ width: '22%' }} />
                <col style={{ width: '9%' }} />
                <col style={{ width: '9%' }} />
                <col style={{ width: '12%' }} />
                <col style={{ width: '10%' }} />
                <col style={{ width: '24%' }} />
                <col style={{ width: '14%' }} />
              </colgroup>
              <thead>
                <tr>
                  <th style={TH}>User</th>
                  <th style={{ ...TH, ...NUM }} title="Sessions of this user that contributed at least one fully-covered hour.">
                    Sessions
                  </th>
                  <th style={{ ...TH, ...NUM }} title="Whole clock hours in which exactly one of this user's sessions held the address for the entire hour.">
                    Hours
                  </th>
                  <th style={{ ...TH, ...NUM }} title="Log events, not unique connections.">
                    Events
                  </th>
                  <th style={{ ...TH, ...NUM }} title="Events the firewall denied.">
                    Denied
                  </th>
                  <th style={TH} title="Summed only from log rows whose byte counters can be summed.">
                    Volume
                  </th>
                  <th style={TH}>Gateway</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.username}>
                    <td title={`${u.assignedIpCount} assigned address${u.assignedIpCount === 1 ? '' : 'es'} in this window`}>
                      {u.username}
                    </td>
                    <td style={NUM}>{formatCount(u.sessionCount)}</td>
                    <td style={NUM}>{formatCount(u.attributedHours)}</td>
                    <td style={NUM}>
                      {formatCount(u.events)}
                      {u.multiDeviceCounted ? (
                        <Badge
                          color="muted"
                          title={
                            `${u.loggingDeviceCount} firewalls logged this address, so a flow crossing more `
                            + 'than one of them is counted by each. This is a count of log events, not of '
                            + 'unique connections.'
                          }
                        >
                          x{u.loggingDeviceCount}
                        </Badge>
                      ) : null}
                    </td>
                    <td style={NUM}>
                      {u.denied > 0 ? (
                        <span style={{ color: 'var(--sev-high)' }}>{formatCount(u.denied)}</span>
                      ) : (
                        formatCount(u.denied)
                      )}
                    </td>
                    <td>{volumeCell(u)}</td>
                    <td title={u.gateways.join(', ')}>
                      {u.gateways.length > 0 ? u.gateways.join(', ') : (
                        <NotMeasured reason="The session's gateway device could not be resolved to a name." />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>

            <div style={{ ...SUBTLE, maxWidth: '95ch' }}>{notes.bytes} {notes.doubleCount}</div>
          </div>
        </CardBody>
      </Card>

      {unattributedPanel(data)}
    </div>
  );
}
