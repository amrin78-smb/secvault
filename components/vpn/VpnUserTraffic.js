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

// ⛔ The refusals, given the same weight as the answers. An operator who cannot
// see how much traffic went unnamed has no way to judge the names above it.
function unattributedPanel(unattributed, totals, collisions, collisionsTotal) {
  const rows = ['partial_hour', 'collision', 'gap'].map((key) => ({
    key,
    label: REASON_LABEL[key],
    ...unattributed[key],
  }));
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
            <p style={{ margin: '4px 0 0', ...SUBTLE, maxWidth: '90ch' }}>
              A VPN pool recycles addresses, so an hour that two sessions touched, or that a session
              held for only part of, cannot be assigned to a person without inventing the answer.
              These events are real and are counted here rather than dropped.
              {share == null
                ? ''
                : ` They are ${share}% of all traffic seen from these addresses in this window.`}
            </p>
          </div>
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
                  <td>{r.label}</td>
                  <td style={NUM}>{formatCount(r.buckets)}</td>
                  <td style={NUM}>{formatCount(r.events)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
          {collisionsTotal > 0 ? (
            <div style={SUBTLE}>
              {formatCount(collisionsTotal)} address-hour
              {collisionsTotal === 1 ? '' : 's'} were held by more than one session.
              {sameUser > 0
                ? ` ${sameUser} of the ${collisions.length} shown are one person reconnecting onto the same address — a benign ambiguity, and still an ambiguity.`
                : ''}
            </div>
          ) : null}
          {collisions.length > 0 ? (
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
          ) : null}
        </div>
      </CardBody>
    </Card>
  );
}

function notMeasuredPanel(coverage, notes, windowMeta) {
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
          <EmptyState
            message={
              coverage.reasonText
              || 'Traffic was seen from these addresses, but none of it fell in an hour a single '
                + 'session demonstrably held — so no name can be put to it. Every event is '
                + 'accounted for below.'
            }
          />
          <div style={SUBTLE}>{notes.vendorScope}</div>
        </div>
      </CardBody>
    </Card>
  );
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
  const data = await getVpnUserTraffic(pool, { days, deviceId, username, topUsers });
  const { coverage, notes, totals, users } = data;

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
        </div>
      </CardBody>
    </Card>
  );

  if (!data.measured || users.length === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
        {header}
        {notMeasuredPanel(coverage, notes, data.window)}
        {data.measured ? unattributedPanel(data.unattributed, totals, data.collisions, data.collisionsTotal) : null}
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
      {header}

      <Card>
        <CardBody>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
            {coverageStrip(coverage, data.window)}

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--s3)' }}>
              {statTile('Users named', formatCount(data.usersTotal), `${formatCount(coverage.sessionsJoinable)} joinable sessions`)}
              {statTile('Hours attributed', formatCount(totals.bucketsAttributed), `of ${formatCount(totals.bucketsConsidered)} address-hours seen`)}
              {statTile('Events attributed', formatCount(totals.eventsAttributed), `of ${formatCount(totals.eventsConsidered)} seen`)}
              {statTile('Pool addresses', formatCount(coverage.poolAddresses), 'observed being assigned')}
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

      {unattributedPanel(data.unattributed, totals, data.collisions, data.collisionsTotal)}
    </div>
  );
}
