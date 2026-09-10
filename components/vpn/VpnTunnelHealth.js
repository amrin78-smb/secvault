import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';
import NotMeasured, { CoverageNote } from '../ui/NotMeasured';
import TimeAgo from '../ui/TimeAgo';
import { SEVERITY_TEXT_COLOR } from '../analysis/severityRamp';
import { vendorLabel } from '../devices/vendorMeta';
import { getVpnTunnelHealth } from '../../lib/engines/vpnTunnelHealth';

// Fleet-wide SITE-TO-SITE IPSEC TUNNEL HEALTH — "which tunnels are down, and
// how much of the fleet can SecVault actually answer that for?"
//
// ⛔ SERVER component. It fetches its own data through `pool`, exactly like
// VpnUserHeatmap / VpnUserTraffic, so it survives AutoRefresh's
// router.refresh() and needs no client JS at all. Every judgement is made in
// lib/engines/vpnTunnelHealth.js; this file only decides how to draw them.
//
// ⛔ Distinct from components/vpn/IpsecTunnelsTable.js, which lists ONE
// device's tunnels on /devices/[id]/vpn. This is the fleet view, and its
// subject is as much the COVERAGE as the tunnels — see below.
//
// ⛔ ═══ WHAT THIS SCREEN IS ALLOWED TO CLAIM ══════════════════════════════
// A tunnel dashboard is one of the easiest places in this product to draw a
// confident lie, because the failure modes all look like good news:
//
//   * a vendor SecVault cannot ask contributes zero down tunnels, which reads
//     identically to a vendor with zero down tunnels. So EVERY active device
//     appears in the coverage table, including the ones nothing was ever
//     collected from, and the headline numbers carry their denominator;
//   * a stale snapshot's "up" is a fact about the past. It is drawn as NOT
//     MEASURED with its last known state and age in the tooltip — never as a
//     green Up badge. Live, one firewall's newest tunnel snapshot is over a
//     month old while its VPN poll fails every cycle;
//   * a status verb the engine does not recognise is hueless and shown
//     verbatim, never mapped onto Down;
//   * "down since" is not rendered, because it is not derivable. The panel
//     says so, and says what it would take, rather than quietly implying that
//     the collection time is the failure time.

const SUBTLE = { fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' };

const TH = {
  textAlign: 'left',
  fontSize: 'var(--text-xs)',
  textTransform: 'uppercase',
  letterSpacing: '0.04em',
  color: 'var(--text-muted)',
  fontWeight: 600,
};

const NUM = { textAlign: 'right', fontVariantNumeric: 'tabular-nums' };

const MONO = { fontFamily: 'var(--font-mono)', wordBreak: 'break-word' };

// The hueless treatment, as a style rather than a colour. Used for every state
// that means "SecVault could not measure this" — a gap is neither good news
// nor bad news, and giving it a ramp hue in either direction is the same lie.
const UNMEASURED_CHIP = {
  background: 'var(--surface-subtle)',
  color: 'var(--unmeasured)',
  border: '1px solid var(--border)',
};

const CALLOUT = {
  fontSize: 'var(--text-sm)',
  color: 'var(--text-secondary)',
  border: '1px solid var(--border)',
  borderLeft: '3px solid var(--unmeasured)',
  borderRadius: 'var(--radius-sm)',
  padding: 'var(--s2) var(--s3)',
  background: 'var(--surface-subtle)',
};

const COVERAGE_LABEL = {
  reporting: 'Reporting',
  no_rows_polled: 'No tunnels reported',
  no_rows_unconfirmed: 'Not confirmed',
  unsupported: 'Cannot be collected',
  support_unknown: 'Support unknown',
};

function formatCount(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return '—';
  return v.toLocaleString('en-US');
}

/**
 * A tunnel's CURRENT health. Four outcomes, and only two of them are a
 * statement about the tunnel itself.
 *
 * ⛔ `unmeasured` is not a fifth flavour of down. It means the snapshot this
 * row came from is older than the staleness window, so the device's last
 * answer — whatever it was — has expired. The last answer is preserved in the
 * tooltip as evidence, never as the badge.
 */
function HealthBadge({ tunnel }) {
  if (tunnel.health === 'up') return <Badge color="success">Up</Badge>;
  if (tunnel.health === 'down') return <Badge color="danger">Down</Badge>;
  if (tunnel.health === 'unknown') {
    const raw = tunnel.rawStatus;
    return (
      <span
        className="badge"
        style={UNMEASURED_CHIP}
        title={
          raw
            ? `The device reported "${raw}", which SecVault does not recognise as either up or down. `
              + 'An unrecognised word is never mapped onto a state — that would raise an alarm no '
              + 'device raised, or hide one it did.'
            : 'The device returned this tunnel without any status — neither up nor down was reported.'
        }
      >
        {raw ? `“${raw}”` : 'No status'}
      </span>
    );
  }
  const known = tunnel.lastKnownStatus === 'unknown' ? 'an unrecognised status' : tunnel.lastKnownStatus;
  return (
    <span
      className="badge"
      style={UNMEASURED_CHIP}
      title={
        `Last measured ${tunnel.ageMinutes === null ? 'at an unknown time' : `${formatCount(tunnel.ageMinutes)} minutes ago`}`
        + `, when the device reported ${known}. That is a fact about the past: this tunnel’s current `
        + 'state is unmeasured.'
      }
    >
      Not measured
    </span>
  );
}

/**
 * What the far end of a tunnel is, as far as SecVault can tell.
 *
 * ⛔ “Not matched” is deliberately not called “external”. Peer matching runs
 * against collected device_interfaces addresses, and that collection is itself
 * partial — a managed firewall whose interfaces were never collected is
 * unmatchable no matter how well known it is.
 */
function PeerCell({ tunnel, note }) {
  if (tunnel.peerKind === 'unreadable') {
    return (
      <NotMeasured
        reason={
          tunnel.peerRaw
            ? `The device reported the peer as "${tunnel.peerRaw}", which is not an address SecVault can parse.`
            : 'The device did not report a peer address for this tunnel.'
        }
      />
    );
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s1)' }}>
      <span style={MONO}>{tunnel.peerIp}</span>
      {tunnel.peerKind === 'managed_device' ? (
        <Badge color="teal" title="This peer address is an interface of another firewall SecVault manages.">
          {tunnel.peerDeviceNames.join(', ')}
        </Badge>
      ) : null}
      {tunnel.peerKind === 'self' ? (
        <Badge
          color="warning"
          title="This peer address is one of this same device's own interfaces — a configuration oddity or a parsing artefact, worth a look either way."
        >
          own interface
        </Badge>
      ) : null}
      {tunnel.peerKind === 'dialup' ? (
        <span className="badge" style={UNMEASURED_CHIP} title="0.0.0.0 — a dial-up or unnumbered peer. There is no fixed far end to identify.">
          dial-up peer
        </span>
      ) : null}
      {tunnel.peerKind === 'unmatched' ? (
        <span className="badge" style={UNMEASURED_CHIP} title={note}>
          not matched
        </span>
      ) : null}
    </div>
  );
}

function CoverageBadge({ device }) {
  const label = COVERAGE_LABEL[device.coverage] || device.coverage;
  // ⛔ Only a device that is reporting AND current gets a hue. Every other
  // state is a gap in what SecVault knows, and gaps are hueless.
  if (device.coverage === 'reporting' && device.snapshotFreshness === 'fresh') {
    return <Badge color="teal" title={device.coverageReason}>{label}</Badge>;
  }
  if (device.coverage === 'reporting') {
    return (
      <span
        className="badge"
        style={UNMEASURED_CHIP}
        title={
          'Tunnel rows exist for this device, but the snapshot they came from is older than the '
          + 'staleness window, so none of their states can be treated as current.'
        }
      >
        Stale snapshot
      </span>
    );
  }
  return (
    <span className="badge" style={UNMEASURED_CHIP} title={device.coverageReason}>
      {label}
    </span>
  );
}

// Plain functions returning JSX, called imperatively — NOT nested component
// definitions (CLAUDE.md's first Critical Rule).
function statTile(label, value, hint, color) {
  return (
    <div
      style={{
        flex: '1 1 170px',
        minWidth: 170,
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: 'var(--s3)',
        background: 'var(--surface-subtle)',
      }}
    >
      <div
        style={{
          fontSize: 'var(--text-xs)',
          textTransform: 'uppercase',
          letterSpacing: '0.04em',
          color: 'var(--text-muted)',
        }}
      >
        {label}
      </div>
      <div style={{ fontSize: 'var(--text-xl)', fontWeight: 600, fontVariantNumeric: 'tabular-nums', color }}>
        {value}
      </div>
      {hint ? <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{hint}</div> : null}
    </div>
  );
}

function downTable(rows, peerNote) {
  return (
    <Table>
      <colgroup>
        <col style={{ width: '20%' }} />
        <col style={{ width: '22%' }} />
        <col style={{ width: '24%' }} />
        <col style={{ width: '10%' }} />
        <col style={{ width: '10%' }} />
        <col style={{ width: '14%' }} />
      </colgroup>
      <thead>
        <tr>
          <th style={TH}>Firewall</th>
          <th style={TH}>Tunnel</th>
          <th style={TH}>Peer</th>
          <th style={TH}>State</th>
          <th style={TH}>IKE</th>
          <th style={TH}>Last measured</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((t) => (
          <tr key={t.tunnelId}>
            <td>
              {t.deviceName}
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                {vendorLabel(t.vendor)}
                {t.site ? ` · ${t.site}` : ''}
              </div>
            </td>
            <td style={MONO}>
              {t.name || <NotMeasured reason="The device did not report a name for this tunnel." />}
            </td>
            <td>
              <PeerCell tunnel={t} note={peerNote} />
            </td>
            <td>
              <HealthBadge tunnel={t} />
            </td>
            <td>
              {t.ikeVersion || (
                <NotMeasured reason="The device did not report an IKE version for this tunnel." />
              )}
            </td>
            <td>
              <TimeAgo value={t.collectedAt} empty="Never" />
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function coverageTable(devices) {
  return (
    <Table>
      <colgroup>
        <col style={{ width: '22%' }} />
        <col style={{ width: '16%' }} />
        <col style={{ width: '18%' }} />
        <col style={{ width: '8%' }} />
        <col style={{ width: '8%' }} />
        <col style={{ width: '14%' }} />
        <col style={{ width: '14%' }} />
      </colgroup>
      <thead>
        <tr>
          <th style={TH}>Firewall</th>
          <th style={TH}>Vendor / access</th>
          <th style={TH}>Coverage</th>
          <th style={{ ...TH, ...NUM }}>Up</th>
          <th style={{ ...TH, ...NUM }}>Down</th>
          <th style={TH}>Snapshot</th>
          <th style={TH}>Last VPN poll OK</th>
        </tr>
      </thead>
      <tbody>
        {devices.map((d) => (
          <tr key={d.deviceId}>
            <td>
              {d.name}
              {d.site ? (
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{d.site}</div>
              ) : null}
            </td>
            <td>
              {vendorLabel(d.vendor)}
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{d.mgmtMethod}</div>
            </td>
            <td>
              <CoverageBadge device={d} />
            </td>
            {/* ⛔ A device we cannot ask has no zero to show. An em-dash with a
                reason, never a 0 — a 0 in a Down column reads as "nothing is
                wrong here", which is precisely what is not known. */}
            <td style={NUM}>
              {d.snapshotFreshness === 'fresh' ? (
                formatCount(d.counts.up)
              ) : (
                <NotMeasured reason={d.coverageReason} />
              )}
            </td>
            <td style={NUM}>
              {d.snapshotFreshness === 'fresh' ? (
                <span style={d.counts.down > 0 ? { color: SEVERITY_TEXT_COLOR.critical, fontWeight: 600 } : undefined}>
                  {formatCount(d.counts.down)}
                </span>
              ) : (
                <NotMeasured reason={d.coverageReason} />
              )}
            </td>
            <td>
              {d.collectedAt ? (
                <TimeAgo value={d.collectedAt} />
              ) : (
                <NotMeasured reason="No tunnel snapshot has ever been stored for this device." />
              )}
            </td>
            <td>
              {d.lastVpnPollOkAt ? (
                <TimeAgo value={d.lastVpnPollOkAt} />
              ) : (
                <NotMeasured reason="No successful VPN poll was recorded for this device inside the lookback window." />
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function unrecognisedPanel(rows, devicesById) {
  return (
    <Card>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 'var(--text-base)', fontWeight: 600 }}>
              Status values SecVault does not recognise
            </h3>
            <p style={{ margin: 'var(--s1) 0 0', ...SUBTLE, maxWidth: '90ch' }}>
              These tunnels came back with a word that is neither <code>up</code> nor{' '}
              <code>down</code>. They are counted as unknown and shown verbatim — mapping an
              unfamiliar vendor verb onto a state would either invent an outage or hide one. If a
              value here is genuinely an up or down state, add it to the enumeration in{' '}
              <code>lib/engines/vpnTunnelHealth.js</code> on this evidence.
            </p>
          </div>
          <Table>
            <colgroup>
              <col style={{ width: '30%' }} />
              <col style={{ width: '15%' }} />
              <col style={{ width: '55%' }} />
            </colgroup>
            <thead>
              <tr>
                <th style={TH}>Reported value</th>
                <th style={{ ...TH, ...NUM }}>Tunnels</th>
                <th style={TH}>Seen on</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.value}>
                  <td style={MONO}>{r.value}</td>
                  <td style={NUM}>{formatCount(r.count)}</td>
                  <td>{r.deviceIds.map((id) => devicesById.get(id) || id).join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      </CardBody>
    </Card>
  );
}

/**
 * @param {object}  props
 * @param {number} [props.staleAfterMinutes] how old a tunnel snapshot may be
 *   before its states are reported as unmeasured. Default 120 (the VPN poll
 *   runs every 5-59 minutes, so this is 2-4 missed polls).
 * @param {string} [props.deviceId] restrict the tunnel/coverage rows to one
 *   firewall. Peer matching stays fleet-wide regardless.
 */
export default async function VpnTunnelHealth({ staleAfterMinutes, deviceId = null }) {
  const health = await getVpnTunnelHealth(pool, { staleAfterMinutes, deviceId });
  const { fleet, devices, down, notes } = health;
  const devicesById = new Map(devices.map((d) => [d.deviceId, d.name]));

  const uncovered =
    fleet.devices.unsupported
    + fleet.devices.supportUnknown
    + fleet.devices.noRowsUnconfirmed
    + fleet.devices.reportingStale
    + fleet.devices.reportingUnknownAge;

  const header = (
    <Card>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
          <div>
            <h2 style={{ margin: 0, fontSize: 'var(--text-lg)', fontWeight: 600 }}>
              Site-to-site tunnel health
            </h2>
            <p style={{ margin: 'var(--s2) 0 0', ...SUBTLE, maxWidth: '95ch' }}>
              {notes.scope} {notes.staleness}
            </p>
          </div>
          <div style={CALLOUT}>{notes.vendorCoverage}</div>
        </div>
      </CardBody>
    </Card>
  );

  // ⛔ The whole fleet is never the denominator. Percentages and "all clear"
  // statements are only ever made over the firewalls that both CAN be asked and
  // have a current answer.
  const summary = (
    <Card>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--s3)' }}>
            {statTile(
              'Tunnels down',
              formatCount(fleet.tunnels.down),
              'Reported down on a current snapshot',
              fleet.tunnels.down > 0 ? SEVERITY_TEXT_COLOR.critical : undefined
            )}
            {statTile('Tunnels up', formatCount(fleet.tunnels.up), 'Reported up on a current snapshot')}
            {statTile(
              'Status not recognised',
              formatCount(fleet.tunnels.unknownStatus),
              'Neither up nor down was readable'
            )}
            {statTile(
              'Unmeasured',
              formatCount(fleet.tunnels.unmeasured),
              `Snapshot older than ${formatCount(health.staleAfterMinutes)} min`
            )}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
            <span style={SUBTLE}>
              Measured across <strong>{formatCount(fleet.devices.claimable)}</strong> of{' '}
              <strong>{formatCount(fleet.devices.total)}</strong> active firewalls, holding{' '}
              <strong>{formatCount(fleet.tunnels.total)}</strong> collected tunnel
              {fleet.tunnels.total === 1 ? '' : 's'}.
            </span>
            <CoverageNote covered={fleet.devices.claimable} total={fleet.devices.total} />
            {/* ⛔ REPORTING TUNNELS AND REPORTING *DOWN* TUNNELS ARE DIFFERENT
                CAPABILITIES. Palo Alto's `show vpn ipsec-sa` lists ESTABLISHED
                SAs only, so a down tunnel is simply ABSENT — never a row with
                status "down". Measured live: that is 141 of 151 tunnels. Without
                this sentence the "Tunnels down" tile reads as an all-clear for
                firewalls whose down-ness SecVault structurally cannot see. */}
            {fleet.tunnels.downObservability
              && fleet.tunnels.downObservability.blindDevices > 0 ? (
              <span style={SUBTLE}>
                <strong>{formatCount(fleet.tunnels.downObservability.blindTunnels)}</strong>{' '}
                of these tunnels are on{' '}
                <strong>{formatCount(fleet.tunnels.downObservability.blindDevices)}</strong>{' '}
                firewall{fleet.tunnels.downObservability.blindDevices === 1 ? '' : 's'}{' '}
                ({fleet.tunnels.downObservability.blindVendors.join(', ')}) whose tunnel
                command reports only ESTABLISHED tunnels. A tunnel that is down there
                is invisible — not counted down, not counted up — so the count above is
                currently-established tunnels, not configured ones, and a zero in
                “Tunnels down” is not a measurement for them.
              </span>
            ) : null}
            {uncovered > 0 ? (
              <span style={SUBTLE}>
                {fleet.devices.unsupported > 0
                  ? `${fleet.devices.unsupported} cannot be asked at all (no tunnel collection for that vendor and access method). `
                  : ''}
                {fleet.devices.reportingStale + fleet.devices.reportingUnknownAge > 0
                  ? `${fleet.devices.reportingStale + fleet.devices.reportingUnknownAge} have only a stale snapshot. `
                  : ''}
                {fleet.devices.noRowsUnconfirmed > 0
                  ? `${fleet.devices.noRowsUnconfirmed} returned no tunnels and had no successful VPN poll to confirm it. `
                  : ''}
                {fleet.devices.supportUnknown > 0
                  ? `${fleet.devices.supportUnknown} use a vendor or access method whose tunnel support is unknown. `
                  : ''}
                Each is listed below.
              </span>
            ) : null}
            {fleet.devices.noRowsPolled > 0 ? (
              <span style={SUBTLE}>
                {fleet.devices.noRowsPolled} firewall
                {fleet.devices.noRowsPolled === 1 ? '' : 's'} returned no tunnels on a recent
                successful poll. That most likely means none are configured — it is not proof, because
                a tunnel command that failed on a reachable device leaves no database trace.
              </span>
            ) : null}
          </div>
        </div>
      </CardBody>
    </Card>
  );

  const downPanel = (
    <Card>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 'var(--text-base)', fontWeight: 600 }}>
              Tunnels currently reported down ({formatCount(down.length)})
            </h3>
            {/* ⛔ THE DURATION QUESTION, answered honestly and up front. The
                operator's next question after "which are down" is always "since
                when", and the collection time is sitting right there in the
                table looking like an answer. It is not one. */}
            <p style={{ margin: 'var(--s1) 0 0', ...SUBTLE, maxWidth: '90ch' }}>{notes.downSince}</p>
          </div>
          {down.length === 0 ? (
            // ⛔ Not "all tunnels healthy". The statement is scoped to the
            // firewalls that could be asked and answered recently, because that
            // is the only population it is true of.
            <EmptyState
              message={
                fleet.devices.claimable === 0
                  ? 'No firewall has a current tunnel snapshot, so nothing can be said about whether any '
                    + 'tunnel is down. See the coverage table below.'
                  : `No tunnel is reported down on the ${formatCount(fleet.devices.claimable)} firewall`
                    + `${fleet.devices.claimable === 1 ? '' : 's'} with a current snapshot. `
                    + 'This says nothing about the firewalls listed as uncovered below.'
              }
            />
          ) : (
            downTable(down, notes.peering)
          )}
        </div>
      </CardBody>
    </Card>
  );

  const coveragePanel = (
    <Card>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 'var(--text-base)', fontWeight: 600 }}>
              Coverage by firewall ({formatCount(devices.length)})
            </h3>
            <p style={{ margin: 'var(--s1) 0 0', ...SUBTLE, maxWidth: '90ch' }}>
              Every active firewall appears here, including the ones SecVault cannot ask. A firewall
              that reports nothing is a gap in what is known, not a firewall with no tunnels — the
              two are drawn differently on purpose.
            </p>
          </div>
          {devices.length === 0 ? (
            <EmptyState message="No active firewalls." />
          ) : (
            coverageTable(devices)
          )}
        </div>
      </CardBody>
    </Card>
  );

  const peeringPanel = (
    <Card>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 'var(--text-base)', fontWeight: 600 }}>
              Where the far ends are
            </h3>
            <p style={{ margin: 'var(--s1) 0 0', ...SUBTLE, maxWidth: '90ch' }}>{notes.peering}</p>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--s3)' }}>
            {statTile(
              'Another managed firewall',
              formatCount(fleet.peering.managedDevice),
              'Peer matched a collected interface address'
            )}
            {statTile('Not matched', formatCount(fleet.peering.unmatched), 'No managed interface carries this address')}
            {statTile('Dial-up peer', formatCount(fleet.peering.dialup), '0.0.0.0 — no fixed far end')}
            {statTile('Peer unreadable', formatCount(fleet.peering.unreadable), 'Absent or unparseable')}
          </div>
          <span style={SUBTLE}>
            Interface addresses have been collected from{' '}
            <strong>{formatCount(fleet.peering.devicesWithInterfaceData)}</strong> of{' '}
            <strong>{formatCount(fleet.peering.devicesTotal)}</strong> active firewalls, so a peer can
            only ever be matched against that much of the fleet.
          </span>
          {fleet.peering.self > 0 ? (
            <span style={SUBTLE}>
              {fleet.peering.self} tunnel{fleet.peering.self === 1 ? '' : 's'} name a peer that is one
              of the reporting device&rsquo;s own interfaces — worth a look either way.
            </span>
          ) : null}
        </div>
      </CardBody>
    </Card>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
      {header}
      {summary}
      {downPanel}
      {health.unrecognisedStatuses.length > 0
        ? unrecognisedPanel(health.unrecognisedStatuses, devicesById)
        : null}
      {coveragePanel}
      {peeringPanel}
    </div>
  );
}
