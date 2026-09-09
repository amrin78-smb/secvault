import Link from 'next/link';
import { pool } from '../../../../lib/db';
import PageHeader from '../../../../components/ui/PageHeader';
import Card, { CardBody } from '../../../../components/ui/Card';
import Badge from '../../../../components/ui/Badge';
import EmptyState from '../../../../components/ui/EmptyState';
import { getDiscoveredDevices } from '../../../../lib/engines/deviceDiscovery';
import { vendorLabel } from '../../../../components/devices/vendorMeta';
import { timeAgo, absoluteUtc } from '../../../../lib/formatDisplay';
import DiscoveredDeviceActions from '../../../../components/devices/DiscoveredDeviceActions';

export const dynamic = 'force-dynamic';

// Firewalls sending SecVault syslog from an address that matches no device.
//
// ⛔ THE TWO GROUPS ARE THE WHOLE POINT OF THIS PAGE. Measured on the live
// fleet, 5 of 8 unmatched senders are HA passive peers SecVault ALREADY knows
// about (matched on peer address and peer serial independently). Listing all
// eight as "new devices to add" would invite an operator to create five
// duplicate firewalls, and the feature would be untrustworthy from the first
// screen. So they are separated, and the evidence for each match is shown
// rather than a bare verdict.

const CELL = { padding: '10px 12px', verticalAlign: 'top', fontSize: 'var(--text-sm)' };

const TH = {
  textAlign: 'left',
  padding: '9px 12px',
  fontSize: 10,
  letterSpacing: '0.07em',
  textTransform: 'uppercase',
  color: 'var(--text-muted)',
  borderBottom: '1px solid var(--border)',
  whiteSpace: 'nowrap',
};

const MONO = {
  fontFamily: 'ui-monospace, Consolas, monospace',
  fontSize: 'var(--text-sm)',
};

// The "Already decided" badge printed the bare column value ('promoted',
// 'linked', 'ignored'). An unrecognised status still falls through to the raw
// string — a status we have no word for is information, not nothing.
const DECISION_LABELS = {
  promoted: 'Promoted',
  linked: 'Linked',
  ignored: 'Ignored',
};

// ⛔ Module top level, plain functions returning JSX, called imperatively.
function seenCell(row) {
  return (
    <td style={{ ...CELL, whiteSpace: 'nowrap' }}>
      <span title={absoluteUtc(row.last_seen_at) || ''}>{timeAgo(row.last_seen_at) || '—'}</span>
      {/* ⛔ The rollup buckets by HOUR, so this is hour-granular and says so
          rather than implying a precision it does not have. */}
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
        {row.observed_hours}h seen · to the hour
      </div>
    </td>
  );
}

function vendorCell(row) {
  // ⛔ A vendor we never identified renders as "Unknown", muted — never as a
  // guess, and never blank. Two of the live senders are in this state, and one
  // more read 0% vendor for a full hour despite being a Palo Alto whose log
  // format the parser does not yet recognise.
  if (!row.observed_vendor) {
    return (
      <td style={{ ...CELL, color: 'var(--text-muted)' }}>
        Unknown
        {row.vendor_conflict ? (
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--yellow)' }}>
            more than one vendor seen — may be a log relay
          </div>
        ) : null}
      </td>
    );
  }
  return (
    <td style={CELL}>
      {vendorLabel(row.observed_vendor)}
      {row.vendor_conflict ? (
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--yellow)' }}>
          more than one vendor seen — may be a log relay
        </div>
      ) : null}
    </td>
  );
}

export default async function DiscoveredDevicesPage() {
  let rows = [];
  let loadError = null;
  try {
    rows = await getDiscoveredDevices(pool);
  } catch (err) {
    // ⛔ Surfaced, never rendered as an empty list — "no unknown senders" is the
    // most dangerous wrong answer this page can give.
    loadError = err.message;
  }

  const pending = rows.filter((r) => r.status === 'new');
  const unmanaged = pending.filter((r) => r.correlation.kind === 'unmanaged');
  const knownPeers = pending.filter((r) => r.correlation.kind !== 'unmanaged');
  const decided = rows.filter((r) => r.status !== 'new');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <PageHeader
        title="Discovered Senders"
        subtitle={
          'Firewalls sending SecVault syslog from an address that matches no device in the ' +
          'inventory. Nothing here is added automatically — review, then promote or link.'
        }
      />

      {loadError ? (
        <Card>
          <CardBody>
            <div style={{ color: 'var(--red)', fontSize: 'var(--text-sm)' }}>
              <strong>Could not load discovered senders.</strong> {loadError}
            </div>
          </CardBody>
        </Card>
      ) : null}

      <Card>
        <CardBody>
          <div style={{ fontWeight: 700, marginBottom: 4 }}>
            Unmanaged firewalls ({unmanaged.length})
          </div>
          <div
            style={{
              fontSize: 'var(--text-sm)',
              color: 'var(--text-muted)',
              marginBottom: 12,
              lineHeight: 1.6,
            }}
          >
            These addresses match nothing SecVault knows. Adding one to the inventory needs
            credentials — syslog is one-way, so it can tell us a device exists but never how
            to log in to it.
          </div>

          {unmanaged.length === 0 ? (
            <EmptyState message="No unmanaged senders. Every device sending syslog is either in the inventory or linked to a device that is." />
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 760 }}>
                <thead>
                  <tr>
                    <th style={TH}>Reported name</th>
                    <th style={TH}>Source address</th>
                    <th style={TH}>Vendor</th>
                    <th style={{ ...TH, textAlign: 'right' }}>Events</th>
                    <th style={TH}>Last seen</th>
                    <th style={TH}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {unmanaged.map((r) => (
                    <tr key={r.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={CELL}>
                        {r.observed_hostname || (
                          <span style={{ color: 'var(--text-muted)' }}>not reported</span>
                        )}
                      </td>
                      <td style={{ ...CELL, ...MONO, whiteSpace: 'nowrap' }}>{r.sourceIp}</td>
                      {vendorCell(r)}
                      <td
                        style={{
                          ...CELL,
                          textAlign: 'right',
                          fontVariantNumeric: 'tabular-nums',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {Number(r.event_count).toLocaleString()}
                      </td>
                      {seenCell(r)}
                      <td style={{ ...CELL, whiteSpace: 'nowrap' }}>
                        <DiscoveredDeviceActions
                          id={r.id}
                          kind="unmanaged"
                          sourceIp={r.sourceIp}
                          hostname={r.observed_hostname}
                          vendor={r.observed_vendor}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardBody>
      </Card>

      {knownPeers.length > 0 ? (
        <Card>
          <CardBody>
            <div style={{ fontWeight: 700, marginBottom: 4 }}>
              Already part of a managed device ({knownPeers.length})
            </div>
            <div
              style={{
                fontSize: 'var(--text-sm)',
                color: 'var(--text-muted)',
                marginBottom: 12,
                lineHeight: 1.6,
              }}
            >
              These addresses match a device SecVault already manages — almost always the
              passive unit of an HA pair, which logs from its own address. Linking one files
              its logs under the device it belongs to.{' '}
              <strong>Do not add these as new devices</strong> — that would duplicate a
              firewall you already have.
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 760 }}>
                <thead>
                  <tr>
                    <th style={TH}>Reported name</th>
                    <th style={TH}>Source address</th>
                    <th style={TH}>Belongs to</th>
                    <th style={TH}>Why we think so</th>
                    <th style={TH}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {knownPeers.map((r) => (
                    <tr key={r.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={CELL}>
                        {r.observed_hostname || (
                          <span style={{ color: 'var(--text-muted)' }}>not reported</span>
                        )}
                      </td>
                      <td style={{ ...CELL, ...MONO, whiteSpace: 'nowrap' }}>{r.sourceIp}</td>
                      <td style={{ ...CELL, whiteSpace: 'nowrap' }}>
                        <Link
                          href={`/devices/${r.correlation.deviceId}`}
                          style={{ color: 'var(--text-primary)', fontWeight: 600 }}
                        >
                          {r.correlation.deviceName}
                        </Link>
                      </td>
                      {/* ⛔ The evidence, not just a verdict. An operator about
                          to merge two firewalls should see what matched. */}
                      <td style={{ ...CELL, color: 'var(--text-secondary)' }}>
                        {r.correlation.evidence}
                      </td>
                      <td style={{ ...CELL, whiteSpace: 'nowrap' }}>
                        <DiscoveredDeviceActions
                          id={r.id}
                          kind="ha-peer"
                          sourceIp={r.sourceIp}
                          deviceId={r.correlation.deviceId}
                          deviceName={r.correlation.deviceName}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardBody>
        </Card>
      ) : null}

      {decided.length > 0 ? (
        <Card>
          <CardBody>
            <div style={{ fontWeight: 700, marginBottom: 10 }}>
              Already decided ({decided.length})
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {decided.map((r) => (
                <div
                  key={r.id}
                  style={{
                    display: 'flex',
                    gap: 10,
                    alignItems: 'baseline',
                    fontSize: 'var(--text-sm)',
                  }}
                >
                  <Badge color={r.status === 'ignored' ? 'muted' : 'success'}>
                    {DECISION_LABELS[r.status] || r.status}
                  </Badge>
                  <span style={MONO}>{r.sourceIp}</span>
                  <span style={{ color: 'var(--text-muted)' }}>
                    {r.observed_hostname || 'name not reported'}
                    {r.decided_by ? ` · by ${r.decided_by}` : ''}
                    {r.decision_note ? ` · ${r.decision_note}` : ''}
                  </span>
                </div>
              ))}
            </div>
          </CardBody>
        </Card>
      ) : null}
    </div>
  );
}
