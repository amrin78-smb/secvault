import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Badge from '../ui/Badge';
import IconChip from '../ui/IconChip';
import { IconClock } from '../icons';
import { licenseStatus } from '../../lib/engines/deviceHealth';

export const dynamic = 'force-dynamic';

// Fleet licence/support-contract expiry, condensed to the one question a
// dashboard should answer: is anything lapsed or about to lapse, and on how
// many devices.
//
// ⛔ The verdict comes from deviceHealth.licenseStatus(), never from a date
// comparison written here. /lifecycle already renders the full table off that
// same function; a second, subtly different rule would let the dashboard and
// the detail page disagree about whether a contract has lapsed.
//
// ⛔ expires_at is TRI-STATE (see lib/schema.sql). A NULL date means PERPETUAL
// when expires_raw is 'Never', NOT LICENSED when the vendor said 'n/a', and
// genuinely UNKNOWN otherwise. Those must not be merged: treating an unparsed
// expiry as "fine" is exactly how a support contract lapses unnoticed, and
// counting a not-licensed component as a renewal item invents work that does
// not exist.
//
// ⛔ COVERAGE IS STATED. Only adapters implementing getLicenses() populate this
// (Palo Alto both transports, Fortinet over SSH). Devices with no rows are
// reported as uncollected rather than silently treated as healthy — the same
// rule /lifecycle and the Fleet Map already follow.

const WARN_DAYS = 90;

async function getLicenceSummary(dbPool) {
  const [{ rows: deviceRows }, { rows: licenceRows }] = await Promise.all([
    dbPool.query('SELECT COUNT(*)::int AS n FROM devices WHERE active = true'),
    dbPool.query(
      `SELECT l.device_id, l.expires_at, l.expires_raw, l.expired
         FROM device_licenses l
         JOIN devices d ON d.id = l.device_id
        WHERE d.active = true`
    ),
  ]);

  const activeDevices = deviceRows[0] ? deviceRows[0].n : 0;
  const now = new Date();

  // Count DEVICES, not licence rows. A single Palo Alto reports 8-10 licences;
  // "37 expired" reads as a catastrophe when it is one device's worth of
  // components, so the headline counts devices and the detail counts rows.
  const devicesByStatus = { expired: new Set(), expiring: new Set(), unknown: new Set() };
  let expiredRows = 0;
  let expiringRows = 0;
  const covered = new Set();

  for (const row of licenceRows) {
    covered.add(row.device_id);
    const { status, daysRemaining } = licenseStatus(row, now, WARN_DAYS);
    if (status === 'expired') {
      devicesByStatus.expired.add(row.device_id);
      expiredRows += 1;
    } else if (status === 'expiring') {
      devicesByStatus.expiring.add(row.device_id);
      expiringRows += 1;
    } else if (status === 'unknown') {
      devicesByStatus.unknown.add(row.device_id);
    }
    // 'perpetual', 'not_licensed' and 'ok' are all deliberately NOT renewal
    // items and are counted nowhere above.
    void daysRemaining;
  }

  return {
    activeDevices,
    coveredDevices: covered.size,
    expiredDevices: devicesByStatus.expired.size,
    expiringDevices: devicesByStatus.expiring.size,
    unknownDevices: devicesByStatus.unknown.size,
    expiredRows,
    expiringRows,
  };
}

function Row({ label, value, tone, sub }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'baseline',
        justifyContent: 'space-between',
        gap: 8,
        padding: '5px 0',
      }}
    >
      <span style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>{label}</span>
      <span style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
        {sub && (
          <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>{sub}</span>
        )}
        <Badge color={tone}>{value}</Badge>
      </span>
    </div>
  );
}

export default async function LicenceExpiryWidget() {
  const s = await getLicenceSummary(pool);

  const uncollected = Math.max(0, s.activeDevices - s.coveredDevices);
  const nothingCollected = s.coveredDevices === 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <IconChip icon={IconClock} color="#fbbf24" bg="rgba(251,191,36,0.20)" />
          Licence &amp; Support Expiry
        </CardTitle>
      </CardHeader>
      <CardBody>
        {nothingCollected ? (
          // Not "all clear" — nothing has been read at all, and saying so is
          // the whole point of this branch.
          <div style={{ fontSize: 'var(--text-base)', color: 'var(--text-muted)' }}>
            No licence data collected from any of the {s.activeDevices} active device
            {s.activeDevices === 1 ? '' : 's'} yet. Supported on Palo Alto (both transports) and
            Fortinet over SSH.
          </div>
        ) : (
          <>
            <Row
              label="Lapsed"
              value={s.expiredDevices}
              tone={s.expiredDevices > 0 ? 'danger' : 'success'}
              sub={s.expiredRows > 0 ? `${s.expiredRows} licence${s.expiredRows === 1 ? '' : 's'}` : null}
            />
            <Row
              label={`Expiring within ${WARN_DAYS}d`}
              value={s.expiringDevices}
              tone={s.expiringDevices > 0 ? 'warning' : 'success'}
              sub={
                s.expiringRows > 0 ? `${s.expiringRows} licence${s.expiringRows === 1 ? '' : 's'}` : null
              }
            />
            {s.unknownDevices > 0 && (
              // An expiry string the vendor gave us that we could not parse.
              // Kept visible and separate from "fine" on purpose.
              <Row label="Unreadable expiry" value={s.unknownDevices} tone="warning" />
            )}
            <div
              style={{
                marginTop: 8,
                paddingTop: 8,
                borderTop: '1px solid var(--border)',
                fontSize: 'var(--text-sm)',
                color: 'var(--text-muted)',
                display: 'flex',
                justifyContent: 'space-between',
                gap: 8,
              }}
            >
              <span>
                Read from {s.coveredDevices} of {s.activeDevices} device
                {s.activeDevices === 1 ? '' : 's'}
                {uncollected > 0 ? ` — ${uncollected} not collected` : ''}
              </span>
              <Link href="/lifecycle" style={{ color: 'var(--primary)', whiteSpace: 'nowrap' }}>
                View all
              </Link>
            </div>
          </>
        )}
      </CardBody>
    </Card>
  );
}
