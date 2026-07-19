import { pool } from '../../lib/db';
import EmptyState from '../ui/EmptyState';
import { VENDOR_META } from '../devices/vendorMeta';

// Dashboard widget: active-device count by vendor, as a plain-CSS horizontal
// bar list (no chart library -- this is a simple proportion-of-total view,
// same "no chart needed for something this simple" call the app already
// makes elsewhere). Async server component, does its own pool.query --
// same "server components query the DB directly" convention as the rest of
// this app's dashboard-style pages.
async function getVendorCounts(dbPool) {
  const { rows } = await dbPool.query(
    `SELECT vendor, COUNT(*)::int AS count
     FROM devices
     WHERE active = true
     GROUP BY vendor
     ORDER BY count DESC`
  );
  return rows;
}

export default async function VendorDistribution() {
  const rows = await getVendorCounts(pool);
  const total = rows.reduce((sum, row) => sum + row.count, 0);

  if (total === 0) {
    return <EmptyState message="No active devices yet. Add one from the Devices page." />;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {rows.map((row) => {
        const pct = Math.round((row.count / total) * 100);
        const label = VENDOR_META[row.vendor]?.label || row.vendor;
        return (
          <div key={row.vendor}>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'baseline',
                marginBottom: 2,
                fontSize: 'var(--text-xs)',
              }}
            >
              <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{label}</span>
              <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>
                {row.count} ({pct}%)
              </span>
            </div>
            <div
              style={{
                width: '100%',
                height: 6,
                borderRadius: 3,
                background: 'var(--bg-primary)',
                border: '1px solid var(--border)',
                overflow: 'hidden',
              }}
            >
              <div
                style={{
                  width: `${pct}%`,
                  height: '100%',
                  background: 'var(--primary)',
                  borderRadius: 3,
                }}
              />
            </div>
          </div>
        );
      })}
      <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 2 }}>
        {total} device{total === 1 ? '' : 's'} across {rows.length} vendor{rows.length === 1 ? '' : 's'}.
      </div>
    </div>
  );
}
