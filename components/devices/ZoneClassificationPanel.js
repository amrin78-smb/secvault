'use client';

// Per-device Zone Classification panel — lives on the device's own Manage
// tab (devices/[id]/page.js, tab === 'manage'). Seeded from the `initialZones`
// prop — devices/[id]/page.js (a server component) fetches getDeviceZones()
// itself and passes the result down, same pattern as SnmpConfigForm's own
// `initial` prop. Auto-saves each zone's role via PUT on <select> change
// (optimistic update, reverts on error) — same pattern as
// components/analysis/AcknowledgeControl.js.
//
// ⛔ Bug fixed 2026-07-23, reported directly by a user: this used to
// self-fetch GET /api/devices/[id]/zone-classifications ONCE on mount and
// never again — the header comment at the time reasoned "this data isn't
// rendered anywhere else on this page, so there's nothing else to re-sync",
// which missed the actual real trigger: clicking "Collect Now" on this same
// tab for a device's FIRST successful rule collection is exactly when a
// zone list first has anything to show. DeviceActions' router.refresh()
// re-renders devices/[id]/page.js with fresh data, but a client component's
// own useEffect(fetchOnMount, [deviceId]) doesn't re-run just because its
// parent re-rendered — deviceId never changes, so the stale empty "No zone
// data yet" state from before the collect silently persisted until a full
// page reload. Fixed by taking the zone list as a prop instead (which DOES
// flow through on every re-render) and resyncing local state whenever it
// changes, mirroring the existing per-row resync pattern below.
//
// This is a per-device rebuild of a feature that originally shipped as a
// single fleet-wide Settings > Zones list — reported directly as unusable,
// since real zone names turned out to be per-device VPN tunnel/site
// identifiers (e.g. "3bb", "awsvpn", "dmz1".."dmz6"), not shared role names
// reused across devices. See lib/engines/zoneClassification.js's own header
// comment for the full history.
//
// Only ever rendered from inside devices/[id]/page.js's `tab === 'manage'
// && canWrite` block, which is already fully admin-gated (both the tab link
// and the tab content) — so this component intentionally has no client-side
// admin check of its own and always shows the edit controls directly.

import { useEffect, useState } from 'react';

const ROLE_OPTIONS = [
  { value: '', label: 'Unclassified' },
  { value: 'internal', label: 'Internal' },
  { value: 'external', label: 'External' },
  { value: 'dmz', label: 'DMZ' },
];

function ZoneRoleSelect({ deviceId, zoneName, role }) {
  const [value, setValue] = useState(role || '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  // Resync if the prop changes for a reason other than this control's own
  // save (mirrors AcknowledgeControl.js's own resync effect) — skipped
  // while a save is in flight so the in-flight request's own
  // success/revert handling stays the source of truth until it settles.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (saving) return;
    setValue(role || '');
  }, [role]);

  async function handleChange(e) {
    const next = e.target.value;
    const previous = value;
    setValue(next); // optimistic
    setSaving(true);
    setError(null);
    try {
      const res = await fetch(`/api/devices/${deviceId}/zone-classifications`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ zone_name: zoneName, role: next === '' ? null : next }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) {
        throw new Error(data.error || 'Failed to save');
      }
    } catch (err) {
      setValue(previous); // revert the optimistic update
      setError(err.message || 'Failed to save');
    } finally {
      setSaving(false);
    }
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <select
        value={value}
        onChange={handleChange}
        disabled={saving}
        aria-label={`Role for zone ${zoneName}`}
        className="select"
        style={{ fontSize: 'var(--text-sm)', opacity: saving ? 0.5 : 1 }}
      >
        {ROLE_OPTIONS.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
      {error && (
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--red)' }} title={error}>
          ⚠
        </span>
      )}
    </div>
  );
}

export default function ZoneClassificationPanel({ deviceId, initialZones }) {
  const [zones, setZones] = useState(initialZones || []);

  // Resync whenever the server-fetched prop changes — i.e. after every
  // router.refresh() (a fresh Collect Now, most importantly). getDeviceZones()
  // itself already fails soft (returns [] on any DB error, never throws — see
  // its own header comment), so there's no separate error state to track here
  // the way the old client-fetch version needed one.
  useEffect(() => {
    setZones(initialZones || []);
  }, [initialZones]);

  const introText =
    'Tag each zone below as Internal, External, or DMZ. This powers the External Exposure rule finding, the ' +
    'External-to-Internal compliance check, and highlighting on the Reachability tab. SecVault never guesses a ' +
    "zone's role from its name — only what you tell it here.";

  return (
    <div>
      <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', marginBottom: 16 }}>
        {introText}
      </p>
      {zones.length === 0 ? (
        <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-muted)' }}>
          No zone data yet — this fills in once rules with zone information are collected for this device.
        </p>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
          <thead>
            <tr>
              <th
                style={{
                  width: '60%',
                  textAlign: 'left',
                  padding: '8px 12px',
                  borderBottom: '1px solid var(--border)',
                  fontSize: 'var(--text-sm)',
                  color: 'var(--text-muted)',
                }}
              >
                Zone Name
              </th>
              <th
                style={{
                  width: '40%',
                  textAlign: 'left',
                  padding: '8px 12px',
                  borderBottom: '1px solid var(--border)',
                  fontSize: 'var(--text-sm)',
                  color: 'var(--text-muted)',
                }}
              >
                Role
              </th>
            </tr>
          </thead>
          <tbody>
            {zones.map((z) => (
              <tr key={z.zone_name}>
                <td
                  style={{
                    padding: '8px 12px',
                    borderBottom: '1px solid var(--border)',
                    fontSize: 'var(--text-base)',
                    color: 'var(--text-primary)',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  {z.zone_name}
                </td>
                <td style={{ padding: '8px 12px', borderBottom: '1px solid var(--border)' }}>
                  <ZoneRoleSelect deviceId={deviceId} zoneName={z.zone_name} role={z.role} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
