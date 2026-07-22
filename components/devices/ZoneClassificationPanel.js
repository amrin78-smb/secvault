'use client';

// Per-device Zone Classification panel — lives on the device's own Manage
// tab (devices/[id]/page.js, tab === 'manage'). Self-fetches
// GET /api/devices/[id]/zone-classifications on mount, then auto-saves each
// zone's role via PUT on <select> change (optimistic update, reverts on
// error) — same pattern as components/analysis/AcknowledgeControl.js, just
// without router.refresh() (this data isn't rendered anywhere else on this
// page, so there's nothing else to re-sync).
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

export default function ZoneClassificationPanel({ deviceId }) {
  const [zones, setZones] = useState(null); // null = loading, [] = loaded empty
  const [loadError, setLoadError] = useState(false); // true = fetch() itself failed (network), distinct from a genuinely empty list

  async function loadZones() {
    setLoadError(false);
    try {
      const res = await fetch(`/api/devices/${deviceId}/zone-classifications`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || 'Failed to load zones');
      }
      setZones(data.zones || []);
    } catch (err) {
      setLoadError(true);
    }
  }

  useEffect(() => {
    loadZones();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deviceId]);

  const introText =
    'Tag each zone below as Internal, External, or DMZ. This powers the External Exposure rule finding, the ' +
    'External-to-Internal compliance check, and highlighting on the Reachability tab. SecVault never guesses a ' +
    "zone's role from its name — only what you tell it here.";

  if (loadError) {
    return (
      <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
        Failed to load zones.{' '}
        <button type="button" onClick={loadZones} className="btn btn-secondary" style={{ marginLeft: 8 }}>
          Retry
        </button>
      </p>
    );
  }

  if (zones === null) {
    return (
      <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>Loading zones…</p>
    );
  }

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
