'use client';

// Zone Classification (Settings tab) — lets an admin explicitly tag each
// real zone name observed across the fleet's collected rules as Internal /
// External / DMZ. Deliberately NOT automatic pattern-matching — see
// lib/schema.sql's zone_classifications table comment for why an earlier
// feature (the Compliance page's Network Details card) already tried and
// rejected that approach for this exact deployment's zone names
// ("TFM-HQ"/"YCC"/"VRZ" aren't reliably classifiable by name). An explicit,
// operator-supplied mapping sidesteps that risk entirely.
//
// Visible to every authenticated user (read-only for a viewer) — the
// underlying data isn't secret, and knowing zone roles helps a viewer
// interpret the Reachability tab too. Only the role <select> itself is
// gated on `canWrite` (passed from Settings page.js's isAdminUser, same
// convention as the other admin-only Settings surfaces) — the real
// enforcement is PUT /api/zone-classifications' own server-side
// isAdmin() check; this is UI-hiding only, matching this app's usual
// "defense in depth, not the real boundary" posture for RBAC.
//
// GET is fetched on mount for everyone (not admin-gated server-side either,
// unlike CredentialProfilesPanel's list) — a genuine network failure is
// distinguished from "just empty" via a loadError state, same pattern
// UsersPanel/CredentialProfilesPanel already established.

import { useEffect, useState } from 'react';
import Badge from '../ui/Badge';

const ROLE_OPTIONS = [
  { value: '', label: 'Unclassified' },
  { value: 'internal', label: 'Internal' },
  { value: 'external', label: 'External' },
  { value: 'dmz', label: 'DMZ' },
];

// External is the "danger" hue deliberately -- it's the side of a rule that
// makes an allow toward Internal worth flagging (see ReachabilityTab.js /
// the external_exposure finding), same red-means-risky convention used
// throughout this app's badges.
const ROLE_BADGE_COLOR = { internal: 'success', external: 'danger', dmz: 'warning' };
const ROLE_LABEL = { internal: 'Internal', external: 'External', dmz: 'DMZ' };

function RoleBadge({ role }) {
  if (!role) {
    return <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>Unclassified</span>;
  }
  return <Badge color={ROLE_BADGE_COLOR[role]}>{ROLE_LABEL[role]}</Badge>;
}

// One zone's row: a select that auto-saves on change (optimistic, reverts
// on error) — same pattern as components/analysis/AcknowledgeControl.js.
function ZoneRoleRow({ zone, canWrite, onSaved }) {
  const [role, setRole] = useState(zone.role || '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (saving) return;
    setRole(zone.role || '');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [zone.role]);

  async function handleChange(e) {
    const next = e.target.value;
    const previous = role;
    setRole(next);
    setSaving(true);
    setError(null);
    try {
      const res = await fetch('/api/zone-classifications', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ zone_name: zone.zone_name, role: next || null }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) {
        throw new Error(data.error || 'Failed to save');
      }
      onSaved(zone.zone_name, next || null);
    } catch (err) {
      setRole(previous);
      setError(err.message || 'Failed to save');
    } finally {
      setSaving(false);
    }
  }

  return (
    <tr style={{ borderBottom: '1px solid var(--border)' }}>
      <td style={{ padding: '8px 0', fontSize: 'var(--text-base)', color: 'var(--text-primary)' }}>
        {zone.zone_name}
      </td>
      <td style={{ padding: '8px 0' }}>
        {canWrite ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <select
              value={role}
              onChange={handleChange}
              disabled={saving}
              className="select"
              style={{ fontSize: 'var(--text-sm)', padding: '4px 26px 4px 8px', opacity: saving ? 0.5 : 1 }}
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
        ) : (
          <RoleBadge role={role || null} />
        )}
      </td>
    </tr>
  );
}

export default function ZoneClassificationsPanel({ canWrite }) {
  const [zones, setZones] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const res = await fetch('/api/zone-classifications');
        const data = await res.json().catch(() => ({}));
        if (!cancelled) {
          if (!res.ok) throw new Error(data.error || 'Failed to load zones');
          setZones(Array.isArray(data.zones) ? data.zones : []);
          setLoadError(null);
        }
      } catch (err) {
        if (!cancelled) setLoadError(err.message || 'Failed to load zones');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, []);

  function handleSaved(zoneName, role) {
    setZones((prev) => prev.map((z) => (z.zone_name === zoneName ? { ...z, role } : z)));
  }

  if (loading) {
    return <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>Loading zones…</p>;
  }

  if (loadError) {
    return (
      <p style={{ fontSize: 'var(--text-base)', color: 'var(--red)' }}>
        Failed to load zones: {loadError}
      </p>
    );
  }

  const classifiedCount = zones.filter((z) => z.role).length;

  return (
    <div style={{ maxWidth: 640, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', margin: 0 }}>
        Every distinct zone name seen across the fleet&apos;s collected rules, so far. Tag each one Internal,
        External, or DMZ to power zone-aware features (the Reachability tab, the Exposure Risk finding, and the
        External-to-Internal compliance check). This is a manual, one-time mapping — SecVault deliberately does
        not guess a zone&apos;s role from its name, since real zone names vary too much across deployments to guess
        reliably. An unclassified zone is simply treated as unknown everywhere, never assumed either way.
      </p>

      {zones.length === 0 ? (
        <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-muted)' }}>
          No zone data collected yet — this list fills in once devices with zone-reporting rules are collected.
        </p>
      ) : (
        <>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', margin: 0 }}>
            {classifiedCount} of {zones.length} classified.
          </p>
          <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
            <colgroup>
              <col style={{ width: '55%' }} />
              <col style={{ width: '45%' }} />
            </colgroup>
            <thead>
              <tr style={{ borderBottom: '2px solid var(--border)' }}>
                <th style={{ textAlign: 'left', padding: '8px 0', fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                  Zone
                </th>
                <th style={{ textAlign: 'left', padding: '8px 0', fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                  Role
                </th>
              </tr>
            </thead>
            <tbody>
              {zones.map((zone) => (
                <ZoneRoleRow key={zone.zone_name} zone={zone} canWrite={canWrite} onSaved={handleSaved} />
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}
