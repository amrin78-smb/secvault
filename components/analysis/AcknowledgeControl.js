'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

// Per-row status control for Cleanup/Optimization/Reorder tabs (Rule Analysis
// Dashboard Phase 2). Auto-saves on change (optimistic update, reverts on
// error) rather than needing a separate Save button per table row -- POSTs to
// /api/devices/[id]/acknowledgements, then router.refresh() so the tab's
// server component re-queries with the new status. Same fetch+revert pattern
// as DeviceRowActions.js's inline row actions.
//
// CONTRACT for callers (the three tab components): only render this when
// `ruleIdVendor` is truthy. A handful of already-degraded/unparseable rule
// shapes across adapters leave firewall_rules.rule_id_vendor NULL -- that
// finding simply has no acknowledge control (see lib/schema.sql's
// finding_acknowledgements comment for why a NULL key can't be used safely).
const STATUS_OPTIONS = [
  { value: 'new', label: 'New' },
  { value: 'acknowledged', label: 'Acknowledged' },
  { value: 'dismissed', label: 'Dismissed' },
  { value: 'actioned', label: 'Actioned' },
];

export default function AcknowledgeControl({ deviceId, ruleIdVendor, findingType, currentStatus = 'new' }) {
  const router = useRouter();
  const [status, setStatus] = useState(currentStatus);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  async function handleChange(e) {
    const next = e.target.value;
    const previous = status;
    setStatus(next); // optimistic
    setSaving(true);
    setError(null);
    try {
      const res = await fetch(`/api/devices/${deviceId}/acknowledgements`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule_id_vendor: ruleIdVendor, finding_type: findingType, status: next }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.error) {
        throw new Error(data.error || 'Failed to save');
      }
      router.refresh();
    } catch (err) {
      setStatus(previous); // revert the optimistic update
      setError(err.message || 'Failed to save');
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="flex items-center gap-1.5">
      <select
        value={status}
        onChange={handleChange}
        disabled={saving}
        aria-label="Finding status"
        className="rounded border border-border bg-bg-base px-1.5 py-1 text-xs text-text-primary disabled:opacity-50"
      >
        {STATUS_OPTIONS.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
      {error && (
        <span className="text-xs text-danger" title={error}>
          ⚠
        </span>
      )}
    </div>
  );
}
