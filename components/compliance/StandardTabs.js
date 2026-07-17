'use client';

import { useEffect, useState } from 'react';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';

// Deliberate deviation from this app's usual `?tab=` server-navigation
// convention (see app/(dashboard)/devices/[id]/analysis/page.js) -- see
// app/(dashboard)/compliance/[deviceId]/page.js's own comment for why:
// switching standards here only re-filters an already-fetched findings
// array, there is no new per-tab DB query the way analysis's tabs each run.

// Compliance status -> Badge color. pass=green, fail=red, warning=amber,
// na=muted/gray, per the task's own status-badge spec.
const STATUS_BADGE = {
  pass: { label: 'Pass', color: 'success' },
  fail: { label: 'Fail', color: 'danger' },
  warning: { label: 'Warning', color: 'warning' },
  na: { label: 'N/A', color: 'muted' },
};

// audit_checks.severity is 'critical'|'high'|'medium'|'low'|'info' (per
// lib/schema.sql) -- one more value ('low') than
// components/analysis/SeverityBadge.js's rule-analysis severity set, so a
// local map is used here rather than reusing that component and having it
// silently fall back to 'info' styling for 'low'.
const SEVERITY_BADGE = {
  critical: { label: 'Critical', color: 'danger' },
  high: { label: 'High', color: 'warning' },
  medium: { label: 'Medium', color: 'info' },
  low: { label: 'Low', color: 'muted' },
  info: { label: 'Info', color: 'muted' },
};

export default function StandardTabs({ standards, findings }) {
  const [active, setActive] = useState(standards?.[0]?.key || '');

  // Nice-to-have deep-link support: /compliance/[deviceId]#CIS_V8 preselects
  // that tab, so the fleet matrix's per-standard chip links
  // (ComplianceMatrix.js) land directly on the right tab instead of always
  // opening to the first standard.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const hash = window.location.hash.replace('#', '');
    if (hash && standards.some((s) => s.key === hash)) {
      setActive(hash);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = findings.filter((f) => Array.isArray(f.standards) && f.standards.includes(active));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4, borderBottom: '1px solid var(--border)' }}>
        {standards.map((s) => {
          const isActive = active === s.key;
          return (
            <button
              key={s.key}
              type="button"
              onClick={() => setActive(s.key)}
              style={{
                padding: '8px 12px',
                fontSize: 'var(--text-base)',
                background: 'none',
                border: 'none',
                borderBottom: isActive ? '2px solid var(--primary)' : '2px solid transparent',
                color: isActive ? 'var(--primary)' : 'var(--text-secondary)',
                cursor: 'pointer',
              }}
            >
              {s.label}
            </button>
          );
        })}
      </div>

      {filtered.length === 0 ? (
        <EmptyState message="No findings for this standard yet." />
      ) : (
        <Table>
          <colgroup>
            <col style={{ width: '28%' }} />
            <col style={{ width: '10%' }} />
            <col style={{ width: '10%' }} />
            <col style={{ width: '30%' }} />
            <col style={{ width: '22%' }} />
          </colgroup>
          <thead>
            <tr>
              <th>Check Name</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Detail</th>
              <th>Remediation</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((f) => {
              const sev = SEVERITY_BADGE[f.severity] || SEVERITY_BADGE.info;
              const st = STATUS_BADGE[f.status] || STATUS_BADGE.na;
              return (
                <tr key={f.id}>
                  <td title={f.name}>{f.name}</td>
                  <td>
                    <Badge color={sev.color}>{sev.label}</Badge>
                  </td>
                  <td>
                    <Badge color={st.color}>{st.label}</Badge>
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }} title={f.detail || ''}>
                    {f.detail || '—'}
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }} title={f.remediationGuidance || ''}>
                    {f.remediationGuidance || '—'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </Table>
      )}
    </div>
  );
}
